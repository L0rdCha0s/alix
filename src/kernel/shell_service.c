#include "shell_service.h"

#include "fd.h"
#include "heap.h"
#include "libc.h"
#include "process.h"
#include "shell.h"
#include "spinlock.h"
#include "vfs.h"

typedef struct shell_session
{
    uint32_t handle;
    shell_state_t state;
    process_t *owner;
    int stdout_fd;
    char *capture;
    size_t capture_len;
    size_t capture_cap;
    size_t read_offset;
    bool running;
    bool completed;
    int last_status;
    process_t *runner;
    struct shell_session *next;
    spinlock_t lock;
} shell_session_t;

static shell_session_t *g_shell_sessions = NULL;
static uint32_t g_next_shell_handle = 1;
static spinlock_t g_shell_list_lock;
static bool g_shell_list_lock_initialized = false;

static inline void shell_list_lock(void)
{
    if (!__atomic_load_n(&g_shell_list_lock_initialized, __ATOMIC_ACQUIRE))
    {
        spinlock_init(&g_shell_list_lock);
        __atomic_store_n(&g_shell_list_lock_initialized, true, __ATOMIC_RELEASE);
    }
    spinlock_lock(&g_shell_list_lock);
}

static inline void shell_list_unlock(void)
{
    spinlock_unlock(&g_shell_list_lock);
}

static shell_session_t *shell_session_find(uint32_t handle, process_t *owner);
static shell_session_t *shell_session_find_locked(uint32_t handle, process_t *owner);
static bool shell_session_reserve(shell_session_t *session, size_t extra);
static void shell_session_reset(shell_session_t *session);
static bool shell_session_append(shell_session_t *session, const char *data, size_t len);
static ssize_t shell_session_fd_write(void *ctx, const void *buffer, size_t count);
static int shell_session_fd_close(void *ctx);
static void shell_session_stream(void *context, const char *data, size_t len);
static void shell_session_exec_task(void *arg);
static process_t *shell_session_cleanup_runner_locked(shell_session_t *session);

static const fd_ops_t g_shell_session_fd_ops = {
    .read = NULL,
    .write = shell_session_fd_write,
    .close = shell_session_fd_close,
};

static inline void shell_session_lock(shell_session_t *session)
{
    if (session)
    {
        spinlock_lock(&session->lock);
    }
}

static inline void shell_session_unlock(shell_session_t *session)
{
    if (session)
    {
        spinlock_unlock(&session->lock);
    }
}

typedef struct shell_exec_task
{
    shell_session_t *session;
    char *line;
} shell_exec_task_t;

int shell_service_open_session(void)
{
    process_t *owner = process_current();
    if (!owner)
    {
        return -1;
    }

    shell_session_t *session = (shell_session_t *)malloc(sizeof(shell_session_t));
    if (!session)
    {
        return -1;
    }
    memset(session, 0, sizeof(*session));

    session->capture_cap = 0;
    session->capture_len = 0;
    session->capture = NULL;
    session->read_offset = 0;
    session->running = false;
    session->completed = false;
    session->last_status = 0;
    session->runner = NULL;
    spinlock_init(&session->lock);

    int fd = fd_allocate(&g_shell_session_fd_ops, session);
    if (fd < 0)
    {
        free(session);
        return -1;
    }

    shell_session_reset(session);

    session->stdout_fd = fd;
    session->state.cwd = process_current_cwd();
    if (!session->state.cwd)
    {
        session->state.cwd = vfs_root();
    }
    session->state.stream_fn = shell_session_stream;
    session->state.stream_context = session;
    session->state.stdout_fd = fd;
    session->state.owner_process = owner;
    session->state.wait_hook = NULL;

    session->owner = owner;

    shell_list_lock();
    session->handle = g_next_shell_handle++;
    session->next = g_shell_sessions;
    g_shell_sessions = session;
    shell_list_unlock();

    return (int)session->handle;
}

int shell_service_exec(uint32_t handle,
                       const char *command,
                       size_t command_len)
{
    if (!command)
    {
        return -1;
    }

    if (command_len == 0)
    {
        command_len = strlen(command);
    }

    char *line = (char *)malloc(command_len + 1);
    if (!line)
    {
        return -1;
    }
    memcpy(line, command, command_len);
    line[command_len] = '\0';

    process_t *owner = process_current();
    shell_session_t *session = shell_session_find_locked(handle, owner);
    if (!session)
    {
        free(line);
        return -1;
    }

    if (session->running)
    {
        shell_session_unlock(session);
        free(line);
        return -1;
    }

    process_t *zombie = shell_session_cleanup_runner_locked(session);
    shell_session_reset(session);
    session->running = true;
    session->completed = false;
    session->last_status = 0;
    shell_session_unlock(session);

    if (zombie)
    {
        process_destroy(zombie);
    }

    shell_exec_task_t *task = (shell_exec_task_t *)malloc(sizeof(shell_exec_task_t));
    if (!task)
    {
        shell_session_lock(session);
        session->running = false;
        shell_session_unlock(session);
        free(line);
        return -1;
    }
    task->session = session;
    task->line = line;

    process_t *proc = process_create_kernel_with_parent("shell_exec",
                                                        shell_session_exec_task,
                                                        task,
                                                        0,
                                                        session->stdout_fd,
                                                        session->owner);
    if (!proc)
    {
        shell_session_lock(session);
        session->running = false;
        shell_session_unlock(session);
        free(task->line);
        free(task);
        return -1;
    }

    shell_session_lock(session);
    session->runner = proc;
    shell_session_unlock(session);
    return 0;
}

bool shell_service_close_session(uint32_t handle)
{
    process_t *owner = process_current();
    shell_list_lock();

    shell_session_t **cursor = &g_shell_sessions;
    while (*cursor)
    {
        shell_session_t *session = *cursor;
        if (session->handle == handle && session->owner == owner)
        {
            shell_session_lock(session);
            if (session->running && (!session->runner || !process_is_zombie(session->runner)))
            {
                if (session->runner)
                {
                    process_kill(session->runner, -1);
                }
                shell_session_unlock(session);
                shell_list_unlock();
                return false;
            }

            process_t *zombie = shell_session_cleanup_runner_locked(session);
            if (!session->runner)
            {
                session->running = false;
            }
            *cursor = session->next;
            shell_session_unlock(session);

            if (session->stdout_fd >= 0)
            {
                fd_close(session->stdout_fd);
            }
            free(session->capture);
            free(session);
            shell_list_unlock();
            if (zombie)
            {
                process_destroy(zombie);
            }
            return true;
        }
        cursor = &session->next;
    }

    shell_list_unlock();
    return false;
}

ssize_t shell_service_poll(uint32_t handle,
                           char *output,
                           size_t output_capacity,
                           int *status_out,
                           int *running_out)
{
    process_t *owner = process_current();
    shell_session_t *session = shell_session_find_locked(handle, owner);
    if (!session)
    {
        return -1;
    }

    process_t *zombie = shell_session_cleanup_runner_locked(session);
    if (!session->runner)
    {
        session->running = false;
    }

    size_t available = 0;
    if (session->capture_len > session->read_offset)
    {
        available = session->capture_len - session->read_offset;
    }

    size_t copied = 0;
    if (output && output_capacity > 0)
    {
        size_t to_copy = available;
        if (to_copy >= output_capacity)
        {
            to_copy = output_capacity - 1;
        }
        if (to_copy > 0)
        {
            memcpy(output, session->capture + session->read_offset, to_copy);
            copied = to_copy;
            session->read_offset += to_copy;
            output[to_copy] = '\0';
        }
        else
        {
            output[0] = '\0';
        }
    }

    if (session->read_offset && session->read_offset == session->capture_len)
    {
        /* Compact to avoid unbounded growth when polling frequently. */
        session->capture_len = 0;
        session->read_offset = 0;
        if (session->capture)
        {
            session->capture[0] = '\0';
        }
    }

    if (status_out)
    {
        *status_out = session->completed ? session->last_status : 0;
    }
    if (running_out)
    {
        *running_out = session->running ? 1 : 0;
    }

    shell_session_unlock(session);
    if (zombie)
    {
        process_destroy(zombie);
    }
    return (ssize_t)copied;
}

void shell_service_cleanup_process(process_t *process)
{
    if (!process)
    {
        return;
    }

    shell_list_lock();

    shell_session_t **cursor = &g_shell_sessions;
    while (*cursor)
    {
        shell_session_t *session = *cursor;
        if (session->owner == process)
        {
            shell_session_lock(session);
            if (session->runner && !process_is_zombie(session->runner))
            {
                process_t *runner = session->runner;
                shell_session_unlock(session);
                shell_list_unlock();
                process_kill(runner, -1);
                process_join(runner, NULL);
                shell_list_lock();
                continue;
            }

            process_t *zombie = shell_session_cleanup_runner_locked(session);
            if (!session->runner)
            {
                session->running = false;
            }
            *cursor = session->next;
            shell_session_unlock(session);

            if (session->stdout_fd >= 0)
            {
                fd_close(session->stdout_fd);
            }
            free(session->capture);
            free(session);

            shell_list_unlock();
            if (zombie)
            {
                process_destroy(zombie);
            }
            shell_list_lock();
            cursor = &g_shell_sessions;
            continue;
        }
        cursor = &session->next;
    }

    shell_list_unlock();
}

static shell_session_t *shell_session_find(uint32_t handle, process_t *owner)
{
    for (shell_session_t *session = g_shell_sessions; session; session = session->next)
    {
        if (session->handle == handle && session->owner == owner)
        {
            return session;
        }
    }
    return NULL;
}

static shell_session_t *shell_session_find_locked(uint32_t handle, process_t *owner)
{
    shell_list_lock();
    shell_session_t *session = shell_session_find(handle, owner);
    if (session)
    {
        shell_session_lock(session);
    }
    shell_list_unlock();
    return session;
}

static bool shell_session_reserve(shell_session_t *session, size_t extra)
{
    if (!session)
    {
        return false;
    }
    size_t needed = session->capture_len + extra + 1;
    if (needed <= session->capture_cap)
    {
        return true;
    }
    size_t new_cap = session->capture_cap ? session->capture_cap : 512;
    while (new_cap < needed)
    {
        new_cap *= 2;
    }
    char *buffer = (char *)realloc(session->capture, new_cap);
    if (!buffer)
    {
        return false;
    }
    session->capture = buffer;
    session->capture_cap = new_cap;
    return true;
}

static void shell_session_reset(shell_session_t *session)
{
    if (!session)
    {
        return;
    }
    session->capture_len = 0;
    session->read_offset = 0;
    if (session->capture)
    {
        session->capture[0] = '\0';
    }
}

static bool shell_session_append(shell_session_t *session, const char *data, size_t len)
{
    if (!session || !data || len == 0)
    {
        return true;
    }
    shell_session_lock(session);
    if (!shell_session_reserve(session, len))
    {
        shell_session_unlock(session);
        return false;
    }
    memcpy(session->capture + session->capture_len, data, len);
    session->capture_len += len;
    session->capture[session->capture_len] = '\0';
    shell_session_unlock(session);
    return true;
}

static ssize_t shell_session_fd_write(void *ctx, const void *buffer, size_t count)
{
    shell_session_t *session = (shell_session_t *)ctx;
    if (!session)
    {
        return -1;
    }
    if (!buffer || count == 0)
    {
        return 0;
    }
    if (!shell_session_append(session, (const char *)buffer, count))
    {
        return -1;
    }
    return (ssize_t)count;
}

static int shell_session_fd_close(void *ctx)
{
    (void)ctx;
    return 0;
}

static void shell_session_stream(void *context, const char *data, size_t len)
{
    shell_session_append((shell_session_t *)context, data, len);
}

static void shell_session_exec_task(void *arg)
{
    shell_exec_task_t *task = (shell_exec_task_t *)arg;
    if (!task || !task->session || !task->line)
    {
        process_exit(-1);
    }

    shell_session_t *session = task->session;
    bool success = false;
    char *result = shell_execute_line(&session->state, task->line, &success);
    if (result)
    {
        shell_session_append(session, result, strlen(result));
        free(result);
    }
    free(task->line);
    free(task);

    shell_session_lock(session);
    session->running = false;
    session->completed = true;
    session->last_status = success ? 0 : -1;
    shell_session_unlock(session);
    process_exit(0);
}

static process_t *shell_session_cleanup_runner_locked(shell_session_t *session)
{
    if (!session)
    {
        return NULL;
    }
    process_t *runner = NULL;
    if (session->runner && process_is_zombie(session->runner))
    {
        runner = session->runner;
        session->runner = NULL;
        session->running = false;
    }
    return runner;
}

int shell_service_interrupt(uint32_t handle)
{
    process_t *owner = process_current();
    shell_session_t *session = shell_session_find_locked(handle, owner);
    if (!session)
    {
        return -1;
    }

    bool ok = false;
    if (session->running)
    {
        ok = shell_request_interrupt(&session->state);
    }
    shell_session_unlock(session);
    return ok ? 0 : -1;
}
