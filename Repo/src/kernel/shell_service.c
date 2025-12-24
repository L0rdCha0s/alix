#include "shell_service.h"

#include "fd.h"
#include "heap.h"
#include "libc.h"
#include "process.h"
#include "shell.h"
#include "shell_prompt.h"
#include "spinlock.h"
#include "user_auth.h"
#include "vfs.h"
#include "procfs.h"
#include "serial.h"

/*
 * src/kernel/shell_service.c
 *
 * Kernel-resident shell session service exposed to user space via syscalls.
 *
 * User processes can:
 * - open a session (allocates a session object + capture FD)
 * - execute commands asynchronously in a helper kernel process
 * - poll collected output and completion status
 *
 * This is used by userland tools like the graphical shell.
 * See docs/kernel/syscalls.md.
 */

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
    bool authenticated;
    bool awaiting_password;
    uint32_t pending_uid;
    uint32_t pending_gid;
    char pending_user[PROCESS_NAME_MAX];
    char *pending_home;
    struct shell_session *next;
    spinlock_t lock;
} shell_session_t;

static shell_session_t *g_shell_sessions = NULL;
static uint32_t g_next_shell_handle = 1;
static spinlock_t g_shell_list_lock;
static bool g_shell_list_lock_initialized = false;
static uint32_t g_shellsvc_log_enable = 0;

static inline bool shellsvc_log_enabled(void)
{
    return __atomic_load_n(&g_shellsvc_log_enable, __ATOMIC_ACQUIRE) != 0;
}

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
static bool shell_session_handle_login(shell_session_t *session, char *line);
static ssize_t shell_session_fd_write(void *ctx, const void *buffer, size_t count);
static int shell_session_fd_close(void *ctx);
static void shell_session_stream(void *context, const char *data, size_t len);
static void shell_session_exec_task(void *arg);
static process_t *shell_session_cleanup_runner_locked(shell_session_t *session);
static ssize_t shellsvc_log_read(vfs_node_t *node, size_t offset, void *buffer, size_t count, void *context);
static ssize_t shellsvc_log_write(vfs_node_t *node, size_t offset, const void *buffer, size_t count, void *context);

static void shell_session_log(shell_session_t *session, const char *tag)
{
    if (!session || !tag || !shellsvc_log_enabled())
    {
        return;
    }
    process_t *runner = session->runner;
    uint64_t runner_pid = runner ? process_get_pid(runner) : 0;
    uint64_t owner_pid = session->owner ? process_get_pid(session->owner) : 0;
    serial_printf("[shellsvc] %s handle=%u running=%s completed=%s runner=0x%016llX owner=0x%016llX",
                  tag,
                  (unsigned)session->handle,
                  session->running ? "true" : "false",
                  session->completed ? "true" : "false",
                  (unsigned long long)runner_pid,
                  (unsigned long long)owner_pid);
}

static const fd_ops_t g_shell_session_fd_ops = {
    .read = NULL,
    .write = shell_session_fd_write,
    .close = shell_session_fd_close,
    .pread = NULL,
    .lseek = NULL,
    .fstat = NULL,
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
    session->authenticated = (process_get_uid(owner) != PROCESS_UID_INVALID);
    session->awaiting_password = false;
    session->pending_uid = VFS_UID_ROOT;
    session->pending_gid = VFS_GID_ROOT;
    session->pending_user[0] = '\0';
    session->pending_home = NULL;

    if (!session->authenticated)
    {
        shell_session_append(session, "login: ", sizeof("login: ") - 1);
    }

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
        serial_printf("[shellsvc] exec lookup failed handle=%u owner=0x%016llX",
                      (unsigned)handle,
                      (unsigned long long)(owner ? process_get_pid(owner) : 0));
        free(line);
        return -1;
    }

    if (!session->authenticated)
    {
        bool handled = shell_session_handle_login(session, line);
        shell_session_unlock(session);
        free(line);
        return handled ? 0 : -1;
    }

    if (session->running)
    {
        shell_session_log(session, "exec_rejected_running");
        shell_session_unlock(session);
        free(line);
        return -1;
    }

    process_t *zombie = shell_session_cleanup_runner_locked(session);
    shell_session_reset(session);
    session->running = true;
    session->completed = false;
    session->last_status = 0;
    shell_session_log(session, "exec_start");
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
        shell_session_log(session, "exec_create_failed");
        free(task->line);
        free(task);
        return -1;
    }

    shell_session_lock(session);
    session->runner = proc;
    shell_session_log(session, "exec_runner_set");
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
                /* Do not hold any shell locks while killing/joining processes;
                 * process_destroy() will re-enter shell_service_cleanup_process().
                 */
                process_t *runner = session->runner;
                process_t *fg = shell_foreground_load(&session->state);
                shell_foreground_store(&session->state, NULL);
                session->runner = NULL;
                session->running = false;
                session->completed = true;
                session->last_status = -1;
                shell_session_unlock(session);
                shell_list_unlock();

                if (fg && !process_is_zombie(fg))
                {
                    process_kill_tree(fg);
                }
                if (runner && !process_is_zombie(runner))
                {
                    process_kill_tree(runner);
                }
                if (fg)
                {
                    process_join(fg, NULL);
                    if (process_is_zombie(fg))
                    {
                        process_destroy(fg);
                    }
                }
                if (runner)
                {
                    process_join(runner, NULL);
                    if (process_is_zombie(runner))
                    {
                        process_destroy(runner);
                    }
                }
                /* Retry close now that the session has been torn down. */
                return shell_service_close_session(handle);
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
            free(session->pending_home);
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
    //shell_session_log(session, "poll_after_cleanup");

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

ssize_t shell_service_get_cwd(uint32_t handle, char *buffer, size_t capacity)
{
    if (!buffer || capacity == 0)
    {
        return -1;
    }
    process_t *owner = process_current();
    shell_session_t *session = shell_session_find_locked(handle, owner);
    if (!session)
    {
        return -1;
    }

    vfs_node_t *cwd = session->state.cwd ? session->state.cwd : vfs_root();
    size_t written = vfs_build_path(cwd, buffer, capacity);
    shell_session_unlock(session);
    if (written == 0 || written >= capacity)
    {
        return -1;
    }
    buffer[written] = '\0';
    return (ssize_t)written;
}

ssize_t shell_service_get_prompt(uint32_t handle, char *buffer, size_t capacity)
{
    if (!buffer || capacity == 0)
    {
        return -1;
    }
    process_t *owner = process_current();
    shell_session_t *session = shell_session_find_locked(handle, owner);
    if (!session)
    {
        return -1;
    }

    if (!session->authenticated)
    {
        buffer[0] = '\0';
        shell_session_unlock(session);
        return 0;
    }

    char *prompt = shell_prompt_build(session->owner);
    shell_session_unlock(session);
    if (!prompt)
    {
        return -1;
    }

    size_t len = strlen(prompt);
    if (len + 1 > capacity)
    {
        free(prompt);
        return -1;
    }

    memcpy(buffer, prompt, len + 1);
    free(prompt);
    return (ssize_t)len;
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
            process_t *fg = shell_foreground_load(&session->state);
            process_t *fg_to_wait = NULL;
            if (fg && !process_is_zombie(fg))
            {
                process_kill_tree(fg);
                fg_to_wait = fg;
                shell_foreground_store(&session->state, NULL);
            }
            if (session->runner && !process_is_zombie(session->runner))
            {
                process_t *runner = session->runner;
                shell_session_unlock(session);
                shell_list_unlock();
                process_kill_tree(runner);
                process_join(runner, NULL);
                shell_list_lock();
                continue;
            }

            process_t *zombie = shell_session_cleanup_runner_locked(session);
            if (!session->runner)
            {
                session->running = false;
            }
            process_t *fg_zombie = NULL;
            if (fg && process_is_zombie(fg))
            {
                fg_zombie = fg;
                shell_foreground_store(&session->state, NULL);
            }
            *cursor = session->next;
            shell_session_unlock(session);

            if (session->stdout_fd >= 0)
            {
                fd_close(session->stdout_fd);
            }
            free(session->pending_home);
            free(session->capture);
            free(session);

            shell_list_unlock();
            if (fg_to_wait)
            {
                process_join(fg_to_wait, NULL);
                if (process_is_zombie(fg_to_wait))
                {
                    process_destroy(fg_to_wait);
                }
            }
            if (zombie)
            {
                process_destroy(zombie);
            }
            if (fg_zombie)
            {
                process_destroy(fg_zombie);
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

static bool shell_session_append_locked(shell_session_t *session, const char *data, size_t len)
{
    if (!session || !data || len == 0)
    {
        return true;
    }
    if (!shell_session_reserve(session, len))
    {
        return false;
    }
    memcpy(session->capture + session->capture_len, data, len);
    session->capture_len += len;
    session->capture[session->capture_len] = '\0';
    return true;
}

static bool shell_session_append(shell_session_t *session, const char *data, size_t len)
{
    if (!session || !data || len == 0)
    {
        return true;
    }
    shell_session_lock(session);
    bool ok = shell_session_append_locked(session, data, len);
    shell_session_unlock(session);
    return ok;
}

static char *shellsvc_trim_whitespace(char *text)
{
    if (!text)
    {
        return text;
    }
    while (*text == ' ' || *text == '\t')
    {
        ++text;
    }
    size_t len = strlen(text);
    while (len > 0 && (text[len - 1] == ' ' || text[len - 1] == '\t'))
    {
        text[--len] = '\0';
    }
    return text;
}

static void shell_session_auth_reset(shell_session_t *session)
{
    if (!session)
    {
        return;
    }
    session->pending_user[0] = '\0';
    session->pending_uid = VFS_UID_ROOT;
    session->pending_gid = VFS_GID_ROOT;
    if (session->pending_home)
    {
        free(session->pending_home);
        session->pending_home = NULL;
    }
    session->awaiting_password = false;
}

static bool shell_session_handle_login(shell_session_t *session, char *line)
{
    if (!session || !line || session->authenticated)
    {
        return false;
    }
    char *trimmed = shellsvc_trim_whitespace(line);
    if (!session->awaiting_password)
    {
        if (!trimmed || trimmed[0] == '\0')
        {
            shell_session_append_locked(session, "login: ", sizeof("login: ") - 1);
            return true;
        }
        user_record_t record;
        memset(&record, 0, sizeof(record));
        if (!user_auth_lookup(trimmed, &record))
        {
            shell_session_auth_reset(session);
            shell_session_append_locked(session,
                                        "Login incorrect\nlogin: ",
                                        sizeof("Login incorrect\nlogin: ") - 1);
            user_auth_free_record(&record);
            return true;
        }
        size_t user_len = strlen(trimmed);
        if (user_len >= sizeof(session->pending_user))
        {
            user_len = sizeof(session->pending_user) - 1;
        }
        memcpy(session->pending_user, trimmed, user_len);
        session->pending_user[user_len] = '\0';
        session->pending_uid = record.uid;
        session->pending_gid = record.gid;
        if (record.home)
        {
            session->pending_home = record.home;
            record.home = NULL;
        }
        user_auth_free_record(&record);
        session->awaiting_password = true;
        shell_session_append_locked(session, "password: ", sizeof("password: ") - 1);
        return true;
    }

    if (session->pending_user[0] == '\0')
    {
        shell_session_auth_reset(session);
        shell_session_append_locked(session, "login: ", sizeof("login: ") - 1);
        return true;
    }

    if (user_auth_check_password(session->pending_user, trimmed))
    {
        session->authenticated = true;
        session->awaiting_password = false;
        process_set_identity(session->owner, session->pending_uid, session->pending_gid);
        if (session->pending_home && session->pending_home[0] != '\0')
        {
            vfs_node_t *home = vfs_resolve(vfs_root(), session->pending_home);
            if (home && vfs_is_dir(home))
            {
                session->state.cwd = home;
            }
        }
        shell_session_auth_reset(session);
        shell_session_append_locked(session, "login ok\n", sizeof("login ok\n") - 1);
        return true;
    }

    shell_session_auth_reset(session);
    shell_session_append_locked(session,
                                "Login incorrect\nlogin: ",
                                sizeof("Login incorrect\nlogin: ") - 1);
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
        serial_printf("[shellsvc] worker_bad_task task=%p session=%p line=%p",
                      (void *)task,
                      task ? (void *)task->session : NULL,
                      task ? (void *)task->line : NULL);
        process_exit(-1);
    }

    shell_session_t *session = task->session;
    shell_session_log(session, "worker_begin");
    if (shellsvc_log_enabled())
    {
        serial_printf("[shellsvc] worker_exec handle=%u entering execute_line",
                      (unsigned)session->handle);
    }
    bool success = false;
    char *result = shell_execute_line(&session->state, task->line, &success);
    if (shellsvc_log_enabled())
    {
        serial_printf("[shellsvc] worker_exec handle=%u execute_line_done success=%s result=%p",
                      (unsigned)session->handle,
                      success ? "true" : "false",
                      (void *)result);
    }
    if (result && !session->state.stream_fn)
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
    shell_session_log(session, "worker_end");
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
        shell_session_log(session, "cleanup_runner");
    }
    return runner;
}

int shell_service_interrupt(uint32_t handle)
{
    process_t *owner = process_current();
    shell_session_t *session = shell_session_find_locked(handle, owner);
    if (!session)
    {
        serial_printf("[shellsvc] interrupt lookup_failed handle=%u owner=0x%016llX",
                      (unsigned)handle,
                      (unsigned long long)(owner ? process_get_pid(owner) : 0));
        return -1;
    }

    process_t *fg = shell_foreground_load(&session->state);
    process_t *runner = session->runner;

    if (shellsvc_log_enabled())
    {
        serial_printf("[shellsvc] interrupt request handle=%u running=%s fg_pid=0x%016llX runner_pid=0x%016llX",
                      (unsigned)handle,
                      session->running ? "true" : "false",
                      (unsigned long long)(fg ? process_get_pid(fg) : 0),
                      (unsigned long long)(runner ? process_get_pid(runner) : 0));
    }

    bool killed = false;
    if (session->running)
    {
        if (fg && !process_is_zombie(fg))
        {
            process_kill_tree(fg);
            killed = true;
        }

        if (runner && !process_is_zombie(runner))
        {
            process_kill_tree(runner);
            killed = true;
        }

        if (killed)
        {
            shell_foreground_store(&session->state, NULL);
            session->running = false;
            session->completed = true;
            session->last_status = -1;
        }
    }
    shell_session_unlock(session);
    return killed ? 0 : -1;
}

static ssize_t shellsvc_log_read(vfs_node_t *node, size_t offset, void *buffer, size_t count, void *context)
{
    (void)node;
    (void)context;
    if (!buffer)
    {
        return -1;
    }
    char tmp[3];
    tmp[0] = shellsvc_log_enabled() ? '1' : '0';
    tmp[1] = '\n';
    tmp[2] = '\0';
    size_t len = 2;
    if (offset >= len)
    {
        return 0;
    }
    size_t to_copy = len - offset;
    if (to_copy > count)
    {
        to_copy = count;
    }
    memcpy(buffer, tmp + offset, to_copy);
    return (ssize_t)to_copy;
}

static ssize_t shellsvc_log_write(vfs_node_t *node, size_t offset, const void *buffer, size_t count, void *context)
{
    (void)node;
    (void)context;
    (void)offset;
    if (!buffer || count == 0)
    {
        return -1;
    }
    const char *cbuf = (const char *)buffer;
    size_t idx = 0;
    while (idx < count && (cbuf[idx] == ' ' || cbuf[idx] == '\t'))
    {
        ++idx;
    }
    if (idx >= count)
    {
        return -1;
    }
    int value = -1;
    if (cbuf[idx] == '0')
    {
        value = 0;
    }
    else if (cbuf[idx] == '1')
    {
        value = 1;
    }
    if (value < 0)
    {
        return -1;
    }
    for (size_t tail = idx + 1; tail < count; ++tail)
    {
        char t = cbuf[tail];
        if (t == ' ' || t == '\t' || t == '\r' || t == '\n')
        {
            continue;
        }
        return -1;
    }
    __atomic_store_n(&g_shellsvc_log_enable, (uint32_t)value, __ATOMIC_RELEASE);
    return (ssize_t)count;
}

void shell_service_sys_controls_init(void)
{
    (void)procfs_create_file_at("sys/shellsvc/log_enable",
                                shellsvc_log_read,
                                shellsvc_log_write,
                                &g_shellsvc_log_enable);
}
