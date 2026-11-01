#include "shell_service.h"
#include "io_stream.h"

#include "fd.h"
#include "fd_table.h"
#include "process_internal.h"
#include "io_vfs_service.h"
#include "errno.h"
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
    bool closed, auth_busy;
    uint64_t auth_generation;
    fd_description_t *lifetime, *shutdown;
    shell_actor_t *runner_actor;
    uint32_t pending_uid;
    uint32_t pending_gid;
    char pending_user[PROCESS_NAME_MAX];
    char *pending_home;
    struct shell_session *next;
    spinlock_t lock;
} shell_session_t;

typedef struct
{
    shell_session_t *session;
    fd_description_t *session_owner;
    char *line;
    uint64_t generation;
    bool login_success, resolve_home;
    char home[VFS_PATH_MAX];
} shell_login_job_t;

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
static bool shell_session_append_locked(shell_session_t *session, const char *data, size_t len);
static bool shell_session_handle_login(shell_session_t *session, char *line, shell_login_job_t *job);
static ssize_t shell_session_fd_write(void *ctx, const void *buffer, size_t count);
static int shell_session_fd_close(void *ctx);
static fd_description_t *shell_session_import_owned(void *ctx);
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
    uint64_t runner_pid = shell_actor_pid(session->runner_actor);
    uint64_t owner_pid = session->state.owner_pid;
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

static int shell_session_lifetime_close(void *context)
{
    shell_session_t *session = context;
    /* Actor descriptors release their session pins only after actual process
     * and creator quiescence. Keep the capture slot registered until then. */
    if (session->state.actor_live || session->state.actors) fatal("session freed with live actors");
    /* A finishing actor can restore its saved console tap. Clear matching
     * global views only after tracked actors can no longer republish them. */
    shell_clear_active_shell(&session->state);
    shell_clear_console_tap_if_matches(session->state.stream_fn, session->state.stream_context);
    if (session->stdout_fd >= 0) fd_close(session->stdout_fd);
    shell_cwd_destroy(&session->state);
    free(session->pending_home);
    free(session->capture);
    free(session);
    return 0;
}

static const fd_ops_t shell_session_lifetime_ops = { .close = shell_session_lifetime_close };

static ssize_t shell_owned_stream_write(void *context, const void *buffer, size_t count)
{
    shell_session_t *session = context;
    if (!buffer && count) return -EINVAL;
    if (!count) return 0;
    shell_session_lock(session);
    ssize_t result = session->closed ? -EPIPE :
        shell_session_append_locked(session, buffer, count) ? (ssize_t)count : -ENOMEM;
    shell_session_unlock(session);
    return result;
}

static int shell_owned_stream_stat(void *context, syscall_stat_t *out)
{
    (void)context;
    if (!out) return -EINVAL;
    *out = (syscall_stat_t){ .type = SYSCALL_NODE_TYPE_CHARACTER };
    return 0;
}

static fd_description_t *shell_session_import_owned(void *context)
{
    /* The publishing global FD lock protects context until we acquire its
     * lifetime. Final session disposal removes that slot before freeing it. */
    shell_session_t *session = context;
    /* Do not wait for the session lock while holding the publishing FD lock.
     * The lifetime pointer is immutable; final disposal removes this FD slot
     * before freeing context, and a zero reference count cannot resurrect. */
    bool retained = !__atomic_load_n(&session->closed, __ATOMIC_ACQUIRE) && fd_description_get(session->lifetime);
    if (!retained) return NULL;
    const fd_ops_t ops = { .write = shell_owned_stream_write, .fstat = shell_owned_stream_stat };
    fd_description_t *description = io_stream_create(&ops, session, session->lifetime, process_fd_retirement_queue());
    if (!description) fd_description_put(session->lifetime);
    return description;
}

static int shell_session_shutdown_close(void *context)
{
    shell_session_t *session = context;
    shell_actors_mark_closing(&session->state);
    (void)shell_actors_retire_all(&session->state);
    /* The separately queued actor finalizers retain the session while they
     * stop/join. They must run even when actor I/O holds other session pins. */
    fd_description_put(session->lifetime);
    return 0;
}

static const fd_ops_t shell_session_shutdown_ops = { .close = shell_session_shutdown_close };

static void shell_session_runner_retired(void *context, shell_actor_t *actor)
{
    shell_session_t *session = context;
    shell_session_lock(session);
    if (session->runner_actor == actor)
    {
        session->runner_actor = NULL;
        session->runner = NULL;
        if (session->running)
        {
            session->running = false;
            session->completed = true;
            session->last_status = -1;
        }
    }
    shell_session_unlock(session);
}

static int shell_login_job_close(void *context)
{
    shell_login_job_t *job = context;
    /* Cancellation can discard the caller while the worker still owns this
     * job. Clear only this generation, never a newer login attempt. */
    shell_session_lock(job->session);
    if (job->session->auth_generation == job->generation) job->session->auth_busy = false;
    shell_session_unlock(job->session);
    free(job->line);
    fd_description_put(job->session_owner);
    free(job);
    return 0;
}

static const fd_ops_t shell_login_job_ops = { .close = shell_login_job_close };

static int shell_session_login_dispatch_locked(shell_session_t *session, char *line)
{
    /* Entry owns session->lock. The list owns its lifetime until we acquire
     * our reference; no raw session pointer is pinned after unlocking. */
    spinlock_preempt_disable();
    if (session->closed || session->auth_busy || session->auth_generation == (uint64_t)-1 ||
        !fd_description_get(session->lifetime))
    {
        shell_session_unlock(session);
        free(line);
        spinlock_preempt_enable();
        return -1;
    }
    fd_description_t *session_owner = session->lifetime;
    uint64_t generation = ++session->auth_generation;
    session->auth_busy = true;
    shell_session_unlock(session);

    shell_login_job_t *job = calloc(1, sizeof(*job));
    fd_description_t *job_owner = NULL;
    if (job)
    {
        job->session = session;
        job->session_owner = session_owner;
        job->line = line;
        job->generation = generation;
        job_owner = fd_description_create_deferred(&shell_login_job_ops, job, process_fd_retirement_queue());
    }
    if (!job_owner)
    {
        shell_session_lock(session);
        if (session->auth_generation == generation) session->auth_busy = false;
        shell_session_unlock(session);
        free(job);
        free(line);
        fd_description_put(session_owner);
        spinlock_preempt_enable();
        return -1;
    }

    shell_session_lock(session);
    bool handled = !session->closed && shell_session_handle_login(session, line, job);
    fd_description_t *base = job->resolve_home ? shell_cwd_acquire(&session->state) : NULL;
    shell_session_unlock(session);
    bool submitted = false;
    int prepared = 0;
    if (handled && job->resolve_home && base)
    {
        prepared = io_vfs_prepare_cwd(job->home, base, job_owner);
        submitted = prepared == 0;
    }
    fd_description_put(base);
    if (!submitted)
    {
        shell_session_lock(session);
        bool accepted = handled && !session->closed && prepared != -ECANCELED && prepared != -ESRCH;
        if (accepted && job->login_success)
            shell_session_append_locked(session, "login ok\n", sizeof("login ok\n") - 1);
        if (session->auth_generation == generation) session->auth_busy = false;
        shell_session_unlock(session);
        fd_description_put(job_owner);
        spinlock_preempt_enable();
        return accepted ? 0 : -1;
    }

    /* The registered request now owns another job reference. Its immutable
     * path, line and session pin survive caller death; workers never access
     * the session or a process pointer. Only this live caller publishes state. */
    fd_description_put(job_owner);
    spinlock_preempt_enable();
    io_request_status_t status;
    int result = process_io_wait_current(&status);
    spinlock_preempt_disable();
    io_request_t *request = NULL;
    if (!result) result = process_io_result_current(&request, &status);
    shell_session_lock(session);
    bool accepted = !result && !session->closed && session->auth_generation == generation;
    if (accepted && status.result == 0)
    {
        fd_description_t *owner = NULL;
        int taken = io_request_take_result(request, &owner);
        if (!taken)
        {
            /* Login historically changes this session's home only. Command
             * runners install that retained base before executing, so another
             * session's owner-process default is neither needed nor changed. */
            int applied = shell_cwd_replace_owned(&session->state, owner);
            if (applied) fd_description_put(owner);
            if (applied) accepted = false;
        }
        else accepted = false;
    }
    if (accepted) shell_session_append_locked(session, "login ok\n", sizeof("login ok\n") - 1);
    if (session->auth_generation == generation) session->auth_busy = false;
    shell_session_unlock(session);
    (void)process_io_finish_current(result != 0);
    spinlock_preempt_enable();
    return accepted ? 0 : -1;
}

int shell_service_open_session(void)
{
    process_t *owner = process_current();
    if (!owner)
    {
        return -1;
    }
    spinlock_preempt_disable();

    shell_session_t *session = (shell_session_t *)malloc(sizeof(shell_session_t));
    if (!session)
    {
        spinlock_preempt_enable();
        return -1;
    }
    memset(session, 0, sizeof(*session));
    session->stdout_fd = -1;

    session->capture_cap = 0;
    session->capture_len = 0;
    session->capture = NULL;
    session->read_offset = 0;
    session->running = false;
    session->completed = false;
    session->last_status = 0;
    session->runner = NULL;
    spinlock_init(&session->lock);
    if (!shell_cwd_init(&session->state))
    {
        free(session);
        spinlock_preempt_enable();
        return -1;
    }
    session->lifetime = fd_description_create_deferred(&shell_session_lifetime_ops, session, process_fd_retirement_queue());
    if (!session->lifetime)
    {
        shell_cwd_destroy(&session->state);
        free(session);
        spinlock_preempt_enable();
        return -1;
    }
    session->state.lifetime_owner = session->lifetime;
    session->shutdown = fd_description_create_deferred(&shell_session_shutdown_ops, session, process_fd_retirement_queue());
    if (!session->shutdown)
    {
        fd_description_put(session->lifetime);
        spinlock_preempt_enable();
        return -1;
    }

    int fd = fd_allocate_importable(&g_shell_session_fd_ops, session, shell_session_import_owned);
    if (fd < 0)
    {
        fd_description_put(session->shutdown);
        spinlock_preempt_enable();
        return -1;
    }

    shell_session_reset(session);

    session->stdout_fd = fd;
    session->state.stream_fn = shell_session_stream;
    session->state.stream_context = session;
    session->state.stdout_fd = fd;
    session->state.owner_process = owner;
    session->state.owner_pid = process_current_pid();
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

    int handle = (int)session->handle;
    spinlock_preempt_enable();
    return handle;
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

    if (session->auth_busy)
    {
        spinlock_preempt_disable();
        shell_session_unlock(session);
        free(line);
        spinlock_preempt_enable();
        return -1;
    }
    if (!session->authenticated) return shell_session_login_dispatch_locked(session, line);

    (void)shell_session_cleanup_runner_locked(session);
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
    shell_actor_t *actor = NULL;
    if (!shell_actor_begin(&session->state, &actor, shell_session_runner_retired, session))
    {
        session->running = false;
        shell_session_unlock(session);
        free(line);
        return -1;
    }
    session->runner_actor = actor;
    session->runner = NULL;
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
        shell_actor_complete(actor);
        return -1;
    }
    task->session = session;
    task->line = line;

    process_t *proc = shell_actor_create(actor, "shell_exec", shell_session_exec_task,
                                          task, 0, session->stdout_fd);
    if (!proc)
    {
        shell_session_lock(session);
        session->running = false;
        shell_session_unlock(session);
        shell_session_log(session, "exec_create_failed");
        free(task->line);
        free(task);
        shell_actor_complete(actor);
        return -1;
    }

    shell_session_lock(session);
    session->runner = proc;
    shell_session_log(session, "exec_runner_set");
    bool closed = session->closed;
    shell_session_unlock(session);
    shell_actor_complete(actor); /* Last creator access to session/record. */
    return closed ? -1 : 0;
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
            __atomic_store_n(&session->closed, true, __ATOMIC_RELEASE);
            shell_actors_mark_closing(&session->state);
            *cursor = session->next;
            shell_session_unlock(session);
            fd_description_put(session->shutdown);
            shell_list_unlock();
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
        *running_out = (session->running || session->auth_busy) ? 1 : 0;
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

    fd_description_t *cwd_owner = shell_cwd_acquire(&session->state);
    vfs_node_t *cwd = cwd_owner ? fd_description_context(cwd_owner) : NULL;
    size_t written = cwd ? vfs_build_path(cwd, buffer, capacity) : 0;
    fd_description_put(cwd_owner);
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
    if (!process) return;
    shell_list_lock();
    shell_session_t **cursor = &g_shell_sessions;
    while (*cursor)
    {
        shell_session_t *session = *cursor;
        if (session->owner == process)
        {
            shell_session_lock(session);
            __atomic_store_n(&session->closed, true, __ATOMIC_RELEASE);
            shell_actors_mark_closing(&session->state);
            *cursor = session->next;
            shell_session_unlock(session);
            fd_description_put(session->shutdown);
        }
        else cursor = &session->next;
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

static bool shell_session_handle_login(shell_session_t *session, char *line, shell_login_job_t *job)
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
        job->login_success = true;
        if (session->pending_home && session->pending_home[0] != '\0')
        {
            size_t length = 0, source = 0;
            /* The account database's relative homes historically resolve
             * from root, independently of this session's current directory. */
            if (session->pending_home[0] != '/') job->home[length++] = '/';
            while (length < VFS_PATH_MAX && session->pending_home[source])
            {
                job->home[length++] = session->pending_home[source++];
            }
            if (length < VFS_PATH_MAX)
            {
                job->home[length] = 0;
                job->resolve_home = true;
            }
        }
        shell_session_auth_reset(session);
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
    bool success = shell_cwd_apply_current(&session->state);
    char *result = success ? shell_execute_line(&session->state, task->line, &success) : NULL;
    if (shellsvc_log_enabled())
    {
        serial_printf("[shellsvc] worker_exec handle=%u execute_line_done success=%s result=%p",
                      (unsigned)session->handle,
                      success ? "true" : "false",
                      (void *)result);
    }
    if (result)
    {
        if (!session->state.stream_fn)
        {
            shell_session_append(session, result, strlen(result));
        }
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
    if (session)
    {
        bool running = session->runner_actor && !shell_actor_quiescent(session->runner_actor);
        spinlock_lock(&session->state.actors_lock);
        bool retiring = session->state.actors_paused && session->state.actor_live != 0;
        spinlock_unlock(&session->state.actors_lock);
        session->running = running || retiring;
        shell_actors_reap(&session->state);
    }
    return NULL; /* Process disposal belongs to protected actor finalizers. */
}

int shell_service_interrupt(uint32_t handle)
{
    shell_session_t *session = shell_session_find_locked(handle, process_current());
    if (!session) return -1;
    bool pending = shell_actors_retire_all(&session->state);
    if (pending)
    {
        session->completed = true;
        session->last_status = -1;
    }
    shell_session_unlock(session);
    return pending ? 0 : -1;
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
