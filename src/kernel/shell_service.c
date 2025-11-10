#include "shell_service.h"

#include "fd.h"
#include "heap.h"
#include "libc.h"
#include "process.h"
#include "shell.h"
#include "vfs.h"

static inline uint64_t shell_cpu_save_flags(void)
{
    uint64_t flags;
    __asm__ volatile ("pushfq; pop %0" : "=r"(flags));
    return flags;
}

static inline void shell_cpu_restore_flags(uint64_t flags)
{
    __asm__ volatile ("push %0; popfq" :: "r"(flags) : "cc");
}

static inline void shell_cpu_cli(void)
{
    __asm__ volatile ("cli" ::: "memory");
}

typedef struct shell_session
{
    uint32_t handle;
    shell_state_t state;
    process_t *owner;
    int stdout_fd;
    char *capture;
    size_t capture_len;
    size_t capture_cap;
    struct shell_session *next;
} shell_session_t;

static shell_session_t *g_shell_sessions = NULL;
static uint32_t g_next_shell_handle = 1;

static shell_session_t *shell_session_find(uint32_t handle, process_t *owner);
static bool shell_session_reserve(shell_session_t *session, size_t extra);
static void shell_session_reset(shell_session_t *session);
static bool shell_session_append(shell_session_t *session, const char *data, size_t len);
static ssize_t shell_session_fd_write(void *ctx, const void *buffer, size_t count);
static int shell_session_fd_close(void *ctx);
static void shell_session_stream(void *context, const char *data, size_t len);

static const fd_ops_t g_shell_session_fd_ops = {
    .read = NULL,
    .write = shell_session_fd_write,
    .close = shell_session_fd_close,
};

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

    session->owner = owner;

    uint64_t flags = shell_cpu_save_flags();
    shell_cpu_cli();
    session->handle = g_next_shell_handle++;
    session->next = g_shell_sessions;
    g_shell_sessions = session;
    shell_cpu_restore_flags(flags);

    return (int)session->handle;
}

ssize_t shell_service_exec(uint32_t handle,
                           const char *command,
                           size_t command_len,
                           char *output,
                           size_t output_capacity,
                           int *status_out)
{
    if (!command)
    {
        return -1;
    }

    process_t *owner = process_current();
    shell_session_t *session = shell_session_find(handle, owner);
    if (!session)
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

    shell_session_reset(session);

    bool success = false;
    char *result = shell_execute_line(&session->state, line, &success);
    free(line);
    if (result)
    {
        if (!shell_session_append(session, result, strlen(result)))
        {
            free(result);
            return -1;
        }
        free(result);
    }

    size_t available = session->capture_len;
    size_t to_copy = 0;
    if (output && output_capacity > 0)
    {
        if (available < output_capacity - 1)
        {
            to_copy = available;
        }
        else if (output_capacity > 0)
        {
            to_copy = output_capacity - 1;
        }
        if (to_copy > 0)
        {
            memcpy(output, session->capture, to_copy);
        }
        output[to_copy] = '\0';
    }

    if (status_out)
    {
        *status_out = success ? 0 : -1;
    }

    return (ssize_t)available;
}

bool shell_service_close_session(uint32_t handle)
{
    process_t *owner = process_current();
    uint64_t flags = shell_cpu_save_flags();
    shell_cpu_cli();

    shell_session_t **cursor = &g_shell_sessions;
    while (*cursor)
    {
        shell_session_t *session = *cursor;
        if (session->handle == handle && session->owner == owner)
        {
            *cursor = session->next;
            shell_cpu_restore_flags(flags);

            if (session->stdout_fd >= 0)
            {
                fd_close(session->stdout_fd);
            }
            free(session->capture);
            free(session);
            return true;
        }
        cursor = &session->next;
    }

    shell_cpu_restore_flags(flags);
    return false;
}

void shell_service_cleanup_process(process_t *process)
{
    if (!process)
    {
        return;
    }

    uint64_t flags = shell_cpu_save_flags();
    shell_cpu_cli();

    shell_session_t **cursor = &g_shell_sessions;
    while (*cursor)
    {
        shell_session_t *session = *cursor;
        if (session->owner == process)
        {
            *cursor = session->next;
            shell_cpu_restore_flags(flags);

            if (session->stdout_fd >= 0)
            {
                fd_close(session->stdout_fd);
            }
            free(session->capture);
            free(session);

            flags = shell_cpu_save_flags();
            shell_cpu_cli();
            cursor = &g_shell_sessions;
            continue;
        }
        cursor = &session->next;
    }

    shell_cpu_restore_flags(flags);
}

static shell_session_t *shell_session_find(uint32_t handle, process_t *owner)
{
    uint64_t flags = shell_cpu_save_flags();
    shell_cpu_cli();
    for (shell_session_t *session = g_shell_sessions; session; session = session->next)
    {
        if (session->handle == handle && session->owner == owner)
        {
            shell_cpu_restore_flags(flags);
            return session;
        }
    }
    shell_cpu_restore_flags(flags);
    return NULL;
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
    if (!shell_session_reserve(session, len))
    {
        return false;
    }
    memcpy(session->capture + session->capture_len, data, len);
    session->capture_len += len;
    session->capture[session->capture_len] = '\0';
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
