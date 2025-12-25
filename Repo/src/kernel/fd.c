#include "fd.h"
#include "spinlock.h"

/*
 * src/kernel/fd.c
 *
 * Minimal kernel file descriptor table.
 *
 * FDs are small integers that index a global table of `{ ops, context }`.
 * This layer is shared by:
 * - VFS-backed files created by syscalls (`src/kernel/syscall.c`)
 * - TCP sockets (`src/net/tcp.c`)
 * - Shell service capture FDs (`src/kernel/shell_service.c`)
 *
 * NOTE: This is currently a single global table (not per-process).
 * See docs/kernel/syscalls.md.
 */

#define FD_MAX 32

typedef struct
{
    bool used;
    const fd_ops_t *ops;
    void *context;
} fd_entry_t;

static fd_entry_t g_fd_table[FD_MAX];
static spinlock_t g_fd_lock;

static bool fd_valid(int fd)
{
    return fd >= 0 && fd < (int)FD_MAX;
}

/*
 * Allocate the lowest-numbered free FD and install ops/context.
 */
int fd_allocate(const fd_ops_t *ops, void *context)
{
    if (!ops)
    {
        return -1;
    }

    spinlock_lock(&g_fd_lock);
    for (int i = 0; i < (int)FD_MAX; ++i)
    {
        if (!g_fd_table[i].used)
        {
            g_fd_table[i].used = true;
            g_fd_table[i].ops = ops;
            g_fd_table[i].context = context;
            spinlock_unlock(&g_fd_lock);
            return i;
        }
    }
    spinlock_unlock(&g_fd_lock);
    return -1;
}

/*
 * Install an FD at a specific number.
 *
 * Used for reserving conventional descriptors (e.g. fd=1 for stdout).
 */
int fd_install(int fd, const fd_ops_t *ops, void *context)
{
    if (!ops || !fd_valid(fd))
    {
        return -1;
    }
    spinlock_lock(&g_fd_lock);
    if (g_fd_table[fd].used)
    {
        spinlock_unlock(&g_fd_lock);
        return -1;
    }
    g_fd_table[fd].used = true;
    g_fd_table[fd].ops = ops;
    g_fd_table[fd].context = context;
    spinlock_unlock(&g_fd_lock);
    return fd;
}

/*
 * Release an FD table slot without calling close().
 *
 * Most callers should use `fd_close` to run the underlying close operation.
 */
void fd_release(int fd)
{
    if (!fd_valid(fd))
    {
        return;
    }

    spinlock_lock(&g_fd_lock);
    g_fd_table[fd].used = false;
    g_fd_table[fd].ops = NULL;
    g_fd_table[fd].context = NULL;
    spinlock_unlock(&g_fd_lock);
}

static bool fd_get(int fd, const fd_ops_t **ops_out, void **context_out)
{
    if (!fd_valid(fd))
    {
        return false;
    }

    if (!ops_out || !context_out)
    {
        return false;
    }

    spinlock_lock(&g_fd_lock);
    fd_entry_t *entry = &g_fd_table[fd];
    if (!entry->used)
    {
        spinlock_unlock(&g_fd_lock);
        return false;
    }
    *ops_out = entry->ops;
    *context_out = entry->context;
    spinlock_unlock(&g_fd_lock);
    return true;
}

ssize_t fd_read(int fd, void *buffer, size_t count)
{
    const fd_ops_t *ops = NULL;
    void *context = NULL;
    if (!fd_get(fd, &ops, &context) || !ops || !ops->read)
    {
        return -1;
    }
    return ops->read(context, buffer, count);
}

/*
 * Invoke the `write` op for an FD.
 */
ssize_t fd_write(int fd, const void *buffer, size_t count)
{
    const fd_ops_t *ops = NULL;
    void *context = NULL;
    if (!fd_get(fd, &ops, &context) || !ops || !ops->write)
    {
        return -1;
    }
    return ops->write(context, buffer, count);
}

/*
 * Close an FD and run its `close` op (if present).
 *
 * The FD slot is cleared before invoking `ops->close` so close() can safely
 * reuse/allocate FDs if needed.
 */
int fd_close(int fd)
{
    if (!fd_valid(fd))
    {
        return -1;
    }

    const fd_ops_t *ops = NULL;
    void *context = NULL;
    spinlock_lock(&g_fd_lock);
    fd_entry_t *entry = &g_fd_table[fd];
    if (!entry->used)
    {
        spinlock_unlock(&g_fd_lock);
        return -1;
    }
    ops = entry->ops;
    context = entry->context;
    entry->used = false;
    entry->ops = NULL;
    entry->context = NULL;
    spinlock_unlock(&g_fd_lock);

    if (ops && ops->close)
    {
        return ops->close(context);
    }
    return 0;
}

/*
 * Positional read using `pread` if supported by the FD type.
 */
ssize_t fd_pread(int fd, void *buffer, size_t count, size_t offset)
{
    const fd_ops_t *ops = NULL;
    void *context = NULL;
    if (!fd_get(fd, &ops, &context) || !ops || !ops->pread)
    {
        return -1;
    }
    return ops->pread(context, buffer, count, offset);
}

/*
 * Seek using `lseek` if supported by the FD type.
 */
int64_t fd_lseek(int fd, int64_t offset, int whence)
{
    const fd_ops_t *ops = NULL;
    void *context = NULL;
    if (!fd_get(fd, &ops, &context) || !ops || !ops->lseek)
    {
        return -1;
    }
    return ops->lseek(context, offset, whence);
}

/*
 * Stat an FD using `fstat` if supported by the FD type.
 */
int fd_fstat(int fd, syscall_stat_t *out)
{
    const fd_ops_t *ops = NULL;
    void *context = NULL;
    if (!fd_get(fd, &ops, &context) || !ops || !ops->fstat)
    {
        return -1;
    }
    return ops->fstat(context, out);
}
