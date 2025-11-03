#include "fd.h"

#define FD_MAX 32

typedef struct
{
    bool used;
    const fd_ops_t *ops;
    void *context;
} fd_entry_t;

static fd_entry_t g_fd_table[FD_MAX];

static bool fd_valid(int fd)
{
    return fd >= 0 && fd < (int)FD_MAX;
}

int fd_allocate(const fd_ops_t *ops, void *context)
{
    if (!ops)
    {
        return -1;
    }

    for (int i = 0; i < (int)FD_MAX; ++i)
    {
        if (!g_fd_table[i].used)
        {
            g_fd_table[i].used = true;
            g_fd_table[i].ops = ops;
            g_fd_table[i].context = context;
            return i;
        }
    }
    return -1;
}

void fd_release(int fd)
{
    if (!fd_valid(fd))
    {
        return;
    }

    g_fd_table[fd].used = false;
    g_fd_table[fd].ops = NULL;
    g_fd_table[fd].context = NULL;
}

static fd_entry_t *fd_lookup(int fd)
{
    if (!fd_valid(fd))
    {
        return NULL;
    }

    fd_entry_t *entry = &g_fd_table[fd];
    if (!entry->used)
    {
        return NULL;
    }
    return entry;
}

ssize_t fd_read(int fd, void *buffer, size_t count)
{
    fd_entry_t *entry = fd_lookup(fd);
    if (!entry || !entry->ops || !entry->ops->read)
    {
        return -1;
    }
    return entry->ops->read(entry->context, buffer, count);
}

ssize_t fd_write(int fd, const void *buffer, size_t count)
{
    fd_entry_t *entry = fd_lookup(fd);
    if (!entry || !entry->ops || !entry->ops->write)
    {
        return -1;
    }
    return entry->ops->write(entry->context, buffer, count);
}

int fd_close(int fd)
{
    fd_entry_t *entry = fd_lookup(fd);
    if (!entry)
    {
        return -1;
    }

    const fd_ops_t *ops = entry->ops;
    void *context = entry->context;
    entry->used = false;
    entry->ops = NULL;
    entry->context = NULL;

    if (ops && ops->close)
    {
        return ops->close(context);
    }
    return 0;
}
