#include "fd_table.h"
#include "heap.h"
#include "spinlock.h"
#include "errno.h"

struct fd_description
{
    uint32_t references;
    fd_ops_t ops;
    void *context;
};

typedef struct
{
    fd_description_t *description;
    uint32_t flags;
} fd_table_entry_t;

struct fd_table
{
    uint32_t references;
    spinlock_t lock;
    size_t capacity;
    bool closed;
    fd_table_entry_t entries[];
};

/* A live reference (or a locked, owning table slot) protects the allocation
 * throughout this CAS loop. It never attempts resurrection from a raw pointer. */
static bool fd_reference_get(uint32_t *references)
{
    uint32_t count = __atomic_load_n(references, __ATOMIC_RELAXED);
    for (;;)
    {
        if (count == 0 || count == (uint32_t)-1)
        {
            return false;
        }
        if (__atomic_compare_exchange_n(references, &count, count + 1, false,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED))
        {
            return true;
        }
    }
}

fd_description_t *fd_description_create(const fd_ops_t *ops, void *context)
{
    if (!ops)
    {
        return NULL;
    }
    fd_description_t *description = calloc(1, sizeof(*description));
    if (!description)
    {
        return NULL;
    }
    description->references = 1;
    description->ops = *ops;
    description->context = context;
    return description;
}

bool fd_description_get(fd_description_t *description)
{
    return description && fd_reference_get(&description->references);
}

int fd_description_put(fd_description_t *description)
{
    if (!description || __atomic_fetch_sub(&description->references, 1, __ATOMIC_ACQ_REL) != 1)
    {
        return 0;
    }
    int result = 0;
    if (description->ops.close)
    {
        result = description->ops.close(description->context);
    }
    free(description);
    return result;
}

const fd_ops_t *fd_description_ops(const fd_description_t *description)
{
    return description ? &description->ops : NULL;
}

void *fd_description_context(const fd_description_t *description)
{
    return description ? description->context : NULL;
}

fd_table_t *fd_table_create(size_t capacity)
{
    if (capacity == 0 || capacity > FD_TABLE_MAX_ENTRIES ||
        capacity > ((size_t)-1 - sizeof(fd_table_t)) / sizeof(fd_table_entry_t))
    {
        return NULL;
    }
    fd_table_t *table = calloc(1, sizeof(*table) + capacity * sizeof(fd_table_entry_t));
    if (!table)
    {
        return NULL;
    }
    table->references = 1;
    table->capacity = capacity;
    spinlock_init(&table->lock);
    return table;
}

bool fd_table_get(fd_table_t *table)
{
    return table && fd_reference_get(&table->references);
}

size_t fd_table_capacity(const fd_table_t *table)
{
    return table ? table->capacity : 0;
}

void fd_table_shutdown(fd_table_t *table)
{
    if (!table)
    {
        return;
    }
    spinlock_lock(&table->lock);
    if (table->closed)
    {
        spinlock_unlock(&table->lock);
        return;
    }
    table->closed = true;
    spinlock_unlock(&table->lock);
    /* This caller exclusively owns draining after setting closed. Every
     * other operation checks closed under the lock before touching entries;
     * repeated shutdown calls return without touching them. No allocation or
     * stack-owned retirement array is needed. Outstanding pins own their refs. */
    for (size_t index = 0; index < table->capacity; ++index)
    {
        fd_description_t *description = table->entries[index].description;
        table->entries[index].description = NULL;
        table->entries[index].flags = 0;
        fd_description_put(description);
    }
}

void fd_table_put(fd_table_t *table)
{
    if (!table || __atomic_fetch_sub(&table->references, 1, __ATOMIC_ACQ_REL) != 1)
    {
        return;
    }
    fd_table_shutdown(table);
    free(table);
}

static bool fd_table_valid(const fd_table_t *table, int fd)
{
    return table && fd >= 0 && (size_t)fd < table->capacity;
}

static bool fd_table_flags_valid(uint32_t flags)
{
    return (flags & ~FD_TABLE_CLOEXEC) == 0;
}

int fd_table_install(fd_table_t *table, fd_description_t *description,
                     int minimum, uint32_t flags)
{
    if (!fd_table_valid(table, minimum) || !description || !fd_table_flags_valid(flags))
    {
        return -EINVAL;
    }
    int result = -EMFILE;
    spinlock_lock(&table->lock);
    if (table->closed)
    {
        result = -EBADF;
    }
    else
    {
        for (size_t index = (size_t)minimum; index < table->capacity; ++index)
        {
            if (!table->entries[index].description)
            {
                if (!fd_description_get(description))
                {
                    result = -EOVERFLOW;
                    break;
                }
                table->entries[index].description = description;
                table->entries[index].flags = flags;
                result = (int)index;
                break;
            }
        }
    }
    spinlock_unlock(&table->lock);
    return result;
}

int fd_table_install_at(fd_table_t *table, int fd,
                        fd_description_t *description, uint32_t flags)
{
    if (!fd_table_valid(table, fd))
    {
        return -EBADF;
    }
    if (!description || !fd_table_flags_valid(flags))
    {
        return -EINVAL;
    }
    int result = fd;
    spinlock_lock(&table->lock);
    if (table->closed)
    {
        result = -EBADF;
    }
    else if (table->entries[fd].description)
    {
        result = -EEXIST;
    }
    else if (!fd_description_get(description))
    {
        result = -EOVERFLOW;
    }
    else
    {
        table->entries[fd].description = description;
        table->entries[fd].flags = flags;
    }
    spinlock_unlock(&table->lock);
    return result;
}

int fd_table_pin(fd_table_t *table, int fd, fd_description_t **description_out,
                 uint32_t *flags_out)
{
    if (!description_out)
    {
        return -EINVAL;
    }
    *description_out = NULL;
    if (flags_out)
    {
        *flags_out = 0;
    }
    if (!fd_table_valid(table, fd))
    {
        return -EBADF;
    }
    int result = -EBADF;
    spinlock_lock(&table->lock);
    if (!table->closed && table->entries[fd].description)
    {
        fd_description_t *description = table->entries[fd].description;
        if (fd_description_get(description))
        {
            *description_out = description;
            if (flags_out)
            {
                *flags_out = table->entries[fd].flags;
            }
            result = 0;
        }
        else
        {
            result = -EOVERFLOW;
        }
    }
    spinlock_unlock(&table->lock);
    return result;
}

static int fd_table_remove(fd_table_t *table, int fd, fd_description_t *expected)
{
    if (!fd_table_valid(table, fd))
    {
        return -EBADF;
    }
    fd_description_t *description = NULL;
    int result = -EBADF;
    spinlock_lock(&table->lock);
    if (!table->closed && table->entries[fd].description)
    {
        if (expected && table->entries[fd].description != expected)
        {
            result = -EAGAIN;
        }
        else
        {
            description = table->entries[fd].description;
            table->entries[fd].description = NULL;
            table->entries[fd].flags = 0;
            result = 0;
        }
    }
    spinlock_unlock(&table->lock);
    return description ? fd_description_put(description) : result;
}

int fd_table_close(fd_table_t *table, int fd)
{
    return fd_table_remove(table, fd, NULL);
}

int fd_table_close_if(fd_table_t *table, int fd, fd_description_t *expected)
{
    return expected ? fd_table_remove(table, fd, expected) : -EINVAL;
}

int fd_table_dup(fd_table_t *table, int source, int minimum, uint32_t flags)
{
    if (!fd_table_valid(table, source))
    {
        return -EBADF;
    }
    if (!fd_table_valid(table, minimum) || !fd_table_flags_valid(flags))
    {
        return -EINVAL;
    }
    int result = -EBADF;
    spinlock_lock(&table->lock);
    if (!table->closed && table->entries[source].description)
    {
        result = -EMFILE;
        for (size_t index = (size_t)minimum; index < table->capacity; ++index)
        {
            if (!table->entries[index].description)
            {
                fd_description_t *description = table->entries[source].description;
                if (!fd_description_get(description))
                {
                    result = -EOVERFLOW;
                    break;
                }
                table->entries[index].description = description;
                table->entries[index].flags = flags;
                result = (int)index;
                break;
            }
        }
    }
    spinlock_unlock(&table->lock);
    return result;
}

static int fd_table_duplicate_to(fd_table_t *table, int source, int destination,
                                  uint32_t flags, bool allow_same)
{
    if (!fd_table_valid(table, source) || !fd_table_valid(table, destination))
    {
        return -EBADF;
    }
    if (!fd_table_flags_valid(flags) || (!allow_same && source == destination))
    {
        return -EINVAL;
    }
    int result = -EBADF;
    fd_description_t *previous = NULL;
    spinlock_lock(&table->lock);
    if (!table->closed && table->entries[source].description)
    {
        fd_description_t *description = table->entries[source].description;
        if (source == destination)
        {
            result = destination;
        }
        else if (!fd_description_get(description))
        {
            result = -EOVERFLOW;
        }
        else
        {
            previous = table->entries[destination].description;
            table->entries[destination].description = description;
            table->entries[destination].flags = flags;
            result = destination;
        }
    }
    spinlock_unlock(&table->lock);
    /* POSIX dup2/dup3 atomically replace the descriptor and do not return a
     * replaced description's final-close error. */
    fd_description_put(previous);
    return result;
}

int fd_table_dup2(fd_table_t *table, int source, int destination)
{
    return fd_table_duplicate_to(table, source, destination, 0, true);
}

int fd_table_dup3(fd_table_t *table, int source, int destination, uint32_t flags)
{
    return fd_table_duplicate_to(table, source, destination, flags, false);
}

int fd_table_get_flags(fd_table_t *table, int fd, uint32_t *flags_out)
{
    if (!flags_out)
    {
        return -EINVAL;
    }
    *flags_out = 0;
    if (!fd_table_valid(table, fd))
    {
        return -EBADF;
    }
    int result = -EBADF;
    spinlock_lock(&table->lock);
    if (!table->closed && table->entries[fd].description)
    {
        *flags_out = table->entries[fd].flags;
        result = 0;
    }
    spinlock_unlock(&table->lock);
    return result;
}

int fd_table_set_flags(fd_table_t *table, int fd, uint32_t flags)
{
    if (!fd_table_valid(table, fd))
    {
        return -EBADF;
    }
    if (!fd_table_flags_valid(flags))
    {
        return -EINVAL;
    }
    int result = -EBADF;
    spinlock_lock(&table->lock);
    if (!table->closed && table->entries[fd].description)
    {
        table->entries[fd].flags = flags;
        result = 0;
    }
    spinlock_unlock(&table->lock);
    return result;
}
