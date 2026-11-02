#include "fd_table.h"
#include "heap.h"
#include "spinlock.h"
#include "errno.h"

typedef enum { FD_RETIRE_DESCRIPTION, FD_RETIRE_TABLE } fd_retirement_kind_t;
typedef struct fd_retirement_item
{
    struct fd_retirement_item *next;
    void *object;
    fd_retirement_kind_t kind;
} fd_retirement_item_t;

struct fd_retirement_queue
{
    spinlock_t lock;
    size_t capacity, live, pending, drainers;
    uint32_t references;
    bool closed;
    fd_retirement_item_t *head, *tail;
};

struct fd_description
{
    fd_retirement_queue_t *retirement_queue;
    fd_retirement_item_t retirement;
    uint32_t references;
    fd_ops_t ops;
    void *context;
    uint32_t status_flags;
};

typedef struct
{
    fd_description_t *description;
    uint32_t flags;
    uint64_t reservation;
} fd_table_entry_t;

struct fd_table
{
    fd_retirement_queue_t *retirement_queue;
    fd_retirement_item_t retirement;
    uint32_t references;
    spinlock_t lock;
    size_t capacity, soft_limit, hard_limit;
    uint64_t next_ticket;
    bool closed;
    fd_table_entry_t entries[];
};

fd_retirement_queue_t *fd_retirement_queue_create(size_t capacity)
{
    if (!capacity || capacity > FD_RETIREMENT_MAX_OBJECTS) return NULL;
    fd_retirement_queue_t *queue = calloc(1, sizeof(*queue));
    if (!queue) return NULL;
    spinlock_init(&queue->lock);
    queue->capacity = capacity;
    queue->references = 1;
    return queue;
}

bool fd_retirement_queue_get(fd_retirement_queue_t *queue)
{
    if (!queue) return false;
    spinlock_lock(&queue->lock);
    bool acquired = queue->references && queue->references != (uint32_t)-1;
    if (acquired) ++queue->references;
    spinlock_unlock(&queue->lock);
    return acquired;
}

int fd_retirement_queue_put(fd_retirement_queue_t *queue)
{
    if (!queue) return -EINVAL;
    spinlock_lock(&queue->lock);
    int result = queue->references > 1 ? 0 : -EINVAL;
    if (!result) --queue->references;
    spinlock_unlock(&queue->lock);
    return result;
}

void fd_retirement_queue_shutdown(fd_retirement_queue_t *queue)
{
    if (!queue) return;
    spinlock_lock(&queue->lock);
    queue->closed = true;
    spinlock_unlock(&queue->lock);
}

int fd_retirement_queue_snapshot(fd_retirement_queue_t *queue, fd_retirement_status_t *out)
{
    if (!queue || !out) return -EINVAL;
    spinlock_lock(&queue->lock);
    out->capacity = queue->capacity;
    out->live = queue->live;
    out->pending = queue->pending;
    out->drainers = queue->drainers;
    out->references = queue->references;
    out->closed = queue->closed;
    spinlock_unlock(&queue->lock);
    return 0;
}

int fd_retirement_queue_destroy(fd_retirement_queue_t *queue)
{
    if (!queue) return -EINVAL;
    spinlock_preempt_disable();
    spinlock_lock(&queue->lock);
    if (!queue->closed || queue->live || queue->drainers || queue->references != 1)
    {
        spinlock_unlock(&queue->lock);
        spinlock_preempt_enable();
        return -EBUSY;
    }
    queue->references = 0;
    spinlock_unlock(&queue->lock);
    free(queue);
    spinlock_preempt_enable();
    return 0;
}

/* Reservations protect the queue while an allocation runs outside its lock.
 * Every admitted object keeps that reservation until final destruction. */
static bool fd_retirement_reserve(fd_retirement_queue_t *queue)
{
    if (!queue) return true;
    spinlock_lock(&queue->lock);
    bool admitted = !queue->closed && queue->live < queue->capacity;
    if (admitted) ++queue->live;
    spinlock_unlock(&queue->lock);
    return admitted;
}

static void fd_retirement_unreserve(fd_retirement_queue_t *queue)
{
    if (!queue) return;
    spinlock_lock(&queue->lock);
    --queue->live;
    spinlock_unlock(&queue->lock);
}

static void fd_retirement_enqueue(fd_retirement_queue_t *queue, fd_retirement_item_t *item,
                                   fd_retirement_kind_t kind, void *object)
{
    item->next = NULL;
    item->kind = kind;
    item->object = object;
    spinlock_lock(&queue->lock);
    if (queue->tail) queue->tail->next = item;
    else queue->head = item;
    queue->tail = item;
    ++queue->pending;
    spinlock_unlock(&queue->lock);
}

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

static fd_description_t *fd_description_create_internal(const fd_ops_t *ops, void *context,
                                                         fd_retirement_queue_t *queue)
{
    if (!ops)
    {
        return NULL;
    }
    if (!fd_retirement_reserve(queue)) return NULL;
    fd_description_t *description = calloc(1, sizeof(*description));
    if (!description)
    {
        fd_retirement_unreserve(queue);
        return NULL;
    }
    description->retirement_queue = queue;
    description->references = 1;
    description->ops = *ops;
    description->context = context;
    return description;
}

fd_description_t *fd_description_create(const fd_ops_t *ops, void *context)
{
    return fd_description_create_internal(ops, context, NULL);
}

fd_description_t *fd_description_create_deferred(const fd_ops_t *ops, void *context,
                                                 fd_retirement_queue_t *queue)
{
    return queue ? fd_description_create_internal(ops, context, queue) : NULL;
}

bool fd_description_get(fd_description_t *description)
{
    return description && fd_reference_get(&description->references);
}

bool fd_description_referenced(const fd_description_t *description)
{
    return description && __atomic_load_n(&description->references, __ATOMIC_ACQUIRE) != 0;
}

int fd_description_put(fd_description_t *description)
{
    if (!description) return 0;
    bool deferred = description->retirement_queue != NULL;
    if (deferred) spinlock_preempt_disable();
    if (__atomic_fetch_sub(&description->references, 1, __ATOMIC_ACQ_REL) != 1)
    {
        if (deferred) spinlock_preempt_enable();
        return 0;
    }
    if (deferred)
    {
        fd_retirement_enqueue(description->retirement_queue, &description->retirement,
                               FD_RETIRE_DESCRIPTION, description);
        spinlock_preempt_enable();
        return 0;
    }
    int result = 0;
    if (description->ops.close) result = description->ops.close(description->context);
    free(description);
    return result;
}

bool fd_description_is_deferred_to(const fd_description_t *description, const fd_retirement_queue_t *queue)
{
    return description && queue && description->retirement_queue == queue;
}

const fd_ops_t *fd_description_ops(const fd_description_t *description)
{
    return description ? &description->ops : NULL;
}

void *fd_description_context(const fd_description_t *description)
{
    return description ? description->context : NULL;
}

int fd_description_initialize_status(fd_description_t *description, uint32_t flags)
{
    uint32_t known = FD_STATUS_READ | FD_STATUS_WRITE | FD_STATUS_APPEND | FD_STATUS_NONBLOCK | FD_STATUS_SYNC;
    if (!description || (flags & ~known)) return -EINVAL;
    __atomic_store_n(&description->status_flags, flags, __ATOMIC_RELEASE);
    return 0;
}

uint32_t fd_description_status_flags(const fd_description_t *description)
{
    return description ? __atomic_load_n(&description->status_flags, __ATOMIC_ACQUIRE) : 0;
}

int fd_description_set_status_flags(fd_description_t *description, uint32_t flags)
{
    uint32_t mutable = FD_STATUS_APPEND | FD_STATUS_NONBLOCK;
    uint32_t known = mutable | FD_STATUS_READ | FD_STATUS_WRITE | FD_STATUS_SYNC;
    if (!description || (flags & ~known)) return -EINVAL;
    uint32_t old = __atomic_load_n(&description->status_flags, __ATOMIC_RELAXED), next;
    do { next = (old & ~mutable) | (flags & mutable); }
    while (!__atomic_compare_exchange_n(&description->status_flags, &old, next, false,
                                         __ATOMIC_RELEASE, __ATOMIC_RELAXED));
    return 0;
}

int fd_description_update_status_flags(fd_description_t *description, uint32_t mask, uint32_t flags)
{
    uint32_t mutable = FD_STATUS_APPEND | FD_STATUS_NONBLOCK;
    if (!description || (mask & ~mutable) || (flags & ~mask)) return -EINVAL;
    uint32_t old = __atomic_load_n(&description->status_flags, __ATOMIC_RELAXED), next;
    do { next = (old & ~mask) | flags; }
    while (!__atomic_compare_exchange_n(&description->status_flags, &old, next, false,
                                         __ATOMIC_RELEASE, __ATOMIC_RELAXED));
    return 0;
}

static fd_table_t *fd_table_create_internal(size_t capacity, fd_retirement_queue_t *queue)
{
    if (capacity == 0 || capacity > FD_TABLE_MAX_ENTRIES ||
        capacity > ((size_t)-1 - sizeof(fd_table_t)) / sizeof(fd_table_entry_t))
    {
        return NULL;
    }
    if (!fd_retirement_reserve(queue)) return NULL;
    fd_table_t *table = calloc(1, sizeof(*table) + capacity * sizeof(fd_table_entry_t));
    if (!table)
    {
        fd_retirement_unreserve(queue);
        return NULL;
    }
    table->retirement_queue = queue;
    table->references = 1;
    table->capacity = capacity;
    table->soft_limit = table->hard_limit = capacity;
    table->next_ticket = 1;
    spinlock_init(&table->lock);
    return table;
}

fd_table_t *fd_table_create(size_t capacity)
{
    return fd_table_create_internal(capacity, NULL);
}

fd_table_t *fd_table_create_deferred(size_t capacity, fd_retirement_queue_t *queue)
{
    return queue ? fd_table_create_internal(capacity, queue) : NULL;
}

bool fd_table_get(fd_table_t *table)
{
    return table && fd_reference_get(&table->references);
}

size_t fd_table_capacity(const fd_table_t *table)
{
    return table ? table->capacity : 0;
}

int fd_table_get_limits(fd_table_t *table, uint64_t *soft, uint64_t *hard)
{
    if (!table || !soft || !hard) return -EINVAL;
    spinlock_lock(&table->lock);
    int result = table->closed ? -EBADF : 0;
    if (!result) { *soft = table->soft_limit; *hard = table->hard_limit; }
    spinlock_unlock(&table->lock);
    return result;
}

int fd_table_set_limits(fd_table_t *table, uint64_t soft, uint64_t hard, bool raise_allowed)
{
    if (!table || soft > hard) return -EINVAL;
    spinlock_lock(&table->lock);
    int result = table->closed ? -EBADF :
        hard > table->capacity || (hard > table->hard_limit && !raise_allowed) ? -EPERM : 0;
    if (!result) { table->soft_limit = (size_t)soft; table->hard_limit = (size_t)hard; }
    spinlock_unlock(&table->lock);
    return result;
}

void fd_table_shutdown(fd_table_t *table)
{
    if (!table)
    {
        return;
    }
    bool deferred = table->retirement_queue != NULL;
    if (deferred) spinlock_preempt_disable();
    spinlock_lock(&table->lock);
    if (table->closed)
    {
        spinlock_unlock(&table->lock);
        if (deferred) spinlock_preempt_enable();
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
        table->entries[index].reservation = 0;
        fd_description_put(description);
    }
    if (deferred) spinlock_preempt_enable();
}

void fd_table_put(fd_table_t *table)
{
    if (!table) return;
    bool deferred = table->retirement_queue != NULL;
    if (deferred) spinlock_preempt_disable();
    if (__atomic_fetch_sub(&table->references, 1, __ATOMIC_ACQ_REL) != 1)
    {
        if (deferred) spinlock_preempt_enable();
        return;
    }
    if (deferred)
    {
        fd_retirement_enqueue(table->retirement_queue, &table->retirement,
                               FD_RETIRE_TABLE, table);
        spinlock_preempt_enable();
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
    if (table->retirement_queue && table->retirement_queue != description->retirement_queue)
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
        for (size_t index = (size_t)minimum; index < table->soft_limit; ++index)
        {
            if (!table->entries[index].description && !table->entries[index].reservation)
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

int fd_table_install_pair(fd_table_t *table, fd_description_t *first,
                           fd_description_t *second, uint32_t flags, int output[2])
{
    if (!table || !first || !second || !output || !fd_table_flags_valid(flags) ||
        (table->retirement_queue && (table->retirement_queue != first->retirement_queue ||
                                      table->retirement_queue != second->retirement_queue))) return -EINVAL;
    int slots[2] = { -1, -1 };
    int result = -EMFILE;
    bool retained = false;
    spinlock_preempt_disable();
    spinlock_lock(&table->lock);
    if (table->closed) result = -EBADF;
    else
    {
        unsigned found = 0;
        for (size_t index = 0; index < table->soft_limit && found < 2; ++index)
            if (!table->entries[index].description && !table->entries[index].reservation)
                slots[found++] = (int)index;
        if (found == 2)
        {
            retained = fd_description_get(first);
            if (!retained || !fd_description_get(second)) result = -EOVERFLOW;
            else
            {
                table->entries[slots[0]].description = first;
                table->entries[slots[1]].description = second;
                table->entries[slots[0]].flags = flags;
                table->entries[slots[1]].flags = flags;
                output[0] = slots[0]; output[1] = slots[1];
                result = 0;
            }
        }
    }
    spinlock_unlock(&table->lock);
    if (result && retained) fd_description_put(first);
    spinlock_preempt_enable();
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
    if (table->retirement_queue && table->retirement_queue != description->retirement_queue)
    {
        return -EINVAL;
    }
    int result = fd;
    spinlock_lock(&table->lock);
    if (table->closed)
    {
        result = -EBADF;
    }
    else if ((size_t)fd >= table->soft_limit)
    {
        result = -EMFILE;
    }
    else if (table->entries[fd].description || table->entries[fd].reservation)
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
    bool deferred = table->retirement_queue != NULL;
    if (deferred) spinlock_preempt_disable();
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
    result = description ? fd_description_put(description) : result;
    if (deferred) spinlock_preempt_enable();
    return result;
}

int fd_table_close(fd_table_t *table, int fd)
{
    return fd_table_remove(table, fd, NULL);
}

int fd_table_close_if(fd_table_t *table, int fd, fd_description_t *expected)
{
    return expected ? fd_table_remove(table, fd, expected) : -EINVAL;
}

static int fd_table_duplicate_from(fd_table_t *table, int source, int minimum, uint32_t flags, bool check_minimum)
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
        result = check_minimum && (size_t)minimum >= table->soft_limit ? -EINVAL : -EMFILE;
        for (size_t index = (size_t)minimum; index < table->soft_limit; ++index)
        {
            if (!table->entries[index].description && !table->entries[index].reservation)
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

int fd_table_dup(fd_table_t *table, int source, int minimum, uint32_t flags)
{
    return fd_table_duplicate_from(table, source, minimum, flags, false);
}

int fd_table_dup_minimum(fd_table_t *table, int source, int minimum, uint32_t flags)
{
    return fd_table_duplicate_from(table, source, minimum, flags, true);
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
    bool deferred = table->retirement_queue != NULL;
    if (deferred) spinlock_preempt_disable();
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
        else if ((size_t)destination >= table->soft_limit)
        {
            result = -EBADF;
        }
        else if (table->entries[destination].reservation)
        {
            result = -EBUSY;
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
    if (deferred) spinlock_preempt_enable();
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

typedef struct
{
    fd_table_t *table;
    int slot;
    uint64_t ticket;
} fd_reservation_t;

static int fd_reservation_close(void *context)
{
    fd_reservation_t *reservation = context;
    fd_table_t *table = reservation->table;
    if (table)
    {
        spinlock_lock(&table->lock);
        if (!table->closed && reservation->slot >= 0 &&
            table->entries[reservation->slot].reservation == reservation->ticket)
            table->entries[reservation->slot].reservation = 0;
        spinlock_unlock(&table->lock);
        fd_table_put(table);
    }
    free(reservation);
    return 0;
}

static const fd_ops_t fd_reservation_ops = { .close = fd_reservation_close };

bool fd_table_reservation_valid(const fd_description_t *description)
{
    return description && fd_description_ops(description)->close == fd_reservation_close;
}

int fd_table_reservation_cancel(fd_description_t *owner)
{
    if (!fd_table_reservation_valid(owner)) return -EINVAL;
    fd_reservation_t *reservation = fd_description_context(owner);
    fd_table_t *table = reservation->table;
    if (!table || reservation->slot < 0) return -EINVAL;
    int result = -EAGAIN;
    spinlock_lock(&table->lock);
    if (table->closed) result = -EBADF;
    else if (table->entries[reservation->slot].reservation == reservation->ticket)
    {
        table->entries[reservation->slot].reservation = 0;
        result = 0;
    }
    spinlock_unlock(&table->lock);
    return result;
}

int fd_table_reserve_deferred(fd_table_t *table, fd_description_t **out)
{
    if (!out) return -EINVAL;
    *out = NULL;
    if (!table || !table->retirement_queue || !spinlock_preempt_disabled()) return -EINVAL;
    fd_reservation_t *reservation = calloc(1, sizeof(*reservation));
    if (!reservation) return -ENOMEM;
    reservation->slot = -1;
    fd_description_t *owner = fd_description_create_deferred(&fd_reservation_ops, reservation, table->retirement_queue);
    if (!owner) { free(reservation); return -ENOMEM; }
    if (!fd_table_get(table)) { fd_description_put(owner); return -EOVERFLOW; }
    reservation->table = table;
    int result = -EMFILE;
    spinlock_lock(&table->lock);
    if (table->closed) result = -EBADF;
    else if (!table->next_ticket || table->next_ticket == (uint64_t)-1) result = -EOVERFLOW;
    else for (size_t index = 0; index < table->soft_limit; ++index)
    {
        fd_table_entry_t *entry = &table->entries[index];
        if (entry->description || entry->reservation) continue;
        reservation->slot = (int)index;
        reservation->ticket = table->next_ticket++;
        entry->reservation = reservation->ticket;
        result = 0;
        break;
    }
    spinlock_unlock(&table->lock);
    if (result) fd_description_put(owner);
    else *out = owner;
    return result;
}

int fd_table_reservation_commit(fd_description_t *owner, fd_description_t *target, uint32_t flags)
{
    if (!spinlock_preempt_disabled() || !fd_table_reservation_valid(owner) || !target ||
        fd_table_reservation_valid(target) || !fd_table_flags_valid(flags)) return -EINVAL;
    fd_reservation_t *reservation = fd_description_context(owner);
    fd_table_t *table = reservation->table;
    if (!table || reservation->slot < 0 || table->retirement_queue != target->retirement_queue) return -EINVAL;
    int result = -EAGAIN;
    spinlock_lock(&table->lock);
    if (table->closed) result = -EBADF;
    else if (table->entries[reservation->slot].reservation == reservation->ticket)
    {
        if (!fd_description_get(target)) result = -EOVERFLOW;
        else
        {
            fd_table_entry_t *entry = &table->entries[reservation->slot];
            entry->description = target;
            entry->flags = flags;
            entry->reservation = 0;
            result = reservation->slot;
        }
    }
    spinlock_unlock(&table->lock);
    return result;
}

int fd_table_clone_deferred(fd_table_t *source, bool close_on_exec, fd_table_t **out)
{
    if (!out) return -EINVAL;
    *out = NULL;
    if (!source || !source->retirement_queue || !spinlock_preempt_disabled()) return -EINVAL;
    fd_table_t *copy = fd_table_create_deferred(source->capacity, source->retirement_queue);
    if (!copy) return -ENOMEM;
    int result = 0;
    spinlock_lock(&source->lock);
    if (source->closed) result = -ECANCELED;
    else for (size_t index = 0; index < source->capacity; ++index)
    {
        fd_table_entry_t *entry = &source->entries[index];
        if (!entry->description || (close_on_exec && (entry->flags & FD_TABLE_CLOEXEC))) continue;
        if (!fd_description_get(entry->description)) { result = -EOVERFLOW; break; }
        copy->entries[index] = *entry;
    }
    if (!result) { copy->soft_limit = source->soft_limit; copy->hard_limit = source->hard_limit; }
    spinlock_unlock(&source->lock);
    if (result) fd_table_put(copy);
    else *out = copy;
    return result;
}

size_t fd_retirement_queue_drain(fd_retirement_queue_t *queue, size_t budget)
{
    if (!queue || !budget) return 0;
    spinlock_lock(&queue->lock);
    if (queue->drainers == (size_t)-1)
    {
        spinlock_unlock(&queue->lock);
        return 0;
    }
    ++queue->drainers;
    spinlock_unlock(&queue->lock);
    size_t drained = 0;
    while (drained < budget)
    {
        spinlock_lock(&queue->lock);
        fd_retirement_item_t *item = queue->head;
        if (item)
        {
            queue->head = item->next;
            if (!queue->head) queue->tail = NULL;
            --queue->pending;
        }
        spinlock_unlock(&queue->lock);
        if (!item) break;
        /* The detached zero-reference object belongs exclusively to this
         * persistent drainer. No callback or free runs under module locks. */
        if (item->kind == FD_RETIRE_DESCRIPTION)
        {
            fd_description_t *description = item->object;
            if (description->ops.close) (void)description->ops.close(description->context);
            free(description);
        }
        else
        {
            fd_table_t *table = item->object;
            fd_table_shutdown(table);
            free(table);
        }
        fd_retirement_unreserve(queue);
        ++drained;
    }
    spinlock_lock(&queue->lock);
    --queue->drainers;
    spinlock_unlock(&queue->lock);
    return drained;
}
