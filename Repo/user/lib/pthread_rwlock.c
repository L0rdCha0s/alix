#include "pthread.h"
#include "stdlib.h"
#include "errno.h"

#define RWLOCK_MAGIC 0x50545257u
#define RWATTRIBUTE_MAGIC 0x50545241u
#define RWCOUNT_MAX ((uint32_t)-1)

enum { RW_RESERVED, RW_READER_WAIT, RW_WRITER_WAIT, RW_READER_HELD };

typedef struct alix_rwlock_record
{
    pthread_rwlock_t *lock;
    struct alix_rwlock_record *thread_next;
    struct alix_rwlock_record *queue_next;
    uint32_t depth;
    uint32_t kind;
    bool eligible;
} rw_record_t;

typedef struct
{
    rw_record_t *records;
    rw_record_t *spare;
    bool cleanup_registered;
} rw_thread_t;

static _Thread_local rw_thread_t rw_thread;
extern int __cxa_thread_atexit_impl(void (*function)(void *), void *argument, void *dso);
extern void *__dso_handle;

static int rw_status(int status) { return status < 0 ? -status : status; }
static void rw_notify(pthread_rwlock_t *lock)
{
    if (lock->waiting_readers || lock->waiting_writers)
        (void)alix_cond_broadcast(&lock->changed);
}

/* Every queue pointer refers to a heap record, never a caller's stack. */
static void rw_remove_waiter(pthread_rwlock_t *lock, rw_record_t *record)
{
    rw_record_t **cursor = record->kind == RW_READER_WAIT ? &lock->read_head : &lock->write_head;
    rw_record_t *previous = NULL;
    while (*cursor && *cursor != record)
    {
        previous = *cursor;
        cursor = &(*cursor)->queue_next;
    }
    if (!*cursor) return;
    *cursor = record->queue_next;
    if (record->kind == RW_READER_WAIT)
    {
        --lock->waiting_readers;
        if (record->eligible) --lock->reader_batch;
    }
    else
    {
        --lock->waiting_writers;
        if (lock->write_tail == record) lock->write_tail = previous;
    }
    record->queue_next = NULL;
    record->eligible = false;
    record->kind = RW_RESERVED;
}

static void rw_thread_cleanup(void *argument)
{
    rw_thread_t *state = argument;
    rw_record_t *record = state->records;
    state->records = NULL;
    while (record)
    {
        rw_record_t *next = record->thread_next;
        if (record->kind == RW_READER_WAIT || record->kind == RW_WRITER_WAIT)
        {
            pthread_rwlock_t *lock = record->lock;
            alix_mutex_lock(&lock->gate);
            rw_remove_waiter(lock, record);
            rw_notify(lock);
            alix_mutex_unlock(&lock->gate);
        }
        /* These locks are not robust. Exiting while holding a read lock
         * leaves it held; metadata can still be reclaimed without dangling
         * pointers because held-reader records are only in this TLS list. */
        free(record);
        record = next;
    }
    free(state->spare);
    state->spare = NULL;
    state->cleanup_registered = false;
}

static rw_record_t *rw_reader_owned(pthread_rwlock_t *lock)
{
    for (rw_record_t *record = rw_thread.records; record; record = record->thread_next)
        if (record->lock == lock && record->kind == RW_READER_HELD) return record;
    return NULL;
}

static rw_record_t *rw_record_reserve(pthread_rwlock_t *lock)
{
    int saved_errno = errno;
    if (!rw_thread.cleanup_registered)
    {
        int result = __cxa_thread_atexit_impl(rw_thread_cleanup, &rw_thread, __dso_handle);
        errno = saved_errno;
        if (result != 0) return NULL;
        rw_thread.cleanup_registered = true;
    }
    rw_record_t *record = rw_thread.spare;
    if (record) rw_thread.spare = NULL;
    else record = malloc(sizeof(*record));
    errno = saved_errno;
    if (!record) return NULL;
    *record = (rw_record_t){.lock = lock, .thread_next = rw_thread.records};
    rw_thread.records = record;
    return record;
}

static void rw_record_release(rw_record_t *record)
{
    rw_record_t **cursor = &rw_thread.records;
    while (*cursor && *cursor != record) cursor = &(*cursor)->thread_next;
    if (*cursor) *cursor = record->thread_next;
    record->lock = NULL;
    record->thread_next = NULL;
    if (!rw_thread.spare) rw_thread.spare = record;
    else
    {
        int saved_errno = errno;
        free(record);
        errno = saved_errno;
    }
}

int pthread_rwlockattr_init(pthread_rwlockattr_t *attribute)
{
    if (!attribute) return EINVAL;
    *attribute = (pthread_rwlockattr_t){PTHREAD_PROCESS_PRIVATE, RWATTRIBUTE_MAGIC};
    return 0;
}

int pthread_rwlockattr_destroy(pthread_rwlockattr_t *attribute)
{
    if (!attribute || attribute->magic != RWATTRIBUTE_MAGIC) return EINVAL;
    attribute->magic = 0;
    return 0;
}

int pthread_rwlockattr_setpshared(pthread_rwlockattr_t *attribute, int shared)
{
    if (!attribute || attribute->magic != RWATTRIBUTE_MAGIC) return EINVAL;
    if (shared == PTHREAD_PROCESS_SHARED) return ENOTSUP;
    return shared == PTHREAD_PROCESS_PRIVATE ? 0 : EINVAL;
}

int pthread_rwlockattr_getpshared(const pthread_rwlockattr_t *attribute, int *shared)
{
    if (!attribute || attribute->magic != RWATTRIBUTE_MAGIC || !shared) return EINVAL;
    *shared = attribute->shared;
    return 0;
}

int pthread_rwlock_init(pthread_rwlock_t *lock, const pthread_rwlockattr_t *attribute)
{
    if (!lock || (attribute && attribute->magic != RWATTRIBUTE_MAGIC)) return EINVAL;
    if (attribute && attribute->shared != PTHREAD_PROCESS_PRIVATE) return ENOTSUP;
    *lock = (pthread_rwlock_t)PTHREAD_RWLOCK_INITIALIZER;
    return 0;
}

int pthread_rwlock_destroy(pthread_rwlock_t *lock)
{
    if (!lock || lock->magic != RWLOCK_MAGIC) return EINVAL;
    if (!alix_mutex_trylock(&lock->gate)) return EBUSY;
    int result = 0;
    if (lock->writer || lock->readers || lock->waiting_readers || lock->waiting_writers ||
        lock->reader_batch || lock->read_head || lock->write_head) result = EBUSY;
    else lock->magic = 0;
    alix_mutex_unlock(&lock->gate);
    return result;
}

static int rw_read(pthread_rwlock_t *lock, bool try_only)
{
    if (!lock || lock->magic != RWLOCK_MAGIC) return EINVAL;
    rw_record_t *record = rw_reader_owned(lock);
    bool recursive = record != NULL;
    if (!record && !(record = rw_record_reserve(lock))) return EAGAIN;
    int result = 0;
    bool removed_waiter = false;
    alix_mutex_lock(&lock->gate);
    if (lock->magic != RWLOCK_MAGIC) result = EINVAL;
    else if (!try_only && lock->writer && lock->writer == pthread_self()) result = EDEADLK;
    else if (recursive)
    {
        if (lock->readers == RWCOUNT_MAX || record->depth == RWCOUNT_MAX) result = EAGAIN;
        else { ++record->depth; ++lock->readers; }
    }
    else
    {
        if (lock->writer || lock->write_head)
        {
            if (try_only) result = EBUSY;
            else if (lock->waiting_readers == RWCOUNT_MAX) result = EAGAIN;
            else
            {
                record->kind = RW_READER_WAIT;
                record->queue_next = lock->read_head;
                lock->read_head = record;
                ++lock->waiting_readers;
                while (lock->writer || (lock->write_head && !record->eligible))
                {
                    int waited = rw_status(alix_cond_wait(&lock->changed, &lock->gate));
                    if (waited && waited != EINTR) { result = waited; break; }
                }
                rw_remove_waiter(lock, record);
                removed_waiter = true;
            }
        }
        if (!result)
        {
            if (lock->readers == RWCOUNT_MAX) result = EAGAIN;
            else { ++lock->readers; record->depth = 1; record->kind = RW_READER_HELD; }
        }
    }
    if (result && removed_waiter) rw_notify(lock);
    alix_mutex_unlock(&lock->gate);
    if (result && !recursive) rw_record_release(record);
    return result;
}

int pthread_rwlock_rdlock(pthread_rwlock_t *lock) { return rw_read(lock, false); }
int pthread_rwlock_tryrdlock(pthread_rwlock_t *lock) { return rw_read(lock, true); }

static int rw_write(pthread_rwlock_t *lock, bool try_only)
{
    if (!lock || lock->magic != RWLOCK_MAGIC) return EINVAL;
    uint64_t self = pthread_self();
    rw_record_t *record = NULL;
    int result = 0;
    bool removed_waiter = false;
    alix_mutex_lock(&lock->gate);
    if (lock->magic != RWLOCK_MAGIC) result = EINVAL;
    else if (lock->writer == self || rw_reader_owned(lock)) result = try_only ? EBUSY : EDEADLK;
    else if (!lock->writer && !lock->readers && !lock->reader_batch && !lock->write_head)
        lock->writer = self;
    else if (try_only) result = EBUSY;
    else
    {
        /* Allocate before joining shared queues and outside the gate. */
        alix_mutex_unlock(&lock->gate);
        record = rw_record_reserve(lock);
        if (!record) return EAGAIN;
        alix_mutex_lock(&lock->gate);
        if (lock->magic != RWLOCK_MAGIC) result = EINVAL;
        else if (lock->waiting_writers == RWCOUNT_MAX) result = EAGAIN;
        else
        {
            record->kind = RW_WRITER_WAIT;
            if (lock->write_tail) lock->write_tail->queue_next = record;
            else lock->write_head = record;
            lock->write_tail = record;
            ++lock->waiting_writers;
            while (lock->writer || lock->readers || lock->reader_batch || lock->write_head != record)
            {
                int waited = rw_status(alix_cond_wait(&lock->changed, &lock->gate));
                if (waited && waited != EINTR) { result = waited; break; }
            }
            rw_remove_waiter(lock, record);
            removed_waiter = true;
            if (!result) lock->writer = self;
        }
    }
    if (result && removed_waiter) rw_notify(lock);
    alix_mutex_unlock(&lock->gate);
    if (record) rw_record_release(record);
    return result;
}

int pthread_rwlock_wrlock(pthread_rwlock_t *lock) { return rw_write(lock, false); }
int pthread_rwlock_trywrlock(pthread_rwlock_t *lock) { return rw_write(lock, true); }

int pthread_rwlock_unlock(pthread_rwlock_t *lock)
{
    if (!lock || lock->magic != RWLOCK_MAGIC) return EINVAL;
    rw_record_t *released = NULL;
    int result = 0;
    alix_mutex_lock(&lock->gate);
    if (lock->magic != RWLOCK_MAGIC) result = EINVAL;
    else if (lock->writer)
    {
        if (lock->writer != pthread_self()) result = EPERM;
        else
        {
            lock->writer = 0;
            /* Admit this finite reader cohort before the next FIFO writer.
             * Later arrivals have eligible=false and cannot extend it. */
            lock->reader_batch = lock->waiting_readers;
            for (rw_record_t *record = lock->read_head; record; record = record->queue_next)
                record->eligible = true;
            rw_notify(lock);
        }
    }
    else
    {
        rw_record_t *record = rw_reader_owned(lock);
        if (!record || !lock->readers) result = EPERM;
        else
        {
            --lock->readers;
            if (--record->depth == 0) { record->kind = RW_RESERVED; released = record; }
            if (!lock->readers) rw_notify(lock);
        }
    }
    alix_mutex_unlock(&lock->gate);
    if (released) rw_record_release(released);
    return result;
}
