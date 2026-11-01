#include "semaphore.h"
#include "usyscall.h"
#include "errno.h"
#include <stdint.h>

#define ALIX_SEM_MAGIC 0x53454D41u
_Static_assert(__atomic_always_lock_free(4, 0), "sem_post requires lock-free 32-bit atomics");

static bool sem_valid(sem_t *semaphore)
{
    return semaphore && __atomic_load_n(&semaphore->magic, __ATOMIC_ACQUIRE) == ALIX_SEM_MAGIC;
}

static int sem_error(int error) { errno = error; return -1; }

static bool sem_take(sem_t *semaphore)
{
    uint32_t value = __atomic_load_n(&semaphore->value, __ATOMIC_RELAXED);
    while (value)
        if (__atomic_compare_exchange_n(&semaphore->value, &value, value - 1, false,
                                          __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return true;
    return false;
}

int sem_init(sem_t *semaphore, int shared, unsigned value)
{
    if (!semaphore || value > SEM_VALUE_MAX) return sem_error(EINVAL);
    if (shared) return sem_error(ENOTSUP);
    semaphore->value = value; semaphore->sequence = 0; semaphore->waiters = 0;
    __atomic_store_n(&semaphore->magic, ALIX_SEM_MAGIC, __ATOMIC_RELEASE);
    return 0;
}

int sem_destroy(sem_t *semaphore)
{
    if (!sem_valid(semaphore)) return sem_error(EINVAL);
    if (__atomic_load_n(&semaphore->waiters, __ATOMIC_ACQUIRE)) return sem_error(EBUSY);
    __atomic_store_n(&semaphore->magic, 0, __ATOMIC_RELEASE);
    return 0;
}

int sem_post(sem_t *semaphore)
{
    if (!sem_valid(semaphore)) return sem_error(EINVAL);
    uint32_t value = __atomic_load_n(&semaphore->value, __ATOMIC_RELAXED);
    do
    {
        if (value >= SEM_VALUE_MAX) return sem_error(EOVERFLOW);
    } while (!__atomic_compare_exchange_n(&semaphore->value, &value, value + 1, false,
                                           __ATOMIC_RELEASE, __ATOMIC_RELAXED));
    __atomic_add_fetch(&semaphore->sequence, 1u, __ATOMIC_SEQ_CST);
    if (__atomic_load_n(&semaphore->waiters, __ATOMIC_SEQ_CST))
        (void)sys_futex_wake(&semaphore->sequence, 1);
    return 0;
}

int sem_trywait(sem_t *semaphore)
{
    if (!sem_valid(semaphore)) return sem_error(EINVAL);
    return sem_take(semaphore) ? 0 : sem_error(EAGAIN);
}

/* Convert an absolute realtime deadline to a bounded futex sleep. Recheck the
 * realtime clock after each timeout, including changes made by time sync. */
static int sem_remaining(const struct timespec *deadline, uint32_t *milliseconds)
{
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now)) return errno;
    if (deadline->tv_sec < now.tv_sec ||
        (deadline->tv_sec == now.tv_sec && deadline->tv_nsec <= now.tv_nsec)) return ETIMEDOUT;
    uint64_t seconds = (uint64_t)deadline->tv_sec - (uint64_t)now.tv_sec;
    int64_t nanoseconds = deadline->tv_nsec - now.tv_nsec;
    if (nanoseconds < 0) { --seconds; nanoseconds += 1000000000; }
    *milliseconds = seconds ? 1000u : (uint32_t)((nanoseconds + 999999) / 1000000);
    if (!*milliseconds) *milliseconds = 1;
    return 0;
}

static int sem_wait_common(sem_t *semaphore, const struct timespec *deadline, bool timed)
{
    if (!sem_valid(semaphore)) return sem_error(EINVAL);
    if (sem_take(semaphore)) return 0;
    if (timed && (!deadline || deadline->tv_nsec < 0 || deadline->tv_nsec >= 1000000000))
        return sem_error(EINVAL);
    __atomic_add_fetch(&semaphore->waiters, 1u, __ATOMIC_SEQ_CST);
    int error = 0;
    for (;;)
    {
        uint32_t sequence = __atomic_load_n(&semaphore->sequence, __ATOMIC_SEQ_CST);
        if (sem_take(semaphore)) break;
        uint32_t timeout = SYSCALL_FUTEX_WAIT_FOREVER;
        if (timed && (error = sem_remaining(deadline, &timeout))) break;
        int result = sys_futex_wait(&semaphore->sequence, sequence, timeout);
        if (result == SYSCALL_FUTEX_OK || result == SYSCALL_FUTEX_AGAIN ||
            result == SYSCALL_FUTEX_TIMED_OUT) continue;
        error = result < 0 ? -result : EIO;
        break;
    }
    __atomic_sub_fetch(&semaphore->waiters, 1u, __ATOMIC_RELEASE);
    return error ? sem_error(error) : 0;
}

int sem_wait(sem_t *semaphore) { return sem_wait_common(semaphore, NULL, false); }
int sem_timedwait(sem_t *semaphore, const struct timespec *deadline)
{
    return sem_wait_common(semaphore, deadline, true);
}
int sem_getvalue(sem_t *semaphore, int *value)
{
    if (!sem_valid(semaphore) || !value) return sem_error(EINVAL);
    *value = (int)__atomic_load_n(&semaphore->value, __ATOMIC_RELAXED);
    return 0;
}
