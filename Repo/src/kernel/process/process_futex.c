#include "process_internal.h"

/*
 * Process-private, 32-bit address waits. The expected-value check and waiter
 * publication are serialized with wake by the scheduler lock. A wake marks
 * the heap-owned thread before touching its queue, so a wake in the interval
 * before wait_queue_wait() enqueues cannot be lost.
 *
 * No user pointer is retained as a dereferenceable pointer. It is only a key;
 * the initial atomic load resolves owned physical backing under memory_lock.
 * Once asleep, the predicate reads the kernel thread's notification flag only.
 * Process termination already removes every thread from its wait/sleep queues,
 * and deferred thread reclamation owns all of this metadata's lifetime.
 */

uint64_t g_futex_wait_registrations;
uint64_t g_futex_wake_calls;
uint64_t g_futex_wake_candidates;
uint64_t g_futex_woken;
uint64_t g_futex_memory_busy_retries;
uint64_t g_futex_slow_read_reused, g_futex_epoch_retries;
/* Coarse clock accounting, never a claim of per-wake nanosecond accuracy. */
uint64_t g_futex_resume_count[SMP_MAX_CPUS], g_futex_resume_ticks[SMP_MAX_CPUS];
uint64_t g_futex_resume_max_ticks[SMP_MAX_CPUS];

static size_t futex_bucket(uintptr_t address)
{
    return ((address >> 2) ^ (address >> 12) ^ (address >> 20)) &
           (PROCESS_FUTEX_BUCKET_COUNT - 1u);
}

/* Every bucket/link operation uses the scheduler lock. The process owns the
 * bucket heads and the thread owns its intrusive links throughout a wait. */
static void futex_unlink_locked(thread_t *thread)
{
    if (!thread->futex_indexed) return;
    if (thread->futex_bucket_prev)
        thread->futex_bucket_prev->futex_bucket_next = thread->futex_bucket_next;
    else
        thread->process->futex_buckets[futex_bucket(thread->futex_address)] = thread->futex_bucket_next;
    if (thread->futex_bucket_next)
        thread->futex_bucket_next->futex_bucket_prev = thread->futex_bucket_prev;
    thread->futex_bucket_prev = NULL;
    thread->futex_bucket_next = NULL;
    thread->futex_indexed = false;
}

static void futex_register_locked(thread_t *thread, uintptr_t address)
{
    size_t bucket = futex_bucket(address);
    thread->futex_address = address;
    thread->futex_bucket_prev = NULL;
    thread->futex_bucket_next = thread->process->futex_buckets[bucket];
    if (thread->futex_bucket_next)
        thread->futex_bucket_next->futex_bucket_prev = thread;
    thread->process->futex_buckets[bucket] = thread;
    thread->futex_indexed = true;
    thread->futex_waiting = true;
}

void process_futex_cancel_wait_locked(thread_t *thread)
{
    if (!thread) return;
    futex_unlink_locked(thread);
    thread->futex_waiting = false;
    thread->futex_address = 0;
    thread->futex_interrupted = false;
}

static bool futex_address_valid(uintptr_t address)
{
    return (address & (sizeof(uint32_t) - 1u)) == 0 &&
           user_ptr_range_valid((const void *)address, sizeof(uint32_t));
}

static bool futex_notified(void *context)
{
    thread_t *thread = (thread_t *)context;
    return __atomic_load_n(&thread->futex_notified, __ATOMIC_ACQUIRE);
}

int process_futex_wait(uintptr_t address, uint32_t expected, uint32_t timeout_ms)
{
    thread_t *thread = current_thread_local();
    process_t *process = thread ? thread->process : NULL;
    if (!thread || !thread->is_user || !process || !process->is_user ||
        !futex_address_valid(address))
    {
        return SYSCALL_FUTEX_INVALID;
    }

    uint64_t flags;
    uint32_t value = 0;
    for (;;)
    {
        flags = scheduler_lock_acquire("futex_wait_register");
        if (thread->exited || thread->pending_destroy || !thread_lifetime_active(thread))
        {
            scheduler_lock_release(flags);
            return SYSCALL_FUTEX_INTERRUPTED;
        }
        bool busy = false;
        if (process_memory_try_read_user_u32(process, address, &value, &busy)) break;
        if (!busy)
        {
            scheduler_lock_release(flags);
            return SYSCALL_FUTEX_FAULT;
        }
        ++g_futex_memory_busy_retries;
        uint64_t wake_sequence = process->futex_wake_sequence;
        scheduler_lock_release(flags);
        /* Obtain a checked scalar outside scheduler serialization. Retain no
         * physical alias after memory_lock is released. A stable wake sequence
         * makes this load the comparison point: no wake can cross the gap to
         * registration unnoticed. If a wake did cross, retry with fresh data.
         * This avoids discarding a completed read and repeatedly competing
         * with page-by-page user copies for a second lock acquisition. */
        bool valid = process_memory_read_user_u32(process, address, &value);
        flags = scheduler_lock_acquire("futex_wait_validate");
        if (thread->exited || thread->pending_destroy || !thread_lifetime_active(thread))
        {
            scheduler_lock_release(flags);
            return SYSCALL_FUTEX_INTERRUPTED;
        }
        if (!valid)
        {
            scheduler_lock_release(flags);
            return SYSCALL_FUTEX_FAULT;
        }
        if (process->futex_wake_sequence == wake_sequence)
        {
            ++g_futex_slow_read_reused;
            break;
        }
        ++g_futex_epoch_retries;
        scheduler_lock_release(flags);
    }
    if (value != expected)
    {
        scheduler_lock_release(flags);
        return SYSCALL_FUTEX_AGAIN;
    }
    if (process_signal_pending_locked(thread))
    {
        scheduler_lock_release(flags);
        return SYSCALL_FUTEX_INTERRUPTED;
    }
    if (timeout_ms == 0)
    {
        scheduler_lock_release(flags);
        return SYSCALL_FUTEX_TIMED_OUT;
    }

    wait_queue_init(&thread->futex_queue);
    __atomic_store_n(&thread->futex_notified, false, __ATOMIC_RELEASE);
    thread->futex_interrupted = false;
    thread->futex_wake_stamped = false;
    futex_register_locked(thread, address);
    ++g_futex_wait_registrations;
    scheduler_lock_release(flags);

    if (timeout_ms == SYSCALL_FUTEX_WAIT_FOREVER)
    {
        wait_queue_wait(&thread->futex_queue, futex_notified, thread);
    }
    else
    {
        uint64_t frequency = timer_frequency();
        uint64_t ticks = (timeout_ms / 1000u) * frequency +
                         ((timeout_ms % 1000u) * frequency + 999u) / 1000u;
        if (ticks == 0)
        {
            ticks = 1;
        }
        (void)wait_queue_wait_timeout(&thread->futex_queue, futex_notified, thread, ticks);
    }

    flags = scheduler_lock_acquire("futex_wait_finish");
    bool notified = futex_notified(thread);
    bool interrupted = thread->futex_interrupted;
    if (thread->futex_wake_stamped && notified && !interrupted)
    {
        uint32_t cpu = current_cpu_index();
        if (cpu < SMP_MAX_CPUS)
        {
            uint64_t elapsed = timer_ticks() - thread->futex_woken_tick;
            ++g_futex_resume_count[cpu];
            g_futex_resume_ticks[cpu] += elapsed;
            if (elapsed > g_futex_resume_max_ticks[cpu]) g_futex_resume_max_ticks[cpu] = elapsed;
        }
    }
    thread->futex_wake_stamped = false;
    process_futex_cancel_wait_locked(thread);
    scheduler_lock_release(flags);
    return interrupted ? SYSCALL_FUTEX_INTERRUPTED : notified ? SYSCALL_FUTEX_OK : SYSCALL_FUTEX_TIMED_OUT;
}

int process_futex_wake(uintptr_t address, uint32_t max_waiters)
{
    thread_t *self = current_thread_local();
    process_t *process = self ? self->process : NULL;
    if (!self || !self->is_user || !process || !process->is_user ||
        !futex_address_valid(address))
    {
        return SYSCALL_FUTEX_INVALID;
    }

    uint64_t flags = scheduler_lock_acquire("futex_wake");
    ++g_futex_wake_calls;
    ++process->futex_wake_sequence;
    uint32_t count = 0;
    for (thread_t *thread = process->futex_buckets[futex_bucket(address)];
         thread && count < max_waiters && count < 0x7FFFFFFFu;
         )
    {
        thread_t *next = thread->futex_bucket_next;
        ++g_futex_wake_candidates;
        if (thread->pending_destroy || thread->exited ||
            !thread_lifetime_active(thread) || futex_notified(thread))
        {
            /* A terminating waiter may never return through wait_finish. */
            futex_unlink_locked(thread);
        }
        else if (thread->futex_address == address)
        {
            futex_unlink_locked(thread);
            thread->futex_woken_tick = timer_ticks();
            thread->futex_wake_stamped = true;
            __atomic_store_n(&thread->futex_notified, true, __ATOMIC_RELEASE);
            wait_queue_wake_all_locked(&thread->futex_queue);
            ++count;
        }
        thread = next;
    }
    g_futex_woken += count;
    scheduler_lock_release(flags);
    return (int)count;
}
