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

    uint64_t flags = scheduler_lock_acquire("futex_wait_register");
    uint32_t value = 0;
    if (!process_memory_read_user_u32(process, address, &value))
    {
        scheduler_lock_release(flags);
        return SYSCALL_FUTEX_FAULT;
    }
    if (value != expected)
    {
        scheduler_lock_release(flags);
        return SYSCALL_FUTEX_AGAIN;
    }
    if (timeout_ms == 0)
    {
        scheduler_lock_release(flags);
        return SYSCALL_FUTEX_TIMED_OUT;
    }

    wait_queue_init(&thread->futex_queue);
    thread->futex_address = address;
    __atomic_store_n(&thread->futex_notified, false, __ATOMIC_RELEASE);
    thread->futex_waiting = true;
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
    thread->futex_waiting = false;
    thread->futex_address = 0;
    scheduler_lock_release(flags);
    return notified ? SYSCALL_FUTEX_OK : SYSCALL_FUTEX_TIMED_OUT;
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
    spinlock_lock(&process->threads_lock);
    uint32_t count = 0;
    for (thread_t *thread = process->threads;
         thread && count < max_waiters && count < 0x7FFFFFFFu;
         thread = thread->process_next)
    {
        if (!thread->futex_waiting || thread->futex_address != address ||
            thread->pending_destroy || thread->exited ||
            !thread_lifetime_active(thread) || futex_notified(thread))
        {
            continue;
        }
        __atomic_store_n(&thread->futex_notified, true, __ATOMIC_RELEASE);
        wait_queue_wake_all_locked(&thread->futex_queue);
        ++count;
    }
    spinlock_unlock(&process->threads_lock);
    scheduler_lock_release(flags);
    return (int)count;
}
