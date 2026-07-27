#ifndef SPINLOCK_H
#define SPINLOCK_H

#include "types.h"

typedef struct
{
    volatile uint32_t value;
} spinlock_t;

/* Implemented by the process scheduler. Generic spinlocks suppress scheduler
 * preemption while held so an owner cannot be switched out behind waiters. */
void spinlock_preempt_disable(void);
void spinlock_preempt_enable(void);
bool spinlock_preempt_disabled(void);

static inline void spinlock_init(spinlock_t *lock)
{
    if (lock)
    {
        lock->value = 0;
    }
}

static inline void spinlock_lock_raw(spinlock_t *lock)
{
    if (!lock)
    {
        return;
    }
    while (__sync_lock_test_and_set(&lock->value, 1) != 0)
    {
        while (lock->value)
        {
            __asm__ volatile ("pause");
        }
    }
}

static inline void spinlock_unlock_raw(spinlock_t *lock)
{
    if (!lock)
    {
        return;
    }
    __sync_lock_release(&lock->value);
}

static inline void spinlock_lock(spinlock_t *lock)
{
    if (!lock)
    {
        return;
    }
    spinlock_preempt_disable();
    spinlock_lock_raw(lock);
}

static inline void spinlock_unlock(spinlock_t *lock)
{
    if (!lock)
    {
        return;
    }
    spinlock_unlock_raw(lock);
    spinlock_preempt_enable();
}

/* Use these wrappers for locks shared with hard-IRQ handlers.  The caller's
 * interrupt-enable state is carried by the returned token, which makes nested
 * acquisition and acquisition from interrupt context restore the right state. */
static inline uint64_t spinlock_lock_irqsave(spinlock_t *lock)
{
    uint64_t flags;
    __asm__ volatile ("pushfq; pop %0" : "=r"(flags) :: "memory");
    if (!lock)
    {
        return flags;
    }
    __asm__ volatile ("cli" ::: "memory");
    spinlock_lock(lock);
    return flags;
}

static inline void spinlock_unlock_irqrestore(spinlock_t *lock, uint64_t flags)
{
    if (!lock)
    {
        return;
    }
    /* Keep the preemption-depth guard raised while IRQs are restored.  A
     * pending interrupt can run immediately at popfq; it must still defer
     * scheduler/timer work until this release sequence is complete. */
    spinlock_unlock_raw(lock);
    __asm__ volatile ("push %0; popfq" :: "r"(flags) : "memory", "cc");
    spinlock_preempt_enable();
}

#endif /* SPINLOCK_H */
