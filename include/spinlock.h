#ifndef SPINLOCK_H
#define SPINLOCK_H

#include "types.h"

typedef struct
{
    volatile uint32_t value;
} spinlock_t;

static inline void spinlock_init(spinlock_t *lock)
{
    if (lock)
    {
        lock->value = 0;
    }
}

static inline void spinlock_lock(spinlock_t *lock)
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

static inline void spinlock_unlock(spinlock_t *lock)
{
    if (!lock)
    {
        return;
    }
    __sync_lock_release(&lock->value);
}

#endif /* SPINLOCK_H */
