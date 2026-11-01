#include "libc.h"
#include "string.h"

/* GCC/Clang implement naturally aligned 1/2/4/8-byte C11 atomics in-line on
 * x86-64. Larger aggregate atomics use this shared, blocking runtime gate.
 * Stronger sequential ordering is permitted for every requested memory order. */
static alix_mutex_t atomic_gate;
void alix_atomic_load(size_t, const volatile void *, void *, int) __asm__("__atomic_load");
void alix_atomic_store(size_t, volatile void *, const void *, int) __asm__("__atomic_store");
void alix_atomic_exchange(size_t, volatile void *, const void *, void *, int) __asm__("__atomic_exchange");
bool alix_atomic_compare_exchange(size_t, volatile void *, void *, const void *, int, int) __asm__("__atomic_compare_exchange");
bool alix_atomic_is_lock_free(size_t, const volatile void *) __asm__("__atomic_is_lock_free");

void alix_atomic_load(size_t size, const volatile void *source, void *output, int order)
{
    (void)order;
    alix_mutex_lock(&atomic_gate);
    memcpy(output, (const void *)source, size);
    alix_mutex_unlock(&atomic_gate);
}
void alix_atomic_store(size_t size, volatile void *target, const void *value, int order)
{
    (void)order;
    alix_mutex_lock(&atomic_gate);
    memcpy((void *)target, value, size);
    alix_mutex_unlock(&atomic_gate);
}
void alix_atomic_exchange(size_t size, volatile void *target, const void *value, void *old, int order)
{
    (void)order;
    alix_mutex_lock(&atomic_gate);
    memcpy(old, (const void *)target, size);
    memcpy((void *)target, value, size);
    alix_mutex_unlock(&atomic_gate);
}
bool alix_atomic_compare_exchange(size_t size, volatile void *target, void *expected,
                                   const void *desired, int success, int failure)
{
    (void)success; (void)failure;
    alix_mutex_lock(&atomic_gate);
    bool equal = memcmp((const void *)target, expected, size) == 0;
    if (equal) memcpy((void *)target, desired, size);
    else memcpy(expected, (const void *)target, size);
    alix_mutex_unlock(&atomic_gate);
    return equal;
}
bool alix_atomic_is_lock_free(size_t size, const volatile void *address)
{
    return (size == 1 || size == 2 || size == 4 || size == 8) && !((uintptr_t)address & (size - 1));
}

typedef unsigned __int128 atomic_u128;
atomic_u128 alix_load_16(const volatile void *, int) __asm__("__atomic_load_16");
void alix_store_16(volatile void *, atomic_u128, int) __asm__("__atomic_store_16");
atomic_u128 alix_exchange_16(volatile void *, atomic_u128, int) __asm__("__atomic_exchange_16");
bool alix_compare_16(volatile void *, void *, atomic_u128, int, int) __asm__("__atomic_compare_exchange_16");
atomic_u128 alix_load_16(const volatile void *source, int order)
{
    atomic_u128 result;
    alix_atomic_load(sizeof(result), source, &result, order);
    return result;
}
void alix_store_16(volatile void *target, atomic_u128 value, int order)
{
    alix_atomic_store(sizeof(value), target, &value, order);
}
atomic_u128 alix_exchange_16(volatile void *target, atomic_u128 value, int order)
{
    atomic_u128 result;
    alix_atomic_exchange(sizeof(value), target, &value, &result, order);
    return result;
}
bool alix_compare_16(volatile void *target, void *expected, atomic_u128 desired, int success, int failure)
{
    return alix_atomic_compare_exchange(sizeof(desired), target, expected, &desired, success, failure);
}
#define ATOMIC_FETCH_16(operation, expression) \
atomic_u128 alix_fetch_##operation##_16(volatile void *, atomic_u128, int) __asm__("__atomic_fetch_" #operation "_16"); \
atomic_u128 alix_fetch_##operation##_16(volatile void *target, atomic_u128 value, int order) \
{ \
    (void)order; atomic_u128 previous, next; \
    alix_mutex_lock(&atomic_gate); \
    memcpy(&previous, (const void *)target, sizeof(previous)); \
    next = (expression); memcpy((void *)target, &next, sizeof(next)); \
    alix_mutex_unlock(&atomic_gate); return previous; \
}
ATOMIC_FETCH_16(add, previous + value)
ATOMIC_FETCH_16(sub, previous - value)
ATOMIC_FETCH_16(and, previous & value)
ATOMIC_FETCH_16(or, previous | value)
ATOMIC_FETCH_16(xor, previous ^ value)
ATOMIC_FETCH_16(nand, ~(previous & value))
#undef ATOMIC_FETCH_16
