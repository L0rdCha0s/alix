#include "userlib.h"
#include "serial.h"

#define WORKERS 4u
#define ROUNDS 32u
#define INCREMENTS 128u

typedef struct
{
    alix_mutex_t mutex;
    alix_cond_t work;
    alix_cond_t changed;
    alix_thread_t threads[WORKERS];
    uint32_t ready;
    uint32_t tokens;
    uint32_t completed;
    uint32_t failures;
    uint32_t cpu_mask;
    uint32_t next_worker;
    uint32_t counter;
    volatile uint32_t word;
} shared_t;

static void worker(void *argument)
{
    shared_t *shared = (shared_t *)argument;
    uint32_t cpu = __atomic_fetch_add(&shared->next_worker, 1u, __ATOMIC_RELAXED);
    if (sys_thread_set_affinity(cpu) != 0 || sys_thread_cpu() != cpu)
    {
        alix_mutex_lock(&shared->mutex);
        ++shared->failures;
        (void)alix_cond_signal(&shared->changed);
        alix_mutex_unlock(&shared->mutex);
        return;
    }
    __atomic_fetch_or(&shared->cpu_mask, 1u << cpu, __ATOMIC_RELAXED);
    for (uint32_t i = 0; i < INCREMENTS; ++i)
    {
        alix_mutex_lock(&shared->mutex);
        uint32_t prior = shared->counter;
        if ((i & 15u) == 0)
        {
            /* Deliberately yield while owning the mutex so other CPUs must
             * sleep on contention; an unprotected update loses increments. */
            (void)sys_yield();
        }
        shared->counter = prior + 1;
        alix_mutex_unlock(&shared->mutex);
    }
    alix_mutex_lock(&shared->mutex);
    ++shared->ready;
    (void)alix_cond_signal(&shared->changed);
    for (uint32_t round = 0; round < ROUNDS; ++round)
    {
        while (shared->tokens == 0)
        {
            if (alix_cond_timedwait(&shared->work, &shared->mutex, 3000) != 0)
            {
                ++shared->failures;
                alix_mutex_unlock(&shared->mutex);
                return;
            }
        }
        --shared->tokens;
        ++shared->completed;
        (void)alix_cond_signal(&shared->changed);
    }
    alix_mutex_unlock(&shared->mutex);
}

static bool wait_count(shared_t *shared, uint32_t *count, uint32_t expected)
{
    while (*count < expected && shared->failures == 0)
    {
        int result = alix_cond_timedwait(&shared->changed, &shared->mutex, 3000);
        if (result != 0)
        {
            ++shared->failures;
            return false;
        }
    }
    return shared->failures == 0;
}

int main(void)
{
    /* Every shared object and thread argument is heap-owned. */
    shared_t *shared = (shared_t *)calloc(1, sizeof(*shared));
    if (!shared)
    {
        serial_printf("THREAD_SYNC_TEST: FAIL allocation\n");
        return 1;
    }
    alix_mutex_init(&shared->mutex);
    alix_cond_init(&shared->work);
    alix_cond_init(&shared->changed);
    if (sys_futex_wait(NULL, 0, 0) != SYSCALL_FUTEX_INVALID ||
        sys_futex_wait((volatile uint32_t *)((uintptr_t)&shared->word + 1), 0, 0) != SYSCALL_FUTEX_INVALID ||
        sys_futex_wait((volatile uint32_t *)0x00000001F0000000ULL, 0, 0) != SYSCALL_FUTEX_FAULT ||
        sys_futex_wait(&shared->word, 1, ALIX_WAIT_FOREVER) != SYSCALL_FUTEX_AGAIN ||
        sys_futex_wait(&shared->word, 0, 0) != SYSCALL_FUTEX_TIMED_OUT ||
        sys_futex_wake(&shared->word, 0) != 0)
    {
        serial_printf("THREAD_SYNC_TEST: FAIL validation\n");
        free(shared);
        return 1;
    }
    uint64_t started = sys_monotonic_millis();
    int timeout = sys_futex_wait(&shared->word, 0, 25);
    uint64_t elapsed = sys_monotonic_millis() - started;
    if (timeout != SYSCALL_FUTEX_TIMED_OUT || elapsed < 20 || elapsed > 2000)
    {
        serial_printf("THREAD_SYNC_TEST: FAIL timeout result=%d elapsed=%llu\n", timeout, (unsigned long long)elapsed);
        free(shared);
        return 1;
    }
    alix_mutex_lock(&shared->mutex);
    if (alix_cond_timedwait(&shared->work, &shared->mutex, 1) != SYSCALL_FUTEX_TIMED_OUT ||
        __atomic_load_n(&shared->mutex.state, __ATOMIC_ACQUIRE) == 0)
    {
        serial_printf("THREAD_SYNC_TEST: FAIL reacquire\n");
        return 1;
    }
    alix_mutex_unlock(&shared->mutex);

    uint32_t created = 0;
    for (; created < WORKERS; ++created)
    {
        if (alix_thread_create(&shared->threads[created], "sync_worker", worker, shared) != 0)
        {
            serial_printf("THREAD_SYNC_TEST: FAIL thread create\n");
            /* Exiting the process cancels its blocked threads; do not free
             * shared state while a worker can still reference it. */
            return 1;
        }
    }
    alix_mutex_lock(&shared->mutex);
    bool okay = wait_count(shared, &shared->ready, WORKERS);
    for (uint32_t round = 0; okay && round < ROUNDS; ++round)
    {
        shared->tokens += WORKERS;
        okay = alix_cond_broadcast(&shared->work) == 0 &&
               wait_count(shared, &shared->completed, (round + 1) * WORKERS);
    }
    alix_mutex_unlock(&shared->mutex);
    if (!okay)
    {
        serial_printf("THREAD_SYNC_TEST: FAIL handoff\n");
        return 1;
    }
    for (uint32_t i = 0; i < created; ++i)
    {
        if (alix_thread_join(shared->threads[i], NULL) != 0)
        {
            serial_printf("THREAD_SYNC_TEST: FAIL join\n");
            return 1;
        }
    }
    okay = shared->failures == 0 && shared->cpu_mask == ((1u << WORKERS) - 1u) &&
           shared->completed == WORKERS * ROUNDS && shared->tokens == 0 &&
           shared->counter == WORKERS * INCREMENTS;
    serial_printf("THREAD_SYNC_TEST: %s workers=%u cpu_mask=0x%X handoffs=%u counter=%u\n", okay ? "PASS" : "FAIL", WORKERS, shared->cpu_mask, shared->completed, shared->counter);
    free(shared);
    return okay ? 0 : 1;
}
