#include "userlib.h"
#include "serial.h"
#include "errno.h"
#include "stdlib.h"
#include "sys/mman.h"
#include "sys/random.h"

#define ENTROPY_WORKERS 8u
#define ENTROPY_ROUNDS 64u
#define ENTROPY_SAMPLE_BYTES 256u
#define PAGE_BYTES 4096u

typedef struct entropy_shared entropy_shared_t;
typedef struct
{
    entropy_shared_t *shared;
    alix_thread_t thread;
    unsigned cpu;
    uint8_t samples[2][ENTROPY_SAMPLE_BYTES];
} entropy_worker_t;

struct entropy_shared
{
    entropy_worker_t workers[ENTROPY_WORKERS];
    volatile uint32_t ready;
    volatile uint32_t start;
    volatile uint32_t failures;
    volatile uint32_t cpu_mask;
};

static int failure(const char *reason)
{
    serial_printf("ENTROPY_TEST: FAIL %s\n", reason);
    return 1;
}

static bool filled_with(const uint8_t *bytes, size_t count, uint8_t value)
{
    for (size_t i = 0; i < count; ++i)
    {
        if (bytes[i] != value)
        {
            return false;
        }
    }
    return true;
}

static bool wait_value(volatile uint32_t *value, uint32_t expected)
{
    uint64_t started = sys_monotonic_millis();
    while (__atomic_load_n(value, __ATOMIC_ACQUIRE) != expected)
    {
        if (sys_monotonic_millis() - started > 5000)
        {
            return false;
        }
        sys_yield();
    }
    return true;
}

static void entropy_worker(void *argument)
{
    entropy_worker_t *worker = argument;
    entropy_shared_t *shared = worker->shared;
    if (sys_thread_set_affinity(worker->cpu) != 0 || sys_thread_cpu() != worker->cpu)
    {
        __atomic_add_fetch(&shared->failures, 1, __ATOMIC_RELAXED);
        __atomic_add_fetch(&shared->ready, 1, __ATOMIC_RELEASE);
        return;
    }
    __atomic_fetch_or(&shared->cpu_mask, 1u << worker->cpu, __ATOMIC_RELAXED);
    __atomic_add_fetch(&shared->ready, 1, __ATOMIC_RELEASE);
    if (!wait_value(&shared->start, 1))
    {
        __atomic_add_fetch(&shared->failures, 1, __ATOMIC_RELAXED);
        return;
    }
    for (unsigned round = 0; round < ENTROPY_ROUNDS; ++round)
    {
        uint8_t *sample = worker->samples[round & 1u];
        uint8_t *previous = worker->samples[(round & 1u) ^ 1u];
        if (getentropy(sample, ENTROPY_SAMPLE_BYTES) != 0 ||
            filled_with(sample, ENTROPY_SAMPLE_BYTES, 0) ||
            (round && memcmp(sample, previous, ENTROPY_SAMPLE_BYTES) == 0) ||
            sys_thread_cpu() != worker->cpu)
        {
            __atomic_add_fetch(&shared->failures, 1, __ATOMIC_RELAXED);
            return;
        }
        if ((round & 7u) == 0)
        {
            sys_yield();
        }
    }
}

int main(int argc, char **argv)
{
    uint8_t *bytes = malloc(2 * ENTROPY_SAMPLE_BYTES + 2);
    if (!bytes)
    {
        return failure("allocation");
    }
    memset(bytes, 0xA5, 2 * ENTROPY_SAMPLE_BYTES + 2);
    if (argc > 1 && strcmp(argv[1], "unsupported") == 0)
    {
        if (getrandom(bytes, 32, 0) != -1 || errno != ENOSYS ||
            getrandom(bytes, 32, GRND_NONBLOCK) != -1 || errno != ENOSYS ||
            getentropy(bytes, 32) != -1 || errno != ENOSYS ||
            !filled_with(bytes, 2 * ENTROPY_SAMPLE_BYTES + 2, 0xA5))
        {
            return failure("unsupported backend");
        }
        free(bytes);
        serial_printf("ENTROPY_TEST: unsupported PASS\n");
        return 0;
    }
    if (getrandom(NULL, 0, 0) != 0 || getentropy(NULL, 0) != 0 ||
        getrandom(bytes, 32, 2) != -1 || errno != EINVAL ||
        getentropy(bytes, 257) != -1 || errno != EIO ||
        getrandom(NULL, 32, 0) != -1 || errno != EFAULT ||
        !filled_with(bytes, 2 * ENTROPY_SAMPLE_BYTES + 2, 0xA5))
    {
        return failure("arguments");
    }
    /* Unaligned output and a larger request exercise native short-read bounds. */
    if (getrandom(bytes + 1, 2 * ENTROPY_SAMPLE_BYTES, GRND_NONBLOCK) != ENTROPY_SAMPLE_BYTES ||
        bytes[0] != 0xA5 || !filled_with(bytes + ENTROPY_SAMPLE_BYTES + 1, ENTROPY_SAMPLE_BYTES + 1, 0xA5) ||
        filled_with(bytes + 1, ENTROPY_SAMPLE_BYTES, 0xA5))
    {
        return failure("short read or bounds");
    }
    free(bytes);

    uint8_t *page = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED)
    {
        return failure("mapping");
    }
    memset(page, 0x6D, PAGE_BYTES);
    if (mprotect(page, PAGE_BYTES, PROT_READ) != 0 ||
        getrandom(page, 32, 0) != -1 || errno != EFAULT ||
        !filled_with(page, PAGE_BYTES, 0x6D) ||
        mprotect(page, PAGE_BYTES, PROT_NONE) != 0 ||
        getentropy(page, 32) != -1 || errno != EFAULT ||
        mprotect(page, PAGE_BYTES, PROT_READ | PROT_WRITE) != 0 ||
        !filled_with(page, PAGE_BYTES, 0x6D) ||
        getentropy(page, 32) != 0 || filled_with(page, 32, 0x6D) ||
        munmap(page, PAGE_BYTES) != 0 ||
        getrandom(page, 32, 0) != -1 || errno != EFAULT)
    {
        return failure("protected or unmapped copyout");
    }

    entropy_shared_t *shared = calloc(1, sizeof(*shared));
    if (!shared)
    {
        return failure("shared allocation");
    }
    for (unsigned cpu = 0; cpu < ENTROPY_WORKERS; ++cpu)
    {
        entropy_worker_t *worker = &shared->workers[cpu];
        worker->shared = shared;
        worker->cpu = cpu;
        if (alix_thread_create(&worker->thread, "entropy", entropy_worker, worker) != 0)
        {
            /* Process termination reclaims shared state after its workers stop. */
            return failure("worker creation");
        }
    }
    if (!wait_value(&shared->ready, ENTROPY_WORKERS))
    {
        return failure("worker readiness");
    }
    __atomic_store_n(&shared->start, 1, __ATOMIC_RELEASE);
    for (unsigned cpu = 0; cpu < ENTROPY_WORKERS; ++cpu)
    {
        if (alix_thread_join(shared->workers[cpu].thread, NULL) != 0)
        {
            return failure("join");
        }
    }
    if (shared->failures || shared->cpu_mask != 0xFF)
    {
        return failure("per-CPU generation");
    }
    for (unsigned cpu = 0; cpu < ENTROPY_WORKERS; ++cpu)
    {
        for (unsigned other = cpu + 1; other < ENTROPY_WORKERS; ++other)
        {
            if (memcmp(shared->workers[cpu].samples[0], shared->workers[other].samples[0], ENTROPY_SAMPLE_BYTES) == 0)
            {
                return failure("repeated CPU samples");
            }
        }
    }
    free(shared);
    /* Diversity catches constant/duplicated output, not cryptographic quality. */
    serial_printf("ENTROPY_TEST: PASS workers=8 cpu_mask=0xFF samples=512\n");
    return 0;
}
