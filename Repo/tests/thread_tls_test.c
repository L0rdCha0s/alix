#include "userlib.h"
#include "serial.h"

#define WORKERS 8u
#define ITERATIONS 512u

typedef struct
{
    uintptr_t self;
    uint64_t token;
    uint64_t counter;
    alix_thread_t thread;
    int status;
    int failed;
    uint32_t index;
    uint32_t cpu_mask;
} tls_record_t;

static volatile uint32_t ready;
static volatile uint32_t start;

static uintptr_t tls_self(void)
{
    uintptr_t value;
    __asm__ volatile ("movq %%fs:0, %0" : "=r"(value) :: "memory");
    return value;
}

static uint64_t tls_token(void)
{
    uint64_t value;
    __asm__ volatile ("movq %%fs:8, %0" : "=r"(value) :: "memory");
    return value;
}

static void worker(void *arg)
{
    tls_record_t *record = (tls_record_t *)arg;
    uintptr_t original_tls = sys_thread_get_tls();
    if (sys_thread_set_tls((uintptr_t)record) != 0)
    {
        record->failed = 1;
    }
    __atomic_add_fetch(&ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&start, __ATOMIC_ACQUIRE))
    {
        sys_yield();
    }
    if (!record->failed)
    {
        for (uint64_t i = 1; i <= ITERATIONS; ++i)
        {
            if ((i & 63u) == 1)
            {
                uint32_t target = (record->index + (uint32_t)(i / 64u)) % WORKERS;
                if (sys_thread_set_affinity(target) != 0 || sys_thread_cpu() != target)
                {
                    record->failed = 1;
                    break;
                }
                record->cpu_mask |= 1u << target;
            }
            if (tls_self() != (uintptr_t)record || tls_token() != record->token ||
                sys_thread_get_tls() != (uintptr_t)record)
            {
                record->failed = 1;
                break;
            }
            __asm__ volatile ("movq %0, %%fs:16" :: "r"(i) : "memory");
            if ((i & 7u) == 0)
            {
                sys_yield();
            }
            if ((i & 63u) == 0)
            {
                sys_sleep_ms(1);
            }
        }
    }
    int cleared = sys_thread_set_tls(0);
    uintptr_t empty = sys_thread_get_tls();
    int restored = sys_thread_set_tls(original_tls);
    if (cleared != 0 || empty != 0 || restored != 0)
    {
        record->failed = 1;
    }
    if (sys_thread_set_affinity((uint32_t)-1) != 0)
    {
        record->failed = 1;
    }
}

int main(void)
{
    tls_record_t *records = (tls_record_t *)calloc(WORKERS + 1, sizeof(*records));
    if (!records)
    {
        serial_printf("THREAD_TLS_TEST: FAIL allocation\n");
        return 1;
    }
    int failed = 0;
    uintptr_t original_tls = sys_thread_get_tls();
    if (sys_thread_set_affinity(32) >= 0 || sys_thread_cpu() >= WORKERS)
    {
        serial_printf("THREAD_TLS_TEST: FAIL affinity validation\n");
        free(records);
        return 1;
    }
    tls_record_t *main_record = &records[WORKERS];
    main_record->self = (uintptr_t)main_record;
    main_record->token = 0xA11C00000000FFFFULL;
    unsigned created = 0;
    for (unsigned i = 0; i < WORKERS; ++i)
    {
        records[i].self = (uintptr_t)&records[i];
        records[i].token = 0xA11C000000000000ULL + i;
        records[i].index = i;
        if (alix_thread_create(&records[i].thread, "tls_test", worker, &records[i]) != 0)
        {
            failed = 1;
            break;
        }
        ++created;
    }
    while (__atomic_load_n(&ready, __ATOMIC_ACQUIRE) < created)
    {
        sys_yield();
    }
    /* All allocation and thread startup uses the compiler's native TLS.
     * Only raw syscalls/assembly run while this manual test TCB is installed. */
    if (sys_thread_set_tls((uintptr_t)main_record) != 0)
    {
        __atomic_store_n(&start, 1, __ATOMIC_RELEASE);
        serial_printf("THREAD_TLS_TEST: FAIL main setup\n");
        return 1;
    }
    static const uintptr_t invalid[] = {
        1, 0x1000, 0x0000800000000000ULL, 0xFFFF800000000000ULL, (uintptr_t)-1
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    {
        if (sys_thread_set_tls(invalid[i]) >= 0 || sys_thread_get_tls() != (uintptr_t)main_record)
        {
            failed = 1;
        }
    }
    __atomic_store_n(&start, 1, __ATOMIC_RELEASE);
    for (unsigned i = 0; i < created; ++i)
    {
        if (sys_thread_join(records[i].thread, &records[i].status) != 0)
        {
            /* A failed join does not prove that the worker stopped using its
             * heap record. Process exit owns cancellation and reclamation. */
            (void)sys_thread_set_tls(original_tls);
            serial_printf("THREAD_TLS_TEST: FAIL join\n");
            return 1;
        }
        if (records[i].status != 0 || records[i].failed || records[i].counter != ITERATIONS ||
            records[i].cpu_mask != ((1u << WORKERS) - 1u))
        {
            failed = 1;
        }
        if (tls_self() != (uintptr_t)main_record || tls_token() != main_record->token)
        {
            failed = 1;
        }
    }
    int cleared = sys_thread_set_tls(0);
    uintptr_t empty = sys_thread_get_tls();
    int restored = sys_thread_set_tls(original_tls);
    if (created != WORKERS || cleared != 0 || empty != 0 || restored != 0)
    {
        failed = 1;
    }
    free(records);
    serial_printf("THREAD_TLS_TEST: %s workers=8 required_cpu_mask=0xFF\n", failed ? "FAIL" : "PASS");
    return failed ? 1 : 0;
}
