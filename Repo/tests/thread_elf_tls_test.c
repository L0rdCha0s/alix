#include "userlib.h"
#include "serial.h"
#include "errno.h"

#define WORKERS 8u
static _Thread_local int initialized = 73;
static _Thread_local unsigned char zeroed[193] __attribute__((aligned(128)));
static uint32_t before_main;
static volatile uint32_t ready;
static volatile uint32_t start;

typedef struct
{
    alix_thread_t thread;
    uintptr_t address;
    uintptr_t thread_pointer;
    uint32_t index;
    uint32_t cpu_mask;
    uint32_t failed;
} worker_t;

__attribute__((constructor(200))) static void check_initial_thread(void)
{
    if (initialized == 73 && errno == 0 && sys_thread_get_tls() != 0 &&
        ((uintptr_t)zeroed & 127u) == 0)
    {
        before_main = 1;
    }
    initialized = 900;
    errno = EDOM;
    zeroed[0] = 0xAB;
}

static void worker(void *argument)
{
    worker_t *state = argument;
    state->address = (uintptr_t)&initialized;
    state->thread_pointer = sys_thread_get_tls();
    if (initialized != 73 || errno != 0 || state->thread_pointer == 0 ||
        *(const uintptr_t *)state->thread_pointer != state->thread_pointer ||
        ((uintptr_t)zeroed & 127u) != 0)
    {
        state->failed = 1;
    }
    for (size_t j = 0; j < sizeof(zeroed); ++j)
    {
        if (zeroed[j] != 0) state->failed = 1;
        zeroed[j] = (unsigned char)(state->index + 1u);
    }
    initialized = (int)(100 + state->index);
    errno = (int)(200 + state->index);
    __atomic_add_fetch(&ready, 1u, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&start, __ATOMIC_ACQUIRE)) sys_yield();
    for (unsigned round = 0; round < WORKERS; ++round)
    {
        uint32_t cpu = (state->index + round) % WORKERS;
        if (sys_thread_set_affinity(cpu) != 0 || sys_thread_cpu() != cpu ||
            sys_thread_get_tls() != state->thread_pointer ||
            initialized != (int)(100 + state->index) || errno != (int)(200 + state->index))
        {
            state->failed = 1;
        }
        state->cpu_mask |= 1u << cpu;
        for (size_t j = 0; j < sizeof(zeroed); ++j)
        {
            if (zeroed[j] != (unsigned char)(state->index + 1u)) state->failed = 1;
        }
        sys_sleep_ms(1);
    }
}

int main(void)
{
    worker_t *workers = calloc(WORKERS, sizeof(*workers));
    if (!workers || !before_main || initialized != 900 || errno != EDOM || zeroed[0] != 0xAB)
    {
        serial_printf("ELF_TLS_TEST: FAIL initial thread or constructor\n");
        return 1;
    }
    for (unsigned i = 0; i < WORKERS; ++i)
    {
        workers[i].index = i;
        if (alix_thread_create(&workers[i].thread, "elf_tls", worker, &workers[i]) != 0)
        {
            __atomic_store_n(&start, 1u, __ATOMIC_RELEASE);
            serial_printf("ELF_TLS_TEST: FAIL create\n");
            return 1;
        }
    }
    while (__atomic_load_n(&ready, __ATOMIC_ACQUIRE) != WORKERS) sys_yield();
    __atomic_store_n(&start, 1u, __ATOMIC_RELEASE);
    for (unsigned i = 0; i < WORKERS; ++i)
    {
        if (alix_thread_join(workers[i].thread, NULL) != 0)
        {
            serial_printf("ELF_TLS_TEST: FAIL join\n");
            return 1; /* Do not free records unless every user is quiescent. */
        }
        if (workers[i].failed || workers[i].cpu_mask != 0xFF ||
            workers[i].address == (uintptr_t)&initialized)
        {
            serial_printf("ELF_TLS_TEST: FAIL isolated TLS or CPU migration\n");
            return 1;
        }
        for (unsigned j = 0; j < i; ++j)
        {
            if (workers[i].address == workers[j].address)
            {
                serial_printf("ELF_TLS_TEST: FAIL shared TLS allocation\n");
                return 1;
            }
        }
    }
    bool okay = initialized == 900 && errno == EDOM && zeroed[0] == 0xAB;
    free(workers);
    serial_printf("ELF_TLS_TEST: %s workers=8 initialized=73 alignment=128 cpu_mask=0xFF\n", okay ? "PASS" : "FAIL");
    return okay ? 0 : 1;
}
