#include "wasm2c_rt_mem.h"
#include "wasm2c_rt_minwasi.h"
#include "wasm-rt-impl.h"
#include "pthread.h"
#include "usyscall.h"
#include "time.h"
#include "unistd.h"
#include "sys/resource.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include "errno.h"

extern uint32_t w2c_wasi__snapshot__preview1_clock_time_get(w2c_wasi__snapshot__preview1 *, uint32_t, uint64_t, uint32_t);
extern uint32_t w2c_wasi__snapshot__preview1_clock_res_get(w2c_wasi__snapshot__preview1 *, uint32_t, uint32_t);
#define CHECK(c, message) do { if (!(c)) { printf("RLBOX_RUNTIME_TEST: FAIL %s line=%u\n", message, __LINE__); return 1; } } while (0)
typedef struct fixture fixture_t;
typedef struct
{
    fixture_t *fixture;
    pthread_t thread;
    unsigned cpu, failed;
    uint64_t cpu_ns, wall_ns, checksum;
    wasm_rt_memory_t memory;
    w2c_wasi__snapshot__preview1 wasi;
} worker_t;
struct fixture { worker_t workers[8]; unsigned ready, start, mask; uint64_t resolution; };

static uint64_t nanos(clockid_t id)
{
    struct timespec value;
    if (clock_gettime(id, &value)) return UINT64_MAX;
    return (uint64_t)value.tv_sec * 1000000000ull + (uint64_t)value.tv_nsec;
}
static bool sandbox_clock_and_trap(worker_t *worker)
{
    wasm_rt_memory_t *memory = &worker->memory;
    worker->wasi.instance_memory = memory;
    if (!minwasi_init_instance(&worker->wasi)) return false;
    for (uint32_t clock = 0; clock < 4; ++clock)
    {
        if (w2c_wasi__snapshot__preview1_clock_time_get(&worker->wasi, clock, 1, 16 + clock * 16) ||
            w2c_wasi__snapshot__preview1_clock_res_get(&worker->wasi, clock, 24 + clock * 16)) return false;
        uint64_t resolution = 0;
        memcpy(&resolution, memory->data + 24 + clock * 16, sizeof(resolution));
        if (!resolution || resolution > 1000000000ull) return false;
    }
    uint64_t sentinel = UINT64_C(0x123456789abcdef0), saved;
    memcpy(memory->data + 128, &sentinel, 8);
    if (!w2c_wasi__snapshot__preview1_clock_time_get(&worker->wasi, 99, 1, 128)) return false;
    memcpy(&saved, memory->data + 128, 8);
    if (saved != sentinel) return false;
    wasm_rt_trap_t trap = (WASM_RT_SAVE_STACK_DEPTH(), WASM_RT_SETJMP(g_wasm_rt_jmp_buf));
    if (trap == WASM_RT_TRAP_NONE)
    {
        (void)w2c_wasi__snapshot__preview1_clock_time_get(&worker->wasi, 0, 1, (uint32_t)memory->size - 4);
        return false;
    }
    if (trap != WASM_RT_TRAP_OOB) return false;
    minwasi_cleanup_instance(&worker->wasi);
    return true;
}
static void *run_worker(void *argument)
{
    worker_t *worker = argument;
    fixture_t *fixture = worker->fixture;
    bool ready = false;
#define REQUIRE(c, code) do { if (!(c)) { worker->failed = code; goto finished; } } while (0)
    REQUIRE(!sys_thread_set_affinity(worker->cpu) && sys_thread_cpu() == worker->cpu, 1);
    w2c_mem_capacity capacity = { .is_valid = true, .is_mem_32 = true, .max_pages = 4, .max_size = 262144 };
    worker->memory = create_wasm2c_memory(1, &capacity, "alix-rlbox-runtime");
    REQUIRE(worker->memory.data && !((uintptr_t)worker->memory.data & (UINT64_C(0x200000000) - 1)), 2);
    REQUIRE(worker->memory.pages == 1 && worker->memory.size == 65536 && worker->memory.max_pages == 4, 3);
    REQUIRE(worker->memory.data[0] == 0 && worker->memory.data[65535] == 0, 4);
    worker->memory.data[0] = (unsigned char)(worker->cpu + 1);
    worker->memory.data[65535] = (unsigned char)(worker->cpu + 17);
    REQUIRE(sandbox_clock_and_trap(worker), 5);
    __atomic_fetch_or(&fixture->mask, 1u << worker->cpu, __ATOMIC_RELEASE);
    __atomic_add_fetch(&fixture->ready, 1u, __ATOMIC_RELEASE);
    ready = true;
    while (!__atomic_load_n(&fixture->start, __ATOMIC_ACQUIRE)) sys_yield();
    uint64_t cpu = nanos(CLOCK_THREAD_CPUTIME_ID), wall = nanos(CLOCK_MONOTONIC);
    REQUIRE(cpu != UINT64_MAX && wall != UINT64_MAX, 6);
    uint64_t until = wall + 400000000ull, value = worker->cpu + 1;
    do {
        for (unsigned i = 0; i < 4096; ++i) { value = value * UINT64_C(6364136223846793005) + i; __asm__ volatile("" : "+r"(value)); }
    } while (nanos(CLOCK_MONOTONIC) < until);
    worker->cpu_ns = nanos(CLOCK_THREAD_CPUTIME_ID) - cpu;
    worker->wall_ns = nanos(CLOCK_MONOTONIC) - wall;
    worker->checksum = value;
    REQUIRE(worker->cpu_ns > 0 && worker->cpu_ns <= worker->wall_ns + 3 * fixture->resolution, 7);
    REQUIRE(worker->memory.data[0] == worker->cpu + 1 && worker->memory.data[65535] == worker->cpu + 17, 8);
finished:
    if (worker->memory.data) destroy_wasm2c_memory(&worker->memory);
    if (!ready) __atomic_add_fetch(&fixture->ready, 1u, __ATOMIC_RELEASE);
    return NULL;
#undef REQUIRE
}
int main(int argc, char **argv)
{
    CHECK(getpagesize() == 4096 && minwasi_init(), "page size/minWASI initialization");
    wasm_rt_init();
    if (argc > 1 && !strcmp(argv[1], "guard"))
    {
        wasm_rt_memory_t *memory = calloc(1, sizeof(*memory));
        w2c_mem_capacity capacity = { .is_valid = true, .is_mem_32 = true, .max_pages = 4, .max_size = 262144 };
        CHECK(memory != NULL, "guard state");
        *memory = create_wasm2c_memory(1, &capacity, "alix-rlbox-guard");
        CHECK(memory->data != NULL, "guard allocation");
        volatile unsigned char *guard = memory->data + memory->max_pages * 65536ull;
        printf("VM_FAULT_TEST: armed write address=0x%llX\n", (unsigned long long)(uintptr_t)guard);
        *guard = 1;
        return 2;
    }
    fixture_t *fixture = calloc(1, sizeof(*fixture));
    struct timespec *resolution = calloc(1, sizeof(*resolution));
    CHECK(fixture && resolution, "clock fixture");
    for (clockid_t id = 0; id < 4; ++id)
    {
        CHECK(!clock_getres(id, resolution) && resolution->tv_sec >= 0 && resolution->tv_nsec >= 0 &&
              resolution->tv_nsec < 1000000000L, "normalized resolution");
        CHECK((uint64_t)resolution->tv_sec * 1000000000ull + resolution->tv_nsec > 0, "positive resolution");
        CHECK(!clock_getres(id, NULL), "null resolution output");
    }
    CHECK(!clock_getres(CLOCK_THREAD_CPUTIME_ID, resolution), "CPU resolution");
    fixture->resolution = (uint64_t)resolution->tv_sec * 1000000000ull + resolution->tv_nsec;
    resolution->tv_sec = 123; resolution->tv_nsec = 456;
    CHECK(clock_getres(99, resolution) == -1 && errno == EINVAL && resolution->tv_sec == 123 && resolution->tv_nsec == 456, "invalid resolution");
    CHECK(clock_gettime(99, resolution) == -1 && errno == EINVAL && resolution->tv_sec == 123 && resolution->tv_nsec == 456, "invalid clock");
    CHECK(clock_gettime(0, NULL) == -1 && errno == EFAULT, "null time output");
    for (unsigned i = 0; i < 8; ++i)
    { fixture->workers[i].fixture = fixture; fixture->workers[i].cpu = i; CHECK(!pthread_create(&fixture->workers[i].thread, NULL, run_worker, &fixture->workers[i]), "create"); }
    while (__atomic_load_n(&fixture->ready, __ATOMIC_ACQUIRE) != 8) sys_yield();
    CHECK(fixture->mask == 255, "CPU mask");
    uint64_t cpu_before = nanos(CLOCK_THREAD_CPUTIME_ID), process_before = nanos(CLOCK_PROCESS_CPUTIME_ID), wall_before = nanos(CLOCK_MONOTONIC);
    __atomic_store_n(&fixture->start, 1u, __ATOMIC_RELEASE);
    sys_sleep_ms(200);
    uint64_t idle_cpu = nanos(CLOCK_THREAD_CPUTIME_ID) - cpu_before;
    uint64_t idle_wall = nanos(CLOCK_MONOTONIC) - wall_before;
    CHECK(idle_cpu <= idle_wall / 2 + 2 * fixture->resolution, "sleep excluded from thread CPU clock");
    uint64_t total = 0;
    for (unsigned i = 0; i < 8; ++i)
    { CHECK(!pthread_join(fixture->workers[i].thread, NULL), "join"); CHECK(!fixture->workers[i].failed, "worker"); total += fixture->workers[i].cpu_ns; }
    uint64_t process_cpu = nanos(CLOCK_PROCESS_CPUTIME_ID) - process_before;
    CHECK(process_cpu + 8 * fixture->resolution >= total && process_cpu > 0, "aggregate process CPU clock");
    struct rusage usage;
    CHECK(!getrusage(RUSAGE_SELF, &usage) && clock() >= 0, "existing usage/clock ABI");
    free(resolution); free(fixture);
    wasm_rt_free();
    puts("RLBOX_RUNTIME_TEST: PASS cpus=8 clocks=4 thread_cpu=1 process_cpu=1 sleep_excluded=1 alignment_8g=1 reserved_guard=1 minwasi=1 traps=8 cleanup=1");
    return 0;
}
