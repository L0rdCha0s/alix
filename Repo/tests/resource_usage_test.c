#include "sys/resource.h"
#include "sys/mman.h"
#include "pthread.h"
#include "usyscall.h"
#include "serial.h"
#include "stdlib.h"
#include "string.h"
#include "errno.h"

#define WORKERS 8u
#define PAGES 16u
#define CHECK(test,label) do { if (!(test)) { serial_printf("RESOURCE_USAGE_TEST: FAIL %s\n",label); return 1; } } while (0)
typedef struct shared shared_t;
typedef struct
{
    shared_t *shared;
    pthread_t thread;
    unsigned cpu, failed;
    uint64_t checksum;
    struct rusage usage;
} worker_t;
struct shared
{
    worker_t workers[WORKERS];
    uint32_t ready, start, done, mask;
    struct rusage before, after, invalid;
};

static void *run_worker(void *argument)
{
    worker_t *worker = argument;
    shared_t *shared = worker->shared;
    unsigned char *pages = MAP_FAILED;
    bool ready = false;
#define REQUIRE(test,code) do { if (!(test)) { worker->failed=(code); goto finished; } } while (0)
    REQUIRE(sys_thread_set_affinity(worker->cpu) == 0 && sys_thread_cpu() == worker->cpu, 1);
    pages = mmap(NULL, PAGES * 4096u, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(pages != MAP_FAILED, 2);
    REQUIRE(madvise(pages, PAGES * 4096u, MADV_DONTNEED) == 0, 3);
    __atomic_add_fetch(&shared->ready, 1u, __ATOMIC_RELEASE);
    ready = true;
    while (!__atomic_load_n(&shared->start, __ATOMIC_ACQUIRE)) sys_yield();
    for (unsigned index = 0; index < PAGES; ++index)
    {
        volatile unsigned char *page = pages + index * 4096u;
        REQUIRE(page[0] == 0, 4);
        page[0] = (unsigned char)(index + 1);
    }
    uint64_t until = sys_monotonic_millis() + 250;
    uint64_t value = worker->cpu + 1u;
    do
    {
        for (unsigned index = 0; index < 4096; ++index)
        {
            value = value * UINT64_C(6364136223846793005) + index + 1u;
            __asm__ volatile ("" : "+r"(value));
        }
    } while (sys_monotonic_millis() < until);
    worker->checksum = value;
    REQUIRE(getrusage(RUSAGE_SELF, &worker->usage) == 0 && worker->usage.ru_minflt >= 0 &&
            worker->usage.ru_majflt == 0 && worker->usage.ru_utime.tv_sec >= 0 &&
            worker->usage.ru_utime.tv_usec >= 0 && worker->usage.ru_utime.tv_usec < 1000000 &&
            worker->usage.ru_stime.tv_sec >= 0 && worker->usage.ru_stime.tv_usec >= 0 &&
            worker->usage.ru_stime.tv_usec < 1000000, 5);
    __atomic_fetch_or(&shared->mask, 1u << worker->cpu, __ATOMIC_RELEASE);
finished:
    if (pages != MAP_FAILED && munmap(pages, PAGES * 4096u) != 0 && !worker->failed) worker->failed = 6;
    if (!ready) __atomic_add_fetch(&shared->ready, 1u, __ATOMIC_RELEASE);
    __atomic_add_fetch(&shared->done, 1u, __ATOMIC_RELEASE);
    return NULL;
#undef REQUIRE
}

int main(void)
{
    shared_t *shared = calloc(1, sizeof(*shared));
    CHECK(shared, "heap state");
    errno = EDOM;
    CHECK(getrusage(RUSAGE_SELF, &shared->before) == 0 && errno == EDOM, "initial snapshot");
    for (unsigned index = 0; index < WORKERS; ++index)
    {
        worker_t *worker = &shared->workers[index];
        worker->shared = shared;
        worker->cpu = index;
        CHECK(pthread_create(&worker->thread, NULL, run_worker, worker) == 0, "create worker");
    }
    while (__atomic_load_n(&shared->ready, __ATOMIC_ACQUIRE) != WORKERS) sys_yield();
    __atomic_store_n(&shared->start, 1u, __ATOMIC_RELEASE);
    for (unsigned index = 0; index < WORKERS; ++index)
    {
        CHECK(pthread_join(shared->workers[index].thread, NULL) == 0, "join worker");
        CHECK(!shared->workers[index].failed, "worker measurement");
    }
    CHECK(getrusage(RUSAGE_SELF, &shared->after) == 0, "final snapshot");
    CHECK(shared->after.ru_minflt - shared->before.ru_minflt >= WORKERS * PAGES &&
          shared->after.ru_majflt == 0, "real recovered page faults");
    uint64_t before_cpu = (uint64_t)(shared->before.ru_utime.tv_sec + shared->before.ru_stime.tv_sec) * 1000000u +
                          shared->before.ru_utime.tv_usec + shared->before.ru_stime.tv_usec;
    uint64_t after_cpu = (uint64_t)(shared->after.ru_utime.tv_sec + shared->after.ru_stime.tv_sec) * 1000000u +
                         shared->after.ru_utime.tv_usec + shared->after.ru_stime.tv_usec;
    CHECK(after_cpu > before_cpu && shared->mask == 0xff, "sampled CPU time on all CPUs");
    memset(&shared->invalid, 0xa5, sizeof(shared->invalid));
    CHECK(getrusage(-1, &shared->invalid) == -1 && errno == EINVAL, "unsupported usage selector");
    for (size_t index = 0; index < sizeof(shared->invalid); ++index)
        CHECK(((unsigned char *)&shared->invalid)[index] == 0xa5, "failed query preserves output");
    CHECK(getrusage(RUSAGE_SELF, NULL) == -1 && errno == EFAULT, "null output");
    CHECK(sys_resource_usage(RUSAGE_SELF, (void *)1, sizeof(syscall_resource_usage_t)) == -EFAULT,
          "kernel output ownership check");
    free(shared);
    serial_printf("RESOURCE_USAGE_TEST: PASS workers=8 cpu_mask=0xFF faults=128 cpu_time=1 major=0\n");
    return 0;
}
