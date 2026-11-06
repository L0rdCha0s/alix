#include "usyscall.h"
#include "pthread.h"
#include "stdlib.h"
#include "serial.h"

typedef struct { unsigned cpu; uint64_t baseline; bool failed; } worker_t;
static void *sample_uptime(void *argument)
{
    worker_t *worker = argument;
    if (sys_thread_set_affinity(worker->cpu) != 0) { worker->failed = true; return NULL; }
    sys_yield();
    if (sys_thread_cpu() != worker->cpu) worker->failed = true;
    uint64_t previous = worker->baseline;
    for (unsigned i = 0; i < 128; ++i)
    {
        uint64_t now = sys_process_uptime_ns();
        if (now < previous) worker->failed = true;
        previous = now;
        sys_yield();
    }
    return NULL;
}

int main(void)
{
    uint64_t boot_before = sys_monotonic_millis();
    uint64_t first = sys_process_uptime_ns();
    if (sys_sleep_ms(25) != 0) return 1;
    uint64_t second = sys_process_uptime_ns();
    uint64_t boot_after = sys_monotonic_millis();
    if (second < first || second - first < 25000000ULL ||
        second - first > (boot_after - boot_before) * 1000000ULL)
    { serial_printf("PROCESS_UPTIME_TEST: FAIL elapsed boot_before=%llu boot_after=%llu first_ns=%llu second_ns=%llu\n",
                    (unsigned long long)boot_before, (unsigned long long)boot_after,
                    (unsigned long long)first, (unsigned long long)second); return 1; }

    worker_t *workers = calloc(8, sizeof(*workers));
    pthread_t *threads = calloc(8, sizeof(*threads));
    if (!workers || !threads) { free(workers); free(threads); return 1; }
    unsigned created = 0;
    for (; created < 8; ++created)
    {
        workers[created].cpu = created;
        workers[created].baseline = second;
        if (pthread_create(&threads[created], NULL, sample_uptime, &workers[created]) != 0) break;
    }
    bool okay = created == 8;
    for (unsigned i = 0; i < created; ++i)
        if (pthread_join(threads[i], NULL) != 0 || workers[i].failed) okay = false;
    free(workers); free(threads);
    if (!okay) { serial_printf("PROCESS_UPTIME_TEST: FAIL process-shared sampling\n"); return 1; }
    serial_printf("PROCESS_UPTIME_TEST: PASS cpus=8 samples=1024 elapsed=1 process_shared=1\n");
    return 0;
}
