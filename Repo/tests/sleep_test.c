#include "errno.h"
#include "limits.h"
#include "pthread.h"
#include "serial.h"
#include "signal.h"
#include "stdlib.h"
#include "string.h"
#include "unistd.h"
#include "usyscall.h"

#define CHECK(c, label) do { if (!(c)) { serial_printf("SLEEP_TEST: FAIL %s line=%u errno=%d\n", label, __LINE__, errno); return 1; } } while (0)
typedef struct
{
    pthread_t thread;
    uint64_t tid, elapsed;
    unsigned cpu, seconds, remaining, failed;
    int error, handled;
    syscall_thread_info_t info;
} sleep_job_t;
typedef struct
{
    sleep_job_t jobs[8];
    struct sigaction action;
} sleep_fixture_t;
static _Thread_local volatile sig_atomic_t handled;

static void caught(int number) { if (number == SIGUSR1) ++handled; }
static void *worker(void *context)
{
    sleep_job_t *job = context;
    if (sys_thread_set_affinity(job->cpu) || sys_thread_cpu() != job->cpu) job->failed = 1;
    __atomic_store_n(&job->tid, sys_thread_self(), __ATOMIC_RELEASE);
    errno = EDOM;
    uint64_t start = sys_monotonic_millis();
    job->remaining = sleep(job->seconds);
    job->elapsed = sys_monotonic_millis() - start;
    job->error = errno;
    job->handled = handled;
    return NULL;
}
static int wait_blocked(sleep_job_t *job)
{
    uint64_t deadline = sys_monotonic_millis() + 5000;
    while (sys_monotonic_millis() < deadline)
    {
        uint64_t tid = __atomic_load_n(&job->tid, __ATOMIC_ACQUIRE);
        if (tid && !sys_thread_info(tid, &job->info) && job->info.state == SYSCALL_THREAD_STATE_BLOCKED) return 0;
        sys_sleep_ms(1);
    }
    return -1;
}
int main(void)
{
    sleep_fixture_t *test = calloc(1, sizeof(*test));
    CHECK(test, "heap fixture");
    errno = EDOM;
    CHECK(!sleep(0) && errno == EDOM, "zero sleep preserves errno");
    CHECK(!sigemptyset(&test->action.sa_mask), "signal mask");
    test->action.sa_handler = caught;
    for (unsigned phase = 0; phase < 3; ++phase)
    {
        test->action.sa_flags = phase == 2 ? SA_RESTART : 0;
        CHECK(!sigaction(SIGUSR1, &test->action, NULL), "signal action");
        memset(test->jobs, 0, sizeof(test->jobs));
        for (unsigned cpu = 0; cpu < 8; ++cpu)
        {
            sleep_job_t *job = &test->jobs[cpu];
            job->cpu = cpu;
            job->seconds = !phase ? 1 : phase == 1 ? 10 : UINT_MAX;
            CHECK(!pthread_create(&job->thread, NULL, worker, job), "worker creation");
        }
        if (phase)
        {
            for (unsigned cpu = 0; cpu < 8; ++cpu) CHECK(!wait_blocked(&test->jobs[cpu]), "registered timer wait");
            sys_sleep_ms(25);
            for (unsigned cpu = 0; cpu < 8; ++cpu) CHECK(!pthread_kill(test->jobs[cpu].thread, SIGUSR1), "interrupt sleeper");
        }
        for (unsigned cpu = 0; cpu < 8; ++cpu)
        {
            sleep_job_t *job = &test->jobs[cpu];
            CHECK(!pthread_join(job->thread, NULL) && !job->failed, "pinned worker completion");
            if (!phase) CHECK(!job->remaining && job->elapsed >= 1000 && job->error == EDOM && !job->handled, "one second sleep");
            else CHECK(job->remaining > 0 && job->remaining <= job->seconds && job->elapsed < 6000 && job->error == EINTR && job->handled == 1, "interrupted sleep returns unslept seconds");
        }
    }
    free(test);
    serial_printf("SLEEP_TEST: PASS cpus=8 normal=8 interrupted=16 restart=1 uint_max=1 zero=1 errno=1\n");
    return 0;
}
