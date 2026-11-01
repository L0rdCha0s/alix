#include "semaphore.h"
#include "pthread.h"
#include "signal.h"
#include "stdlib.h"
#include "string.h"
#include "memory.h"
#include "stdio.h"
#include "unistd.h"
#include "usyscall.h"
#include "serial.h"
#include "errno.h"
#include "spawn.h"
#include "alix_process.h"
#include "sys/wait.h"

#define CHECK(c,label) do{if(!(c)){serial_printf("POSIX_RUNTIME_TEST: FAIL %s line=%u errno=%d\n",label,__LINE__,errno);return 1;}}while(0)
typedef struct fixture fixture_t;
typedef struct
{
    pthread_t thread;
    fixture_t *fixture;
    uint64_t tid;
    unsigned cpu, mode, failed;
    int result, error;
    syscall_thread_info_t info;
} job_t;
struct fixture
{
    sem_t ready, start, tokens, signal, ping, pong;
    job_t jobs[8];
    struct timespec deadline;
    struct sigaction action;
    uint64_t consumed, payload;
    uint32_t cpu_mask;
    int value, status;
    char *assignment;
    char *arguments[3];
    char **environment;
    pid_t child;
};
static sem_t *g_signal_semaphore;
static volatile sig_atomic_t g_signals, g_post_result;
static int g_environment_before_main;
__attribute__((constructor)) static void environment_constructor(void)
{
    const char *value = getenv("PORT_RENAMED");
    g_environment_before_main = value && !strcmp(value, "snapshot value");
}
static void caught(int number)
{
    if (number == SIGUSR1) ++g_signals;
    if (number == SIGUSR2) g_post_result = sem_post(g_signal_semaphore);
}
static void must_not_run(void) { serial_printf("POSIX_RUNTIME_TEST: FAIL _exit ran an exit handler\n"); }
static void *worker(void *pointer)
{
    job_t *job = pointer; fixture_t *test = job->fixture;
    __atomic_store_n(&job->tid, sys_thread_self(), __ATOMIC_RELEASE);
    if (sys_thread_set_affinity(job->cpu) || sys_thread_cpu() != job->cpu) job->failed = 1;
    __atomic_fetch_or(&test->cpu_mask, 1u << job->cpu, __ATOMIC_RELAXED);
    if (job->mode < 2)
    {
        if (sem_post(&test->ready) || sem_wait(&test->start)) job->failed = 2;
        for (unsigned index = 0; index < 5000 && !job->failed; ++index)
        {
            if (!job->mode)
            {
                if (sem_post(&test->tokens)) job->failed = 3;
            }
            else
            {
                if (sem_wait(&test->tokens)) job->failed = 4;
                else __atomic_add_fetch(&test->consumed, 1u, __ATOMIC_RELAXED);
            }
        }
    }
    else if (job->mode == 2 || job->mode == 3)
    {
        for (uint64_t index = 1; index <= 1000 && !job->failed; ++index)
        {
            if (job->mode == 2)
            {
                test->payload = index;
                if (sem_post(&test->ping) || sem_wait(&test->pong)) job->failed = 5;
            }
            else
            {
                if (sem_wait(&test->ping) || test->payload != index || sem_post(&test->pong)) job->failed = 6;
            }
        }
    }
    else
    {
        job->result = sem_wait(&test->signal); job->error = errno;
    }
    return NULL;
}
static int wait_blocked(job_t *job)
{
    uint64_t deadline = sys_monotonic_millis() + 3000;
    while (sys_monotonic_millis() < deadline)
    {
        uint64_t tid = __atomic_load_n(&job->tid, __ATOMIC_ACQUIRE);
        if (tid && !sys_thread_info(tid, &job->info) && job->info.state == SYSCALL_THREAD_STATE_BLOCKED) return 0;
        sys_sleep_ms(1);
    }
    return -1;
}
int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "quick"))
    {
        CHECK(!atexit(must_not_run), "child exit handler registration");
        _exit(7);
    }
    if (argc > 1 && !strcmp(argv[1], "environment"))
    {
        CHECK(g_environment_before_main && getenv("PORT_RENAMED") &&
              !strcmp(getenv("PORT_RENAMED"), "snapshot value"), "snapshot environment visible before main");
        return 17;
    }
    fixture_t *test = calloc(1, sizeof(*test)); CHECK(test, "heap fixture");
    CHECK(sem_init(&test->signal, 1, 0) == -1 && errno == ENOTSUP, "shared semaphore capability is explicit");
    CHECK(!sem_init(&test->signal, 0, 1) && !sem_trywait(&test->signal) &&
          sem_trywait(&test->signal) == -1 && errno == EAGAIN, "semaphore token/trywait");
    CHECK(!clock_gettime(CLOCK_REALTIME, &test->deadline), "absolute deadline clock");
    test->deadline.tv_nsec += 30000000;
    if (test->deadline.tv_nsec >= 1000000000) { ++test->deadline.tv_sec; test->deadline.tv_nsec -= 1000000000; }
    uint64_t start = sys_monotonic_millis();
    CHECK(sem_timedwait(&test->signal, &test->deadline) == -1 && errno == ETIMEDOUT &&
          sys_monotonic_millis() - start >= 20, "real absolute semaphore timeout");
    CHECK(!sem_destroy(&test->signal) && !sem_init(&test->signal, 0, SEM_VALUE_MAX) &&
          sem_post(&test->signal) == -1 && errno == EOVERFLOW && !sem_destroy(&test->signal), "overflow preserves semaphore count");
    CHECK(!sem_init(&test->ready, 0, 0) && !sem_init(&test->start, 0, 0) &&
          !sem_init(&test->tokens, 0, 0) && !sem_init(&test->ping, 0, 0) && !sem_init(&test->pong, 0, 0), "SMP semaphore initialization");
    for (unsigned cpu = 0; cpu < 8; ++cpu)
    {
        job_t *job = &test->jobs[cpu]; job->fixture = test; job->cpu = cpu; job->mode = cpu < 4 ? 0 : 1;
        CHECK(!pthread_create(&job->thread, NULL, worker, job), "SMP semaphore worker");
    }
    for (unsigned cpu = 0; cpu < 8; ++cpu) CHECK(!sem_wait(&test->ready), "worker readiness");
    for (unsigned cpu = 0; cpu < 8; ++cpu) CHECK(!wait_blocked(&test->jobs[cpu]), "waiters block in kernel futex");
    CHECK(sem_destroy(&test->start) == -1 && errno == EBUSY, "live waiters prevent destruction");
    for (unsigned cpu = 0; cpu < 8; ++cpu) CHECK(!sem_post(&test->start), "wake each initial waiter");
    for (unsigned cpu = 0; cpu < 8; ++cpu)
        CHECK(!pthread_join(test->jobs[cpu].thread, NULL) && !test->jobs[cpu].failed, "SMP token worker result");
    CHECK(test->cpu_mask == 0xff && test->consumed == 20000 &&
          !sem_getvalue(&test->tokens, &test->value) && !test->value, "all CPUs and exact token accounting");
    memset(test->jobs, 0, sizeof(test->jobs));
    for (unsigned index = 0; index < 2; ++index)
    {
        job_t *job = &test->jobs[index]; job->fixture = test; job->cpu = index + 4; job->mode = index + 2;
        CHECK(!pthread_create(&job->thread, NULL, worker, job), "payload handoff worker");
    }
    for (unsigned index = 0; index < 2; ++index)
        CHECK(!pthread_join(test->jobs[index].thread, NULL) && !test->jobs[index].failed, "release/acquire publishes payload");
    CHECK(!sem_init(&test->signal, 0, 0) && !sigemptyset(&test->action.sa_mask), "signal semaphore");
    test->action.sa_handler = caught;
    CHECK(!sigaction(SIGUSR1, &test->action, NULL) && !sigaction(SIGUSR2, &test->action, NULL), "semaphore signal handlers");
    job_t *job = &test->jobs[0]; memset(job, 0, sizeof(*job)); job->fixture = test; job->cpu = 7; job->mode = 4;
    CHECK(!pthread_create(&job->thread, NULL, worker, job) && !wait_blocked(job) &&
          !pthread_kill(job->thread, SIGUSR1) && !pthread_join(job->thread, NULL) &&
          job->result == -1 && job->error == EINTR && g_signals == 1 && !sem_destroy(&test->signal), "caught signal interrupts semaphore wait");
    CHECK(!sem_init(&test->signal, 0, 0), "signal post initialization");
    memset(job, 0, sizeof(*job)); job->fixture = test; job->cpu = 6; job->mode = 4;
    g_signal_semaphore = &test->signal; g_post_result = -1;
    CHECK(!pthread_create(&job->thread, NULL, worker, job) && !wait_blocked(job) &&
          !raise(SIGUSR2) && !pthread_join(job->thread, NULL) && !job->result &&
          !g_post_result && !sem_destroy(&test->signal), "signal-safe semaphore post wakes waiter");
    g_signal_semaphore = NULL;
    serial_printf("POSIX_RUNTIME_TEST: SEM PASS cpus=8 tokens=20000 payloads=1000 signal=1\n");
    test->assignment = calloc(128, 1); CHECK(test->assignment, "borrowed environment storage");
    strcpy(test->assignment, "PORT_BORROW=first");
    CHECK(!putenv(test->assignment) && getenv("PORT_BORROW") == test->assignment + 12, "putenv retains supplied storage");
    strcpy(test->assignment, "PORT_RENAMED=snapshot value");
    CHECK(!getenv("PORT_BORROW") && !strcmp(getenv("PORT_RENAMED"), "snapshot value"), "environment tracks mutable name and value");
    test->environment = alix_environment_copy(); CHECK(test->environment, "owned environment snapshot");
    strcpy(test->assignment, "PORT_RENAMED=parent changed");
    test->arguments[0] = "/tmp/test.elf"; test->arguments[1] = "environment";
    CHECK(!posix_spawn(&test->child, test->arguments[0], NULL, NULL, test->arguments, test->environment) &&
          waitpid(test->child, &test->status, 0) == test->child && WIFEXITED(test->status) &&
          WEXITSTATUS(test->status) == 17, "spawn uses immutable environment snapshot");
    alix_environment_free(test->environment);
    CHECK(!setenv("PORT_RENAMED", "owned", 1) && !strcmp(getenv("PORT_RENAMED"), "owned") &&
          !unsetenv("PORT_RENAMED"), "setenv/unsetenv release only owned storage");
    free(test->assignment);
    test->arguments[1] = "quick";
    test->child = alix_spawn_argv(test->arguments[0], test->arguments);
    CHECK(test->child > 0 && waitpid(test->child, &test->status, 0) == test->child &&
          WIFEXITED(test->status) && WEXITSTATUS(test->status) == 7, "_exit bypasses exit handlers and reports status");
    CHECK(!sem_destroy(&test->ready) && !sem_destroy(&test->start) && !sem_destroy(&test->tokens) &&
          !sem_destroy(&test->ping) && !sem_destroy(&test->pong), "all semaphores retire cleanly");
    free(test);
    serial_printf("POSIX_RUNTIME_TEST: PASS semaphores=1 putenv=1 spawn_snapshot=1 _exit=1\n");
    return 0;
}
