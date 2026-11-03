#include "errno.h"
#include "fcntl.h"
#include "limits.h"
#include "pthread.h"
#include "serial.h"
#include "signal.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "sys/resource.h"
#include "sys/stat.h"
#include "syslog.h"
#include "unistd.h"
#include "usyscall.h"

#define CHECK(c, label) do { if (!(c)) { serial_printf("SYSLOG_USLEEP_TEST: FAIL %s line=%u errno=%d\n", label, __LINE__, errno); return 1; } } while (0)
typedef struct
{
    pthread_t thread;
    uint64_t tid, elapsed;
    unsigned cpu, phase, failed;
    int result, error, handled;
    syscall_thread_info_t info;
} service_job_t;
typedef struct
{
    service_job_t jobs[8];
    struct sigaction action;
    struct rlimit limit, lowered;
    struct stat metadata;
    char expected[128], payload[SYSCALL_LOG_MAX_BYTES];
} service_fixture_t;
static _Thread_local volatile sig_atomic_t handled;
static void caught(int number) { if (number == SIGUSR1) ++handled; }

static void *worker(void *context)
{
    service_job_t *job = context;
    if (sys_thread_set_affinity(job->cpu) || sys_thread_cpu() != job->cpu) { job->failed = 1; return NULL; }
    errno = EDOM;
    if (!job->phase)
        for (unsigned index = 0; index < 16; ++index)
        {
            syslog(LOG_INFO, "SYSLOG_RACE cpu=%u item=%u end=ok", job->cpu, index);
            if (errno != EDOM) job->failed = 2;
        }
    handled = 0;
    __atomic_store_n(&job->tid, sys_thread_self(), __ATOMIC_RELEASE);
    uint64_t start = sys_monotonic_millis();
    job->result = usleep(job->phase ? UINT_MAX : 25000u);
    job->elapsed = sys_monotonic_millis() - start;
    job->error = errno; job->handled = handled;
    return NULL;
}

int main(void)
{
    service_fixture_t *test = calloc(1, sizeof(*test)); CHECK(test, "heap fixture");
    CHECK(setlogmask(0) == 0xff, "default severity mask");
    openlog("alix-syslog", LOG_PID | LOG_NDELAY, LOG_LOCAL0);
    static const char direct[] = "SYSLOG_DIRECT_RECORD\n";
    int64_t direct_result = sys_file_io(SYSCALL_FILE_LOG, (uintptr_t)direct, sizeof(direct) - 1, 0, 0);
    CHECK(direct_result == sizeof(direct) - 1, "protected journal append");
    errno = ENOENT;
    syslog(LOG_NOTICE, "SYSLOG_NATIVE errno=%m literal=%%m");
    CHECK(errno == ENOENT, "syslog preserves caller errno");
    CHECK(setlogmask(LOG_UPTO(LOG_ERR)) == 0xff, "severity mask update");
    syslog(LOG_DEBUG, "SYSLOG_SHOULD_NOT_APPEAR");
    syslog(LOG_ERR, "SYSLOG_ALLOWED");
    CHECK(setlogmask(0) == LOG_UPTO(LOG_ERR) && setlogmask(0xff) == LOG_UPTO(LOG_ERR), "severity query and restore");
    CHECK(!getrlimit(RLIMIT_NOFILE, &test->limit), "descriptor limit query");
    test->lowered = test->limit; test->lowered.rlim_cur = 3;
    CHECK(!setrlimit(RLIMIT_NOFILE, &test->lowered), "descriptor exhaustion fixture");
    errno = EDOM; syslog(LOG_NOTICE, "SYSLOG_WITHOUT_DESCRIPTOR");
    CHECK(errno == EDOM && !setrlimit(RLIMIT_NOFILE, &test->limit), "logging does not allocate a public descriptor");
    CHECK(sys_file_io(SYSCALL_FILE_LOG, 1, 1, 0, 0) == -EFAULT &&
          sys_file_io(SYSCALL_FILE_LOG, (uintptr_t)test->payload, SYSCALL_LOG_MAX_BYTES + 1, 0, 0) == -EINVAL &&
          sys_file_io(SYSCALL_FILE_LOG, (uintptr_t)test->payload, 1, 1, 0) == -EINVAL, "checked logging ABI");
    test->action.sa_handler = caught; test->action.sa_flags = SA_RESTART;
    CHECK(!sigemptyset(&test->action.sa_mask) && !sigaction(SIGUSR1, &test->action, NULL), "caught signal setup");
    errno = EDOM; CHECK(!usleep(0) && errno == EDOM, "zero microsecond sleep");
    for (unsigned phase = 0; phase < 2; ++phase)
    {
        memset(test->jobs, 0, sizeof(test->jobs));
        for (unsigned cpu = 0; cpu < 8; ++cpu)
        {
            service_job_t *job = &test->jobs[cpu]; job->cpu = cpu; job->phase = phase;
            CHECK(!pthread_create(&job->thread, NULL, worker, job), "worker creation");
        }
        if (phase)
            for (unsigned cpu = 0; cpu < 8; ++cpu)
            {
                service_job_t *job = &test->jobs[cpu]; uint64_t limit = sys_monotonic_millis() + 5000;
                bool blocked = false;
                while (sys_monotonic_millis() < limit)
                {
                    uint64_t tid = __atomic_load_n(&job->tid, __ATOMIC_ACQUIRE);
                    if (tid && !sys_thread_info(tid, &job->info) && job->info.state == SYSCALL_THREAD_STATE_BLOCKED) { blocked = true; break; }
                    sys_sleep_ms(1);
                }
                CHECK(blocked && !pthread_kill(job->thread, SIGUSR1), "interrupt maximum microsecond delay");
            }
        for (unsigned cpu = 0; cpu < 8; ++cpu)
        {
            service_job_t *job = &test->jobs[cpu];
            CHECK(!pthread_join(job->thread, NULL) && !job->failed, "pinned worker completion");
            if (!phase) CHECK(!job->result && job->elapsed >= 25 && job->error == EDOM, "microsecond delay rounds safely");
            else CHECK(job->result == -1 && job->error == EINTR && job->handled == 1 && job->elapsed < 6000, "usleep is interruptible with SA_RESTART");
        }
    }
    closelog();
    int fd = open("/var/log/console.log", O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0 && !fstat(fd, &test->metadata) && test->metadata.st_size < 2u * 1024u * 1024u, "native system journal");
    CHECK((test->metadata.st_mode & 0777) == 0644 && unlink("/var/log/console.log") == -1 && errno == EROFS,
          "journal permissions and locked namespace");
    size_t size = test->metadata.st_size, used = 0;
    char *journal = calloc(size + 1, 1); CHECK(journal, "journal reply heap");
    while (used < size)
    {
        ssize_t count = read(fd, journal + used, size - used);
        CHECK(count > 0, "journal readback"); used += (size_t)count;
    }
    CHECK(!close(fd), "journal close");
    snprintf(test->expected, sizeof(test->expected), "alix-syslog[%d]: SYSLOG_NATIVE errno=%s literal=%%m", getpid(), strerror(ENOENT));
    if (!(strstr(journal, test->expected) && strstr(journal, "SYSLOG_ALLOWED") &&
          strstr(journal, "SYSLOG_WITHOUT_DESCRIPTOR") && !strstr(journal, "SYSLOG_SHOULD_NOT_APPEAR")))
    {
        serial_printf("SYSLOG_USLEEP_TEST: journal native=%u allowed=%u descriptor=%u filtered=%u expected=%s\n",
            !!strstr(journal, "SYSLOG_NATIVE"), !!strstr(journal, "SYSLOG_ALLOWED"),
            !!strstr(journal, "SYSLOG_WITHOUT_DESCRIPTOR"), !!strstr(journal, "SYSLOG_SHOULD_NOT_APPEAR"), test->expected);
        char *entry = strstr(journal, "SYSLOG_NATIVE");
        if (entry) { char *end = strchr(entry, '\n'); sys_serial_write(entry, end ? (size_t)(end - entry) + 1 : strlen(entry)); }
        CHECK(false, "journal formatting and mask readback");
    }
    for (unsigned cpu = 0; cpu < 8; ++cpu)
        for (unsigned index = 0; index < 16; ++index)
        {
            snprintf(test->expected, sizeof(test->expected), "SYSLOG_RACE cpu=%u item=%u end=ok\n", cpu, index);
            char *found = strstr(journal, test->expected);
            CHECK(found && !strstr(found + strlen(test->expected), test->expected), "complete exactly-once concurrent log records");
        }
    free(journal); free(test);
    serial_printf("SYSLOG_USLEEP_TEST: PASS cpus=8 records=128 journal=1 mask=1 errno=1 fd_independent=1 timers=8 interrupts=8 max_delay=1\n");
    return 0;
}
