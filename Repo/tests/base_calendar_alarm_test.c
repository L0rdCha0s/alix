#include "alix_process.h"
#include "dirent.h"
#include "errno.h"
#include "fcntl.h"
#include "pthread.h"
#include "serial.h"
#include "signal.h"
#include "stdlib.h"
#include "string.h"
#include "sys/stat.h"
#include "sys/wait.h"
#include "unistd.h"
#include "usyscall.h"
#include "calendar_parse_cases.h"

#define CHECK(c, label) do { if (!(c)) { serial_printf("BASE_CALENDAR_ALARM_TEST: FAIL %s line=%u errno=%d\n", label, __LINE__, errno); return 1; } } while (0)
typedef struct
{
    pthread_t thread;
    unsigned cpu, failed, replacements;
    DIR *directory;
    struct dirent entry;
    unsigned *seen;
} calendar_job_t;
typedef struct
{
    calendar_job_t jobs[8];
    unsigned seen[32];
    char directory[128], path[256];
    char *arguments[3];
    struct sigaction action;
    sigset_t mask, pending;
    struct stat64 metadata;
    int status, wait_signal;
} calendar_fixture_t;
static volatile sig_atomic_t caught;
static void alarm_handler(int number) { if (number == SIGALRM) ++caught; }

static void *calendar_worker(void *context)
{
    calendar_job_t *job = context;
    if (sys_thread_set_affinity(job->cpu) || sys_thread_cpu() != job->cpu) { job->failed = 1; return NULL; }
    if (job->replacements)
    {
        for (unsigned i = 0; i < 128; ++i)
        {
            unsigned previous = alarm(30 + job->cpu);
            if (previous && (previous < 30 || previous > 37)) job->failed = 2;
        }
        return NULL;
    }
    job->failed = (unsigned)calendar_parse_cases(job->cpu);
    for (;;)
    {
        struct dirent *entry = NULL;
        errno = EDOM;
        int result = readdir_r(job->directory, &job->entry, &entry);
        if (result || errno != EDOM) { job->failed = 3; break; }
        if (!entry) break;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char *end;
        unsigned long index = strtoul(entry->d_name + 4, &end, 10);
        if (entry != &job->entry || strncmp(entry->d_name, "item", 4) || *end || index >= 32 || !entry->d_ino || entry->d_type != DT_REG)
        { job->failed = 4; break; }
        __atomic_add_fetch(&job->seen[index], 1, __ATOMIC_RELAXED);
    }
    return NULL;
}
static void *alarm_waiter(void *context)
{
    calendar_fixture_t *test = context;
    if (sigwait(&test->mask, &test->wait_signal)) test->wait_signal = -1;
    return NULL;
}
static int child(const char *mode)
{
    CHECK(!alarm(0), "new child has no inherited alarm");
    if (!strcmp(mode, "ignore")) CHECK(signal(SIGALRM, SIG_IGN) != SIG_ERR, "ignored child action");
    CHECK(!alarm(1), "child alarm");
    if (!strcmp(mode, "exit")) return 37;
    sys_sleep_ms(1400);
    return !strcmp(mode, "ignore") ? 0 : 99;
}
int main(int argc, char **argv)
{
    if (argc > 1) return child(argv[1]);
    calendar_fixture_t *test = calloc(1, sizeof(*test)); CHECK(test, "fixture heap");
    CHECK(!setenv("TZ", "UTC0", 1), "UTC fixture selection"); tzset();
    strcpy(test->directory, "/tmp/base-calendar-XXXXXX");
    CHECK(mkdtemp(test->directory), "private test directory");
    for (unsigned i = 0; i < 32; ++i)
    {
        snprintf(test->path, sizeof(test->path), "%s/item%u", test->directory, i);
        int fd = open(test->path, O_CREAT | O_EXCL | O_RDWR, 0600);
        CHECK(fd >= 0 && write(fd, "test", 4) == 4 && !fstat64(fd, &test->metadata) &&
              test->metadata.st_size == 4 && !close(fd) && !stat64(test->path, &test->metadata), "64-bit stat ABI");
    }
    DIR *directory = opendir(test->directory); CHECK(directory, "shared directory stream");
    for (unsigned cpu = 0; cpu < 8; ++cpu)
    {
        calendar_job_t *job = &test->jobs[cpu]; job->cpu = cpu; job->seen = test->seen; job->directory = directory;
        CHECK(!pthread_create(&job->thread, NULL, calendar_worker, job), "parser/directory workers");
    }
    for (unsigned cpu = 0; cpu < 8; ++cpu)
    {
        calendar_job_t *job = &test->jobs[cpu];
        CHECK(!pthread_join(job->thread, NULL), "worker join");
        if (job->failed) serial_printf("BASE_CALENDAR_ALARM_TEST: worker cpu=%u failure=%u\n", cpu, job->failed);
        CHECK(!job->failed, "thread-isolated parse and directory result");
    }
    for (unsigned i = 0; i < 32; ++i) CHECK(test->seen[i] == 1, "directory exactly-once entries");
    struct dirent *entry = (void *)1;
    CHECK(!readdir_r(directory, &test->jobs[0].entry, &entry) && !entry, "directory EOF");
    rewinddir(directory); CHECK(readdir(directory) && !closedir(directory), "mixed directory APIs");
    for (unsigned i = 0; i < 32; ++i)
    {
        snprintf(test->path, sizeof(test->path), "%s/item%u", test->directory, i);
        CHECK(!unlink(test->path), "fixture file removal");
    }
    CHECK(!rmdir(test->directory), "fixture directory removal");
    CHECK(!sigemptyset(&test->action.sa_mask), "handler mask");
    test->action.sa_handler = alarm_handler; test->action.sa_flags = SA_RESTART;
    CHECK(!sigaction(SIGALRM, &test->action, NULL), "alarm handler");
    errno = EDOM;
    CHECK(!alarm(UINT32_MAX) && alarm(0) == UINT32_MAX && errno == EDOM, "maximum alarm delay and cancellation");
    CHECK(!alarm(3), "arm alarm"); sys_sleep_ms(20);
    CHECK(alarm(0) == 3 && !caught, "round up remaining seconds");
    uint64_t start = sys_monotonic_millis();
    CHECK(!alarm(1) && usleep(UINT32_MAX) == -1 && errno == EINTR, "alarm interrupts sleep despite SA_RESTART");
    CHECK(caught == 1 && sys_monotonic_millis() - start >= 990 && !alarm(0), "one-shot delivery and deadline");
    CHECK(!sigemptyset(&test->mask) && !sigaddset(&test->mask, SIGALRM) &&
          !pthread_sigmask(SIG_BLOCK, &test->mask, NULL), "block alarm");
    CHECK(!alarm(1), "blocked alarm"); sys_sleep_ms(1200);
    CHECK(!sigpending(&test->pending) && sigismember(&test->pending, SIGALRM) == 1 && caught == 1,
          "blocked process signal remains pending");
    CHECK(!sigwait(&test->mask, &test->wait_signal) && test->wait_signal == SIGALRM && !alarm(0), "consume pending alarm");
    CHECK(!pthread_create(&test->jobs[0].thread, NULL, alarm_waiter, test) && !alarm(1), "process alarm synchronous waiter");
    CHECK(!pthread_join(test->jobs[0].thread, NULL) && test->wait_signal == SIGALRM && caught == 1,
          "alarm delivered to eligible process thread");
    CHECK(!pthread_sigmask(SIG_UNBLOCK, &test->mask, NULL), "unblock alarm");
    for (unsigned cpu = 0; cpu < 8; ++cpu)
    {
        calendar_job_t *job = &test->jobs[cpu]; job->replacements = 1;
        CHECK(!pthread_create(&job->thread, NULL, calendar_worker, job), "concurrent replacement workers");
    }
    for (unsigned cpu = 0; cpu < 8; ++cpu)
        CHECK(!pthread_join(test->jobs[cpu].thread, NULL) && !test->jobs[cpu].failed, "process-wide atomic alarm replacement");
    unsigned remaining = alarm(0); CHECK(remaining >= 30 && remaining <= 37, "last concurrent alarm cancellation");
    test->arguments[0] = "/tmp/test.elf";
    static const char *const modes[] = {"exit", "fatal", "ignore"};
    for (unsigned i = 0; i < 3; ++i)
    {
        test->arguments[1] = (char *)modes[i];
        pid_t pid = alix_spawn_argv(test->arguments[0], test->arguments); CHECK(pid > 0, "alarm child launch");
        CHECK(waitpid(pid, &test->status, 0) == pid, "alarm child wait");
        if (i == 1) CHECK(WIFSIGNALED(test->status) && WTERMSIG(test->status) == SIGALRM, "default alarm terminates child");
        else CHECK(WIFEXITED(test->status) && WEXITSTATUS(test->status) == (i == 0 ? 37 : 0), "exit cleanup and ignored alarm");
    }
    CHECK(caught == 1, "cancelled and dead-process alarms never reach parent");
    free(test);
    serial_printf("BASE_CALENDAR_ALARM_TEST: PASS cpus=8 roundtrips=49152 directory_entries=32 alarm=1 blocked=1 replacement=1024 exit_cleanup=1 stat64=1\n");
    return 0;
}
