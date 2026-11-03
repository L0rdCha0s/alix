#include "alix_process.h"
#include "dirent.h"
#include "errno.h"
#include "fcntl.h"
#include "poll.h"
#include "pthread.h"
#include "serial.h"
#include "signal.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "sys/resource.h"
#include "sys/stat.h"
#include "sys/wait.h"
#include "unistd.h"
#include "usyscall.h"

#define CHECK(c, label) do { if (!(c)) { serial_printf("NAMED_FIFO_TEST: FAIL %s line=%u errno=%d\n", label, __LINE__, errno); return 1; } } while (0)
typedef struct { uint32_t magic, cpu, index, inverse; } record_t;
typedef struct
{
    pthread_t thread;
    unsigned cpu, mode, failed;
    uint64_t tid;
    int fd, error;
    char path[256];
    syscall_thread_info_t info;
    record_t record;
} fifo_job_t;
typedef struct
{
    fifo_job_t jobs[8];
    char directory[128], path[256], text[32], *arguments[4];
    unsigned seen[8][32];
    record_t records[256];
    struct stat metadata, other;
    struct pollfd poll;
    struct sigaction action;
    struct rlimit limit;
    int pipes[2], status;
} fifo_fixture_t;
static volatile sig_atomic_t interrupted;
static void caught(int number) { if (number == SIGUSR1) ++interrupted; }

static void *fifo_worker(void *context)
{
    fifo_job_t *job = context;
    if (sys_thread_set_affinity(job->cpu) || sys_thread_cpu() != job->cpu) { job->failed = 1; return NULL; }
    __atomic_store_n(&job->tid, sys_thread_self(), __ATOMIC_RELEASE);
    job->fd = open(job->path, job->mode == 1 || job->mode == 3 ? O_RDONLY : O_WRONLY);
    job->error = errno;
    if (job->mode == 3) { if (job->fd >= 0) { close(job->fd); job->failed = 2; } return NULL; }
    if (job->fd < 0) { job->failed = 3; return NULL; }
    if (job->mode == 1)
    {
        if (read(job->fd, &job->record, sizeof(job->record)) != sizeof(job->record) || job->record.magic != 0xf1f0cafe) job->failed = 4;
    }
    else
    {
        unsigned count = job->mode == 2 ? 1 : 32;
        for (unsigned i = 0; i < count; ++i)
        {
            job->record = (record_t){0xf1f0cafe, job->cpu, i, ~i};
            if (write(job->fd, &job->record, sizeof(job->record)) != sizeof(job->record)) { job->failed = 5; break; }
        }
    }
    if (close(job->fd)) job->failed = 6;
    return NULL;
}
static int wait_blocked(fifo_job_t *job)
{
    uint64_t deadline = sys_monotonic_millis() + 6000;
    while (sys_monotonic_millis() < deadline)
    {
        uint64_t tid = __atomic_load_n(&job->tid, __ATOMIC_ACQUIRE);
        if (tid && !sys_thread_info(tid, &job->info) && job->info.state == SYSCALL_THREAD_STATE_BLOCKED) return 0;
        sys_sleep_ms(1);
    }
    return 1;
}
static int child(int argc, char **argv)
{
    if (argc != 4) return 1;
    int notify = atoi(argv[3]);
    if (write(notify, "r", 1) != 1) return 2;
    int fd = open(argv[2], O_RDONLY);
    if (fd >= 0) close(fd);
    return 3;
}
int main(int argc, char **argv)
{
    if (argc > 1) return child(argc, argv);
    fifo_fixture_t *test = calloc(1, sizeof(*test)); CHECK(test, "heap fixture");
    strcpy(test->directory, "/tmp/named-fifo-XXXXXX"); CHECK(mkdtemp(test->directory), "fixture directory");
    snprintf(test->path, sizeof(test->path), "%s/pipe", test->directory);
    mode_t previous = umask(0027);
    CHECK(!mkfifo(test->path, 0766), "create FIFO"); umask(previous);
    CHECK(!stat(test->path, &test->metadata) && S_ISFIFO(test->metadata.st_mode) &&
          (test->metadata.st_mode & 0777) == 0740 && !test->metadata.st_size && test->metadata.st_nlink == 1, "FIFO metadata and creation mask");
    CHECK(mkfifo(test->path, 0600) == -1 && errno == EEXIST &&
          mkfifo((void *)1, 0600) == -1 && errno == EFAULT, "exclusive creation and checked copies");
    CHECK(open(test->path, O_WRONLY | O_NONBLOCK) == -1 && errno == ENXIO, "nonblocking writer without a reader");
    int reader = open(test->path, O_RDONLY | O_NONBLOCK | O_CLOEXEC); CHECK(reader >= 0, "nonblocking reader");
    CHECK(fcntl(reader, F_GETFD) == FD_CLOEXEC && !fstat(reader, &test->other) &&
          S_ISFIFO(test->other.st_mode) && test->other.st_ino == test->metadata.st_ino &&
          test->other.st_mode == test->metadata.st_mode, "open FIFO identity and mode");
    CHECK(read(reader, test->text, 1) == 0, "empty FIFO with no writer is EOF");
    int writer = open(test->path, O_WRONLY | O_NONBLOCK); CHECK(writer >= 0, "connected writer");
    CHECK(read(reader, test->text, 1) == -1 && errno == EAGAIN && write(writer, "first", 5) == 5 &&
          read(reader, test->text, sizeof(test->text)) == 5 && !memcmp(test->text, "first", 5), "real byte stream");
    CHECK(!close(writer), "writer close");
    test->poll = (struct pollfd){reader, POLLIN, 0};
    CHECK(poll(&test->poll, 1, 3000) == 1 && (test->poll.revents & POLLHUP) && read(reader, test->text, 1) == 0, "last-writer HUP and EOF");
    for (unsigned cpu = 0; cpu < 8; ++cpu)
    {
        fifo_job_t *job = &test->jobs[cpu]; job->cpu = cpu; strcpy(job->path, test->path);
        CHECK(!pthread_create(&job->thread, NULL, fifo_worker, job), "independent concurrent writers");
    }
    for (unsigned cpu = 0; cpu < 8; ++cpu)
        CHECK(!pthread_join(test->jobs[cpu].thread, NULL) && !test->jobs[cpu].failed, "writer completion");
    size_t used = 0;
    while (used < sizeof(test->records))
    {
        ssize_t count = read(reader, (char *)test->records + used, sizeof(test->records) - used);
        CHECK(count > 0, "atomic records readback"); used += (size_t)count;
    }
    for (unsigned i = 0; i < 256; ++i)
    {
        record_t *record = &test->records[i];
        CHECK(record->magic == 0xf1f0cafe && record->cpu < 8 && record->index < 32 && record->inverse == ~record->index &&
              !test->seen[record->cpu][record->index]++, "complete exactly-once atomic records");
    }
    writer = open(test->path, O_WRONLY); CHECK(writer >= 0 && !unlink(test->path), "unlink retains open endpoints");
    CHECK(!mkfifo(test->path, 0600) && !stat(test->path, &test->other) && test->other.st_ino != test->metadata.st_ino,
          "recreated name has independent identity");
    CHECK(open(test->path, O_WRONLY | O_NONBLOCK) == -1 && errno == ENXIO &&
          write(writer, "old", 3) == 3 && read(reader, test->text, sizeof(test->text)) == 3 && !memcmp(test->text, "old", 3) &&
          !fstat(reader, &test->metadata) && !test->metadata.st_nlink, "unlinked stream is distinct from replacement");
    CHECK(!close(writer) && !close(reader), "unlinked endpoints close");
    for (unsigned cpu = 0; cpu < 8; ++cpu)
    {
        fifo_job_t *job = &test->jobs[cpu]; memset(job, 0, sizeof(*job)); job->cpu = cpu; job->mode = 1;
        snprintf(job->path, sizeof(job->path), "%s/block%u", test->directory, cpu);
        CHECK(!mkfifo(job->path, 0600) && !pthread_create(&job->thread, NULL, fifo_worker, job), "blocking reader setup");
    }
    for (unsigned cpu = 0; cpu < 8; ++cpu) CHECK(!wait_blocked(&test->jobs[cpu]), "blocking reader registration");
    sys_sleep_ms(100);
    CHECK(!stat(test->path, &test->metadata), "all blocked opens leave the storage service usable");
    for (unsigned cpu = 0; cpu < 8; ++cpu)
    {
        writer = open(test->jobs[cpu].path, O_WRONLY | O_NONBLOCK); CHECK(writer >= 0, "reader/writer rendezvous");
        test->records[0] = (record_t){0xf1f0cafe, cpu, 0, ~0u};
        CHECK(write(writer, test->records, sizeof(record_t)) == sizeof(record_t) && !close(writer), "peer may close before reader returns");
    }
    for (unsigned cpu = 0; cpu < 8; ++cpu)
        CHECK(!pthread_join(test->jobs[cpu].thread, NULL) && !test->jobs[cpu].failed && !unlink(test->jobs[cpu].path), "rendezvous result and cleanup");
    fifo_job_t *job = &test->jobs[0]; memset(job, 0, sizeof(*job)); job->mode = 2; strcpy(job->path, test->path);
    CHECK(!pthread_create(&job->thread, NULL, fifo_worker, job) && !wait_blocked(job), "blocking writer registration");
    reader = open(test->path, O_RDONLY | O_NONBLOCK); CHECK(reader >= 0, "writer peer arrives");
    CHECK(!pthread_join(job->thread, NULL) && !job->failed && read(reader, test->records, sizeof(record_t)) == sizeof(record_t),
          "blocking writer rendezvous");
    /* Completed requests and descriptors retire on protected workers. Wait
     * for the final writer reference before testing a fresh disconnected open. */
    test->poll = (struct pollfd){reader, POLLIN, 0};
    CHECK(poll(&test->poll, 1, 3000) == 1 && (test->poll.revents & POLLHUP) && !close(reader), "writer retirement before cancellation fixture");
    test->action.sa_handler = caught; test->action.sa_flags = SA_RESTART;
    CHECK(!sigemptyset(&test->action.sa_mask) && !sigaction(SIGUSR1, &test->action, NULL) && !getrlimit(RLIMIT_NOFILE, &test->limit), "interruption fixture");
    struct rlimit limited = test->limit; limited.rlim_cur = 4;
    CHECK(!setrlimit(RLIMIT_NOFILE, &limited), "one available FD slot");
    memset(job, 0, sizeof(*job)); job->mode = 3; strcpy(job->path, test->path);
    CHECK(!pthread_create(&job->thread, NULL, fifo_worker, job) && !wait_blocked(job), "interruptible open registration");
    sys_sleep_ms(100);
    CHECK(!pthread_kill(job->thread, SIGUSR1) && !pthread_join(job->thread, NULL) && !job->failed &&
          job->fd == -1 && job->error == EINTR && interrupted == 1, "signal cancels blocked open despite SA_RESTART");
    uint64_t deadline = sys_monotonic_millis() + 3000;
    do { reader = open(test->path, O_RDONLY | O_NONBLOCK); if (reader >= 0) break; sys_sleep_ms(1); } while (sys_monotonic_millis() < deadline);
    CHECK(reader == 3 && !close(reader) && !setrlimit(RLIMIT_NOFILE, &test->limit), "cancelled open releases its FD reservation");
    CHECK(!pipe(test->pipes), "child acknowledgement pipe");
    snprintf(test->text, sizeof(test->text), "%d", test->pipes[1]);
    test->arguments[0] = "/tmp/test.elf"; test->arguments[1] = "blocked"; test->arguments[2] = test->path; test->arguments[3] = test->text;
    char **child_arguments = calloc(5, sizeof(char *)); CHECK(child_arguments, "child argv ownership");
    memcpy(child_arguments, test->arguments, sizeof(test->arguments));
    pid_t pid = alix_spawn_argv(test->arguments[0], child_arguments); free(child_arguments);
    CHECK(pid > 0 && !close(test->pipes[1]) && read(test->pipes[0], test->text, 1) == 1 && !close(test->pipes[0]), "blocked child started");
    sys_sleep_ms(150);
    CHECK(!kill(pid, SIGTERM) && waitpid(pid, &test->status, 0) == pid && WIFSIGNALED(test->status), "kill blocked opener");
    deadline = sys_monotonic_millis() + 3000;
    do { writer = open(test->path, O_WRONLY | O_NONBLOCK); if (writer < 0 && errno == ENXIO) break; if (writer >= 0) close(writer); sys_sleep_ms(1); } while (sys_monotonic_millis() < deadline);
    CHECK(writer == -1 && errno == ENXIO, "dead opener leaves no reader or pinned request");
    CHECK(!unlink(test->path) && !rmdir(test->directory), "fixture cleanup");
    free(test);
    serial_printf("NAMED_FIFO_TEST: PASS cpus=8 records=256 rendezvous=8 unlink=1 nonblock=1 signal=1 killed_opener=1 reservation=1\n");
    return 0;
}
