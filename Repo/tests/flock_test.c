#include "fcntl.h"
#include "sys/file.h"
#include "sys/wait.h"
#include "pthread.h"
#include "signal.h"
#include "spawn.h"
#include "unistd.h"
#include "usyscall.h"
#include "stdlib.h"
#include "string.h"
#include "stdio.h"
#include "serial.h"
#include "errno.h"

#define BASE "/tmp/flock-native"
#define MAIN_PATH BASE "/counter"
#define HELD_PATH BASE "/child-held"
#define READY_PATH BASE "/child-ready"
#define CHECK(c,label) do { if(!(c)){serial_printf("FLOCK_NATIVE_TEST: FAIL %s line=%u errno=%d\n",label,__LINE__,errno);return 1;} }while(0)
typedef struct fixture fixture_t;
typedef struct {
    fixture_t *fixture;
    pthread_t thread;
    unsigned cpu, failed;
    uint64_t tid, value;
    int fd, result, error;
    uint32_t done;
    syscall_thread_info_t info;
} job_t;
struct fixture {
    uint32_t ready, start, cpu_mask;
    job_t jobs[8];
    struct sigaction action;
    char executable[4096], descriptor[32];
    char *arguments[4];
    unsigned char byte;
    uint64_t child_tid;
    int status;
    syscall_process_info_t snapshot[256];
};
static volatile sig_atomic_t caught_signals;
static void caught(int number) { if (number == SIGUSR1) ++caught_signals; }
static int wait_blocked(job_t *job)
{
    uint64_t deadline = sys_monotonic_millis() + 5000;
    while (sys_monotonic_millis() < deadline)
    {
        uint64_t tid = __atomic_load_n(&job->tid, __ATOMIC_ACQUIRE);
        if (tid && !sys_thread_info(tid, &job->info) && job->info.state == SYSCALL_THREAD_STATE_BLOCKED) return 0;
        if (__atomic_load_n(&job->done, __ATOMIC_ACQUIRE)) return -1;
        sys_sleep_ms(1);
    }
    return -1;
}
static void *counter_worker(void *opaque)
{
    job_t *job = opaque; fixture_t *test = job->fixture;
    if (sys_thread_set_affinity(job->cpu) || sys_thread_cpu() != job->cpu) job->failed = 1;
    job->fd = open(MAIN_PATH, O_RDWR | O_CLOEXEC);
    if (job->fd < 0) job->failed = 2;
    __atomic_fetch_or(&test->cpu_mask, 1u << job->cpu, __ATOMIC_RELAXED);
    __atomic_add_fetch(&test->ready, 1u, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&test->start, __ATOMIC_ACQUIRE)) sys_yield();
    for (unsigned index = 0; index < 32 && !job->failed; ++index)
    {
        if (flock(job->fd, LOCK_EX)) { job->failed = 3; break; }
        if (lseek(job->fd, 0, SEEK_SET) != 0 || read(job->fd, &job->value, sizeof(job->value)) != sizeof(job->value)) job->failed = 4;
        else
        {
            ++job->value; sys_yield();
            if (lseek(job->fd, 0, SEEK_SET) != 0 || write(job->fd, &job->value, sizeof(job->value)) != sizeof(job->value)) job->failed = 5;
        }
        if (flock(job->fd, LOCK_UN)) job->failed = 6;
    }
    if (job->fd >= 0 && close(job->fd)) job->failed = 7;
    return NULL;
}
static void *waiter(void *opaque)
{
    job_t *job = opaque;
    if (sys_thread_set_affinity(job->cpu)) job->failed = 1;
    __atomic_store_n(&job->tid, sys_thread_self(), __ATOMIC_RELEASE);
    job->result = flock(job->fd, LOCK_EX); job->error = errno;
    __atomic_store_n(&job->done, 1u, __ATOMIC_RELEASE);
    return NULL;
}
static int lock_eventually(int fd)
{
    uint64_t deadline = sys_monotonic_millis() + 5000;
    while (flock(fd, LOCK_EX | LOCK_NB))
    {
        if (errno != EWOULDBLOCK || sys_monotonic_millis() >= deadline) return -1;
        sys_sleep_ms(1);
    }
    return 0;
}
static int wait_child_blocked(fixture_t *test, pid_t child)
{
    uint64_t deadline = sys_monotonic_millis() + 5000;
    while (sys_monotonic_millis() < deadline)
    {
        ssize_t count = sys_proc_snapshot(test->snapshot, 256);
        if (count < 0 || count > 256) return -1;
        for (ssize_t index = 0; index < count; ++index)
            if (test->snapshot[index].pid == (uint64_t)child &&
                test->snapshot[index].thread_state == SYSCALL_THREAD_STATE_BLOCKED) return 0;
        sys_sleep_ms(1);
    }
    return -1;
}
static int spawn(fixture_t *test, const char *mode, pid_t *pid)
{
    if (alix_get_executable_path(test->executable, sizeof(test->executable)) <= 0) return -1;
    test->arguments[0] = test->executable; test->arguments[1] = (char *)mode;
    test->arguments[2] = !strcmp(mode, "inherit") ? test->descriptor : NULL; test->arguments[3] = NULL;
    return posix_spawn(pid, test->executable, NULL, NULL, test->arguments, NULL);
}
int main(int argc, char **argv)
{
    fixture_t *test = calloc(1, sizeof(*test)); CHECK(test, "heap fixture");
    if (argc == 3 && !strcmp(argv[1], "inherit"))
    {
        int inherited = atoi(argv[2]);
        CHECK(!flock(inherited, LOCK_EX | LOCK_NB) && !flock(inherited, LOCK_UN), "inherited open-description lock ownership");
        free(test); return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "child"))
    {
        CHECK(!sys_thread_set_affinity(6), "child CPU affinity");
        int held = open(HELD_PATH, O_RDWR | O_CREAT | O_CLOEXEC); CHECK(held >= 0 && !flock(held, LOCK_EX), "child acquires sibling lock");
        int wait_fd = open(MAIN_PATH, O_RDWR | O_CLOEXEC); CHECK(wait_fd >= 0, "child blocking target");
        int ready = open(READY_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC); CHECK(ready >= 0, "child readiness file");
        test->child_tid = sys_thread_self();
        CHECK(write(ready, &test->child_tid, sizeof(test->child_tid)) == sizeof(test->child_tid) && !close(ready), "publish child thread identity");
        (void)flock(wait_fd, LOCK_EX);
        serial_printf("FLOCK_NATIVE_TEST: FAIL killed child resumed its blocked lock\n"); return 1;
    }
    CHECK(!mkdir(BASE, 0777), "test directory");
    int a = open(MAIN_PATH, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC);
    int b = open(MAIN_PATH, O_RDWR | O_CLOEXEC); CHECK(a >= 0 && b >= 0, "independent opens");
    CHECK(!flock(a, LOCK_SH) && !flock(b, LOCK_SH), "concurrent shared owners");
    CHECK(flock(a, LOCK_EX | LOCK_NB) == -1 && errno == EWOULDBLOCK, "nonblocking upgrade conflict");
    CHECK(!flock(b, LOCK_UN) && !flock(b, LOCK_EX | LOCK_NB), "failed upgrade releases old shared hold");
    CHECK(flock(a, LOCK_SH | LOCK_NB) == -1 && errno == EWOULDBLOCK, "exclusive owner excludes reader");
    CHECK(!flock(b, LOCK_UN) && !flock(a, LOCK_EX), "exclusive acquisition");
    CHECK(lseek(b, 0, SEEK_SET) == 0 && write(b, "A", 1) == 1, "whole-file locking remains advisory");
    int alias = dup(a); CHECK(alias >= 0 && !close(a), "close one duplicate");
    CHECK(flock(b, LOCK_EX | LOCK_NB) == -1 && errno == EWOULDBLOCK, "duplicate retains lock");
    CHECK(!flock(alias, LOCK_UN) && !flock(b, LOCK_EX | LOCK_NB) && !flock(b, LOCK_UN), "unlock through duplicate");
    CHECK(!flock(alias, LOCK_EX) && !close(alias) && !flock(b, LOCK_EX | LOCK_NB), "last-close release is promptly visible");
    CHECK(!flock(b, LOCK_UN), "initial lock cleanup");
    CHECK(flock(-1, LOCK_EX) == -1 && errno == EBADF, "invalid fd");
    CHECK(flock(b, 0) == -1 && errno == EINVAL && flock(b, LOCK_SH | LOCK_EX) == -1 && errno == EINVAL, "invalid modes");
    CHECK(sys_file_io(SYSCALL_FILE_FLOCK, b, LOCK_EX, 1, 0) == -EINVAL, "reserved syscall arguments");
    CHECK(flock(1, LOCK_EX) == -1 && errno == EOPNOTSUPP, "unsupported console descriptor");
    a = open(MAIN_PATH, O_RDONLY | O_CLOEXEC); CHECK(a >= 0 && !flock(a, LOCK_EX) && !close(a), "read-only regular-file locking");
    CHECK(!flock(b, LOCK_EX | LOCK_NB) && !rename(MAIN_PATH, BASE "/renamed"), "rename locked inode");
    a = open(BASE "/renamed", O_RDWR | O_CLOEXEC); CHECK(a >= 0 && flock(a, LOCK_EX | LOCK_NB) == -1 && errno == EWOULDBLOCK, "lock identity survives rename");
    CHECK(!close(a) && !flock(b, LOCK_UN) && !rename(BASE "/renamed", MAIN_PATH), "rename cleanup");
    CHECK(lseek(b, 0, SEEK_SET) == 0 && write(b, &test->jobs[0].value, sizeof(uint64_t)) == sizeof(uint64_t), "counter initialize");
    for (unsigned cpu = 0; cpu < 8; ++cpu)
    {
        job_t *job = &test->jobs[cpu]; job->fixture = test; job->cpu = cpu; job->fd = -1;
        CHECK(!pthread_create(&job->thread, NULL, counter_worker, job), "start pinned workers");
    }
    uint64_t deadline = sys_monotonic_millis() + 5000;
    while (__atomic_load_n(&test->ready, __ATOMIC_ACQUIRE) != 8 && sys_monotonic_millis() < deadline) sys_sleep_ms(1);
    CHECK(test->ready == 8, "workers ready"); __atomic_store_n(&test->start, 1u, __ATOMIC_RELEASE);
    for (unsigned cpu = 0; cpu < 8; ++cpu) CHECK(!pthread_join(test->jobs[cpu].thread, NULL) && !test->jobs[cpu].failed, "pinned critical sections");
    CHECK(test->cpu_mask == 0xff && lseek(b, 0, SEEK_SET) == 0 && read(b, &test->jobs[0].value, sizeof(uint64_t)) == sizeof(uint64_t) && test->jobs[0].value == 256, "all updates preserved");

    job_t *job = &test->jobs[7]; job->done = 0; job->tid = 0; job->cpu = 7;
    job->fd = open(MAIN_PATH, O_RDWR | O_CLOEXEC); CHECK(job->fd >= 0 && !flock(b, LOCK_EX), "descriptor reuse fixture");
    CHECK(!pthread_create(&job->thread, NULL, waiter, job) && !wait_blocked(job), "original description blocks");
    int original_fd = job->fd; CHECK(!close(original_fd), "close waiting descriptor number");
    int replacement = open(BASE "/reused", O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC);
    CHECK(replacement == original_fd && !flock(b, LOCK_UN) && !pthread_join(job->thread, NULL) && job->result == 0, "waiting acquisition retains original identity");
    a = open(BASE "/reused", O_RDWR | O_CLOEXEC);
    CHECK(a >= 0 && !flock(a, LOCK_EX | LOCK_NB) && !flock(a, LOCK_UN) && !close(a) && !close(replacement), "reused number never retargets lock");
    CHECK(!flock(b, LOCK_EX | LOCK_NB) && !flock(b, LOCK_UN), "closed original target leaves no hidden lock");
    job->done = 0; job->tid = 0;
    job->fd = open(MAIN_PATH, O_RDWR | O_CLOEXEC); CHECK(job->fd >= 0 && !flock(b, LOCK_EX), "interrupt fixture");
    test->action.sa_handler = caught; CHECK(!sigemptyset(&test->action.sa_mask) && !sigaction(SIGUSR1, &test->action, NULL), "caught signal");
    CHECK(!pthread_create(&job->thread, NULL, waiter, job) && !wait_blocked(job), "lock waiter blocks");
    int progress = open(BASE "/progress", O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC);
    CHECK(progress >= 0 && write(progress, "P", 1) == 1 && !close(progress), "storage progresses while lock waits");
    CHECK(!pthread_kill(job->thread, SIGUSR1) && !pthread_join(job->thread, NULL) && job->result == -1 && job->error == EINTR && caught_signals == 1, "interrupt blocked lock");
    CHECK(!flock(b, LOCK_UN) && !lock_eventually(b), "cancelled caller never acquires late lock");
    CHECK(!flock(b, LOCK_UN) && !close(job->fd), "interrupt cleanup");

    CHECK(!flock(b, LOCK_EX) && !fcntl(b, F_SETFD, 0), "inheritable lock owner");
    snprintf(test->descriptor, sizeof(test->descriptor), "%d", b); pid_t child;
    CHECK(!spawn(test, "inherit", &child) && waitpid(child, &test->status, 0) == child && WIFEXITED(test->status) && !WEXITSTATUS(test->status), "native inherited-description child");
    a = open(MAIN_PATH, O_RDWR | O_CLOEXEC); CHECK(a >= 0 && !flock(a, LOCK_EX | LOCK_NB) && !flock(a, LOCK_UN), "child unlock affects shared open description");
    CHECK(!close(a) && !fcntl(b, F_SETFD, FD_CLOEXEC) && !flock(b, LOCK_EX), "independent killed child fixture");
    CHECK(!spawn(test, "child", &child), "spawn blocked child");
    bool ready = false; deadline = sys_monotonic_millis() + 5000;
    while (!ready && sys_monotonic_millis() < deadline)
    {
        int fd = open(READY_PATH, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) { ready = read(fd, &test->child_tid, sizeof(test->child_tid)) == sizeof(test->child_tid); close(fd); }
        if (!ready) sys_sleep_ms(1);
    }
    CHECK(ready, "child owns sibling lock"); job->done = 0; job->tid = test->child_tid;
    CHECK(!wait_child_blocked(test, child), "child has blocked I/O"); sys_sleep_ms(20);
    CHECK(!kill(child, SIGKILL) && waitpid(child, &test->status, 0) == child && WIFSIGNALED(test->status) && WTERMSIG(test->status) == SIGKILL, "kill and reap lock waiter");
    a = open(HELD_PATH, O_RDWR | O_CLOEXEC); CHECK(a >= 0 && !lock_eventually(a) && !flock(a, LOCK_UN) && !close(a), "killed process releases held sibling lock");
    CHECK(!flock(b, LOCK_UN) && !close(b), "parent final release");
    CHECK(!unlink(HELD_PATH) && !unlink(READY_PATH) && !unlink(MAIN_PATH) && !unlink(BASE "/progress") && !unlink(BASE "/reused") && !rmdir(BASE), "fixture cleanup");
    serial_printf("FLOCK_NATIVE_TEST: PASS cpus=8 sections=256 shared=1 exclusive=1 aliases=1 close=1 rename=1 inherited=1 reuse=1 eintr=1 killed=1 progress=1 advisory=1\n");
    free(test); return 0;
}
