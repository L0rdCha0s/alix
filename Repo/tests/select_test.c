#include "sys/select.h"
#include "sys/mman.h"
#include "sys/socket.h"
#include "sys/wait.h"
#include "alix_process.h"
#include "pthread.h"
#include "fcntl.h"
#include "unistd.h"
#include "usyscall.h"
#include "signal.h"
#include "stdlib.h"
#include "string.h"
#include "stdio.h"
#include "serial.h"
#include "errno.h"
#include <stdint.h>

#define CHECK(c, label) do { if (!(c)) { serial_printf("SELECT_TEST: FAIL %s line=%u errno=%d\n", label, __LINE__, errno); return 1; } } while (0)
_Static_assert(sizeof(fd_set) == 32 && FD_SETSIZE == 256, "native select ABI");
typedef struct {
    pthread_t thread;
    uint64_t tid;
    syscall_thread_info_t info;
    fd_set read;
    int fd, result, error;
    unsigned cpu, failed;
} job_t;
typedef struct {
    fd_set read, write, except, saved;
    struct timeval timeout;
    struct sigaction action;
    int pairs[8][2], status, option;
    socklen_t option_size;
    job_t jobs[8];
    syscall_select_t query;
    syscall_process_info_t processes[256];
    char **arguments, reader_text[32], marker_text[32];
    unsigned char bytes[16384];
} fixture_t;
static volatile sig_atomic_t signals;
static void caught(int number) { if (number == SIGUSR1) ++signals; }

static void *waiter(void *argument)
{
    job_t *job = argument;
    if (sys_thread_set_affinity(job->cpu) || sys_thread_cpu() != job->cpu) job->failed = 1;
    FD_ZERO(&job->read); FD_SET(job->fd, &job->read);
    __atomic_store_n(&job->tid, sys_thread_self(), __ATOMIC_RELEASE);
    job->result = select(job->fd + 1, &job->read, NULL, NULL, NULL);
    job->error = errno;
    return NULL;
}
static int wait_blocked(job_t *job)
{
    uint64_t deadline = sys_monotonic_millis() + 3000;
    while (sys_monotonic_millis() < deadline)
    {
        uint64_t tid = __atomic_load_n(&job->tid, __ATOMIC_ACQUIRE);
        if (tid && !sys_thread_info(tid, &job->info) && job->info.state == SYSCALL_THREAD_STATE_BLOCKED) return 0;
        sys_yield();
    }
    return -1;
}
static int canceled_caller(fixture_t *test)
{
    CHECK(!pipe(test->pairs[0]) && !pipe(test->pairs[1]), "child pipes");
    CHECK(!fcntl(test->pairs[0][1], F_SETFD, FD_CLOEXEC) &&
          !fcntl(test->pairs[1][0], F_SETFD, FD_CLOEXEC), "child descriptor filter");
    test->arguments = calloc(5, sizeof(*test->arguments)); CHECK(test->arguments, "owned child arguments");
    snprintf(test->reader_text, sizeof(test->reader_text), "%d", test->pairs[0][0]);
    snprintf(test->marker_text, sizeof(test->marker_text), "%d", test->pairs[1][1]);
    test->arguments[0] = "/tmp/test.elf"; test->arguments[1] = "select-child";
    test->arguments[2] = test->reader_text; test->arguments[3] = test->marker_text;
    pid_t child = alix_spawn_argv(test->arguments[0], test->arguments);
    CHECK(child > 0 && !close(test->pairs[0][0]) && !close(test->pairs[1][1]), "spawn child");
    CHECK(read(test->pairs[1][0], test->bytes, 1) == 1 && test->bytes[0] == 'R' &&
          !close(test->pairs[1][0]), "child ready");
    bool blocked = false;
    for (unsigned attempt = 0; attempt < 100 && !blocked; ++attempt)
    {
        ssize_t count = sys_proc_snapshot(test->processes, 256); CHECK(count >= 0 && count <= 256, "child snapshot");
        for (ssize_t i = 0; i < count; ++i)
            if (test->processes[i].pid == (uint64_t)child &&
                test->processes[i].thread_state == SYSCALL_THREAD_STATE_BLOCKED) blocked = true;
        if (!blocked) sys_sleep_ms(1);
    }
    CHECK(blocked && !kill(child, SIGKILL) && waitpid(child, &test->status, 0) == child &&
          WIFSIGNALED(test->status) && WTERMSIG(test->status) == SIGKILL, "kill/reap blocked select caller");
    FD_ZERO(&test->write); FD_SET(test->pairs[0][1], &test->write);
    test->timeout = (struct timeval){ .tv_sec = 3 };
    CHECK(select(test->pairs[0][1] + 1, NULL, &test->write, NULL, &test->timeout) == 1 &&
          FD_ISSET(test->pairs[0][1], &test->write), "cancellation releases pinned final reader");
    CHECK(!close(test->pairs[0][1]), "close canceled child pipe");
    free(test->arguments); test->arguments = NULL;
    return 0;
}

static int boundary_checks(fixture_t *test)
{
    FD_ZERO(&test->read);
    for (int fd = 0; fd < (int)FD_SETSIZE; ++fd) FD_SET(fd, &test->read);
    for (int fd = 0; fd < (int)FD_SETSIZE; ++fd) CHECK(FD_ISSET(fd, &test->read), "all native fd bits");
    for (int fd = 0; fd < (int)FD_SETSIZE; ++fd) FD_CLR(fd, &test->read);
    for (int fd = 0; fd < (int)FD_SETSIZE; ++fd) CHECK(!FD_ISSET(fd, &test->read), "clear native fd bits");
    test->timeout = (struct timeval){ 0 };
    CHECK(select(-1, NULL, NULL, NULL, &test->timeout) == -1 && errno == EINVAL &&
          select(257, NULL, NULL, NULL, &test->timeout) == -1 && errno == EINVAL, "descriptor-count bounds");
    CHECK(select(0, (fd_set *)1, NULL, NULL, &test->timeout) == -1 && errno == EFAULT &&
          select(0, NULL, NULL, NULL, (struct timeval *)1) == -1 && errno == EFAULT, "checked user inputs");
    test->timeout.tv_sec = -1;
    CHECK(select(0, NULL, NULL, NULL, &test->timeout) == -1 && errno == EINVAL, "negative timeout");
    test->timeout = (struct timeval){ .tv_usec = 1000000 };
    CHECK(select(0, NULL, NULL, NULL, &test->timeout) == -1 && errno == EINVAL, "non-normalized timeout");
    test->timeout = (struct timeval){ .tv_sec = INT64_MAX };
    CHECK(select(0, NULL, NULL, NULL, &test->timeout) == -1 && errno == EINVAL, "timeout overflow");
    test->timeout = (struct timeval){ .tv_usec = 30001 };
    uint64_t start = sys_monotonic_millis();
    CHECK(!select(0, NULL, NULL, NULL, &test->timeout) && sys_monotonic_millis() - start >= 31 &&
          test->timeout.tv_sec == 0 && test->timeout.tv_usec == 30001, "rounded monotonic timeout remains unchanged");
    test->timeout = (struct timeval){ 0 };
    FD_SET(255, &test->read); test->saved = test->read;
    CHECK(select(256, &test->read, NULL, NULL, &test->timeout) == -1 && errno == EBADF &&
          !memcmp(&test->read, &test->saved, sizeof(fd_set)), "invalid descriptor preserves masks");
    fd_set *readonly = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(readonly != MAP_FAILED, "copyout mapping");
    FD_ZERO(readonly); FD_SET(200, readonly);
    CHECK(!mprotect(readonly, 4096, PROT_READ) &&
          select(0, readonly, NULL, NULL, &test->timeout) == -1 && errno == EFAULT &&
          FD_ISSET(200, readonly) && !munmap(readonly, 4096), "checked read-only output");
    test->query = (syscall_select_t){ .version = SYSCALL_SELECT_VERSION, .size = sizeof(test->query), .nfds = 0 };
    CHECK(sys_file_io(SYSCALL_FILE_SELECT, 1, sizeof(test->query), 0, 0) == -EFAULT &&
          sys_file_io(SYSCALL_FILE_SELECT, (uintptr_t)&test->query, sizeof(test->query) - 1, 0, 0) == -EINVAL,
          "raw query copy/size checks");
    test->query.version = 99;
    CHECK(sys_file_io(SYSCALL_FILE_SELECT, (uintptr_t)&test->query, sizeof(test->query), 0, 0) == -ENOTSUP,
          "raw version check");
    CHECK(!select(0, NULL, NULL, NULL, &test->timeout), "fresh operation after copy failures");
    return 0;
}

static int tcp_checks(fixture_t *test, uint16_t port)
{
    int fd = sys_socket_open(NULL);
    CHECK(fd >= 0 && !fcntl(fd, F_SETFL, O_RDWR | O_NONBLOCK) &&
          sys_socket_connect(fd, "10.0.2.2", port) == -1 && errno == EINPROGRESS, "native nonblocking TCP connect");
    FD_ZERO(&test->write); FD_SET(fd, &test->write); test->timeout = (struct timeval){ .tv_sec = 3 };
    CHECK(select(fd + 1, NULL, &test->write, NULL, &test->timeout) == 1 && FD_ISSET(fd, &test->write), "TCP connect readiness");
    test->option = -1; test->option_size = sizeof(test->option);
    CHECK(!getsockopt(fd, SOL_SOCKET, SO_ERROR, &test->option, &test->option_size) && !test->option &&
          read(fd, test->bytes, 1) == -1 && errno == EAGAIN && write(fd, "G", 1) == 1, "real TCP connection");
    size_t total = 0;
    while (total < sizeof(test->bytes))
    {
        FD_ZERO(&test->read); FD_SET(fd, &test->read);
        CHECK(select(fd + 1, &test->read, NULL, NULL, &test->timeout) == 1 && FD_ISSET(fd, &test->read), "TCP read readiness");
        ssize_t count = read(fd, test->bytes + total, sizeof(test->bytes) - total);
        CHECK(count > 0 && (size_t)count <= sizeof(test->bytes) - total, "TCP bytes after select");
        total += (size_t)count;
    }
    for (unsigned i = 0; i < total; ++i) CHECK(test->bytes[i] == (unsigned char)(i % 251), "TCP payload integrity");
    FD_ZERO(&test->read); FD_SET(fd, &test->read);
    CHECK(select(fd + 1, &test->read, NULL, NULL, &test->timeout) == 1 &&
          FD_ISSET(fd, &test->read) && read(fd, test->bytes, 1) == 0, "TCP EOF readability");
    FD_ZERO(&test->except); FD_SET(fd, &test->except); test->timeout = (struct timeval){ .tv_usec = 30000 };
    uint64_t start = sys_monotonic_millis();
    CHECK(select(fd + 1, NULL, NULL, &test->except, &test->timeout) == 0 &&
          sys_monotonic_millis() - start >= 30 && !FD_ISSET(fd, &test->except) && !close(fd), "hangup is not exceptional readiness");
    serial_printf("SELECT_TEST: TCP PASS bytes=16384 eof=1 except_hup=1\n");
    return 0;
}

int main(int argc, char **argv)
{
    fixture_t *test = calloc(1, sizeof(*test)); CHECK(test, "heap fixture");
    if (argc == 4 && !strcmp(argv[1], "select-child"))
    {
        int reader = atoi(argv[2]); FD_SET(reader, &test->read);
        CHECK(write(atoi(argv[3]), "R", 1) == 1, "child ready marker");
        (void)select(reader + 1, &test->read, NULL, NULL, NULL);
        CHECK(false, "killed select returned");
    }
    CHECK(!boundary_checks(test), "native ABI/copy boundaries");
    int regular = open("/tmp/select-file", O_CREAT | O_TRUNC | O_RDWR);
    CHECK(regular >= 0 && dup2(regular, 255) == 255, "highest private descriptor");
    FD_ZERO(&test->read); FD_ZERO(&test->write); FD_ZERO(&test->except);
    FD_SET(255, &test->read); FD_SET(255, &test->write); FD_SET(255, &test->except);
    CHECK(select(256, &test->read, &test->write, &test->except, NULL) == 2 &&
          FD_ISSET(255, &test->read) && FD_ISSET(255, &test->write) && !FD_ISSET(255, &test->except), "sum readiness bits across sets");
    CHECK(!close(255) && !close(regular) && !unlink("/tmp/select-file"), "close regular aliases");
    for (unsigned i = 0; i < 8; ++i)
    {
        CHECK(!pipe(test->pairs[i]), "SMP pipes");
        job_t *job = &test->jobs[i]; job->fd = test->pairs[i][0]; job->cpu = i;
        CHECK(!pthread_create(&job->thread, NULL, waiter, job) && !wait_blocked(job), "eight pinned waiters block");
    }
    for (unsigned i = 0; i < 8; ++i) CHECK(write(test->pairs[i][1], "S", 1) == 1, "wake waiters");
    for (unsigned i = 0; i < 8; ++i)
    {
        job_t *job = &test->jobs[i];
        CHECK(!pthread_join(job->thread, NULL) && !job->failed && job->result == 1 && FD_ISSET(job->fd, &job->read) &&
              read(job->fd, test->bytes, 1) == 1 && test->bytes[0] == 'S' &&
              !close(test->pairs[i][0]) && !close(test->pairs[i][1]), "SMP select results");
    }
    serial_printf("SELECT_TEST: SMP PASS cpus=8\n");
    job_t *job = &test->jobs[0]; memset(job, 0, sizeof(*job)); job->cpu = 7;
    CHECK(!pipe(test->pairs[0]), "reuse pipe"); job->fd = test->pairs[0][0];
    CHECK(!pthread_create(&job->thread, NULL, waiter, job) && !wait_blocked(job), "original descriptor wait");
    CHECK(!close(job->fd) && !pipe(test->pairs[1]) && test->pairs[1][0] == job->fd &&
          write(test->pairs[0][1], "P", 1) == 1 && !pthread_join(job->thread, NULL) && job->result == 1 &&
          FD_ISSET(job->fd, &job->read), "select retains original description across reuse");
    CHECK(!close(test->pairs[0][1]) && !close(test->pairs[1][0]) && !close(test->pairs[1][1]), "close reused pipes");
    memset(job, 0, sizeof(*job)); job->cpu = 6;
    test->action.sa_handler = caught; test->action.sa_flags = SA_RESTART;
    CHECK(!sigemptyset(&test->action.sa_mask) && !sigaction(SIGUSR1, &test->action, NULL) && !pipe(test->pairs[0]), "signal setup");
    job->fd = test->pairs[0][0];
    CHECK(!pthread_create(&job->thread, NULL, waiter, job) && !wait_blocked(job) &&
          !pthread_kill(job->thread, SIGUSR1) && !pthread_join(job->thread, NULL) &&
          job->result == -1 && job->error == EINTR && signals == 1 && FD_ISSET(job->fd, &job->read), "signal interruption preserves masks");
    CHECK(!close(test->pairs[0][0]) && !close(test->pairs[0][1]), "close interrupted pipe");
    CHECK(!canceled_caller(test), "canceled caller ownership");
    CHECK(argc == 3 && !strcmp(argv[1], "tcp") && !tcp_checks(test, (uint16_t)atoi(argv[2])), "TCP fixture");
    free(test);
    serial_printf("SELECT_TEST: PASS timeout=1 sets=1 cpus=8 close_reuse=1 signal=1 copy_checks=1 killed_waiter=1\n");
    return 0;
}
