#include "poll.h"
#include "pthread.h"
#include "unistd.h"
#include "usyscall.h"
#include "fcntl.h"
#include "signal.h"
#include "errno.h"
#include "stdlib.h"
#include "string.h"
#include "serial.h"
#include "stdio.h"
#include "alix_process.h"
#include "sys/wait.h"

#define CHECK(value, label) do { if (!(value)) { serial_printf("POLL_TEST: FAIL %s line=%u errno=%d\n", label, __LINE__, errno); return 1; } } while (0)
typedef struct
{
    pthread_t thread;
    uint64_t tid;
    struct pollfd entry;
    int result, error;
    unsigned cpu, failed;
    unsigned char byte;
    syscall_thread_info_t info;
} job_t;
typedef struct
{
    int pairs[8][2];
    struct pollfd entries[8];
    job_t jobs[8];
    struct sigaction action;
    unsigned char bytes[16384];
    syscall_process_info_t snapshot[256];
    char **arguments, reader_text[32], marker_text[32];
} fixture_t;
static volatile sig_atomic_t signals;
static void caught(int number) { if (number == SIGUSR1) ++signals; }
static void *worker(void *pointer)
{
    job_t *job = pointer;
    if (sys_thread_set_affinity(job->cpu) || sys_thread_cpu() != job->cpu) job->failed = 1;
    __atomic_store_n(&job->tid, sys_thread_self(), __ATOMIC_RELEASE);
    job->result = poll(&job->entry, 1, -1);
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
        sys_sleep_ms(1);
    }
    return -1;
}
static int canceled_process(fixture_t *test)
{
    CHECK(pipe(test->pairs[0]) == 0 && pipe(test->pairs[1]) == 0, "child pipes");
    CHECK(!fcntl(test->pairs[0][1], F_SETFD, FD_CLOEXEC) &&
          !fcntl(test->pairs[1][0], F_SETFD, FD_CLOEXEC), "child excludes unused pipe ends");
    test->arguments = calloc(5, sizeof(*test->arguments));
    CHECK(test->arguments, "child argv");
    snprintf(test->reader_text, sizeof(test->reader_text), "%d", test->pairs[0][0]);
    snprintf(test->marker_text, sizeof(test->marker_text), "%d", test->pairs[1][1]);
    test->arguments[0] = "/tmp/test.elf"; test->arguments[1] = "poll-child";
    test->arguments[2] = test->reader_text; test->arguments[3] = test->marker_text;
    pid_t child = alix_spawn_argv(test->arguments[0], test->arguments);
    CHECK(child > 0 && !close(test->pairs[0][0]) && !close(test->pairs[1][1]), "spawn poll child");
    CHECK(read(test->pairs[1][0], test->bytes, 1) == 1 && test->bytes[0] == 'R' &&
          !close(test->pairs[1][0]), "child has inherited poll target");
    bool blocked = false;
    for (unsigned attempt = 0; attempt < 100 && !blocked; ++attempt)
    {
        ssize_t count = sys_proc_snapshot(test->snapshot, 256);
        CHECK(count >= 0 && count <= 256, "child snapshot");
        for (ssize_t index = 0; index < count; ++index)
            if (test->snapshot[index].pid == (uint64_t)child &&
                test->snapshot[index].thread_state == SYSCALL_THREAD_STATE_BLOCKED) blocked = true;
        if (!blocked) sys_sleep_ms(1);
    }
    int *status = calloc(1, sizeof(*status));
    CHECK(status && blocked && !kill(child, SIGKILL) && waitpid(child, status, 0) == child &&
          WIFSIGNALED(*status) && WTERMSIG(*status) == SIGKILL, "kill/reap indefinite poll waiter");
    test->entries[0] = (struct pollfd){ .fd = test->pairs[0][1] };
    CHECK(poll(test->entries, 1, 3000) == 1 && test->entries[0].revents == POLLERR,
          "cancellation releases pinned final reader");
    CHECK(!close(test->pairs[0][1]), "child writer close");
    free(status); free(test->arguments); test->arguments = NULL;
    return 0;
}
int main(int argc, char **argv)
{
    fixture_t *test = calloc(1, sizeof(*test));
    CHECK(test, "heap fixture");
    if (argc == 4 && !strcmp(argv[1], "poll-child"))
    {
        test->entries[0] = (struct pollfd){ .fd = atoi(argv[2]), .events = POLLIN };
        CHECK(write(atoi(argv[3]), "R", 1) == 1, "child ready");
        (void)poll(test->entries, 1, -1);
        CHECK(false, "killed poll returned");
    }
    CHECK(poll(NULL, 0, 0) == 0, "empty immediate poll");
    uint64_t start = sys_monotonic_millis();
    CHECK(poll(NULL, 0, 30) == 0 && sys_monotonic_millis() - start >= 30, "empty monotonic timeout");
    CHECK(poll(NULL, 1, 0) == -1 && errno == EFAULT &&
          poll(test->entries, 257, 0) == -1 && errno == EINVAL, "pointer/count validation");
    test->entries[0] = (struct pollfd){ .fd = -1, .events = -1, .revents = -1 };
    test->entries[1] = (struct pollfd){ .fd = 255, .events = 0 };
    CHECK(poll(test->entries, 2, 0) == 1 && !test->entries[0].revents &&
          test->entries[1].revents == POLLNVAL, "negative and invalid descriptors");
    CHECK(pipe(test->pairs[0]) == 0, "pipe open");
    test->entries[0] = (struct pollfd){ .fd = test->pairs[0][0], .events = POLLIN };
    test->entries[1] = (struct pollfd){ .fd = test->pairs[0][1], .events = POLLOUT };
    CHECK(poll(test->entries, 2, 0) == 1 && !test->entries[0].revents &&
          test->entries[1].revents == POLLOUT, "empty pipe direction readiness");
    CHECK(write(test->pairs[0][1], test->bytes, sizeof(test->bytes)) == sizeof(test->bytes), "fill pipe");
    CHECK(poll(test->entries, 2, 0) == 1 && test->entries[0].revents == POLLIN &&
          !test->entries[1].revents, "full pipe backpressure");
    CHECK(read(test->pairs[0][0], test->bytes, 2048) == 2048 && poll(test->entries + 1, 1, 0) == 0,
          "atomic write needs PIPE_BUF space");
    CHECK(read(test->pairs[0][0], test->bytes, 2048) == 2048 && poll(test->entries + 1, 1, 0) == 1,
          "atomic write space becomes ready");
    CHECK(close(test->pairs[0][1]) == 0, "close writer");
    // HUP is reported even when the caller requests no events, with buffered
    // data still readable before the final EOF.
    test->entries[0].events = 0;
    CHECK(poll(test->entries, 1, 3000) == 1 && test->entries[0].revents == POLLHUP &&
          read(test->pairs[0][0], test->bytes, sizeof(test->bytes)) == 12288 &&
          read(test->pairs[0][0], test->bytes, 1) == 0 && !close(test->pairs[0][0]), "hangup and buffered EOF");

    for (unsigned index = 0; index < 8; ++index)
    {
        CHECK(pipe(test->pairs[index]) == 0, "SMP pipe");
        job_t *job = &test->jobs[index]; job->cpu = index;
        job->entry = (struct pollfd){ .fd = test->pairs[index][0], .events = POLLIN };
        CHECK(!pthread_create(&job->thread, NULL, worker, job) && !wait_blocked(job), "SMP poll waiter blocks");
    }
    for (unsigned index = 0; index < 8; ++index)
        CHECK(write(test->pairs[index][1], "S", 1) == 1, "wake SMP poll waiter");
    for (unsigned index = 0; index < 8; ++index)
    {
        job_t *job = &test->jobs[index];
        CHECK(!pthread_join(job->thread, NULL) && !job->failed && job->result == 1 && job->entry.revents == POLLIN &&
              read(test->pairs[index][0], test->bytes, 1) == 1 && test->bytes[0] == 'S' &&
              !close(test->pairs[index][0]) && !close(test->pairs[index][1]), "SMP poll readiness/results");
    }
    serial_printf("POLL_TEST: SMP PASS cpus=8\n");
    int regular = open("/tmp/poll-file", O_CREAT | O_TRUNC | O_RDWR, 0666);
    CHECK(regular >= 0, "regular file open");
    test->entries[0] = (struct pollfd){ .fd = regular, .events = POLLIN | POLLOUT };
    CHECK(poll(test->entries, 1, -1) == 1 && test->entries[0].revents == (POLLIN | POLLOUT) &&
          !close(regular) && !unlink("/tmp/poll-file"), "regular file immediate readiness at EOF");
    if (argc == 3 && !strcmp(argv[1], "tcp"))
    {
        int socket = sys_socket_open(NULL);
        CHECK(socket >= 0 && fcntl(socket, F_GETFL) == O_RDWR, "native TCP access status");
        int alias = dup(socket);
        CHECK(alias >= 0 && !fcntl(alias, F_SETFL, O_RDWR | O_NONBLOCK) &&
              fcntl(socket, F_GETFL) == (O_RDWR | O_NONBLOCK) && !close(alias), "socket aliases share nonblocking status");
        CHECK(sys_socket_connect(socket, "10.0.2.2", (uint16_t)atoi(argv[2])) == -1 && errno == EINPROGRESS,
              "nonblocking TCP starts a real connection");
        test->entries[0] = (struct pollfd){ .fd = socket, .events = POLLOUT };
        CHECK(poll(test->entries, 1, 3000) == 1 && test->entries[0].revents == POLLOUT,
              "native TCP write readiness");
        CHECK(read(socket, test->bytes, 1) == -1 && errno == EAGAIN && write(socket, "G", 1) == 1,
              "idle nonblocking socket does not occupy the event worker");
        size_t total = 0;
        while (total < sizeof(test->bytes))
        {
            test->entries[0].events = POLLIN;
            CHECK(poll(test->entries, 1, 3000) == 1 && (test->entries[0].revents & POLLIN), "native TCP read readiness");
            ssize_t count = read(socket, test->bytes + total, sizeof(test->bytes) - total);
            CHECK(count > 0 && (size_t)count <= sizeof(test->bytes) - total, "native TCP read after readiness");
            total += (size_t)count;
        }
        for (size_t index = 0; index < total; ++index)
            CHECK(test->bytes[index] == (unsigned char)(index % 251), "native TCP poll data integrity");
        CHECK(poll(test->entries, 1, 3000) == 1 && (test->entries[0].revents & POLLHUP) &&
              read(socket, test->bytes, 1) == 0 && !close(socket), "native TCP EOF/hangup readiness");
        serial_printf("POLL_TEST: TCP PASS bytes=16384 eof=1\n");
    }
    memset(test->jobs, 0, sizeof(test->jobs));
    job_t *job = &test->jobs[0]; job->cpu = 7;
    CHECK(pipe(test->pairs[0]) == 0, "close/reuse pipe");
    job->entry = (struct pollfd){ .fd = test->pairs[0][0], .events = POLLIN };
    CHECK(!pthread_create(&job->thread, NULL, worker, job) && !wait_blocked(job), "pinned descriptor waiter");
    int old = test->pairs[0][0];
    CHECK(!close(old) && pipe(test->pairs[1]) == 0 && test->pairs[1][0] == old &&
          write(test->pairs[0][1], "P", 1) == 1 && !pthread_join(job->thread, NULL) && job->result == 1 &&
          job->entry.fd == old && job->entry.revents == POLLIN, "poll pins original across close/reuse");
    CHECK(!close(test->pairs[0][1]) && !close(test->pairs[1][0]) && !close(test->pairs[1][1]), "close reused pipe");
    memset(job, 0, sizeof(*job)); job->cpu = 6;
    test->action.sa_handler = caught;
    // SA_RESTART must not restart poll.
    test->action.sa_flags = SA_RESTART;
    CHECK(!sigemptyset(&test->action.sa_mask) && !sigaction(SIGUSR1, &test->action, NULL) &&
          pipe(test->pairs[0]) == 0, "caught poll signal");
    job->entry = (struct pollfd){ .fd = test->pairs[0][0], .events = POLLIN };
    CHECK(!pthread_create(&job->thread, NULL, worker, job) && !wait_blocked(job) &&
          !pthread_kill(job->thread, SIGUSR1) && !pthread_join(job->thread, NULL) &&
          job->result == -1 && job->error == EINTR && signals == 1, "caught signal interrupts indefinite poll");
    CHECK(!close(test->pairs[0][0]) && !close(test->pairs[0][1]), "close interrupted pipe");
    CHECK(!canceled_process(test), "canceled process releases all poll owners");
    free(test);
    serial_printf("POLL_TEST: PASS timeout=1 pipes=1 cpus=8 close_reuse=1 signal=1 killed_waiter=1\n");
    return 0;
}
