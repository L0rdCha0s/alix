#include "unistd.h"
#include "usyscall.h"
#include "fcntl.h"
#include "pthread.h"
#include "signal.h"
#include "errno.h"
#include "stdlib.h"
#include "string.h"
#include "sys/stat.h"
#include "serial.h"

#define CHECK(c,label) do { if (!(c)) { serial_printf("PIPE_TEST: FAIL %s errno=%d\n",label,errno); return 1; } } while(0)
#define WORKERS 8u
#define RECORDS 64u
typedef struct { uint32_t owner, sequence; unsigned char payload[120]; } packet_t;
typedef struct
{
    pthread_t thread;
    int fd;
    unsigned mode, cpu, failed, started, done;
    ssize_t result;
    packet_t packet;
    unsigned char bytes[4096];
} job_t;
static volatile sig_atomic_t g_sigpipe;
static void pipe_signal(int number) { if (number == SIGPIPE) ++g_sigpipe; }

static void *job(void *argument)
{
    job_t *work = argument;
    __atomic_store_n(&work->started, 1, __ATOMIC_RELEASE);
    if (work->mode == 0)
    {
        if (sys_thread_set_affinity(work->cpu) || sys_thread_cpu() != work->cpu) work->failed = 1;
        for (unsigned index = 0; index < RECORDS && !work->failed; ++index)
        {
            work->packet.owner = work->cpu; work->packet.sequence = index;
            memset(work->packet.payload, (int)(work->cpu * RECORDS + index), sizeof(work->packet.payload));
            if (write(work->fd, &work->packet, sizeof(work->packet)) != sizeof(work->packet)) work->failed = 2;
        }
    }
    else if (work->mode == 1) work->result = write(work->fd, work->bytes, sizeof(work->bytes));
    else work->result = read(work->fd, work->bytes, 1);
    if (close(work->fd)) work->failed = 3;
    __atomic_store_n(&work->done, 1, __ATOMIC_RELEASE);
    return NULL;
}

int main(int argc, char **argv)
{
    int *fds = calloc(2, sizeof(*fds));
    unsigned char *buffer = calloc(1, 16384);
    struct stat *stat = calloc(1, sizeof(*stat));
    CHECK(fds && buffer && stat, "heap state");
    if (argc > 1 && !strcmp(argv[1], "default"))
    {
        CHECK(pipe(fds) == 0 && close(fds[0]) == 0, "default pipe");
        sys_sleep_ms(30);
        serial_printf("PIPE_TEST: default armed pid=%d tid=%llu signo=13 status=141 vector=0 site=0x0\n",
                      getpid(), (unsigned long long)sys_thread_self());
        (void)write(fds[1], "x", 1);
        CHECK(0, "default SIGPIPE returned");
    }
    CHECK(pipe2(fds, O_CLOEXEC) == 0 && fds[0] == 3 && fds[1] == 4, "lowest descriptor pair");
    CHECK(fcntl(fds[0], F_GETFD) == FD_CLOEXEC && fcntl(fds[1], F_GETFD) == FD_CLOEXEC, "atomic CLOEXEC flags");
    CHECK(fstat(fds[0], stat) == 0 && S_ISFIFO(stat->st_mode) && !isatty(fds[0]) && errno == ENOTTY, "FIFO metadata");
    CHECK(read(fds[1], buffer, 1) == -1 && errno == EBADF && write(fds[0], "x", 1) == -1 && errno == EBADF, "endpoint direction");
    CHECK(lseek(fds[0], 0, 0) == -1 && errno == ESPIPE, "pipe cannot seek");
    CHECK(write(fds[1], buffer, 0) == 0 && read(fds[0], buffer, 0) == 0, "zero length operations");
    CHECK(close(fds[0]) == 0 && close(fds[1]) == 0, "close initial pair");
    CHECK(pipe2(fds, 0x40000000) == -1 && errno == EINVAL, "reject unsupported flags");
    CHECK(pipe(NULL) == -1 && errno == EFAULT, "invalid output pointer");
    int *aliases = calloc(253, sizeof(*aliases));
    CHECK(aliases, "capacity heap");
    for (unsigned index = 0; index < 252; ++index) { aliases[index] = dup(1); CHECK(aliases[index] == (int)index + 3, "fill private table"); }
    fds[0] = -19; fds[1] = -23;
    CHECK(pipe(fds) == -1 && errno == EMFILE && fds[0] == -19 && fds[1] == -23, "no half pair or output on EMFILE");
    CHECK((aliases[252] = dup(1)) == 255, "failed pair preserves remaining slot");
    for (unsigned index = 0; index < 253; ++index) CHECK(close(aliases[index]) == 0, "release capacity");
    free(aliases);
    CHECK(pipe(fds) == 0, "backpressure pipe");
    memset(buffer, 'a', 16384);
    CHECK(write(fds[1], buffer, 16384) == 16384, "fill pipe");
    job_t *blocked = calloc(1, sizeof(*blocked));
    CHECK(blocked, "backpressure state");
    blocked->mode = 1; blocked->fd = fds[1]; memset(blocked->bytes, 'b', sizeof(blocked->bytes));
    CHECK(!pthread_create(&blocked->thread, NULL, job, blocked), "blocked writer");
    while (!__atomic_load_n(&blocked->started, __ATOMIC_ACQUIRE)) sys_yield();
    sys_sleep_ms(30);
    CHECK(!__atomic_load_n(&blocked->done, __ATOMIC_ACQUIRE), "full pipe blocks");
    CHECK(read(fds[0], buffer, 2048) == 2048, "drain half atomic write");
    sys_sleep_ms(30);
    CHECK(!__atomic_load_n(&blocked->done, __ATOMIC_ACQUIRE), "small write stays atomic under backpressure");
    CHECK(read(fds[0], buffer, 2048) == 2048 && !pthread_join(blocked->thread, NULL) &&
          !blocked->failed && blocked->result == 4096, "reader allows blocked writer to finish");
    CHECK(read(fds[0], buffer, 16384) == 16384, "drain ring across wrap");
    for (unsigned index = 0; index < 16384; ++index) CHECK(buffer[index] == (index < 12288 ? 'a' : 'b'), "wrapped byte order");
    CHECK(read(fds[0], buffer, 1) == 0 && close(fds[0]) == 0, "EOF after writer close");
    free(blocked);
    job_t *idle = calloc(3, sizeof(*idle)); int *writers = calloc(3, sizeof(*writers));
    CHECK(idle && writers, "idle state");
    for (unsigned index = 0; index < 3; ++index)
    {
        CHECK(pipe(fds) == 0, "idle pipe");
        idle[index].mode = 2; idle[index].fd = fds[0]; writers[index] = fds[1];
        CHECK(!pthread_create(&idle[index].thread, NULL, job, &idle[index]), "idle reader");
    }
    sys_sleep_ms(30);
    CHECK(pipe(fds) == 0 && write(fds[1], "fresh", 5) == 5 && read(fds[0], buffer, 5) == 5 &&
          !memcmp(buffer, "fresh", 5) && close(fds[0]) == 0 && close(fds[1]) == 0, "idle readers do not occupy storage workers");
    for (unsigned index = 0; index < 3; ++index)
        CHECK(close(writers[index]) == 0 && !pthread_join(idle[index].thread, NULL) &&
              !idle[index].failed && idle[index].result == 0, "wake idle reader with EOF");
    free(writers); free(idle);
    CHECK(pipe(fds) == 0, "SMP pipe");
    job_t *workers = calloc(WORKERS, sizeof(*workers));
    unsigned char *seen = calloc(WORKERS * RECORDS, 1); packet_t *packet = calloc(1, sizeof(*packet));
    CHECK(workers && seen && packet, "SMP heap state");
    for (unsigned index = 0; index < WORKERS; ++index)
    {
        workers[index].cpu = index; workers[index].fd = dup(fds[1]);
        CHECK(workers[index].fd >= 3 && !pthread_create(&workers[index].thread, NULL, job, &workers[index]), "SMP writer creation");
    }
    CHECK(close(fds[1]) == 0, "aliases retain writer");
    for (unsigned index = 0; index < WORKERS * RECORDS; ++index)
    {
        CHECK(read(fds[0], packet, sizeof(*packet)) == sizeof(*packet) && packet->owner < WORKERS && packet->sequence < RECORDS, "atomic record header");
        unsigned slot = packet->owner * RECORDS + packet->sequence;
        CHECK(!seen[slot]++, "exactly once record");
        for (unsigned byte = 0; byte < sizeof(packet->payload); ++byte) CHECK(packet->payload[byte] == (unsigned char)slot, "no interleaved record bytes");
    }
    for (unsigned index = 0; index < WORKERS; ++index) CHECK(!pthread_join(workers[index].thread, NULL) && !workers[index].failed, "SMP writer join");
    CHECK(read(fds[0], buffer, 1) == 0 && close(fds[0]) == 0, "EOF after final alias");
    CHECK(signal(SIGPIPE, pipe_signal) != SIG_ERR && pipe(fds) == 0 && close(fds[0]) == 0, "broken pipe setup");
    sys_sleep_ms(30);
    CHECK(write(fds[1], "x", 1) == -1 && errno == EPIPE && g_sigpipe == 1, "EPIPE and calling-thread signal");
    CHECK(signal(SIGPIPE, SIG_IGN) != SIG_ERR && write(fds[1], "x", 1) == -1 && errno == EPIPE && g_sigpipe == 1, "ignored SIGPIPE preserves EPIPE");
    CHECK(close(fds[1]) == 0, "broken pipe close");
    free(packet); free(seen); free(workers); free(stat); free(buffer); free(fds);
    serial_printf("PIPE_TEST: PASS workers=8 records=512 atomic4096=1 wrap=1 idle_reads=3 EOF=1 SIGPIPE=1 pair_rollback=1\n");
    return 0;
}
