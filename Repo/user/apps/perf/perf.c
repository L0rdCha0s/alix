/* Native, owned-descriptor performance workloads. Shared state is heap-owned.
 * All latency percentiles below are batch-average costs, except the separately
 * labelled GUI distributions. The monotonic clock has millisecond granularity.
 */
#include "perf.h"
#include "arpa/inet.h"
#include "dirent.h"
#include "errno.h"
#include "fcntl.h"
#include "netdb.h"
#include "netinet/in.h"
#include "poll.h"
#include "sched.h"
#include "serial.h"
#include "spawn.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "sys/mman.h"
#include "sys/random.h"
#include "sys/resource.h"
#include "sys/socket.h"
#include "sys/stat.h"
#include "sys/utsname.h"
#include "sys/uio.h"
#include "sys/wait.h"
#include "time.h"
#include "unistd.h"
#include "usyscall.h"

#define KB 1024u
#define MB (1024u * KB)
#define REQUIRE(x)                                                                                 \
    do                                                                                             \
    {                                                                                              \
        if (!(x))                                                                                  \
            return errno ? errno : EIO;                                                            \
    } while (0)
static bool serial_log;
void perf_log(const char *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    if (serial_log)
    {
        char *line = NULL;
        int length = vasprintf(&line, format, arguments);
        if (length > 0)
            serial_output_bytes(line, (size_t)length);
        free(line);
    }
    else
        vprintf(format, arguments);
    va_end(arguments);
}
static volatile uint64_t sink;
static _Thread_local uint64_t tls_value;
uint64_t perf_now_ns(void) { return sys_monotonic_millis() * UINT64_C(1000000); }
static uint64_t tv_us(struct timeval value)
{
    return (uint64_t)value.tv_sec * 1000000u + value.tv_usec;
}
static bool selected(perf_config_t *c, const char *g) { return !c->group || !strcmp(c->group, g); }
static bool selected_case(perf_config_t *c, const char *name)
{
    return !c->case_name || !strcmp(c->case_name, name);
}
static bool stopped(perf_config_t *c) { return __atomic_load_n(&c->state->stop, __ATOMIC_ACQUIRE); }
static void current(perf_config_t *c, const char *name)
{
    pthread_mutex_lock(&c->state->lock);
    snprintf(c->state->current, sizeof(c->state->current), "%s", name);
    pthread_mutex_unlock(&c->state->lock);
    perf_log("PERF_BEGIN,%s\n", name);
}
static uint64_t sample_target_ns(const perf_config_t *c, unsigned scale)
{
    struct timespec resolution = {0};
    uint64_t quantum = UINT64_C(10000000);
    if (!clock_getres(CLOCK_MONOTONIC, &resolution))
    {
        uint64_t reported = (uint64_t)resolution.tv_sec * UINT64_C(1000000000) + resolution.tv_nsec;
        if (reported) quantum = reported;
    }
    uint64_t requested = (uint64_t)c->duration_ms * UINT64_C(1000000) * scale;
    return requested < quantum * 5 ? quantum * 5 : requested;
}
static int compare_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}
const char *perf_status(int error)
{
    return error == -2 ? "STOP" : error < 0 ? "SKIP" : error ? "FAIL" : "OK";
}
void perf_record(perf_state_t *s, const perf_result_t *r)
{
    pthread_mutex_lock(&s->lock);
    if (s->count < PERF_MAX_RESULTS)
        s->results[s->count++] = *r;
    if (r->error > 0)
        s->failed++;
    if (r->error == -1)
        s->skipped++;
    pthread_mutex_unlock(&s->lock);
    perf_log("PERF_RESULT,%s,%s,%s,%u,%u,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,"
             "%llu,%llu,%d\n",
             r->group, r->name, perf_status(r->error), r->samples, r->workers,
             (unsigned long long)r->operations, (unsigned long long)r->bytes,
             (unsigned long long)r->elapsed_ns, (unsigned long long)r->p50_ns,
             (unsigned long long)r->p95_ns, (unsigned long long)r->max_ns,
             (unsigned long long)r->user_us, (unsigned long long)r->system_us,
             (unsigned long long)r->minor_faults, (unsigned long long)r->major_faults, r->error);
    if (r->detail[0])
        perf_log("PERF_DETAIL,%s,%s\n", r->name, r->detail);
}
static void usage_delta(perf_result_t *r, struct rusage *a, struct rusage *b)
{
    r->user_us += tv_us(b->ru_utime) - tv_us(a->ru_utime);
    r->system_us += tv_us(b->ru_stime) - tv_us(a->ru_stime);
    r->minor_faults += b->ru_minflt - a->ru_minflt;
    r->major_faults += b->ru_majflt - a->ru_majflt;
}
static void finish(perf_result_t *r, uint64_t *costs)
{
    if (!r->samples)
        return;
    qsort(costs, r->samples, sizeof(*costs), compare_u64);
    r->p50_ns = costs[r->samples / 2];
    r->p95_ns = costs[(r->samples * 95 + 99) / 100 - 1];
    r->max_ns = costs[r->samples - 1];
}

typedef enum
{
    PID,
    CLOCK,
    CPU_CLOCK,
    YIELD,
    RANDOM,
    FUTEX_MISS,
    FUTEX_WAKE,
    MALLOC,
    CALLOC,
    REALLOC,
    FRAGMENT,
    MEMCPY,
    MEMCPY_UNALIGNED,
    MEMSET,
    MEMMOVE,
    MEMMOVE_BACK1,
    MEMMOVE_FWD1,
    MEMCOPY_GUARD,
    MEMCMP_EQUAL,
    MEMCMP_UNALIGNED,
    MEMCMP_EARLY,
    MEMCMP_LATE,
    MEMCMP_GUARD,
    VM_MAP,
    VM_RESERVE,
    VM_PROTECT,
    VM_FAULT,
    MUTEX,
    RWLOCK,
    RWLOCK_WRITE,
    PTHREAD_SELF,
    NATIVE_THREAD_SELF,
    THREAD_IDENTITY,
    FORK_IDENTITY,
    TLS,
    THREAD,
    SPAWN,
    FORK,
    PIPE,
    LOCAL,
    POLL_IDLE,
    POLL_READY,
    POLL_DISTINCT_IDLE,
    POLL_DISTINCT_READY,
    POLL_LOCAL_REPEAT,
    STAT,
    OPEN,
    DUP,
    DIRECTORY,
    CREATE,
    FILE_READ,
    FILE_READ_API,
    FILE_READ_CHECKED,
    FILE_WRITE,
    FILE_RANDOM,
    FILE_SYNC,
    FILE_MAP,
    SOCKET,
    SOCKET_BURST,
    TCP_CONNECT,
    TCP_ECHO,
    TCP_STREAM,
    TCP_VECTOR,
    UDP_ECHO,
    DNS,
    SLEEP
} operation_t;
typedef struct
{
    const char *group, *name;
    operation_t op;
    size_t size;
    unsigned cap;
} bench_t;
static const bench_t benches[] = {
    {"syscall", "getpid", PID, 0, 1048576},
    {"syscall", "monotonic_clock", CLOCK, 0, 1048576},
    {"syscall", "process_cpu_clock", CPU_CLOCK, 0, 65536},
    {"syscall", "getrandom_256", RANDOM, 256, 65536},
    {"scheduling", "yield_alone", YIELD, 0, 65536},
    {"scheduling", "sleep_1ms", SLEEP, 1, 32},
    {"scheduling", "sleep_10ms", SLEEP, 10, 8},
    {"threading", "futex_value_mismatch", FUTEX_MISS, 0, 65536},
    {"threading", "futex_wake_empty", FUTEX_WAKE, 0, 65536},
    {"memory", "malloc_free_64", MALLOC, 64, 1048576},
    {"memory", "malloc_free_4096", MALLOC, 4096, 65536},
    {"memory", "malloc_free_1m", MALLOC, MB, 4096},
    {"memory", "calloc_free_64k", CALLOC, 64 * KB, 4096},
    {"memory", "realloc_grow_4k_64k", REALLOC, 0, 4096},
    {"memory", "fragment_64_allocations", FRAGMENT, 0, 1024},
    {"memory", "memcpy_4k", MEMCPY, 4 * KB, 1048576},
    {"memory", "memcpy_1m", MEMCPY, MB, 4096},
    {"memory", "memcpy_unaligned_4k", MEMCPY_UNALIGNED, 4 * KB, 65536},
    {"memory", "memcpy_unaligned_1m", MEMCPY_UNALIGNED, MB, 4096},
    {"memory", "memory_copy_guard_pages", MEMCOPY_GUARD, 0, 1},
    {"memory", "memset_1m", MEMSET, MB, 4096},
    {"memory", "memmove_overlap_64k", MEMMOVE, 64 * KB, 65536},
    {"memory", "memmove_backward_1_64k", MEMMOVE_BACK1, 64 * KB, 65536},
    {"memory", "memmove_forward_1_64k", MEMMOVE_FWD1, 64 * KB, 65536},
    {"memory", "memcmp_equal_4k", MEMCMP_EQUAL, 4 * KB, 1048576},
    {"memory", "memcmp_equal_1m", MEMCMP_EQUAL, MB, 4096},
    {"memory", "memcmp_unaligned_4k", MEMCMP_UNALIGNED, 4 * KB, 1048576},
    {"memory", "memcmp_unaligned_1m", MEMCMP_UNALIGNED, MB, 4096},
    {"memory", "memcmp_early_difference", MEMCMP_EARLY, 4 * KB, 1048576},
    {"memory", "memcmp_late_difference", MEMCMP_LATE, 4 * KB, 1048576},
    {"memory", "memcmp_guard_pages", MEMCMP_GUARD, 0, 1},
    {"vm", "map_touch_unmap_64k", VM_MAP, 64 * KB, 256},
    {"vm", "reserve_unmap_64m", VM_RESERVE, 64 * MB, 256},
    {"vm", "protect_read_rw_64k", VM_PROTECT, 64 * KB, 256},
    {"vm", "discard_refault_16_pages", VM_FAULT, 64 * KB, 256},
    {"threading", "mutex_uncontended", MUTEX, 0, 1048576},
    {"threading", "mutex_recursive_uncontended", MUTEX, PTHREAD_MUTEX_RECURSIVE, 1048576},
    {"threading", "mutex_errorcheck_uncontended", MUTEX, PTHREAD_MUTEX_ERRORCHECK, 1048576},
    {"threading", "pthread_self", PTHREAD_SELF, 0, 1048576},
    {"threading", "native_thread_self", NATIVE_THREAD_SELF, 0, 1048576},
    {"threading", "thread_identity_lifecycle", THREAD_IDENTITY, 0, 8},
    {"process", "fork_thread_identity", FORK_IDENTITY, 0, 4},
    {"threading", "rwlock_read_uncontended", RWLOCK, 0, 1048576},
    {"threading", "rwlock_write_uncontended", RWLOCK_WRITE, 0, 1048576},
    {"threading", "thread_local_access", TLS, 0, 1048576},
    {"threading", "thread_create_join", THREAD, 0, 64},
    {"process", "spawn_self_wait", SPAWN, 0, 8},
    {"process", "fork_exit_wait", FORK, 0, 8},
    {"ipc", "pipe_roundtrip_64", PIPE, 64, 4096},
    {"ipc", "pipe_roundtrip_4k", PIPE, 4096, 4096},
    {"ipc", "socketpair_roundtrip_64", LOCAL, 64, 4096},
    {"ipc", "socketpair_roundtrip_4k", LOCAL, 4096, 4096},
    {"ipc", "poll_idle_1", POLL_IDLE, 1, 65536},
    {"ipc", "poll_idle_32", POLL_IDLE, 32, 65536},
    {"ipc", "poll_idle_128", POLL_IDLE, 128, 65536},
    {"ipc", "poll_ready_32", POLL_READY, 32, 65536},
    {"ipc", "poll_idle_distinct_128", POLL_DISTINCT_IDLE, 128, 65536},
    {"ipc", "poll_ready_distinct_128", POLL_DISTINCT_READY, 128, 65536},
    {"ipc", "poll_idle_local_repeated_128", POLL_LOCAL_REPEAT, 128, 65536},
    {"filesystem", "stat", STAT, 0, 65536},
    {"filesystem", "open_close", OPEN, 0, 4096},
    {"filesystem", "dup_close", DUP, 0, 4096},
    {"filesystem", "directory_scan", DIRECTORY, 0, 4096},
    {"filesystem", "directory_scan_128", DIRECTORY, 128, 128},
    {"filesystem", "create_unlink", CREATE, 0, 1024},
    {"filesystem", "cached_read_64k", FILE_READ, 64 * KB, 4096},
    {"filesystem", "cached_read_4k_api", FILE_READ_API, 4 * KB, 4096},
    {"filesystem", "cached_read_60k_api", FILE_READ_API, 60 * KB, 4096},
    {"filesystem", "cached_read_64k_api", FILE_READ_API, 64 * KB, 4096},
    {"filesystem", "cached_read_60k_checked", FILE_READ_CHECKED, 60 * KB, 4096},
    {"filesystem", "overwrite_64k", FILE_WRITE, 64 * KB, 4096},
    {"filesystem", "random_pread_4k", FILE_RANDOM, 4 * KB, 4096},
    {"filesystem", "write_fsync_4k", FILE_SYNC, 4 * KB, 32},
    {"filesystem", "private_map_read_64k", FILE_MAP, 64 * KB, 256},
    {"network", "socket_create_close", SOCKET, 0, 4096},
    {"network", "socket_burst_128", SOCKET_BURST, 128, 1},
    {"network", "tcp_connect_close", TCP_CONNECT, 0, 16},
    {"network", "tcp_echo_64", TCP_ECHO, 64, 256},
    {"network", "tcp_echo_serial_64k", TCP_ECHO, 64 * KB, 64},
    {"network", "tcp_echo_stream_1m", TCP_STREAM, MB, 8},
    {"network", "tcp_vector_stream_1m", TCP_VECTOR, MB, 8},
    {"network", "udp_echo_64", UDP_ECHO, 64, 256},
    {"network", "udp_echo_1200", UDP_ECHO, 1200, 256},
    {"network", "dns_lookup", DNS, 0, 8},
};
typedef struct
{
    perf_config_t *config;
    const bench_t *bench;
    unsigned char *a, *b;
    void **slots;
    int fd, pair[2];
    int fd_batch[128], socket_receive_capacity;
    socklen_t socket_option_size;
    struct iovec send_vectors[2], receive_vectors[2];
    struct msghdr send_message, receive_message;
    uint64_t vector_sends, vector_writes, vector_receives;
    uint64_t file_read_calls, file_read_bytes, directory_calls, directory_entries;
    uint64_t directory_seen[2];
    unsigned directory_files;
    struct pollfd *polls;
    int *poll_fds;
    void *mapping;
    unsigned char *guard_a, *guard_b;
    size_t guard_length;
    uint64_t move_calls;
    char directory[4096], path[4096], temporary[4096];
    bool directory_created;
    pthread_mutex_t mutex;
    pthread_mutexattr_t mutex_attribute;
    pthread_rwlock_t rwlock;
    syscall_thread_info_t thread_info;
    pthread_t identity_thread;
    uint64_t parent_tid;
    unsigned identity_error;
    volatile uint32_t futex;
    uint64_t random_index;
    struct sockaddr_in endpoint;
} context_t;
static context_t *identity_fork_context;
static bool identity_fork_callback_registered;
static int identity_check(context_t *x, uint64_t previous)
{
    if (sys_thread_info(0, &x->thread_info) != 0)
        return EIO;
    uint64_t actual = x->thread_info.tid;
    if (!actual || (previous && actual == previous) || pthread_self() != actual ||
        sys_thread_self() != actual)
        return EIO;
    return 0;
}
static void identity_child_callback(void)
{
    context_t *x = identity_fork_context;
    if (x)
        x->identity_error = identity_check(x, x->parent_tid);
}
static void *identity_worker(void *argument)
{
    context_t *x = argument;
    x->identity_error = identity_check(x, x->parent_tid);
    uint64_t expected = x->thread_info.tid;
    unsigned cpus = x->config->cpus < 8 ? x->config->cpus : 8;
    for (unsigned cpu = 0; cpu < cpus && !x->identity_error; cpu++)
    {
        if (sys_thread_set_affinity(cpu) != 0 || sys_thread_cpu() != cpu ||
            identity_check(x, x->parent_tid) != 0 || x->thread_info.tid != expected)
            x->identity_error = EIO;
    }
    return NULL;
}
static int wait_fd(int fd, short events)
{
    struct pollfd p = {fd, events, 0};
    int rc;
    do
        rc = poll(&p, 1, 2000);
    while (rc < 0 && errno == EINTR);
    if (rc == 0)
        return ETIMEDOUT;
    if (rc < 0)
        return errno;
    if (p.revents & (POLLERR | POLLNVAL))
        return EIO;
    return 0;
}
static int transfer(int fd, void *buffer, size_t length, bool writing, bool network)
{
    size_t done = 0;
    uint64_t deadline = perf_now_ns() + UINT64_C(5000000000);
    while (done < length)
    {
        if (perf_now_ns() > deadline)
            return ETIMEDOUT;
        ssize_t n = network
                        ? (writing ? send(fd, (char *)buffer + done, length - done,
                                          MSG_DONTWAIT | MSG_NOSIGNAL)
                                   : recv(fd, (char *)buffer + done, length - done, MSG_DONTWAIT))
                        : (writing ? write(fd, (char *)buffer + done, length - done)
                                   : read(fd, (char *)buffer + done, length - done));
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            int e = wait_fd(fd, writing ? POLLOUT : POLLIN);
            if (e)
                return e;
            continue;
        }
        if (n <= 0)
            return n ? errno : EIO;
        done += (size_t)n;
    }
    return 0;
}
static int tcp_open(context_t *x)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    if (connect(fd, (struct sockaddr *)&x->endpoint, sizeof(x->endpoint)) < 0)
    {
        if (errno != EINPROGRESS)
        {
            int e = errno;
            close(fd);
            errno = e;
            return -1;
        }
        int e = wait_fd(fd, POLLOUT);
        socklen_t size = sizeof(e);
        if (!e && getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &size) < 0)
            e = errno;
        if (e)
        {
            close(fd);
            errno = e;
            return -1;
        }
    }
    return fd;
}
static int prepare(context_t *x)
{
    const bench_t *b = x->bench;
    x->fd = x->pair[0] = x->pair[1] = -1;
    x->mapping = MAP_FAILED;
    x->a = malloc(MB + 64);
    x->b = malloc(MB + 64);
    x->slots = calloc(64, sizeof(void *));
    REQUIRE(x->a && x->b && x->slots);
    for (size_t i = 0; i < MB + 64; i++)
        x->a[i] = (unsigned char)(i * 37u + 11u);
    memset(x->b, 0, MB + 64);
    if (b->op >= MEMCMP_EQUAL && b->op <= MEMCMP_LATE)
    {
        size_t source = b->op == MEMCMP_UNALIGNED ? 1 : 0,
               destination = b->op == MEMCMP_UNALIGNED ? 2 : 0;
        memcpy(x->b + destination, x->a + source, b->size);
        if (b->op == MEMCMP_EARLY)
            x->b[0] ^= 0x80;
        if (b->op == MEMCMP_LATE)
            x->b[b->size - 1] ^= 0x80;
    }
    if (b->op == MEMMOVE || b->op == MEMMOVE_BACK1 || b->op == MEMMOVE_FWD1)
        memcpy(x->b, x->a, b->size + 16);
    if (b->op == MEMCOPY_GUARD)
    {
        x->guard_length = 12288;
        x->guard_a = mmap(NULL, x->guard_length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        x->guard_b = mmap(NULL, x->guard_length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        REQUIRE(x->guard_a != MAP_FAILED && x->guard_b != MAP_FAILED);
        REQUIRE(!mprotect(x->guard_a, 4096, PROT_NONE) && !mprotect(x->guard_a + 8192, 4096, PROT_NONE) &&
                !mprotect(x->guard_b, 4096, PROT_NONE) && !mprotect(x->guard_b + 8192, 4096, PROT_NONE));
        for (unsigned i = 0; i < 4096; i++) x->guard_a[4096+i] = x->a[i];
        REQUIRE(!mprotect(x->guard_a + 4096, 4096, PROT_READ));
    }
    if (b->op == MEMCMP_GUARD)
    {
        x->guard_length = 8192;
        x->guard_a = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        x->guard_b = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        REQUIRE(x->guard_a != MAP_FAILED && x->guard_b != MAP_FAILED);
        REQUIRE(mprotect(x->guard_a + 4096, 4096, PROT_NONE) == 0 &&
                mprotect(x->guard_b + 4096, 4096, PROT_NONE) == 0);
        for (unsigned i = 0; i < 4096; i++)
            x->guard_a[i] = (unsigned char)(i * 37u + 11u);
    }
    int e = pthread_mutexattr_init(&x->mutex_attribute);
    if (e)
        return e;
    if (b->op == MUTEX && b->size)
    {
        e = pthread_mutexattr_settype(&x->mutex_attribute, (int)b->size);
        if (e)
            return e;
    }
    e = pthread_mutex_init(&x->mutex, &x->mutex_attribute);
    pthread_mutexattr_destroy(&x->mutex_attribute);
    if (e)
        return e;
    e = pthread_rwlock_init(&x->rwlock, NULL);
    if (e)
        return e;
    if (b->op == PTHREAD_SELF || b->op == NATIVE_THREAD_SELF || b->op == THREAD_IDENTITY ||
        b->op == FORK_IDENTITY)
    {
        REQUIRE(sys_thread_info(0, &x->thread_info) == 0);
        x->parent_tid = x->thread_info.tid;
        if (b->op == FORK_IDENTITY)
        {
            if (x->config->gui)
                return -1;
            identity_fork_context = x;
            if (!identity_fork_callback_registered)
            {
                e = pthread_atfork(NULL, NULL, identity_child_callback);
                if (e)
                    return e;
                identity_fork_callback_registered = true;
            }
        }
    }
    if (b->op == VM_PROTECT || b->op == VM_FAULT)
    {
        x->mapping =
            mmap(NULL, b->size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        REQUIRE(x->mapping != MAP_FAILED);
    }
    if (b->op == PIPE || b->op == POLL_IDLE || b->op == POLL_READY)
    {
        REQUIRE(pipe2(x->pair, O_NONBLOCK | O_CLOEXEC) == 0);
        if (b->op == POLL_IDLE || b->op == POLL_READY)
        {
            x->polls = calloc(b->size, sizeof(*x->polls));
            REQUIRE(x->polls);
            for (size_t i = 0; i < b->size; i++)
                x->polls[i] = (struct pollfd){x->pair[0], POLLIN, 0};
            if (b->op == POLL_READY)
                REQUIRE(write(x->pair[1], x->a, 1) == 1);
        }
    }
    if (b->op == POLL_DISTINCT_IDLE || b->op == POLL_DISTINCT_READY || b->op == POLL_LOCAL_REPEAT)
    {
        x->polls = calloc(b->size, sizeof(*x->polls));
        REQUIRE(x->polls);
        if (b->op == POLL_LOCAL_REPEAT)
        {
            REQUIRE(!socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, x->pair));
            for (size_t i = 0; i < b->size; i++)
                x->polls[i] = (struct pollfd){x->pair[0], POLLIN, 0};
        }
        else
        {
            x->poll_fds = malloc(b->size * sizeof(*x->poll_fds));
            REQUIRE(x->poll_fds);
            for (size_t i = 0; i < b->size; i++) x->poll_fds[i] = -1;
            for (size_t i = 0; i < b->size; i += 2)
                REQUIRE(!socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, x->poll_fds + i));
            for (size_t i = 0; i < b->size; i++)
            {
                x->polls[i] = (struct pollfd){x->poll_fds[i], POLLIN, 0};
                if (b->op == POLL_DISTINCT_READY)
                    REQUIRE(send(x->poll_fds[i], x->a, 1, MSG_DONTWAIT | MSG_NOSIGNAL) == 1);
            }
        }
    }
    if (b->op == LOCAL)
        REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, x->pair) == 0);
    if (!strcmp(b->group, "filesystem"))
    {
        snprintf(x->directory, sizeof(x->directory), "%s/perf-XXXXXX", x->config->workdir);
        REQUIRE(mkdtemp(x->directory));
        x->directory_created = true;
        snprintf(x->path, sizeof(x->path), "%s/data", x->directory);
        snprintf(x->temporary, sizeof(x->temporary), "%s/churn", x->directory);
        x->fd = open(x->path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
        REQUIRE(x->fd >= 0);
        REQUIRE(transfer(x->fd, x->a, MB, true, false) == 0);
        if (b->op == DIRECTORY && b->size)
        {
            REQUIRE(b->size <= 128);
            for (unsigned i = 1; i < b->size; i++)
            {
                snprintf(x->temporary, sizeof(x->temporary), "%s/entry-%03u", x->directory, i);
                int child = open(x->temporary, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
                REQUIRE(child >= 0);
                x->directory_files = i;
                REQUIRE(close(child) == 0);
            }
            snprintf(x->temporary, sizeof(x->temporary), "%s/churn", x->directory);
        }
    }
    if (b->op == TCP_CONNECT || b->op == TCP_ECHO || (b->op == TCP_STREAM || b->op == TCP_VECTOR) || b->op == UDP_ECHO)
    {
        if (!x->config->net_host || !x->config->port)
            return -1;
        x->endpoint.sin_family = AF_INET;
        x->endpoint.sin_port = htons(x->config->port);
        REQUIRE(inet_pton(AF_INET, x->config->net_host, &x->endpoint.sin_addr) == 1);
        if (b->op == TCP_ECHO || (b->op == TCP_STREAM || b->op == TCP_VECTOR))
        {
            x->fd = tcp_open(x);
            REQUIRE(x->fd >= 0);
            x->socket_option_size = sizeof(x->socket_receive_capacity);
            REQUIRE(getsockopt(x->fd, SOL_SOCKET, SO_RCVBUF, &x->socket_receive_capacity,
                               &x->socket_option_size) == 0);
        }
        if (b->op == UDP_ECHO)
        {
            x->fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            REQUIRE(x->fd >= 0);
            REQUIRE(connect(x->fd, (struct sockaddr *)&x->endpoint, sizeof(x->endpoint)) == 0);
        }
    }
    if (b->op == DNS && !x->config->dns_host)
        return -1;
    return 0;
}
static void cleanup(context_t *x)
{
    if (x->fd >= 0)
        close(x->fd);
    if (x->pair[0] >= 0)
        close(x->pair[0]);
    if (x->pair[1] >= 0)
        close(x->pair[1]);
    if (x->poll_fds)
        for (size_t i = 0; i < x->bench->size; i++)
            if (x->poll_fds[i] >= 0) close(x->poll_fds[i]);
    if (x->mapping != MAP_FAILED)
        munmap(x->mapping, x->bench->size);
    if (x->guard_a && x->guard_a != MAP_FAILED)
        munmap(x->guard_a, x->guard_length);
    if (x->guard_b && x->guard_b != MAP_FAILED)
        munmap(x->guard_b, x->guard_length);
    if (x->slots)
        for (unsigned i = 0; i < 64; i++)
            free(x->slots[i]);
    if (x->path[0])
        unlink(x->path);
    if (x->temporary[0])
        unlink(x->temporary);
    for (unsigned i = 1; i <= x->directory_files; i++)
    {
        snprintf(x->temporary, sizeof(x->temporary), "%s/entry-%03u", x->directory, i);
        unlink(x->temporary);
    }
    if (x->directory_created)
        rmdir(x->directory);
    pthread_mutex_destroy(&x->mutex);
    pthread_rwlock_destroy(&x->rwlock);
    if (identity_fork_context == x)
        identity_fork_context = NULL;
    free(x->a);
    free(x->b);
    free(x->slots);
    free(x->polls);
    free(x->poll_fds);
    free(x);
}
static void *empty_thread(void *arg) { return arg; }
static int child_wait(pid_t pid)
{
    int status = 0;
    pid_t r;
    do
        r = waitpid(pid, &status, 0);
    while (r < 0 && errno == EINTR);
    return r == pid && WIFEXITED(status) && !WEXITSTATUS(status) ? 0 : ECHILD;
}
/* Correctness diagnostic. Source is read-only and both sides of each usable
 * page are protected. The oracle uses bytes, independent of the wide copies. */
static int guarded_copy(context_t *x)
{
    unsigned char *source_page = x->guard_a + 4096, *page = x->guard_b + 4096;
    for (unsigned ni = 0; ni < 260; ni++)
    {
        size_t n = ni < 258 ? ni : ni == 258 ? 4095 : 4096;
        for (unsigned edge = 0; edge < 2; edge++)
            for (size_t a = 0; a < 8 && n + a <= 4096; a++)
                for (size_t b = 0; b < 8 && n + b <= 4096; b++)
                    for (unsigned kind = 0; kind < 2; kind++)
                    {
                        size_t from = edge ? 4096 - n - a : a;
                        size_t to = edge ? 4096 - n - b : b;
                        memset(page, 0xA5, 4096);
                        void *result = kind ? memmove(page + to, source_page + from, n)
                                            : memcpy(page + to, source_page + from, n);
                        if (result != page + to) return EIO;
                        size_t low = to > 32 ? to - 32 : 0, high = to + n;
                        high = 4096 - high < 32 ? 4096 : high + 32;
                        for (size_t i = low; i < high; i++)
                        {
                            unsigned char expected = i >= to && i - to < n ? x->a[from + i - to] : 0xA5;
                            if (page[i] != expected)
                            {
                                perf_log("PERF_COPY_FAIL,kind=%u,size=%u,edge=%u,source=%u,target=%u,index=%u\n",
                                         kind, (unsigned)n, edge, (unsigned)a, (unsigned)b, (unsigned)i);
                                return EIO;
                            }
                        }
                    }
        for (size_t gap = 1; gap <= 33; gap++)
            for (size_t alignment = 0; alignment < 8 && n + gap + alignment <= 4096; alignment++)
                for (unsigned edge = 0; edge < 2; edge++)
                    for (unsigned backward = 0; backward < 2; backward++)
                    {
                        size_t first = edge ? 4096 - n - gap - alignment : alignment;
                        size_t from = first + (backward ? 0 : gap), to = first + (backward ? gap : 0);
                        size_t low = first > 32 ? first - 32 : 0, high = first + n + gap;
                        high = 4096 - high < 32 ? 4096 : high + 32;
                        memcpy(page, x->a, 4096);
                        for (size_t i = low; i < high; i++) x->b[i] = x->a[i];
                        if (backward)
                            for (size_t i = n; i > 0; i--) x->b[to + i - 1] = x->b[from + i - 1];
                        else
                            for (size_t i = 0; i < n; i++) x->b[to + i] = x->b[from + i];
                        if (memmove(page + to, page + from, n) != page + to) return EIO;
                        for (size_t i = low; i < high; i++)
                            if (page[i] != x->b[i])
                            {
                                perf_log("PERF_MOVE_FAIL,size=%u,gap=%u,edge=%u,backward=%u,index=%u\n",
                                         (unsigned)n, (unsigned)gap, edge, backward, (unsigned)i);
                                return EIO;
                            }
                    }
    }
    memcpy(page, x->a, 4096);
    if (memmove(page, page, 4096) != page || memmove(page + 4096, page + 4096, 0) != page + 4096)
        return EIO;
    for (size_t i = 0; i < 4096; i++) if (page[i] != x->a[i]) return EIO;
    return 0;
}
static int operation(context_t *x)
{
    const bench_t *b = x->bench;
    size_t z = b->size;
    int fd, e;
    void *p;
    struct timespec t;
    errno = 0;
    switch (b->op)
    {
    case PID:
        sink = getpid();
        break;
    case CLOCK:
        REQUIRE(!clock_gettime(CLOCK_MONOTONIC, &t));
        sink = t.tv_nsec;
        break;
    case CPU_CLOCK:
        REQUIRE(!clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t));
        sink = t.tv_nsec;
        break;
    case YIELD:
        REQUIRE(!sched_yield());
        break;
    case SLEEP:
        t = (struct timespec){0, (long)z * 1000000};
        while (nanosleep(&t, &t) < 0)
            REQUIRE(errno == EINTR);
        break;
    case RANDOM:
        REQUIRE(getrandom(x->b, z, 0) == (ssize_t)z);
        sink = x->b[0];
        break;
    case FUTEX_MISS:
        e = sys_futex_wait(&x->futex, 1, 1);
        REQUIRE(e == -EAGAIN);
        break;
    case FUTEX_WAKE:
        REQUIRE(sys_futex_wake(&x->futex, 1) >= 0);
        break;
    case MALLOC:
        p = malloc(z);
        REQUIRE(p);
        ((volatile char *)p)[0] = 1;
        ((volatile char *)p)[z - 1] = 2;
        free(p);
        break;
    case CALLOC:
        p = calloc(1, z);
        REQUIRE(p);
        e = ((unsigned char *)p)[0] | ((unsigned char *)p)[z - 1];
        free(p);
        REQUIRE(!e);
        break;
    case REALLOC:
        p = malloc(4096);
        REQUIRE(p);
        memset(p, 19, 4096);
        {
            void *q = realloc(p, 64 * KB);
            if (!q)
            {
                free(p);
                return ENOMEM;
            }
            p = q;
        }
        e = ((unsigned char *)p)[4095];
        free(p);
        REQUIRE(e == 19);
        break;
    case FRAGMENT:
        for (unsigned i = 0; i < 64; i++)
        {
            x->slots[i] = malloc(32 + (i * 157) % 8192);
            REQUIRE(x->slots[i]);
        }
        for (unsigned i = 0; i < 64; i += 2)
        {
            free(x->slots[i]);
            x->slots[i] = NULL;
        }
        for (unsigned i = 0; i < 64; i += 2)
        {
            x->slots[i] = malloc(256 + i * 13);
            REQUIRE(x->slots[i]);
        }
        for (unsigned i = 0; i < 64; i++)
        {
            free(x->slots[i]);
            x->slots[i] = NULL;
        }
        break;
    case MEMCPY:
        memcpy(x->b, x->a, z);
        sink = x->b[z - 1];
        REQUIRE(x->b[z - 1] == x->a[z - 1]);
        break;
    case MEMCPY_UNALIGNED:
        REQUIRE(memcpy(x->b + 2, x->a + 1, z) == x->b + 2);
        sink = x->b[z + 1];
        break;
    case MEMCOPY_GUARD:
        return guarded_copy(x);
    case MEMSET:
        memset(x->b, 41, z);
        sink = x->b[z - 1];
        REQUIRE(x->b[z - 1] == 41);
        break;
    case MEMMOVE:
        memmove(x->b + 16, x->b, z);
        sink = x->b[z];
        break;
    case MEMMOVE_BACK1:
        REQUIRE(memmove(x->b + 1, x->b, z) == x->b + 1);
        sink = x->b[z];
        break;
    case MEMMOVE_FWD1:
        REQUIRE(memmove(x->b, x->b + 1, z) == x->b);
        sink = x->b[0];
        break;
    case MEMCMP_EQUAL:
    case MEMCMP_UNALIGNED:
    case MEMCMP_EARLY:
    case MEMCMP_LATE:
    {
        unsigned char *a = x->a + (b->op == MEMCMP_UNALIGNED ? 1 : 0);
        unsigned char *other = x->b + (b->op == MEMCMP_UNALIGNED ? 2 : 0);
        int value = memcmp(a, other, z);
        sink = (uint64_t)(int64_t)value;
        if (b->op == MEMCMP_EARLY || b->op == MEMCMP_LATE)
        {
            size_t at = b->op == MEMCMP_EARLY ? 0 : z - 1;
            int expected = (int)a[at] - (int)other[at];
            REQUIRE((value < 0) == (expected < 0) && (value > 0) == (expected > 0));
        }
        else
            REQUIRE(value == 0);
        break;
    }
    case MEMCMP_GUARD:
        for (unsigned ni = 0; ni <= 258; ni++)
        {
            size_t n = ni == 258 ? 4096 : ni;
            unsigned limit = n == 4096 ? 1 : 8;
            for (unsigned ao = 0; ao < limit; ao++)
                for (unsigned bo = 0; bo < limit; bo++)
                {
                    unsigned char *a = x->guard_a + 4096 - n - ao,
                                  *other = x->guard_b + 4096 - n - bo;
                    memcpy(other, a, n);
                    REQUIRE(memcmp(a, other, n) == 0 && memcmp(a, a, n) == 0);
                    if (n)
                        for (unsigned where = 0; where < 3; where++)
                        {
                            size_t at = where == 0 ? 0 : where == 1 ? n / 2 : n - 1;
                            other[at] ^= 0x80;
                            int expected = (int)a[at] - (int)other[at];
                            int value = memcmp(a, other, n), reverse = memcmp(other, a, n);
                            REQUIRE((value < 0) == (expected < 0) && (value > 0) == (expected > 0));
                            REQUIRE((reverse < 0) == (expected > 0) &&
                                    (reverse > 0) == (expected < 0));
                            other[at] ^= 0x80;
                        }
                }
        }
        break;
    case VM_MAP:
    case VM_RESERVE:
        p = mmap(NULL, z, b->op == VM_MAP ? PROT_READ | PROT_WRITE : PROT_NONE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        REQUIRE(p != MAP_FAILED);
        if (b->op == VM_MAP)
            for (size_t i = 0; i < z; i += 4096)
                ((volatile char *)p)[i] = 1;
        REQUIRE(!munmap(p, z));
        break;
    case VM_PROTECT:
        REQUIRE(!mprotect(x->mapping, z, PROT_READ));
        REQUIRE(!mprotect(x->mapping, z, PROT_READ | PROT_WRITE));
        break;
    case VM_FAULT:
        REQUIRE(!madvise(x->mapping, z, MADV_DONTNEED));
        for (size_t i = 0; i < z; i += 4096)
        {
            volatile char *v = (char *)x->mapping + i;
            REQUIRE(!*v);
            *v = 17;
        }
        break;
    case MUTEX:
        e = pthread_mutex_lock(&x->mutex);
        if (e)
            return e;
        e = pthread_mutex_unlock(&x->mutex);
        if (e)
            return e;
        break;
    case RWLOCK:
        e = pthread_rwlock_rdlock(&x->rwlock);
        if (e)
            return e;
        e = pthread_rwlock_unlock(&x->rwlock);
        if (e)
            return e;
        break;
    case RWLOCK_WRITE:
        e = pthread_rwlock_wrlock(&x->rwlock);
        if (e)
            return e;
        e = pthread_rwlock_unlock(&x->rwlock);
        if (e)
            return e;
        break;
    case PTHREAD_SELF:
        REQUIRE(pthread_self() == x->parent_tid);
        break;
    case NATIVE_THREAD_SELF:
        REQUIRE(sys_thread_self() == x->parent_tid);
        break;
    case THREAD_IDENTITY:
        x->identity_error = 0;
        e = pthread_create(&x->identity_thread, NULL, identity_worker, x);
        if (e)
            return e;
        e = pthread_join(x->identity_thread, NULL);
        if (e)
            return e;
        if (x->identity_error)
            return x->identity_error;
        break;
    case FORK_IDENTITY:
    {
        REQUIRE(pthread_self() == x->parent_tid);
        x->identity_error = 0;
        pid_t pid = fork();
        REQUIRE(pid >= 0);
        if (!pid)
            _exit(x->identity_error || identity_check(x, x->parent_tid) ? 1 : 0);
        return child_wait(pid);
    }
    case TLS:
        tls_value++;
        __asm__ volatile("" : "+m"(tls_value));
        break;
    case THREAD:
    {
        pthread_t thread;
        void *value = NULL;
        e = pthread_create(&thread, NULL, empty_thread, x);
        if (e)
            return e;
        e = pthread_join(thread, &value);
        if (e)
            return e;
        REQUIRE(value == x);
        break;
    }
    case SPAWN:
    {
        pid_t pid;
        char *args[] = {x->config->executable, "--child", NULL};
        char *env[] = {NULL};
        e = posix_spawn(&pid, args[0], NULL, NULL, args, env);
        if (e)
            return e;
        return child_wait(pid);
    }
    case FORK:
    {
        pid_t pid = fork();
        REQUIRE(pid >= 0);
        if (!pid)
            _exit(0);
        return child_wait(pid);
    }
    case PIPE:
    case LOCAL:
        e = transfer(x->pair[1], x->a, z, true, b->op == LOCAL);
        if (e)
            return e;
        e = transfer(x->pair[0], x->b, z, false, b->op == LOCAL);
        if (e)
            return e;
        REQUIRE(!memcmp(x->a, x->b, z));
        break;
    case POLL_IDLE:
    case POLL_READY:
    case POLL_DISTINCT_IDLE:
    case POLL_DISTINCT_READY:
    case POLL_LOCAL_REPEAT:
        e = poll(x->polls, z, 0);
        REQUIRE(e == (b->op == POLL_READY || b->op == POLL_DISTINCT_READY ? (int)z : 0));
        break;
    case STAT:
    {
        struct stat st;
        REQUIRE(!stat(x->path, &st) && st.st_size == MB);
        break;
    }
    case OPEN:
        fd = open(x->path, O_RDONLY | O_CLOEXEC);
        REQUIRE(fd >= 0);
        REQUIRE(!close(fd));
        break;
    case DUP:
        fd = dup(x->fd);
        REQUIRE(fd >= 0);
        REQUIRE(!close(fd));
        break;
    case DIRECTORY:
    {
        DIR *d = opendir(x->directory);
        REQUIRE(d);
        unsigned found = 0, dot = 0, parent = 0;
        int invalid = 0;
        x->directory_seen[0] = x->directory_seen[1] = 0;
        struct dirent *entry;
        errno = 0;
        for (;;)
        {
            ++x->directory_calls;
            entry = readdir(d);
            if (!entry)
                break;
            ++x->directory_entries;
            if (!entry->d_ino)
                invalid = 1;
            if (!strcmp(entry->d_name, "."))
                dot++;
            else if (!strcmp(entry->d_name, ".."))
                parent++;
            else if (!strcmp(entry->d_name, "data"))
            {
                if (x->directory_seen[0] & 1)
                    invalid = 1;
                x->directory_seen[0] |= 1;
                found++;
            }
            else if (z && !strncmp(entry->d_name, "entry-", 6))
            {
                char *end;
                unsigned long index = strtoul(entry->d_name + 6, &end, 10);
                if (*end || !index || index >= z)
                    invalid = 1;
                else
                {
                    uint64_t mask = UINT64_C(1) << (index % 64);
                    if (x->directory_seen[index / 64] & mask)
                        invalid = 1;
                    x->directory_seen[index / 64] |= mask;
                    found++;
                }
            }
            else
                invalid = 1;
        }
        e = errno;
        if (closedir(d) < 0 && !e)
            e = errno;
        REQUIRE(!e && !invalid && found == (z ? z : 1) && dot == 1 && parent == 1);
        break;
    }
    case CREATE:
        fd = open(x->temporary, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
        REQUIRE(fd >= 0);
        close(fd);
        REQUIRE(!unlink(x->temporary));
        break;
    case FILE_READ:
    case FILE_READ_API:
    case FILE_READ_CHECKED:
        for (size_t done = 0; done < z;)
        {
            ssize_t n = pread(x->fd, x->b + done, z - done, (off_t)done);
            ++x->file_read_calls;
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0)
                return n < 0 ? errno : EIO;
            if ((size_t)n > z - done)
                return EIO;
            done += (size_t)n;
            x->file_read_bytes += (uint64_t)n;
        }
        if (b->op != FILE_READ_API)
            REQUIRE(!memcmp(x->a, x->b, z));
        break;
    case FILE_WRITE:
    case FILE_SYNC:
        REQUIRE(lseek(x->fd, 0, SEEK_SET) == 0);
        e = transfer(x->fd, x->a, z, true, false);
        if (e)
            return e;
        if (b->op == FILE_SYNC)
            REQUIRE(!fsync(x->fd));
        break;
    case FILE_RANDOM:
        x->random_index = x->random_index * 6364136223846793005ULL + 1;
        {
            size_t offset = ((x->random_index >> 32) % 256) * 4096;
            REQUIRE(pread(x->fd, x->b, z, offset) == (ssize_t)z);
            REQUIRE(!memcmp(x->a + offset, x->b, z));
        }
        break;
    case FILE_MAP:
        p = mmap(NULL, z, PROT_READ, MAP_PRIVATE, x->fd, 0);
        REQUIRE(p != MAP_FAILED);
        e = memcmp(p, x->a, z);
        REQUIRE(!munmap(p, z));
        REQUIRE(!e);
        break;
    case SOCKET:
        fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        REQUIRE(fd >= 0);
        close(fd);
        break;
    case SOCKET_BURST:
    {
        unsigned opened = 0;
        int error = 0;
        for (; opened < 128; opened++)
        {
            x->fd_batch[opened] = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
            if (x->fd_batch[opened] < 0)
            {
                error = errno;
                break;
            }
        }
        if (opened)
        {
            x->socket_option_size = sizeof(x->socket_receive_capacity);
            if (getsockopt(x->fd_batch[0], SOL_SOCKET, SO_RCVBUF, &x->socket_receive_capacity,
                           &x->socket_option_size) < 0 &&
                !error)
                error = errno;
        }
        for (unsigned i = 0; i < opened; i++)
            close(x->fd_batch[i]);
        if (error)
            return error;
        break;
    }
    case TCP_CONNECT:
        fd = tcp_open(x);
        REQUIRE(fd >= 0);
        close(fd);
        break;
    case TCP_ECHO:
        /* Interleave chunks so the echo peer cannot fill its send window while
         * we are still trying to fill ours. Each operation verifies all bytes. */
        for (size_t i = 0; i < z; i += 1024)
        {
            size_t n = z - i < 1024 ? z - i : 1024;
            e = transfer(x->fd, x->a + i, n, true, true);
            if (e)
                return e;
            e = transfer(x->fd, x->b + i, n, false, true);
            if (e)
                return e;
        }
        REQUIRE(!memcmp(x->a, x->b, z));
        break;
    case TCP_STREAM:
    case TCP_VECTOR:
    {
        size_t sent = 0, received = 0;
        uint64_t deadline = perf_now_ns() + UINT64_C(10000000000);
        while (received < z)
        {
            if (stopped(x->config))
                return ECANCELED;
            if (perf_now_ns() > deadline)
                return ETIMEDOUT;
            bool progress = false;
            if (sent < z)
            {
                ssize_t n;
                if (b->op == TCP_VECTOR)
                {
                    size_t left = z - sent, first = left < 733 ? left : 733;
                    x->send_vectors[0] = (struct iovec){x->a + sent, first};
                    x->send_vectors[1] = (struct iovec){x->a + sent + first, left - first};
                    if ((x->vector_sends + x->vector_writes) & 1)
                    {
                        ++x->vector_writes;
                        n = writev(x->fd, x->send_vectors, 2);
                    }
                    else
                    {
                        ++x->vector_sends;
                        x->send_message.msg_iov = x->send_vectors;
                        x->send_message.msg_iovlen = 2;
                        n = sendmsg(x->fd, &x->send_message, MSG_DONTWAIT | MSG_NOSIGNAL);
                    }
                }
                else
                    n = send(x->fd, x->a + sent, z - sent, MSG_DONTWAIT | MSG_NOSIGNAL);
                if (n > 0)
                {
                    sent += (size_t)n;
                    progress = true;
                }
                else if (n == 0)
                    return EIO;
                else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                    return errno;
            }
            ssize_t n;
            if (b->op == TCP_VECTOR)
            {
                size_t left = z - received, first = left < 17 ? left : 17;
                x->receive_vectors[0] = (struct iovec){x->b + received, first};
                x->receive_vectors[1] = (struct iovec){x->b + received + first, left - first};
                x->receive_message.msg_iov = x->receive_vectors;
                x->receive_message.msg_iovlen = 2;
                ++x->vector_receives;
                n = recvmsg(x->fd, &x->receive_message, MSG_DONTWAIT);
            }
            else
                n = recv(x->fd, x->b + received, z - received, MSG_DONTWAIT);
            if (n > 0)
            {
                received += (size_t)n;
                progress = true;
            }
            else if (n == 0)
                return EIO;
            else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                return errno;
            if (!progress)
            {
                e = wait_fd(x->fd, POLLIN | (sent < z ? POLLOUT : 0));
                if (e)
                    return e;
            }
        }
        REQUIRE(sent == z && !memcmp(x->a, x->b, z));
        break;
    }
    case UDP_ECHO:
        REQUIRE(send(x->fd, x->a, z, MSG_DONTWAIT) == (ssize_t)z);
        e = wait_fd(x->fd, POLLIN);
        if (e)
            return e;
        REQUIRE(recv(x->fd, x->b, z + 1, MSG_DONTWAIT) == (ssize_t)z);
        REQUIRE(!memcmp(x->a, x->b, z));
        break;
    case DNS:
    {
        struct addrinfo hint = {0}, *list = NULL;
        hint.ai_family = AF_INET;
        hint.ai_socktype = SOCK_STREAM;
        e = getaddrinfo(x->config->dns_host, NULL, &hint, &list);
        if (e)
            return EHOSTUNREACH;
        REQUIRE(list);
        freeaddrinfo(list);
        break;
    }
    }
    return 0;
}
static int batch(context_t *x, unsigned n)
{
    for (unsigned i = 0; i < n; i++)
    {
        if ((i & 63) == 0 && stopped(x->config))
            return ECANCELED;
        int e = operation(x);
        if (e)
            return e;
    }
    if (x->bench->op == MEMMOVE || x->bench->op == MEMMOVE_BACK1 || x->bench->op == MEMMOVE_FWD1)
        x->move_calls += n;
    return 0;
}
static void run_bench(perf_config_t *c, const bench_t *b)
{
    if ((b->op == SOCKET_BURST || b->op == THREAD_IDENTITY || b->op == FORK_IDENTITY ||
         b->op == MEMCMP_GUARD || b->op == MEMCOPY_GUARD || b->op == TCP_VECTOR ||
         (b->op == DIRECTORY && b->size) || b->op == FILE_READ_API ||
         b->op == FILE_READ_CHECKED || b->op == POLL_DISTINCT_IDLE ||
         b->op == POLL_DISTINCT_READY || b->op == POLL_LOCAL_REPEAT) &&
        !c->case_name)
        return;
    if (!selected(c, b->group) || !selected_case(c, b->name) || stopped(c))
        return;
    current(c, b->name);
    perf_result_t r = {0};
    snprintf(r.name, sizeof(r.name), "%s", b->name);
    snprintf(r.group, sizeof(r.group), "%s", b->group);
    r.workers = 1;
    context_t *x = calloc(1, sizeof(*x));
    if (!x)
    {
        r.error = ENOMEM;
        perf_record(c->state, &r);
        return;
    }
    x->bench = b;
    x->config = c;
    r.error = prepare(x);
    if (r.error < 0)
        snprintf(r.detail, sizeof(r.detail), "%s",
                 b->op == FORK_IDENTITY ? "run with --cli for fork identity validation"
                 : b->op == DNS         ? "supply --dns-host"
                                        : "supply --net and --port for an echo server");
    uint64_t *costs = calloc(c->rounds, sizeof(uint64_t));
    unsigned n = 1;
    if (!costs && !r.error)
        r.error = ENOMEM;
    /* Warmup and geometric calibration are not reported as measured samples. */
    if (!r.error)
        r.error = batch(x, 1);
    while (!r.error && n < b->cap && !stopped(c))
    {
        uint64_t start = perf_now_ns();
        r.error = batch(x, n);
        uint64_t elapsed = perf_now_ns() - start;
        if (elapsed >= (uint64_t)c->duration_ms * 1000000)
            break;
        n = n > b->cap / 2 ? b->cap : n * 2;
    }
    uint64_t target = sample_target_ns(c, 1);
    for (unsigned round = 0; !r.error && round < c->rounds && !stopped(c); round++)
    {
        struct rusage before = {0}, after = {0};
        if (getrusage(RUSAGE_SELF, &before))
        {
            r.error = errno;
            break;
        }
        uint64_t start = perf_now_ns(), elapsed = 0, operations = 0;
        do
        {
            r.error = batch(x, n);
            operations += n;
            elapsed = perf_now_ns() - start;
        } while (!r.error && !stopped(c) && elapsed < target);
        if (getrusage(RUSAGE_SELF, &after))
        {
            r.error = errno;
            break;
        }
        if (r.error)
            break;
        perf_log("PERF_SAMPLE,%s,%u,%llu,%llu\n", b->name, round, (unsigned long long)operations,
                 (unsigned long long)elapsed);
        costs[r.samples++] = elapsed / operations;
        r.operations += operations;
        r.elapsed_ns += elapsed;
        usage_delta(&r, &before, &after);
    }
    if (!r.error && !r.samples)
        r.error = ECANCELED;
    if (!r.error && r.elapsed_ns == 0)
        snprintf(r.detail, sizeof(r.detail),
                 "below clock resolution; increase --duration or iteration cap");
    if (b->op == MEMCPY || b->op == MEMCPY_UNALIGNED || b->op == MEMSET || b->op == MEMMOVE ||
        b->op == MEMMOVE_BACK1 || b->op == MEMMOVE_FWD1 || b->op == MEMCMP_EQUAL ||
        b->op == MEMCMP_UNALIGNED || b->op == MEMCMP_LATE || b->op == FILE_READ ||
        b->op == FILE_READ_API || b->op == FILE_READ_CHECKED ||
        b->op == FILE_WRITE || b->op == FILE_RANDOM || b->op == FILE_SYNC || b->op == FILE_MAP ||
        b->op == PIPE || b->op == LOCAL || b->op == TCP_ECHO || (b->op == TCP_STREAM || b->op == TCP_VECTOR) ||
        b->op == UDP_ECHO)
        r.bytes = r.operations * b->size;
    if (b->op == SLEEP)
        snprintf(r.detail, sizeof(r.detail), "requested=%u ms; reported cost includes wakeup delay",
                 (unsigned)b->size);
    if (r.error == ECANCELED)
        r.error = -2;
    finish(&r, costs);
    free(costs);
    if (!r.error && (b->op == MEMCPY || b->op == MEMCPY_UNALIGNED))
    {
        size_t source = b->op == MEMCPY_UNALIGNED ? 1 : 0, target = source ? 2 : 0;
        if (memcmp(x->b + target, x->a + source, b->size)) r.error = EIO;
    }
    if (!r.error && (b->op == MEMMOVE || b->op == MEMMOVE_BACK1 || b->op == MEMMOVE_FWD1))
    {
        size_t gap = b->op == MEMMOVE ? 16 : 1;
        for (size_t i = 0; i < b->size + gap; i++)
        {
            size_t original;
            if (b->op == MEMMOVE_FWD1)
            {
                size_t shift = x->move_calls < b->size ? (size_t)x->move_calls : b->size;
                original = i >= b->size ? i : i + shift < b->size ? i + shift : b->size;
            }
            else
                original = x->move_calls <= i / gap ? i - (size_t)x->move_calls * gap : i % gap;
            if (x->b[i] != x->a[original]) { r.error = EIO; break; }
        }
    }
    if (!r.error && (b->op == POLL_IDLE || b->op == POLL_READY || b->op == POLL_DISTINCT_IDLE ||
                     b->op == POLL_DISTINCT_READY || b->op == POLL_LOCAL_REPEAT))
    {
        short expected = b->op == POLL_READY || b->op == POLL_DISTINCT_READY ? POLLIN : 0;
        for (size_t i = 0; i < b->size; i++)
            if (x->polls[i].revents != expected) { r.error = EIO; break; }
        if (b->op == POLL_DISTINCT_IDLE || b->op == POLL_DISTINCT_READY || b->op == POLL_LOCAL_REPEAT)
            snprintf(r.detail, sizeof(r.detail), "%u entries; %s local endpoints; final revents validated",
                     (unsigned)b->size, b->op == POLL_LOCAL_REPEAT ? "repeated" : "distinct");
    }
    if (b->op == MEMCOPY_GUARD && !r.error)
        snprintf(r.detail, sizeof(r.detail), "8x8 alignments; overlap gaps 1..33; guarded page edges and canaries");
    if (b->op == FILE_READ_API && !r.error && memcmp(x->a, x->b, b->size))
        r.error = EIO;
    if (b->op == FILE_READ || b->op == FILE_READ_API || b->op == FILE_READ_CHECKED)
        snprintf(r.detail, sizeof(r.detail), "pread_calls=%llu bytes=%llu; check=%s; includes warmup",
                 (unsigned long long)x->file_read_calls, (unsigned long long)x->file_read_bytes,
                 b->op == FILE_READ_API ? "after timing" : "each op");
    if (b->op == DIRECTORY)
        snprintf(r.detail, sizeof(r.detail), "readdir_calls=%llu entries=%llu; includes warmup",
                 (unsigned long long)x->directory_calls, (unsigned long long)x->directory_entries);
    if (b->op == TCP_ECHO || (b->op == TCP_STREAM || b->op == TCP_VECTOR))
        snprintf(r.detail, sizeof(r.detail), "connected_rx_bytes=%d", x->socket_receive_capacity);
    if (b->op == TCP_VECTOR)
        snprintf(r.detail, sizeof(r.detail), "sendmsg=%llu writev=%llu recvmsg=%llu; verified payload",
                 (unsigned long long)x->vector_sends, (unsigned long long)x->vector_writes,
                 (unsigned long long)x->vector_receives);
    if (b->op == MEMCMP_GUARD && !r.error)
        snprintf(r.detail, sizeof(r.detail),
                 "all 8x8 alignments; equal/first/middle/last differences; protected page ends");
    if (!r.error && (b->op == THREAD_IDENTITY || b->op == FORK_IDENTITY))
        snprintf(r.detail, sizeof(r.detail),
                 "identity checked against native self-info; migration or fork callbacks verified");
    if (b->op == SOCKET_BURST)
        snprintf(r.detail, sizeof(r.detail), "rx_bytes_per_socket=%d reserved_for_128=%llu",
                 x->socket_receive_capacity,
                 (unsigned long long)((uint64_t)x->socket_receive_capacity * 128));
    cleanup(x);
    perf_record(c->state, &r);
}

typedef struct parallel parallel_t;
typedef struct
{
    parallel_t *shared;
    pthread_t thread;
    unsigned index;
    uint64_t count, value;
    int error;
    unsigned char padding[64];
} worker_t;
struct parallel
{
    perf_config_t *config;
    worker_t *workers;
    pthread_mutex_t mutex;
    uint32_t ready, start, done;
    unsigned mode, count;
    bool same_cpu;
    uint64_t deadline, shared_counter;
    context_t *file_context;
    bench_t file_bench;
    unsigned char **read_buffers;
};
static void parallel_file_cleanup(parallel_t *p)
{
    if (p->read_buffers)
        for (unsigned i = 0; i < p->count; i++) free(p->read_buffers[i]);
    free(p->read_buffers);
    if (p->file_context) cleanup(p->file_context);
}
static int parallel_file_prepare(parallel_t *p)
{
    p->file_bench = (bench_t){"filesystem", "pread_parallel_n", FILE_READ_API, 4096, 1};
    p->file_context = calloc(1, sizeof(*p->file_context));
    if (!p->file_context) return ENOMEM;
    p->file_context->bench = &p->file_bench;
    p->file_context->config = p->config;
    int error = prepare(p->file_context);
    if (error) return error;
    p->read_buffers = calloc(p->count, sizeof(*p->read_buffers));
    if (!p->read_buffers) return ENOMEM;
    for (unsigned i = 0; i < p->count; i++)
    {
        p->read_buffers[i] = malloc(4096);
        if (!p->read_buffers[i]) return ENOMEM;
    }
    return 0;
}
static void *parallel_worker(void *arg)
{
    worker_t *w = arg;
    parallel_t *p = w->shared;
    w->error = -sys_thread_set_affinity(p->same_cpu ? 0 : w->index % p->config->cpus);
    __atomic_add_fetch(&p->ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&p->start, __ATOMIC_ACQUIRE))
        sched_yield();
    uint64_t count = 0, value = w->index + 1;
    if (!w->error)
        do
        {
            for (unsigned k = 0; k < 64; k++)
            {
                if (p->mode == 0)
                {
                    for (unsigned j = 0; j < 128; j++)
                    {
                        value = value * 6364136223846793005ULL + j;
                        __asm__ volatile("" : "+r"(value));
                    }
                }
                else if (p->mode == 1)
                    __atomic_add_fetch(&p->shared_counter, 1, __ATOMIC_RELAXED);
                else if (p->mode == 2)
                {
                    int e = pthread_mutex_lock(&p->mutex);
                    if (e)
                    {
                        w->error = e;
                        break;
                    }
                    p->shared_counter++;
                    pthread_mutex_unlock(&p->mutex);
                }
                else if (p->mode == 3)
                {
                    void *v = malloc(256);
                    if (!v)
                    {
                        w->error = ENOMEM;
                        break;
                    }
                    ((volatile char *)v)[0] = 1;
                    free(v);
                }
                else if (p->mode == 5)
                {
                    ssize_t bytes = pread(p->file_context->fd, p->read_buffers[w->index], 4096, 0);
                    if (bytes != 4096)
                    {
                        w->error = bytes < 0 ? errno : EIO;
                        break;
                    }
                }
                else
                    sched_yield();
                count++;
            }
        } while (!w->error && perf_now_ns() < p->deadline && !stopped(p->config));
    w->count = count;
    w->value = value;
    __atomic_add_fetch(&p->done, 1, __ATOMIC_RELEASE);
    return NULL;
}
static void run_parallel(perf_config_t *c, const char *name, unsigned mode, unsigned count,
                         bool same)
{
    const char *group = mode == 5 ? "filesystem" :
                        mode == 0 || mode == 4 ? "scheduling" : "threading";
    if (mode == 5 && !c->case_name) return;
    if (!selected(c, group) || !selected_case(c, name) || stopped(c))
        return;
    current(c, name);
    perf_result_t r = {0};
    snprintf(r.name, sizeof(r.name), "%s", name);
    snprintf(r.group, sizeof(r.group), "%s", group);
    r.workers = count;
    uint64_t *costs = calloc(c->rounds, sizeof(uint64_t));
    if (!costs)
    {
        r.error = ENOMEM;
        perf_record(c->state, &r);
        return;
    }
    for (unsigned round = 0; round < c->rounds && !r.error && !stopped(c); round++)
    {
        parallel_t *p = calloc(1, sizeof(*p));
        if (!p)
        {
            r.error = ENOMEM;
            break;
        }
        p->config = c;
        p->mode = mode;
        p->count = count;
        p->same_cpu = same;
        p->workers = calloc(count, sizeof(worker_t));
        if (!p->workers)
        {
            free(p);
            r.error = ENOMEM;
            break;
        }
        if (mode == 5 && (r.error = parallel_file_prepare(p)))
        {
            parallel_file_cleanup(p);
            free(p->workers);
            free(p);
            break;
        }
        pthread_mutex_init(&p->mutex, NULL);
        unsigned created = 0;
        for (unsigned i = 0; i < count; i++)
        {
            worker_t *w = &p->workers[i];
            w->shared = p;
            w->index = i;
            r.error = pthread_create(&w->thread, NULL, parallel_worker, w);
            if (r.error)
                break;
            created++;
        }
        while (__atomic_load_n(&p->ready, __ATOMIC_ACQUIRE) < created)
            sched_yield();
        struct rusage before = {0}, after = {0};
        getrusage(RUSAGE_SELF, &before);
        uint64_t start = perf_now_ns();
        p->deadline = start + sample_target_ns(c, 4);
        __atomic_store_n(&p->start, 1, __ATOMIC_RELEASE);
        while (__atomic_load_n(&p->done, __ATOMIC_ACQUIRE) < created)
            usleep(1000);
        uint64_t elapsed = perf_now_ns() - start;
        getrusage(RUSAGE_SELF, &after);
        uint64_t total = 0, low = UINT64_MAX, high = 0;
        for (unsigned i = 0; i < created; i++)
        {
            worker_t *w = &p->workers[i];
            pthread_join(w->thread, NULL);
            if (w->error)
                r.error = w->error;
            if (mode == 5 && w->count && memcmp(p->file_context->a, p->read_buffers[i], 4096))
                r.error = EIO;
            if (mode == 5 && !w->count && !stopped(c))
                r.error = EIO;
            total += w->count;
            if (w->count < low)
                low = w->count;
            if (w->count > high)
                high = w->count;
            sink = w->value;
        }
        if ((mode == 1 || mode == 2) && p->shared_counter != total)
            r.error = EIO;
        if (!r.error && total)
        {
            costs[r.samples++] = elapsed / total;
            r.operations += total;
            r.elapsed_ns += elapsed;
            usage_delta(&r, &before, &after);
            perf_log("PERF_SAMPLE,%s,%u,%llu,%llu\n", name, round, (unsigned long long)total,
                     (unsigned long long)elapsed);
            perf_log("PERF_FAIRNESS,%s,%u,%llu,%llu\n", name, round, (unsigned long long)low,
                     (unsigned long long)high);
        }
        else if (!r.error)
            r.error = EIO;
        pthread_mutex_destroy(&p->mutex);
        parallel_file_cleanup(p);
        free(p->workers);
        free(p);
    }
    finish(&r, costs);
    free(costs);
    if (mode == 5)
    {
        r.bytes = r.operations * 4096;
        snprintf(r.detail, sizeof(r.detail), "shared pread; every worker progressed; final bytes checked outside timing");
    }
    perf_record(c->state, &r);
}

typedef struct
{
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    pthread_t thread;
    perf_config_t *config;
    unsigned turn, peer_cpu;
    uint64_t owner_pid;
    bool abort, ready;
    int error;
} handoff_t;
/* Debugger-only root: the coordinator publishes this heap record until join. */
static handoff_t *g_perf_handoff;
__attribute__((noinline)) void perf_handoff_ready_checkpoint(void)
{
    __asm__ volatile("" : : "r"(g_perf_handoff) : "memory");
}
__attribute__((noinline)) void perf_handoff_sample_checkpoint(void)
{
    __asm__ volatile("" : : "r"(g_perf_handoff) : "memory");
}
static int handoff_wait(handoff_t *h, unsigned turn)
{
    while (h->turn != turn && !h->abort)
    {
        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += 2;
        int e = pthread_cond_timedwait(&h->condition, &h->mutex, &deadline);
        if (e)
        {
            h->error = e;
            h->abort = true;
            pthread_cond_broadcast(&h->condition);
            return e;
        }
    }
    return h->abort ? ECANCELED : 0;
}
static void *handoff_worker(void *arg)
{
    handoff_t *h = arg;
    int affinity_error = sys_thread_set_affinity(h->peer_cpu);
    pthread_mutex_lock(&h->mutex);
    if (affinity_error) { h->error = EIO; h->abort = true; }
    h->ready = true;
    pthread_cond_signal(&h->condition);
    while (!h->abort)
    {
        if (handoff_wait(h, 1))
            break;
        h->turn = 0;
        pthread_cond_signal(&h->condition);
    }
    pthread_mutex_unlock(&h->mutex);
    return NULL;
}
static void run_handoff(perf_config_t *c, const char *name, unsigned cpu, unsigned peer,
                        bool diagnostic)
{
    if ((diagnostic && !c->case_name) || !selected(c, "threading") ||
        !selected_case(c, name) || stopped(c)) return;
    current(c, name);
    perf_result_t r = {0};
    snprintf(r.name, sizeof(r.name), "%s", name);
    snprintf(r.group, sizeof(r.group), "threading");
    r.workers = 2;
    if (cpu >= c->cpus || peer >= c->cpus)
    {
        r.error = -1;
        snprintf(r.detail, sizeof(r.detail), "requires CPUs %u and %u", cpu, peer);
        perf_record(c->state, &r);
        return;
    }
    if (sys_thread_set_affinity(cpu))
    {
        r.error = EIO;
        perf_record(c->state, &r);
        return;
    }
    uint64_t *costs = calloc(c->rounds, sizeof(uint64_t));
    if (!costs)
    {
        r.error = ENOMEM;
        sys_thread_set_affinity(0);
        perf_record(c->state, &r);
        return;
    }
    for (unsigned sample = 0; sample < c->rounds && !r.error && !stopped(c); sample++)
    {
        handoff_t *h = calloc(1, sizeof(*h));
        if (!h)
        {
            r.error = ENOMEM;
            break;
        }
        h->config = c;
        h->peer_cpu = peer;
        h->owner_pid = (uint64_t)getpid();
        r.error = pthread_mutex_init(&h->mutex, NULL);
        if (r.error) { free(h); break; }
        r.error = pthread_cond_init(&h->condition, NULL);
        if (r.error) { pthread_mutex_destroy(&h->mutex); free(h); break; }
        r.error = pthread_create(&h->thread, NULL, handoff_worker, h);
        if (r.error)
        {
            pthread_cond_destroy(&h->condition);
            pthread_mutex_destroy(&h->mutex);
            free(h);
            break;
        }
        pthread_mutex_lock(&h->mutex);
        while (!h->ready && !h->abort)
        {
            struct timespec d;
            clock_gettime(CLOCK_REALTIME, &d);
            d.tv_sec += 2;
            int e = pthread_cond_timedwait(&h->condition, &h->mutex, &d);
            if (e)
            {
                h->error = e;
                h->abort = true;
            }
        }
        perf_log("PERF_HANDOFF_IDS,%u,%llu,%llu\n", sample,
                 (unsigned long long)pthread_self(), (unsigned long long)h->thread);
        g_perf_handoff = h;
        perf_handoff_ready_checkpoint();
        struct rusage before = {0}, after = {0};
        getrusage(RUSAGE_SELF, &before);
        uint64_t start = perf_now_ns();
        unsigned completed = 0;
        uint64_t target = sample_target_ns(c, 1);
        while (!h->abort)
        {
            h->turn = 1;
            pthread_cond_signal(&h->condition);
            if (handoff_wait(h, 0))
                break;
            completed++;
            if (perf_now_ns() - start >= target) break;
            if (stopped(c))
            {
                h->abort = true;
                break;
            }
        }
        uint64_t elapsed = perf_now_ns() - start;
        getrusage(RUSAGE_SELF, &after);
        perf_handoff_sample_checkpoint();
        h->abort = true;
        pthread_cond_broadcast(&h->condition);
        pthread_mutex_unlock(&h->mutex);
        pthread_join(h->thread, NULL);
        g_perf_handoff = NULL;
        r.error = h->error;
        if (!r.error && completed)
        {
            costs[r.samples++] = elapsed / completed;
            r.operations += completed;
            r.elapsed_ns += elapsed;
            usage_delta(&r, &before, &after);
            perf_log("PERF_SAMPLE,%s,%u,%u,%llu\n", name, sample, completed,
                     (unsigned long long)elapsed);
        }
        pthread_cond_destroy(&h->condition);
        pthread_mutex_destroy(&h->mutex);
        free(h);
    }
    finish(&r, costs);
    free(costs);
    snprintf(r.detail, sizeof(r.detail), "condition round trip; CPUs %u/%u; target_ns=%llu",
             cpu, peer, (unsigned long long)sample_target_ns(c, 1));
    if (sys_thread_set_affinity(0) && !r.error) r.error = EIO;
    perf_record(c->state, &r);
}
int perf_run(perf_config_t *c)
{
    sys_thread_set_affinity(0);
    __atomic_store_n(&c->state->running, 1, __ATOMIC_RELEASE);
    perf_log("PERF_META,version,1\nPERF_META,mode,%s\nPERF_META,cpus,%u\nPERF_"
             "META,threads,%u\nPERF_META,rounds,%u\nPERF_META,duration_ms,%u\n",
             c->gui ? "gui" : "cli", c->cpus, c->threads, c->rounds, c->duration_ms);
    struct timespec resolution = {0};
    clock_getres(CLOCK_MONOTONIC, &resolution);
    perf_log("PERF_META,clock,monotonic_milliseconds\nPERF_META,clock_resolution_"
             "ns,%llu\nPERF_META,percentiles,batch_average_ns_per_operation\n",
             (unsigned long long)((uint64_t)resolution.tv_sec * 1000000000 + resolution.tv_nsec));
    perf_log("PERF_META,condition_protocol,timed_minimum_five_ticks_v2\n"
             "PERF_META,parallel_protocol,minimum_five_ticks_v2\n"
             "PERF_META,minimum_sample_ticks,5\n");
    perf_log("PERF_META,case,%s\n", c->case_name ? c->case_name : "all");
    perf_log("PERF_META,group,%s\n", c->group ? c->group : "all");
    perf_log("PERF_META,ui_present_batch,%u\n", c->present_batch);
    perf_log("PERF_META,ui_present,%s\n", c->present_mode == 1   ? "static"
                                          : c->present_mode == 2 ? "bottom"
                                                                 : "dashboard");
    perf_log("PERF_META,workdir,%s\nPERF_META,network,%s:%u\n", c->workdir,
             c->net_host ? c->net_host : "disabled", c->port);
    struct utsname *identity = calloc(1, sizeof(*identity));
    if (identity && !uname(identity))
        perf_log("PERF_META,kernel,%s %s %s\n", identity->sysname, identity->release,
                 identity->version);
    free(identity);
    for (size_t i = 0; i < sizeof(benches) / sizeof(benches[0]); i++)
    {
        /* fork from a multi-threaded GUI would benchmark a different lifecycle
         * and inherits unrelated UI state. Run this case in CLI mode. */
        if (c->gui && benches[i].op == FORK && selected(c, "process") &&
            selected_case(c, benches[i].name))
        {
            perf_result_t r = {.error = -1};
            snprintf(r.name, sizeof(r.name), "fork_exit_wait");
            snprintf(r.group, sizeof(r.group), "process");
            snprintf(r.detail, sizeof(r.detail),
                     "run with --cli to measure a single-threaded fork");
            perf_record(c->state, &r);
            continue;
        }
        run_bench(c, &benches[i]);
    }
    run_handoff(c, "condition_pingpong", 0, c->cpus > 1 ? 1 : 0, false);
    run_handoff(c, "condition_pingpong_2_3", 2, 3, true);
    run_parallel(c, "cpu_work_1", 0, 1, false);
    run_parallel(c, "cpu_work_n", 0, c->threads, false);
    run_parallel(c, "cpu_work_2n", 0, c->threads * 2, false);
    run_parallel(c, "atomic_contended_n", 1, c->threads, false);
    run_parallel(c, "mutex_contended_n", 2, c->threads, false);
    run_parallel(c, "malloc_contended_n", 3, c->threads, false);
    run_parallel(c, "yield_same_cpu_n", 4, c->threads, true);
    run_parallel(c, "yield_spread_n", 4, c->threads, false);
    run_parallel(c, "pread_parallel_n", 5, c->threads, false);
    pthread_mutex_lock(&c->state->lock);
    snprintf(c->state->current, sizeof(c->state->current), "%s",
             stopped(c) ? "Stopped" : "Complete");
    unsigned count = c->state->count, failed = c->state->failed, skipped = c->state->skipped;
    pthread_mutex_unlock(&c->state->lock);
    perf_log("PERF_DONE,results=%u,failed=%u,skipped=%u,stopped=%u\n", count, failed, skipped,
             stopped(c));
    __atomic_store_n(&c->state->running, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&c->state->done, 1, __ATOMIC_RELEASE);
    return failed ? 1 : 0;
}
static void help(void)
{
    perf_log("perf [--gui | --cli] [--autorun] [--exit-when-done] [--quick]\n"
             "     [--group "
             "memory|vm|syscall|threading|scheduling|process|ipc|filesystem|network]\n"
             "     [--ui-present dashboard|static|bottom] [--present-batch 1..128] [--case NAME] "
             "[--rounds 1..15] "
             "[--duration 10..1000] [--threads 1..32]\n"
             "     [--workdir /tmp] [--net IPv4 --port PORT] [--dns-host NAME]\n"
             "Default opens the GUI. --cli prints CSV records. Echo endpoint must "
             "support TCP and UDP.\n");
}
int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--child"))
        return 0;
    setvbuf(stdout, NULL, _IOLBF, 4096);
    perf_config_t *c = calloc(1, sizeof(*c));
    perf_state_t *s = calloc(1, sizeof(*s));
    if (!c || !s)
    {
        free(c);
        free(s);
        return 1;
    }
    /* GUI callbacks run on another CPU: option strings must not remain on
     * the main thread's initial argv stack. Keep a process-owned heap copy. */
    size_t option_bytes = 1;
    for (int i = 0; i < argc; ++i)
        option_bytes += strlen(argv[i]) + 1;
    char *option_text = malloc(option_bytes);
    char **option_arguments = calloc((argc > 0 ? (size_t)argc : 0) + 1, sizeof(char *));
    if (!option_text || !option_arguments)
    {
        free(option_text);
        free(option_arguments);
        free(c);
        free(s);
        return 1;
    }
    char *option_cursor = option_text;
    for (int i = 0; i < argc; ++i)
    {
        size_t bytes = strlen(argv[i]) + 1;
        memcpy(option_cursor, argv[i], bytes);
        option_arguments[i] = option_cursor;
        option_cursor += bytes;
    }
    argv = option_arguments;
    c->state = s;
    c->rounds = 5;
    c->duration_ms = 30;
    c->present_batch = 1;
    c->gui = true;
    c->workdir = "/tmp";
    pthread_mutex_init(&s->lock, NULL);
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    c->cpus = cpus > 0 ? (unsigned)cpus : 1;
    c->threads = c->cpus > 8 ? 8 : c->cpus;
    for (int i = 1; i < argc; i++)
    {
        const char *v = argv[i];
        if (!strcmp(v, "--help"))
        {
            help();
            free(option_text);
            free(option_arguments);
            free(c);
            free(s);
            return 0;
        }
        if (!strcmp(v, "--cli"))
            c->gui = false;
        else if (!strcmp(v, "--gui"))
            c->gui = true;
        else if (!strcmp(v, "--autorun"))
            c->autorun = true;
        else if (!strcmp(v, "--exit-when-done"))
            c->exit_when_done = true;
        else if (!strcmp(v, "--quick"))
        {
            c->rounds = 3;
            c->duration_ms = 10;
        }
        else if (i + 1 < argc)
        {
            const char *a = argv[++i];
            if (!strcmp(v, "--group"))
                c->group = a;
            else if (!strcmp(v, "--case"))
                c->case_name = a;
            else if (!strcmp(v, "--present-batch"))
                c->present_batch = (unsigned)atoi(a);
            else if (!strcmp(v, "--ui-present"))
            {
                if (!strcmp(a, "dashboard"))
                    c->present_mode = 0;
                else if (!strcmp(a, "static"))
                    c->present_mode = 1;
                else if (!strcmp(a, "bottom"))
                    c->present_mode = 2;
                else
                {
                    help();
                    return 2;
                }
            }
            else if (!strcmp(v, "--workdir"))
                c->workdir = a;
            else if (!strcmp(v, "--net"))
                c->net_host = a;
            else if (!strcmp(v, "--dns-host"))
                c->dns_host = a;
            else if (!strcmp(v, "--rounds"))
                c->rounds = (unsigned)atoi(a);
            else if (!strcmp(v, "--duration"))
                c->duration_ms = (unsigned)atoi(a);
            else if (!strcmp(v, "--threads"))
                c->threads = (unsigned)atoi(a);
            else if (!strcmp(v, "--port"))
                c->port = (unsigned)atoi(a);
            else
            {
                help();
                return 2;
            }
        }
        else
        {
            help();
            return 2;
        }
    }
    if (!c->rounds || c->rounds > PERF_MAX_ROUNDS || c->duration_ms < 10 || c->duration_ms > 1000 ||
        !c->threads || c->threads > 32 ||
        (!c->present_batch || c->present_batch > 128 ||
         (c->present_batch > 1 && !c->present_mode) || (!c->gui && c->present_mode)) ||
        c->port > 65535 || (!!c->port != !!c->net_host))
    {
        help();
        return 2;
    }
    if (c->group)
    {
        bool valid = false;
        for (size_t i = 0; i < sizeof(benches) / sizeof(benches[0]); i++)
            if (!strcmp(c->group, benches[i].group))
                valid = true;
        if (!valid)
        {
            help();
            return 2;
        }
    }
    if (alix_get_executable_path(c->executable, sizeof(c->executable)) < 0)
    {
        perf_log("perf: cannot resolve executable path\n");
        return 1;
    }
    if (c->case_name)
    {
        bool valid = false;
        for (size_t i = 0; i < sizeof(benches) / sizeof(benches[0]); i++)
            if (!strcmp(c->case_name, benches[i].name))
                valid = true;
        const char *extra[] = {"condition_pingpong", "condition_pingpong_2_3", "cpu_work_1",         "cpu_work_n",
                               "cpu_work_2n",        "atomic_contended_n", "mutex_contended_n",
                               "malloc_contended_n", "yield_same_cpu_n",   "yield_spread_n",
                               "pread_parallel_n"};
        for (size_t i = 0; i < sizeof(extra) / sizeof(extra[0]); i++)
            if (!strcmp(c->case_name, extra[i]))
                valid = true;
        if (!valid)
        {
            help();
            return 2;
        }
    }
    serial_log = c->gui;
    int result = c->gui ? perf_gui(c) : perf_run(c);
    pthread_mutex_destroy(&s->lock);
    free(option_text);
    free(option_arguments);
    free(s);
    free(c);
    return result;
}
