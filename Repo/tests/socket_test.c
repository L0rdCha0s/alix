#include "sys/socket.h"
#include "arpa/inet.h"
#include "pthread.h"
#include "poll.h"
#include "fcntl.h"
#include "unistd.h"
#include "usyscall.h"
#include "stdlib.h"
#include "string.h"
#include "errno.h"
#include "serial.h"
#include "netinet/tcp.h"
#include "sys/stat.h"
#include "sys/ioctl.h"
#define CHECK(c) do { if (!(c)) { job->failed = __LINE__; job->error = errno; goto finished; } } while (0)
typedef struct {
    unsigned index, failed; int error, descriptor, alias;
    pthread_t thread; struct sockaddr_in address; struct pollfd entry;
    struct sockaddr_in local, peer;
    socklen_t length;
    int option, available_before, available_after;
    struct stat metadata;
    unsigned char bytes[16384], first[32], second[32];
} job_t;
static int query_contract(job_t *job, bool connected)
{
    job->length = 0;
    CHECK(!getsockname(job->descriptor, NULL, &job->length) && job->length == sizeof(job->local));
    memset(&job->local, 0x5a, sizeof(job->local)); job->length = sizeof(sa_family_t);
    CHECK(!getsockname(job->descriptor, (struct sockaddr *)&job->local, &job->length) &&
          job->local.sin_family == AF_INET && job->length == sizeof(job->local) && ((unsigned char *)&job->local)[2] == 0x5a);
    job->length = sizeof(job->local);
    CHECK(!getsockname(job->descriptor, (struct sockaddr *)&job->local, &job->length) && job->length == sizeof(job->local));
    job->length = sizeof(job->peer);
    int peer = getpeername(job->alias, (struct sockaddr *)&job->peer, &job->length);
    if (connected)
    {
        CHECK(!peer && !memcmp(&job->peer, &job->address, sizeof(job->peer)) &&
              job->local.sin_family == AF_INET && ntohl(job->local.sin_addr.s_addr) == 0x0a00020f && job->local.sin_port);
    }
    else CHECK(peer == -1 && errno == ENOTCONN && !job->local.sin_addr.s_addr && !job->local.sin_port);
    CHECK(!fstat(job->descriptor, &job->metadata) && S_ISSOCK(job->metadata.st_mode));
    job->option = 0x5a5a5a5a; job->length = 1;
    CHECK(!getsockopt(job->alias, SOL_SOCKET, SO_TYPE, &job->option, &job->length) && job->length == 1 &&
          ((unsigned char *)&job->option)[0] == SOCK_STREAM && ((unsigned char *)&job->option)[1] == 0x5a);
    job->length = sizeof(job->option);
    CHECK(!getsockopt(job->descriptor, SOL_SOCKET, SO_DOMAIN, &job->option, &job->length) && job->option == AF_INET);
    CHECK(!getsockopt(job->descriptor, SOL_SOCKET, SO_PROTOCOL, &job->option, &job->length) && job->option == IPPROTO_TCP);
    CHECK(!getsockopt(job->descriptor, SOL_SOCKET, SO_ERROR, &job->option, &job->length) && !job->option);
    CHECK(!getsockopt(job->descriptor, SOL_SOCKET, SO_RCVBUF, &job->option, &job->length) && job->option > 0);
    CHECK(!getsockopt(job->descriptor, SOL_SOCKET, SO_SNDBUF, &job->option, &job->length) && job->option == 1460);
    CHECK(!getsockopt(job->descriptor, IPPROTO_TCP, TCP_MAXSEG, &job->option, &job->length) && job->option > 0 && job->option <= 1460);
    job->option = 1;
    CHECK(!setsockopt(job->alias, IPPROTO_TCP, TCP_NODELAY, &job->option, sizeof(job->option)));
    job->option = 0;
    CHECK(setsockopt(job->descriptor, IPPROTO_TCP, TCP_NODELAY, &job->option, sizeof(job->option)) == -1 && errno == EOPNOTSUPP);
    CHECK(!getsockopt(job->descriptor, IPPROTO_TCP, TCP_NODELAY, &job->option, &job->length) && job->option == 1);
    job->option = 0;
    CHECK(!setsockopt(job->descriptor, SOL_SOCKET, SO_KEEPALIVE, &job->option, sizeof(job->option)));
    job->option = 1;
    CHECK(setsockopt(job->descriptor, SOL_SOCKET, SO_KEEPALIVE, &job->option, sizeof(job->option)) == -1 && errno == EOPNOTSUPP);
    CHECK(!getsockopt(job->descriptor, SOL_SOCKET, SO_KEEPALIVE, &job->option, &job->length) && !job->option);
    job->option = 77;
    CHECK(getsockopt(job->descriptor, SOL_SOCKET, 0x7fffffff, &job->option, &job->length) == -1 &&
          errno == ENOPROTOOPT && job->option == 77 && job->length == sizeof(job->option));
    CHECK(getsockopt(job->descriptor, SOL_SOCKET, SO_TYPE, &job->option, NULL) == -1 && errno == EFAULT);
finished:
    return job->failed ? 1 : 0;
}
static void *worker(void *context)
{
    job_t *job = context;
    int flags = job->index & 1 ? SOCK_NONBLOCK : 0;
    CHECK(!sys_thread_set_affinity(job->index) && sys_thread_cpu() == job->index);
    job->descriptor = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | flags, IPPROTO_TCP);
    CHECK(job->descriptor >= 0 && fcntl(job->descriptor, F_GETFD) == FD_CLOEXEC &&
          fcntl(job->descriptor, F_GETFL) == (int)(O_RDWR | (flags ? O_NONBLOCK : 0)));
    job->alias = dup(job->descriptor);
    CHECK(job->alias >= 0 && fcntl(job->alias, F_GETFD) == 0);
    job->option=flags?0:1;CHECK(!ioctl(job->alias,FIONBIO,&job->option));
    CHECK(fcntl(job->descriptor,F_GETFL)==(int)(O_RDWR|(flags?0:O_NONBLOCK)));
    job->option=flags?1:0;CHECK(!ioctl(job->descriptor,FIONBIO,&job->option));
    CHECK(fcntl(job->alias,F_GETFL)==(int)(O_RDWR|(flags?O_NONBLOCK:0)));
    if (query_contract(job, false)) goto finished;
    CHECK(connect(job->descriptor, NULL, sizeof(job->address)) == -1 && errno == EFAULT);
    CHECK(connect(job->descriptor, (const struct sockaddr *)&job->address, 1) == -1 && errno == EINVAL);
    int connected = connect(job->descriptor, (const struct sockaddr *)&job->address, sizeof(job->address));
    CHECK(flags ? connected == -1 && errno == EINPROGRESS : connected == 0);
    job->entry = (struct pollfd){ .fd = job->descriptor, .events = POLLOUT };
    CHECK(poll(&job->entry, 1, 5000) == 1 && job->entry.revents == POLLOUT);
    if (query_contract(job, true)) goto finished;
    CHECK(recv(job->descriptor, job->bytes, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN &&
          fcntl(job->alias, F_GETFL) == (int)(O_RDWR | (flags ? O_NONBLOCK : 0)));
    CHECK(recv(job->descriptor, job->bytes, 1, MSG_OOB) == -1 && errno == EOPNOTSUPP);
    CHECK(send(job->descriptor, NULL, 1, MSG_NOSIGNAL) == -1 && errno == EFAULT);
    CHECK(send(job->descriptor, "G", 1, MSG_DONTWAIT | MSG_NOSIGNAL) == 1);
    job->entry.events = POLLIN;
    CHECK(poll(&job->entry, 1, 5000) == 1 && (job->entry.revents & POLLIN));
    CHECK(!ioctl(job->descriptor,FIONREAD,&job->available_before) && job->available_before>=32 && job->available_before<=16384);
    CHECK(ioctl(job->descriptor,FIONREAD,(void *)"readonly")==-1 && errno==EFAULT);
    CHECK(recv(job->descriptor, (void *)"readonly", 8, MSG_PEEK | MSG_DONTWAIT) == -1 && errno == EFAULT);
    CHECK(recv(job->descriptor, job->first, sizeof(job->first), MSG_PEEK | MSG_DONTWAIT) == sizeof(job->first));
    CHECK(recv(job->alias, job->second, sizeof(job->second), MSG_PEEK | MSG_DONTWAIT) == sizeof(job->second) &&
          !memcmp(job->first, job->second, sizeof(job->first)));
    CHECK(!ioctl(job->alias,FIONREAD,&job->available_after) && job->available_after>=job->available_before && job->available_after<=16384);
    CHECK(recv(job->alias, job->bytes, sizeof(job->first), MSG_DONTWAIT) == sizeof(job->first) &&
          !memcmp(job->first, job->bytes, sizeof(job->first)));
    size_t total = sizeof(job->first);
    while (total < sizeof(job->bytes))
    {
        CHECK(poll(&job->entry, 1, 5000) == 1 && (job->entry.revents & POLLIN));
        ssize_t count = recv(job->descriptor, job->bytes + total, sizeof(job->bytes) - total, MSG_DONTWAIT);
        CHECK(count > 0 && (size_t)count <= sizeof(job->bytes) - total);
        total += (size_t)count;
    }
    for (size_t index = 0; index < total; ++index) CHECK(job->bytes[index] == index % 251);
    CHECK(poll(&job->entry, 1, 5000) == 1 && (job->entry.revents & POLLHUP));
    CHECK(recv(job->descriptor, job->first, 1, MSG_PEEK | MSG_DONTWAIT) == 0 &&
          recv(job->alias, job->first, 1, MSG_DONTWAIT) == 0);
    CHECK(!ioctl(job->descriptor,FIONREAD,&job->available_after) && !job->available_after);
finished:
    if (job->alias >= 0) close(job->alias);
    if (job->descriptor >= 0) close(job->descriptor);
    return NULL;
}

typedef struct {
    pthread_t thread;
    int descriptor, result, value, error;
    unsigned cpu, failed;
    unsigned *ready, *start;
    socklen_t length;
} error_job_t;
typedef struct {
    struct sockaddr_in address;
    struct pollfd entry;
    error_job_t jobs[8];
    unsigned ready, start;
    int value, pipes[2];
    socklen_t length;
} error_fixture_t;
static void *error_reader(void *context)
{
    error_job_t *job = context;
    if (sys_thread_set_affinity(job->cpu) || sys_thread_cpu() != job->cpu) job->failed = 1;
    __atomic_add_fetch(job->ready, 1u, __ATOMIC_SEQ_CST);
    while (!__atomic_load_n(job->start, __ATOMIC_SEQ_CST)) sys_sleep_ms(1);
    job->length = sizeof(job->value);
    job->result = getsockopt(job->descriptor, SOL_SOCKET, SO_ERROR, &job->value, &job->length);
    job->error = errno;
    return NULL;
}
#define REQUIRE(c) do { if (!(c)) { serial_printf("SOCKET_QUERY_TEST: FAIL line=%u errno=%d\n", __LINE__, errno); return 1; } } while (0)
static int error_contract(uint16_t refused_port)
{
    error_fixture_t *test = calloc(1, sizeof(*test)); REQUIRE(test);
    test->address.sin_family = AF_INET; test->address.sin_port = htons(refused_port);
    REQUIRE(inet_pton(AF_INET, "10.0.2.2", &test->address.sin_addr) == 1);
    int blocking = socket(AF_INET, SOCK_STREAM, 0); REQUIRE(blocking >= 0);
    REQUIRE(connect(blocking, (const struct sockaddr *)&test->address, sizeof(test->address)) == -1 && errno == ECONNREFUSED);
    REQUIRE(!close(blocking));
    int descriptor = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    REQUIRE(descriptor >= 0 && connect(descriptor, (const struct sockaddr *)&test->address, sizeof(test->address)) == -1 && errno == EINPROGRESS);
    test->entry = (struct pollfd){ .fd = descriptor, .events = POLLOUT };
    REQUIRE(poll(&test->entry, 1, 5000) == 1 && (test->entry.revents & POLLERR));
    REQUIRE(!ioctl(descriptor,FIONREAD,&test->value) && !test->value);
    test->length = sizeof(test->value);
    REQUIRE(getsockopt(descriptor, SOL_SOCKET, SO_ERROR, (void *)"readonly", &test->length) == -1 && errno == EFAULT);
    REQUIRE(getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &test->value, (socklen_t *)"readonly") == -1 && errno == EFAULT);
    int alias = dup(descriptor); REQUIRE(alias >= 0);
    for (unsigned index = 0; index < 8; ++index)
    {
        error_job_t *job = &test->jobs[index];
        job->cpu = index; job->descriptor = index & 1 ? alias : descriptor;
        job->ready = &test->ready; job->start = &test->start;
        REQUIRE(!pthread_create(&job->thread, NULL, error_reader, job));
    }
    while (__atomic_load_n(&test->ready, __ATOMIC_SEQ_CST) != 8) sys_sleep_ms(1);
    __atomic_store_n(&test->start, 1u, __ATOMIC_SEQ_CST);
    unsigned errors = 0;
    for (unsigned index = 0; index < 8; ++index)
    {
        error_job_t *job = &test->jobs[index]; REQUIRE(!pthread_join(job->thread, NULL));
        REQUIRE(!job->failed && !job->result && job->length == sizeof(job->value));
        REQUIRE(!job->value || job->value == ECONNREFUSED);
        if (job->value) ++errors;
    }
    REQUIRE(errors == 1 && !getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &test->value, &test->length) && !test->value);
    REQUIRE(!close(alias) && !close(descriptor) && !pipe(test->pipes));
    REQUIRE(getsockopt(test->pipes[0], SOL_SOCKET, SO_TYPE, &test->value, &test->length) == -1 && errno == ENOTSOCK);
    REQUIRE(!close(test->pipes[0]) && !close(test->pipes[1]));
    free(test);
    serial_printf("SOCKET_QUERY_TEST: PASS endpoints=1 options=1 failed_copy=1 error_once=1 cpus=8\n");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 3) return 1;
    job_t *jobs = calloc(8, sizeof(*jobs)); if (!jobs) return 1;
    if (socket(AF_INET6, SOCK_STREAM, 0) != -1 || errno != EAFNOSUPPORT ||
        socket(AF_INET, SOCK_STREAM, IPPROTO_UDP) != -1 || errno != EPROTONOSUPPORT ||
        socket(AF_INET, SOCK_STREAM | 0x40000000, 0) != -1 || errno != EINVAL) return 1;
    for (unsigned index = 0; index < 8; ++index)
    {
        job_t *job = &jobs[index]; job->index = index; job->descriptor = job->alias = -1;
        job->address.sin_family = AF_INET; job->address.sin_port = htons((uint16_t)atoi(argv[1]));
        if (inet_pton(AF_INET, "10.0.2.2", &job->address.sin_addr) != 1 ||
            !inet_ntop(AF_INET, &job->address.sin_addr, (char *)job->first, sizeof(job->first)) ||
            strcmp((char *)job->first, "10.0.2.2") || pthread_create(&job->thread, NULL, worker, job)) return 1;
    }
    unsigned failures = 0;
    for (unsigned index = 0; index < 8; ++index)
    {
        if (pthread_join(jobs[index].thread, NULL)) ++failures;
        if (jobs[index].failed) { ++failures; serial_printf("SOCKET_TEST: FAIL cpu=%u line=%u errno=%d\n", index, jobs[index].failed, jobs[index].error); }
    }
    if (!failures)
        for (unsigned index = 0; index < 8; ++index)
            serial_printf("SOCKET_QUERY_ENDPOINT: cpu=%u local=10.0.2.15:%u peer=10.0.2.2:%u\n", index,
                          (unsigned)ntohs(jobs[index].local.sin_port), (unsigned)ntohs(jobs[index].peer.sin_port));
    free(jobs);
    if (failures || error_contract((uint16_t)atoi(argv[2]))) return 1;
    serial_printf("SOCKET_TEST: PASS cpus=8 bytes=131072 blocking=1 nonblock=1 per_call=1 peek=1 aliases=1 eof=1 copy_checks=1\n");
    serial_printf("SOCKET_IOCTL_TEST: PASS cpus=8 nonblock=1 readable=1 peek_preserved=1 error_preserved=1 eof=1\n");
    return 0;
}
