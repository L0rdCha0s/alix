#include "alix_network.h"
#include "sys/socket.h"
#include "netinet/in.h"
#include "arpa/inet.h"
#include "sys/mman.h"
#include "sys/ioctl.h"
#include "sys/stat.h"
#include "sys/uio.h"
#include "fcntl.h"
#include "unistd.h"
#include "poll.h"
#include "stdlib.h"
#include "string.h"
#include "errno.h"
#include "spawn.h"
#include "signal.h"
#include "sys/wait.h"
#include "usyscall.h"

#define CHECK(c) do { if (!(c)) return __LINE__; } while (0)
_Static_assert(sizeof(alix_udp_packet_info_t) == 24, "native packet metadata ABI");
int alix_udp_socket_api_test(unsigned port)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
    CHECK(fd >= 0 && fcntl(fd, F_GETFD) == FD_CLOEXEC);
    struct sockaddr_in *address = calloc(2, sizeof(*address));
    unsigned char *buffer = calloc(2048, 1);
    CHECK(address && buffer);
    address[0].sin_family = AF_INET;
    CHECK(bind(fd, (void *)&address[0], sizeof(*address)) == 0);
    socklen_t length = sizeof(*address);
    CHECK(getsockname(fd, (void *)&address[0], &length) == 0 && length == 16 && address[0].sin_port != 0);
    CHECK(getpeername(fd, (void *)&address[1], &length) == -1 && errno == ENOTCONN);
    int type = 0; length = sizeof(type);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) == 0 && type == SOCK_DGRAM);
    int budget = 4096, tos = 2, ttl = 55;
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &budget, sizeof(budget)) == 0);
    CHECK(setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) == 0 &&
          setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) == 0);
    address[1].sin_family = AF_INET; address[1].sin_port = htons((uint16_t)port);
    CHECK(inet_pton(AF_INET, "10.0.2.2", &address[1].sin_addr) == 1);
    CHECK(sendto(fd, (void *)1, 1, 0, (void *)&address[1], 16) == -1 && errno == EFAULT);
    CHECK(sendto(fd, buffer, 1, 0, (void *)1, 16) == -1 && errno == EFAULT);
    CHECK(sendto(fd, buffer, 1473, 0, (void *)&address[1], 16) == -1 && errno == EMSGSIZE);
    CHECK(alix_udp_send(fd, buffer, 1, (void *)&address[1], 16, 2, 1) == -1 && errno == EADDRNOTAVAIL);
    memcpy(buffer, "primitive", 9);
    CHECK(sendto(fd, buffer, 9, 0, (void *)&address[1], 16) == 9);
    struct pollfd poller = { fd, POLLIN, 0 };
    CHECK(poll(&poller, 1, 3000) == 1 && (poller.revents & POLLIN));
    int available = -1;
    CHECK(ioctl(fd, FIONREAD, &available) == 0 && available == 9);
    unsigned char *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(page != MAP_FAILED);
    *(socklen_t *)page = 16;
    CHECK(mprotect(page, 4096, PROT_READ) == 0);
    CHECK(recvfrom(fd, buffer, 32, MSG_PEEK, (void *)&address[0], (void *)page) == -1 && errno == EFAULT);
    length = 1;
    CHECK(recvfrom(fd, buffer, 32, MSG_PEEK, (void *)&address[0], &length) == 9 && length == 16);
    length = 16;
    CHECK(recvfrom(fd, buffer, 4, 0, (void *)&address[0], &length) == 4 && !memcmp(buffer, "prim", 4) &&
          address[0].sin_port == address[1].sin_port && address[0].sin_addr.s_addr == address[1].sin_addr.s_addr);
    CHECK(recv(fd, buffer, 32, MSG_DONTWAIT) == -1 && errno == EAGAIN);
    CHECK(sendto(fd, NULL, 0, 0, (void *)&address[1], 16) == 0);
    poller.revents = 0; CHECK(poll(&poller, 1, 3000) == 1 && (poller.revents & POLLIN));
    CHECK(ioctl(fd, FIONREAD, &available) == 0 && available == 0);
    length = 16; CHECK(recvfrom(fd, NULL, 0, 0, (void *)&address[0], &length) == 0 && length == 16);
    CHECK(connect(fd, (void *)&address[1], 16) == 0);
    int alias = fcntl(fd, F_DUPFD_CLOEXEC, 0); CHECK(alias >= 0 && close(fd) == 0);
    fd = alias;
    struct iovec vectors[3] = {{(void *)"v", 1}, {NULL, 0}, {(void *)"ec", 2}};
    struct msghdr message = { .msg_iov = vectors, .msg_iovlen = 3 };
    CHECK(sendmsg(fd, &message, MSG_NOSIGNAL) == 3);
    vectors[0] = (struct iovec){buffer, 1}; vectors[2] = (struct iovec){buffer + 1, 2};
    CHECK(recvmsg(fd, &message, 0) == 3 && !message.msg_flags && !memcmp(buffer, "vec", 3));
    CHECK(send(fd, "oversize-reply", 14, 0) == 14);
    CHECK(recv(fd, buffer, 4, MSG_TRUNC) == 14 && !memcmp(buffer, "over", 4));
    struct stat status; CHECK(fstat(fd, &status) == 0 && S_ISSOCK(status.st_mode));
    CHECK(munmap(page, 4096) == 0 && close(fd) == 0);
    free(buffer); free(address);
    return 0;
}

int alix_udp_cancel_child(void)
{
    unsigned char *data = calloc(32, 1);
    if (!data || write(21, "R", 1) != 1) return 19;
    (void)recv(20, data, 32, 0);
    return 20; /* No datagram is sent to this socket; the parent must kill it. */
}

int alix_udp_cancel_test(unsigned host_port)
{
    struct cancellation {
        posix_spawn_file_actions_t actions;
        struct sockaddr_in local, remote;
        pid_t child;
        int status, pipe[2];
        char ready, reply[8];
        char *arguments[3];
    } *test = calloc(1, sizeof(*test));
    CHECK(test);
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    test->local.sin_family = AF_INET;
    CHECK(fd >= 0 && bind(fd, (void *)&test->local, 16) == 0);
    socklen_t length = 16;
    CHECK(getsockname(fd, (void *)&test->local, &length) == 0 && pipe2(test->pipe, O_CLOEXEC) == 0);
    CHECK(posix_spawn_file_actions_init(&test->actions) == 0 &&
          posix_spawn_file_actions_adddup2(&test->actions, fd, 20) == 0 &&
          posix_spawn_file_actions_adddup2(&test->actions, test->pipe[1], 21) == 0);
    test->arguments[0] = "/tmp/test.elf"; test->arguments[1] = "udp-cancel-child";
    CHECK(posix_spawn(&test->child, test->arguments[0], &test->actions, NULL, test->arguments, NULL) == 0);
    CHECK(posix_spawn_file_actions_destroy(&test->actions) == 0 && close(test->pipe[1]) == 0 && close(fd) == 0);
    CHECK(read(test->pipe[0], &test->ready, 1) == 1 && test->ready == 'R');
    CHECK(close(test->pipe[0]) == 0);
    sys_sleep_ms(100);
    CHECK(kill(test->child, 0) == 0);
    /* Another UDP receive must progress while the child's receive is pending. */
    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    test->remote.sin_family = AF_INET; test->remote.sin_port = htons((uint16_t)host_port);
    CHECK(fd >= 0 && inet_pton(AF_INET, "10.0.2.2", &test->remote.sin_addr) == 1);
    CHECK(sendto(fd, "alive", 5, 0, (void *)&test->remote, 16) == 5 && recv(fd, test->reply, 8, 0) == 5 &&
          !memcmp(test->reply, "alive", 5) && close(fd) == 0);
    CHECK(kill(test->child, SIGKILL) == 0 && waitpid(test->child, &test->status, 0) == test->child &&
          WIFSIGNALED(test->status) && WTERMSIG(test->status) == SIGKILL);
    uint64_t deadline = sys_monotonic_millis() + 3000;
    for (;;)
    {
        fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
        int result = bind(fd, (void *)&test->local, 16);
        CHECK(close(fd) == 0);
        if (result == 0) break;
        CHECK(errno == EADDRINUSE && sys_monotonic_millis() < deadline);
        sys_sleep_ms(1);
    }
    free(test);
    return 0;
}
