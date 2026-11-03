#include "sys/socket.h"
#include "sys/un.h"
#include "netinet/in.h"
#include "poll.h"
#include "fcntl.h"
#include "errno.h"
#include "stddef.h"
#include "stdalign.h"
#include "stdlib.h"
#include "string.h"
#include "limits.h"
#include "sys/uio.h"

int alix_socket2_layout(const size_t *values, size_t count)
{
    const size_t expected[] = { sizeof(struct sockaddr_storage), sizeof(struct sockaddr_in6),
        sizeof(struct in6_addr), alignof(struct in6_addr), sizeof(struct sockaddr_un),
        sizeof(struct ipv6_mreq), sizeof(struct ip_mreqn), sizeof(struct msghdr),
        offsetof(struct msghdr, msg_iovlen), sizeof(struct pollfd), offsetof(struct pollfd, revents) };
    if (count != sizeof(expected) / sizeof(expected[0])) return 0;
    for (size_t i = 0; i < count; ++i) if (values[i] != expected[i]) return 0;
    return 1;
}
int alix_socket2_flags(int fd)
{
    int status = fcntl(fd, F_GETFL), descriptor = fcntl(fd, F_GETFD);
    if (status < 0 || descriptor < 0) return -errno;
    return ((descriptor & FD_CLOEXEC) ? 1 : 0) | ((status & O_NONBLOCK) ? 2 : 0);
}
int alix_socket2_send_flags(void) { return MSG_NOSIGNAL; }

#define CHECK(c) do { if (!(c)) return __LINE__; } while (0)
int alix_socket2_message_faults(int fd)
{
    struct msghdr *message = calloc(1, sizeof(*message));
    struct iovec *vectors = calloc(3, sizeof(*vectors));
    CHECK(message && vectors);
    CHECK(sendmsg(fd, NULL, MSG_NOSIGNAL) == -1 && errno == EFAULT);
    message->msg_iov = vectors; message->msg_iovlen = 1025;
    CHECK(sendmsg(fd, message, MSG_NOSIGNAL) == -1 && errno == EINVAL);
    message->msg_iovlen = 2;
    vectors[0] = (struct iovec){ .iov_base = (void *)"X", .iov_len = 1 };
    vectors[1] = (struct iovec){ .iov_base = (void *)1, .iov_len = 1 };
    CHECK(sendmsg(fd, message, MSG_NOSIGNAL) == -1 && errno == EFAULT);
    vectors[0].iov_len = INT64_MAX;
    CHECK(sendmsg(fd, message, MSG_NOSIGNAL) == -1 && errno == EINVAL);
    message->msg_iov = (void *)1;
    CHECK(sendmsg(fd, message, MSG_NOSIGNAL) == -1 && errno == EFAULT);
    message->msg_iov = vectors; message->msg_iovlen = 0;
    message->msg_name = (void *)1; message->msg_namelen = 16;
    CHECK(sendmsg(fd, message, MSG_NOSIGNAL) == -1 && errno == EOPNOTSUPP);
    message->msg_name = NULL; message->msg_namelen = 0;
    message->msg_control = (void *)1; message->msg_controllen = 1;
    CHECK(sendmsg(fd, message, MSG_NOSIGNAL) == -1 && errno == EOPNOTSUPP);
    message->msg_control = NULL; message->msg_controllen = 0;
    CHECK(sendmsg(fd, message, MSG_PEEK) == -1 && errno == EOPNOTSUPP);
    CHECK(sendmsg(fd, message, MSG_NOSIGNAL) == 0);
    vectors[0].iov_len = 1; message->msg_iovlen = 1; message->msg_flags = 1234;
    CHECK(recvmsg(fd, message, MSG_DONTWAIT) == -1 && errno == EAGAIN && message->msg_flags == 1234);
    CHECK(!(fcntl(fd, F_GETFL) & O_NONBLOCK));
    free(vectors); free(message);
    return 0;
}
