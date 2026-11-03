#ifndef ALIX_SYS_SOCKET_H
#define ALIX_SYS_SOCKET_H
#ifdef TTF_HOST_BUILD
#include_next <sys/socket.h>
#else
#include "sys/types.h"
#include "sys/uio.h"
#include "syscall_defs.h"
typedef uint32_t socklen_t;
typedef uint16_t sa_family_t;
#define AF_UNSPEC 0
#define AF_UNIX 1
#define AF_LOCAL AF_UNIX
#define AF_INET SYSCALL_AF_INET
#define AF_INET6 10
#define PF_UNSPEC AF_UNSPEC
#define PF_UNIX AF_UNIX
#define PF_LOCAL AF_LOCAL
#define PF_INET AF_INET
#define PF_INET6 AF_INET6
#define SOCK_STREAM SYSCALL_SOCK_STREAM
#define SOCK_DGRAM 2
#define SOCK_RAW 3
#define SOCK_SEQPACKET 5
#define SOCK_RDM 4
#define SOCK_CLOEXEC SYSCALL_OPEN_CLOEXEC
#define SOCK_NONBLOCK SYSCALL_OPEN_NONBLOCK
#define SOL_SOCKET SYSCALL_SOL_SOCKET
#define SO_DEBUG 1
#define SO_REUSEADDR SYSCALL_SO_REUSEADDR
#define SO_TYPE SYSCALL_SO_TYPE
#define SO_ERROR SYSCALL_SO_ERROR
#define SO_DONTROUTE 5
#define SO_BROADCAST 6
#define SO_SNDBUF SYSCALL_SO_SNDBUF
#define SO_RCVBUF SYSCALL_SO_RCVBUF
#define SO_KEEPALIVE SYSCALL_SO_KEEPALIVE
#define SO_OOBINLINE 10
#define SO_LINGER 13
#define SO_REUSEPORT 15
#define SO_RCVLOWAT 18
#define SO_SNDLOWAT 19
#define SO_RCVTIMEO 20
#define SO_SNDTIMEO 21
#define SO_ACCEPTCONN SYSCALL_SO_ACCEPTCONN
#define SO_PROTOCOL SYSCALL_SO_PROTOCOL
#define SO_DOMAIN SYSCALL_SO_DOMAIN
#define MSG_OOB 1
#define MSG_PEEK SYSCALL_MSG_PEEK
#define MSG_DONTROUTE 4
#define MSG_CTRUNC 8
#define MSG_TRUNC 0x20
#define MSG_DONTWAIT SYSCALL_MSG_DONTWAIT
#define MSG_EOR 0x80
#define MSG_WAITALL 0x100
#define MSG_NOSIGNAL SYSCALL_MSG_NOSIGNAL
#define MSG_CMSG_CLOEXEC (1u << 17)
#define SCM_RIGHTS 1
#define SHUT_RD 0
#define SHUT_WR 1
#define SHUT_RDWR 2
#define SOMAXCONN 128
struct sockaddr { sa_family_t sa_family; char sa_data[14]; };
struct sockaddr_storage { sa_family_t ss_family; unsigned char __padding[118]; uint64_t __align; };
struct msghdr {
    void *msg_name;
    socklen_t msg_namelen;
    struct iovec *msg_iov;
    size_t msg_iovlen;
    void *msg_control;
    size_t msg_controllen;
    int msg_flags;
};
struct cmsghdr { size_t cmsg_len; int cmsg_level; int cmsg_type; };
struct linger { int l_onoff; int l_linger; };
#define CMSG_ALIGN(length) (((size_t)(length) + sizeof(size_t) - 1) & ~(sizeof(size_t) - 1))
#define CMSG_LEN(length) (CMSG_ALIGN(sizeof(struct cmsghdr)) + (size_t)(length))
#define CMSG_SPACE(length) (CMSG_ALIGN(sizeof(struct cmsghdr)) + CMSG_ALIGN(length))
#define CMSG_DATA(header) ((unsigned char *)(header) + CMSG_ALIGN(sizeof(struct cmsghdr)))
#define CMSG_FIRSTHDR(message) ((message)->msg_controllen >= sizeof(struct cmsghdr) ? (struct cmsghdr *)(message)->msg_control : NULL)
static inline struct cmsghdr *CMSG_NXTHDR(const struct msghdr *message, const struct cmsghdr *header)
{
    uintptr_t base = (uintptr_t)message->msg_control, current = (uintptr_t)header;
    if (current < base || current - base > message->msg_controllen) return NULL;
    size_t remaining = message->msg_controllen - (current - base);
    if (remaining < sizeof(*header) || header->cmsg_len < sizeof(*header) || header->cmsg_len > remaining) return NULL;
    size_t step = CMSG_ALIGN(header->cmsg_len);
    if (step < header->cmsg_len || step > remaining || remaining - step < sizeof(*header) || current + step < current) return NULL;
    return (struct cmsghdr *)(current + step);
}
#ifdef __cplusplus
extern "C" {
#endif
int socket(int domain, int type, int protocol);
int socketpair(int domain, int type, int protocol, int descriptors[2]);
int connect(int descriptor, const struct sockaddr *address, socklen_t length);
int bind(int descriptor, const struct sockaddr *address, socklen_t length);
int listen(int descriptor, int backlog);
int accept(int descriptor, struct sockaddr *address, socklen_t *length);
int accept4(int descriptor, struct sockaddr *address, socklen_t *length, int flags);
int getsockname(int descriptor, struct sockaddr *address, socklen_t *length);
int getpeername(int descriptor, struct sockaddr *address, socklen_t *length);
int getsockopt(int descriptor, int level, int option, void *value, socklen_t *length);
int setsockopt(int descriptor, int level, int option, const void *value, socklen_t length);
int shutdown(int descriptor, int direction);
ssize_t send(int descriptor, const void *data, size_t length, int flags);
ssize_t recv(int descriptor, void *data, size_t length, int flags);
ssize_t sendto(int descriptor, const void *data, size_t length, int flags, const struct sockaddr *address, socklen_t address_length);
ssize_t recvfrom(int descriptor, void *data, size_t length, int flags, struct sockaddr *address, socklen_t *address_length);
ssize_t sendmsg(int descriptor, const struct msghdr *message, int flags);
ssize_t recvmsg(int descriptor, struct msghdr *message, int flags);
#ifdef __cplusplus
}
#endif
#endif
#endif
