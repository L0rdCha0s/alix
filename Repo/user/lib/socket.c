#include "sys/socket.h"
#include "netinet/in.h"
#include "usyscall.h"
#include "errno.h"
#include "alix_network.h"
#include "net/if.h"
#include "stdlib.h"
#include "string.h"
#include <stddef.h>

_Static_assert(sizeof(struct sockaddr_in) == sizeof(syscall_sockaddr_in_t), "native IPv4 address ABI");

static syscall_net_stats_t *interface_snapshot(size_t *count)
{
    const size_t capacity = 8;
    syscall_net_stats_t *snapshot = calloc(capacity, sizeof(*snapshot));
    if (!snapshot) { errno = ENOMEM; return NULL; }
    ssize_t result = sys_net_snapshot(snapshot, capacity);
    if (result < 0 || (size_t)result > capacity)
    { free(snapshot); errno = EIO; return NULL; }
    *count = (size_t)result;
    return snapshot;
}

unsigned int if_nametoindex(const char *name)
{
    if (!name) { errno = EINVAL; return 0; }
    if (!*name || strnlen(name, SYSCALL_NET_IF_NAME_MAX) == SYSCALL_NET_IF_NAME_MAX)
    { errno = ENXIO; return 0; }
    int saved = errno;
    size_t count = 0;
    syscall_net_stats_t *snapshot = interface_snapshot(&count);
    if (!snapshot) return 0;
    unsigned int result = 0;
    for (size_t index = 0; index < count; ++index)
        if (snapshot[index].present && !strcmp(name, snapshot[index].name))
        { result = (unsigned int)index + 1; break; }
    free(snapshot);
    errno = result ? saved : ENXIO;
    return result;
}

char *if_indextoname(unsigned int index, char *name)
{
    if (!name) { errno = EFAULT; return NULL; }
    if (!index) { errno = ENXIO; return NULL; }
    int saved = errno;
    size_t count = 0;
    syscall_net_stats_t *snapshot = interface_snapshot(&count);
    if (!snapshot) return NULL;
    bool found = index <= count && snapshot[index - 1].present;
    if (found)
    {
        memcpy(name, snapshot[index - 1].name, SYSCALL_NET_IF_NAME_MAX);
        name[SYSCALL_NET_IF_NAME_MAX - 1] = 0;
    }
    free(snapshot);
    errno = found ? saved : ENXIO;
    return found ? name : NULL;
}
_Static_assert(sizeof(struct msghdr) == sizeof(syscall_msghdr_t) &&
               offsetof(struct msghdr, msg_iov) == offsetof(syscall_msghdr_t, vectors) &&
               offsetof(struct msghdr, msg_flags) == offsetof(syscall_msghdr_t, flags), "native message ABI");
_Static_assert(offsetof(struct sockaddr_in, sin_port) == offsetof(syscall_sockaddr_in_t, port_be) &&
               offsetof(struct sockaddr_in, sin_addr) == offsetof(syscall_sockaddr_in_t, address_be), "native address offsets");
static int64_t socket_call(uint32_t operation, uint64_t first, uint64_t second, uint64_t third, uint64_t fourth)
{
#ifndef ALIX_OWNED_FDS
    (void)operation; (void)first; (void)second; (void)third; (void)fourth;
    errno = ENOTSUP; return -1;
#else
    int64_t result = sys_file_io(operation, first, second, third, fourth);
    if (result < 0) { errno = (int)-result; return -1; }
    return result;
#endif
}
int socket(int domain, int type, int protocol)
{
    return (int)socket_call(SYSCALL_FILE_NET_OPEN, (uint64_t)(int64_t)domain, (uint64_t)(int64_t)type, (uint64_t)(int64_t)protocol, 0);
}
int connect(int descriptor, const struct sockaddr *address, socklen_t length)
{
    return (int)socket_call(SYSCALL_FILE_NET_CONNECT, (uint64_t)(int64_t)descriptor, (uintptr_t)address, length, 0);
}
int getsockname(int descriptor, struct sockaddr *address, socklen_t *length)
{
    return (int)socket_call(SYSCALL_FILE_NET_GETNAME, (uint64_t)(int64_t)descriptor, (uintptr_t)address, (uintptr_t)length, 0);
}
int getpeername(int descriptor, struct sockaddr *address, socklen_t *length)
{
    return (int)socket_call(SYSCALL_FILE_NET_GETNAME, (uint64_t)(int64_t)descriptor, (uintptr_t)address, (uintptr_t)length, 1);
}
int getsockopt(int descriptor, int level, int option, void *value, socklen_t *length)
{
    uint64_t selector = ((uint64_t)(uint32_t)level << 32) | (uint32_t)option;
    return (int)socket_call(SYSCALL_FILE_NET_GETOPT, (uint64_t)(int64_t)descriptor, (uintptr_t)value, (uintptr_t)length, selector);
}
int setsockopt(int descriptor, int level, int option, const void *value, socklen_t length)
{
    uint64_t selector = ((uint64_t)(uint32_t)level << 32) | (uint32_t)option;
    return (int)socket_call(SYSCALL_FILE_NET_SETOPT, (uint64_t)(int64_t)descriptor, (uintptr_t)value, length, selector);
}
ssize_t send(int descriptor, const void *data, size_t length, int flags)
{
    return (ssize_t)socket_call(SYSCALL_FILE_NET_SEND, (uint64_t)(int64_t)descriptor, (uintptr_t)data, length, (uint64_t)(int64_t)flags);
}
ssize_t recv(int descriptor, void *data, size_t length, int flags)
{
    return (ssize_t)socket_call(SYSCALL_FILE_NET_RECV, (uint64_t)(int64_t)descriptor, (uintptr_t)data, length, (uint64_t)(int64_t)flags);
}
ssize_t sendmsg(int descriptor, const struct msghdr *message, int flags)
{
    return (ssize_t)socket_call(SYSCALL_FILE_NET_SENDMSG, (uint64_t)(int64_t)descriptor,
                              (uintptr_t)message, (uint64_t)(int64_t)flags, 0);
}
ssize_t recvmsg(int descriptor, struct msghdr *message, int flags)
{
    return (ssize_t)socket_call(SYSCALL_FILE_NET_RECVMSG, (uint64_t)(int64_t)descriptor,
                              (uintptr_t)message, (uint64_t)(int64_t)flags, 0);
}

/* These transport operations have public declarations but no kernel backend
 * yet. Validate the owned socket without consuming SO_ERROR or data, and let
 * callers detect the unsupported capability through the standard error path. */
static int socket_operation_unavailable(int descriptor)
{
    int type=0;socklen_t length=sizeof(type);
    if(getsockopt(descriptor,SOL_SOCKET,SO_TYPE,&type,&length))return -1;
    errno=EOPNOTSUPP;return -1;
}
int bind(int descriptor,const struct sockaddr *address,socklen_t length)
{ return (int)socket_call(SYSCALL_FILE_NET_BIND, (uint64_t)(int64_t)descriptor, (uintptr_t)address, length, 0); }
int listen(int descriptor,int backlog)
{ (void)backlog;return socket_operation_unavailable(descriptor); }
int accept4(int descriptor,struct sockaddr *address,socklen_t *length,int flags)
{
    (void)address;(void)length;
    if(flags & ~(SOCK_CLOEXEC|SOCK_NONBLOCK)){errno=EINVAL;return -1;}
    return socket_operation_unavailable(descriptor);
}
int accept(int descriptor,struct sockaddr *address,socklen_t *length)
{ return accept4(descriptor,address,length,0); }
int shutdown(int descriptor,int direction)
{
    if(direction!=SHUT_RD && direction!=SHUT_WR && direction!=SHUT_RDWR){errno=EINVAL;return -1;}
    return socket_operation_unavailable(descriptor);
}
int socketpair(int domain,int type,int protocol,int descriptors[2])
{
    (void)descriptors;
    if(domain!=AF_UNIX){errno=EAFNOSUPPORT;return -1;}
    if(protocol){errno=EPROTONOSUPPORT;return -1;}
    if((type & ~(SOCK_CLOEXEC|SOCK_NONBLOCK))!=SOCK_STREAM){errno=EPROTONOSUPPORT;return -1;}
    errno=EOPNOTSUPP;return -1;
}
ssize_t sendto(int descriptor,const void *data,size_t length,int flags,
               const struct sockaddr *address,socklen_t address_length)
{
    if(!address && !address_length)return send(descriptor,data,length,flags);
    syscall_udp_request_t request = { .data = (uintptr_t)data, .length = length,
        .address = (uintptr_t)address, .address_length = address_length, .flags = (uint32_t)flags, .tos = -1 };
    return (ssize_t)socket_call(SYSCALL_FILE_DATAGRAM, (uint64_t)(int64_t)descriptor, 0, (uintptr_t)&request, 0);
}
ssize_t recvfrom(int descriptor,void *data,size_t length,int flags,
                 struct sockaddr *address,socklen_t *address_length)
{
    if(!address)return recv(descriptor,data,length,flags);
    syscall_udp_request_t request = { .data = (uintptr_t)data, .length = length,
        .address = (uintptr_t)address, .address_length_pointer = (uintptr_t)address_length,
        .flags = (uint32_t)flags, .tos = -1 };
    return (ssize_t)socket_call(SYSCALL_FILE_DATAGRAM, (uint64_t)(int64_t)descriptor, 1, (uintptr_t)&request, 0);
}
ssize_t alix_udp_send(int fd, const void *data, size_t length, const struct sockaddr *destination,
                      uint32_t destination_length, int tos, uint32_t source_ipv4)
{
    syscall_udp_request_t request = { .data = (uintptr_t)data, .length = length,
        .address = (uintptr_t)destination, .address_length = destination_length,
        .tos = tos, .source_ipv4 = source_ipv4 };
    return (ssize_t)socket_call(SYSCALL_FILE_DATAGRAM, (uint64_t)(int64_t)fd, 0, (uintptr_t)&request, 0);
}
ssize_t alix_udp_recv(int fd, void *data, size_t length, alix_udp_packet_info_t *info, int flags)
{
    syscall_udp_request_t request = { .data = (uintptr_t)data, .length = length,
        .packet_info = (uintptr_t)info, .flags = (uint32_t)flags, .tos = -1 };
    return (ssize_t)socket_call(SYSCALL_FILE_DATAGRAM, (uint64_t)(int64_t)fd, 1, (uintptr_t)&request, 0);
}
