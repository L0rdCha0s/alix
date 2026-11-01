#include "sys/socket.h"
#include "netinet/in.h"
#include "usyscall.h"
#include "errno.h"
#include <stddef.h>

_Static_assert(sizeof(struct sockaddr_in) == sizeof(syscall_sockaddr_in_t), "native IPv4 address ABI");
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
