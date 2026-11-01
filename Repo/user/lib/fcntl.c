#include "fcntl.h"
#include "unistd.h"
#include "usyscall.h"
#include "errno.h"
#include <stdarg.h>

static int fd_result(int64_t result)
{
    if (result < 0) { errno = (int)-result; return -1; }
    return (int)result;
}

int fcntl(int fd, int command, ...)
{
    uint64_t source = (uint64_t)(int64_t)fd;
    if (command == F_GETFD) return fd_result(sys_file_io(SYSCALL_FILE_GETFD,source,0,0,0));
    if (command != F_SETFD && command != F_DUPFD && command != F_DUPFD_CLOEXEC)
    { errno = EINVAL; return -1; }
    va_list arguments;
    va_start(arguments,command);
    int argument = va_arg(arguments,int);
    va_end(arguments);
    if (command == F_SETFD)
        return fd_result(sys_file_io(SYSCALL_FILE_SETFD,source,(uint64_t)(int64_t)argument,0,0));
    return fd_result(sys_file_io(SYSCALL_FILE_DUP,source,(uint64_t)(int64_t)argument,
                                  command == F_DUPFD_CLOEXEC ? SYSCALL_FILE_CLOEXEC : 0,0));
}

int dup(int fd)
{
    return fd_result(sys_file_io(SYSCALL_FILE_DUP,(uint64_t)(int64_t)fd,0,0,0));
}

int dup2(int source, int destination)
{
    return fd_result(sys_file_io(SYSCALL_FILE_DUP2,(uint64_t)(int64_t)source,(uint64_t)(int64_t)destination,0,0));
}

int dup3(int source, int destination, int flags)
{
    if (flags & ~O_CLOEXEC) { errno = EINVAL; return -1; }
    return fd_result(sys_file_io(SYSCALL_FILE_DUP3,(uint64_t)(int64_t)source,(uint64_t)(int64_t)destination,
                                  flags & O_CLOEXEC ? SYSCALL_FILE_CLOEXEC : 0,0));
}

int pipe2(int fds[2], int flags)
{
    if (flags & ~O_CLOEXEC) { errno = EINVAL; return -1; }
    return fd_result(sys_file_io(SYSCALL_FILE_PIPE, (uintptr_t)fds,
                                  flags & O_CLOEXEC ? SYSCALL_FILE_CLOEXEC : 0, 0, 0));
}

int pipe(int fds[2]) { return pipe2(fds, 0); }
