#include "fcntl.h"
#include "unistd.h"
#include "usyscall.h"
#include "errno.h"
#include "sys/file.h"
#include <stdarg.h>
#include <stddef.h>
_Static_assert(sizeof(struct flock) == 24 && sizeof(struct flock) == sizeof(syscall_record_lock_t) &&
    offsetof(struct flock,l_start) == offsetof(syscall_record_lock_t,start) &&
    offsetof(struct flock,l_len) == offsetof(syscall_record_lock_t,length) &&
    offsetof(struct flock,l_pid) == offsetof(syscall_record_lock_t,pid) &&
    offsetof(struct flock,l_type) == offsetof(syscall_record_lock_t,type) &&
    offsetof(struct flock,l_whence) == offsetof(syscall_record_lock_t,whence), "native record lock ABI");

static int fd_result(int64_t result)
{
    if (result < 0) { errno = (int)-result; return -1; }
    return (int)result;
}

int flock(int fd, int operation)
{
    return fd_result(sys_file_io(SYSCALL_FILE_FLOCK, (uint64_t)(int64_t)fd,
                                  (uint64_t)(int64_t)operation, 0, 0));
}

int fcntl(int fd, int command, ...)
{
    uint64_t source = (uint64_t)(int64_t)fd;
    if (command == F_GETFD) return fd_result(sys_file_io(SYSCALL_FILE_GETFD,source,0,0,0));
    if (command == F_GETFL) return fd_result(sys_file_io(SYSCALL_FILE_GETFL,source,0,0,0));
    if (command == F_GETLK || command == F_SETLK || command == F_SETLKW)
    {
        va_list pointers; va_start(pointers,command);
        struct flock *query = va_arg(pointers,struct flock *); va_end(pointers);
        return fd_result(sys_file_io(SYSCALL_FILE_RECORD_LOCK,source,(uint32_t)command,(uintptr_t)query,0));
    }
    if (command != F_SETFD && command != F_SETFL && command != F_DUPFD && command != F_DUPFD_CLOEXEC)
    { errno = EINVAL; return -1; }
    va_list arguments;
    va_start(arguments,command);
    int argument = va_arg(arguments,int);
    va_end(arguments);
    if (command == F_SETFL)
        return fd_result(sys_file_io(SYSCALL_FILE_SETFL,source,(uint64_t)(int64_t)argument,0,0));
    if (command == F_SETFD)
        return fd_result(sys_file_io(SYSCALL_FILE_SETFD,source,(uint64_t)(int64_t)argument,0,0));
    return fd_result(sys_file_io(SYSCALL_FILE_DUP,source,(uint64_t)(int64_t)argument,
                                  command == F_DUPFD_CLOEXEC ? SYSCALL_FILE_CLOEXEC : 0,SYSCALL_DUP_CHECK_MINIMUM));
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
    if (flags & ~(O_CLOEXEC | O_NONBLOCK)) { errno = EINVAL; return -1; }
    return fd_result(sys_file_io(SYSCALL_FILE_PIPE, (uintptr_t)fds,
                                  (flags & O_CLOEXEC ? SYSCALL_FILE_CLOEXEC : 0) |
                                  (flags & O_NONBLOCK ? SYSCALL_OPEN_NONBLOCK : 0), 0, 0));
}

int pipe(int fds[2]) { return pipe2(fds, 0); }
