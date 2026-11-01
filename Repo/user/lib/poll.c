#include "poll.h"
#include "usyscall.h"
#include "errno.h"
#include <stddef.h>

_Static_assert(sizeof(struct pollfd) == sizeof(syscall_pollfd_t), "poll ABI size");
_Static_assert(offsetof(struct pollfd, revents) == offsetof(syscall_pollfd_t, revents), "poll ABI offset");
int poll(struct pollfd *entries, nfds_t count, int timeout)
{
    int64_t result = sys_file_io(SYSCALL_FILE_POLL, (uintptr_t)entries, count,
                                  (uint64_t)(int64_t)timeout, 0);
    if (result < 0) { errno = (int)-result; return -1; }
    return (int)result;
}
