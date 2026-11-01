#include "sys/select.h"
#include "usyscall.h"
#include "stdlib.h"
#include "errno.h"

_Static_assert(sizeof(fd_set) == 32, "native descriptor set ABI");
_Static_assert(sizeof(struct timeval) == 16, "native select timeout ABI");
_Static_assert(sizeof(syscall_select_t) == 48, "native select query ABI");

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
#ifdef ALIX_OWNED_FDS
    syscall_select_t *query = calloc(1, sizeof(*query));
    if (!query) { errno = ENOMEM; return -1; }
    query->version = SYSCALL_SELECT_VERSION;
    query->size = sizeof(*query);
    query->nfds = nfds;
    query->readfds = (uintptr_t)readfds;
    query->writefds = (uintptr_t)writefds;
    query->exceptfds = (uintptr_t)exceptfds;
    query->timeout = (uintptr_t)timeout;
    int64_t result = sys_file_io(SYSCALL_FILE_SELECT, (uintptr_t)query, sizeof(*query), 0, 0);
    free(query);
    if (result < 0) { errno = (int)-result; return -1; }
    return (int)result;
#else
    (void)nfds; (void)readfds; (void)writefds; (void)exceptfds; (void)timeout;
    errno = ENOTSUP;
    return -1;
#endif
}
