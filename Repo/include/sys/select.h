#ifndef ALIX_SYS_SELECT_H
#define ALIX_SYS_SELECT_H
#ifdef TTF_HOST_BUILD
#include_next <sys/select.h>
#else
#include "syscall_defs.h"
#include "sys/time.h"

/* This is a fixed native ABI matching the process-owned descriptor table.
 * A third-party FD_SETSIZE preference cannot change the wire layout. */
#ifdef FD_SETSIZE
#undef FD_SETSIZE
#endif
#define FD_SETSIZE SYSCALL_SELECT_FD_MAX
typedef syscall_fd_set_t fd_set;

static inline void __alix_fd_zero(fd_set *set)
{
    for (unsigned i = 0; i < FD_SETSIZE / 64u; ++i) set->bits[i] = 0;
}
static inline void __alix_fd_set(int fd, fd_set *set)
{
    if ((unsigned)fd < FD_SETSIZE) set->bits[(unsigned)fd / 64u] |= (uint64_t)1 << ((unsigned)fd % 64u);
}
static inline void __alix_fd_clear(int fd, fd_set *set)
{
    if ((unsigned)fd < FD_SETSIZE) set->bits[(unsigned)fd / 64u] &= ~((uint64_t)1 << ((unsigned)fd % 64u));
}
static inline int __alix_fd_isset(int fd, const fd_set *set)
{
    return (unsigned)fd < FD_SETSIZE && (set->bits[(unsigned)fd / 64u] & ((uint64_t)1 << ((unsigned)fd % 64u))) != 0;
}
#define FD_ZERO(set) __alix_fd_zero(set)
#define FD_SET(fd, set) __alix_fd_set((fd), (set))
#define FD_CLR(fd, set) __alix_fd_clear((fd), (set))
#define FD_ISSET(fd, set) __alix_fd_isset((fd), (set))

#ifdef __cplusplus
extern "C" {
#endif
int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
#ifdef __cplusplus
}
#endif
#endif
#endif
