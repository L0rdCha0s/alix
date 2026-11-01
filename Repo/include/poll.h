#ifndef ALIX_POLL_H
#define ALIX_POLL_H
#ifdef TTF_HOST_BUILD
#include_next <poll.h>
#else
#include "syscall_defs.h"
typedef unsigned long nfds_t;
struct pollfd { int fd; short events, revents; };
#define POLLIN SYSCALL_POLL_IN
#define POLLPRI SYSCALL_POLL_PRI
#define POLLOUT SYSCALL_POLL_OUT
#define POLLERR SYSCALL_POLL_ERR
#define POLLHUP SYSCALL_POLL_HUP
#define POLLNVAL SYSCALL_POLL_NVAL
#ifdef __cplusplus
extern "C" {
#endif
int poll(struct pollfd *entries, nfds_t count, int timeout);
#ifdef __cplusplus
}
#endif
#endif
#endif
