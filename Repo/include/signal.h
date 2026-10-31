#ifndef ALIX_SIGNAL_H
#define ALIX_SIGNAL_H

#ifdef TTF_HOST_BUILD
#include_next <signal.h>
#else

typedef int sig_atomic_t;

#define SIGINT 2
#define SIGILL 4
#define SIGABRT 6
#define SIGFPE 8
#define SIGSEGV 11
#define SIGTERM 15

#define SIG_DFL ((void (*)(int))0)
#define SIG_IGN ((void (*)(int))1)
#define SIG_ERR ((void (*)(int))-1)

#ifdef __cplusplus
extern "C" {
#endif

/* ISO C registration and synchronous raise(). Kernel-generated hardware and
 * asynchronous signal delivery, sigaction and alternate stacks are not yet
 * implemented. Handlers remain installed after a successful raise(). */
void (*signal(int number, void (*handler)(int)))(int);
int raise(int number);

#ifdef __cplusplus
}
#endif
#endif
#endif
