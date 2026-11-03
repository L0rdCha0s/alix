#ifndef ALIX_SIGNAL_H
#define ALIX_SIGNAL_H
#ifdef TTF_HOST_BUILD
#include_next <signal.h>
#else
#include "signal_abi.h"
#include "sys/types.h"
typedef int sig_atomic_t;
typedef alix_sigset_t sigset_t;
typedef alix_stack_t stack_t;
typedef alix_siginfo_t siginfo_t;
typedef void (*sighandler_t)(int);
struct sigaction
{
    union {
        sighandler_t sa_handler;
        void (*sa_sigaction)(int, siginfo_t *, void *);
    };
    sigset_t sa_mask;
    int sa_flags;
};
#define NSIG ALIX_SIGNAL_COUNT
#define SIGHUP ALIX_SIGHUP
#define SIGINT ALIX_SIGINT
#define SIGQUIT ALIX_SIGQUIT
#define SIGILL ALIX_SIGILL
#define SIGTRAP ALIX_SIGTRAP
#define SIGABRT ALIX_SIGABRT
#define SIGBUS ALIX_SIGBUS
#define SIGFPE ALIX_SIGFPE
#define SIGKILL ALIX_SIGKILL
#define SIGUSR1 ALIX_SIGUSR1
#define SIGSEGV ALIX_SIGSEGV
#define SIGUSR2 ALIX_SIGUSR2
#define SIGPIPE ALIX_SIGPIPE
#define SIGALRM ALIX_SIGALRM
#define SIGTERM ALIX_SIGTERM
#define SIGCHLD ALIX_SIGCHLD
#define SIGCONT ALIX_SIGCONT
#define SIGSTOP ALIX_SIGSTOP
#define SIGTSTP ALIX_SIGTSTP
#define SIGTTIN ALIX_SIGTTIN
#define SIGTTOU ALIX_SIGTTOU
#define SIGURG ALIX_SIGURG
#define SIGXCPU ALIX_SIGXCPU
#define SIGXFSZ ALIX_SIGXFSZ
#define SIGVTALRM ALIX_SIGVTALRM
#define SIGPROF ALIX_SIGPROF
#define SIGWINCH ALIX_SIGWINCH
#define SIGIO ALIX_SIGIO
#define SIGSYS ALIX_SIGSYS
#define SIG_DFL ((sighandler_t)0)
#define SIG_IGN ((sighandler_t)1)
#define SIG_ERR ((sighandler_t) - 1)
#define SIG_BLOCK ALIX_SIG_BLOCK
#define SIG_UNBLOCK ALIX_SIG_UNBLOCK
#define SIG_SETMASK ALIX_SIG_SETMASK
#define SA_SIGINFO ALIX_SA_SIGINFO
#define SA_NODEFER ALIX_SA_NODEFER
#define SA_ONSTACK ALIX_SA_ONSTACK
#define SA_RESETHAND ALIX_SA_RESETHAND
#define SA_RESTART ALIX_SA_RESTART
#define SS_ONSTACK ALIX_SS_ONSTACK
#define SS_DISABLE ALIX_SS_DISABLE
#define MINSIGSTKSZ ALIX_MINSIGSTKSZ
#define SIGSTKSZ ALIX_SIGSTKSZ
#define SI_USER ALIX_SI_USER
#define SI_TKILL ALIX_SI_TKILL
#define SI_KERNEL ALIX_SI_KERNEL
#define CLD_EXITED ALIX_CLD_EXITED
#define CLD_KILLED ALIX_CLD_KILLED
#define CLD_DUMPED ALIX_CLD_DUMPED
#define CLD_TRAPPED ALIX_CLD_TRAPPED
#define CLD_STOPPED ALIX_CLD_STOPPED
#define CLD_CONTINUED ALIX_CLD_CONTINUED
#define SEGV_MAPERR ALIX_SEGV_MAPERR
#define SEGV_ACCERR ALIX_SEGV_ACCERR
#define ILL_ILLOPC ALIX_ILL_ILLOPC
#define FPE_INTDIV ALIX_FPE_INTDIV
#define FPE_INTOVF ALIX_FPE_INTOVF
#define FPE_FLTDIV ALIX_FPE_FLTDIV
#define FPE_FLTOVF ALIX_FPE_FLTOVF
#define FPE_FLTUND ALIX_FPE_FLTUND
#define FPE_FLTRES ALIX_FPE_FLTRES
#define FPE_FLTINV ALIX_FPE_FLTINV
#define FPE_FLTSUB ALIX_FPE_FLTSUB
#ifdef __cplusplus
extern "C"
{
#endif
    sighandler_t signal(int, sighandler_t);
    int sigaction(int, const struct sigaction *, struct sigaction *);
    int sigemptyset(sigset_t *);
    int sigfillset(sigset_t *);
    int sigaddset(sigset_t *, int);
    int sigdelset(sigset_t *, int);
    int sigismember(const sigset_t *, int);
    int sigprocmask(int, const sigset_t *, sigset_t *);
    int sigpending(sigset_t *);
    int sigwait(const sigset_t *, int *);
    int sigaltstack(const stack_t *, stack_t *);
    int raise(int);
    int kill(pid_t, int);
#ifdef __cplusplus
}
#endif
#endif
#endif
