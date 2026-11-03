#include "signal.h"
#include "errno.h"
#include "pthread.h"
#include "usyscall.h"
#include <stddef.h>

_Static_assert(sizeof(struct sigaction) == sizeof(alix_sigaction_t), "native action wire");
_Static_assert(offsetof(struct sigaction, sa_mask) == 8 && offsetof(struct sigaction, sa_flags) == 16,
               "native action fields");

static int signal_result(int result)
{
    if (result < 0)
    {
        errno = -result;
        return -1;
    }
    return result;
}
static int signal_number(int number)
{
    return number > 0 && number < (int)ALIX_SIGNAL_COUNT;
}

int sigaction(int number, const struct sigaction *action, struct sigaction *old)
{
    return signal_result(
        sys_sigaction(number, (const alix_sigaction_t *)action, (alix_sigaction_t *)old, sizeof(*action)));
}
sighandler_t signal(int number, sighandler_t handler)
{
    struct sigaction action = {0}, old = {0};
    action.sa_handler = handler;
    action.sa_flags = SA_RESTART;
    return sigaction(number, &action, &old) == 0 ? old.sa_handler : SIG_ERR;
}
int sigemptyset(sigset_t *set)
{
    if (!set)
    {
        errno = EINVAL;
        return -1;
    }
    *set = 0;
    return 0;
}
int sigfillset(sigset_t *set)
{
    if (!set)
    {
        errno = EINVAL;
        return -1;
    }
    *set = ALIX_SIGNAL_MASK;
    return 0;
}
int sigaddset(sigset_t *set, int number)
{
    if (!set || !signal_number(number))
    {
        errno = EINVAL;
        return -1;
    }
    *set |= 1ULL << (number - 1);
    return 0;
}
int sigdelset(sigset_t *set, int number)
{
    if (!set || !signal_number(number))
    {
        errno = EINVAL;
        return -1;
    }
    *set &= ~(1ULL << (number - 1));
    return 0;
}
int sigismember(const sigset_t *set, int number)
{
    if (!set || !signal_number(number))
    {
        errno = EINVAL;
        return -1;
    }
    return (*set & (1ULL << (number - 1))) != 0;
}
int sigprocmask(int how, const sigset_t *set, sigset_t *old)
{
    return signal_result(sys_sigprocmask(how, set, old));
}
int sigpending(sigset_t *set)
{
    return signal_result(sys_sigprocmask(ALIX_SIG_PENDING, NULL, set));
}
int sigwait(const sigset_t *set, int *number)
{
    int saved = errno;
    int result;
    do { result = sys_sigwait(set, number, sizeof(*set), 0); } while (result == -EINTR);
    errno = saved;
    return result < 0 ? -result : result;
}
int sigaltstack(const stack_t *stack, stack_t *old)
{
    return signal_result(sys_sigaltstack(stack, old, sizeof(*stack)));
}
int raise(int number)
{
    return signal_result(sys_raise(number, 0));
}
int kill(pid_t pid, int number)
{
    return signal_result(sys_kill(pid, number));
}

unsigned alarm(unsigned seconds)
{
    int64_t result = sys_process(SYSCALL_PROCESS_ALARM, seconds, 0, 0);
    if (result < 0) { errno = (int)-result; return 0; }
    return (unsigned)result;
}
int pthread_sigmask(int how, const sigset_t *set, sigset_t *old)
{
    int result = sys_sigprocmask(how, set, old);
    return result < 0 ? -result : result;
}
int pthread_kill(pthread_t thread, int number)
{
    if (!thread)
        return ESRCH;
    int result = sys_raise(number, thread);
    return result < 0 ? -result : result;
}
