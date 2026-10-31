#include "signal.h"
#include "types.h"
#include "errno.h"
#include "usyscall.h"

typedef void (*signal_handler_t)(int);
static signal_handler_t signal_handlers[16];

static bool signal_supported(int number)
{
    switch (number)
    {
        case SIGABRT:
        case SIGFPE:
        case SIGILL:
        case SIGINT:
        case SIGSEGV:
        case SIGTERM:
            return true;
        default:
            return false;
    }
}

signal_handler_t signal(int number, signal_handler_t handler)
{
    if (!signal_supported(number) || handler == SIG_ERR)
    {
        errno = EINVAL;
        return SIG_ERR;
    }
    return __atomic_exchange_n(&signal_handlers[number], handler, __ATOMIC_ACQ_REL);
}

int raise(int number)
{
    if (!signal_supported(number))
    {
        errno = EINVAL;
        return -1;
    }
    signal_handler_t handler = __atomic_load_n(&signal_handlers[number], __ATOMIC_ACQUIRE);
    if (handler == SIG_IGN)
    {
        return 0;
    }
    if (handler == SIG_DFL)
    {
        /* Default ISO C dispositions terminate the process. Do not run libc
         * exit handlers or pretend this synchronous API delivers OS faults. */
        sys_exit(128 + number);
    }
    /* No lock or borrowed record survives the call into application code.
     * The handler runs on this thread and remains installed afterward. */
    handler(number);
    return 0;
}
