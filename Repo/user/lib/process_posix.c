#include "unistd.h"
#include "usyscall.h"

pid_t getpid(void)
{
    /* The kernel allocates only positive IDs representable by pid_t. */
    return sys_getpid();
}
