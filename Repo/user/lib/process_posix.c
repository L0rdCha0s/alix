#include "unistd.h"
#include "usyscall.h"
#include "sys/resource.h"
#include "errno.h"

pid_t getpid(void)
{
    /* The kernel allocates only positive IDs representable by pid_t. */
    return sys_getpid();
}

int getrlimit(int resource, struct rlimit *limit)
{
    if (!limit) { errno = EFAULT; return -1; }
    if (resource != RLIMIT_AS) { errno = EINVAL; return -1; }
    /* Alix currently imposes no aggregate per-process virtual-memory quota.
     * This is independent of its finite address window, per-region layout
     * limits and allocation failures. No configurable limit is being hidden;
     * adding such a kernel policy must replace this query with its snapshot. */
    limit->rlim_cur = RLIM_INFINITY;
    limit->rlim_max = RLIM_INFINITY;
    return 0;
}
