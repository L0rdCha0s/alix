#include "unistd.h"
#include "usyscall.h"
#include "sys/resource.h"
#include "errno.h"
#include <limits.h>

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

static void resource_ticks_to_timeval(uint64_t ticks, uint32_t frequency, struct timeval *value)
{
    uint64_t seconds = ticks / frequency;
    if (seconds > INT64_MAX) { value->tv_sec = INT64_MAX; value->tv_usec = 999999; }
    else
    {
        value->tv_sec = (time_t)seconds;
        value->tv_usec = (suseconds_t)(((ticks % frequency) * 1000000ULL) / frequency);
    }
}

int getrusage(int who, struct rusage *usage)
{
    if (!usage) { errno = EFAULT; return -1; }
    syscall_resource_usage_t snapshot = {0};
    int result = sys_resource_usage(who, &snapshot, sizeof(snapshot));
    if (result < 0) { errno = -result; return -1; }
    if (snapshot.version != SYSCALL_USAGE_VERSION || snapshot.size != sizeof(snapshot) ||
        !snapshot.tick_frequency || snapshot.reserved)
    { errno = EIO; return -1; }
    struct rusage value = {0};
    resource_ticks_to_timeval(snapshot.user_ticks, snapshot.tick_frequency, &value.ru_utime);
    resource_ticks_to_timeval(snapshot.system_ticks, snapshot.tick_frequency, &value.ru_stime);
    value.ru_minflt = snapshot.minor_faults > LONG_MAX ? LONG_MAX : (long)snapshot.minor_faults;
    value.ru_majflt = snapshot.major_faults > LONG_MAX ? LONG_MAX : (long)snapshot.major_faults;
    *usage = value;
    return 0;
}
