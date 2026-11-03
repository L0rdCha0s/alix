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

uint32_t geteuid(void) { return getuid(); }
uint32_t getgid(void) { return (uint32_t)sys_process(SYSCALL_PROCESS_GETGID, 0, 0, 0); }
uint32_t getegid(void) { return getgid(); }

static int resource_snapshot(syscall_resource_usage_t *snapshot)
{
    int result = sys_resource_usage(RUSAGE_SELF, snapshot, sizeof(*snapshot));
    if (result < 0) { errno = -result; return -1; }
    if (snapshot->version != SYSCALL_USAGE_VERSION || snapshot->size != sizeof(*snapshot) ||
        !snapshot->tick_frequency || snapshot->reserved)
    { errno = EIO; return -1; }
    return 0;
}

clock_t clock(void)
{
    syscall_resource_usage_t snapshot = {0};
    if (resource_snapshot(&snapshot)) return (clock_t)-1;
    if (UINT64_MAX - snapshot.user_ticks < snapshot.system_ticks)
    { errno = EOVERFLOW; return (clock_t)-1; }
    uint64_t ticks = snapshot.user_ticks + snapshot.system_ticks;
    uint64_t seconds = ticks / snapshot.tick_frequency;
    if (seconds > INT64_MAX / CLOCKS_PER_SEC) { errno = EOVERFLOW; return (clock_t)-1; }
    uint64_t base = seconds * CLOCKS_PER_SEC;
    uint64_t fraction = ((ticks % snapshot.tick_frequency) * CLOCKS_PER_SEC) / snapshot.tick_frequency;
    if (fraction > INT64_MAX - base) { errno = EOVERFLOW; return (clock_t)-1; }
    return (clock_t)(base + fraction);
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
    if (who != RUSAGE_SELF) { errno = EINVAL; return -1; }
    syscall_resource_usage_v2_t extended = {0};
    syscall_resource_usage_t *snapshot = &extended.usage;
    int result = sys_resource_usage(RUSAGE_SELF, snapshot, sizeof(extended));
    if (result < 0) { errno = -result; return -1; }
    if (snapshot->version != SYSCALL_USAGE_VERSION_2 || snapshot->size != sizeof(extended) ||
        !snapshot->tick_frequency || snapshot->reserved || extended.peak_resident_pages < extended.resident_pages)
    { errno = EIO; return -1; }
    struct rusage value = {0};
    resource_ticks_to_timeval(snapshot->user_ticks, snapshot->tick_frequency, &value.ru_utime);
    resource_ticks_to_timeval(snapshot->system_ticks, snapshot->tick_frequency, &value.ru_stime);
    value.ru_minflt = snapshot->minor_faults > LONG_MAX ? LONG_MAX : (long)snapshot->minor_faults;
    value.ru_majflt = snapshot->major_faults > LONG_MAX ? LONG_MAX : (long)snapshot->major_faults;
    value.ru_maxrss = extended.peak_resident_pages > LONG_MAX / 4u ? LONG_MAX : (long)(extended.peak_resident_pages * 4u);
    *usage = value;
    return 0;
}

/* Installed programs retain their original 48-byte output ABI. */
typedef struct { struct timeval user, system; long minor, major; } resource_usage_legacy_t;
int resource_getrusage_legacy(int, resource_usage_legacy_t *) __asm__("getrusage");
int resource_getrusage_legacy(int who, resource_usage_legacy_t *usage)
{
    if (!usage) { errno = EFAULT; return -1; }
    if (who != RUSAGE_SELF) { errno = EINVAL; return -1; }
    syscall_resource_usage_t snapshot = {0};
    if (resource_snapshot(&snapshot)) return -1;
    resource_usage_legacy_t value = {0};
    resource_ticks_to_timeval(snapshot.user_ticks, snapshot.tick_frequency, &value.user);
    resource_ticks_to_timeval(snapshot.system_ticks, snapshot.tick_frequency, &value.system);
    value.minor = snapshot.minor_faults > LONG_MAX ? LONG_MAX : (long)snapshot.minor_faults;
    value.major = snapshot.major_faults > LONG_MAX ? LONG_MAX : (long)snapshot.major_faults;
    *usage = value;
    return 0;
}
