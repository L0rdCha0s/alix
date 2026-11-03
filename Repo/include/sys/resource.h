#ifndef ALIX_SYS_RESOURCE_H
#define ALIX_SYS_RESOURCE_H
#ifdef TTF_HOST_BUILD
#include_next <sys/resource.h>
#else
#include "types.h"
#include "sys/time.h"
#include "syscall_defs.h"

typedef uint64_t rlim_t;
struct rlimit { rlim_t rlim_cur, rlim_max; };
#define RLIM_INFINITY UINT64_MAX
#define RLIMIT_NOFILE SYSCALL_RESOURCE_NOFILE
#define RLIMIT_AS SYSCALL_RESOURCE_AS
#define RUSAGE_SELF SYSCALL_USAGE_SELF
/* Native measured fields. No swap/file-backed paging is implemented yet, so
 * successful recoverable user faults are minor faults; major faults stay zero. */
struct rusage
{
    struct timeval ru_utime, ru_stime;
    long ru_minflt, ru_majflt;
    long ru_maxrss; /* Peak resident user mappings, in KiB. */
};

#ifdef __cplusplus
extern "C" {
#endif
int getrlimit(int resource, struct rlimit *limit);
int setrlimit(int resource, const struct rlimit *limit);
int getrusage(int who, struct rusage *usage) __asm__("alix_getrusage_v2");
#ifdef __cplusplus
}
#endif
#endif
#endif
