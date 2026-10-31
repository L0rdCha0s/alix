#ifndef ALIX_SYS_RESOURCE_H
#define ALIX_SYS_RESOURCE_H
#ifdef TTF_HOST_BUILD
#include_next <sys/resource.h>
#else
#include "types.h"

typedef uint64_t rlim_t;
struct rlimit { rlim_t rlim_cur, rlim_max; };
#define RLIM_INFINITY UINT64_MAX
#define RLIMIT_AS 9

#ifdef __cplusplus
extern "C" {
#endif
int getrlimit(int resource, struct rlimit *limit);
#ifdef __cplusplus
}
#endif
#endif
#endif
