#ifndef SYS_TYPES_H
#define SYS_TYPES_H

#ifdef TTF_HOST_BUILD
#include_next <sys/types.h>
#else
#include <stdint.h>
#include "../types.h"

typedef int64_t off_t;
typedef uint64_t ino_t;
typedef int32_t pid_t;
typedef uint32_t uid_t;
typedef uint32_t gid_t;
typedef uint32_t mode_t;
typedef int64_t suseconds_t;

#endif
#endif /* SYS_TYPES_H */
