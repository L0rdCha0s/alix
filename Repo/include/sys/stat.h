#ifndef SYS_STAT_H
#define SYS_STAT_H

#include "types.h"
#include "syscall_defs.h"

#ifdef TTF_HOST_BUILD
#include_next <sys/stat.h>
typedef struct stat stat_t;
#else
typedef struct stat
{
    uint64_t st_size;
    uint32_t st_mode;
    uint32_t st_type;
} stat_t;

#ifndef KERNEL_BUILD
int fstat(int fd, struct stat *st);
#endif

#endif
#endif /* SYS_STAT_H */
