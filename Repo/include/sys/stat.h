#ifndef SYS_STAT_H
#define SYS_STAT_H

#include "types.h"
#include "syscall_defs.h"

typedef struct stat
{
    uint64_t st_size;
    uint32_t st_mode;
    uint32_t st_type;
} stat_t;

#ifndef KERNEL_BUILD
int fstat(int fd, struct stat *st);
#endif

#endif /* SYS_STAT_H */
