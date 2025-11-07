#ifndef SYSCALL_DEFS_H
#define SYSCALL_DEFS_H

#include "types.h"

typedef enum
{
    SYSCALL_EXIT = 0,
    SYSCALL_WRITE = 1,
    SYSCALL_READ = 2,
    SYSCALL_OPEN = 3,
    SYSCALL_CLOSE = 4,
    SYSCALL_SBRK = 5,
} syscall_id_t;

#define SYSCALL_OPEN_READ     (1u << 0)
#define SYSCALL_OPEN_WRITE    (1u << 1)
#define SYSCALL_OPEN_CREATE   (1u << 2)
#define SYSCALL_OPEN_TRUNCATE (1u << 3)

#endif
