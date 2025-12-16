#ifndef FCNTL_H
#define FCNTL_H

#include "syscall_defs.h"

#define O_RDONLY SYSCALL_OPEN_READ
#define O_WRONLY SYSCALL_OPEN_WRITE
#define O_RDWR   (SYSCALL_OPEN_READ | SYSCALL_OPEN_WRITE)
#define O_CREAT  SYSCALL_OPEN_CREATE
#define O_TRUNC  SYSCALL_OPEN_TRUNCATE
#define O_APPEND (1u << 16)
#define O_BINARY 0

int open(const char *path, uint64_t flags, ...);

#endif /* FCNTL_H */
