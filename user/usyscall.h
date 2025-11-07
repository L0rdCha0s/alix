#ifndef USER_USYSCALL_H
#define USER_USYSCALL_H

#include "types.h"
#include "syscall_defs.h"

ssize_t sys_write(int fd, const void *buffer, size_t count);
ssize_t sys_read(int fd, void *buffer, size_t count);
int sys_close(int fd);
int sys_open(const char *path, uint64_t flags);
void *sys_sbrk(int64_t increment);
void sys_exit(int status) __attribute__((noreturn));

#endif
