#ifndef USER_USERLIB_H
#define USER_USERLIB_H

#include "libc.h"
#include "usyscall.h"

int open(const char *path, uint64_t flags);
void *sbrk(int64_t increment);
void exit(int status) __attribute__((noreturn));

#endif
