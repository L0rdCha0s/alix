#ifndef FCNTL_H
#define FCNTL_H

#include "syscall_defs.h"

#define O_RDONLY SYSCALL_OPEN_READ
#define O_WRONLY SYSCALL_OPEN_WRITE
#define O_RDWR   (SYSCALL_OPEN_READ | SYSCALL_OPEN_WRITE)
#define O_CREAT  SYSCALL_OPEN_CREATE
#define O_TRUNC  SYSCALL_OPEN_TRUNCATE
#define O_EXCL SYSCALL_OPEN_EXCLUSIVE
#define O_APPEND SYSCALL_OPEN_APPEND
#define O_NONBLOCK SYSCALL_OPEN_NONBLOCK
#define O_NDELAY O_NONBLOCK
#define O_ACCMODE (O_RDONLY | O_WRONLY)
#define O_BINARY 0
#define O_CLOEXEC SYSCALL_OPEN_CLOEXEC
#define FD_CLOEXEC SYSCALL_FILE_CLOEXEC
#define F_DUPFD 0
#define F_GETFD 1
#define F_SETFD 2
#define F_GETFL 3
#define F_SETFL 4
#define F_DUPFD_CLOEXEC 1030

#ifdef __cplusplus
extern "C" {
#endif
int open(const char *path, uint64_t flags, ...);
int fcntl(int fd, int command, ...);
#ifdef __cplusplus
}
#endif

#endif /* FCNTL_H */
