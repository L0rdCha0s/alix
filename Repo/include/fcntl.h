#ifndef FCNTL_H
#define FCNTL_H

#include "syscall_defs.h"
#include "sys/types.h"

#define O_RDONLY SYSCALL_OPEN_READ
#define O_WRONLY SYSCALL_OPEN_WRITE
#define O_RDWR   (SYSCALL_OPEN_READ | SYSCALL_OPEN_WRITE)
#define O_CREAT  SYSCALL_OPEN_CREATE
#define O_TRUNC  SYSCALL_OPEN_TRUNCATE
#define O_EXCL SYSCALL_OPEN_EXCLUSIVE
#define O_APPEND SYSCALL_OPEN_APPEND
#define O_NONBLOCK SYSCALL_OPEN_NONBLOCK
#define O_SYNC SYSCALL_OPEN_SYNC
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
#define F_GETLK SYSCALL_F_GETLK
#define F_SETLK SYSCALL_F_SETLK
#define F_SETLKW SYSCALL_F_SETLKW
#define F_RDLCK SYSCALL_F_RDLCK
#define F_WRLCK SYSCALL_F_WRLCK
#define F_UNLCK SYSCALL_F_UNLCK
struct flock
{
    off_t l_start, l_len;
    pid_t l_pid;
    short l_type, l_whence;
};

#ifdef __cplusplus
extern "C" {
#endif
#ifdef TTF_HOST_BUILD
int open(const char *path, uint64_t flags, ...);
#else
int open(const char *path, uint64_t flags, ...) __asm__("alix_open_v2");
#endif
int creat(const char *path, mode_t mode);
int fcntl(int fd, int command, ...);
#ifdef __cplusplus
}
#endif

#endif /* FCNTL_H */
