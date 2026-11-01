#ifndef ALIX_SYS_FILE_H
#define ALIX_SYS_FILE_H
#ifdef TTF_HOST_BUILD
#include_next <sys/file.h>
#else
#include "../syscall_defs.h"
#define LOCK_SH SYSCALL_FLOCK_SHARED
#define LOCK_EX SYSCALL_FLOCK_EXCLUSIVE
#define LOCK_NB SYSCALL_FLOCK_NONBLOCK
#define LOCK_UN SYSCALL_FLOCK_UNLOCK
#ifdef __cplusplus
extern "C" {
#endif
int flock(int fd, int operation);
#ifdef __cplusplus
}
#endif
#endif
#endif
