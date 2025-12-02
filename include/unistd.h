#ifndef UNISTD_H
#define UNISTD_H

#include "types.h"
#include "syscall_defs.h"

#ifndef KERNEL_BUILD
ssize_t read(int fd, void *buffer, size_t count);
ssize_t write(int fd, const void *buffer, size_t count);
int close(int fd);
int access(const char *path, int mode);
int64_t lseek(int fd, int64_t offset, int whence);
#endif

#define R_OK 4
#define W_OK 2
#define X_OK 1
#define F_OK 0

#endif /* UNISTD_H */
