#ifndef UNISTD_H
#define UNISTD_H

#include "types.h"
#include "sys/types.h"
#include "syscall_defs.h"

#ifndef KERNEL_BUILD
#ifdef __cplusplus
extern "C" {
#endif

ssize_t read(int fd, void *buffer, size_t count);
ssize_t write(int fd, const void *buffer, size_t count);
int close(int fd);
int dup(int fd);
int dup2(int source, int destination);
int dup3(int source, int destination, int flags);
int isatty(int fd);
int pipe(int fds[2]);
int pipe2(int fds[2], int flags);
pid_t fork(void);
int execv(const char *path, char *const argv[]);
int execvp(const char *file, char *const argv[]);
int chdir(const char *path);
char *getcwd(char *buffer, size_t capacity);
int access(const char *path, int mode);
int unlink(const char *path);
ssize_t readlink(const char *path, char *buffer, size_t capacity);
int64_t lseek(int fd, int64_t offset, int whence);
uint32_t getuid(void);
pid_t getpid(void);
long sysconf(int name);
int getentropy(void *buffer, size_t length);
#ifdef __cplusplus
}
#endif
#endif

#define R_OK 4
#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#define W_OK 2
#define X_OK 1
#define F_OK 0
#define _SC_PAGESIZE 1
#define _SC_PAGE_SIZE _SC_PAGESIZE
#define _SC_NPROCESSORS_ONLN 2
#define _SC_NPROCESSORS_CONF 3

#endif /* UNISTD_H */
