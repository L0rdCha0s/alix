#ifndef UNISTD_H
#define UNISTD_H

#include "types.h"
#include "sys/types.h"
#include "syscall_defs.h"

#define _POSIX_MONOTONIC_CLOCK 200809L

#ifndef KERNEL_BUILD
#ifdef __cplusplus
extern "C" {
#endif

ssize_t read(int fd, void *buffer, size_t count);
ssize_t pread(int fd, void *buffer, size_t count, off_t offset);
ssize_t write(int fd, const void *buffer, size_t count);
int close(int fd);
int fsync(int fd);
int ftruncate(int fd, off_t length);
int truncate(const char *path, off_t length);
int fchown(int fd, uid_t uid, gid_t gid);
void _exit(int status) __attribute__((__noreturn__));
int dup(int fd);
int dup2(int source, int destination);
int dup3(int source, int destination, int flags);
int isatty(int fd);
int pipe(int fds[2]);
int pipe2(int fds[2], int flags);
pid_t fork(void);
int execv(const char *path, char *const argv[]);
int execvp(const char *file, char *const argv[]);
int execve(const char *path, char *const argv[], char *const envp[]);
int execl(const char *path, const char *argument, ...);
int execle(const char *path, const char *argument, ...);
int execlp(const char *path, const char *argument, ...);
int chdir(const char *path);
char *getcwd(char *buffer, size_t capacity);
/* Absolute launch-path snapshot, including NUL on success. Return byte length
 * excluding NUL, or -1/errno; ERANGE never returns a truncated path. Anonymous
 * in-memory images have no path and report ENOENT. */
ssize_t alix_get_executable_path(char *buffer, size_t capacity);
int access(const char *path, int mode);
int unlink(const char *path);
int rmdir(const char *path);
ssize_t readlink(const char *path, char *buffer, size_t capacity);
int64_t lseek(int fd, int64_t offset, int whence);
uint32_t getuid(void);
uint32_t geteuid(void);
uint32_t getgid(void);
uint32_t getegid(void);
int gethostname(char *name, size_t capacity);
pid_t getpid(void);
unsigned int sleep(unsigned int seconds);
int usleep(useconds_t microseconds);
unsigned alarm(unsigned seconds);
int symlink(const char *target, const char *path);
int faccessat(int directory, const char *path, int mode, int flags);
long sysconf(int name);
int getpagesize(void);
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
#define _SC_PHYS_PAGES 4
#define _SC_AVPHYS_PAGES 5

#endif /* UNISTD_H */
