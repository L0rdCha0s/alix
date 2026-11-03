#ifndef USER_USERLIB_H
#define USER_USERLIB_H

#include "libc.h"
#include "usyscall.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef TTF_HOST_BUILD
int open(const char *path, uint64_t flags, ...);
#else
int open(const char *path, uint64_t flags, ...) __asm__("alix_open_v2");
#endif
int socket_open(const char *iface_name);
int socket_connect(int fd, const char *ipv4_text, uint16_t port);
void *sbrk(int64_t increment);
void exit(int status) __attribute__((__noreturn__));
int64_t lseek(int fd, int64_t offset, int whence);
int fstat(int fd, struct stat *st);
ssize_t pread(int fd, void *buffer, size_t count, off_t offset);

#ifdef __cplusplus
}
#endif

#endif
