#ifndef USER_USERLIB_H
#define USER_USERLIB_H

#include "libc.h"
#include "usyscall.h"

int open(const char *path, uint64_t flags, ...);
int socket_open(const char *iface_name);
int socket_connect(int fd, const char *ipv4_text, uint16_t port);
void *sbrk(int64_t increment);
void exit(int status) __attribute__((noreturn));
int64_t lseek(int fd, int64_t offset, int whence);
int fstat(int fd, struct stat *st);
ssize_t pread(int fd, void *buffer, size_t count, size_t offset);

#endif
