#ifndef LIBC_H
#define LIBC_H

#ifdef TTF_HOST_BUILD
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#else
#include "types.h"
#endif
#include "syscall_defs.h"
#include "sys/stat.h"

void *memset(void *dst, int value, size_t count);
void *memmove(void *dst, const void *src, size_t count);
void *memcpy(void *dst, const void *src, size_t count);
int memcmp(const void *a, const void *b, size_t count);
size_t strlen(const char *str);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, size_t n);
char *strcpy(char *dst, const char *src);
char *strncpy(char *dst, const char *src, size_t n);
char *strchr(const char *str, int ch);
char *strrchr(const char *str, int ch);
int strcasecmp(const char *a, const char *b);
int strncasecmp(const char *a, const char *b, size_t n);

void *malloc(size_t size);
void free(void *ptr);
void *calloc(size_t count, size_t size);
void *realloc(void *ptr, size_t size);
int abs(int value);
int atoi(const char *str);

ssize_t read(int fd, void *buffer, size_t count);
ssize_t write(int fd, const void *buffer, size_t count);
int close(int fd);
int open(const char *path, uint64_t flags, ...);
int socket_open(const char *iface_name);
int socket_connect(int fd, const char *ipv4_text, uint16_t port);
int printf(const char *format, ...);
int64_t lseek(int fd, int64_t offset, int whence);
int fstat(int fd, struct stat *st);
ssize_t pread(int fd, void *buffer, size_t count, size_t offset);
void exit(int status);

#endif
