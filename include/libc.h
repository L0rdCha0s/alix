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
char *strstr(const char *haystack, const char *needle);
int strcasecmp(const char *a, const char *b);
int strncasecmp(const char *a, const char *b, size_t n);
char *strerror(int errnum);

void *malloc(size_t size);
void free(void *ptr);
void *calloc(size_t count, size_t size);
void *realloc(void *ptr, size_t size);
int abs(int value);
int atoi(const char *str);
int setenv(const char *name, const char *value, int overwrite);
int unsetenv(const char *name);
char *getenv(const char *name);

ssize_t read(int fd, void *buffer, size_t count);
ssize_t write(int fd, const void *buffer, size_t count);
int close(int fd);
int open(const char *path, uint64_t flags, ...);
int socket_open(const char *iface_name);
int socket_connect(int fd, const char *ipv4_text, uint16_t port);
ssize_t socket_available(int fd);
int printf(const char *format, ...);
int64_t lseek(int fd, int64_t offset, int whence);
int fstat(int fd, struct stat *st);
ssize_t pread(int fd, void *buffer, size_t count, size_t offset);
void exit(int status);

typedef uint64_t alix_thread_t;

typedef struct
{
    volatile uint32_t state;
} alix_mutex_t;

void alix_mutex_init(alix_mutex_t *mutex);
void alix_mutex_lock(alix_mutex_t *mutex);
void alix_mutex_unlock(alix_mutex_t *mutex);

alix_thread_t alix_thread_self(void);
int alix_thread_create(alix_thread_t *thread_out,
                       const char *name,
                       void (*start)(void *),
                       void *arg);
int alix_thread_join(alix_thread_t thread, int *status_out);
void alix_thread_exit(int status) __attribute__((noreturn));

#endif
