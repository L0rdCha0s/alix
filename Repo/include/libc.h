#ifndef LIBC_H
#define LIBC_H

#ifdef TTF_HOST_BUILD
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "sys/types.h"
#else
#include "types.h"
#endif
#include "syscall_defs.h"
#include "sys/types.h"
#include "sys/stat.h"
#include "alix_mutex.h"

#ifdef __cplusplus
extern "C" {
#endif

void *memset(void *dst, int value, size_t count);
void *memmove(void *dst, const void *src, size_t count);
void *memcpy(void *dst, const void *src, size_t count);
int memcmp(const void *a, const void *b, size_t count);
void *memchr(const void *src, int ch, size_t count);
size_t strlen(const char *str);
size_t strnlen(const char *str, size_t maximum);
char *strdup(const char *str);
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
int putenv(char *assignment);
char *getenv(const char *name);
uint32_t getuid(void);
#ifdef TTF_HOST_BUILD
int mkdir(const char *path, mode_t mode);
#else
int mkdir(const char *path, uint32_t mode);
#endif
char *alix_home_dir(void);
bool alix_ensure_dir_path(const char *path);

ssize_t read(int fd, void *buffer, size_t count);
ssize_t write(int fd, const void *buffer, size_t count);
int close(int fd);
#ifdef TTF_HOST_BUILD
int open(const char *path, uint64_t flags, ...);
#else
int open(const char *path, uint64_t flags, ...) __asm__("alix_open_v2");
#endif
int socket_open(const char *iface_name);
int socket_connect(int fd, const char *ipv4_text, uint16_t port);
ssize_t socket_available(int fd);
int printf(const char *format, ...);
int snprintf(char *buffer, size_t size, const char *format, ...);
int64_t lseek(int fd, int64_t offset, int whence);
int fstat(int fd, struct stat *st);
ssize_t pread(int fd, void *buffer, size_t count, off_t offset);
void exit(int status);

typedef uint64_t alix_thread_t;

typedef struct
{
    alix_mutex_t mutex;
    uint64_t owner;
    uint32_t depth;
} alix_recursive_mutex_t;
void alix_recursive_mutex_init(alix_recursive_mutex_t *mutex);
int alix_recursive_mutex_lock(alix_recursive_mutex_t *mutex);
bool alix_recursive_mutex_trylock(alix_recursive_mutex_t *mutex);
int alix_recursive_mutex_unlock(alix_recursive_mutex_t *mutex);

typedef struct { volatile uint32_t state; } alix_once_t;
int alix_call_once(alix_once_t *once, void (*initialize)(void));

typedef uint64_t alix_tls_key_t;
int alix_tls_key_create(alix_tls_key_t *key, void (*destroy)(void *));
int alix_tls_key_delete(alix_tls_key_t key);
void *alix_tls_get(alix_tls_key_t key);
int alix_tls_set(alix_tls_key_t key, void *value);
void alix_thread_run_tls_destructors(void);
void alix_run_exit_handlers(void);

/* Shared mutex/condition state belongs in process heap or static storage, not
 * another thread's stack. Wait with the mutex held and check the application's
 * predicate in a loop. All returns from a valid wait reacquire that mutex. */
typedef struct
{
    volatile uint32_t sequence;
} alix_cond_t;

#define ALIX_WAIT_FOREVER ((uint32_t)-1)

void alix_cond_init(alix_cond_t *condition);
int alix_cond_wait(alix_cond_t *condition, alix_mutex_t *mutex);
int alix_cond_timedwait(alix_cond_t *condition, alix_mutex_t *mutex, uint32_t timeout_ms);
int alix_cond_signal(alix_cond_t *condition);
int alix_cond_broadcast(alix_cond_t *condition);

alix_thread_t alix_thread_self(void);
int alix_thread_create(alix_thread_t *thread_out,
                       const char *name,
                       void (*start)(void *),
                       void *arg);
int alix_thread_join(alix_thread_t thread, int *status_out);
int alix_thread_detach(alix_thread_t thread);
void alix_thread_exit(int status) __attribute__((__noreturn__));

#ifdef __cplusplus
}
#endif

#endif
