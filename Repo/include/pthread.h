#include "signal.h"
#ifndef ALIX_PTHREAD_H
#define ALIX_PTHREAD_H

#ifdef TTF_HOST_BUILD
#include_next <pthread.h>
#else
#include "libc.h"
#include "time.h"

typedef uint64_t pthread_t;
typedef alix_tls_key_t pthread_key_t;
typedef alix_once_t pthread_once_t;

#define PTHREAD_CREATE_JOINABLE 0
#define PTHREAD_CREATE_DETACHED 1
#define PTHREAD_MUTEX_NORMAL 0
#define PTHREAD_MUTEX_DEFAULT PTHREAD_MUTEX_NORMAL
#define PTHREAD_MUTEX_RECURSIVE 1
#define PTHREAD_MUTEX_ERRORCHECK 2
#define PTHREAD_PROCESS_PRIVATE 0
#define PTHREAD_PROCESS_SHARED 1
#define PTHREAD_STACK_MIN 16384u
#define PTHREAD_DESTRUCTOR_ITERATIONS 4
#define PTHREAD_CANCELED ((void *)-1)
#define PTHREAD_ONCE_INIT {0}
#define PTHREAD_MUTEX_INITIALIZER {{0},0,0,0,PTHREAD_MUTEX_NORMAL,0x50544D58u}
#define PTHREAD_COND_INITIALIZER {{0},0,CLOCK_REALTIME,0x50544356u}

typedef struct
{
    size_t stack_size;
    size_t guard_size;
    void *stack_address;
    int detach_state;
    uint32_t magic;
} pthread_attr_t;

typedef struct { int type; uint32_t magic; } pthread_mutexattr_t;
typedef struct { clockid_t clock; uint32_t magic; } pthread_condattr_t;

typedef struct
{
    alix_mutex_t gate;
    uint64_t owner;
    uint32_t depth;
    volatile uint32_t waiters;
    int type;
    uint32_t magic;
} pthread_mutex_t;

typedef struct
{
    alix_cond_t native;
    volatile uint32_t waiters;
    clockid_t clock;
    uint32_t magic;
} pthread_cond_t;

/* Native phase-fair read/write locks. Wait records are heap-owned. */
struct alix_rwlock_record;
typedef struct { int shared; uint32_t magic; } pthread_rwlockattr_t;
typedef struct
{
    alix_mutex_t gate;
    alix_cond_t changed;
    uint64_t writer;
    uint32_t readers;
    uint32_t waiting_readers;
    uint32_t waiting_writers;
    uint32_t reader_batch;
    uint32_t magic;
    struct alix_rwlock_record *read_head;
    struct alix_rwlock_record *write_head;
    struct alix_rwlock_record *write_tail;
} pthread_rwlock_t;
#define PTHREAD_RWLOCK_INITIALIZER {{0},{0},0,0,0,0,0,0x50545257u,NULL,NULL,NULL}

#ifdef __cplusplus
extern "C" {
#endif

int pthread_attr_init(pthread_attr_t *attribute);
int pthread_attr_destroy(pthread_attr_t *attribute);
int pthread_attr_setdetachstate(pthread_attr_t *attribute, int state);
int pthread_attr_getdetachstate(const pthread_attr_t *attribute, int *state);
int pthread_attr_setstacksize(pthread_attr_t *attribute, size_t size);
int pthread_attr_getstacksize(const pthread_attr_t *attribute, size_t *size);
int pthread_attr_setguardsize(pthread_attr_t *attribute, size_t size);
int pthread_attr_getguardsize(const pthread_attr_t *attribute, size_t *size);
int pthread_attr_setstack(pthread_attr_t *attribute, void *address, size_t size);
int pthread_attr_getstack(const pthread_attr_t *attribute, void **address, size_t *size);
int pthread_getattr_np(pthread_t thread, pthread_attr_t *attribute);

int pthread_create(pthread_t *thread, const pthread_attr_t *attribute,
                    void *(*start)(void *), void *argument);
int pthread_join(pthread_t thread, void **result);
int pthread_detach(pthread_t thread);
pthread_t pthread_self(void);
int pthread_sigmask(int how, const sigset_t *set, sigset_t *old);
int pthread_kill(pthread_t thread, int number);
int pthread_equal(pthread_t left, pthread_t right);
void pthread_exit(void *result) __attribute__((__noreturn__));
int pthread_setname_np(pthread_t thread, const char *name);
int pthread_getname_np(pthread_t thread, char *name, size_t size);

int pthread_mutexattr_init(pthread_mutexattr_t *attribute);
int pthread_mutexattr_destroy(pthread_mutexattr_t *attribute);
int pthread_mutexattr_settype(pthread_mutexattr_t *attribute, int type);
int pthread_mutexattr_gettype(const pthread_mutexattr_t *attribute, int *type);
int pthread_mutexattr_setpshared(pthread_mutexattr_t *attribute, int shared);
int pthread_mutexattr_getpshared(const pthread_mutexattr_t *attribute, int *shared);
int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attribute);
int pthread_mutex_destroy(pthread_mutex_t *mutex);
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_trylock(pthread_mutex_t *mutex);
int pthread_mutex_unlock(pthread_mutex_t *mutex);

int pthread_condattr_init(pthread_condattr_t *attribute);
int pthread_condattr_destroy(pthread_condattr_t *attribute);
int pthread_condattr_setclock(pthread_condattr_t *attribute, clockid_t clock);
int pthread_condattr_getclock(const pthread_condattr_t *attribute, clockid_t *clock);
int pthread_condattr_setpshared(pthread_condattr_t *attribute, int shared);
int pthread_condattr_getpshared(const pthread_condattr_t *attribute, int *shared);
int pthread_cond_init(pthread_cond_t *condition, const pthread_condattr_t *attribute);
int pthread_cond_destroy(pthread_cond_t *condition);
int pthread_cond_wait(pthread_cond_t *condition, pthread_mutex_t *mutex);
int pthread_cond_timedwait(pthread_cond_t *condition, pthread_mutex_t *mutex,
                           const struct timespec *deadline);
int pthread_cond_signal(pthread_cond_t *condition);
int pthread_cond_broadcast(pthread_cond_t *condition);
int pthread_rwlockattr_init(pthread_rwlockattr_t *attribute);
int pthread_rwlockattr_destroy(pthread_rwlockattr_t *attribute);
int pthread_rwlockattr_setpshared(pthread_rwlockattr_t *attribute, int shared);
int pthread_rwlockattr_getpshared(const pthread_rwlockattr_t *attribute, int *shared);
int pthread_rwlock_init(pthread_rwlock_t *lock, const pthread_rwlockattr_t *attribute);
int pthread_rwlock_destroy(pthread_rwlock_t *lock);
int pthread_rwlock_rdlock(pthread_rwlock_t *lock);
int pthread_rwlock_tryrdlock(pthread_rwlock_t *lock);
int pthread_rwlock_wrlock(pthread_rwlock_t *lock);
int pthread_rwlock_trywrlock(pthread_rwlock_t *lock);
int pthread_rwlock_unlock(pthread_rwlock_t *lock);

int pthread_once(pthread_once_t *once, void (*initialize)(void));
int pthread_key_create(pthread_key_t *key, void (*destroy)(void *));
int pthread_key_delete(pthread_key_t key);
void *pthread_getspecific(pthread_key_t key);
int pthread_setspecific(pthread_key_t key, const void *value);

#ifdef __cplusplus
}
#endif
#endif
#endif
