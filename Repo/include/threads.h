#ifndef ALIX_THREADS_H
#define ALIX_THREADS_H
#include "pthread.h"

typedef pthread_t thrd_t;
typedef int (*thrd_start_t)(void *);
typedef pthread_key_t tss_t;
typedef void (*tss_dtor_t)(void *);
typedef pthread_once_t once_flag;
typedef pthread_cond_t cnd_t;
typedef struct { pthread_mutex_t native; int type; } mtx_t;
#define ONCE_FLAG_INIT PTHREAD_ONCE_INIT
#define TSS_DTOR_ITERATIONS PTHREAD_DESTRUCTOR_ITERATIONS
#ifndef __cplusplus
#define thread_local _Thread_local
#endif
enum { thrd_success, thrd_busy, thrd_error, thrd_nomem, thrd_timedout };
enum { mtx_plain = 0, mtx_recursive = 1, mtx_timed = 2 };
#ifdef __cplusplus
extern "C" {
#endif
void call_once(once_flag *, void (*)(void));
int cnd_broadcast(cnd_t *);
void cnd_destroy(cnd_t *);
int cnd_init(cnd_t *);
int cnd_signal(cnd_t *);
int cnd_timedwait(cnd_t *, mtx_t *, const struct timespec *);
int cnd_wait(cnd_t *, mtx_t *);
void mtx_destroy(mtx_t *);
int mtx_init(mtx_t *, int);
int mtx_lock(mtx_t *);
int mtx_timedlock(mtx_t *, const struct timespec *);
int mtx_trylock(mtx_t *);
int mtx_unlock(mtx_t *);
int thrd_create(thrd_t *, thrd_start_t, void *);
thrd_t thrd_current(void);
int thrd_detach(thrd_t);
int thrd_equal(thrd_t, thrd_t);
void thrd_exit(int) __attribute__((__noreturn__));
int thrd_join(thrd_t, int *);
int thrd_sleep(const struct timespec *, struct timespec *);
void thrd_yield(void);
int tss_create(tss_t *, tss_dtor_t);
void tss_delete(tss_t);
void *tss_get(tss_t);
int tss_set(tss_t, void *);
#ifdef __cplusplus
}
#endif
#endif
