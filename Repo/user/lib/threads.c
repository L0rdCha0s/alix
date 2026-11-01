#include "threads.h"
#include "stdlib.h"
#include "errno.h"
#include "usyscall.h"

static int thread_result(int error)
{
    if (!error) return thrd_success;
    if (error == ETIMEDOUT) return thrd_timedout;
    if (error == EBUSY) return thrd_busy;
    return thrd_error;
}

typedef struct { thrd_start_t function; void *argument; } thread_start_t;

static void *thread_start(void *opaque)
{
    /* The creator transfers this heap record to the child. The callback's
     * own shared argument must likewise have process lifetime or heap storage. */
    thread_start_t *start = opaque;
    thrd_start_t function = start->function;
    void *argument = start->argument;
    free(start);
    return (void *)(intptr_t)function(argument);
}

int thrd_create(thrd_t *thread, thrd_start_t function, void *argument)
{
    if (!thread || !function) return thrd_error;
    thread_start_t *start = malloc(sizeof(*start));
    if (!start) return thrd_nomem;
    *start = (thread_start_t){function, argument};
    int error = pthread_create(thread, NULL, thread_start, start);
    if (error) free(start);
    return error == ENOMEM || error == EAGAIN ? thrd_nomem : (error ? thrd_error : thrd_success);
}

thrd_t thrd_current(void) { return pthread_self(); }
int thrd_equal(thrd_t a, thrd_t b) { return pthread_equal(a, b); }
int thrd_detach(thrd_t thread) { return thread_result(pthread_detach(thread)); }
void thrd_exit(int result) { pthread_exit((void *)(intptr_t)result); }
int thrd_join(thrd_t thread, int *result)
{
    void *value;
    int error = pthread_join(thread, &value);
    if (!error && result) *result = (int)(intptr_t)value;
    return thread_result(error);
}
int thrd_sleep(const struct timespec *duration, struct timespec *remaining)
{
    if (!nanosleep(duration, remaining)) return 0;
    return errno == EINTR ? -1 : -2;
}
void thrd_yield(void) { (void)sys_yield(); }

void call_once(once_flag *flag, void (*function)(void))
{
    if (pthread_once(flag, function)) __builtin_trap();
}
int tss_create(tss_t *key, tss_dtor_t destroy) { return thread_result(pthread_key_create(key, destroy)); }
void tss_delete(tss_t key) { (void)pthread_key_delete(key); }
void *tss_get(tss_t key) { return pthread_getspecific(key); }
int tss_set(tss_t key, void *value) { return thread_result(pthread_setspecific(key, value)); }

int mtx_init(mtx_t *mutex, int type)
{
    if (!mutex || (type & ~(mtx_recursive | mtx_timed))) return thrd_error;
    pthread_mutexattr_t attribute;
    int error = pthread_mutexattr_init(&attribute);
    if (error) return thread_result(error);
    error = pthread_mutexattr_settype(&attribute,
        type & mtx_recursive ? PTHREAD_MUTEX_RECURSIVE : PTHREAD_MUTEX_NORMAL);
    if (!error) error = pthread_mutex_init(&mutex->native, &attribute);
    (void)pthread_mutexattr_destroy(&attribute);
    if (!error) mutex->type = type;
    return thread_result(error);
}
void mtx_destroy(mtx_t *mutex) { (void)pthread_mutex_destroy(&mutex->native); }
int mtx_lock(mtx_t *mutex) { return thread_result(pthread_mutex_lock(&mutex->native)); }
int mtx_trylock(mtx_t *mutex) { return thread_result(pthread_mutex_trylock(&mutex->native)); }
int mtx_unlock(mtx_t *mutex) { return thread_result(pthread_mutex_unlock(&mutex->native)); }
int mtx_timedlock(mtx_t *mutex, const struct timespec *deadline)
{
    if (!mutex || !(mutex->type & mtx_timed) || !deadline ||
        deadline->tv_nsec < 0 || deadline->tv_nsec >= 1000000000L) return thrd_error;
    for (;;)
    {
        int error = pthread_mutex_trylock(&mutex->native);
        if (error != EBUSY) return thread_result(error);
        struct timespec now;
        if (clock_gettime(CLOCK_REALTIME, &now)) return thrd_error;
        if (now.tv_sec > deadline->tv_sec ||
            (now.tv_sec == deadline->tv_sec && now.tv_nsec >= deadline->tv_nsec)) return thrd_timedout;
        /* Sleep rather than spin. Re-read realtime after every bounded wait,
         * including clock adjustments and interrupted sleeps. */
        struct timespec delay = {0, 1000000L};
        if (now.tv_sec == deadline->tv_sec && deadline->tv_nsec - now.tv_nsec < delay.tv_nsec)
            delay.tv_nsec = deadline->tv_nsec - now.tv_nsec;
        if (nanosleep(&delay, NULL) && errno != EINTR) return thrd_error;
    }
}
int cnd_init(cnd_t *condition)
{
    int error = pthread_cond_init(condition, NULL);
    return error == ENOMEM ? thrd_nomem : (error ? thrd_error : thrd_success);
}
void cnd_destroy(cnd_t *condition) { (void)pthread_cond_destroy(condition); }
int cnd_signal(cnd_t *condition) { return thread_result(pthread_cond_signal(condition)); }
int cnd_broadcast(cnd_t *condition) { return thread_result(pthread_cond_broadcast(condition)); }
int cnd_wait(cnd_t *condition, mtx_t *mutex)
{
    return thread_result(pthread_cond_wait(condition, &mutex->native));
}
int cnd_timedwait(cnd_t *condition, mtx_t *mutex, const struct timespec *deadline)
{
    return thread_result(pthread_cond_timedwait(condition, &mutex->native, deadline));
}
