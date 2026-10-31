#include "pthread.h"
#include "stdlib.h"
#include "errno.h"
#include "serial.h"
#include "usyscall.h"

typedef struct shared shared_t;
typedef struct
{
    shared_t *shared;
    pthread_t thread;
    uint32_t index;
    uint32_t kind;
    volatile uint32_t entered;
    volatile uint32_t release;
    int result;
} worker_t;

struct shared
{
    pthread_rwlock_t lock;
    worker_t workers[8];
    uint64_t value, mirror;
    volatile uint32_t readers, writer, failed;
    uint32_t order[4], order_count;
};

#define CHECK(condition, label) do { if (!(condition)) { \
    serial_printf("THREAD_RWLOCK_TEST: FAIL %s\n", label); return 1; } } while (0)

static void fail(shared_t *shared) { __atomic_store_n(&shared->failed, 1, __ATOMIC_RELEASE); }

static void *phase_worker(void *argument)
{
    worker_t *worker = argument;
    shared_t *shared = worker->shared;
    if (sys_thread_set_affinity(worker->index) != 0) fail(shared);
    worker->result = worker->kind ? pthread_rwlock_wrlock(&shared->lock) : pthread_rwlock_rdlock(&shared->lock);
    if (worker->result) { fail(shared); return NULL; }
    uint32_t slot = __atomic_fetch_add(&shared->order_count, 1, __ATOMIC_ACQ_REL);
    if (slot >= 4) fail(shared); else shared->order[slot] = worker->index;
    __atomic_store_n(&worker->entered, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&worker->release, __ATOMIC_ACQUIRE)) sys_yield();
    if (pthread_rwlock_unlock(&shared->lock) != 0) fail(shared);
    return NULL;
}

static bool wait_counts(shared_t *shared, uint32_t readers, uint32_t writers)
{
    uint64_t start = sys_monotonic_millis();
    do
    {
        alix_mutex_lock(&shared->lock.gate);
        bool ready = shared->lock.waiting_readers == readers && shared->lock.waiting_writers == writers;
        alix_mutex_unlock(&shared->lock.gate);
        if (ready) return true;
        sys_yield();
    } while (!shared->failed && sys_monotonic_millis() - start < 5000);
    return false;
}

static bool wait_entered(worker_t *worker)
{
    uint64_t start = sys_monotonic_millis();
    while (!__atomic_load_n(&worker->entered, __ATOMIC_ACQUIRE))
    {
        if (worker->shared->failed || sys_monotonic_millis() - start >= 5000) return false;
        sys_yield();
    }
    return true;
}

static void *stress_worker(void *argument)
{
    worker_t *worker = argument;
    shared_t *shared = worker->shared;
    if (sys_thread_set_affinity(worker->index) != 0 || sys_thread_cpu() != worker->index) fail(shared);
    errno = 700 + (int)worker->index;
    for (unsigned iteration = 0; iteration < 256; ++iteration)
    {
        if (worker->index & 1u)
        {
            if (pthread_rwlock_wrlock(&shared->lock) != 0) { fail(shared); return NULL; }
            if (__atomic_load_n(&shared->readers, __ATOMIC_ACQUIRE) ||
                __atomic_exchange_n(&shared->writer, 1, __ATOMIC_ACQ_REL)) fail(shared);
            ++shared->value;
            if ((iteration & 7u) == 0) sys_yield();
            shared->mirror = shared->value ^ 0x123456789abcdef0ULL;
            __atomic_store_n(&shared->writer, 0, __ATOMIC_RELEASE);
        }
        else
        {
            if (pthread_rwlock_rdlock(&shared->lock) != 0) { fail(shared); return NULL; }
            __atomic_add_fetch(&shared->readers, 1, __ATOMIC_ACQ_REL);
            if (__atomic_load_n(&shared->writer, __ATOMIC_ACQUIRE) ||
                shared->mirror != (shared->value ^ 0x123456789abcdef0ULL)) fail(shared);
            if ((iteration & 7u) == 0)
            {
                if (pthread_rwlock_rdlock(&shared->lock) != 0 || pthread_rwlock_unlock(&shared->lock) != 0) fail(shared);
                sys_yield();
            }
            __atomic_sub_fetch(&shared->readers, 1, __ATOMIC_ACQ_REL);
        }
        if (pthread_rwlock_unlock(&shared->lock) != 0) { fail(shared); return NULL; }
    }
    if (errno != 700 + (int)worker->index) fail(shared);
    return NULL;
}

int main(void)
{
    shared_t *shared = calloc(1, sizeof(*shared));
    CHECK(shared != NULL, "allocation");
    pthread_rwlockattr_t attribute;
    int process_shared = -1;
    CHECK(pthread_rwlockattr_init(&attribute) == 0 &&
          pthread_rwlockattr_getpshared(&attribute, &process_shared) == 0 &&
          process_shared == PTHREAD_PROCESS_PRIVATE &&
          pthread_rwlockattr_setpshared(&attribute, PTHREAD_PROCESS_SHARED) == ENOTSUP &&
          pthread_rwlock_init(&shared->lock, &attribute) == 0 &&
          pthread_rwlockattr_destroy(&attribute) == 0, "attributes");
    CHECK(pthread_rwlock_rdlock(&shared->lock) == 0, "initial reader");
    for (unsigned index = 0; index < 4; ++index)
    {
        shared->workers[index].shared = shared;
        shared->workers[index].index = index + 1;
        shared->workers[index].kind = (index & 1u) == 0;
    }
    worker_t *a = &shared->workers[0], *b = &shared->workers[1];
    worker_t *c = &shared->workers[2], *d = &shared->workers[3];
    CHECK(pthread_create(&a->thread, NULL, phase_worker, a) == 0 && wait_counts(shared, 0, 1), "queued writer");
    CHECK(pthread_rwlock_rdlock(&shared->lock) == 0 && pthread_rwlock_tryrdlock(&shared->lock) == 0 &&
          pthread_rwlock_unlock(&shared->lock) == 0 && pthread_rwlock_unlock(&shared->lock) == 0,
          "recursive reader with writer queued");
    CHECK(pthread_rwlock_wrlock(&shared->lock) == EDEADLK &&
          pthread_rwlock_trywrlock(&shared->lock) == EBUSY && pthread_rwlock_destroy(&shared->lock) == EBUSY,
          "upgrade and active destruction");
    CHECK(pthread_create(&b->thread, NULL, phase_worker, b) == 0 && wait_counts(shared, 1, 1), "queued reader");
    CHECK(pthread_create(&c->thread, NULL, phase_worker, c) == 0 && wait_counts(shared, 1, 2), "FIFO writer");
    CHECK(pthread_rwlock_unlock(&shared->lock) == 0 && wait_entered(a), "first writer progress");
    CHECK(pthread_rwlock_unlock(&shared->lock) == EPERM && pthread_rwlock_tryrdlock(&shared->lock) == EBUSY,
          "writer ownership");
    __atomic_store_n(&a->release, 1, __ATOMIC_RELEASE);
    CHECK(wait_entered(b), "reader cohort progress");
    CHECK(pthread_rwlock_unlock(&shared->lock) == EPERM, "reader ownership");
    CHECK(pthread_create(&d->thread, NULL, phase_worker, d) == 0 && wait_counts(shared, 1, 1), "late reader queues");
    CHECK(!d->entered && !c->entered, "cohort exclusion");
    __atomic_store_n(&b->release, 1, __ATOMIC_RELEASE);
    CHECK(wait_entered(c) && !d->entered, "next writer precedes late reader");
    __atomic_store_n(&c->release, 1, __ATOMIC_RELEASE);
    CHECK(wait_entered(d), "late reader eventually runs");
    __atomic_store_n(&d->release, 1, __ATOMIC_RELEASE);
    for (unsigned index = 0; index < 4; ++index)
        CHECK(pthread_join(shared->workers[index].thread, NULL) == 0, "phase join");
    CHECK(shared->order_count == 4 && shared->order[0] == 1 && shared->order[1] == 2 &&
          shared->order[2] == 3 && shared->order[3] == 4 && !shared->failed, "fair phase order");
    shared->mirror = 0x123456789abcdef0ULL;
    for (unsigned index = 0; index < 8; ++index)
    {
        worker_t *worker = &shared->workers[index];
        worker->shared = shared;
        worker->index = index;
        CHECK(pthread_create(&worker->thread, NULL, stress_worker, worker) == 0, "stress creation");
    }
    for (unsigned index = 0; index < 8; ++index)
        CHECK(pthread_join(shared->workers[index].thread, NULL) == 0, "stress join");
    CHECK(!shared->failed && shared->value == 1024 && pthread_rwlock_destroy(&shared->lock) == 0,
          "exclusive writers and shared readers");
    free(shared);
    serial_printf("THREAD_RWLOCK_TEST: PASS cpus=8 writes=1024 recursion=1 fifo=1 cohorts=1\n");
    return 0;
}
