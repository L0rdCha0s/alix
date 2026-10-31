#include "pthread.h"
#include "userlib.h"
#include "stdlib.h"
#include "errno.h"
#include "serial.h"
#include "unistd.h"

#define WORKERS 8u
#define INCREMENTS 128u

typedef struct shared shared_t;
typedef struct
{
    shared_t *shared;
    pthread_t thread;
    uint64_t token;
    uint32_t index;
    volatile uint32_t finished;
    char name[32];
} worker_t;

struct shared
{
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    pthread_once_t once;
    pthread_key_t key;
    worker_t workers[WORKERS];
    uint32_t ready;
    uint32_t go;
    uint32_t counter;
    volatile uint32_t failed;
    volatile uint32_t destroyed;
    uint32_t initialized;
    pid_t process_id;
    syscall_thread_info_t info;
};

static shared_t *global_shared;
static bool main_passed;
static pthread_mutex_t static_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t static_condition = PTHREAD_COND_INITIALIZER;

#define CHECK(condition, label) do { if (!(condition)) { \
    serial_printf("THREAD_PTHREAD_TEST: FAIL %s\n", label); return 1; } } while (0)

static void initialize_once(void) { ++global_shared->initialized; }

static void destroy_value(void *value)
{
    worker_t *worker = value;
    __atomic_add_fetch(&worker->shared->destroyed, 1, __ATOMIC_ACQ_REL);
    __atomic_store_n(&worker->finished, 1, __ATOMIC_RELEASE);
}

static void *worker_main(void *argument)
{
    worker_t *worker = argument;
    shared_t *shared = worker->shared;
    pthread_attr_t attribute;
    void *stack = NULL;
    size_t size = 0, guard = 0;
    uint8_t local;
    if (getpid() != shared->process_id || !pthread_equal(pthread_self(), worker->thread) ||
        sys_thread_set_affinity(worker->index) != 0 || sys_thread_cpu() != worker->index ||
        pthread_getattr_np(pthread_self(), &attribute) != 0 ||
        pthread_attr_getstack(&attribute, &stack, &size) != 0 ||
        pthread_attr_getguardsize(&attribute, &guard) != 0 || size < 65536 || guard != 4096 ||
        (uintptr_t)&local < (uintptr_t)stack || (uintptr_t)&local >= (uintptr_t)stack + size ||
        pthread_attr_destroy(&attribute) != 0 ||
        pthread_setname_np(pthread_self(), "pthread-worker") != 0 ||
        pthread_getname_np(pthread_self(), worker->name, sizeof(worker->name)) != 0 ||
        strcmp(worker->name, "pthread-worker") != 0 ||
        pthread_setname_np(pthread_self(), "0123456789012345678901234567890123") != ERANGE ||
        pthread_getname_np(pthread_self(), worker->name, 1) != ERANGE ||
        pthread_once(&shared->once, initialize_once) != 0 ||
        pthread_setspecific(shared->key, worker) != 0 || pthread_getspecific(shared->key) != worker)
    {
        __atomic_store_n(&shared->failed, 1, __ATOMIC_RELEASE);
    }
    errno = 500 + (int)worker->index;
    pthread_mutex_lock(&shared->mutex);
    ++shared->ready;
    pthread_cond_broadcast(&shared->condition);
    while (!shared->go) pthread_cond_wait(&shared->condition, &shared->mutex);
    pthread_mutex_unlock(&shared->mutex);
    for (unsigned i = 0; i < INCREMENTS; ++i)
    {
        pthread_mutex_lock(&shared->mutex);
        uint32_t previous = shared->counter;
        if ((i & 7u) == 0) sys_yield();
        shared->counter = previous + 1;
        pthread_mutex_unlock(&shared->mutex);
    }
    if (errno != 500 + (int)worker->index) __atomic_store_n(&shared->failed, 1, __ATOMIC_RELEASE);
    if (worker->index & 1u) pthread_exit(&worker->token);
    return &worker->token;
}

static void *quick_return(void *argument)
{
    worker_t *worker = argument;
    if (worker->thread != pthread_self()) __atomic_store_n(&worker->shared->failed, 1, __ATOMIC_RELEASE);
    return &worker->token;
}

static void *detached_return(void *argument)
{
    worker_t *worker = argument;
    if (pthread_setspecific(worker->shared->key, worker) != 0)
        __atomic_store_n(&worker->shared->failed, 1, __ATOMIC_RELEASE);
    return &worker->token;
}

static void exit_check(void)
{
    serial_printf("THREAD_PTHREAD_TEST: exit %s\n", main_passed ? "PASS" : "FAIL");
    if (!main_passed) sys_exit(1);
}

typedef struct
{
    pthread_t initial;
    pthread_t joiner;
    pthread_t survivor;
    uint64_t result;
    volatile uint32_t joined;
    volatile uint32_t survived;
    volatile uint32_t failed;
} initial_exit_t;
static initial_exit_t *initial_exit;

static void *join_initial(void *unused)
{
    (void)unused;
    void *result = NULL;
    if (pthread_join(initial_exit->initial, &result) != 0 || result != &initial_exit->result)
        __atomic_store_n(&initial_exit->failed, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&initial_exit->joined, 1, __ATOMIC_RELEASE);
    return NULL;
}

static void *survive_initial(void *unused)
{
    (void)unused;
    while (!__atomic_load_n(&initial_exit->joined, __ATOMIC_ACQUIRE)) sys_yield();
    __atomic_store_n(&initial_exit->survived, 1, __ATOMIC_RELEASE);
    return NULL;
}

static void initial_exit_check(void)
{
    bool okay = initial_exit && initial_exit->joined && initial_exit->survived && !initial_exit->failed;
    serial_printf("THREAD_PTHREAD_TEST: initial-exit %s\n", okay ? "PASS" : "FAIL");
    if (!okay) sys_exit(1);
}

static int test_initial_exit(void)
{
    initial_exit = calloc(1, sizeof(*initial_exit));
    CHECK(initial_exit != NULL, "initial exit allocation");
    initial_exit->initial = pthread_self();
    initial_exit->result = 0x123456789ABCDEF0ULL;
    CHECK(atexit(initial_exit_check) == 0, "initial exit callback");
    CHECK(pthread_create(&initial_exit->joiner, NULL, join_initial, NULL) == 0, "initial joiner");
    CHECK(pthread_create(&initial_exit->survivor, NULL, survive_initial, NULL) == 0, "initial survivor");
    pthread_exit(&initial_exit->result);
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "initial-exit") == 0) return test_initial_exit();
    CHECK(atexit(exit_check) == 0, "exit callback");
    shared_t *shared = calloc(1, sizeof(*shared));
    CHECK(shared != NULL, "shared allocation");
    shared->process_id = getpid();
    CHECK(shared->process_id > 0 && sizeof(pid_t) == 4 && sizeof(intptr_t) == sizeof(void *),
          "native process ID and pointer ABI");
    global_shared = shared;
    CHECK(pthread_mutex_init(&shared->mutex, NULL) == 0 && pthread_cond_init(&shared->condition, NULL) == 0,
          "synchronization initialization");
    CHECK(pthread_key_create(&shared->key, destroy_value) == 0, "TSD key");
    CHECK(pthread_join(pthread_self(), NULL) == EDEADLK, "self join");
    CHECK(pthread_mutex_lock(&static_mutex) == 0 && pthread_mutex_trylock(&static_mutex) == EBUSY &&
          pthread_mutex_destroy(&static_mutex) == EBUSY, "static mutex ownership");
    struct timespec expired = {0, 0};
    CHECK(pthread_cond_timedwait(&static_condition, &static_mutex, &expired) == ETIMEDOUT &&
          pthread_mutex_unlock(&static_mutex) == 0, "expired realtime wait reacquires mutex");

    pthread_mutexattr_t mutex_attribute;
    pthread_mutex_t *special = calloc(1, sizeof(*special));
    CHECK(special && pthread_mutexattr_init(&mutex_attribute) == 0, "mutex attribute");
    CHECK(pthread_mutexattr_setpshared(&mutex_attribute, PTHREAD_PROCESS_SHARED) == ENOTSUP,
          "shared mutex is explicit unsupported");
    CHECK(pthread_mutexattr_settype(&mutex_attribute, PTHREAD_MUTEX_RECURSIVE) == 0 &&
          pthread_mutex_init(special, &mutex_attribute) == 0 && pthread_mutex_lock(special) == 0 &&
          pthread_mutex_lock(special) == 0 && pthread_mutex_unlock(special) == 0 &&
          pthread_mutex_unlock(special) == 0 && pthread_mutex_destroy(special) == 0, "recursive mutex");
    CHECK(pthread_mutexattr_settype(&mutex_attribute, PTHREAD_MUTEX_ERRORCHECK) == 0 &&
          pthread_mutex_init(special, &mutex_attribute) == 0 && pthread_mutex_lock(special) == 0 &&
          pthread_mutex_lock(special) == EDEADLK && pthread_mutex_unlock(special) == 0 &&
          pthread_mutex_unlock(special) == EPERM && pthread_mutex_destroy(special) == 0, "errorcheck mutex");
    CHECK(pthread_mutexattr_destroy(&mutex_attribute) == 0, "destroy mutex attribute");
    free(special);

    pthread_condattr_t condition_attribute;
    pthread_cond_t *timed = calloc(1, sizeof(*timed));
    CHECK(timed && pthread_condattr_init(&condition_attribute) == 0 &&
          pthread_condattr_setclock(&condition_attribute, CLOCK_MONOTONIC) == 0 &&
          pthread_cond_init(timed, &condition_attribute) == 0, "monotonic condition");
    struct timespec deadline;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &deadline) == 0, "monotonic clock");
    deadline.tv_nsec += 25000000;
    if (deadline.tv_nsec >= 1000000000) { ++deadline.tv_sec; deadline.tv_nsec -= 1000000000; }
    uint64_t before = sys_monotonic_millis();
    CHECK(pthread_mutex_lock(&shared->mutex) == 0 &&
          pthread_cond_timedwait(timed, &shared->mutex, &deadline) == ETIMEDOUT &&
          pthread_mutex_unlock(&shared->mutex) == 0 && sys_monotonic_millis() - before >= 20,
          "absolute monotonic timeout");
    CHECK(pthread_cond_destroy(timed) == 0 && pthread_condattr_destroy(&condition_attribute) == 0,
          "timed condition destroy");
    free(timed);

    pthread_attr_t attribute;
    CHECK(pthread_attr_init(&attribute) == 0 && pthread_attr_setstacksize(&attribute, 65536) == 0,
          "thread attributes");
    CHECK(pthread_attr_setstacksize(&attribute, PTHREAD_STACK_MIN - 1) == EINVAL &&
          pthread_attr_setguardsize(&attribute, 0) == ENOTSUP, "unsupported attributes");
    for (uint32_t index = 0; index < WORKERS; ++index)
    {
        worker_t *worker = &shared->workers[index];
        worker->shared = shared;
        worker->index = index;
        worker->token = 0x1234567800000000ULL + index;
        CHECK(pthread_create(&worker->thread, &attribute, worker_main, worker) == 0, "worker creation");
    }
    pthread_mutex_lock(&shared->mutex);
    while (shared->ready < WORKERS) pthread_cond_wait(&shared->condition, &shared->mutex);
    shared->go = 1;
    pthread_cond_broadcast(&shared->condition);
    pthread_mutex_unlock(&shared->mutex);
    for (uint32_t index = 0; index < WORKERS; ++index)
    {
        void *result = NULL;
        CHECK(pthread_join(shared->workers[index].thread, &result) == 0 && result == &shared->workers[index].token,
              "64-bit result and join");
    }
    CHECK(!shared->failed && shared->counter == WORKERS * INCREMENTS && shared->initialized == 1 &&
          shared->destroyed == WORKERS, "cross-core locking once and destructors");

    worker_t *quick = &shared->workers[0];
    CHECK(pthread_attr_setstacksize(&attribute, PTHREAD_STACK_MIN) == 0, "minimal stack");
    for (unsigned iteration = 0; iteration < 128; ++iteration)
    {
        void *result = NULL;
        CHECK(pthread_create(&quick->thread, &attribute, quick_return, quick) == 0 &&
              pthread_join(quick->thread, &result) == 0 && result == &quick->token,
              "fast exit creation race");
    }
    CHECK(pthread_attr_setdetachstate(&attribute, PTHREAD_CREATE_DETACHED) == 0, "detached attribute");
    for (unsigned iteration = 0; iteration < 32; ++iteration)
    {
        __atomic_store_n(&quick->finished, 0, __ATOMIC_RELEASE);
        CHECK(pthread_create(&quick->thread, &attribute, detached_return, quick) == 0, "detached creation");
        while (!__atomic_load_n(&quick->finished, __ATOMIC_ACQUIRE) && !shared->failed) sys_yield();
        CHECK(!shared->failed, "detached TSD publication");
        int query;
        while ((query = sys_thread_info(quick->thread, &shared->info)) == 0) sys_yield();
        CHECK(query == -ESRCH, "detached kernel reclamation");
    }
    CHECK(pthread_attr_destroy(&attribute) == 0 && !shared->failed && shared->destroyed == WORKERS + 32,
          "detached lifetime");
    CHECK(pthread_key_delete(shared->key) == 0 && pthread_cond_destroy(&shared->condition) == 0 &&
          pthread_mutex_destroy(&shared->mutex) == 0, "shared cleanup");
    free(shared);
    global_shared = NULL;
    main_passed = true;
    serial_printf("THREAD_PTHREAD_TEST: main PASS workers=8 increments=1024 fast_joins=128 detached=32\n");
    return 0;
}
