#include "pthread.h"
#include "usyscall.h"
#include "errno.h"
#include "serial.h"

#define ATTRIBUTE_MAGIC 0x50544154u
#define MUTEX_ATTRIBUTE_MAGIC 0x50544D41u
#define CONDITION_ATTRIBUTE_MAGIC 0x50544341u
#define MUTEX_MAGIC 0x50544D58u
#define CONDITION_MAGIC 0x50544356u
#define DEFAULT_STACK_BYTES (256u * 1024u)
#define GUARD_BYTES 4096u

static int pthread_status(int native)
{
    return native < 0 ? -native : native;
}

int pthread_attr_init(pthread_attr_t *attribute)
{
    if (!attribute) return EINVAL;
    *attribute = (pthread_attr_t){DEFAULT_STACK_BYTES, GUARD_BYTES, NULL,
                                 PTHREAD_CREATE_JOINABLE, ATTRIBUTE_MAGIC};
    return 0;
}

int pthread_attr_destroy(pthread_attr_t *attribute)
{
    if (!attribute || attribute->magic != ATTRIBUTE_MAGIC) return EINVAL;
    attribute->magic = 0;
    return 0;
}

int pthread_attr_setdetachstate(pthread_attr_t *attribute, int state)
{
    if (!attribute || attribute->magic != ATTRIBUTE_MAGIC ||
        (state != PTHREAD_CREATE_JOINABLE && state != PTHREAD_CREATE_DETACHED)) return EINVAL;
    attribute->detach_state = state;
    return 0;
}

int pthread_attr_getdetachstate(const pthread_attr_t *attribute, int *state)
{
    if (!attribute || attribute->magic != ATTRIBUTE_MAGIC || !state) return EINVAL;
    *state = attribute->detach_state;
    return 0;
}

int pthread_attr_setstacksize(pthread_attr_t *attribute, size_t size)
{
    if (!attribute || attribute->magic != ATTRIBUTE_MAGIC || size < PTHREAD_STACK_MIN ||
        size > (size_t)-1 - (GUARD_BYTES - 1)) return EINVAL;
    attribute->stack_size = size;
    return 0;
}

int pthread_attr_getstacksize(const pthread_attr_t *attribute, size_t *size)
{
    if (!attribute || attribute->magic != ATTRIBUTE_MAGIC || !size) return EINVAL;
    *size = attribute->stack_size;
    return 0;
}

int pthread_attr_setguardsize(pthread_attr_t *attribute, size_t size)
{
    if (!attribute || attribute->magic != ATTRIBUTE_MAGIC || size > (size_t)-1 - (GUARD_BYTES - 1)) return EINVAL;
    /* The current kernel reserves one guard page per auxiliary allocation. */
    if (size == 0 || size > GUARD_BYTES) return ENOTSUP;
    attribute->guard_size = size;
    return 0;
}

int pthread_attr_getguardsize(const pthread_attr_t *attribute, size_t *size)
{
    if (!attribute || attribute->magic != ATTRIBUTE_MAGIC || !size) return EINVAL;
    *size = attribute->guard_size;
    return 0;
}

int pthread_attr_setstack(pthread_attr_t *attribute, void *address, size_t size)
{
    if (!attribute || attribute->magic != ATTRIBUTE_MAGIC || !address || size < PTHREAD_STACK_MIN) return EINVAL;
    return ENOTSUP; /* Kernel-managed stacks only; never pretend caller memory is used. */
}

int pthread_attr_getstack(const pthread_attr_t *attribute, void **address, size_t *size)
{
    if (!attribute || attribute->magic != ATTRIBUTE_MAGIC || !address || !size) return EINVAL;
    *address = attribute->stack_address;
    *size = attribute->stack_size;
    return 0;
}

pthread_t pthread_self(void) { return sys_thread_self(); }
int pthread_equal(pthread_t left, pthread_t right) { return left == right; }

int pthread_mutexattr_init(pthread_mutexattr_t *attribute)
{
    if (!attribute) return EINVAL;
    *attribute = (pthread_mutexattr_t){PTHREAD_MUTEX_NORMAL, MUTEX_ATTRIBUTE_MAGIC};
    return 0;
}

int pthread_mutexattr_destroy(pthread_mutexattr_t *attribute)
{
    if (!attribute || attribute->magic != MUTEX_ATTRIBUTE_MAGIC) return EINVAL;
    attribute->magic = 0;
    return 0;
}

int pthread_mutexattr_settype(pthread_mutexattr_t *attribute, int type)
{
    if (!attribute || attribute->magic != MUTEX_ATTRIBUTE_MAGIC ||
        (type != PTHREAD_MUTEX_NORMAL && type != PTHREAD_MUTEX_RECURSIVE && type != PTHREAD_MUTEX_ERRORCHECK)) return EINVAL;
    attribute->type = type;
    return 0;
}

int pthread_mutexattr_gettype(const pthread_mutexattr_t *attribute, int *type)
{
    if (!attribute || attribute->magic != MUTEX_ATTRIBUTE_MAGIC || !type) return EINVAL;
    *type = attribute->type;
    return 0;
}

int pthread_mutexattr_setpshared(pthread_mutexattr_t *attribute, int shared)
{
    if (!attribute || attribute->magic != MUTEX_ATTRIBUTE_MAGIC) return EINVAL;
    if (shared == PTHREAD_PROCESS_PRIVATE) return 0;
    return shared == PTHREAD_PROCESS_SHARED ? ENOTSUP : EINVAL;
}

int pthread_mutexattr_getpshared(const pthread_mutexattr_t *attribute, int *shared)
{
    if (!attribute || attribute->magic != MUTEX_ATTRIBUTE_MAGIC || !shared) return EINVAL;
    *shared = PTHREAD_PROCESS_PRIVATE;
    return 0;
}

int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attribute)
{
    if (!mutex || (attribute && attribute->magic != MUTEX_ATTRIBUTE_MAGIC)) return EINVAL;
    memset(mutex, 0, sizeof(*mutex));
    mutex->type = attribute ? attribute->type : PTHREAD_MUTEX_NORMAL;
    mutex->magic = MUTEX_MAGIC;
    return 0;
}

int pthread_mutex_destroy(pthread_mutex_t *mutex)
{
    if (!mutex || mutex->magic != MUTEX_MAGIC) return EINVAL;
    if (__atomic_load_n(&mutex->gate.state, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&mutex->waiters, __ATOMIC_ACQUIRE)) return EBUSY;
    mutex->magic = 0;
    return 0;
}

int pthread_mutex_lock(pthread_mutex_t *mutex)
{
    if (!mutex || mutex->magic != MUTEX_MAGIC) return EINVAL;
    uint64_t self = pthread_self();
    if (__atomic_load_n(&mutex->owner, __ATOMIC_ACQUIRE) == self)
    {
        if (mutex->type == PTHREAD_MUTEX_ERRORCHECK) return EDEADLK;
        if (mutex->type == PTHREAD_MUTEX_RECURSIVE)
        {
            if (mutex->depth == (uint32_t)-1) return EAGAIN;
            ++mutex->depth;
            return 0;
        }
    }
    __atomic_add_fetch(&mutex->waiters, 1, __ATOMIC_RELAXED);
    alix_mutex_lock(&mutex->gate);
    __atomic_sub_fetch(&mutex->waiters, 1, __ATOMIC_RELAXED);
    mutex->depth = 1;
    __atomic_store_n(&mutex->owner, self, __ATOMIC_RELEASE);
    return 0;
}

int pthread_mutex_trylock(pthread_mutex_t *mutex)
{
    if (!mutex || mutex->magic != MUTEX_MAGIC) return EINVAL;
    uint64_t self = pthread_self();
    if (mutex->type == PTHREAD_MUTEX_RECURSIVE &&
        __atomic_load_n(&mutex->owner, __ATOMIC_ACQUIRE) == self)
    {
        if (mutex->depth == (uint32_t)-1) return EAGAIN;
        ++mutex->depth;
        return 0;
    }
    if (!alix_mutex_trylock(&mutex->gate)) return EBUSY;
    mutex->depth = 1;
    __atomic_store_n(&mutex->owner, self, __ATOMIC_RELEASE);
    return 0;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
    if (!mutex || mutex->magic != MUTEX_MAGIC) return EINVAL;
    if (__atomic_load_n(&mutex->owner, __ATOMIC_ACQUIRE) != pthread_self() || !mutex->depth) return EPERM;
    if (--mutex->depth) return 0;
    __atomic_store_n(&mutex->owner, 0, __ATOMIC_RELEASE);
    alix_mutex_unlock(&mutex->gate);
    return 0;
}

int pthread_condattr_init(pthread_condattr_t *attribute)
{
    if (!attribute) return EINVAL;
    *attribute = (pthread_condattr_t){CLOCK_REALTIME, CONDITION_ATTRIBUTE_MAGIC};
    return 0;
}

int pthread_condattr_destroy(pthread_condattr_t *attribute)
{
    if (!attribute || attribute->magic != CONDITION_ATTRIBUTE_MAGIC) return EINVAL;
    attribute->magic = 0;
    return 0;
}

int pthread_condattr_setclock(pthread_condattr_t *attribute, clockid_t clock)
{
    if (!attribute || attribute->magic != CONDITION_ATTRIBUTE_MAGIC ||
        (clock != CLOCK_REALTIME && clock != CLOCK_MONOTONIC)) return EINVAL;
    attribute->clock = clock;
    return 0;
}

int pthread_condattr_getclock(const pthread_condattr_t *attribute, clockid_t *clock)
{
    if (!attribute || attribute->magic != CONDITION_ATTRIBUTE_MAGIC || !clock) return EINVAL;
    *clock = attribute->clock;
    return 0;
}

int pthread_condattr_setpshared(pthread_condattr_t *attribute, int shared)
{
    if (!attribute || attribute->magic != CONDITION_ATTRIBUTE_MAGIC) return EINVAL;
    if (shared == PTHREAD_PROCESS_PRIVATE) return 0;
    return shared == PTHREAD_PROCESS_SHARED ? ENOTSUP : EINVAL;
}

int pthread_condattr_getpshared(const pthread_condattr_t *attribute, int *shared)
{
    if (!attribute || attribute->magic != CONDITION_ATTRIBUTE_MAGIC || !shared) return EINVAL;
    *shared = PTHREAD_PROCESS_PRIVATE;
    return 0;
}

int pthread_cond_init(pthread_cond_t *condition, const pthread_condattr_t *attribute)
{
    if (!condition || (attribute && attribute->magic != CONDITION_ATTRIBUTE_MAGIC)) return EINVAL;
    memset(condition, 0, sizeof(*condition));
    condition->clock = attribute ? attribute->clock : CLOCK_REALTIME;
    condition->magic = CONDITION_MAGIC;
    return 0;
}

int pthread_cond_destroy(pthread_cond_t *condition)
{
    if (!condition || condition->magic != CONDITION_MAGIC) return EINVAL;
    if (__atomic_load_n(&condition->waiters, __ATOMIC_ACQUIRE)) return EBUSY;
    condition->magic = 0;
    return 0;
}

static int condition_wait_ms(pthread_cond_t *condition, pthread_mutex_t *mutex, uint32_t timeout)
{
    if (!condition || condition->magic != CONDITION_MAGIC || !mutex || mutex->magic != MUTEX_MAGIC) return EINVAL;
    uint64_t self = pthread_self();
    if (__atomic_load_n(&mutex->owner, __ATOMIC_ACQUIRE) != self) return EPERM;
    /* A recursive mutex held more than once cannot be completely released by
     * the condition operation; report this instead of deadlocking secretly. */
    if (mutex->depth != 1) return EINVAL;
    __atomic_add_fetch(&condition->waiters, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&mutex->waiters, 1, __ATOMIC_RELAXED);
    mutex->depth = 0;
    __atomic_store_n(&mutex->owner, 0, __ATOMIC_RELEASE);
    int result = alix_cond_timedwait(&condition->native, &mutex->gate, timeout);
    mutex->depth = 1;
    __atomic_store_n(&mutex->owner, self, __ATOMIC_RELEASE);
    __atomic_sub_fetch(&mutex->waiters, 1, __ATOMIC_RELAXED);
    __atomic_sub_fetch(&condition->waiters, 1, __ATOMIC_RELAXED);
    return pthread_status(result);
}

int pthread_cond_wait(pthread_cond_t *condition, pthread_mutex_t *mutex)
{
    return condition_wait_ms(condition, mutex, ALIX_WAIT_FOREVER);
}

static int deadline_remaining(clockid_t clock, const struct timespec *deadline, uint32_t *milliseconds)
{
    struct timespec now;
    int saved_errno = errno;
    int status = clock_gettime(clock, &now);
    int error = errno;
    errno = saved_errno;
    if (status != 0) return error ? error : EINVAL;
    if (deadline->tv_sec < now.tv_sec ||
        (deadline->tv_sec == now.tv_sec && deadline->tv_nsec <= now.tv_nsec))
    {
        *milliseconds = 0;
        return 0;
    }
    uint64_t seconds = (uint64_t)deadline->tv_sec - (uint64_t)now.tv_sec;
    int64_t nanos = deadline->tv_nsec - now.tv_nsec;
    if (nanos < 0) { --seconds; nanos += 1000000000; }
    const uint32_t maximum = (uint32_t)-2;
    uint64_t duration = seconds > maximum / 1000u ? maximum :
                         seconds * 1000u + ((uint64_t)nanos + 999999u) / 1000000u;
    if (duration > maximum) duration = maximum;
    /* Recheck realtime deadlines after clock adjustments. The unchanged
     * condition sequence lets us continue without losing an intervening wake. */
    if (clock == CLOCK_REALTIME && duration > 100u) duration = 100u;
    *milliseconds = (uint32_t)duration;
    return 0;
}

int pthread_cond_timedwait(pthread_cond_t *condition, pthread_mutex_t *mutex,
                           const struct timespec *deadline)
{
    if (!condition || condition->magic != CONDITION_MAGIC || !deadline ||
        deadline->tv_nsec < 0 || deadline->tv_nsec >= 1000000000) return EINVAL;
    for (;;)
    {
        uint32_t remaining;
        int status = deadline_remaining(condition->clock, deadline, &remaining);
        if (status != 0) return status;
        uint32_t sequence = __atomic_load_n(&condition->native.sequence, __ATOMIC_ACQUIRE);
        status = condition_wait_ms(condition, mutex, remaining);
        if (status != ETIMEDOUT) return status;
        uint32_t after;
        status = deadline_remaining(condition->clock, deadline, &after);
        if (status != 0) return status;
        if (after == 0) return ETIMEDOUT;
        if (__atomic_load_n(&condition->native.sequence, __ATOMIC_ACQUIRE) != sequence) return 0;
    }
}

int pthread_cond_signal(pthread_cond_t *condition)
{
    if (!condition || condition->magic != CONDITION_MAGIC) return EINVAL;
    return pthread_status(alix_cond_signal(&condition->native));
}

int pthread_cond_broadcast(pthread_cond_t *condition)
{
    if (!condition || condition->magic != CONDITION_MAGIC) return EINVAL;
    return pthread_status(alix_cond_broadcast(&condition->native));
}

int pthread_once(pthread_once_t *once, void (*initialize)(void))
{
    return pthread_status(alix_call_once(once, initialize));
}

int pthread_key_create(pthread_key_t *key, void (*destroy)(void *))
{
    return pthread_status(alix_tls_key_create(key, destroy));
}

int pthread_key_delete(pthread_key_t key) { return pthread_status(alix_tls_key_delete(key)); }
void *pthread_getspecific(pthread_key_t key) { return alix_tls_get(key); }
int pthread_setspecific(pthread_key_t key, const void *value) { return pthread_status(alix_tls_set(key, (void *)value)); }

typedef struct pthread_control
{
    struct pthread_control *next;
    pthread_t tid;
    void *(*start)(void *);
    void *argument;
    void *result;
    uint32_t references;
    volatile uint32_t published;
    bool heap_owned;
    bool in_registry;
    bool completed;
    bool detached;
    bool join_claimed;
    bool canceled_creation;
} pthread_control_t;

static alix_mutex_t registry_mutex;
static pthread_control_t *registry;
static pthread_control_t initial_thread_control;
static bool initial_thread_registered;
static _Thread_local pthread_control_t *self_control;
static _Thread_local bool exiting;
static _Thread_local bool control_released;
static _Thread_local void *exit_result;

static pthread_control_t *control_drop_locked(pthread_control_t *control, uint32_t count)
{
    if (control->references < count)
    {
        __builtin_trap();
    }
    control->references -= count;
    return control->references == 0 && control->heap_owned ? control : NULL;
}

static void control_unlink_locked(pthread_control_t *control)
{
    pthread_control_t **cursor = &registry;
    while (*cursor && *cursor != control) cursor = &(*cursor)->next;
    if (!*cursor || !control->in_registry) __builtin_trap();
    *cursor = control->next;
    control->next = NULL;
    control->in_registry = false;
}

static pthread_control_t *control_find_locked(pthread_t tid)
{
    for (pthread_control_t *control = registry; control; control = control->next)
    {
        if (control->tid == tid) return control;
    }
    /* Initial-thread pthread_exit/join must not depend on allocating a control
     * block during exit. Its storage lives for the process's entire lifetime. */
    if (!initial_thread_registered)
    {
        syscall_thread_info_t info;
        if (sys_thread_info(tid, &info) == 0 && (info.flags & SYSCALL_THREAD_INFO_MAIN))
        {
            pthread_control_t *control = &initial_thread_control;
            memset(control, 0, sizeof(*control));
            control->tid = info.tid;
            control->completed = info.state == SYSCALL_THREAD_STATE_ZOMBIE;
            control->references = control->completed ? 1 : 2; /* Registry plus live thread. */
            control->published = 1;
            control->detached = (info.flags & SYSCALL_THREAD_INFO_DETACHED) != 0;
            control->in_registry = true;
            control->next = registry;
            registry = control;
            initial_thread_registered = true;
            return control;
        }
    }
    return NULL;
}

static void pthread_start(void *argument) __attribute__((noreturn));
static void pthread_start(void *argument)
{
    pthread_control_t *control = argument;
    self_control = control;
    /* A child may run before thread_create returns its ID. Its heap-owned
     * publication word closes that race without retaining the parent's stack. */
    while (!__atomic_load_n(&control->published, __ATOMIC_ACQUIRE))
    {
        int result = sys_futex_wait(&control->published, 0, ALIX_WAIT_FOREVER);
        if (result != SYSCALL_FUTEX_OK && result != SYSCALL_FUTEX_AGAIN && result != -EINTR) __builtin_trap();
    }
    void *result = control->canceled_creation ? NULL : control->start(control->argument);
    pthread_exit(result);
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attribute,
                    void *(*start)(void *), void *argument)
{
    if (!thread || !start || (attribute && attribute->magic != ATTRIBUTE_MAGIC)) return EINVAL;
    size_t stack_size = attribute ? attribute->stack_size : DEFAULT_STACK_BYTES;
    int detach_state = attribute ? attribute->detach_state : PTHREAD_CREATE_JOINABLE;
    if (stack_size < PTHREAD_STACK_MIN || stack_size > (size_t)-1 - (GUARD_BYTES - 1) ||
        (detach_state != PTHREAD_CREATE_JOINABLE && detach_state != PTHREAD_CREATE_DETACHED)) return EINVAL;
    if (attribute && (attribute->stack_address || attribute->guard_size == 0 ||
                       attribute->guard_size > GUARD_BYTES)) return ENOTSUP;

    pthread_control_t *control = calloc(1, sizeof(*control));
    if (!control) return EAGAIN;
    control->start = start;
    control->argument = argument;
    control->heap_owned = true;
    control->references = 2; /* Creator and child; child is not yet published. */
    int64_t tid = sys_thread_create((uintptr_t)pthread_start, (uintptr_t)control,
                                    stack_size, "pthread");
    if (tid < 0)
    {
        free(control);
        return EAGAIN;
    }

    alix_mutex_lock(&registry_mutex);
    control->tid = (pthread_t)tid;
    control->in_registry = true;
    control->next = registry;
    registry = control;
    ++control->references;
    int detach_result = 0;
    if (detach_state == PTHREAD_CREATE_DETACHED)
    {
        detach_result = sys_thread_detach(control->tid);
        if (detach_result == 0) control->detached = true;
        else control->canceled_creation = true;
    }
    if (detach_result == 0) *thread = control->tid;
    __atomic_store_n(&control->published, 1, __ATOMIC_RELEASE);
    alix_mutex_unlock(&registry_mutex);
    if (sys_futex_wake(&control->published, (uint32_t)-1) < 0) __builtin_trap();

    if (detach_result != 0)
    {
        /* Do not execute a user callback after reporting creation failure. */
        (void)pthread_join(control->tid, NULL);
    }
    alix_mutex_lock(&registry_mutex);
    pthread_control_t *dead = control_drop_locked(control, 1);
    alix_mutex_unlock(&registry_mutex);
    free(dead);
    return detach_result == 0 ? 0 : EAGAIN;
}

int pthread_join(pthread_t thread, void **result)
{
    if (!thread) return ESRCH;
    if (thread == pthread_self()) return EDEADLK;
    alix_mutex_lock(&registry_mutex);
    pthread_control_t *control = control_find_locked(thread);
    if (!control)
    {
        alix_mutex_unlock(&registry_mutex);
        return ESRCH;
    }
    if (control->detached || control->join_claimed)
    {
        alix_mutex_unlock(&registry_mutex);
        return EINVAL;
    }
    control->join_claimed = true;
    ++control->references;
    alix_mutex_unlock(&registry_mutex);

    int joined = sys_thread_join(thread, NULL);
    alix_mutex_lock(&registry_mutex);
    pthread_control_t *dead = NULL;
    if (joined < 0)
    {
        control->join_claimed = false;
        dead = control_drop_locked(control, 1);
    }
    else
    {
        /* pthread-created threads always publish before native exit. An
         * initial thread that used the native exit API has no pointer result. */
        uint32_t released = control->completed ? 2 : 3;
        void *value = control->completed ? control->result : NULL;
        control_unlink_locked(control);
        dead = control_drop_locked(control, released); /* Registry, join, possibly native thread. */
        if (result) *result = value;
    }
    alix_mutex_unlock(&registry_mutex);
    free(dead);
    return joined < 0 ? ESRCH : 0;
}

int pthread_detach(pthread_t thread)
{
    if (!thread) return ESRCH;
    alix_mutex_lock(&registry_mutex);
    pthread_control_t *control = control_find_locked(thread);
    if (!control)
    {
        alix_mutex_unlock(&registry_mutex);
        return ESRCH;
    }
    if (control->detached || control->join_claimed)
    {
        alix_mutex_unlock(&registry_mutex);
        return EINVAL;
    }
    int result = sys_thread_detach(thread);
    pthread_control_t *dead = NULL;
    if (result == 0)
    {
        control->detached = true;
        if (control->completed)
        {
            control_unlink_locked(control);
            dead = control_drop_locked(control, 1);
        }
    }
    alix_mutex_unlock(&registry_mutex);
    free(dead);
    return result < 0 ? ESRCH : 0;
}

void pthread_exit(void *result)
{
    if (!exiting)
    {
        exiting = true;
        exit_result = result;
        if (!self_control)
        {
            alix_mutex_lock(&registry_mutex);
            self_control = control_find_locked(pthread_self());
            alix_mutex_unlock(&registry_mutex);
        }
        alix_thread_run_tls_destructors();
    }
    if (!control_released)
    {
        control_released = true;
        pthread_control_t *control = self_control;
        self_control = NULL;
        if (control)
        {
            alix_mutex_lock(&registry_mutex);
            control->result = exit_result;
            control->completed = true;
            uint32_t released = 1; /* Child/initial-thread reference. */
            if (control->detached)
            {
                control_unlink_locked(control);
                ++released;
            }
            pthread_control_t *dead = control_drop_locked(control, released);
            alix_mutex_unlock(&registry_mutex);
            free(dead);
        }
    }
    int prepared = sys_thread_prepare_exit();
    if (prepared < 0) __builtin_trap();
    if (prepared == 1)
    {
        /* The kernel selects one final live thread to run process callbacks. */
        exit(0);
    }
    sys_thread_exit(0);
}

int pthread_getattr_np(pthread_t thread, pthread_attr_t *attribute)
{
    if (!thread || !attribute) return EINVAL;
    syscall_thread_info_t info;
    int result = sys_thread_info(thread, &info);
    if (result != 0) return pthread_status(result);
    *attribute = (pthread_attr_t){(size_t)info.stack_size, (size_t)info.guard_size,
                                 (void *)(uintptr_t)info.stack_base,
                                 (info.flags & SYSCALL_THREAD_INFO_DETACHED) ? PTHREAD_CREATE_DETACHED : PTHREAD_CREATE_JOINABLE,
                                 ATTRIBUTE_MAGIC};
    return 0;
}

int pthread_setname_np(pthread_t thread, const char *name)
{
    if (!thread || !name) return EINVAL;
    return pthread_status(sys_thread_set_name(thread, name));
}

int pthread_getname_np(pthread_t thread, char *name, size_t size)
{
    if (!thread || !name || !size) return EINVAL;
    syscall_thread_info_t info;
    int result = sys_thread_info(thread, &info);
    if (result != 0) return pthread_status(result);
    size_t length = strlen(info.name) + 1;
    if (length > size) return ERANGE;
    memcpy(name, info.name, length);
    return 0;
}
