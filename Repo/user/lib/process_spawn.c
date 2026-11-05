#include "alix_process.h"
#include "sys/wait.h"
#include "usyscall.h"
#include "errno.h"
#include "stdlib.h"
#include "string.h"
#include "stdarg.h"
#include "alix_mutex.h"

static pid_t process_result(int64_t result)
{
    if (result < 0) { errno = (int)-result; return -1; }
    return (pid_t)result;
}

typedef struct { void (*prepare)(void), (*parent)(void), (*child)(void); } fork_callback_t;
static fork_callback_t fork_callbacks[64];
static size_t fork_callback_count;
static alix_mutex_t fork_callback_lock;
extern int __alix_owned_process_runtime(void);
extern void __alix_fork_prepare(void), __alix_fork_parent(void), __alix_fork_child(void);

int pthread_atfork(void (*prepare)(void), void (*parent)(void), void (*child)(void))
{
    alix_mutex_lock(&fork_callback_lock);
    int error = fork_callback_count == 64 ? ENOMEM : 0;
    if (!error) fork_callbacks[fork_callback_count++] = (fork_callback_t){prepare, parent, child};
    alix_mutex_unlock(&fork_callback_lock);
    return error;
}

pid_t fork(void)
{
    if (!__alix_owned_process_runtime()) { errno = ENOTSUP; return -1; }
    fork_callback_t *callbacks = malloc(sizeof(fork_callbacks));
    if (!callbacks) { errno = ENOMEM; return -1; }
    alix_mutex_lock(&fork_callback_lock);
    size_t count = fork_callback_count;
    memcpy(callbacks, fork_callbacks, count * sizeof(*callbacks));
    alix_mutex_unlock(&fork_callback_lock);
    for (size_t i = count; i; --i) if (callbacks[i-1].prepare) callbacks[i-1].prepare();
    __alix_fork_prepare();
    int64_t result = sys_process(SYSCALL_PROCESS_FORK, 0, 0, 0);
    if (!result) { __alix_fork_child(); alix_mutex_init(&fork_callback_lock); }
    else __alix_fork_parent();
    for (size_t i = 0; i < count; ++i)
    {
        void (*callback)(void) = result ? callbacks[i].parent : callbacks[i].child;
        if (callback) callback();
    }
    free(callbacks);
    return process_result(result);
}

pid_t alix_spawn_argv(const char *path, char *const argv[])
{
    return process_result(sys_process(SYSCALL_PROCESS_SPAWN, (uintptr_t)path, (uintptr_t)argv, 0));
}

pid_t waitpid(pid_t pid, int *status, int flags)
{
    return process_result(sys_process(SYSCALL_PROCESS_WAIT, (uint64_t)(int64_t)pid,
                                       (uintptr_t)status, (uint64_t)(int64_t)flags));
}

pid_t wait(int *status) { return waitpid(-1, status, 0); }

int waitid(idtype_t type, id_t id, siginfo_t *info, int flags)
{
    uint64_t selector = ((uint64_t)(uint32_t)type << 32) | (uint32_t)id;
    int64_t result = sys_process(SYSCALL_PROCESS_WAIT_INFO, selector,
                                 (uintptr_t)info, (uint64_t)(int64_t)flags);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
}

int execve(const char *path, char *const argv[], char *const environment[])
{
    if (!__alix_owned_process_runtime()) { errno = ENOTSUP; return -1; }
    int64_t result = sys_process(SYSCALL_PROCESS_EXEC, (uintptr_t)path,
        (uintptr_t)argv, (uintptr_t)environment);
    errno = result < 0 ? (int)-result : EIO;
    return -1;
}

int execv(const char *path, char *const argv[])
{
    char **environment = alix_environment_copy();
    if (!environment) return -1;
    execve(path, argv, environment);
    int error = errno;
    alix_environment_free(environment);
    errno = error;
    return -1;
}

int execvp(const char *file, char *const argv[])
{
    if (!file || !*file) { errno = ENOENT; return -1; }
    if (strchr(file, '/')) return execv(file, argv);
    char **environment = alix_environment_copy();
    if (!environment) return -1;
    const char *path = "/bin:/usr/bin";
    for (size_t i = 0; environment[i]; ++i)
        if (!strncmp(environment[i], "PATH=", 5)) { path = environment[i] + 5; break; }
    size_t length = strlen(file);
    char *candidate = malloc(4096);
    int error = candidate ? ENOENT : ENOMEM;
    bool denied = false;
    while (candidate)
    {
        const char *separator = strchr(path, ':');
        size_t prefix = separator ? (size_t)(separator - path) : strlen(path);
        if (prefix + (prefix != 0) + length + 1 > 4096) { error = ENAMETOOLONG; break; }
        if (prefix) { memcpy(candidate, path, prefix); candidate[prefix++] = '/'; }
        memcpy(candidate + prefix, file, length + 1);
        execve(candidate, argv, environment);
        error = errno;
        if (error == EACCES) denied = true;
        else if (error != ENOENT && error != ENOTDIR) break;
        if (!separator) { if (denied) error = EACCES; break; }
        path = separator + 1;
    }
    free(candidate); alix_environment_free(environment); errno = error;
    return -1;
}

static int exec_arguments(const char *path, const char *first, va_list arguments, bool search, bool explicit_environment)
{
    va_list count_arguments;
    va_copy(count_arguments, arguments);
    size_t count = first ? 1 : 0;
    if (first) while (va_arg(count_arguments, const char *))
        if (++count > 256) { va_end(count_arguments); errno = E2BIG; return -1; }
    va_end(count_arguments);
    char **vector = calloc(count + 1, sizeof(*vector));
    if (!vector) return -1;
    if (count) vector[0] = (char *)first;
    for (size_t i = 1; i < count; ++i) vector[i] = va_arg(arguments, char *);
    if (count) (void)va_arg(arguments, char *);
    if (explicit_environment) execve(path, vector, va_arg(arguments, char **));
    else if (search) execvp(path, vector);
    else execv(path, vector);
    int error = errno; free(vector); errno = error;
    return -1;
}
#define EXEC_VARIADIC(name, search, explicit_environment) \
int name(const char *path, const char *argument, ...) \
{ va_list ap; va_start(ap, argument); int result = exec_arguments(path, argument, ap, search, explicit_environment); va_end(ap); return result; }
EXEC_VARIADIC(execl, false, false)
EXEC_VARIADIC(execle, false, true)
EXEC_VARIADIC(execlp, true, false)
