#include "alix_process.h"
#include "sys/wait.h"
#include "usyscall.h"
#include "errno.h"

static pid_t process_result(int64_t result)
{
    if (result < 0) { errno = (int)-result; return -1; }
    return (pid_t)result;
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
