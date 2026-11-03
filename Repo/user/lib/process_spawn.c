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

int waitid(idtype_t type, id_t id, siginfo_t *info, int flags)
{
    uint64_t selector = ((uint64_t)(uint32_t)type << 32) | (uint32_t)id;
    int64_t result = sys_process(SYSCALL_PROCESS_WAIT_INFO, selector,
                                 (uintptr_t)info, (uint64_t)(int64_t)flags);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
}
