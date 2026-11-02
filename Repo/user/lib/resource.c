#include "sys/resource.h"
#include "usyscall.h"
#include "errno.h"

_Static_assert(sizeof(struct rlimit) == sizeof(syscall_rlimit_t), "native resource-limit ABI");
static int resource_limit_call(uint32_t operation, int resource, void *limit)
{
    if (!limit) { errno = EFAULT; return -1; }
    if (resource != RLIMIT_AS && resource != RLIMIT_NOFILE) { errno = EINVAL; return -1; }
#ifndef ALIX_OWNED_FDS
    /* Legacy global descriptors do not obey the private process FD policy. */
    if (resource == RLIMIT_NOFILE) { errno = ENOTSUP; return -1; }
#endif
    int64_t result = sys_file_io(operation, (uint64_t)(int64_t)resource, (uintptr_t)limit, sizeof(struct rlimit), 0);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
}
int getrlimit(int resource, struct rlimit *limit)
{ return resource_limit_call(SYSCALL_FILE_GET_LIMIT, resource, limit); }
int setrlimit(int resource, const struct rlimit *limit)
{ return resource_limit_call(SYSCALL_FILE_SET_LIMIT, resource, (void *)limit); }
