#include "sys/utsname.h"
#include "unistd.h"
#include "usyscall.h"
#include "errno.h"
_Static_assert(sizeof(struct utsname) == sizeof(syscall_utsname_t), "native uname ABI");
int uname(struct utsname *info)
{
    int64_t result = sys_file_io(SYSCALL_FILE_SYSTEM_INFO, (uintptr_t)info, sizeof(*info), 0, 0);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
}
int gethostname(char *name, size_t capacity)
{
    int64_t result = sys_file_io(SYSCALL_FILE_HOSTNAME, (uintptr_t)name, capacity, 0, 0);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
}
