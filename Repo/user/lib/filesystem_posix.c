#include "unistd.h"
#include "usyscall.h"
#include "errno.h"
#include "stat_internal.h"
#include "stdlib.h"
#include "limits.h"

static int path_stat(const char *path, struct stat *output, uint32_t flags)
{
    if (!output) { errno = EFAULT; return -1; }
    syscall_stat_t value;
    int64_t result = sys_file_io(SYSCALL_FILE_STAT_PATH, (uintptr_t)path, (uintptr_t)&value, flags, 0);
    if (result < 0) { errno = (int)-result; return -1; }
    return __alix_stat_decode(&value, output);
}

int stat(const char *path, struct stat *output) { return path_stat(path, output, 0); }
int lstat(const char *path, struct stat *output) { return path_stat(path, output, SYSCALL_STAT_NOFOLLOW); }

int chdir(const char *path)
{
    int64_t result = sys_file_io(SYSCALL_FILE_CHDIR, (uintptr_t)path, 0, 0, 0);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
}

char *getcwd(char *buffer, size_t capacity)
{
    bool allocated = !buffer;
    if (!capacity)
    {
        if (buffer) { errno = EINVAL; return NULL; }
        capacity = PATH_MAX;
    }
    if (allocated && !(buffer = malloc(capacity))) { errno = ENOMEM; return NULL; }
    int64_t result = sys_file_io(SYSCALL_FILE_GETCWD, (uintptr_t)buffer, capacity, 0, 0);
    if (result < 0)
    {
        if (allocated) free(buffer);
        errno = (int)-result;
        return NULL;
    }
    return buffer;
}

ssize_t readlink(const char *path, char *buffer, size_t capacity)
{
    ssize_t result = sys_readlink(path, buffer, capacity);
    if (result < 0)
    {
        errno = (int)-result;
        return -1;
    }
    return result;
}
