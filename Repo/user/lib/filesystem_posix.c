#include "unistd.h"
#include "usyscall.h"
#include "errno.h"
#include "stat_internal.h"
#include "stdlib.h"
#include "limits.h"
#include <stddef.h>
#include "sys/time.h"

_Static_assert(sizeof(struct stat) == sizeof(syscall_stat_times_t) && sizeof(struct stat) == 136 &&
               offsetof(struct stat, st_atim) == sizeof(syscall_stat_info_t),
               "full stat ABI size");
#define STAT_FIELD(public_name, wire_name) \
    _Static_assert(offsetof(struct stat, public_name) == offsetof(syscall_stat_info_t, wire_name), "stat field ABI")
STAT_FIELD(st_size, size_bytes); STAT_FIELD(st_mode, mode); STAT_FIELD(st_type, type);
STAT_FIELD(st_atime, atime); STAT_FIELD(st_mtime, mtime); STAT_FIELD(st_ctime, ctime);
STAT_FIELD(st_dev, device); STAT_FIELD(st_ino, inode); STAT_FIELD(st_nlink, links);
STAT_FIELD(st_uid, uid); STAT_FIELD(st_gid, gid); STAT_FIELD(st_blksize, block_size); STAT_FIELD(st_blocks, blocks);
#undef STAT_FIELD
_Static_assert(sizeof(struct timeval)*2 == sizeof(syscall_file_times_t) && sizeof(struct timeval)==16,
               "native file time ABI");
int utimes(const char *path, const struct timeval times[2])
{
    int64_t result=sys_file_io(SYSCALL_FILE_SET_TIMES,(uintptr_t)path,(uintptr_t)times,0,0);
    if (result<0){errno=(int)-result;return -1;}
    return 0;
}

int chmod(const char *path, mode_t mode)
{
    int64_t result = sys_file_io(SYSCALL_FILE_CHMOD_PATH, (uintptr_t)path, mode, 0, 0);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
}

static int path_stat(const char *path, struct stat *output, uint32_t flags)
{
    if (!output) { errno = EFAULT; return -1; }
    int64_t result = sys_file_io(SYSCALL_FILE_PATH_TIMES, (uintptr_t)path, (uintptr_t)output, flags, 0);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
}

int stat(const char *path, struct stat *output) { return path_stat(path, output, 0); }
int lstat(const char *path, struct stat *output) { return path_stat(path, output, SYSCALL_STAT_NOFOLLOW); }

static int path_stat_v2(const char *path, void *output, uint32_t flags)
{
    if (!output) { errno = EFAULT; return -1; }
    int64_t result = sys_file_io(SYSCALL_FILE_PATH_INFO, (uintptr_t)path, (uintptr_t)output, flags, 0);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
}
int __alix_stat_v2(const char *, void *) __asm__("alix_stat_v2");
int __alix_lstat_v2(const char *, void *) __asm__("alix_lstat_v2");
int __alix_stat_v2(const char *path, void *output) { return path_stat_v2(path, output, 0); }
int __alix_lstat_v2(const char *path, void *output) { return path_stat_v2(path, output, SYSCALL_STAT_NOFOLLOW); }

static int legacy_path_stat(const char *path, void *output, uint32_t flags)
{
    if (!output) { errno = EFAULT; return -1; }
    syscall_stat_t value;
    int64_t result = sys_file_io(SYSCALL_FILE_STAT_PATH, (uintptr_t)path, (uintptr_t)&value, flags, 0);
    if (result < 0) { errno = (int)-result; return -1; }
    return __alix_stat_decode_legacy(&value, output);
}
int __alix_stat_legacy(const char *path, void *output) __asm__("stat");
int __alix_lstat_legacy(const char *path, void *output) __asm__("lstat");
int __alix_stat_legacy(const char *path, void *output) { return legacy_path_stat(path, output, 0); }
int __alix_lstat_legacy(const char *path, void *output) { return legacy_path_stat(path, output, SYSCALL_STAT_NOFOLLOW); }

int rmdir(const char *path)
{
    int64_t result = sys_file_io(SYSCALL_FILE_REMOVE, (uintptr_t)path, 0, SYSCALL_REMOVE_DIRECTORY_ONLY, 0);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
}

char *realpath(const char *path, char *resolved)
{
    bool allocated = !resolved;
    if (allocated && !(resolved = malloc(PATH_MAX))) { errno = ENOMEM; return NULL; }
    int64_t result = sys_file_io(SYSCALL_FILE_REALPATH, (uintptr_t)path, (uintptr_t)resolved, PATH_MAX, 0);
    if (result < 0)
    {
        if (allocated) free(resolved);
        errno = (int)-result;
        return NULL;
    }
    return resolved;
}

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
