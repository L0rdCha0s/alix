#ifndef ALIX_SYS_STATVFS_H
#define ALIX_SYS_STATVFS_H
#ifdef TTF_HOST_BUILD
#include_next <sys/statvfs.h>
#else
#include "sys/types.h"
typedef uint64_t fsblkcnt_t;
typedef uint64_t fsfilcnt_t;
struct statvfs
{
    unsigned long f_bsize, f_frsize;
    fsblkcnt_t f_blocks, f_bfree, f_bavail;
    fsfilcnt_t f_files, f_ffree, f_favail;
    unsigned long f_fsid, f_flag, f_namemax;
};
#define ST_RDONLY 1u
#define ST_NOSUID 2u
#pragma GCC visibility push(default)
#ifdef __cplusplus
extern "C" {
#endif
int statvfs(const char *path, struct statvfs *output);
int fstatvfs(int descriptor, struct statvfs *output);
#ifdef __cplusplus
}
#endif
#pragma GCC visibility pop
#endif
#endif
