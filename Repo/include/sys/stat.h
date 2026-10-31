#ifndef SYS_STAT_H
#define SYS_STAT_H

#include "types.h"
#include "syscall_defs.h"

#ifdef TTF_HOST_BUILD
#include_next <sys/stat.h>
typedef struct stat stat_t;
#else
#define S_IFMT   0170000u
#define S_IFREG  0100000u
#define S_IFDIR  0040000u
#define S_IFBLK  0060000u
#define S_IFLNK  0120000u
#define S_IFCHR  0020000u
#define S_IFIFO  0010000u
#define S_IFSOCK 0140000u
#define S_ISREG(mode)  (((mode) & S_IFMT) == S_IFREG)
#define S_ISDIR(mode)  (((mode) & S_IFMT) == S_IFDIR)
#define S_ISBLK(mode)  (((mode) & S_IFMT) == S_IFBLK)
#define S_ISLNK(mode)  (((mode) & S_IFMT) == S_IFLNK)
#define S_ISCHR(mode)  (((mode) & S_IFMT) == S_IFCHR)
#define S_ISFIFO(mode) (((mode) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(mode) (((mode) & S_IFMT) == S_IFSOCK)

typedef struct stat
{
    uint64_t st_size;
    uint32_t st_mode;
    uint32_t st_type;
    uint64_t st_atime;
    uint64_t st_mtime;
    uint64_t st_ctime;
} stat_t;

#ifndef KERNEL_BUILD
#ifdef __cplusplus
extern "C" {
#endif
int fstat(int fd, struct stat *st);
#ifdef __cplusplus
}
#endif
#endif

#endif
#endif /* SYS_STAT_H */
