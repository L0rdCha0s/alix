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
#define S_IRUSR 0400u
#define S_IWUSR 0200u
#define S_IXUSR 0100u
#define S_IRGRP 0040u
#define S_IWGRP 0020u
#define S_IXGRP 0010u
#define S_IROTH 0004u
#define S_IWOTH 0002u
#define S_IXOTH 0001u
#define S_IRWXU 0700u
#define S_IRWXG 0070u
#define S_IRWXO 0007u
#define S_ISUID 04000u
#define S_ISGID 02000u
#define S_ISVTX 01000u
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
    uint64_t st_dev;
    uint64_t st_ino;
    uint64_t st_nlink;
    uint32_t st_uid;
    uint32_t st_gid;
    int64_t st_blksize;
    int64_t st_blocks;
} stat_t;

#ifndef KERNEL_BUILD
#ifdef __cplusplus
extern "C" {
#endif
/* The unsuffixed ELF symbols retain the original 40-byte ABI for installed
 * programs and the existing Rust std runtime. New callers use the full record. */
int fstat(int fd, struct stat *st) __asm__("alix_fstat_v2");
int stat(const char *path, struct stat *st) __asm__("alix_stat_v2");
int lstat(const char *path, struct stat *st) __asm__("alix_lstat_v2");
int fchmod(int fd, mode_t mode);
mode_t umask(mode_t mask);
int mkdir(const char *path, mode_t mode);
#ifdef __cplusplus
}
#endif
#endif

#endif
#endif /* SYS_STAT_H */
