#ifndef SYS_STAT_H
#define SYS_STAT_H

#include "types.h"
#include "syscall_defs.h"

#ifdef TTF_HOST_BUILD
#include_next <sys/stat.h>
typedef struct stat stat_t;
#else
#include "time.h"
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
    struct timespec st_atim, st_mtim, st_ctim;
} stat_t;

/* The native record and file offsets are already 64 bit. These source aliases
 * also select the versioned full-record ABI declared below. */
#define stat64 stat
#define fstat64 fstat
#define lstat64 lstat

#ifndef KERNEL_BUILD
#ifdef __cplusplus
extern "C" {
#endif
/* Original ELF symbols retain their 40-byte record and v2 symbols retain their
 * 88-byte record. New callers also receive the three timespec timestamps. */
int fstat(int fd, struct stat *st) __asm__("alix_fstat_v3");
int stat(const char *path, struct stat *st) __asm__("alix_stat_v3");
int lstat(const char *path, struct stat *st) __asm__("alix_lstat_v3");
int fchmod(int fd, mode_t mode);
int chmod(const char *path, mode_t mode);
mode_t umask(mode_t mask);
int mkdir(const char *path, mode_t mode);
int mkfifo(const char *path, mode_t mode);
#ifdef __cplusplus
}
#endif
#endif

#endif
#endif /* SYS_STAT_H */
