#include "sys/stat.h"
#include "fcntl.h"
#include "unistd.h"
#include "stdlib.h"
#include "string.h"
#include "errno.h"
#include "dirent.h"
#include "pthread.h"
#include "serial.h"
#include "stdio.h"
#include "sys/time.h"
#include "usyscall.h"

/* Exercise both generations in one process; an old caller supplies exactly
 * forty bytes, with canaries immediately on both sides. */
extern int old_fstat(int, void *) __asm__("fstat");
extern int old_stat(const char *, void *) __asm__("stat");
extern int old_lstat(const char *, void *) __asm__("lstat");
#define CHECK(c) do { if (!(c)) { serial_printf("FILE_IDENTITY_TEST: FAIL line=%u errno=%d\n", __LINE__, errno); return 1; } } while (0)
typedef struct {
    pthread_t thread;
    unsigned cpu, failed;
    uint64_t inode, device;
    struct stat info;
} worker_t;
static void *worker(void *argument)
{
    worker_t *w = argument;
    if (sys_thread_set_affinity(w->cpu) || sys_thread_cpu() != w->cpu) { w->failed = 1; return NULL; }
    for (unsigned i = 0; i < 64; ++i)
    {
        int fd = open("/tmp/identity-file", O_RDONLY);
        if (fd < 0) { w->failed = 2; return NULL; }
        if (fstat(fd, &w->info) || w->info.st_ino != w->inode || w->info.st_dev != w->device ||
            w->info.st_nlink != 1 || w->info.st_size != 8 || !S_ISREG(w->info.st_mode) || (w->info.st_mode&0777)!=0640) w->failed = 3;
        if (close(fd)) w->failed = 4;
        if (w->failed) return NULL;
    }
    return NULL;
}
typedef struct {
    struct stat info, other;
    worker_t workers[8];
    uint64_t before[2];
    unsigned char legacy[40];
    uint64_t after[2];
    struct timeval times[2];
} fixture_t;
static int canaries(fixture_t *f)
{
    return f->before[0] == 0x12345678abcdef01ULL && f->before[1] == 0x23456789abcdef12ULL &&
           f->after[0] == 0x3456789abcdef123ULL && f->after[1] == 0x456789abcdef1234ULL;
}
int main(int argc, char **argv)
{
    fixture_t *f = calloc(1, sizeof(*f)); CHECK(f);
    if (argc == 2 && !strcmp(argv[1], "read"))
    {
        int disk = open("/root/identity-owner", O_RDONLY); CHECK(disk >= 3);
        CHECK(!fstat(disk, &f->info) && f->info.st_uid == 12345 && f->info.st_gid == 23456 &&
              f->info.st_size == 8 && f->info.st_ino && f->info.st_nlink == 1 && (f->info.st_mode&0777)==0640 &&
              f->info.st_atime==1600000000 && f->info.st_mtime==1600000001 && !close(disk));
        free(f);
        serial_printf("FILE_IDENTITY_REMOUNT: PASS owner=12345 group=23456 bytes=8 mode=0640 times=1\n");
        return 0;
    }
    int fd = open("/tmp/identity-file", O_RDWR | O_CREAT | O_EXCL, 0600); CHECK(fd >= 3);
    CHECK(write(fd, "identity", 8) == 8 && !fstat(fd, &f->info));
    CHECK(f->info.st_ino && f->info.st_dev && f->info.st_nlink == 1 && f->info.st_size == 8 &&
          f->info.st_uid == getuid() && f->info.st_gid == getgid() && f->info.st_blocks == 1 && f->info.st_blksize == 4096);
    CHECK(!stat("/tmp/identity-file", &f->other) && f->other.st_ino == f->info.st_ino && f->other.st_dev == f->info.st_dev);
    CHECK(!getuid() && !fchown(fd, 1234, 2345) && !fstat(fd, &f->other) &&
          f->other.st_uid == 1234 && f->other.st_gid == 2345 && f->other.st_ino == f->info.st_ino);
    CHECK(!fchown(fd, (uid_t)-1, 3456) && !stat("/tmp/identity-file", &f->other) &&
          f->other.st_uid == 1234 && f->other.st_gid == 3456);
    CHECK(!fchown(fd, (uid_t)-1, (gid_t)-1) && !fstat(fd, &f->other) &&
          f->other.st_uid == 1234 && f->other.st_gid == 3456);
    CHECK(!fchown(fd, getuid(), getgid()) && !fstat(fd, &f->info));
    CHECK(fchown(-1, 0, 0) == -1 && errno == EBADF);
    CHECK(!fchmod(fd,0640)&&!fstat(fd,&f->info)&&(f->info.st_mode&0777)==0640);
    CHECK(fchmod(fd,S_ISUID|0600)==-1&&errno==EOPNOTSUPP);
    CHECK(fchmod(fd,0x80000000)==-1&&errno==EINVAL);
    CHECK(fchmod(-1,0600)==-1&&errno==EBADF);
    int alias = dup(fd); CHECK(alias >= 3 && !fstat(alias, &f->other) && f->other.st_ino == f->info.st_ino && !close(alias));
    DIR *directory = opendir("/tmp"); CHECK(directory);
    bool found = false;
    for (struct dirent *entry; (entry = readdir(directory)); )
        if (!strcmp(entry->d_name, "identity-file")) { CHECK(entry->d_ino == f->info.st_ino); found = true; }
    CHECK(found && !closedir(directory));
    CHECK(!stat("/tmp", &f->other) && f->other.st_nlink >= 2);
    uint64_t parent_links = f->other.st_nlink;
    CHECK(!sys_mkdir("/tmp/identity-directory") && !stat("/tmp", &f->other) && f->other.st_nlink == parent_links + 1);
    CHECK(!rmdir("/tmp/identity-directory") && !stat("/tmp", &f->other) && f->other.st_nlink == parent_links);
    f->before[0] = 0x12345678abcdef01ULL; f->before[1] = 0x23456789abcdef12ULL;
    f->after[0] = 0x3456789abcdef123ULL; f->after[1] = 0x456789abcdef1234ULL;
    CHECK(!old_fstat(fd, f->legacy) && canaries(f) && !memcmp(f->legacy, &f->info, 8) &&
          !memcmp(f->legacy+12,(unsigned char *)&f->info+12,28));
    CHECK(!old_stat("/tmp/identity-file", f->legacy) && canaries(f));
    CHECK(!old_lstat("/tmp/identity-file", f->legacy) && canaries(f));
    CHECK(fstat(fd, (void *)"readonly") == -1 && errno == EFAULT);
    CHECK(stat("/tmp/identity-file", (void *)"readonly") == -1 && errno == EFAULT);
    CHECK(lstat("/tmp/identity-file", (void *)1) == -1 && errno == EFAULT);
    memset(&f->other, 0x5a, sizeof(f->other));
    CHECK(stat("/tmp/identity-absent", &f->other) == -1 && errno == ENOENT && f->other.st_ino == 0x5a5a5a5a5a5a5a5aULL);
    for (unsigned cpu = 0; cpu < 8; ++cpu)
    {
        f->workers[cpu].cpu = cpu; f->workers[cpu].inode = f->info.st_ino; f->workers[cpu].device = f->info.st_dev;
        CHECK(!pthread_create(&f->workers[cpu].thread, NULL, worker, &f->workers[cpu]));
    }
    for (unsigned cpu = 0; cpu < 8; ++cpu) CHECK(!pthread_join(f->workers[cpu].thread, NULL) && !f->workers[cpu].failed);
    CHECK(!rename("/tmp/identity-file", "/tmp/identity-renamed") && !fstat(fd, &f->other) &&
          f->other.st_ino == f->info.st_ino && f->other.st_dev == f->info.st_dev && f->other.st_nlink == 1);
    CHECK(!stat("/tmp/identity-renamed", &f->other) && f->other.st_ino == f->info.st_ino);
    CHECK(!unlink("/tmp/identity-renamed") && !fstat(fd, &f->other) && !f->other.st_nlink && f->other.st_ino == f->info.st_ino);
    int fresh = open("/tmp/identity-renamed", O_RDWR | O_CREAT | O_EXCL, 0600); CHECK(fresh >= 3);
    CHECK(!fstat(fresh, &f->other) && f->other.st_ino != f->info.st_ino && f->other.st_nlink == 1);
    CHECK(!close(fresh) && !close(fd) && !unlink("/tmp/identity-renamed"));
    int disk = open("/tmp/identity-disk/identity-owner", O_RDWR | O_CREAT | O_EXCL, 0600); CHECK(disk >= 3);
    CHECK(write(disk, "identity", 8) == 8 && !fchown(disk, 12345, 23456) && !fsync(disk));
    CHECK(!fchmod(disk,0640)&&!fsync(disk)); /* Metadata-only update. */
    f->times[0]=(struct timeval){.tv_sec=1600000000,.tv_usec=12345};
    f->times[1]=(struct timeval){.tv_sec=1600000001,.tv_usec=987655};
    CHECK(!utimes("/tmp/identity-disk/identity-owner",f->times)&&!fsync(disk));
    CHECK(!fstat(disk, &f->other) && f->other.st_dev != f->info.st_dev && f->other.st_uid == 12345 && f->other.st_gid == 23456);
    CHECK(!close(disk));
    free(f);
    serial_printf("FILE_IDENTITY_TEST: PASS cpus=8 snapshots=512 versions=2 canaries=1 independent_opens=1 aliases=1 readdir=1 rename=1 orphan=1 recreate=1 directories=1 copy_checks=1 ownership=1 mount_identity=1 modes=1 times=1\n");
    return 0;
}
