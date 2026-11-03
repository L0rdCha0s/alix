#include "errno.h"
#include "fcntl.h"
#include "pthread.h"
#include "serial.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "sys/stat.h"
#include "unistd.h"
#include "usyscall.h"

#define CHECK(c, label) do { if (!(c)) { serial_printf("BASE_SYMLINK_TEST: FAIL %s line=%u errno=%d\n", label, __LINE__, errno); return 1; } } while (0)
typedef struct { pthread_t thread; unsigned cpu, failed, won; const char *path; } link_job_t;
typedef struct
{
    link_job_t jobs[8];
    char directory[128], target[256], link[256], alternate[256], nested[256], bytes[256], long_path[4097];
    struct stat metadata;
} link_fixture_t;
static void *create_link(void *context)
{
    link_job_t *job = context;
    if (sys_thread_set_affinity(job->cpu) || sys_thread_cpu() != job->cpu) job->failed = 1;
    if (!symlink("target", job->path)) job->won = 1;
    else if (errno != EEXIST) job->failed = 2;
    int fd = open(job->path, O_RDONLY | O_NOFOLLOW);
    if (fd != -1 || errno != ELOOP) { job->failed = 3; if (fd >= 0) close(fd); }
    return NULL;
}
int main(void)
{
    link_fixture_t *test = calloc(1, sizeof(*test)); CHECK(test, "heap fixture");
    strcpy(test->directory, "/tmp/base-links-XXXXXX"); CHECK(mkdtemp(test->directory), "fixture directory");
    snprintf(test->target, sizeof(test->target), "%s/target", test->directory);
    snprintf(test->link, sizeof(test->link), "%s/link", test->directory);
    int fd = open(test->target, O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(fd >= 0 && write(fd, "content", 7) == 7 && !close(fd), "target creation");
    CHECK(!symlink("target", test->link), "relative symlink");
    CHECK(symlink("different", test->link) == -1 && errno == EEXIST, "exclusive link creation");
    CHECK(readlink(test->link, test->bytes, sizeof(test->bytes)) == 6 && !memcmp(test->bytes, "target", 6), "link target preserved");
    CHECK(!lstat(test->link, &test->metadata) && S_ISLNK(test->metadata.st_mode) &&
          (test->metadata.st_mode & 0777) == 0777 && test->metadata.st_size == 6, "link metadata");
    fd = open(test->link, O_RDONLY);
    CHECK(fd >= 0 && read(fd, test->bytes, sizeof(test->bytes)) == 7 && !memcmp(test->bytes, "content", 7) && !close(fd), "ordinary open follows final link");
    CHECK(open(test->link, O_WRONLY | O_TRUNC | O_NOFOLLOW) == -1 && errno == ELOOP &&
          !stat(test->target, &test->metadata) && test->metadata.st_size == 7, "no-follow precedes truncation");
    CHECK(open(test->link, O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW, 0600) == -1 && errno == EEXIST, "exclusive create checks link identity");
    CHECK(!access(test->directory, F_OK) && !access(test->directory, X_OK) && !access(test->target, R_OK | W_OK), "access directories and files");
    CHECK(access(test->target, X_OK) == -1 && errno == EACCES && !chmod(test->target, 0700) && !access(test->target, X_OK), "execute permission including root");
    CHECK(!faccessat(AT_FDCWD, test->link, R_OK, AT_EACCESS) && !faccessat(-99, test->target, F_OK, 0), "effective access and absolute paths");
    fd = open(test->target, O_RDONLY); CHECK(fd >= 0, "access fd fixture");
    CHECK(faccessat(fd, "relative", F_OK, 0) == -1 && errno == ENOTDIR && !close(fd), "regular FD is not a directory");
    CHECK(faccessat(-99, "relative", F_OK, 0) == -1 && errno == EBADF &&
          faccessat(AT_FDCWD, test->link, 8, 0) == -1 && errno == EINVAL &&
          faccessat(AT_FDCWD, test->link, F_OK, 1) == -1 && errno == EINVAL, "access argument errors");
    snprintf(test->alternate, sizeof(test->alternate), "%s/dangling", test->directory);
    CHECK(!symlink("created", test->alternate), "dangling link");
    CHECK(access(test->alternate, F_OK) == -1 && errno == ENOENT &&
          !faccessat(AT_FDCWD, test->alternate, F_OK, AT_SYMLINK_NOFOLLOW), "link versus target access");
    CHECK(open(test->alternate, O_CREAT | O_EXCL | O_RDWR, 0600) == -1 && errno == EEXIST, "dangling exclusive create");
    fd = open(test->alternate, O_CREAT | O_RDWR, 0600);
    CHECK(fd >= 0 && write(fd, "new", 3) == 3 && !close(fd), "create follows dangling link");
    snprintf(test->nested, sizeof(test->nested), "%s/created", test->directory);
    CHECK(!stat(test->nested, &test->metadata) && test->metadata.st_size == 3 && !unlink(test->nested) && !unlink(test->alternate), "created target is a separate node");
    snprintf(test->alternate, sizeof(test->alternate), "%s/absolute", test->directory);
    CHECK(!symlink(test->target, test->alternate), "absolute target");
    fd = open(test->alternate, O_RDONLY); CHECK(fd >= 0 && !close(fd) && !unlink(test->alternate), "absolute target open");
    snprintf(test->alternate, sizeof(test->alternate), "%s/directory", test->directory);
    CHECK(!symlink(test->directory, test->alternate), "directory link");
    snprintf(test->nested, sizeof(test->nested), "%s/target", test->alternate);
    fd = open(test->nested, O_RDONLY | O_NOFOLLOW);
    CHECK(fd >= 0 && !close(fd) && !unlink(test->alternate), "no-follow permits intermediate directory link");
    snprintf(test->alternate, sizeof(test->alternate), "%s/loop-a", test->directory);
    snprintf(test->nested, sizeof(test->nested), "%s/loop-b", test->directory);
    CHECK(!symlink("loop-b", test->alternate) && !symlink("loop-a", test->nested), "cycle setup");
    CHECK(open(test->alternate, O_RDONLY) == -1 && errno == ELOOP && !unlink(test->alternate) && !unlink(test->nested), "bounded cyclic link traversal");
    memset(test->long_path, 'x', 4096); test->long_path[4096] = 0;
    CHECK(symlink(test->long_path, test->alternate) == -1 && errno == ENAMETOOLONG &&
          symlink((void *)1, test->alternate) == -1 && errno == EFAULT &&
          symlink("x", (void *)1) == -1 && errno == EFAULT &&
          lstat(test->alternate, &test->metadata) == -1 && errno == ENOENT, "failed copies never create links");
    CHECK(symlink("x", "/base-link-forbidden") == -1 && errno == EROFS, "locked root policy");
    snprintf(test->alternate, sizeof(test->alternate), "%s/race", test->directory);
    for (unsigned cpu = 0; cpu < 8; ++cpu)
    {
        test->jobs[cpu].cpu = cpu; test->jobs[cpu].path = test->alternate;
        CHECK(!pthread_create(&test->jobs[cpu].thread, NULL, create_link, &test->jobs[cpu]), "concurrent link creators");
    }
    unsigned wins = 0;
    for (unsigned cpu = 0; cpu < 8; ++cpu)
    { CHECK(!pthread_join(test->jobs[cpu].thread, NULL) && !test->jobs[cpu].failed, "link worker result"); wins += test->jobs[cpu].won; }
    CHECK(wins == 1, "atomic exclusive symlink creation");
    CHECK(!unlink(test->alternate) && !unlink(test->link) && !unlink(test->target) && !rmdir(test->directory), "fixture cleanup");
    free(test);
    serial_printf("BASE_SYMLINK_TEST: PASS cpus=8 exclusive=1 follow=1 nofollow=1 dangling=1 cycle=1 access=1 copy_rollback=1\n");
    return 0;
}
