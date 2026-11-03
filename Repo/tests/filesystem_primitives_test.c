#include "unistd.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include "errno.h"
#include "fcntl.h"
#include "pthread.h"
#include "sys/stat.h"
#include "sys/mman.h"
#include "usyscall.h"
#include "serial.h"
#include <stdint.h>

#define BASE "/tmp/fs-primitives"
#define CHECK(c, label) do { if (!(c)) { serial_printf("FS_PRIMITIVES_TEST: FAIL %s line=%u errno=%d\n", label, __LINE__, errno); return 1; } } while (0)
typedef struct {
    pthread_t thread;
    int fd, alias;
    unsigned cpu, shared, failed;
    struct stat info;
    unsigned char bytes[8192];
    char path[128];
} worker_t;
typedef struct {
    worker_t jobs[8];
    struct stat info;
    int pipes[2];
    unsigned char bytes[8192];
    char path[4096], saved[4096];
} fixture_t;

static void *worker(void *argument)
{
    worker_t *job = argument;
    if (sys_thread_set_affinity(job->cpu) || sys_thread_cpu() != job->cpu) job->failed = 1;
    for (unsigned round = 0; round < 32 && !job->failed; ++round)
    {
        if (job->shared)
        {
            if (ftruncate(job->fd, round & 1u ? 0 : 4096)) { job->failed = 1; break; }
            memset(job->bytes, 0xa5, 4096);
            ssize_t bytes = pread(job->fd, job->bytes, 4096, 0);
            if (bytes != 0 && bytes != 4096) { job->failed = 1; break; }
            for (ssize_t i = 0; i < bytes; ++i) if (job->bytes[i]) job->failed = 1;
            continue;
        }
        if (lseek(job->fd, 0, SEEK_SET) || write(job->fd, "abcdef", 6) != 6 ||
            lseek(job->fd, 17, SEEK_SET) != 17 || ftruncate(job->alias, 3) ||
            fstat(job->fd, &job->info) || job->info.st_size != 3 || lseek(job->fd, 0, SEEK_CUR) != 17 ||
            pread(job->fd, job->bytes, 3, 0) != 3 || memcmp(job->bytes, "abc", 3) ||
            ftruncate(job->alias, sizeof(job->bytes)) ||
            pread(job->fd, job->bytes, sizeof(job->bytes), 0) != sizeof(job->bytes)) { job->failed = 1; break; }
        for (unsigned i = 3; i < sizeof(job->bytes); ++i) if (job->bytes[i]) job->failed = 1;
        if (ftruncate(job->fd, 0) || fstat(job->alias, &job->info) || job->info.st_size ||
            lseek(job->alias, 0, SEEK_CUR) != 17) job->failed = 1;
    }
    return NULL;
}

int main(void)
{
    fixture_t *test = calloc(1, sizeof(*test)); CHECK(test, "heap fixture");
    CHECK(!mkdir(BASE, 0777), "test directory");
    int fd = open(BASE "/regular", O_CREAT | O_EXCL | O_RDWR, 0666);
    CHECK(fd >= 0 && write(fd, "abcdef", 6) == 6, "test file");
    int readonly = open(BASE "/regular", O_RDONLY);
    CHECK(readonly >= 0 && ftruncate(readonly, 0) == -1 && errno == EBADF &&
          !fstat(fd, &test->info) && test->info.st_size == 6 && !close(readonly), "read-only truncation rejected");
    CHECK(ftruncate(fd, -1) == -1 && errno == EINVAL && ftruncate(-1, 0) == -1 && errno == EBADF &&
          sys_file_io(SYSCALL_FILE_TRUNCATE, fd, UINT64_MAX, 0, 0) == -EINVAL, "resize bounds");
    CHECK(!pipe(test->pipes) && ftruncate(test->pipes[0], 0) == -1 && errno == EINVAL &&
          ftruncate(test->pipes[1], 0) == -1 && errno == EINVAL &&
          !close(test->pipes[0]) && !close(test->pipes[1]) &&
          ftruncate(STDOUT_FILENO, 0) == -1 && errno == EINVAL, "unsupported descriptor types");

    char *allocated = realpath(BASE "/../fs-primitives/./regular", NULL);
    CHECK(allocated && !strcmp(allocated, BASE "/regular"), "owned canonical file path"); free(allocated);
    CHECK(realpath("/", test->path) == test->path && !strcmp(test->path, "/"), "canonical root");
    CHECK(realpath("/etc/..", test->path) == test->path && !strcmp(test->path, "/root"), "symlink before dotdot");
    CHECK(!chdir(BASE) && realpath("regular", test->path) == test->path && !strcmp(test->path, BASE "/regular") &&
          !chdir("/"), "canonical captured cwd");
    CHECK(!realpath(BASE "/missing", test->path) && errno == ENOENT &&
          !realpath(BASE "/regular/child", test->path) && errno == ENOTDIR &&
          !realpath((const char *)1, test->path) && errno == EFAULT, "canonical lookup and copy errors");
    memset(test->path, 0x5a, sizeof(test->path)); memcpy(test->saved, test->path, sizeof(test->path));
    CHECK(sys_file_io(SYSCALL_FILE_REALPATH, (uintptr_t)BASE "/regular", (uintptr_t)test->path, 2, 0) == -ERANGE &&
          !memcmp(test->path, test->saved, sizeof(test->path)), "no truncated canonical success");
    char *protected = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(protected != MAP_FAILED, "canonical output mapping"); memset(protected, 0x5a, 4096);
    CHECK(!mprotect(protected, 4096, PROT_READ) && !realpath(BASE "/regular", protected) && errno == EFAULT &&
          protected[0] == 0x5a && !munmap(protected, 4096), "checked read-only canonical output");

    CHECK(rmdir(BASE "/regular") == -1 && errno == ENOTDIR && !stat(BASE "/regular", &test->info), "rmdir preserves regular files");
    CHECK(rmdir(BASE) == -1 && errno == ENOTEMPTY && rmdir("/") == -1 && errno == EBUSY &&
          rmdir(BASE "/.") == -1 && errno == EINVAL && rmdir(BASE "/..") == -1 && errno == ENOTEMPTY &&
          rmdir(BASE "/regular/child") == -1 && errno == ENOTDIR, "directory-only checks");
    CHECK(!mkdir(BASE "/empty", 0777) && !rmdir(BASE "/empty/") &&
          stat(BASE "/empty", &test->info) == -1 && errno == ENOENT, "remove empty directory");
    CHECK(!close(fd), "close initial file");

    for (unsigned i = 0; i < 8; ++i)
    {
        worker_t *job = &test->jobs[i]; job->cpu = i;
        snprintf(job->path, sizeof(job->path), BASE "/cpu-%u", i);
        job->fd = open(job->path, O_CREAT | O_EXCL | O_RDWR, 0666); job->alias = dup(job->fd);
        CHECK(job->fd >= 0 && job->alias >= 0 && !pthread_create(&job->thread, NULL, worker, job), "start resize worker");
    }
    for (unsigned i = 0; i < 8; ++i)
    {
        worker_t *job = &test->jobs[i];
        CHECK(!pthread_join(job->thread, NULL) && !job->failed && !close(job->fd) && !close(job->alias) &&
              !unlink(job->path), "resize zero-fill and alias offsets");
    }
    fd = open(BASE "/regular", O_RDWR); CHECK(fd >= 0 && !ftruncate(fd, 0) && lseek(fd, 1234, SEEK_SET) == 1234, "shared resize file");
    for (unsigned i = 0; i < 8; ++i)
    {
        worker_t *job = &test->jobs[i]; job->fd = fd; job->shared = 1;
        CHECK(!pthread_create(&job->thread, NULL, worker, job), "start shared-node resize worker");
    }
    for (unsigned i = 0; i < 8; ++i) CHECK(!pthread_join(test->jobs[i].thread, NULL) && !test->jobs[i].failed, "shared-node resize/read atomicity");
    CHECK(lseek(fd, 0, SEEK_CUR) == 1234 && !fsync(fd) && !close(fd) &&
          !unlink(BASE "/regular") && !rmdir(BASE), "cleanup after shared resize");
    free(test);
    serial_printf("FS_PRIMITIVES_TEST: PASS cpus=8 resize=1 zero_fill=1 shared_offset=1 shared_node=1 realpath=1 rmdir=1 copy_checks=1\n");
    return 0;
}
