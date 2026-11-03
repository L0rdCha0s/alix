#include "alix_process.h"
#include "errno.h"
#include "fcntl.h"
#include "pthread.h"
#include "serial.h"
#include "spawn.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "sys/mman.h"
#include "sys/resource.h"
#include "sys/stat.h"
#include "sys/wait.h"
#include "unistd.h"
#include "usyscall.h"

#define BASE "/tmp/creation-modes"
#define PROGRAM "/tmp/test.elf"
#define ROUNDS 16
#define CHECK(c, label) do { if (!(c)) { serial_printf("CREATION_MODES_TEST: FAIL %s line=%u errno=%d\n", label, __LINE__, errno); return 1; } } while (0)
extern int legacy_open(const char *path, uint64_t flags, ...) __asm__("open");
typedef struct
{
    pthread_t thread;
    unsigned cpu, phase, failed, old_mask;
    uint64_t inodes[ROUNDS];
    struct stat info;
    char path[128];
} creation_job_t;
typedef struct
{
    creation_job_t jobs[8];
    struct stat info;
    char *arguments[3];
    struct rlimit limit, lowered;
    posix_spawnattr_t attributes;
    posix_spawn_file_actions_t actions;
    char path[128], bytes[8];
    bool seen[9];
    int status;
} creation_fixture_t;

static void *creator(void *context)
{
    creation_job_t *job = context;
    if (sys_thread_set_affinity(job->cpu) || sys_thread_cpu() != job->cpu) { job->failed = 1; return NULL; }
    if (job->phase)
    {
        job->old_mask = umask(job->cpu + 1);
        return NULL;
    }
    for (unsigned index = 0; index < ROUNDS; ++index)
    {
        strcpy(job->path, BASE "/temporary-XXXXXX");
        int fd = mkstemp(job->path);
        if (fd < 0 || fstat(fd, &job->info) || (job->info.st_mode & 0777) != 0600 ||
            fcntl(fd, F_GETFD) != 0 || write(fd, "DATA", 4) != 4 || close(fd) || unlink(job->path))
        { job->failed = 2; return NULL; }
        job->inodes[index] = job->info.st_ino;
    }
    strcpy(job->path, BASE "/directory-XXXXXX");
    if (!mkdtemp(job->path) || stat(job->path, &job->info) || (job->info.st_mode & 0777) != 0700 || rmdir(job->path)) job->failed = 3;
    return NULL;
}

static int child(void)
{
    creation_fixture_t *test = calloc(1, sizeof(*test)); CHECK(test, "child heap");
    CHECK(umask(0077) == 0027, "captured child mask");
    CHECK(!fstat(41, &test->info) && (test->info.st_mode & 0777) == 0640, "file action captured mask and mode");
    int fd = creat(BASE "/child", 0666);
    CHECK(fd >= 0 && !fstat(fd, &test->info) && (test->info.st_mode & 0777) == 0600 && !close(fd), "child mask change");
    free(test); return 23;
}

int main(int argc, char **argv)
{
    (void)argv;
    if (argc > 1) return child();
    creation_fixture_t *test = calloc(1, sizeof(*test)); CHECK(test, "heap fixture");
    mode_t original = umask(0); CHECK(original != (mode_t)-1, "original mask");
    CHECK(!mkdir(BASE, 0777), "fixture directory");
    errno = EDOM; CHECK(umask(0027) == 0 && errno == EDOM, "mask roundtrip preserves errno");
    int fd = open(BASE "/file", O_CREAT | O_EXCL | O_RDWR, 0666);
    CHECK(fd >= 0 && !fstat(fd, &test->info) && (test->info.st_mode & 0777) == 0640 && !close(fd), "regular creation mode");
    CHECK(!mkdir(BASE "/dir", 0777) && !stat(BASE "/dir", &test->info) &&
          (test->info.st_mode & 0777) == 0750, "directory creation mode");
    CHECK(umask((mode_t)-1) == 0027, "mask ignores non-permission bits");
    fd = open(BASE "/zero", O_CREAT | O_EXCL | O_RDWR, 0666);
    CHECK(fd >= 0 && !fstat(fd, &test->info) && !(test->info.st_mode & 0777) &&
          write(fd, "Z", 1) == 1 && !close(fd), "creator retains initial descriptor with zero permissions");
    CHECK(!chmod(BASE "/zero", 0644) && !stat(BASE "/zero", &test->info) &&
          (test->info.st_mode & 0777) == 0644, "path chmod can restore zero permissions and ignores umask");
    CHECK(chmod(BASE "/absent", 0600) == -1 && errno == ENOENT, "missing chmod path");
    CHECK(umask(0027) == 0777, "restore mask");
    CHECK(!sys_file_io(SYSCALL_FILE_MKDIR, (uintptr_t)(BASE "/old-wire-dir"), 0, 0, 0) &&
          !stat(BASE "/old-wire-dir", &test->info) && (test->info.st_mode & 0777) == 0750, "old directory wire honors current mask");
    fd = open(BASE "/file", O_CREAT | O_RDWR, 0000);
    CHECK(fd >= 0 && !fstat(fd, &test->info) && (test->info.st_mode & 0777) == 0640 && !close(fd), "existing inode mode unchanged");
    fd = legacy_open(BASE "/legacy", O_CREAT | O_EXCL | O_RDWR);
    CHECK(fd >= 0 && !fstat(fd, &test->info) && (test->info.st_mode & 0777) == 0640 && !close(fd), "installed open ABI retains default mode");
    CHECK(open(BASE "/unsupported", O_CREAT | O_EXCL | O_RDWR, S_ISUID | 0600) == -1 && errno == EOPNOTSUPP &&
          stat(BASE "/unsupported", &test->info) == -1 && errno == ENOENT, "unsupported mode fails before creation");
    fd = shm_open("/creation-modes", O_CREAT | O_EXCL | O_RDWR, 0666);
    CHECK(fd >= 0 && !fstat(fd, &test->info) && (test->info.st_mode & 0777) == 0640 &&
          !shm_unlink("/creation-modes") && !close(fd), "shared memory creation mask");
    CHECK(!posix_spawn_file_actions_init(&test->actions) &&
          !posix_spawn_file_actions_addopen(&test->actions, 41, BASE "/spawn-action", O_CREAT | O_EXCL | O_WRONLY, 0666), "spawn action setup");
    test->arguments[0] = PROGRAM; test->arguments[1] = "child";
    pid_t pid;
    CHECK(!posix_spawn(&pid, PROGRAM, &test->actions, NULL, test->arguments, NULL) &&
          waitpid(pid, &test->status, 0) == pid && WEXITSTATUS(test->status) == 23 && umask(0077) == 0027,
          "child inherits snapshot and cannot change parent mask");
    CHECK(!posix_spawn_file_actions_destroy(&test->actions), "spawn cleanup");
    CHECK(!posix_spawn_file_actions_init(&test->actions) &&
          !posix_spawn_file_actions_addopen(&test->actions, 41, BASE "/spawn-unsupported", O_CREAT | O_EXCL | O_WRONLY, S_ISUID | 0600), "unsupported action mode setup");
    pid = -123;
    CHECK(posix_spawn(&pid, PROGRAM, &test->actions, NULL, test->arguments, NULL) == EOPNOTSUPP && pid == -123 &&
          stat(BASE "/spawn-unsupported", &test->info) == -1 && errno == ENOENT, "unsupported action mode fails before launch");
    CHECK(!posix_spawn_file_actions_destroy(&test->actions), "unsupported action cleanup");
    for (unsigned phase = 0; phase < 2; ++phase)
    {
        if (phase) CHECK(umask(0) == 0077, "initialize atomic exchanges");
        for (unsigned cpu = 0; cpu < 8; ++cpu)
        {
            creation_job_t *job = &test->jobs[cpu]; job->cpu = cpu; job->phase = phase;
            CHECK(!pthread_create(&job->thread, NULL, creator, job), "creator thread");
        }
        for (unsigned cpu = 0; cpu < 8; ++cpu)
            CHECK(!pthread_join(test->jobs[cpu].thread, NULL) && !test->jobs[cpu].failed, "pinned creator completion");
    }
    unsigned last = umask(0027); CHECK(last <= 8, "atomic final mask"); test->seen[last] = true;
    for (unsigned cpu = 0; cpu < 8; ++cpu)
    {
        unsigned old = test->jobs[cpu].old_mask;
        CHECK(old <= 8 && !test->seen[old], "process-wide atomic exchange permutation"); test->seen[old] = true;
        for (unsigned index = 0; index < ROUNDS; ++index)
            for (unsigned prior = 0; prior < cpu * ROUNDS + index; ++prior)
                CHECK(test->jobs[cpu].inodes[index] != test->jobs[prior / ROUNDS].inodes[prior % ROUNDS], "exclusive temporary inode identity");
    }
    strcpy(test->path, BASE "/suffix-XXXXXX.dat");
    fd = mkostemps(test->path, 4, O_CLOEXEC | O_APPEND);
    CHECK(fd >= 0 && fcntl(fd, F_GETFD) == FD_CLOEXEC && (fcntl(fd, F_GETFL) & O_APPEND) &&
          !strcmp(test->path + strlen(test->path) - 4, ".dat") && !close(fd) && !unlink(test->path), "suffix and descriptor flags");
    strcpy(test->path, BASE "/bad-template");
    CHECK(mkstemp(test->path) == -1 && errno == EINVAL && !strcmp(test->path, BASE "/bad-template"), "invalid template unchanged");
    CHECK(!getrlimit(RLIMIT_NOFILE, &test->limit), "descriptor limit snapshot");
    test->lowered = test->limit; test->lowered.rlim_cur = 3;
    CHECK(!setrlimit(RLIMIT_NOFILE, &test->lowered), "restrict descriptor admission");
    strcpy(test->path, BASE "/admission-XXXXXX");
    CHECK(mkstemp(test->path) == -1 && errno == EMFILE &&
          stat(test->path, &test->info) == -1 && errno == ENOENT, "descriptor admission precedes creation");
    CHECK(!setrlimit(RLIMIT_NOFILE, &test->limit), "restore descriptor limit");
    CHECK(umask(original) == 0027, "restore caller mask");
    free(test);
    serial_printf("CREATION_MODES_TEST: PASS cpus=8 temporary_files=128 atomic_umask=1 spawn=1 file_modes=1 directory_modes=1 shm=1 legacy_abi=1 path_chmod=1 fd_admission=1\n");
    return 0;
}
