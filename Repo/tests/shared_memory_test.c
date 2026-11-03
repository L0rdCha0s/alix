#include "errno.h"
#include "fcntl.h"
#include "pthread.h"
#include "semaphore.h"
#include "serial.h"
#include "signal.h"
#include "spawn.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "sys/mman.h"
#include "sys/stat.h"
#include "sys/wait.h"
#include "unistd.h"
#include "usyscall.h"

#define PAGE 4096u
#define BOOT_NAME "/alix-shm-bootcheck"
#define DISK_MARKER "/tmp/shm-disk/marker"
#define CHECK(c, label) do { if (!(c)) { serial_printf("SHM_TEST: FAIL %s line=%u errno=%d\n", label, __LINE__, errno); return 1; } } while (0)
typedef struct shared_fixture shared_fixture_t;
typedef struct { shared_fixture_t *test; pthread_t thread; unsigned cpu, failed; int fd; } shared_job_t;
struct shared_fixture
{
    shared_job_t jobs[8];
    sem_t ready, start;
    unsigned winners;
    char executable[4096], name[80], holder_name[80], long_name[258];
    char *arguments[4];
    posix_spawn_file_actions_t actions;
    struct stat old_info, new_info;
    pid_t child;
    int status, extra[256];
};

static void *worker(void *context)
{
    shared_job_t *job = context;
    shared_fixture_t *test = job->test;
    if (sys_thread_set_affinity(job->cpu) || sys_thread_cpu() != job->cpu) job->failed = 1;
    job->fd = shm_open(test->name, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (job->fd >= 0)
    {
        __atomic_add_fetch(&test->winners, 1, __ATOMIC_RELAXED);
        if (ftruncate(job->fd, PAGE)) job->failed = 2;
    }
    else if (errno != EEXIST) job->failed = 3;
    if (sem_post(&test->ready) || sem_wait(&test->start)) job->failed = 4;
    if (job->fd < 0) job->fd = shm_open(test->name, O_RDWR, 0);
    if (job->fd < 0 || fcntl(job->fd, F_GETFD) != FD_CLOEXEC) job->failed = 5;
    uint32_t *words = job->failed ? MAP_FAILED : mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, job->fd, 0);
    if (words == MAP_FAILED) job->failed = 6;
    else
    {
        for (unsigned n = 0; n < 64; ++n) __atomic_fetch_add(words, 1, __ATOMIC_SEQ_CST);
        if (munmap(words, PAGE)) job->failed = 7;
    }
    if (job->fd >= 0 && close(job->fd)) job->failed = 8;
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "read-inherited"))
    {
        CHECK(fcntl(41, F_GETFD) == 0, "spawn action clears cloexec on target");
        uint32_t *words = mmap(NULL, PAGE, PROT_READ, MAP_SHARED, 41, 0);
        CHECK(words != MAP_FAILED && *words == 512, "unlinked object inherited read-only");
        CHECK(mprotect(words, PAGE, PROT_READ | PROT_WRITE) == -1 && errno == EACCES, "readonly mapping cannot gain write");
        CHECK(ftruncate(41, 0) == -1 && errno == EBADF, "readonly descriptor cannot truncate");
        CHECK(!munmap(words, PAGE), "child mapping release");
        return 23;
    }
    if (argc > 2 && !strcmp(argv[1], "create-holder"))
    {
        int fd = shm_open(argv[2], O_CREAT | O_EXCL | O_RDWR, 0600);
        CHECK(fd >= 0 && !ftruncate(fd, PAGE), "creator memory object");
        uint32_t *words = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        CHECK(words != MAP_FAILED, "creator mapping");
        __atomic_store_n(words, 0x71717171u, __ATOMIC_RELEASE);
        for (;;) sys_sleep_ms(1000);
    }
    if (argc > 1 && !strcmp(argv[1], "after-reboot"))
    {
        int fd = open("/root/marker", O_RDONLY);
        CHECK(fd >= 0, "same data disk after reboot");
        CHECK(!close(fd), "disk marker release");
        CHECK(shm_open(BOOT_NAME, O_RDONLY, 0) == -1 && errno == ENOENT, "memory namespace is volatile");
        serial_printf("SHM_REBOOT_TEST: PASS namespace_reset=1 disk_marker=1\n");
        return 0;
    }
    shared_fixture_t *test = calloc(1, sizeof(*test));
    CHECK(test, "heap fixture");
    snprintf(test->name, sizeof(test->name), "/alix-shm-%d", getpid());
    snprintf(test->holder_name, sizeof(test->holder_name), "/alix-shm-holder-%d", getpid());
    CHECK(shm_open("bad-name", O_RDWR | O_CREAT, 0600) == -1 && errno == EINVAL, "leading slash required");
    CHECK(shm_open("/bad/sub", O_RDWR | O_CREAT, 0600) == -1 && errno == EINVAL, "single component required");
    CHECK(shm_open((const char *)1, O_RDWR | O_CREAT, 0600) == -1 && errno == EFAULT, "captured name copy");
    CHECK(shm_unlink((const char *)1) == -1 && errno == EFAULT, "unlink name copy");
    memset(test->long_name, 'x', sizeof(test->long_name)); test->long_name[0] = '/'; test->long_name[257] = 0;
    CHECK(shm_open(test->long_name, O_CREAT | O_RDWR, 0600) == -1 && errno == ENAMETOOLONG, "bounded name");
    CHECK(!sem_init(&test->ready, 0, 0) && !sem_init(&test->start, 0, 0), "worker gates");
    for (unsigned cpu = 0; cpu < 8; ++cpu)
    {
        test->jobs[cpu].test = test; test->jobs[cpu].cpu = cpu;
        CHECK(!pthread_create(&test->jobs[cpu].thread, NULL, worker, &test->jobs[cpu]), "worker creation");
    }
    for (unsigned cpu = 0; cpu < 8; ++cpu) CHECK(!sem_wait(&test->ready), "creation results");
    CHECK(test->winners == 1, "atomic exclusive creation");
    for (unsigned cpu = 0; cpu < 8; ++cpu) CHECK(!sem_post(&test->start), "release worker");
    for (unsigned cpu = 0; cpu < 8; ++cpu) CHECK(!pthread_join(test->jobs[cpu].thread, NULL) && !test->jobs[cpu].failed, "shared mapping worker");
    CHECK(!sem_destroy(&test->ready) && !sem_destroy(&test->start), "worker gate release");
    int rw = shm_open(test->name, O_RDWR, 0), ro = shm_open(test->name, O_RDONLY, 0);
    CHECK(rw >= 0 && ro >= 0 && !fstat(rw, &test->old_info), "independent handles");
    CHECK(test->old_info.st_size == PAGE && (test->old_info.st_mode & 0777) == 0600, "size and private creation mode");
    uint32_t *old = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, rw, 0);
    CHECK(old != MAP_FAILED && *old == 512, "all CPU updates retained");
    CHECK(!shm_unlink(test->name) && shm_open(test->name, O_RDONLY, 0) == -1 && errno == ENOENT, "unlink removes name");
    int replacement = shm_open(test->name, O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(replacement >= 0 && !ftruncate(replacement, PAGE) && !fstat(replacement, &test->new_info), "name recreation");
    CHECK(test->new_info.st_ino != test->old_info.st_ino, "new object has distinct identity");
    uint32_t *fresh = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, replacement, 0);
    CHECK(fresh != MAP_FAILED && !*fresh, "new object starts zeroed");
    *fresh = 99;
    CHECK(*old == 512 && !shm_unlink(test->name), "old mapping isolated after recreation");
    CHECK(alix_get_executable_path(test->executable, sizeof(test->executable)) > 0, "executable discovery");
    test->arguments[0] = test->executable; test->arguments[1] = "read-inherited"; test->arguments[2] = NULL;
    CHECK(!posix_spawn_file_actions_init(&test->actions) && !posix_spawn_file_actions_adddup2(&test->actions, ro, 41), "child read-only file action");
    CHECK(!posix_spawn(&test->child, test->executable, &test->actions, NULL, test->arguments, NULL), "child spawn");
    CHECK(!posix_spawn_file_actions_destroy(&test->actions) && waitpid(test->child, &test->status, 0) == test->child && WIFEXITED(test->status) && WEXITSTATUS(test->status) == 23, "child read-only status");
    CHECK(!munmap(old, PAGE) && !munmap(fresh, PAGE) && !close(rw) && !close(ro) && !close(replacement), "unlinked mappings and handles release");
    test->arguments[1] = "create-holder"; test->arguments[2] = test->holder_name; test->arguments[3] = NULL;
    CHECK(!posix_spawn(&test->child, test->executable, NULL, NULL, test->arguments, NULL), "creator spawn");
    uint64_t deadline = sys_monotonic_millis() + 6000;
    ro = -1; old = MAP_FAILED;
    while (sys_monotonic_millis() < deadline)
    {
        if (ro < 0) ro = shm_open(test->holder_name, O_RDONLY, 0);
        if (ro >= 0 && !fstat(ro, &test->old_info) && test->old_info.st_size == PAGE)
        {
            if (old == MAP_FAILED) old = mmap(NULL, PAGE, PROT_READ, MAP_SHARED, ro, 0);
            if (old != MAP_FAILED && __atomic_load_n(old, __ATOMIC_ACQUIRE) == 0x71717171u) break;
        }
        sys_sleep_ms(1);
    }
    CHECK(old != MAP_FAILED && *old == 0x71717171u, "creator initialized mapping");
    CHECK(!kill(test->child, SIGKILL) && waitpid(test->child, &test->status, 0) == test->child && WIFSIGNALED(test->status), "creator termination");
    CHECK(*old == 0x71717171u && !shm_unlink(test->holder_name) && !munmap(old, PAGE) && !close(ro), "memory survives creator exit until final release");
    rw = shm_open(test->name, O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(rw >= 0, "descriptor-pressure object");
    unsigned count = 0;
    while (count < 256)
    {
        int fd = shm_open(test->name, O_RDONLY, 0);
        if (fd < 0) break;
        test->extra[count++] = fd;
    }
    CHECK(count > 0 && count < 256 && errno == EMFILE, "private descriptor limit");
    CHECK(shm_open("/alix-shm-fd-full", O_CREAT | O_EXCL | O_RDWR, 0600) == -1 && errno == EMFILE, "creation reserves descriptor first");
    CHECK(!close(test->extra[--count]) && shm_open("/alix-shm-fd-full", O_RDONLY, 0) == -1 && errno == ENOENT, "failed creation leaves no name");
    while (count) CHECK(!close(test->extra[--count]), "pressure descriptor release");
    CHECK(!close(rw) && !shm_unlink(test->name), "pressure object release");
    rw = shm_open(BOOT_NAME, O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(rw >= 0 && !close(rw), "named object retained until reboot");
    rw = open(DISK_MARKER, O_CREAT | O_TRUNC | O_RDWR, 0600);
    CHECK(rw >= 0 && write(rw, "shm", 3) == 3 && !fsync(rw) && !close(rw), "independent disk marker");
    free(test);
    serial_printf("SHM_TEST: PASS cpus=8 shared=512 exclusive=1 readonly=1 unlink=1 replace=1 cloexec=1 spawn=1 killed_creator=1 fd_limit=1\n");
    return 0;
}
