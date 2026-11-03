#include "errno.h"
#include "fcntl.h"
#include "pthread.h"
#include "serial.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "sys/mman.h"
#include "sys/stat.h"
#include "unistd.h"
#include "usyscall.h"

#define LENGTH 65536u
#define WRITE_PATH "/tmp/fsync-disk/gecko-os/persist.bin"
#define REMOUNT_PATH "/root/gecko-os/persist.bin"
#define CHECK(c, label) do { if (!(c)) { \
    serial_printf("GECKO_OS_INTERFACES_TEST: FAIL %s line=%u errno=%d\n", label, __LINE__, errno); \
    return 1; } } while (0)

typedef struct {
    pthread_t thread;
    int fd, failed;
    unsigned cpu;
    long total;
    unsigned char *bytes;
} worker_t;

static unsigned char pattern(unsigned i) { return (unsigned char)((i * 37u + i / 257u) ^ 0xa5u); }

static void *worker(void *argument)
{
    worker_t *item = argument;
    if (sys_thread_set_affinity(item->cpu) || sys_thread_cpu() != item->cpu) item->failed = 1;
    for (unsigned round = 0; round < 4; ++round)
    {
        errno = EDOM;
        if (fsync(item->fd) || errno != EDOM || sysconf(_SC_PHYS_PAGES) != item->total ||
            sysconf(_SC_AVPHYS_PAGES) <= 0 || pread(item->fd, item->bytes, 1024, 8192) != 1024)
            item->failed = 1;
        for (unsigned i = 0; i < 1024; ++i)
            if (item->bytes[i] != pattern(8192 + i)) item->failed = 1;
    }
    return NULL;
}

static int read_persisted(bool legacy)
{
    unsigned char *bytes = malloc(LENGTH);
    CHECK(bytes, "readback buffer");
    int fd = open(REMOUNT_PATH, O_RDONLY);
    CHECK(fd >= 0, "file survives independent remount");
    struct stat *info = calloc(1, sizeof(*info));
    CHECK(info && !fstat(fd, info) && S_ISREG(info->st_mode) && info->st_size == LENGTH,
          "persisted file metadata");
    size_t offset = 0;
    while (offset < LENGTH)
    {
        ssize_t count = read(fd, bytes + offset, LENGTH - offset);
        CHECK(count > 0 && (size_t)count <= LENGTH - offset, "persisted bytes");
        offset += (size_t)count;
    }
    for (unsigned i = 0; i < LENGTH; ++i) CHECK(bytes[i] == pattern(i), "persisted payload");
    CHECK(!close(fd), "close persisted file");
    serial_printf("FSYNC_REMOUNT_TEST: PASS bytes=65536 metadata=1\n");
    if (!legacy)
    {
        fd = open("/root/gecko-os/resize.bin", O_RDONLY);
        CHECK(fd >= 0 && !fstat(fd, info) && info->st_size == 8192 &&
              pread(fd, bytes, 8192, 0) == 8192 && !memcmp(bytes, "abc", 3), "resized file survives remount");
        for (unsigned i = 3; i < 8192; ++i) CHECK(!bytes[i], "persisted resize zero-fill");
        CHECK(!close(fd), "close resized readback");
        serial_printf("FILE_RESIZE_REMOUNT_TEST: PASS bytes=8192 shrink=1 grow=1 zero_fill=1\n");
    }
    free(info); free(bytes);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "read")) return read_persisted(false);
    if (argc == 2 && !strcmp(argv[1], "read-legacy")) return read_persisted(true);
    CHECK(sysconf(_SC_NPROCESSORS_ONLN) == 8, "eight online CPUs");
    errno = EDOM;
    long total = sysconf(_SC_PHYS_PAGES), before = sysconf(_SC_AVPHYS_PAGES);
    CHECK(total > 0 && before > 4096 && before <= total && errno == EDOM, "actual physical memory query");
    CHECK(sys_memory_pages(2) == -EINVAL, "unknown raw memory query");
    CHECK(sysconf(-1) == -1 && errno == EINVAL, "unknown sysconf key");
    const size_t memory_length = 16u * 1024u * 1024u;
    unsigned char *pages = mmap(NULL, memory_length, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(pages != MAP_FAILED, "memory accounting map");
    for (size_t i = 0; i < memory_length; i += 4096) pages[i] = 0x5a;
    long used = sysconf(_SC_AVPHYS_PAGES);
    CHECK(used > 0 && used < before && sysconf(_SC_PHYS_PAGES) == total, "backing consumes physical pages");
    errno = EDOM;
    CHECK(!madvise(pages, memory_length, MADV_WILLNEED) && errno == EDOM, "will-need advice");
    for (size_t i = 0; i < memory_length; i += 4096) CHECK(pages[i] == 0x5a, "advice preserves contents");
    CHECK(!mprotect(pages, 4096, PROT_NONE) && !madvise(pages, 4096, MADV_WILLNEED) &&
          !mprotect(pages, 4096, PROT_READ | PROT_WRITE) && pages[0] == 0x5a, "protected advice preserves contents");
    CHECK(madvise(pages + 1, 4096, MADV_WILLNEED) == -1 && errno == EINVAL, "unaligned advice");
    CHECK(!munmap(pages, memory_length), "unmap accounting pages");
    CHECK(madvise(pages, memory_length, MADV_WILLNEED) == -1 && errno == ENOMEM, "unowned advice");
    CHECK(sysconf(_SC_AVPHYS_PAGES) > used, "unmapping releases physical backing");

    CHECK(!mkdir("/tmp/fsync-disk/gecko-os", 0700), "persistent parent directory");
    int fd = open(WRITE_PATH, O_RDWR | O_CREAT | O_EXCL, 0666);
    CHECK(fd >= 0, "persistent file creation");
    unsigned char *bytes = malloc(LENGTH);
    CHECK(bytes, "write buffer");
    int resized = open("/tmp/fsync-disk/gecko-os/resize.bin", O_CREAT | O_EXCL | O_RDWR, 0666);
    CHECK(resized >= 0 && write(resized, "abcdef", 6) == 6 && lseek(resized, 1234, SEEK_SET) == 1234 &&
          !ftruncate(resized, 3) && !ftruncate(resized, 8192) && lseek(resized, 0, SEEK_CUR) == 1234 &&
          ftruncate(resized, (off_t)1 << 40) == -1 && errno == EFBIG && !fsync(resized) && !close(resized),
          "mounted shrink/grow, offset preservation and format bound");
    for (unsigned i = 0; i < LENGTH; ++i) bytes[i] = pattern(i);
    size_t offset = 0;
    while (offset < LENGTH)
    {
        ssize_t count = write(fd, bytes + offset, LENGTH - offset);
        CHECK(count > 0 && (size_t)count <= LENGTH - offset, "persistent write");
        offset += (size_t)count;
    }
    int alias = dup(fd);
    CHECK(alias >= 0 && !close(fd) && lseek(alias, 123, SEEK_SET) == 123 &&
          !fsync(alias) && lseek(alias, 0, SEEK_CUR) == 123, "retained alias flush preserves offset");
    worker_t *workers = calloc(8, sizeof(*workers));
    CHECK(workers, "heap-owned worker records");
    for (unsigned i = 0; i < 8; ++i)
    {
        workers[i].fd = alias; workers[i].cpu = i; workers[i].total = total;
        workers[i].bytes = malloc(1024);
        CHECK(workers[i].bytes && !pthread_create(&workers[i].thread, NULL, worker, &workers[i]), "start workers");
    }
    for (unsigned i = 0; i < 8; ++i)
    {
        CHECK(!pthread_join(workers[i].thread, NULL) && !workers[i].failed, "concurrent flush/query/read");
        free(workers[i].bytes);
    }
    free(workers); free(bytes);
    CHECK(!close(alias) && fsync(alias) == -1 && errno == EBADF, "closed descriptor");
    CHECK(fsync(-1) == -1 && errno == EBADF && fsync(999) == -1 && errno == EBADF, "invalid descriptors");
    int *pipes = calloc(2, sizeof(*pipes));
    CHECK(pipes && !pipe(pipes) && fsync(pipes[0]) == -1 && errno == EINVAL &&
          fsync(pipes[1]) == -1 && errno == EINVAL, "pipe cannot be flushed");
    CHECK(!close(pipes[0]) && !close(pipes[1]), "close pipes");
    free(pipes);
    CHECK(fsync(STDOUT_FILENO) == -1 && errno == EINVAL, "console cannot be flushed");
    fd = open(WRITE_PATH, O_RDONLY);
    CHECK(fd >= 0 && !fsync(fd) && !close(fd), "flush read-only description");
    serial_printf("GECKO_OS_INTERFACES_TEST: PASS cpus=8 fsync=1 madv_willneed=1 memory_pages=1\n");
    return 0;
}
