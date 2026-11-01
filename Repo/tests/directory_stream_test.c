#include "dirent.h"
#include "pthread.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "errno.h"
#include "serial.h"
#include "usyscall.h"

#define ROOT_PATH "/tmp/dirent-test"
#define FILES 48u
#define WORKERS 8u
#define CHECK(c,label) do { if (!(c)) { serial_printf("DIRECTORY_STREAM_TEST: FAIL %s errno=%d\n",label,errno); return 1; } } while (0)
typedef struct shared shared_t;
typedef struct { shared_t *shared; pthread_t thread; unsigned cpu,failed; syscall_directory_entry_t entry; } worker_t;
struct shared
{
    int handle;
    uint32_t counts[FILES + 2], mask;
    worker_t workers[WORKERS];
};

static void *read_shared_handle(void *argument)
{
    worker_t *worker = argument;
    shared_t *shared = worker->shared;
    if (sys_thread_set_affinity(worker->cpu) || sys_thread_cpu() != worker->cpu)
    { worker->failed = 1; return NULL; }
    for (;;)
    {
        int64_t result = sys_directory(SYSCALL_DIRECTORY_NEXT, shared->handle, &worker->entry, sizeof(worker->entry));
        if (!result) break;
        if (result != 1) { worker->failed = 2; break; }
        syscall_directory_entry_t *entry = &worker->entry;
        if (entry->version != SYSCALL_DIRENT_VERSION || entry->size != sizeof(*entry) || !entry->inode ||
            entry->name_length > SYSCALL_DIRENT_NAME_MAX || entry->name[entry->name_length])
        { worker->failed = 3; break; }
        unsigned index;
        if (!strcmp(entry->name, ".")) index = FILES;
        else if (!strcmp(entry->name, "..")) index = FILES + 1;
        else
        {
            if (strncmp(entry->name, "item-", 5)) { worker->failed = 4; break; }
            index = (unsigned)atoi(entry->name + 5);
            if (index >= FILES || entry->type != 1) { worker->failed = 5; break; }
        }
        __atomic_add_fetch(&shared->counts[index], 1u, __ATOMIC_RELAXED);
    }
    __atomic_fetch_or(&shared->mask, 1u << worker->cpu, __ATOMIC_RELEASE);
    return NULL;
}

int main(void)
{
    (void)mkdir("/tmp", 0);
    (void)mkdir(ROOT_PATH, 0);
    (void)mkdir(ROOT_PATH "/child", 0);
    (void)mkdir(ROOT_PATH "/many", 0);
    char *path = malloc(256), *long_name = malloc(181);
    CHECK(path && long_name, "heap path buffers");
    memset(long_name, 'x', 180); long_name[180] = 0;
    snprintf(path, 256, "%s/%s", ROOT_PATH, long_name);
    FILE *file = fopen(path, "w");
    CHECK(file && fclose(file) == 0, "long file name");
    file = fopen(ROOT_PATH "/caf\xc3\xa9", "w");
    CHECK(file && fclose(file) == 0, "UTF8 file name");
    for (unsigned index = 0; index < FILES; ++index)
    {
        snprintf(path, 256, "%s/many/item-%u", ROOT_PATH, index);
        file = fopen(path, "w");
        CHECK(file && fclose(file) == 0, "fixture file");
    }
    DIR *directory = opendir(ROOT_PATH), *second = opendir(ROOT_PATH);
    CHECK(directory && second, "independent streams");
    struct dirent *entry = readdir(directory);
    CHECK(entry && !strcmp(entry->d_name, ".") && entry->d_type == DT_DIR && entry->d_ino, "dot identity");
    ino_t identity = entry->d_ino;
    entry = readdir(second);
    CHECK(entry && !strcmp(entry->d_name, ".") && entry->d_ino == identity, "stable identity independent cursor");
    file = fopen(ROOT_PATH "/later", "w");
    CHECK(file && fclose(file) == 0, "mutate after snapshot");
    unsigned count = 1, long_seen = 0, utf8_seen = 0, child_seen = 0;
    errno = EDOM;
    while ((entry = readdir(directory)))
    {
        ++count;
        CHECK(strcmp(entry->d_name, "later"), "immutable snapshot");
        if (!strcmp(entry->d_name, long_name)) { ++long_seen; CHECK(entry->d_type == DT_REG, "regular type"); }
        if (!strcmp(entry->d_name, "caf\xc3\xa9")) ++utf8_seen;
        if (!strcmp(entry->d_name, "child")) { ++child_seen; CHECK(entry->d_type == DT_DIR, "directory type"); }
    }
    CHECK(count == 6 && long_seen == 1 && utf8_seen == 1 && child_seen == 1 && errno == EDOM,
          "all names without truncation and EOF errno");
    rewinddir(directory);
    entry = readdir(directory);
    CHECK(entry && !strcmp(entry->d_name, ".") && entry->d_ino == identity, "rewind identity");
    unsigned later_seen = 0;
    while ((entry = readdir(directory))) if (!strcmp(entry->d_name, "later")) ++later_seen;
    CHECK(later_seen == 1, "rewind refreshes directory state");
    CHECK(closedir(directory) == 0 && closedir(second) == 0, "close streams");
    directory = opendir(ROOT_PATH "/child");
    CHECK(directory && readdir(directory), "child stream");
    entry = readdir(directory);
    CHECK(entry && !strcmp(entry->d_name, "..") && entry->d_ino == identity, "parent identity");
    CHECK(closedir(directory) == 0, "close child");
    CHECK(!opendir(ROOT_PATH "/missing") && errno == ENOENT, "missing directory");
    CHECK(!opendir(ROOT_PATH "/later") && errno == ENOTDIR, "regular file rejected");
    CHECK(!opendir("") && errno == ENOENT, "empty path rejected");
    CHECK(!opendir(NULL) && errno == EFAULT, "null path rejected");
    CHECK(!readdir(NULL) && errno == EBADF && closedir(NULL) == -1 && errno == EBADF, "null stream rejected");
    shared_t *shared = calloc(1, sizeof(*shared));
    CHECK(shared, "heap shared state");
    shared->handle = (int)sys_directory(SYSCALL_DIRECTORY_OPEN, 0, ROOT_PATH "/many", 0);
    CHECK(shared->handle >= 0, "shared kernel cursor");
    CHECK(sys_directory(SYSCALL_DIRECTORY_NEXT, shared->handle, (void *)1, sizeof(syscall_directory_entry_t)) == -EFAULT,
          "bad output before consume");
    for (unsigned index = 0; index < WORKERS; ++index)
    {
        worker_t *worker = &shared->workers[index]; worker->shared = shared; worker->cpu = index;
        CHECK(pthread_create(&worker->thread, NULL, read_shared_handle, worker) == 0, "create reader");
    }
    for (unsigned index = 0; index < WORKERS; ++index)
        CHECK(pthread_join(shared->workers[index].thread, NULL) == 0 && !shared->workers[index].failed, "join reader");
    for (unsigned index = 0; index < FILES + 2; ++index) CHECK(shared->counts[index] == 1, "each entry exactly once");
    CHECK(shared->mask == 0xff, "all CPUs");
    CHECK(sys_directory(SYSCALL_DIRECTORY_CLOSE, shared->handle, NULL, 0) == 0 &&
          sys_directory(SYSCALL_DIRECTORY_CLOSE, shared->handle, NULL, 0) == -EBADF, "closed handle rejected");
    DIR **streams = calloc(257, sizeof(*streams));
    CHECK(streams, "heap limit state");
    for (unsigned index = 0; index < 253; ++index) CHECK((streams[index] = opendir(ROOT_PATH "/child")), "handle capacity excluding stdio");
    CHECK(!opendir(ROOT_PATH "/child") && errno == EMFILE, "bounded table admission");
    for (unsigned index = 0; index < 253; ++index) CHECK(closedir(streams[index]) == 0, "release capacity");
    directory = opendir(ROOT_PATH "/child");
    CHECK(directory && closedir(directory) == 0, "fresh stream after limit");
    free(streams); free(shared); free(long_name); free(path);
    serial_printf("DIRECTORY_STREAM_TEST: PASS workers=8 mask=0xFF exact_once=50 names180=1 UTF8=1 snapshot=1 limit256=1\n");
    return 0;
}
