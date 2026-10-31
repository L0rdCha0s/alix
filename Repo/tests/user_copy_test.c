#include "userlib.h"
#include "serial.h"
#include "sys/mman.h"

#define PAGE_BYTES 4096u
#define COPY_RACE_ROUNDS 128u

typedef struct
{
    void *page;
    int fd;
    alix_thread_t thread;
    volatile uint32_t stop;
    volatile uint32_t ready;
    volatile uint32_t okay;
    volatile uint32_t rejected;
    volatile uint32_t failed;
} copy_race_t;

static int failure(const char *reason)
{
    serial_printf("USER_COPY_TEST: FAIL %s\n", reason);
    return 1;
}

static void copy_worker(void *argument)
{
    copy_race_t *race = (copy_race_t *)argument;
    if (sys_thread_set_affinity(1) != 0 || sys_thread_cpu() != 1)
    {
        __atomic_store_n(&race->failed, 1, __ATOMIC_RELEASE);
        __atomic_store_n(&race->ready, 1, __ATOMIC_RELEASE);
        return;
    }
    __atomic_store_n(&race->ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&race->stop, __ATOMIC_ACQUIRE))
    {
        ssize_t bytes = sys_pread(race->fd, race->page, 16, 0);
        if (bytes == 16)
        {
            __atomic_add_fetch(&race->okay, 1, __ATOMIC_RELEASE);
        }
        else if (bytes < 0)
        {
            __atomic_add_fetch(&race->rejected, 1, __ATOMIC_RELEASE);
        }
        else
        {
            __atomic_store_n(&race->failed, 1, __ATOMIC_RELEASE);
            break;
        }
        sys_yield();
    }
}

static bool wait_for_count(volatile uint32_t *count, copy_race_t *race)
{
    uint64_t deadline = sys_monotonic_millis() + 2000;
    while (__atomic_load_n(count, __ATOMIC_ACQUIRE) == 0)
    {
        if (__atomic_load_n(&race->failed, __ATOMIC_ACQUIRE) ||
            sys_monotonic_millis() >= deadline)
        {
            return false;
        }
        sys_yield();
    }
    return true;
}

int main(void)
{
    static const syscall_time_info_t readonly_time;
    uint8_t *pages = mmap(NULL, 3 * PAGE_BYTES, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pages == MAP_FAILED)
    {
        return failure("mapping");
    }
    int fd = sys_open("/tmp/user-copy.bin",
                       SYSCALL_OPEN_READ | SYSCALL_OPEN_WRITE | SYSCALL_OPEN_CREATE | SYSCALL_OPEN_TRUNCATE);
    if (fd < 0)
    {
        return failure("fixture open");
    }
    memset(pages, 0x6A, PAGE_BYTES);
    if (sys_write(fd, pages, 32) != 32 || mprotect(pages + PAGE_BYTES, PAGE_BYTES, PROT_NONE) != 0)
    {
        return failure("fixture write/protect");
    }
    void *hidden = pages + PAGE_BYTES;
    if (sys_write(fd, hidden, 16) >= 0 || sys_pread(fd, hidden, 16, 0) >= 0 ||
        sys_time_info((syscall_time_info_t *)hidden) >= 0 ||
        sys_time_info((syscall_time_info_t *)&readonly_time) >= 0 ||
        sys_cpu_snapshot((syscall_cpu_stats_t *)hidden, 1) >= 0 ||
        sys_futex_wait((volatile uint32_t *)hidden, 0, 0) != SYSCALL_FUTEX_FAULT ||
        sys_lseek(fd, 0, SYSCALL_SEEK_CUR) != 32)
    {
        return failure("PROT_NONE syscall access");
    }
    if (mprotect(pages, PAGE_BYTES, PROT_READ) != 0 ||
        sys_pread(fd, pages, 16, 0) >= 0 ||
        sys_time_info((syscall_time_info_t *)pages) >= 0 ||
        sys_write(fd, pages, 16) != 16)
    {
        return failure("read-only permissions");
    }
    if (mprotect(pages, PAGE_BYTES, PROT_READ | PROT_WRITE) != 0 ||
        sys_pread(fd, pages, 16, 0) != 16)
    {
        return failure("restore writable copyout");
    }
    for (size_t i = 0; i < 16; ++i)
    {
        if (pages[i] != 0x6A)
        {
            return failure("copyout contents");
        }
    }

    static const char path[] = "/tmp/user-copy.bin";
    char *edge_path = (char *)pages + PAGE_BYTES - sizeof(path);
    memcpy(edge_path, path, sizeof(path));
    int edge_fd = sys_open(edge_path, SYSCALL_OPEN_READ);
    if (edge_fd < 0 || sys_close(edge_fd) != 0)
    {
        return failure("NUL at mapped page boundary");
    }
    pages[PAGE_BYTES - 1] = 'x';
    if (sys_open((char *)pages + PAGE_BYTES - 1, SYSCALL_OPEN_READ) >= 0)
    {
        return failure("unterminated string into PROT_NONE");
    }
    pages[PAGE_BYTES - 1] = 0;

    int shell = sys_shell_open();
    int *status = (int *)(pages + 128);
    int *running = (int *)(pages + 132);
    *status = *running = 0x11223344;
    if (shell < 0 || sys_shell_poll(shell, hidden, 8, status, running) >= 0 ||
        *status != 0x11223344 || *running != 0x11223344 ||
        sys_shell_poll(shell, (char *)pages, 1, status, running) != 0 || pages[0] != 0 ||
        sys_shell_close(shell) != 0)
    {
        return failure("shell poll protected output");
    }
    if (munmap(pages + 2 * PAGE_BYTES, PAGE_BYTES) != 0 ||
        sys_write(fd, pages + 2 * PAGE_BYTES, 4) >= 0 ||
        sys_time_info((syscall_time_info_t *)(pages + 2 * PAGE_BYTES)) >= 0)
    {
        return failure("unmapped syscall access");
    }

    copy_race_t *race = (copy_race_t *)calloc(1, sizeof(*race));
    if (!race)
    {
        return failure("race allocation");
    }
    race->fd = fd;
    race->page = pages;
    if (sys_thread_set_affinity(0) != 0 || sys_thread_cpu() != 0 ||
        alix_thread_create(&race->thread, "copy_race", copy_worker, race) != 0 ||
        !wait_for_count(&race->ready, race) || !wait_for_count(&race->okay, race))
    {
        /* A live worker may own the heap record: process exit handles cleanup. */
        return failure("cross-core reader startup");
    }
    if (mprotect(pages, PAGE_BYTES, PROT_NONE) != 0 || !wait_for_count(&race->rejected, race))
    {
        return failure("cross-core denied copy");
    }
    for (unsigned i = 0; i < COPY_RACE_ROUNDS; ++i)
    {
        if (mprotect(pages, PAGE_BYTES, PROT_READ | PROT_WRITE) != 0)
        {
            return failure("race restore");
        }
        sys_yield();
        if (mprotect(pages, PAGE_BYTES, PROT_NONE) != 0)
        {
            return failure("race protect");
        }
        sys_yield();
    }
    if (mprotect(pages, PAGE_BYTES, PROT_READ | PROT_WRITE) != 0)
    {
        return failure("final restore");
    }
    __atomic_store_n(&race->stop, 1, __ATOMIC_RELEASE);
    if (alix_thread_join(race->thread, NULL) != 0)
    {
        return failure("reader join");
    }
    bool okay = !race->failed && race->okay != 0 && race->rejected != 0;
    uint32_t accepted = race->okay;
    uint32_t rejected = race->rejected;
    free(race);
    if (!okay || sys_thread_set_affinity((uint32_t)-1) != 0 ||
        munmap(pages, 2 * PAGE_BYTES) != 0 || sys_close(fd) != 0)
    {
        return failure("final cleanup or race result");
    }
    serial_printf("USER_COPY_TEST: PASS cpu_mask=0x3 race_rounds=%u accepted=%u rejected=%u\n",
                  COPY_RACE_ROUNDS, accepted, rejected);
    return 0;
}
