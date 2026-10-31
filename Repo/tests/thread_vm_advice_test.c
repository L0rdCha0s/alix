#include "userlib.h"
#include "sys/mman.h"
#include "errno.h"
#include "serial.h"

#define PAGE 4096u
#define WORKERS 4u
#define ROUNDS 64u
#define PATTERN 0xA55A1234u

typedef struct shared shared_t;
typedef struct { shared_t *shared; uint32_t cpu; alix_thread_t thread; } worker_t;
struct shared
{
    volatile uint32_t *word;
    volatile uint32_t ready;
    volatile uint32_t stop;
    volatile uint32_t phase;
    volatile uint32_t failed;
    volatile uint32_t observed[WORKERS];
    uint64_t reads[WORKERS];
    worker_t workers[WORKERS];
};

#define REQUIRE(condition, label) do { if (!(condition)) { \
    serial_printf("VM_ADVICE_TEST: FAIL %s\n", label); return 1; } } while (0)

static bool all_bytes(const uint8_t *bytes, size_t length, uint8_t expected)
{
    for (size_t i = 0; i < length; ++i) if (bytes[i] != expected) return false;
    return true;
}

static void reader(void *argument)
{
    worker_t *worker = argument;
    shared_t *shared = worker->shared;
    if (sys_thread_set_affinity(worker->cpu) != 0 || sys_thread_cpu() != worker->cpu)
        __atomic_store_n(&shared->failed, 1, __ATOMIC_RELEASE);
    __atomic_add_fetch(&shared->ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&shared->stop, __ATOMIC_ACQUIRE))
    {
        uint32_t phase = __atomic_load_n(&shared->phase, __ATOMIC_ACQUIRE);
        /* CPU 3 can refill through safe syscall copy-in while other CPUs use
         * normal instructions and recover through the hardware fault path. */
        if (worker->cpu == 3)
        {
            int result = sys_futex_wait(shared->word, 0, 0);
            if (result != SYSCALL_FUTEX_AGAIN && result != SYSCALL_FUTEX_TIMED_OUT)
                __atomic_store_n(&shared->failed, 1, __ATOMIC_RELEASE);
        }
        uint32_t value = __atomic_load_n(shared->word, __ATOMIC_RELAXED);
        uint32_t after = __atomic_load_n(&shared->phase, __ATOMIC_ACQUIRE);
        if (phase == after && !(phase & 1u) && value != 0)
            __atomic_store_n(&shared->failed, 1, __ATOMIC_RELEASE);
        if (phase == after && !(phase & 1u))
            __atomic_store_n(&shared->observed[worker->cpu], phase, __ATOMIC_RELEASE);
        ++shared->reads[worker->cpu];
        if ((shared->reads[worker->cpu] & 127u) == 0) sys_yield();
    }
}

static bool wait_value(volatile uint32_t *value, uint32_t expected, shared_t *shared)
{
    uint64_t started = sys_monotonic_millis();
    while (__atomic_load_n(value, __ATOMIC_ACQUIRE) != expected)
    {
        if (__atomic_load_n(&shared->failed, __ATOMIC_ACQUIRE) ||
            sys_monotonic_millis() - started > 5000) return false;
        sys_yield();
    }
    return true;
}

static int fault_probe(const char *mode)
{
    uint8_t *page = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(page != MAP_FAILED, "fault allocation");
    int protection;
    if (strcmp(mode, "fault-write") == 0) protection = PROT_READ;
    else if (strcmp(mode, "fault-none") == 0) protection = PROT_NONE;
    else if (strcmp(mode, "fault-exec") == 0) protection = PROT_READ | PROT_WRITE;
    else return 1;
    REQUIRE(mprotect(page, PAGE, protection) == 0 && madvise(page, PAGE, MADV_DONTNEED) == 0,
            "fault setup");
    serial_printf("VM_ADVICE_FAULT: armed %s address=0x%llX\n", mode,
                  (unsigned long long)(uintptr_t)page);
    /* Allow queued serial output to drain before the emergency exception
     * writer starts. The harness still requires the complete armed record. */
    sys_sleep_ms(100);
    if (strcmp(mode, "fault-write") == 0) *(volatile uint8_t *)page = 1;
    else if (strcmp(mode, "fault-none") == 0) { volatile uint8_t value = *(volatile uint8_t *)page; (void)value; }
    else { int (*function)(void) = (int (*)(void))(uintptr_t)page; (void)function(); }
    serial_printf("VM_ADVICE_FAULT: FAIL forbidden access survived\n");
    return 1;
}

int main(int argc, char **argv)
{
    if (argc > 1) return fault_probe(argv[1]);
    const int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    uint8_t *pages = mmap(NULL, 4 * PAGE, PROT_READ | PROT_WRITE, flags, -1, 0);
    REQUIRE(pages != MAP_FAILED, "allocation");
    for (unsigned i = 0; i < 4; ++i) memset(pages + i * PAGE, (int)(0x40 + i), PAGE);
    for (int advice = POSIX_MADV_NORMAL; advice <= POSIX_MADV_DONTNEED; ++advice)
    {
        errno = EDOM;
        REQUIRE(posix_madvise(pages, 4 * PAGE, advice) == 0 && errno == EDOM, "POSIX advice errno");
        for (unsigned i = 0; i < 4; ++i)
            REQUIRE(all_bytes(pages + i * PAGE, PAGE, (uint8_t)(0x40 + i)), "POSIX advice preserves contents");
    }
    REQUIRE(posix_madvise(pages + 1, PAGE, POSIX_MADV_DONTNEED) == EINVAL && errno == EDOM,
            "POSIX error preserves errno");
    REQUIRE(posix_madvise(pages, PAGE, 99) == EINVAL && errno == EDOM, "POSIX unknown policy");
    REQUIRE(madvise(NULL, 0, MADV_DONTNEED) == 0, "advice support query");
    REQUIRE(madvise(pages + 1, PAGE, MADV_DONTNEED) == -1 && errno == EINVAL, "unaligned discard");
    REQUIRE(madvise(pages, PAGE, 99) == -1 && errno == EINVAL, "unknown discard");
    REQUIRE(madvise(pages, PAGE, 0x104) == -1 && errno == EINVAL, "separate advice namespaces");
    REQUIRE(madvise(pages + PAGE, PAGE + 1, MADV_DONTNEED) == 0, "rounded partial discard");
    REQUIRE(all_bytes(pages, PAGE, 0x40) && all_bytes(pages + 3 * PAGE, PAGE, 0x43), "outside contents");
    REQUIRE(all_bytes(pages + PAGE, 2 * PAGE, 0), "demand-zero instruction reads");

    memset(pages + PAGE, 0xB7, PAGE);
    REQUIRE(madvise(pages + PAGE, PAGE, MADV_DONTNEED) == 0, "discard before copy-in");
    REQUIRE(sys_futex_wait((volatile uint32_t *)(pages + PAGE), 0, 0) == SYSCALL_FUTEX_TIMED_OUT,
            "safe copy-in demand zero");
    REQUIRE(madvise(pages + PAGE, PAGE, MADV_DONTNEED) == 0 &&
            sys_time_info((syscall_time_info_t *)(pages + PAGE)) == 0, "safe copy-out commits");
    REQUIRE(all_bytes(pages + PAGE + sizeof(syscall_time_info_t), PAGE - sizeof(syscall_time_info_t), 0),
            "copy-out preserves zero remainder");
    REQUIRE(mprotect(pages + PAGE, PAGE, PROT_READ) == 0 &&
            madvise(pages + PAGE, PAGE, MADV_DONTNEED) == 0, "readonly discard");
    REQUIRE(sys_time_info((syscall_time_info_t *)(pages + PAGE)) < 0 && pages[PAGE] == 0,
            "readonly copy-out denied");
    REQUIRE(mprotect(pages + PAGE, PAGE, PROT_NONE) == 0 &&
            madvise(pages + PAGE, PAGE, MADV_DONTNEED) == 0 &&
            sys_futex_wait((volatile uint32_t *)(pages + PAGE), 0, 0) == SYSCALL_FUTEX_FAULT,
            "hidden discarded page denied");
    REQUIRE(mprotect(pages + PAGE, PAGE, PROT_READ | PROT_WRITE) == 0 && pages[PAGE] == 0,
            "hidden discarded contents stay discarded");
    REQUIRE(munmap(pages + 2 * PAGE, PAGE) == 0, "create hole");
    pages[PAGE] = 0x63;
    REQUIRE(madvise(pages + PAGE, 2 * PAGE, MADV_DONTNEED) == -1 && errno == ENOMEM && pages[PAGE] == 0x63,
            "hole rejection preserves partial range");
    errno = EDOM;
    REQUIRE(posix_madvise(pages + PAGE, 2 * PAGE, POSIX_MADV_DONTNEED) == ENOMEM && errno == EDOM,
            "POSIX validates complete mapping");
    REQUIRE(madvise(pages, 2 * PAGE, MADV_DONTNEED) == 0 &&
            mmap(pages, PAGE, PROT_READ | PROT_WRITE, flags | MAP_FIXED, -1, 0) == pages,
            "fixed replacement over discarded slots");
    REQUIRE(pages[0] == 0 && munmap(pages, 4 * PAGE) == 0, "unmap null slots and hole");

    shared_t *shared = calloc(1, sizeof(*shared));
    REQUIRE(shared != NULL, "race metadata");
    shared->word = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, flags, -1, 0);
    REQUIRE((void *)shared->word != MAP_FAILED, "race allocation");
    for (unsigned i = 0; i < WORKERS; ++i)
    {
        shared->workers[i].shared = shared;
        shared->workers[i].cpu = i;
        REQUIRE(alix_thread_create(&shared->workers[i].thread, "discard_reader", reader, &shared->workers[i]) == 0,
                "reader create");
    }
    REQUIRE(wait_value(&shared->ready, WORKERS, shared), "reader ready");
    for (unsigned round = 0; round < ROUNDS; ++round)
    {
        __atomic_store_n(&shared->phase, round * 2 + 1, __ATOMIC_RELEASE);
        __atomic_store_n(shared->word, PATTERN, __ATOMIC_RELAXED);
        REQUIRE(madvise((void *)shared->word, PAGE, MADV_DONTNEED) == 0, "concurrent discard");
        __atomic_store_n(&shared->phase, round * 2 + 2, __ATOMIC_RELEASE);
        for (unsigned i = 0; i < WORKERS; ++i)
            REQUIRE(wait_value(&shared->observed[i], round * 2 + 2, shared), "cross-CPU zero observation");
    }
    __atomic_store_n(&shared->stop, 1, __ATOMIC_RELEASE);
    for (unsigned i = 0; i < WORKERS; ++i)
        REQUIRE(alix_thread_join(shared->workers[i].thread, NULL) == 0 && shared->reads[i] != 0, "reader join");
    REQUIRE(!shared->failed && *shared->word == 0, "concurrent refill");
    REQUIRE(munmap((void *)shared->word, PAGE) == 0, "race release");
    free(shared);
    serial_printf("VM_ADVICE_TEST: PASS discard=64 readers=4 zero=1 copy=1 posix_preserved=1\n");
    return 0;
}
