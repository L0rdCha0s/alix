#include "userlib.h"
#include "sys/mman.h"
#include "errno.h"
#include "serial.h"

#define PAGE 4096u
#define RESERVATION (512u * 1024u * 1024u)
#define VM_WORKERS 4u
#define PATTERN 0xA55A1234u

static const uint8_t return_42[] = { 0xB8, 42, 0, 0, 0, 0xC3 };

typedef struct vm_shared vm_shared_t;
typedef struct { vm_shared_t *shared; uint32_t cpu; } vm_worker_t;
struct vm_shared
{
    volatile uint32_t ready;
    volatile uint32_t start;
    volatile uint32_t stop;
    volatile uint32_t failed;
    volatile uint32_t phase;
    volatile uint32_t observed[VM_WORKERS];
    volatile uint32_t *word;
    alix_thread_t threads[VM_WORKERS];
    vm_worker_t arguments[VM_WORKERS];
    uint64_t reads[VM_WORKERS];
};

static void reader(void *argument)
{
    vm_worker_t *worker = argument;
    vm_shared_t *shared = worker->shared;
    if (sys_thread_set_affinity(worker->cpu) != 0 || sys_thread_cpu() != worker->cpu)
    {
        __atomic_store_n(&shared->failed, 1, __ATOMIC_RELEASE);
    }
    __atomic_add_fetch(&shared->ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&shared->start, __ATOMIC_ACQUIRE))
    {
        sys_yield();
    }
    while (!__atomic_load_n(&shared->stop, __ATOMIC_ACQUIRE))
    {
        uint32_t phase = __atomic_load_n(&shared->phase, __ATOMIC_ACQUIRE);
        uint32_t value = *shared->word;
        if ((phase == 0 && value != PATTERN && value != 0) || (phase != 0 && value != 0))
        {
            __atomic_store_n(&shared->failed, 1, __ATOMIC_RELEASE);
        }
        if (phase)
        {
            __atomic_store_n(&shared->observed[worker->cpu], phase, __ATOMIC_RELEASE);
        }
        if ((++shared->reads[worker->cpu] & 1023u) == 0)
        {
            sys_yield();
        }
    }
}

static int fault_probe(const char *mode)
{
    uint8_t *page = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED)
    {
        return 1;
    }
    memcpy(page, return_42, sizeof(return_42));
    if (strcmp(mode, "fault-write") == 0)
    {
        if (mprotect(page, PAGE, PROT_READ) != 0) return 1;
        serial_printf("VM_FAULT_TEST: armed write address=0x%llX\n", (unsigned long long)(uintptr_t)page);
        sys_sleep_ms(100); /* Drain queued diagnostics before emergency output. */
        *(volatile uint8_t *)page = 1;
    }
    else if (strcmp(mode, "fault-none") == 0)
    {
        if (mprotect(page, PAGE, PROT_NONE) != 0) return 1;
        serial_printf("VM_FAULT_TEST: armed none address=0x%llX\n", (unsigned long long)(uintptr_t)page);
        sys_sleep_ms(100);
        volatile uint8_t value = *(volatile uint8_t *)page;
        (void)value;
    }
    else if (strcmp(mode, "fault-exec") == 0)
    {
        serial_printf("VM_FAULT_TEST: armed exec address=0x%llX\n", (unsigned long long)(uintptr_t)page);
        sys_sleep_ms(100);
        int (*function)(void) = (int (*)(void))(uintptr_t)page;
        (void)function();
    }
    else
    {
        return 1;
    }
    serial_printf("VM_FAULT_TEST: FAIL forbidden access survived\n");
    return 1;
}

#define REQUIRE(condition, label) do { if (!(condition)) { \
    serial_printf("VM_PLATFORM_TEST: FAIL %s\n", label); return 1; } } while (0)

int main(int argc, char **argv)
{
    if (argc > 1)
    {
        return fault_probe(argv[1]);
    }
    const int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    REQUIRE(mmap(NULL, 0, PROT_READ, flags, -1, 0) == MAP_FAILED && errno == EINVAL, "zero length");
    REQUIRE(mmap(NULL, PAGE, 0x80, flags, -1, 0) == MAP_FAILED && errno == EINVAL,
            "unknown protection rejection");
    REQUIRE(mmap((void *)1, PAGE, PROT_READ, flags | MAP_FIXED_NOREPLACE, -1, 0) == MAP_FAILED,
            "invalid address");

    uint8_t *reservation = mmap(NULL, RESERVATION, PROT_NONE, flags, -1, 0);
    REQUIRE(reservation != MAP_FAILED, "sparse reserve");
    REQUIRE(sys_futex_wait((volatile uint32_t *)reservation, 0, 0) == SYSCALL_FUTEX_FAULT,
            "reserved access denied");
    REQUIRE(mprotect(reservation + PAGE, PAGE * 2, PROT_READ | PROT_WRITE) == 0, "partial commit");
    for (size_t offset = PAGE; offset < PAGE * 3; ++offset)
    {
        REQUIRE(reservation[offset] == 0, "new pages zeroed");
        reservation[offset] = 0x5A;
    }
    REQUIRE(mprotect(reservation + PAGE, PAGE, PROT_NONE) == 0, "hide committed page");
    REQUIRE(sys_futex_wait((volatile uint32_t *)(reservation + PAGE), 0x5A5A5A5Au, 0) == SYSCALL_FUTEX_FAULT,
            "hidden access denied");
    REQUIRE(mprotect(reservation + PAGE, PAGE, PROT_READ) == 0, "restore read permission");
    REQUIRE(reservation[PAGE] == 0x5A, "contents survive PROT_NONE");
    REQUIRE(sys_time_info((syscall_time_info_t *)(reservation + PAGE)) == -1, "kernel copy rejects readonly");
    REQUIRE(munmap(reservation + PAGE, PAGE) == 0, "partial unmap");
    REQUIRE(mprotect(reservation, PAGE * 3, PROT_READ) == -1 && errno == ENOMEM,
            "protect hole is transactional");
    REQUIRE(reservation[PAGE * 2] == 0x5A, "unaffected neighbor retained");
    REQUIRE(mmap(reservation + PAGE * 2, PAGE, PROT_READ | PROT_WRITE,
                 flags | MAP_FIXED_NOREPLACE, -1, 0) == MAP_FAILED && errno == EEXIST,
            "noreplace collision");
    REQUIRE(mmap(reservation + PAGE, PAGE, PROT_READ | PROT_WRITE,
                 flags | MAP_FIXED_NOREPLACE, -1, 0) == reservation + PAGE, "reuse unmapped hole");
    REQUIRE(reservation[PAGE] == 0, "reused address zeroed");
    REQUIRE(munmap(reservation, RESERVATION) == 0, "release sparse range");
    REQUIRE(munmap(reservation, PAGE) == 0, "unmap hole");

    uint8_t *replacement = mmap(NULL, PAGE * 6, PROT_READ | PROT_WRITE, flags, -1, 0);
    REQUIRE(replacement != MAP_FAILED, "replacement setup");
    for (unsigned index = 0; index < 6; ++index) replacement[index * PAGE] = (uint8_t)(index + 1);
    REQUIRE(munmap(replacement + PAGE * 2, PAGE) == 0 &&
            mprotect(replacement + PAGE * 3, PAGE, PROT_NONE) == 0, "replacement holes");
    REQUIRE(mmap(replacement + PAGE, PAGE * 4, PROT_READ | PROT_WRITE, flags | MAP_FIXED,
                 -1, 0) == replacement + PAGE, "fixed replacement across areas and holes");
    REQUIRE(replacement[0] == 1 && replacement[PAGE * 5] == 6, "replacement keeps outside fragments");
    for (size_t offset = PAGE; offset < PAGE * 5; ++offset)
        REQUIRE(replacement[offset] == 0, "fixed replacement is zeroed");
    REQUIRE(mmap(replacement + PAGE, PAGE, PROT_NONE, flags | MAP_FIXED, -1, 0) == replacement + PAGE,
            "replace with reservation");
    REQUIRE(mprotect(replacement + PAGE, PAGE, PROT_READ | PROT_WRITE) == 0 && replacement[PAGE] == 0,
            "commit replaced reservation");
    REQUIRE(munmap(replacement, PAGE * 6) == 0, "replacement release");

    uint8_t *code = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, flags, -1, 0);
    REQUIRE(code != MAP_FAILED, "code allocation");
    memcpy(code, return_42, sizeof(return_42));
    REQUIRE(mprotect(code, PAGE, PROT_READ | PROT_EXEC) == 0, "code RX transition");
    int (*function)(void) = (int (*)(void))(uintptr_t)code;
    REQUIRE(function() == 42, "native generated code");
    REQUIRE(mprotect(code, PAGE, 0x80) == -1 && errno == EINVAL, "unknown protection preserves RX");
    REQUIRE(function() == 42, "rejected protection preserves code");
    REQUIRE(munmap(code, PAGE) == 0, "code release");

    code = mmap(NULL, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC, flags, -1, 0);
    REQUIRE(code != MAP_FAILED, "upstream RWX allocation");
    memcpy(code, return_42, sizeof(return_42));
    function = (int (*)(void))(uintptr_t)code;
    REQUIRE(function() == 42, "native RWX generated code");
    REQUIRE(mprotect(code, PAGE, PROT_EXEC) == 0 && function() == 42, "execute implies readable");
    REQUIRE(mprotect(code, PAGE, PROT_WRITE) == 0, "write implies readable");
    REQUIRE(memcmp(code, return_42, sizeof(return_42)) == 0, "write-only request retains readable bytes");
    memcpy(code, return_42, sizeof(return_42));
    REQUIRE(munmap(code, PAGE) == 0, "RWX code release");

    vm_shared_t *shared = calloc(1, sizeof(*shared));
    REQUIRE(shared != NULL, "shared allocation");
    shared->word = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, flags, -1, 0);
    REQUIRE((void *)shared->word != MAP_FAILED, "shared mapped page");
    *shared->word = PATTERN;
    for (uint32_t cpu = 0; cpu < VM_WORKERS; ++cpu)
    {
        shared->arguments[cpu].shared = shared;
        shared->arguments[cpu].cpu = cpu;
        REQUIRE(alix_thread_create(&shared->threads[cpu], "vm_reader", reader,
                                    &shared->arguments[cpu]) == 0, "reader creation");
    }
    while (__atomic_load_n(&shared->ready, __ATOMIC_ACQUIRE) < VM_WORKERS)
    {
        sys_yield();
    }
    __atomic_store_n(&shared->start, 1, __ATOMIC_RELEASE);
    for (unsigned iteration = 0; iteration < 64; ++iteration)
    {
        REQUIRE(mprotect((void *)shared->word, PAGE, PROT_READ) == 0, "SMP revoke writes");
        REQUIRE(sys_time_info((syscall_time_info_t *)shared->word) == -1, "SMP readonly copy");
        REQUIRE(mprotect((void *)shared->word, PAGE, PROT_READ | PROT_WRITE) == 0, "SMP restore writes");
        REQUIRE(*shared->word == PATTERN, "protection retains shared data");
    }
    REQUIRE(mmap((void *)shared->word, PAGE, PROT_READ, flags | MAP_FIXED, -1, 0) == (void *)shared->word,
            "SMP fixed replacement");
    REQUIRE(*shared->word == 0, "replacement visible to caller");
    __atomic_store_n(&shared->phase, 1, __ATOMIC_RELEASE);
    for (uint32_t cpu = 0; cpu < VM_WORKERS; ++cpu)
    {
        while (__atomic_load_n(&shared->observed[cpu], __ATOMIC_ACQUIRE) == 0)
        {
            sys_yield();
        }
    }
    __atomic_store_n(&shared->stop, 1, __ATOMIC_RELEASE);
    for (uint32_t cpu = 0; cpu < VM_WORKERS; ++cpu)
    {
        REQUIRE(alix_thread_join(shared->threads[cpu], NULL) == 0, "reader join");
        REQUIRE(shared->reads[cpu] != 0, "reader ran on each CPU");
    }
    REQUIRE(!__atomic_load_n(&shared->failed, __ATOMIC_ACQUIRE) && *shared->word == 0,
            "concurrent readable mappings preserved");
    REQUIRE(munmap((void *)shared->word, PAGE) == 0, "shared release");
    free(shared);
    serial_printf("VM_PLATFORM_TEST: PASS sparse=512MiB readers=4 protections=128 fixed=1 jit=42 rwx=42\n");
    return 0;
}
