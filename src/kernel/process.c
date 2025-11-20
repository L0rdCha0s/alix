#include "process.h"

#include "heap.h"
#include "arch/x86/segments.h"
#include "arch/x86/cpu.h"
#include "arch/x86/smp_boot.h"
#include "paging.h"
#include "libc.h"
#include "serial.h"
#include "msr.h"
#include "console.h"
#include "fd.h"
#include "elf.h"
#include "user_atk_host.h"
#include "shell_service.h"
#include "syscall_defs.h"
#include "user_memory.h"
#include "user_copy.h"
#include "memory_layout.h"
#include "timer.h"
#include "interrupts.h"
#include "smp.h"
#include "spinlock.h"
#include "build_features.h"
#include <stddef.h>

extern uintptr_t kernel_heap_end;

#define MSR_FS_BASE         0xC0000100
#define MSR_GS_BASE         0xC0000101
#define RFLAGS_RESERVED_BIT (1ULL << 1)
#define RFLAGS_IF_BIT       (1ULL << 9)
#define RFLAGS_DEFAULT      (RFLAGS_RESERVED_BIT | RFLAGS_IF_BIT)
#define CONTEXT_SWITCH_SAVED_WORDS 7ULL

#define PROCESS_STACK_GUARD_SIZE         (4096UL)
#define STACK_GUARD_PATTERN              0x5A
#define ENABLE_SMP_BOOT_STACK_SCAN         0
#define SMP_BOOT_STACK_SCAN_MAX_QWORDS     8192ULL
#define STACK_SCAN_DUMP_CONTEXT_QWORDS     16ULL
#ifndef ENABLE_SCHEDULER_STACK_DUMP
#define ENABLE_SCHEDULER_STACK_DUMP      0
#endif
#define SCHEDULER_STACK_DUMP_QWORDS      32ULL
#ifndef ENABLE_CONTEXT_GUARD
#define ENABLE_CONTEXT_GUARD             0
#endif
#define CONTEXT_GUARD_WORDS              8ULL
#ifndef ENABLE_STACK_WRITE_DEBUG
#define ENABLE_STACK_WRITE_DEBUG         0
#endif
#ifndef STACK_WATCH_SNAPSHOT_BYTES
#define STACK_WATCH_SNAPSHOT_BYTES       128ULL
#endif
#ifndef STACK_WATCH_TIMEOUT_LIMIT
#define STACK_WATCH_TIMEOUT_LIMIT        20U
#endif
#ifndef ENABLE_STACK_WRITE_DEBUG_LOGS
#define ENABLE_STACK_WRITE_DEBUG_LOGS    0
#endif
#ifndef ENABLE_STACK_SCAN_LOGS
#define ENABLE_STACK_SCAN_LOGS           0
#endif
#ifndef ENABLE_STACK_GUARD_PROTECT
#define ENABLE_STACK_GUARD_PROTECT       0
#endif
#ifndef CONTEXT_GUARD_STRICT
#define CONTEXT_GUARD_STRICT             0
#endif
#ifndef THREAD_CREATE_DEBUG
#define THREAD_CREATE_DEBUG              1
#endif

#define STATIC_ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static const char *const g_context_guard_reg_names[] = {
    "r15",
    "r14",
    "r13",
    "r12",
    "rbx",
    "rbp",
    "rflags"
};

static void thread_trampoline(void) __attribute__((noreturn));

static void fatal(const char *msg) __attribute__((noreturn));
static bool string_name_equals(const char *lhs, const char *rhs);
static void process_create_log(const char *name, const char *event);

#define USER_ADDRESS_SPACE_BASE   (g_mem_layout.user_pointer_base)
#define USER_STUB_CODE_BASE       (USER_ADDRESS_SPACE_BASE + 0x00100000ULL)
#define USER_PREEMPT_STUB_BASE    (USER_ADDRESS_SPACE_BASE + 0x00110000ULL)
#define USER_STACK_TOP            (g_mem_layout.user_stack_top)
#define USER_STACK_SIZE           (g_mem_layout.user_stack_size)
#define USER_HEAP_BASE            (g_mem_layout.user_heap_base)
#define USER_HEAP_SIZE            (g_mem_layout.user_heap_size)
#define PAGE_SIZE_BYTES_LOCAL     4096ULL
#define PROCESS_HEAP_L2_SHIFT     9ULL
#define PROCESS_HEAP_L2_ENTRIES   (1ULL << PROCESS_HEAP_L2_SHIFT)
#define PROCESS_HEAP_L2_MASK      (PROCESS_HEAP_L2_ENTRIES - 1ULL)
#define PROCESS_HEAP_PRESENT_WORDS ((PROCESS_HEAP_L2_ENTRIES + 63ULL) / 64ULL)
#define PROCESS_HEAP_L2_SPAN      (PROCESS_HEAP_L2_ENTRIES * PAGE_SIZE_BYTES_LOCAL)

typedef uint64_t cpu_context_t;

#define PROCESS_TIME_SLICE_DEFAULT_TICKS 10U
#define THREAD_MAGIC 0x54485244u /* 'THRD' */
#define PROCESS_MAGIC 0x50524353u /* 'PRCS' */

typedef struct
{
    uint64_t preempt_resume_rip;
} thread_tls_t;

extern void process_preempt_trampoline(void);

void process_preempt_hook(void);

typedef struct
{
    uint8_t bytes[512];
} __attribute__((aligned(64))) fpu_state_t;

typedef struct process_user_region
{
    void *raw_allocation;
    void *aligned_allocation;
    size_t mapped_size;
    uintptr_t user_base;
    bool writable;
    bool executable;
    struct process_user_region *next;
} process_user_region_t;

#define THREAD_CONTEXT_REDZONE_BYTES (64ULL * 1024ULL)
#define STACK_OWNER_BUCKET_SHIFT 15
#define STACK_OWNER_BUCKET_SIZE (1UL << STACK_OWNER_BUCKET_SHIFT)
#define STACK_OWNER_BUCKET_COUNT 256u
#define STACK_OWNER_BUCKET_MASK (STACK_OWNER_BUCKET_COUNT - 1)

typedef struct user_thread_bootstrap
{
    uintptr_t entry;
    uintptr_t stack_top;
    uint64_t argc;
    uintptr_t argv_ptr;
} user_thread_bootstrap_t;

typedef struct stack_owner_entry stack_owner_entry_t;

static const uint8_t g_user_exit_stub[] = {
    0x31, 0xFF,       /* xor edi, edi */
    0x31, 0xC0,       /* xor eax, eax */
    0xCD, 0x80,       /* int 0x80 */
    0xF4              /* hlt (should not reach) */
};

static const uint8_t g_user_preempt_stub[] = {
    0xB8, (uint8_t)SYSCALL_YIELD, 0x00, 0x00, 0x00, /* mov eax, SYSCALL_YIELD */
    0xCD, 0x80,                                      /* int 0x80 */
    0xEB, 0xF9                                       /* jmp back to self */
};


struct trap_frame
{
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t rbp;
    uint64_t rdx;
    uint64_t rcx;
    uint64_t rbx;
    uint64_t rax;
    uint64_t vector;
    uint64_t error_code;
    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
    uint64_t rsp;
    uint64_t ss;
};

struct thread
{
    thread_tls_t tls;
    process_t *process;
    cpu_context_t *context;
    bool context_valid;
    uint8_t *stack_base;
    uint8_t *stack_guard_base;
    uint8_t *stack_allocation_raw;
    size_t stack_size;
    size_t stack_allocation_size;
    uintptr_t kernel_stack_top;
    thread_entry_t entry;
    void *arg;
    thread_state_t state;
    struct thread *queue_next;
    struct thread *queue_prev;
    struct thread *registry_next;
    uint32_t run_queue_cpu;
    fpu_state_t fpu_state;
    uint64_t fs_base;
    uint64_t gs_base;
    uint32_t time_slice_remaining;
    thread_priority_t base_priority;
    thread_priority_t priority;
    thread_priority_t priority_override;
    bool priority_override_active;
    int exit_status;
    bool in_run_queue;
    bool is_idle;
    bool exited;
    bool in_transition;
    bool preempt_pending;
    bool fpu_initialized;
    wait_queue_t *waiting_queue;
    thread_t *wait_queue_next;
    uint32_t magic;
    char name[PROCESS_NAME_MAX];
    bool stack_guard_failed;
    const char *stack_guard_reason;
    bool is_user;
    bool stack_watch_blocked;
    bool stack_watch_timeout_logged;
    uint32_t stack_watch_timeout_count;
    stack_owner_entry_t *stack_owner_entries;
    bool context_guard_frozen;
    const char *context_guard_freeze_label;
    const char *fault_reason;
    uint64_t fault_error_code;
    uint64_t fault_address;
    bool fault_has_address;
    bool sleeping;
    uint64_t sleep_until_tick;
    struct thread *sleep_queue_next;
    uint64_t context_guard_hash;
    uintptr_t context_guard_ptr;
    uint64_t context_guard_generation;
    uint64_t context_guard_words[CONTEXT_GUARD_WORDS];
    size_t context_guard_count;
    uintptr_t context_guard_protect_base;
    size_t context_guard_protect_len;
    bool context_guard_protected;
    bool context_guard_enabled;
    uint32_t last_cpu_index;
    struct thread *deferred_next;
    bool pending_destroy;
    bool stack_watch_enabled;
    bool stack_watch_active;
    uintptr_t stack_watch_base;
    size_t stack_watch_len;
    uintptr_t stack_watch_suspect;
    const char *stack_watch_context;
    struct thread *stack_watch_next;
    uint64_t stack_watch_freeze_deadline;
    uintptr_t stack_watch_snapshot_addr;
    size_t stack_watch_snapshot_len;
    bool stack_watch_snapshot_valid;
    uint8_t stack_watch_snapshot[STACK_WATCH_SNAPSHOT_BYTES];
};

struct stack_owner_entry
{
    struct stack_owner_entry *bucket_next;
    struct stack_owner_entry *thread_next;
    thread_t *thread;
    uintptr_t base;
    uintptr_t top;
    uint32_t bucket_index;
};

typedef struct process_heap_l2
{
    uintptr_t phys[PROCESS_HEAP_L2_ENTRIES];
    uint64_t present[PROCESS_HEAP_PRESENT_WORDS];
} process_heap_l2_t;

struct process
{
    uint64_t pid;
    process_state_t state;
    char name[PROCESS_NAME_MAX];
    uint64_t cr3;
    paging_space_t address_space;
    thread_t *main_thread;
    thread_t *current_thread;
    int exit_status;
    struct process *next;
    int stdout_fd;
    bool is_user;
    process_t *parent;
    process_t *first_child;
    process_t *sibling_prev;
    process_t *sibling_next;
    vfs_node_t *cwd;
    process_user_region_t *user_regions;
    uintptr_t user_entry_point;
    uintptr_t user_stack_top;
    size_t user_stack_size;
    uintptr_t user_heap_base;
    uintptr_t user_heap_brk;
    uintptr_t user_heap_limit;
    uintptr_t user_heap_committed;
    process_heap_l2_t **heap_page_dirs;
    size_t heap_dir_count;
    uint8_t *user_stack_host;
    uintptr_t user_initial_stack;
    size_t arg_count;
    char **arg_values;
    char *arg_storage;
    size_t arg_storage_size;
    size_t user_argc;
    uintptr_t user_argv_ptr;
    wait_queue_t wait_queue;
    uint32_t magic;
};

typedef struct run_queue
{
    spinlock_t lock;
    thread_t *heads[THREAD_PRIORITY_COUNT];
    thread_t *tails[THREAD_PRIORITY_COUNT];
    uint32_t counts[THREAD_PRIORITY_COUNT];
    uint32_t total;
    thread_t *lock_owner;
    const char *lock_owner_label;
    const void *lock_owner_caller;
    uint64_t lock_acquired_ticks;
    uint32_t cpu_index;
} run_queue_t;

static process_t *g_process_list = NULL;
static process_t *g_current_processes[SMP_MAX_CPUS] = { NULL };
static thread_t *g_current_threads[SMP_MAX_CPUS] = { NULL };
static thread_t *g_idle_threads[SMP_MAX_CPUS] = { NULL };
static thread_t *g_deferred_thread_frees[SMP_MAX_CPUS] = { NULL };
static spinlock_t g_deferred_free_locks[SMP_MAX_CPUS];
#if ENABLE_STACK_WRITE_DEBUG
static bool g_stack_write_debug_enabled = false;
static stack_owner_entry_t *g_stack_owner_buckets[STACK_OWNER_BUCKET_COUNT] = { NULL };
static spinlock_t g_stack_owner_locks[STACK_OWNER_BUCKET_COUNT];
#endif
static process_t *g_idle_process = NULL;
static cpu_context_t *g_bootstrap_context = NULL;
static run_queue_t g_run_queues[SMP_MAX_CPUS];
static thread_t *g_sleep_queue_head = NULL;
static uint64_t g_next_pid = 1;
static spinlock_t g_sleep_queue_lock;
static spinlock_t g_process_lock;

static volatile bool g_scheduler_boot_ready = false;

static fpu_state_t g_fpu_initial_state;
static bool g_fpu_template_ready = false;
static int g_console_stdout_fd = -1;
static uint32_t g_time_slice_ticks = PROCESS_TIME_SLICE_DEFAULT_TICKS;
static thread_t *g_stack_watch_frozen_head = NULL;
static thread_t *g_thread_registry_head = NULL;
static spinlock_t g_thread_registry_lock;
static uint8_t g_context_switch_dummy_flag = 0;
static const uint64_t SCHEDULER_STALL_LOG_MS = 2000ULL;
static const uint64_t RUN_QUEUE_LOCK_WARN_MS = 1000ULL;
static const uint64_t SCHED_SWITCH_WARN_MS = 500ULL;
static const uint64_t DEFERRED_FREE_WARN_MS = 250ULL;

typedef struct deferred_free_stats
{
    uint32_t cpu_index;
    size_t grabbed;
    size_t freed;
    size_t requeued;
    uint64_t duration_ticks;
} deferred_free_stats_t;

static void thread_freeze_for_stack_watch(thread_t *thread, const char *context);
static void thread_unfreeze_after_stack_watch(thread_t *thread);
static void stack_watch_check_timeouts(void);
static void stack_watch_remove_frozen(thread_t *thread);

static inline uint64_t scheduler_ticks_to_ms(uint64_t ticks)
{
    uint64_t freq = timer_frequency();
    if (freq == 0)
    {
        freq = 1000;
    }
    return (ticks * 1000ULL) / freq;
}

static void scheduler_log_if_stalled(const char *label, uint64_t start_ticks)
{
    if (!label || start_ticks == 0)
    {
        return;
    }
    uint64_t elapsed = timer_ticks() - start_ticks;
    uint64_t ms = scheduler_ticks_to_ms(elapsed);
    if (ms >= SCHEDULER_STALL_LOG_MS)
    {
        serial_printf("[sched] stall label=%s duration=%llu ms\r\n",
                      label,
                      (unsigned long long)ms);
    }
}

static inline uint32_t scheduler_time_slice_ticks(void)
{
    if (g_time_slice_ticks == 0)
    {
        return 1;
    }
    return g_time_slice_ticks;
}

static inline uint32_t current_cpu_index(void)
{
    uint32_t idx = smp_current_cpu_index();
    return (idx < SMP_MAX_CPUS) ? idx : 0;
}

static inline thread_t *current_thread_local(void)
{
    uint32_t idx = smp_current_cpu_index();
    if (idx >= SMP_MAX_CPUS)
    {
        idx = 0;
    }
    return g_current_threads[idx];
}

static inline process_t *current_process_local(void)
{
    uint32_t idx = smp_current_cpu_index();
    if (idx >= SMP_MAX_CPUS)
    {
        idx = 0;
    }
    return g_current_processes[idx];
}

static inline void set_current_thread_local(thread_t *thread)
{
    uint32_t idx = smp_current_cpu_index();
    if (idx >= SMP_MAX_CPUS)
    {
        idx = 0;
    }
    g_current_threads[idx] = thread;
}

static inline void set_current_process_local(process_t *process)
{
    uint32_t idx = smp_current_cpu_index();
    if (idx >= SMP_MAX_CPUS)
    {
        idx = 0;
    }
    g_current_processes[idx] = process;
}

static inline void paging_space_mark_active_cpu(paging_space_t *space, uint32_t cpu_index)
{
    if (!space || cpu_index >= SMP_MAX_CPUS)
    {
        return;
    }
    __atomic_fetch_or(&space->active_cpu_mask, (1u << cpu_index), __ATOMIC_RELEASE);
}

static inline void paging_space_clear_active_cpu(paging_space_t *space, uint32_t cpu_index)
{
    if (!space || cpu_index >= SMP_MAX_CPUS)
    {
        return;
    }
    __atomic_fetch_and(&space->active_cpu_mask, ~(1u << cpu_index), __ATOMIC_RELEASE);
}

static void thread_scan_stack_for_suspicious_values(thread_t *thread,
                                                    uintptr_t rsp,
                                                    bool full_stack,
                                                    const char *context);
static bool thread_context_in_bounds(thread_t *thread,
                                     const char *reason);

static ssize_t console_stdout_write(void *ctx, const void *buffer, size_t count)
{
    (void)ctx;
    if (!buffer)
    {
        return 0;
    }
    const char *data = (const char *)buffer;
    for (size_t i = 0; i < count; ++i)
    {
        char c = data[i];
        console_putc(c);
        serial_printf("%c", c);
    }
    return (ssize_t)count;
}

static const fd_ops_t console_stdout_ops = {
    .read = NULL,
    .write = console_stdout_write,
    .close = NULL,
};

static inline uint64_t cpu_save_flags(void)
{
    uint64_t flags;
    __asm__ volatile ("pushfq; pop %0" : "=r"(flags));
    return flags;
}

static inline void cpu_restore_flags(uint64_t flags)
{
    __asm__ volatile ("push %0; popfq" :: "r"(flags) : "cc");
}

static inline void cpu_cli(void)
{
    __asm__ volatile ("cli" ::: "memory");
}

static inline uint64_t read_cr3(void)
{
    uint64_t value;
    __asm__ volatile ("mov %%cr3, %0" : "=r"(value));
    return value;
}

static inline void write_cr3(uint64_t value)
{
    __asm__ volatile ("mov %0, %%cr3" :: "r"(value) : "memory");
}

extern uintptr_t kernel_heap_base;
extern uintptr_t kernel_heap_end;

static bool pointer_in_heap(uint64_t addr, size_t size)
{
    if (addr == 0)
    {
        return false;
    }
    uint64_t heap_start = (uint64_t)kernel_heap_base;
    uint64_t heap_end = (uint64_t)kernel_heap_end;
    return addr >= heap_start && (addr + size) <= heap_end;
}

static inline bool pointer_is_canonical(uintptr_t addr)
{
    /* Sign-extend bit 47 for canonical kernel/user pointers. */
    return ((addr >> 47) == 0) || ((addr >> 47) == 0x1FFFF);
}

static bool thread_pointer_valid(const thread_t *thread)
{
    if (!thread)
    {
        return false;
    }
    bool valid = pointer_in_heap((uint64_t)(uintptr_t)thread, sizeof(thread_t));
    if (!valid)
    {
        serial_printf("%s", "[proc] priority thread ptr invalid addr=0x");
        serial_printf("%016llX", (unsigned long long)((uint64_t)(uintptr_t)thread));
        serial_printf("%s", "\r\n");
        return false;
    }
    if (thread->magic != THREAD_MAGIC)
    {
        serial_printf("%s", "[proc] priority thread magic mismatch addr=0x");
        serial_printf("%016llX", (unsigned long long)((uint64_t)(uintptr_t)thread));
        serial_printf("%s", " magic=0x");
        serial_printf("%016llX", (unsigned long long)((uint64_t)thread->magic));
        serial_printf("%s", "\r\n");
        return false;
    }
    return true;
}

static bool thread_fpu_region_valid(const thread_t *thread)
{
    if (!thread)
    {
        return false;
    }
    uintptr_t addr = (uintptr_t)&thread->fpu_state;
    return pointer_in_heap(addr, sizeof(fpu_state_t));
}

static bool process_pointer_valid(const process_t *process)
{
    if (!process)
    {
        return false;
    }
    bool valid = pointer_in_heap((uint64_t)(uintptr_t)process, sizeof(process_t));
    if (!valid)
    {
        serial_printf("%s", "[proc] process ptr invalid addr=0x");
        serial_printf("%016llX", (unsigned long long)((uint64_t)(uintptr_t)process));
        serial_printf("%s", "\r\n");
        return false;
    }
    if (process->magic != PROCESS_MAGIC)
    {
        serial_printf("%s", "[proc] process magic mismatch addr=0x");
        serial_printf("%016llX", (unsigned long long)((uint64_t)(uintptr_t)process));
        serial_printf("%s", " magic=0x");
        serial_printf("%016llX", (unsigned long long)((uint64_t)process->magic));
        serial_printf("%s", "\r\n");
        return false;
    }
    return true;
}

static uint64_t sanitize_gs_base(thread_t *thread)
{
    if (!thread)
    {
        return 0;
    }

    uint64_t expected_base = (uint64_t)&thread->tls;
    bool valid = pointer_in_heap(thread->gs_base, sizeof(thread_tls_t));
    if (!valid || thread->gs_base != expected_base)
    {
        uint64_t old_base = thread->gs_base;
        thread->gs_base = expected_base;
        serial_printf("%s", "process: repaired GS base for thread ");
        serial_printf("%s", thread->name);
        serial_printf("%s", " old=0x");
        serial_printf("%016llX", (unsigned long long)(old_base));
        serial_printf("%s", " new=0x");
        serial_printf("%016llX", (unsigned long long)(thread->gs_base));
        serial_printf("%s", "\r\n");
    }
    return thread->gs_base;
}

static inline uintptr_t align_up_uintptr(uintptr_t value, uintptr_t alignment)
{
    return (value + alignment - 1) & ~(alignment - 1);
}

static inline uintptr_t align_down_uintptr(uintptr_t value, uintptr_t alignment)
{
    return value & ~(alignment - 1);
}

static inline size_t align_up_size(size_t value, size_t alignment)
{
    return (value + alignment - 1) & ~(alignment - 1);
}

#if ENABLE_STACK_WRITE_DEBUG
static void stack_owner_register_impl(thread_t *thread);
static void stack_owner_unregister_impl(thread_t *thread);
static thread_t *thread_find_stack_owner_impl(uintptr_t addr, size_t len);
#endif
static inline void stack_owner_register(thread_t *thread)
{
#if ENABLE_STACK_WRITE_DEBUG
    stack_owner_register_impl(thread);
#else
    (void)thread;
#endif
}

static inline void stack_owner_unregister(thread_t *thread)
{
#if ENABLE_STACK_WRITE_DEBUG
    stack_owner_unregister_impl(thread);
#else
    (void)thread;
#endif
}

static inline thread_t *thread_find_stack_owner(uintptr_t addr, size_t len)
{
#if ENABLE_STACK_WRITE_DEBUG
    return thread_find_stack_owner_impl(addr, len);
#else
    (void)addr;
    (void)len;
    return NULL;
#endif
}
static bool thread_can_run(const thread_t *thread);
static bool scheduler_thread_in_any_queue(thread_t *thread);
static bool process_heap_zero_range(process_t *process, uintptr_t start, size_t bytes);
static void process_heap_release_from(process_t *process, uintptr_t virt_start);
static void process_free_heap_pages(process_t *process);
static bool process_heap_commit_range(process_t *process, uintptr_t start, uintptr_t end);

static void process_log(const char *msg, uint64_t value)
{
    serial_printf("%s", "[proc] ");
    serial_printf("%s", msg);
    serial_printf("%s", "0x");
    serial_printf("%016llX", (unsigned long long)(value));
    serial_printf("%s", "\r\n");
}

static void process_handle_stack_guard_fault(void) __attribute__((noreturn));
static void process_handle_fatal_fault(void) __attribute__((noreturn));

static bool thread_stack_pointer_valid(const thread_t *thread, uint64_t rsp)
{
    if (!thread || !thread->stack_base)
    {
        return true;
    }

    uintptr_t lower = (uintptr_t)thread->stack_base;
    uintptr_t upper = thread->kernel_stack_top;
    if (rsp < lower)
    {
        return false;
    }
    if (rsp > upper)
    {
        return false;
    }
    return true;
}

static bool thread_stack_guard_intact(const thread_t *thread)
{
    if (!thread || !thread->stack_guard_base)
    {
        return true;
    }
    if (thread->stack_guard_failed)
    {
        return false;
    }
    const uint8_t *guard = thread->stack_guard_base;
    for (size_t i = 0; i < PROCESS_STACK_GUARD_SIZE; ++i)
    {
        if (guard[i] != STACK_GUARD_PATTERN)
        {
            return false;
        }
    }
    return true;
}

#if ENABLE_STACK_WRITE_DEBUG
static bool thread_stack_range_contains(const thread_t *thread,
                                        uintptr_t addr,
                                        size_t len)
{
    if (!thread || !thread->stack_base)
    {
        return false;
    }
    uintptr_t lower = (uintptr_t)thread->stack_base;
    uintptr_t upper = thread->kernel_stack_top;
    if (upper <= lower)
    {
        return false;
    }
    if (addr < lower || addr >= upper)
    {
        return false;
    }
    if (len > 0 && len > (upper - addr))
    {
        return false;
    }
    return true;
}

static uintptr_t thread_stack_watch_default_suspect(thread_t *thread)
{
    if (!thread)
    {
        return 0;
    }

    uintptr_t suspect = thread->context ? (uintptr_t)thread->context : 0;
    if (suspect && thread_stack_range_contains(thread, suspect, 1))
    {
        return suspect;
    }

    if (thread->stack_base &&
        thread_stack_range_contains(thread, (uintptr_t)thread->stack_base, 1))
    {
        return (uintptr_t)thread->stack_base;
    }

    return 0;
}

static void thread_stack_watch_clear_snapshot(thread_t *thread)
{
#if ENABLE_STACK_WRITE_DEBUG
    if (!thread)
    {
        return;
    }
    thread->stack_watch_snapshot_valid = false;
    thread->stack_watch_snapshot_addr = 0;
    thread->stack_watch_snapshot_len = 0;
    thread->stack_watch_timeout_count = 0;
#else
    (void)thread;
#endif
}

static void thread_stack_watch_capture_snapshot(thread_t *thread)
{
#if ENABLE_STACK_WRITE_DEBUG
    if (!thread)
    {
        return;
    }
    thread_stack_watch_clear_snapshot(thread);
    uintptr_t suspect = thread->stack_watch_suspect;
    if (!suspect || !thread_stack_range_contains(thread, suspect, 1))
    {
        return;
    }
    size_t remaining = thread->kernel_stack_top > suspect
                       ? (size_t)(thread->kernel_stack_top - suspect)
                       : 0;
    if (remaining == 0)
    {
        return;
    }
    size_t copy = remaining;
    if (copy > STACK_WATCH_SNAPSHOT_BYTES)
    {
        copy = STACK_WATCH_SNAPSHOT_BYTES;
    }
    memcpy(thread->stack_watch_snapshot, (const void *)suspect, copy);
    thread->stack_watch_snapshot_addr = suspect;
    thread->stack_watch_snapshot_len = copy;
    thread->stack_watch_snapshot_valid = true;
#else
    (void)thread;
#endif
}

static bool thread_stack_watch_snapshot_changed(thread_t *thread,
                                                uintptr_t *addr_out,
                                                uint8_t *old_out,
                                                uint8_t *new_out)
{
#if ENABLE_STACK_WRITE_DEBUG
    if (!thread || !thread->stack_watch_snapshot_valid)
    {
        return false;
    }
    const uint8_t *current = (const uint8_t *)thread->stack_watch_snapshot_addr;
    for (size_t i = 0; i < thread->stack_watch_snapshot_len; ++i)
    {
        uint8_t now = current[i];
        uint8_t prev = thread->stack_watch_snapshot[i];
        if (now != prev)
        {
            if (addr_out)
            {
                *addr_out = thread->stack_watch_snapshot_addr + i;
            }
            if (old_out)
            {
                *old_out = prev;
            }
            if (new_out)
            {
                *new_out = now;
            }
            thread->stack_watch_snapshot_valid = false;
            return true;
        }
    }
#else
    (void)thread;
    (void)addr_out;
    (void)old_out;
    (void)new_out;
#endif
    return false;
}

static bool thread_stack_candidate_matches(thread_t *thread,
                                           uintptr_t addr,
                                           size_t len,
                                           thread_t **owner_out)
{
    if (thread && thread_stack_range_contains(thread, addr, len))
    {
        if (owner_out)
        {
            *owner_out = thread;
        }
        return true;
    }
    return false;
}

static uint32_t stack_owner_bucket_index(uintptr_t addr)
{
    return (uint32_t)((addr >> STACK_OWNER_BUCKET_SHIFT) & STACK_OWNER_BUCKET_MASK);
}

static void stack_owner_register_impl(thread_t *thread)
{
    if (!thread || !thread->stack_base || thread->kernel_stack_top == 0)
    {
        return;
    }

    uintptr_t base = (uintptr_t)thread->stack_base;
    uintptr_t top = thread->kernel_stack_top;
    uintptr_t start = align_down_uintptr(base, STACK_OWNER_BUCKET_SIZE);
    uintptr_t end = align_up_uintptr(top, STACK_OWNER_BUCKET_SIZE);

    for (uintptr_t bucket = start; bucket < end; bucket += STACK_OWNER_BUCKET_SIZE)
    {
        uint32_t idx = stack_owner_bucket_index(bucket);
        stack_owner_entry_t *entry = (stack_owner_entry_t *)malloc(sizeof(stack_owner_entry_t));
        if (!entry)
        {
            continue;
        }
        entry->bucket_index = idx;
        entry->thread = thread;
        entry->base = base;
        entry->top = top;
        entry->thread_next = thread->stack_owner_entries;
        thread->stack_owner_entries = entry;

        spinlock_lock(&g_stack_owner_locks[idx]);
        entry->bucket_next = g_stack_owner_buckets[idx];
        g_stack_owner_buckets[idx] = entry;
        spinlock_unlock(&g_stack_owner_locks[idx]);
    }
}

static void stack_owner_unregister_impl(thread_t *thread)
{
    stack_owner_entry_t *entry = thread ? thread->stack_owner_entries : NULL;
    while (entry)
    {
        uint32_t idx = entry->bucket_index;
        spinlock_lock(&g_stack_owner_locks[idx]);
        stack_owner_entry_t **cursor = &g_stack_owner_buckets[idx];
        while (*cursor)
        {
            if (*cursor == entry)
            {
                *cursor = entry->bucket_next;
                break;
            }
            cursor = &(*cursor)->bucket_next;
        }
        spinlock_unlock(&g_stack_owner_locks[idx]);
        stack_owner_entry_t *next = entry->thread_next;
        free(entry);
        entry = next;
    }
    if (thread)
    {
        thread->stack_owner_entries = NULL;
    }
}

static thread_t *thread_find_stack_owner_impl(uintptr_t addr, size_t len)
{
    uint32_t bucket = stack_owner_bucket_index(addr);
    thread_t *owner = NULL;
    spinlock_lock(&g_stack_owner_locks[bucket]);
    stack_owner_entry_t *entry = g_stack_owner_buckets[bucket];
    while (entry)
    {
        if (thread_stack_candidate_matches(entry->thread, addr, len, &owner))
        {
            break;
        }
        entry = entry->bucket_next;
    }
    spinlock_unlock(&g_stack_owner_locks[bucket]);
    return owner;
}

#endif /* ENABLE_STACK_WRITE_DEBUG */

thread_t *process_find_stack_owner(const void *ptr, size_t len)
{
#if ENABLE_STACK_WRITE_DEBUG
    return thread_find_stack_owner((uintptr_t)ptr, len);
#else
    (void)ptr;
    (void)len;
    return NULL;
#endif
}

bool process_pointer_on_stack(const void *ptr, size_t len)
{
    return process_find_stack_owner(ptr, len) != NULL;
}

static void thread_stack_watch_deactivate(thread_t *thread);

static void thread_free_resources(thread_t *thread);
static void thread_enqueue_deferred_free(thread_t *thread);
static bool thread_process_deferred_frees(uint32_t cpu_index, deferred_free_stats_t *stats);

static void thread_registry_add(thread_t *thread)
{
    if (!thread)
    {
        return;
    }
    spinlock_lock(&g_thread_registry_lock);
    thread->registry_next = g_thread_registry_head;
    g_thread_registry_head = thread;
    spinlock_unlock(&g_thread_registry_lock);
}

static void thread_registry_remove(thread_t *thread)
{
    if (!thread)
    {
        return;
    }
    spinlock_lock(&g_thread_registry_lock);
    thread_t **cursor = &g_thread_registry_head;
    while (*cursor)
    {
        if (*cursor == thread)
        {
            *cursor = thread->registry_next;
            break;
        }
        cursor = &(*cursor)->registry_next;
    }
    thread->registry_next = NULL;
    spinlock_unlock(&g_thread_registry_lock);
}

#if ENABLE_STACK_WRITE_DEBUG
static bool thread_stack_watch_can_arm_now(const thread_t *thread)
{
    if (!thread || thread->stack_watch_active || !thread->stack_base)
    {
        return false;
    }
    if (thread == current_thread_local())
    {
        return false;
    }
    if (thread->state == THREAD_STATE_RUNNING)
    {
        return false;
    }
    return true;
}

static bool thread_stack_watch_arm_now(thread_t *thread)
{
    if (!thread_stack_watch_can_arm_now(thread))
    {
        return false;
    }
    uintptr_t base = align_down_uintptr((uintptr_t)thread->stack_base, PAGE_SIZE_BYTES_LOCAL);
    uintptr_t top = align_up_uintptr(thread->kernel_stack_top, PAGE_SIZE_BYTES_LOCAL);
    if (top <= base)
    {
        return false;
    }
    size_t length = (size_t)(top - base);
    if (!paging_set_kernel_range_writable(base, length, false))
    {
        serial_printf("%s", "[sched] warning: unable to arm stack watch\r\n");
        return false;
    }
    thread->stack_watch_active = true;
    thread->stack_watch_base = base;
    thread->stack_watch_len = length;

#if ENABLE_STACK_WRITE_DEBUG_LOGS
    serial_printf("%s", "[sched] stack watch armed thread=");
    if (thread->name[0])
    {
        serial_printf("%s", thread->name);
    }
    else
    {
        serial_printf("%s", "<unnamed>");
    }
    serial_printf("%s", " pid=0x");
    serial_printf("%016llX", (unsigned long long)(thread->process ? thread->process->pid : 0));
    serial_printf("%s", " context=");
    serial_printf("%s", thread->stack_watch_context ? thread->stack_watch_context : "<none>");
    serial_printf("%s", " suspect=0x");
    serial_printf("%016llX", (unsigned long long)(thread->stack_watch_suspect));
    serial_printf("%s", " base=0x");
    serial_printf("%016llX", (unsigned long long)(base));
    serial_printf("%s", " top=0x");
    serial_printf("%016llX", (unsigned long long)(top));
    serial_printf("%s", "\r\n");
#endif
    thread->stack_watch_timeout_logged = false;
    thread_stack_watch_capture_snapshot(thread);
    return true;
}

static bool thread_stack_watch_activate(thread_t *thread,
                                        const char *context,
                                        uintptr_t suspect_addr)
{
    if (!thread)
    {
        return false;
    }
    if (suspect_addr == 0)
    {
        suspect_addr = thread_stack_watch_default_suspect(thread);
    }

    bool was_enabled = thread->stack_watch_enabled;
    thread->stack_watch_enabled = true;
    thread->stack_watch_context = context;
    thread->stack_watch_suspect = suspect_addr;
    if (thread->stack_watch_active)
    {
        thread_stack_watch_deactivate(thread);
    }
    if (thread_stack_watch_can_arm_now(thread))
    {
        if (thread_stack_watch_arm_now(thread))
        {
            return true;
        }
        thread->stack_watch_enabled = false;
        return false;
    }

    if (!was_enabled)
    {
#if ENABLE_STACK_WRITE_DEBUG_LOGS
        serial_printf("%s", "[sched] stack watch pending thread=");
        if (thread->name[0])
        {
            serial_printf("%s", thread->name);
        }
        else
        {
            serial_printf("%s", "<unnamed>");
        }
        serial_printf("%s", " pid=0x");
        serial_printf("%016llX", (unsigned long long)(thread->process ? thread->process->pid : 0));
        serial_printf("%s", " context=");
        serial_printf("%s", thread->stack_watch_context ? thread->stack_watch_context : "<none>");
        serial_printf("%s", "\r\n");
#endif
    }
    return true;
}

static void thread_stack_watch_maybe_arm(thread_t *thread)
{
    if (!thread || !thread->stack_watch_enabled || thread->stack_watch_active)
    {
        return;
    }
    uintptr_t suspect = thread_stack_watch_default_suspect(thread);
    if (suspect)
    {
        thread->stack_watch_suspect = suspect;
    }
    (void)thread_stack_watch_arm_now(thread);
}
#endif

static void thread_stack_watch_deactivate(thread_t *thread)
{
#if ENABLE_STACK_WRITE_DEBUG
    if (!thread || !thread->stack_watch_active)
    {
        return;
    }
    bool keep_metadata = thread->stack_watch_enabled;
    if (!paging_set_kernel_range_writable(thread->stack_watch_base,
                                          thread->stack_watch_len,
                                          true))
    {
        serial_printf("%s", "[sched] warning: unable to disarm stack watch\r\n");
    }
#if ENABLE_STACK_WRITE_DEBUG_LOGS
    serial_printf("%s", "[sched] stack watch cleared thread=");
    if (thread->name[0])
    {
        serial_printf("%s", thread->name);
    }
    else
    {
        serial_printf("%s", "<unnamed>");
    }
    serial_printf("%s", " pid=0x");
    serial_printf("%016llX", (unsigned long long)(thread->process ? thread->process->pid : 0));
    serial_printf("%s", "\r\n");
#endif
    thread->stack_watch_active = false;
    thread->stack_watch_base = 0;
    thread->stack_watch_len = 0;
    thread_stack_watch_clear_snapshot(thread);
    if (!keep_metadata)
    {
        thread->stack_watch_suspect = 0;
        thread->stack_watch_context = NULL;
    }
#else
    (void)thread;
#endif
}

static void thread_free_resources(thread_t *thread)
{
    if (!thread)
    {
        return;
    }
    const char *name = thread->name[0] ? thread->name : "<unnamed>";
    uint64_t pid = thread->process ? thread->process->pid : 0;
    uintptr_t ctx_ptr = (uintptr_t)thread->context;
    uintptr_t stack_base = (uintptr_t)thread->stack_base;
    uintptr_t stack_top = thread->kernel_stack_top;
    serial_printf("[sched] thread_free_resources name=%s pid=0x%016llX context=0x%016llX stack=[0x%016llX,0x%016llX)\r\n",
                  name,
                  (unsigned long long)pid,
                  (unsigned long long)ctx_ptr,
                  (unsigned long long)stack_base,
                  (unsigned long long)stack_top);
    uint8_t *stack_allocation_raw = thread->stack_allocation_raw;
    uint8_t *stack_guard_base = thread->stack_guard_base;
    uint8_t *stack_base_ptr = thread->stack_base;
    stack_owner_unregister(thread);
    thread->context = NULL;
    thread->context_valid = false;
    thread->kernel_stack_top = 0;
    thread->stack_base = NULL;
    thread->stack_guard_base = NULL;
    thread->stack_allocation_raw = NULL;
    thread->stack_size = 0;
    thread->stack_allocation_size = 0;
    thread->magic = 0;
    thread->process = NULL;
    thread_registry_remove(thread);
    if (stack_allocation_raw)
    {
        free(stack_allocation_raw);
    }
    else if (stack_guard_base)
    {
        free(stack_guard_base);
    }
    else if (stack_base_ptr)
    {
        free(stack_base_ptr);
    }
    free(thread);
}

static void thread_enqueue_deferred_free(thread_t *thread)
{
    if (!thread || thread->pending_destroy)
    {
        return;
    }
    thread->pending_destroy = true;
    uint32_t owner = thread->last_cpu_index;
    if (owner >= SMP_MAX_CPUS)
    {
        owner = 0;
    }
    spinlock_lock(&g_deferred_free_locks[owner]);
    thread->deferred_next = g_deferred_thread_frees[owner];
    g_deferred_thread_frees[owner] = thread;
    spinlock_unlock(&g_deferred_free_locks[owner]);
}

static bool thread_process_deferred_frees(uint32_t cpu_index, deferred_free_stats_t *stats)
{
    if (cpu_index >= SMP_MAX_CPUS)
    {
        cpu_index = 0;
    }

    deferred_free_stats_t local_stats = {
        .cpu_index = cpu_index,
        .grabbed = 0,
        .freed = 0,
        .requeued = 0,
        .duration_ticks = 0
    };

    uint64_t start_ticks = timer_ticks();

    /* Disable interrupts so current-thread observations stay consistent. */
    uint64_t flags = cpu_save_flags();
    cpu_cli();

    /* Build a temporary list of items we can actually free this pass. */
    spinlock_lock(&g_deferred_free_locks[cpu_index]);
    thread_t *list = g_deferred_thread_frees[cpu_index];
    g_deferred_thread_frees[cpu_index] = NULL;
    spinlock_unlock(&g_deferred_free_locks[cpu_index]);

    thread_t *pending = NULL;
    thread_t *tail = NULL;
    thread_t *cursor = list;
    while (cursor)
    {
        thread_t *next = cursor->deferred_next;
        cursor->deferred_next = NULL;
        local_stats.grabbed++;

        bool in_use = false;
        /* Avoid freeing anything still running or referenced as current. */
        for (uint32_t i = 0; i < SMP_MAX_CPUS; ++i)
        {
            if (g_current_threads[i] == cursor)
            {
                in_use = true;
                break;
            }
        }
        /* Belt-and-suspenders: confirm the thread is not still linked in any run queue
         * even if its in_run_queue flag was cleared incorrectly. */
        if (!in_use)
        {
            in_use = scheduler_thread_in_any_queue(cursor);
        }
        if (cursor->state != THREAD_STATE_ZOMBIE || cursor->in_run_queue || cursor->sleeping ||
            cursor->waiting_queue || cursor->in_transition)
        {
            in_use = true;
        }

        if (in_use)
        {
            local_stats.requeued++;
            /* Keep for later retry. */
            if (!pending)
            {
                pending = cursor;
                tail = cursor;
            }
            else
            {
                tail->deferred_next = cursor;
                tail = cursor;
            }
        }
        else
        {
            thread_free_resources(cursor);
            local_stats.freed++;
        }
        cursor = next;
    }

    /* Requeue anything we could not safely free yet. */
    if (pending)
    {
        spinlock_lock(&g_deferred_free_locks[cpu_index]);
        tail->deferred_next = g_deferred_thread_frees[cpu_index];
        g_deferred_thread_frees[cpu_index] = pending;
        spinlock_unlock(&g_deferred_free_locks[cpu_index]);
    }

    cpu_restore_flags(flags);

    local_stats.duration_ticks = timer_ticks() - start_ticks;

    bool did_work = (local_stats.grabbed > 0);
    if (stats)
    {
        *stats = local_stats;
    }

    if (did_work)
    {
        uint64_t ms = scheduler_ticks_to_ms(local_stats.duration_ticks);
        serial_printf("[sched] deferred_free cpu=%u grabbed=0x%016llX freed=0x%016llX requeued=0x%016llX duration=%llu ms%s\r\n",
                      local_stats.cpu_index,
                      (unsigned long long)local_stats.grabbed,
                      (unsigned long long)local_stats.freed,
                      (unsigned long long)local_stats.requeued,
                      (unsigned long long)ms,
                      (ms >= DEFERRED_FREE_WARN_MS) ? " (slow)" : "");
    }

    return did_work;
}

static bool thread_context_in_bounds(thread_t *thread,
                                     const char *reason)
{
    if (!thread)
    {
        return true;
    }
    uintptr_t ctx = (uintptr_t)thread->context;
    uintptr_t lower = (uintptr_t)thread->stack_base;
    uintptr_t upper = thread->kernel_stack_top;
    if (lower == 0 || upper <= lower)
    {
        return true;
    }
    if (ctx >= lower && ctx < upper)
    {
        return true;
    }

    serial_printf("%s", "[sched] context pointer out of bounds ");
    serial_printf("%s", reason ? reason : "<none>");
    serial_printf("%s", " thread=");
    serial_printf("%s", thread->name[0] ? thread->name : "<unnamed>");
    serial_printf("%s", " pid=0x");
    serial_printf("%016llX", (unsigned long long)(thread->process ? thread->process->pid : 0));
    serial_printf("%s", " ctx=0x");
    serial_printf("%016llX", (unsigned long long)ctx);
    serial_printf("%s", " stack=[0x");
    serial_printf("%016llX", (unsigned long long)lower);
    serial_printf("%s", ",0x");
    serial_printf("%016llX", (unsigned long long)upper);
    serial_printf("%s", ")\r\n");
    fatal("context pointer out of bounds");
}

static void thread_check_context_bounds(const thread_t *thread,
                                        const char *label)
{
#if ENABLE_CONTEXT_GUARD
    if (!thread || !thread->context || !thread->stack_base)
    {
        return;
    }
    uintptr_t ctx = (uintptr_t)thread->context;
    uintptr_t lower = (uintptr_t)thread->stack_base;
    uintptr_t upper = thread->kernel_stack_top;
    if (upper <= lower)
    {
        return;
    }
    if (ctx >= lower && ctx < upper)
    {
        return;
    }

    serial_printf("%s", "[sched] context ptr out of range label=");
    serial_printf("%s", label ? label : "<none>");
    serial_printf("%s", " thread=");
    if (thread->name[0])
    {
        serial_printf("%s", thread->name);
    }
    else
    {
        serial_printf("%s", "<unnamed>");
    }
    serial_printf("%s", " pid=0x");
    serial_printf("%016llX", (unsigned long long)(thread->process ? thread->process->pid : 0));
    serial_printf("%s", " ptr=0x");
    serial_printf("%016llX", (unsigned long long)(ctx));
    serial_printf("%s", " stack_base=0x");
    serial_printf("%016llX", (unsigned long long)(lower));
    serial_printf("%s", " stack_top=0x");
    serial_printf("%016llX", (unsigned long long)(upper));
    serial_printf("%s", "\r\n");

#if ENABLE_STACK_WRITE_DEBUG
    thread_t *owner = thread_find_stack_owner(ctx, 0);
    if (owner)
    {
        serial_printf("%s", "  ctx points into stack owned by thread=");
        if (owner->name[0])
        {
            serial_printf("%s", owner->name);
        }
        else
        {
            serial_printf("%s", "<unnamed>");
        }
        serial_printf("%s", " pid=0x");
        serial_printf("%016llX", (unsigned long long)(owner->process ? owner->process->pid : 0));
        serial_printf("%s", "\r\n");
    }
#endif
    fatal("thread context pointer corrupt");
#else
    (void)thread;
    (void)label;
#endif
}

static void thread_mark_stack_guard_failure(thread_t *thread, const char *reason)
{
    if (!thread)
    {
        return;
    }
    if (!thread->stack_guard_failed)
    {
        thread->stack_guard_failed = true;
        thread->stack_guard_reason = reason;
    }
}

static void thread_trigger_stack_guard(thread_t *thread,
                                       interrupt_frame_t *frame,
                                       const char *reason)
{
    if (!thread || !frame)
    {
        return;
    }

    thread_mark_stack_guard_failure(thread, reason);

    uintptr_t lower = (uintptr_t)thread->stack_base;
    uintptr_t upper = thread->kernel_stack_top;

    uintptr_t safe_rsp = upper;
    if (safe_rsp > lower + 64)
    {
        safe_rsp -= 32;
    }
    safe_rsp &= ~(uintptr_t)0xFULL;
    if (safe_rsp <= lower)
    {
        safe_rsp = lower + 32;
    }
    if (safe_rsp > upper)
    {
        safe_rsp = upper;
    }
    safe_rsp &= ~(uintptr_t)0xFULL;

    frame->rsp = safe_rsp;
    frame->rip = (uint64_t)process_handle_stack_guard_fault;
    frame->cs = GDT_SELECTOR_KERNEL_CODE;
    frame->ss = GDT_SELECTOR_KERNEL_DATA;
    frame->rflags &= ~RFLAGS_IF_BIT;
}

static void thread_log_stack_issue(const thread_t *thread,
                                   const char *context,
                                   const char *reason)
{
    uint64_t rsp = 0;
    __asm__ volatile ("mov %%rsp, %0" : "=r"(rsp));
    serial_printf("%s", "[proc] stack issue thread=");
    if (thread && thread->name[0])
    {
        serial_printf("%s", thread->name);
    }
    else
    {
        serial_printf("%s", "<unnamed>");
    }
    serial_printf("%s", " ctx=");
    serial_printf("%s", context ? context : "<none>");
    serial_printf("%s", " reason=");
    serial_printf("%s", reason ? reason : "<unknown>");
    serial_printf("%s", " stack_base=0x");
    serial_printf("%016llX", (unsigned long long)((uintptr_t)(thread ? thread->stack_base : 0)));
    serial_printf("%s", " stack_top=0x");
    serial_printf("%016llX", (unsigned long long)(thread ? thread->kernel_stack_top : 0));
    serial_printf("%s", " rsp=0x");
    serial_printf("%016llX", (unsigned long long)rsp);
    serial_printf("%s", "\r\n");
}

static void thread_assert_stack_current(thread_t *thread, const char *context)
{
    if (!thread)
    {
        return;
    }
    uint64_t rsp = 0;
    __asm__ volatile ("mov %%rsp, %0" : "=r"(rsp));
    if (!thread_stack_pointer_valid(thread, rsp))
    {
        thread_log_stack_issue(thread, context, "rsp_out_of_bounds");
        fatal("kernel stack pointer left bounds");
    }
    if (!thread_stack_guard_intact(thread))
    {
        thread_log_stack_issue(thread, context, "guard_corrupted");
        fatal("kernel stack guard corrupted");
    }
    thread_scan_stack_for_suspicious_values(thread, rsp, false, context);
}

static void thread_assert_stack_guard_only(thread_t *thread, const char *context)
{
    if (!thread)
    {
        return;
    }
    if (!thread_stack_guard_intact(thread))
    {
        thread_log_stack_issue(thread, context, "guard_corrupted");
        fatal("kernel stack guard corrupted (target)");
    }
}

static void scheduler_debug_dump_stack(const uint64_t *base, size_t count)
{
    if (!base || count == 0)
    {
        return;
    }
    for (size_t i = 0; i < count; ++i)
    {
        serial_printf("%s", "    [0x");
        serial_printf("%016llX", (unsigned long long)((uintptr_t)(base + i)));
        serial_printf("%s", "] = 0x");
        serial_printf("%016llX", (unsigned long long)(base[i]));
        serial_printf("%s", "\r\n");
    }
}

static void scheduler_debug_dump_thread_stack(thread_t *thread, const char *label)
{
#if ENABLE_SCHEDULER_STACK_DUMP
    if (!thread || !thread->stack_base)
    {
        return;
    }

    uintptr_t lower = (uintptr_t)thread->stack_base;
    uintptr_t upper = thread->kernel_stack_top;
    if (upper <= lower)
    {
        return;
    }

    size_t total_qwords = (upper - lower) / sizeof(uint64_t);
    size_t dump_qwords = (size_t)SCHEDULER_STACK_DUMP_QWORDS;
    if (dump_qwords > total_qwords)
    {
        dump_qwords = total_qwords;
    }
    if (dump_qwords == 0)
    {
        return;
    }

    uintptr_t ctx_ptr = (uintptr_t)thread->context;
    uintptr_t start_addr = upper - dump_qwords * sizeof(uint64_t);
    if (ctx_ptr >= lower && ctx_ptr < upper)
    {
        size_t half = dump_qwords / 2;
        uintptr_t ctx_start = (ctx_ptr >= half * sizeof(uint64_t))
                                ? ctx_ptr - half * sizeof(uint64_t)
                                : lower;
        if (ctx_start < lower)
        {
            ctx_start = lower;
        }
        uintptr_t ctx_end = ctx_start + dump_qwords * sizeof(uint64_t);
        if (ctx_end > upper)
        {
            ctx_end = upper;
            if (ctx_end >= dump_qwords * sizeof(uint64_t))
            {
                ctx_start = ctx_end - dump_qwords * sizeof(uint64_t);
            }
            else
            {
                ctx_start = lower;
            }
        }
        start_addr = ctx_start;
    }

    const uint64_t *start = (const uint64_t *)start_addr;
    serial_printf("%s", "[sched] stack snapshot label=");
    serial_printf("%s", label ? label : "<none>");
    serial_printf("%s", " thread=");
    if (thread->name[0])
    {
        serial_printf("%s", thread->name);
    }
    else
    {
        serial_printf("%s", "<unnamed>");
    }
    serial_printf("%s", " pid=0x");
    serial_printf("%016llX", (unsigned long long)(thread->process ? thread->process->pid : 0));
    serial_printf("%s", " entries=");
    serial_printf("%016llX", (unsigned long long)(dump_qwords));
    serial_printf("%s", " ctx=0x");
    serial_printf("%016llX", (unsigned long long)(ctx_ptr));
    serial_printf("%s", "\r\n");
    scheduler_debug_dump_stack(start, dump_qwords);
#else
    (void)thread;
    (void)label;
#endif
}

static bool stack_value_is_suspicious(uint64_t value,
                                      const char **reason_out)
{
    if (value >= SMP_BOOT_DATA_PHYS && value < SMP_BOOT_DATA_PHYS + 0x1000)
    {
        if (reason_out)
        {
            *reason_out = "smp_boot";
        }
        return true;
    }
    return false;
}

static void thread_log_stack_scan_hit(thread_t *thread,
                                      const char *context,
                                      const char *reason,
                                      uintptr_t addr,
                                      uint64_t value)
{
#if ENABLE_STACK_SCAN_LOGS
    serial_printf("%s", "[proc] stack scan hit reason=");
    serial_printf("%s", reason ? reason : "<unknown>");
    serial_printf("%s", " ctx=");
    serial_printf("%s", context ? context : "<none>");
    serial_printf("%s", " thread=");
    if (thread && thread->name[0])
    {
        serial_printf("%s", thread->name);
    }
    else
    {
        serial_printf("%s", "<unnamed>");
    }
    serial_printf("%s", " pid=0x");
    serial_printf("%016llX", (unsigned long long)(thread && thread->process ? thread->process->pid : 0));
    serial_printf("%s", " addr=0x");
    serial_printf("%016llX", (unsigned long long)(addr));
    serial_printf("%s", " value=0x");
    serial_printf("%016llX", (unsigned long long)(value));
    serial_printf("%s", "\r\n");

    if (thread && thread->stack_base)
    {
        const uint64_t *lower = (const uint64_t *)(uintptr_t)thread->stack_base;
        const uint64_t *upper = (const uint64_t *)thread->kernel_stack_top;
        const uint64_t *cursor = (const uint64_t *)addr;
        size_t context_qwords = (size_t)STACK_SCAN_DUMP_CONTEXT_QWORDS;
        const uint64_t *start = cursor;
        if (cursor > lower + context_qwords)
        {
            start = cursor - context_qwords;
        }
        else
        {
            start = lower;
        }
        const uint64_t *end = cursor + context_qwords;
        if (end > upper)
        {
            end = upper;
        }
        if (end > start)
        {
            scheduler_debug_dump_stack(start, (size_t)(end - start));
        }
    }
#else
    (void)thread;
    (void)context;
    (void)reason;
    (void)addr;
    (void)value;
#endif
}

static void scheduler_debug_check_resume(thread_t *thread, const char *label)
{
    if (!thread || !thread->context)
    {
        return;
    }

    uintptr_t ctx_ptr = (uintptr_t)thread->context;
    /* If the saved context pointer looks dodgy, bail out instead of crashing in debug checks. */
    if (!pointer_is_canonical(ctx_ptr))
    {
        return;
    }

    uintptr_t lower = (uintptr_t)thread->stack_base;
    uintptr_t upper = thread->kernel_stack_top;
    if (lower == 0 || upper <= lower || ctx_ptr < lower || ctx_ptr >= upper)
    {
        return;
    }

    const size_t saved_context_words = CONTEXT_SWITCH_SAVED_WORDS; /* pushfq + rbp + rbx + r12-15 */
    const uint64_t *context_words = (const uint64_t *)thread->context;
    /* Ensure we won't read past the current stack allocation. */
    uintptr_t max_ctx = ctx_ptr + (saved_context_words + 1) * sizeof(uint64_t);
    if (max_ctx > upper)
    {
        return;
    }
    uint64_t resume_rip = context_words[saved_context_words];
    bool resume_zero = (resume_rip == 0);
    bool resume_boot = (resume_rip >= SMP_BOOT_DATA_PHYS &&
                        resume_rip < SMP_BOOT_DATA_PHYS + 0x1000);
    if (!resume_zero && !resume_boot)
    {
        return;
    }

    process_t *proc = thread->process;
    serial_printf("%s", "[sched] resume rip anomaly label=");
    serial_printf("%s", label ? label : "<none>");
    serial_printf("%s", " reason=");
    serial_printf("%s", resume_zero ? "zero" : "smp_boot");
    serial_printf("%s", " cpu=");
    serial_printf("%016llX", (unsigned long long)(current_cpu_index()));
    serial_printf("%s", " thread=");
    if (thread->name[0])
    {
        serial_printf("%s", thread->name);
    }
    else
    {
        serial_printf("%s", "<unnamed>");
    }
    serial_printf("%s", " pid=0x");
    serial_printf("%016llX", (unsigned long long)(proc ? proc->pid : 0));
    serial_printf("%s", " resume_rip=0x");
    serial_printf("%016llX", (unsigned long long)(resume_rip));
    serial_printf("%s", " ctx=0x");
    serial_printf("%016llX", (unsigned long long)((uintptr_t)thread->context));
    serial_printf("%s", " stack_base=0x");
    serial_printf("%016llX", (unsigned long long)((uintptr_t)thread->stack_base));
    serial_printf("%s", " stack_top=0x");
    serial_printf("%016llX", (unsigned long long)(thread->kernel_stack_top));
    serial_printf("%s", "\r\n");

    const uint64_t *stack_dump = context_words + saved_context_words;
    scheduler_debug_dump_stack(stack_dump, 16);

    fatal("scheduler detected context rip inside SMP bootstrap page");
}

static void thread_scan_stack_for_suspicious_values(thread_t *thread,
                                                    uintptr_t rsp,
                                                    bool full_stack,
                                                    const char *context)
{
#if ENABLE_SMP_BOOT_STACK_SCAN
    if (!thread || !thread->stack_base || thread->is_idle)
    {
        return;
    }

    uintptr_t lower = (uintptr_t)thread->stack_base;
    uintptr_t upper = thread->kernel_stack_top;
    if (lower == 0 || upper <= lower)
    {
        return;
    }

    uintptr_t start_addr = rsp;
    if (start_addr < lower || start_addr >= upper)
    {
        start_addr = lower;
    }
    start_addr &= ~(uintptr_t)0x7ULL;

    const uint64_t *cursor = (const uint64_t *)(full_stack ? lower : start_addr);
    const uint64_t *limit = (const uint64_t *)upper;
    size_t max_qwords = full_stack ? (size_t)((upper - lower) / sizeof(uint64_t))
                                   : (size_t)SMP_BOOT_STACK_SCAN_MAX_QWORDS;

    size_t scanned = 0;
    while (cursor < limit && scanned < max_qwords)
    {
        const char *reason = NULL;
        uint64_t value = *cursor;
        if (stack_value_is_suspicious(value, &reason))
        {
            thread_log_stack_scan_hit(thread, context, reason, (uintptr_t)cursor, value);
#if ENABLE_STACK_WRITE_DEBUG
            thread_stack_watch_activate(thread, context, (uintptr_t)cursor);
#endif
            return;
        }
        cursor++;
        scanned++;
    }
#else
    (void)thread;
    (void)rsp;
    (void)full_stack;
    (void)context;
#endif
}

static size_t thread_context_guard_collect(const thread_t *thread,
                                           const uint64_t **words_out)
{
#if ENABLE_CONTEXT_GUARD
    if (words_out)
    {
        *words_out = NULL;
    }
    if (!thread || !thread->context)
    {
        return 0;
    }
    uintptr_t ctx_ptr = (uintptr_t)thread->context;
    uintptr_t lower = (uintptr_t)thread->stack_base;
    uintptr_t upper = thread->kernel_stack_top;
    if (ctx_ptr < lower || ctx_ptr >= upper)
    {
        return 0;
    }
    size_t max_words = (size_t)((upper - ctx_ptr) / sizeof(uint64_t));
    if (max_words == 0)
    {
        return 0;
    }
    if (words_out)
    {
        *words_out = (const uint64_t *)ctx_ptr;
    }
    return max_words;
#else
    (void)thread;
    (void)words_out;
    return 0;
#endif
}

static void context_guard_dump_window(thread_t *thread,
                                      uintptr_t focus_addr,
                                      size_t words_before,
                                      size_t words_after)
{
#if ENABLE_CONTEXT_GUARD
    if (!thread || !thread->stack_base || focus_addr == 0)
    {
        return;
    }
    uintptr_t lower = (uintptr_t)thread->stack_base;
    uintptr_t upper = thread->kernel_stack_top;
    if (focus_addr < lower || focus_addr >= upper)
    {
        return;
    }

    size_t total_words = words_before + words_after + 1;
    size_t bytes_before = words_before * sizeof(uint64_t);
    uintptr_t start = focus_addr;
    if (bytes_before > 0)
    {
        if (start >= bytes_before)
        {
            start -= bytes_before;
        }
        else
        {
            start = lower;
        }
    }
    if (start < lower)
    {
        start = lower;
    }
    uintptr_t end = start + total_words * sizeof(uint64_t);
    if (end > upper)
    {
        end = upper;
    }
    serial_printf("%s", "[sched] context_guard window thread=");
    if (thread->name[0])
    {
        serial_printf("%s", thread->name);
    }
    else
    {
        serial_printf("%s", "<unnamed>");
    }
    serial_printf("%s", " pid=0x");
    serial_printf("%016llX", (unsigned long long)(thread->process ? thread->process->pid : 0));
    serial_printf("%s", " focus=0x");
    serial_printf("%016llX", (unsigned long long)(focus_addr));
    serial_printf("%s", " range=[0x");
    serial_printf("%016llX", (unsigned long long)(start));
    serial_printf("%s", ",0x");
    serial_printf("%016llX", (unsigned long long)(end));
    serial_printf("%s", ")\r\n");
    for (uintptr_t addr = start; addr + sizeof(uint64_t) <= end; addr += sizeof(uint64_t))
    {
        serial_printf("%s", "  [");
        serial_printf("%016llX", (unsigned long long)(addr));
        serial_printf("%s", "] = 0x");
        serial_printf("%016llX", (unsigned long long)(*(const uint64_t *)addr));
        if (addr == focus_addr)
        {
            serial_printf("%s", " <-- target");
        }
        serial_printf("%s", "\r\n");
    }
#else
    (void)thread;
    (void)focus_addr;
    (void)words_before;
    (void)words_after;
#endif
}

static uint64_t thread_compute_context_guard(const thread_t *thread)
{
#if ENABLE_CONTEXT_GUARD
    const uint64_t *words = NULL;
    size_t available = thread_context_guard_collect(thread, &words);
    if (available == 0 || !words)
    {
        return 0;
    }
    size_t count = (available < CONTEXT_GUARD_WORDS) ? available : (size_t)CONTEXT_GUARD_WORDS;
    uint64_t hash = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < count; ++i)
    {
        hash ^= words[i];
        hash *= 0x100000001B3ULL;
    }
    return hash;
#else
    (void)thread;
    return 0;
#endif
}

static void thread_context_guard_release_pages(thread_t *thread)
{
#if ENABLE_CONTEXT_GUARD
    if (!thread || !thread->context_guard_protected || !thread->context_guard_enabled)
    {
        return;
    }
    if (!paging_set_kernel_range_writable(thread->context_guard_protect_base,
                                          thread->context_guard_protect_len,
                                          true))
    {
        serial_printf("%s", "[sched] warning: failed to unprotect stack guard region\r\n");
    }
    thread->context_guard_protected = false;
    thread->context_guard_protect_base = 0;
    thread->context_guard_protect_len = 0;
#else
    (void)thread;
#endif
}

static void thread_context_guard_protect_pages(thread_t *thread)
{
#if ENABLE_CONTEXT_GUARD
    if (!thread || thread->context_guard_protected || !thread->context_guard_enabled)
    {
        return;
    }
#if !ENABLE_STACK_GUARD_PROTECT
    (void)thread;
    return;
#endif
    if (!thread->stack_base || thread->kernel_stack_top <= (uintptr_t)thread->stack_base)
    {
        return;
    }
    uintptr_t start = align_down_uintptr((uintptr_t)thread->stack_base, PAGE_SIZE_BYTES_LOCAL);
    uintptr_t end = align_up_uintptr(thread->kernel_stack_top, PAGE_SIZE_BYTES_LOCAL);
    size_t length = (size_t)(end - start);
    if (length == 0)
    {
        return;
    }
    if (!paging_set_kernel_range_writable(start, length, false))
    {
        serial_printf("%s", "[sched] warning: failed to protect stack guard region\r\n");
        return;
    }
    thread->context_guard_protect_base = start;
    thread->context_guard_protect_len = length;
    thread->context_guard_protected = true;
#else
    (void)thread;
#endif
}

void thread_disable_context_guard(thread_t *thread)
{
#if ENABLE_CONTEXT_GUARD
    if (!thread)
    {
        return;
    }
    thread_context_guard_release_pages(thread);
    thread->context_guard_enabled = false;
    thread->context_guard_hash = 0;
    thread->context_guard_ptr = 0;
    thread->context_guard_count = 0;
    memset(thread->context_guard_words, 0, sizeof(thread->context_guard_words));
#else
    (void)thread;
#endif
}

static void thread_context_guard_update(thread_t *thread, const char *label)
{
#if ENABLE_CONTEXT_GUARD
    if (thread && !thread->context_guard_enabled)
    {
        return;
    }
    thread_check_context_bounds(thread, label);
    if (!thread || !thread->context)
    {
        return;
    }
    const uint64_t *words = NULL;
    size_t available = thread_context_guard_collect(thread, &words);
    if (available == 0 || !words)
    {
        thread->context_guard_hash = 0;
    thread->context_guard_ptr = 0;
    thread->context_guard_count = 0;
    memset(thread->context_guard_words, 0, sizeof(thread->context_guard_words));
    return;
}
    size_t copy_words = (available < CONTEXT_GUARD_WORDS) ? available : (size_t)CONTEXT_GUARD_WORDS;
    memcpy(thread->context_guard_words, words, copy_words * sizeof(uint64_t));
    if (copy_words < CONTEXT_GUARD_WORDS)
    {
        memset(thread->context_guard_words + copy_words, 0,
               (CONTEXT_GUARD_WORDS - copy_words) * sizeof(uint64_t));
    }
    thread->context_guard_count = copy_words;
    thread->context_guard_hash = thread_compute_context_guard(thread);
    thread->context_guard_ptr = (uintptr_t)thread->context;
    thread->context_guard_generation++;
#else
    (void)thread;
    (void)label;
#endif
}

static void thread_context_guard_verify(thread_t *thread, const char *label)
{
#if ENABLE_CONTEXT_GUARD
    if (thread && !thread->context_guard_enabled)
    {
        return;
    }
    thread_check_context_bounds(thread, label);
    if (!thread || !thread->context_guard_hash || !thread->context)
    {
        return;
    }
    if (thread->context_guard_ptr != (uintptr_t)thread->context)
    {
        thread_context_guard_update(thread, "context_guard_resync");
        return;
    }
    const uint64_t *current_words = NULL;
    size_t available = thread_context_guard_collect(thread, &current_words);
    if (available == 0 || !current_words)
    {
        return;
    }
    size_t compare_words = thread->context_guard_count;
    if (compare_words > CONTEXT_GUARD_WORDS)
    {
        compare_words = CONTEXT_GUARD_WORDS;
    }
    if (compare_words > available)
    {
        compare_words = available;
    }
    uint64_t current_hash = thread_compute_context_guard(thread);
    bool mismatch = (current_hash != thread->context_guard_hash);
    if (!mismatch && compare_words > 0)
    {
        mismatch = (memcmp(thread->context_guard_words,
                           current_words,
                           compare_words * sizeof(uint64_t)) != 0);
    }
    if (!mismatch)
    {
        return;
    }
#if !CONTEXT_GUARD_STRICT
    serial_printf("%s", "[sched] context guard mismatch (resync) label=");
    serial_printf("%s", label ? label : "<none>");
    serial_printf("%s", " thread=");
    serial_printf("%s", thread->name[0] ? thread->name : "<unnamed>");
    serial_printf("%s", " pid=0x");
    serial_printf("%016llX", (unsigned long long)(thread->process ? thread->process->pid : 0));
    serial_printf("%s", " saved_ptr=0x");
    serial_printf("%016llX", (unsigned long long)(thread->context_guard_ptr));
    serial_printf("%s", " current_ptr=0x");
    serial_printf("%016llX", (unsigned long long)((uintptr_t)thread->context));
    serial_printf("%s", " saved_hash=0x");
    serial_printf("%016llX", (unsigned long long)(thread->context_guard_hash));
    serial_printf("%s", " current_hash=0x");
    serial_printf("%016llX", (unsigned long long)(current_hash));
    serial_printf("%s", "\r\n");
    thread_context_guard_update(thread, "context_guard_resync_soft");
    return;
#endif
    size_t diff_index = (size_t)-1;
    for (size_t i = 0; i < compare_words; ++i)
    {
        if (thread->context_guard_words[i] != current_words[i])
        {
            diff_index = i;
            break;
        }
    }
    if (diff_index == 1)
    {
        thread_context_guard_update(thread, "context_guard_r14");
        return;
    }
    serial_printf("%s", "[sched] context guard mismatch label=");
    serial_printf("%s", label ? label : "<none>");
    serial_printf("%s", " thread=");
    if (thread->name[0])
    {
        serial_printf("%s", thread->name);
    }
    else
    {
        serial_printf("%s", "<unnamed>");
    }
    serial_printf("%s", " pid=0x");
    serial_printf("%016llX", (unsigned long long)(thread->process ? thread->process->pid : 0));
    serial_printf("%s", " saved_ptr=0x");
    serial_printf("%016llX", (unsigned long long)(thread->context_guard_ptr));
    serial_printf("%s", " current_ptr=0x");
    serial_printf("%016llX", (unsigned long long)((uintptr_t)thread->context));
    serial_printf("%s", " saved_hash=0x");
    serial_printf("%016llX", (unsigned long long)(thread->context_guard_hash));
    serial_printf("%s", " current_hash=0x");
    serial_printf("%016llX", (unsigned long long)(current_hash));
    serial_printf("%s", "\r\n");
    uintptr_t diff_addr = 0;
    if (diff_index != (size_t)-1)
    {
        diff_addr = thread->context_guard_ptr + diff_index * sizeof(uint64_t);
        serial_printf("%s", "  diff_index=0x");
        serial_printf("%016llX", (unsigned long long)(diff_index));
        serial_printf("%s", " addr=0x");
        serial_printf("%016llX", (unsigned long long)(diff_addr));
        serial_printf("%s", " saved=0x");
        serial_printf("%016llX", (unsigned long long)(thread->context_guard_words[diff_index]));
        serial_printf("%s", " current=0x");
        serial_printf("%016llX", (unsigned long long)(current_words[diff_index]));
        serial_printf("%s", "\r\n");
    }
    const char *reg_name = "<unknown>";
    if (diff_index != (size_t)-1 &&
        diff_index < STATIC_ARRAY_SIZE(g_context_guard_reg_names))
    {
        reg_name = g_context_guard_reg_names[diff_index];
    }
    serial_printf("%s", "  register=");
    serial_printf("%s", reg_name);
    serial_printf("%s", "\r\n");
    if (diff_addr)
    {
        context_guard_dump_window(thread, diff_addr, 4, 4);
    }
    scheduler_debug_dump_thread_stack(thread, label);
    thread_scan_stack_for_suspicious_values(thread,
                                            (uintptr_t)thread->context,
                                            true,
                                            "context_guard");
#if ENABLE_STACK_WRITE_DEBUG
    uintptr_t suspect = (diff_index != (size_t)-1)
                        ? thread->context_guard_ptr + diff_index * sizeof(uint64_t)
                        : (uintptr_t)thread->context_guard_ptr;
    if (thread_stack_watch_activate(thread, label, suspect))
    {
        thread_freeze_for_stack_watch(thread, label);
#if ENABLE_STACK_WRITE_DEBUG_LOGS
        serial_printf("%s", "[sched] context_guard mismatch -> stack watch armed\r\n");
#endif
        thread_context_guard_release_pages(thread);
        thread_context_guard_update(thread, "context_guard_watch");
        return;
    }
#endif
    fatal("context guard mismatch");
#else
    (void)thread;
    (void)label;
#endif
}

static void process_trigger_fatal_fault(thread_t *thread,
                                        interrupt_frame_t *frame,
                                        const char *reason,
                                        uint64_t error_code,
                                        bool has_address,
                                        uint64_t address)
{
    if (!thread || !frame)
    {
        return;
    }
    thread->fault_reason = reason;
    thread->fault_error_code = error_code;
    thread->fault_has_address = has_address;
    thread->fault_address = address;
    frame->rip = (uint64_t)process_handle_fatal_fault;
    frame->cs = GDT_SELECTOR_KERNEL_CODE;
    frame->ss = GDT_SELECTOR_KERNEL_DATA;
    frame->rflags &= ~RFLAGS_IF_BIT;
}

__attribute__((naked)) static void context_switch(cpu_context_t **,
                                                 cpu_context_t *,
                                                 uint8_t *)
{
    __asm__ volatile (
        "pushfq\n\t"
        "push %%rbp\n\t"
        "push %%rbx\n\t"
        "push %%r12\n\t"
        "push %%r13\n\t"
        "push %%r14\n\t"
        "push %%r15\n\t"
        "mov %%rsp, (%%rdi)\n\t"
        "mov %%rsi, %%rsp\n\t"
        "test %%rdx, %%rdx\n\t"
        "jz 1f\n\t"
        "movb $0, (%%rdx)\n\t"
        "1:\n\t"
        "pop %%r15\n\t"
        "pop %%r14\n\t"
        "pop %%r13\n\t"
        "pop %%r12\n\t"
        "pop %%rbx\n\t"
        "pop %%rbp\n\t"
        "popfq\n\t"
        "ret\n\t"
        :
        :
    );
}

static void fpu_prepare_initial_state(void)
{
    if (g_fpu_template_ready)
    {
        return;
    }
    __asm__ volatile ("fninit");
    __asm__ volatile ("fxsave64 %0" : "=m"(g_fpu_initial_state));
    g_fpu_template_ready = true;
}

static inline void fpu_save_state(fpu_state_t *state)
{
    __asm__ volatile ("fxsave64 %0" : "=m"(*state));
}

static inline void fpu_restore_state(const fpu_state_t *state)
{
    __asm__ volatile ("fxrstor64 %0" :: "m"(*state));
}

static void fatal(const char *msg)
{
    serial_printf("%s", "process fatal: ");
    serial_printf("%s", msg);
    serial_printf("%s", "\r\n");
    for (;;)
    {
        __asm__ volatile ("hlt");
    }
}

static process_t *allocate_process(const char *name, bool is_user)
{
    bool needs_clone = is_user;
    bool trace_clone = needs_clone && string_name_equals(name, "shell");
    if (trace_clone)
    {
        heap_debug_verify("shell_pre_alloc_verify");
        heap_debug_dump("shell_pre_alloc_dump");
        serial_printf("%s", "[process] paging trace enabled\r\n");
        paging_set_clone_trace(true);
    }
    process_t *proc = (process_t *)malloc(sizeof(process_t));
    if (!proc)
    {
        if (trace_clone)
        {
            serial_printf("%s", "[process] shell malloc failed\r\n");
            paging_set_clone_trace(false);
        }
        return NULL;
    }
    memset(proc, 0, sizeof(*proc));
    serial_printf("%s", "[process] allocate name=");
    if (name && name[0])
    {
        serial_printf("%s", name);
    }
    else
    {
        serial_printf("%s", "<unnamed>");
    }
    serial_printf("%s", "\r\n");
    proc->pid = g_next_pid++;
    proc->state = PROCESS_STATE_READY;
    bool space_ready = false;
    if (needs_clone)
    {
        process_create_log(name, "clone_start");
        space_ready = paging_clone_kernel_space(&proc->address_space);
    }
    else
    {
        process_create_log(name, "share_kernel");
        space_ready = paging_share_kernel_space(&proc->address_space);
    }
    if (trace_clone)
    {
        heap_debug_verify("shell_post_clone_verify");
        serial_printf("%s", "[process] paging trace disabled\r\n");
        paging_set_clone_trace(false);
    }
    if (!space_ready)
    {
        free(proc);
        process_create_log(name, "space_fail");
        return NULL;
    }
    process_create_log(name, needs_clone ? "clone_done" : "share_done");
    proc->cr3 = proc->address_space.cr3;
    if (name)
    {
        size_t len = strlen(name);
        if (len >= PROCESS_NAME_MAX)
        {
            len = PROCESS_NAME_MAX - 1;
        }
        memcpy(proc->name, name, len);
        proc->name[len] = '\0';
    }
    else
    {
        proc->name[0] = '\0';
    }
    proc->exit_status = 0;
    proc->main_thread = NULL;
    proc->current_thread = NULL;
    proc->next = NULL;
    proc->stdout_fd = g_console_stdout_fd;
    proc->is_user = is_user;
    proc->parent = NULL;
    proc->first_child = NULL;
    proc->sibling_prev = NULL;
    proc->sibling_next = NULL;
    proc->cwd = NULL;
    proc->user_regions = NULL;
    proc->user_entry_point = 0;
    proc->user_stack_top = 0;
    proc->user_stack_size = 0;
    proc->user_heap_base = 0;
    proc->user_heap_brk = 0;
    proc->user_heap_limit = 0;
    proc->user_heap_committed = 0;
    proc->heap_page_dirs = NULL;
    proc->heap_dir_count = 0;
    proc->magic = PROCESS_MAGIC;
    wait_queue_init(&proc->wait_queue);
    return proc;
}

static void process_free_user_regions(process_t *process)
{
    if (!process)
    {
        return;
    }

    process_user_region_t *region = process->user_regions;
    while (region)
    {
        process_user_region_t *next = region->next;
        if (region->aligned_allocation && region->mapped_size > 0)
        {
            user_memory_free(region->aligned_allocation, region->mapped_size);
        }
        free(region);
        region = next;
    }
    process->user_regions = NULL;
    process_free_heap_pages(process);
    process->user_heap_base = 0;
    process->user_heap_brk = 0;
    process->user_heap_limit = 0;
    process->user_heap_committed = 0;
}

static void process_unlink_user_region(process_t *process, process_user_region_t *region)
{
    if (!process || !region)
    {
        return;
    }
    process_user_region_t **cursor = &process->user_regions;
    while (*cursor)
    {
        if (*cursor == region)
        {
            *cursor = region->next;
            break;
        }
        cursor = &(*cursor)->next;
    }
    if (region->aligned_allocation && region->mapped_size > 0)
    {
        user_memory_free(region->aligned_allocation, region->mapped_size);
    }
    free(region);
}

static bool process_map_user_region(process_t *process, const process_user_region_t *region)
{
    if (!process || !region || region->mapped_size == 0)
    {
        return false;
    }
    return paging_map_user_range(&process->address_space,
                                 region->user_base,
                                 (uintptr_t)region->aligned_allocation,
                                 region->mapped_size,
                                 region->writable,
                                 region->executable);
}

static size_t process_heap_dir_capacity(const process_t *process)
{
    return process ? process->heap_dir_count : 0;
}

static process_heap_l2_t *process_heap_table(process_t *process, size_t dir_index, bool create)
{
    if (!process || !process->heap_page_dirs || dir_index >= process->heap_dir_count)
    {
        return NULL;
    }
    process_heap_l2_t *table = process->heap_page_dirs[dir_index];
    if (!table && create)
    {
        table = (process_heap_l2_t *)malloc(sizeof(process_heap_l2_t));
        if (!table)
        {
            return NULL;
        }
        memset(table, 0, sizeof(*table));
        process->heap_page_dirs[dir_index] = table;
    }
    return table;
}

static inline bool process_heap_entry_present(const process_heap_l2_t *table, size_t index)
{
    if (!table || index >= PROCESS_HEAP_L2_ENTRIES)
    {
        return false;
    }
    return (table->present[index / 64] >> (index % 64)) & 1ULL;
}

static inline void process_heap_entry_set(process_heap_l2_t *table, size_t index, uintptr_t phys)
{
    if (!table || index >= PROCESS_HEAP_L2_ENTRIES)
    {
        return;
    }
    table->phys[index] = phys;
    table->present[index / 64] |= (1ULL << (index % 64));
}

static inline void process_heap_entry_clear(process_heap_l2_t *table, size_t index)
{
    if (!table || index >= PROCESS_HEAP_L2_ENTRIES)
    {
        return;
    }
    table->phys[index] = 0;
    table->present[index / 64] &= ~(1ULL << (index % 64));
}

static bool process_heap_table_empty(const process_heap_l2_t *table)
{
    if (!table)
    {
        return true;
    }
    for (size_t i = 0; i < PROCESS_HEAP_PRESENT_WORDS; ++i)
    {
        if (table->present[i])
        {
            return false;
        }
    }
    return true;
}

static bool process_heap_lookup(const process_t *process, uintptr_t virt_page, uintptr_t *phys_out)
{
    if (!process || virt_page < process->user_heap_base || virt_page >= process->user_heap_limit)
    {
        return false;
    }
    uintptr_t offset = (virt_page - process->user_heap_base) / PAGE_SIZE_BYTES_LOCAL;
    size_t dir_index = (size_t)(offset >> PROCESS_HEAP_L2_SHIFT);
    size_t entry_index = (size_t)(offset & PROCESS_HEAP_L2_MASK);
    if (!process->heap_page_dirs || dir_index >= process->heap_dir_count)
    {
        return false;
    }
    process_heap_l2_t *table = process->heap_page_dirs[dir_index];
    if (!process_heap_entry_present(table, entry_index))
    {
        return false;
    }
    if (phys_out)
    {
        *phys_out = table->phys[entry_index];
    }
    return true;
}

static void process_heap_free_map(process_t *process)
{
    if (!process)
    {
        return;
    }
    if (process->heap_page_dirs)
    {
        for (size_t i = 0; i < process->heap_dir_count; ++i)
        {
            if (process->heap_page_dirs[i])
            {
                free(process->heap_page_dirs[i]);
                process->heap_page_dirs[i] = NULL;
            }
        }
        free(process->heap_page_dirs);
    }
    process->heap_page_dirs = NULL;
    process->heap_dir_count = 0;
}

static bool process_heap_zero_range(process_t *process, uintptr_t start, size_t bytes)
{
    if (!process || bytes == 0)
    {
        return true;
    }
    uintptr_t addr = start;
    size_t remaining = bytes;
    while (remaining > 0)
    {
        uintptr_t page_base = align_down_uintptr(addr, PAGE_SIZE_BYTES_LOCAL);
        uintptr_t phys = 0;
        if (!process_heap_lookup(process, page_base, &phys))
        {
            return false;
        }
        size_t page_offset = (size_t)(addr - page_base);
        size_t chunk = PAGE_SIZE_BYTES_LOCAL - page_offset;
        if (chunk > remaining)
        {
            chunk = remaining;
        }
        memset((uint8_t *)(uintptr_t)phys + page_offset, 0, chunk);
        addr += chunk;
        remaining -= chunk;
    }
    return true;
}

static void process_heap_release_from(process_t *process, uintptr_t virt_start)
{
    if (!process || !process->heap_page_dirs)
    {
        return;
    }

    if (virt_start < process->user_heap_base)
    {
        virt_start = process->user_heap_base;
    }

    uintptr_t aligned_start = align_down_uintptr(virt_start, PAGE_SIZE_BYTES_LOCAL);
    size_t start_page = (size_t)((aligned_start - process->user_heap_base) / PAGE_SIZE_BYTES_LOCAL);
    size_t max_pages = process_heap_dir_capacity(process) * PROCESS_HEAP_L2_ENTRIES;

    for (size_t page = start_page; page < max_pages; ++page)
    {
        uintptr_t virt = process->user_heap_base + page * PAGE_SIZE_BYTES_LOCAL;
        if (virt >= process->user_heap_limit)
        {
            break;
        }

        size_t dir_index = page >> PROCESS_HEAP_L2_SHIFT;
        size_t entry_index = page & PROCESS_HEAP_L2_MASK;
        process_heap_l2_t *table = process_heap_table(process, dir_index, false);
        if (!table || !process_heap_entry_present(table, entry_index))
        {
            continue;
        }

        uintptr_t phys = table->phys[entry_index];
        process_heap_entry_clear(table, entry_index);
        paging_unmap_user_page(&process->address_space, virt);
        user_memory_free_page(phys);

        if (process_heap_table_empty(table))
        {
            free(table);
            process->heap_page_dirs[dir_index] = NULL;
        }
    }
}

static void process_free_heap_pages(process_t *process)
{
    if (!process)
    {
        return;
    }
    process_heap_release_from(process, process->user_heap_base);
    process->user_heap_committed = process->user_heap_base;
    process_heap_free_map(process);
}

static bool process_heap_commit_range(process_t *process, uintptr_t start, uintptr_t end)
{
    if (!process || start >= end)
    {
        return true;
    }
    uintptr_t page_addr = start;
    while (page_addr < end)
    {
        uintptr_t phys = 0;
        uintptr_t offset = (page_addr - process->user_heap_base) / PAGE_SIZE_BYTES_LOCAL;
        size_t dir_index = (size_t)(offset >> PROCESS_HEAP_L2_SHIFT);
        size_t entry_index = (size_t)(offset & PROCESS_HEAP_L2_MASK);

        if (dir_index >= process->heap_dir_count)
        {
            process_heap_release_from(process, start);
            process->user_heap_committed = start;
            return false;
        }

        process_heap_l2_t *table = process_heap_table(process, dir_index, true);
        if (!table)
        {
            process_heap_release_from(process, start);
            process->user_heap_committed = start;
            return false;
        }

        if (process_heap_entry_present(table, entry_index))
        {
            page_addr += PAGE_SIZE_BYTES_LOCAL;
            continue;
        }

        if (!user_memory_alloc_page(&phys))
        {
            process_heap_release_from(process, start);
            process->user_heap_committed = start;
            return false;
        }
        memset((void *)(uintptr_t)phys, 0, PAGE_SIZE_BYTES_LOCAL);
        if (!paging_map_user_page(&process->address_space,
                                  page_addr,
                                  phys,
                                  true,
                                  false))
        {
            user_memory_free_page(phys);
            process_heap_release_from(process, start);
             process->user_heap_committed = start;
            return false;
        }
        process_heap_entry_set(table, entry_index, phys);
        page_addr += PAGE_SIZE_BYTES_LOCAL;
    }
    process->user_heap_committed = end;
    return true;
}

static bool process_user_region_allocate(process_t *process,
                                         uintptr_t user_base,
                                         size_t bytes,
                                         bool writable,
                                         bool executable,
                                         process_user_region_t **region_out)
{
    if (!process || bytes == 0)
    {
        return false;
    }

    size_t aligned_bytes = align_up_size(bytes, PAGE_SIZE_BYTES_LOCAL);
    void *host = user_memory_alloc(aligned_bytes);
    if (!host)
    {
        return false;
    }
    memset(host, 0, aligned_bytes);

    process_user_region_t *region = (process_user_region_t *)malloc(sizeof(process_user_region_t));
    if (!region)
    {
        user_memory_free(host, aligned_bytes);
        return false;
    }

    region->raw_allocation = host;
    region->aligned_allocation = host;
    region->mapped_size = aligned_bytes;
    region->user_base = user_base;
    region->writable = writable;
    region->executable = executable;
    region->next = process->user_regions;
    process->user_regions = region;
    process_log("region host=", (uintptr_t)host);
    process_log("region size=", aligned_bytes);

    if (region_out)
    {
        *region_out = region;
    }
    return true;
}

static bool process_heap_commit(process_t *process, uintptr_t commit_start, uintptr_t commit_end)
{
    if (!process || commit_end <= commit_start)
    {
        return true;
    }
    uintptr_t addr = commit_start;
    while (addr < commit_end)
    {
        size_t chunk = commit_end - addr;
        void *host = NULL;
        if (!process_map_user_segment(process, addr, chunk, true, false, &host))
        {
            return false;
        }
        memset(host, 0, chunk);
        addr += chunk;
    }
    return true;
}

bool process_map_user_segment(process_t *process,
                              uintptr_t user_base,
                              size_t bytes,
                              bool writable,
                              bool executable,
                              void **host_ptr_out)
{
    if (!process || bytes == 0)
    {
        return false;
    }

    uintptr_t aligned_base = align_down_uintptr(user_base, PAGE_SIZE_BYTES_LOCAL);
    size_t offset = (size_t)(user_base - aligned_base);
    size_t total = align_up_size(bytes + offset, PAGE_SIZE_BYTES_LOCAL);
    process_log("map base=", aligned_base);
    process_log("map bytes=", total);

    process_user_region_t *region = NULL;
    if (!process_user_region_allocate(process,
                                      aligned_base,
                                      total,
                                      writable,
                                      executable,
                                      &region))
    {
        return false;
    }

    if (!process_map_user_region(process, region))
    {
        process_unlink_user_region(process, region);
        process_log("map fail base=", aligned_base);
        return false;
    }

    if (host_ptr_out)
    {
        uint8_t *base_ptr = (uint8_t *)region->aligned_allocation;
        *host_ptr_out = base_ptr + offset;
        process_log("map host ptr=", (uintptr_t)*host_ptr_out);
    }
    return true;
}

static bool process_setup_user_stack(process_t *process)
{
    void *host = NULL;
    if (!process_map_user_segment(process,
                                  USER_STACK_TOP - USER_STACK_SIZE,
                                  USER_STACK_SIZE,
                                  true,
                                  false,
                                  &host))
    {
        return false;
    }
    process->user_stack_top = USER_STACK_TOP;
    process->user_stack_size = USER_STACK_SIZE;
    process->user_stack_host = (uint8_t *)host;
    return true;
}

static bool process_setup_user_heap(process_t *process)
{
    if (!process)
    {
        return false;
    }
    process->user_heap_base = USER_HEAP_BASE;
    process->user_heap_brk = USER_HEAP_BASE;
    process->user_heap_limit = USER_HEAP_BASE + USER_HEAP_SIZE;
    process->user_heap_committed = USER_HEAP_BASE;
    size_t dir_count = (USER_HEAP_SIZE + PROCESS_HEAP_L2_SPAN - 1) / PROCESS_HEAP_L2_SPAN;
    if (dir_count == 0)
    {
        dir_count = 1;
    }
    process->heap_dir_count = dir_count;
    process->heap_page_dirs = (process_heap_l2_t **)malloc(sizeof(process_heap_l2_t *) * dir_count);
    if (!process->heap_page_dirs)
    {
        process->heap_dir_count = 0;
        return false;
    }
    memset(process->heap_page_dirs, 0, sizeof(process_heap_l2_t *) * dir_count);
    return true;
}

static void process_clear_args(process_t *process)
{
    if (!process)
    {
        return;
    }
    if (process->arg_values)
    {
        free(process->arg_values);
        process->arg_values = NULL;
    }
    if (process->arg_storage)
    {
        free(process->arg_storage);
        process->arg_storage = NULL;
    }
    process->arg_storage_size = 0;
    process->arg_count = 0;
}

static bool process_store_args(process_t *process,
                               const char *const *argv,
                               size_t argc)
{
    if (!process)
    {
        return false;
    }

    process_clear_args(process);

    if (!argv || argc == 0)
    {
        return true;
    }

    char **values = (char **)malloc(sizeof(char *) * argc);
    if (!values)
    {
        return false;
    }

    size_t total_bytes = 0;
    for (size_t i = 0; i < argc; ++i)
    {
        const char *arg = argv[i] ? argv[i] : "";
        total_bytes += strlen(arg) + 1;
    }
    if (total_bytes == 0)
    {
        total_bytes = 1;
    }

    char *storage = (char *)malloc(total_bytes);
    if (!storage)
    {
        free(values);
        return false;
    }

    size_t offset = 0;
    for (size_t i = 0; i < argc; ++i)
    {
        const char *arg = argv[i] ? argv[i] : "";
        size_t len = strlen(arg);
        memcpy(storage + offset, arg, len);
        storage[offset + len] = '\0';
        values[i] = storage + offset;
        offset += len + 1;
    }

    process->arg_values = values;
    process->arg_storage = storage;
    process->arg_storage_size = offset;
    process->arg_count = argc;
    return true;
}

static void process_dump_stack_entry(uintptr_t addr, uintptr_t value, bool mark_rsp)
{
    serial_printf("%s", "    [");
    serial_printf("%016llX", (unsigned long long)(addr));
    serial_printf("%s", "] = 0x");
    serial_printf("%016llX", (unsigned long long)(value));
    if (mark_rsp)
    {
        serial_printf("%s", " <-- rsp");
    }
    serial_printf("%s", "\r\n");
}

static inline bool process_write_stack_uintptr(uint8_t *host_base,
                                               uintptr_t stack_bottom,
                                               uintptr_t stack_top,
                                               uintptr_t addr,
                                               uintptr_t value)
{
    if (!host_base || addr < stack_bottom || addr + sizeof(uintptr_t) > stack_top)
    {
        return false;
    }
    size_t offset = (size_t)(addr - stack_bottom);
    memcpy(host_base + offset, &value, sizeof(uintptr_t));
    return true;
}

static bool process_setup_preempt_stub(process_t *process)
{
    if (!process)
    {
        return false;
    }

    void *stub_ptr = NULL;
    if (!process_map_user_segment(process,
                                  USER_PREEMPT_STUB_BASE,
                                  PAGE_SIZE_BYTES_LOCAL,
                                  false,
                                  true,
                                  &stub_ptr))
    {
        return false;
    }

    memset(stub_ptr, 0x90, PAGE_SIZE_BYTES_LOCAL);
    memcpy(stub_ptr, g_user_preempt_stub, sizeof(g_user_preempt_stub));
    return true;
}

void process_dump_user_stack(process_t *process,
                             uintptr_t rsp,
                             size_t max_entries_above,
                             size_t max_entries_below)
{
    if (!process || !process->is_user || (max_entries_above == 0 && max_entries_below == 0))
    {
        return;
    }
    if (!process->user_stack_host || process->user_stack_size == 0 || rsp == 0)
    {
        serial_printf("%s", "  user stack: unavailable\r\n");
        return;
    }

    uintptr_t stack_top = process->user_stack_top;
    uintptr_t stack_bottom = stack_top - process->user_stack_size;

    serial_printf("%s", "  user stack: range=[");
    serial_printf("%016llX", (unsigned long long)(stack_bottom));
    serial_printf("%s", ", ");
    serial_printf("%016llX", (unsigned long long)(stack_top));
    serial_printf("%s", ") rsp=");
    serial_printf("%016llX", (unsigned long long)(rsp));
    serial_printf("%s", "\r\n");

    if (rsp < stack_bottom || rsp >= stack_top)
    {
        serial_printf("%s", "  user stack: rsp outside stack bounds\r\n");
        return;
    }

    /* Print entries below rsp (older stack values) */
    if (max_entries_below > 0)
    {
        uintptr_t addr = rsp;
        size_t ready = 0;
        while (addr > stack_bottom && ready < max_entries_below)
        {
            addr -= sizeof(uintptr_t);
            ready++;
            if (addr < stack_bottom)
            {
                break;
            }
        }

        while (ready > 0 && addr >= stack_bottom)
        {
            size_t offset = (size_t)(addr - stack_bottom);
            uintptr_t value = 0;
            memcpy(&value, process->user_stack_host + offset, sizeof(uintptr_t));
            process_dump_stack_entry(addr, value, false);
            addr += sizeof(uintptr_t);
            ready--;
        }
    }

    /* Print entries starting at rsp and moving upward */
    if (max_entries_above > 0)
    {
        uintptr_t addr = rsp;
        size_t remaining = max_entries_above;
        while (remaining > 0 && addr + sizeof(uintptr_t) <= stack_top)
        {
            size_t offset = (size_t)(addr - stack_bottom);
            uintptr_t value = 0;
            memcpy(&value, process->user_stack_host + offset, sizeof(uintptr_t));
            process_dump_stack_entry(addr, value, addr == rsp);
            addr += sizeof(uintptr_t);
            remaining--;
        }
    }
}

static bool process_prepare_stack_with_args(process_t *process)
{
    if (!process || !process->user_stack_host || process->user_stack_size == 0)
    {
        return false;
    }

    uintptr_t stack_top = process->user_stack_top;
    uintptr_t stack_bottom = stack_top - process->user_stack_size;
    uint8_t *host = process->user_stack_host;

    size_t argc = process->arg_count;
    char **argv = process->arg_values;

    uintptr_t sp = stack_top;
    uintptr_t *arg_ptrs = NULL;

    if (argc > 0)
    {
        arg_ptrs = (uintptr_t *)malloc(sizeof(uintptr_t) * argc);
        if (!arg_ptrs)
        {
            return false;
        }
    }

    for (size_t i = 0; i < argc; ++i)
    {
        const char *arg = argv[i] ? argv[i] : "";
        size_t len = strlen(arg) + 1;
        if (sp < stack_bottom + len)
        {
            free(arg_ptrs);
            return false;
        }
        sp -= len;
        uintptr_t dst = sp;
        size_t offset = (size_t)(dst - stack_bottom);
        memcpy(host + offset, arg, len);
        arg_ptrs[i] = dst;
    }

    sp = align_down_uintptr(sp, 16ULL);

    if (sp < stack_bottom + sizeof(uintptr_t))
    {
        free(arg_ptrs);
        return false;
    }

    if (sp < stack_bottom + sizeof(uintptr_t))
    {
        if (arg_ptrs) free(arg_ptrs);
        return false;
    }
    sp -= sizeof(uintptr_t);
    if (!process_write_stack_uintptr(host, stack_bottom, stack_top, sp, 0))
    {
        free(arg_ptrs);
        return false;
    }

    for (size_t i = argc; i > 0; --i)
    {
        if (sp < stack_bottom + sizeof(uintptr_t))
        {
            free(arg_ptrs);
            return false;
        }
        sp -= sizeof(uintptr_t);
        if (!process_write_stack_uintptr(host, stack_bottom, stack_top, sp, arg_ptrs[i - 1]))
        {
            free(arg_ptrs);
            return false;
        }
    }

    uintptr_t argv_ptr = sp;

    if (sp < stack_bottom + sizeof(uintptr_t))
    {
        free(arg_ptrs);
        return false;
    }
    sp -= sizeof(uintptr_t);
    if (!process_write_stack_uintptr(host, stack_bottom, stack_top, sp, (uintptr_t)argc))
    {
        free(arg_ptrs);
        return false;
    }

    process->user_stack_top = sp;
    process->user_initial_stack = sp;
    process->user_argc = argc;
    process->user_argv_ptr = argv_ptr;

    if (arg_ptrs)
    {
        free(arg_ptrs);
    }
    process_clear_args(process);
    return true;
}

static bool process_setup_basic_user_memory(process_t *process)
{
    if (!process_setup_user_stack(process))
    {
        return false;
    }
    if (!process_setup_user_heap(process))
    {
        return false;
    }
    return process_setup_preempt_stub(process);
}

static bool process_setup_dummy_user_space(process_t *process)
{
    if (!process)
    {
        return false;
    }

    void *code_ptr = NULL;
    if (!process_map_user_segment(process,
                                  USER_STUB_CODE_BASE,
                                  PAGE_SIZE_BYTES_LOCAL,
                                  false,
                                  true,
                                  &code_ptr))
    {
        return false;
    }
    memcpy(code_ptr, g_user_exit_stub, sizeof(g_user_exit_stub));

    if (!process_setup_basic_user_memory(process))
    {
        return false;
    }

    process->user_entry_point = USER_STUB_CODE_BASE;
    return true;
}

static void scheduler_schedule(bool requeue_current);
static void idle_thread_entry(void *arg) __attribute__((noreturn));
static void thread_trampoline(void) __attribute__((noreturn));
static void user_thread_entry(void *arg) __attribute__((noreturn));
static void enqueue_thread(thread_t *thread);
static void remove_from_run_queue(thread_t *thread);
static inline uint32_t scheduler_time_slice_ticks(void);
static void thread_refresh_priority(thread_t *thread);
static void thread_set_base_priority(thread_t *thread, thread_priority_t priority);
static void thread_set_priority_override(thread_t *thread, bool enabled, thread_priority_t priority);
static void thread_remove_from_wait_queue(thread_t *thread);
static void wait_queue_enqueue_locked(wait_queue_t *queue, thread_t *thread);
static thread_t *wait_queue_dequeue_locked(wait_queue_t *queue);
static void process_attach_child(process_t *parent, process_t *child);
static void process_detach_child(process_t *child);
static process_t *process_detach_first_child(process_t *parent);
static void process_reap_orphans(void);

static void scheduler_trace(const char *prefix, thread_t *thread)
{
    if (!prefix || !thread)
    {
        return;
    }

    const char *name = thread->name[0] ? thread->name : "<unnamed>";
    uint64_t pid = thread->process ? thread->process->pid : 0;
    serial_printf("%s thread=%s pid=0x%016llX state=%s ctx_valid=%s stack=0x%016llX\r\n",
                  prefix,
                  name,
                  (unsigned long long)pid,
                  thread_state_name(thread->state),
                  thread->context_valid ? "true" : "false",
                  (unsigned long long)((uintptr_t)thread->stack_base));
}

static bool thread_name_equals(const thread_t *thread, const char *name)
{
    if (!thread || !name)
    {
        return false;
    }
    return strncmp(thread->name, name, PROCESS_NAME_MAX) == 0;
}

static bool string_name_equals(const char *lhs, const char *rhs)
{
    if (!lhs || !rhs)
    {
        return false;
    }
    return strncmp(lhs, rhs, PROCESS_NAME_MAX) == 0;
}

#define ENABLE_SHELL_TRACE 0

static void process_create_log(const char *name, const char *event)
{
    if (!ENABLE_SHELL_TRACE)
    {
        return;
    }

    serial_printf("%s", "[proc-trace] process_create ");
    serial_printf("%s", event ? event : "<none>");
    serial_printf("%s", " name=");
    serial_printf("%s", name ? name : "<none>");
    serial_printf("%s", "\r\n");
}

static void scheduler_shell_log(const char *event, thread_t *thread)
{
    if (!ENABLE_SHELL_TRACE || !thread)
    {
        return;
    }

    serial_printf("%s", "[sched-trace] ");
    serial_printf("%s", event);
    serial_printf("%s", " state=");
    serial_printf("%s", thread_state_name(thread->state));
    serial_printf("%s", " ctx_valid=");
    serial_printf("%s", thread->context_valid ? "true" : "false");
    serial_printf("%s", " name=");
    serial_printf("%s", thread->name[0] ? thread->name : "<unnamed>");
    serial_printf("%s", " pid=0x");
    serial_printf("%016llX", (unsigned long long)(thread->process ? thread->process->pid : 0));
    serial_printf("%s", " rsp0=0x");
    serial_printf("%016llX", (unsigned long long)((uint64_t)thread->kernel_stack_top));
    serial_printf("%s", "\r\n");
}

static void scheduler_wait_for_boot_ready(void)
{
    while (!__atomic_load_n(&g_scheduler_boot_ready, __ATOMIC_ACQUIRE))
    {
        __asm__ volatile ("hlt");
    }
}

static process_t *process_finalize_new_process(process_t *proc,
                                               thread_t *thread,
                                               int stdout_fd,
                                               process_t *parent)
{
    if (!proc || !thread)
    {
        return NULL;
    }

    if (stdout_fd >= 0)
    {
        proc->stdout_fd = stdout_fd;
    }
    else
    {
        proc->stdout_fd = g_console_stdout_fd;
    }

    proc->main_thread = thread;
    proc->current_thread = thread;
    spinlock_lock(&g_process_lock);
    proc->next = g_process_list;
    g_process_list = proc;
    spinlock_unlock(&g_process_lock);

    process_t *actual_parent = parent ? parent : current_process_local();
    vfs_node_t *inherit_cwd = NULL;
    if (actual_parent)
    {
        process_attach_child(actual_parent, proc);
        inherit_cwd = actual_parent->cwd;
    }

    if (!inherit_cwd)
    {
        inherit_cwd = vfs_root();
    }
    proc->cwd = inherit_cwd;

    enqueue_thread(thread);
    return proc;
}

static thread_t *thread_create(process_t *process,
                               const char *name,
                               thread_entry_t entry,
                               void *arg,
                               size_t stack_size,
                               bool is_idle,
                               bool user_mode)
{
    if (!process || !entry)
    {
        return NULL;
    }

    thread_t *thread = (thread_t *)malloc(sizeof(thread_t));
    if (!thread)
    {
        return NULL;
    }
    memset(thread, 0, sizeof(*thread));
    thread->last_cpu_index = 0;
    thread->deferred_next = NULL;
    thread->pending_destroy = false;
    bool is_user_thread = user_mode;
    if (!is_user_thread && process)
    {
        is_user_thread = process->is_user;
    }

    size_t requested_stack = stack_size ? stack_size : PROCESS_DEFAULT_STACK_SIZE;
    size_t guard_bytes = align_up_uintptr(PROCESS_STACK_GUARD_SIZE, PAGE_SIZE_BYTES_LOCAL);
    size_t aligned_stack = align_up_uintptr(requested_stack, PAGE_SIZE_BYTES_LOCAL);
    size_t allocation_size = guard_bytes + aligned_stack + PAGE_SIZE_BYTES_LOCAL;
    const uintptr_t heap_limit = (uintptr_t)kernel_heap_end;
#if THREAD_CREATE_DEBUG
    serial_printf("%s", "[thread_create] begin name=");
    serial_printf("%s", name ? name : "<null>");
    serial_printf("%s", " stack=0x");
    serial_printf("%016llX", (unsigned long long)requested_stack);
    serial_printf("%s", " aligned=0x");
    serial_printf("%016llX", (unsigned long long)aligned_stack);
    serial_printf("%s", " alloc=0x");
    serial_printf("%016llX", (unsigned long long)allocation_size);
    serial_printf("%s", " is_user=");
    serial_printf("%s", is_user_thread ? "true" : "false");
    serial_printf("%s", " is_idle=");
    serial_printf("%s", is_idle ? "true" : "false");
    serial_printf("%s", "\r\n");
#endif
    uint8_t *raw_allocation = NULL;
    uint8_t *guard_base = NULL;
    const int max_layout_attempts = 4;
    for (int attempt = 0; attempt < max_layout_attempts; ++attempt)
    {
        raw_allocation = (uint8_t *)malloc(allocation_size);
#if THREAD_CREATE_DEBUG
        serial_printf("%s", "[thread_create] attempt=");
        serial_printf("%016llX", (unsigned long long)attempt);
        serial_printf("%s", " raw=");
        serial_printf("%016llX", (unsigned long long)((uintptr_t)raw_allocation));
        serial_printf("%s", "\r\n");
#endif
        if (!raw_allocation)
        {
            break;
        }
        guard_base = (uint8_t *)align_up_uintptr((uintptr_t)raw_allocation, PAGE_SIZE_BYTES_LOCAL);
        uintptr_t stack_end = (uintptr_t)(guard_base + guard_bytes + aligned_stack);
#if THREAD_CREATE_DEBUG
        serial_printf("%s", "[thread_create] layout raw=");
        serial_printf("%016llX", (unsigned long long)((uintptr_t)raw_allocation));
        serial_printf("%s", " guard_base=");
        serial_printf("%016llX", (unsigned long long)((uintptr_t)guard_base));
        serial_printf("%s", " stack_end=0x");
        serial_printf("%016llX", (unsigned long long)stack_end);
        serial_printf("%s", " heap_limit=0x");
        serial_printf("%016llX", (unsigned long long)heap_limit);
        serial_printf("%s", "\r\n");
#endif
        if (stack_end <= heap_limit)
        {
            break;
        }
        free(raw_allocation);
        raw_allocation = NULL;
    }

    if (!raw_allocation)
    {
#if THREAD_CREATE_DEBUG
        serial_printf("%s", "[thread_create] alloc_failed name=");
        serial_printf("%s", name ? name : "<null>");
        serial_printf("%s", " alloc_size=0x");
        serial_printf("%016llX", (unsigned long long)allocation_size);
        serial_printf("%s", "\r\n");
#endif
        free(thread);
        return NULL;
    }

#if THREAD_CREATE_DEBUG
    serial_printf("%s", "[thread_create] using_allocation raw=");
    serial_printf("%016llX", (unsigned long long)((uintptr_t)raw_allocation));
    serial_printf("%s", " guard_base=");
    serial_printf("%016llX", (unsigned long long)((uintptr_t)guard_base));
    serial_printf("%s", " guard_bytes=0x");
    serial_printf("%016llX", (unsigned long long)guard_bytes);
    serial_printf("%s", " aligned_stack=0x");
    serial_printf("%016llX", (unsigned long long)aligned_stack);
    serial_printf("%s", "\r\n");
#endif

    memset(guard_base, STACK_GUARD_PATTERN, guard_bytes);
    thread->stack_allocation_raw = raw_allocation;
    thread->stack_allocation_size = allocation_size;
    thread->stack_guard_base = guard_base;
    thread->stack_base = guard_base + guard_bytes;
    thread->stack_size = aligned_stack;
#if THREAD_CREATE_DEBUG
    serial_printf("%s", "[thread_create] guard_filled base=");
    serial_printf("%016llX", (unsigned long long)((uintptr_t)thread->stack_base));
    serial_printf("%s", " size=0x");
    serial_printf("%016llX", (unsigned long long)thread->stack_size);
    serial_printf("%s", "\r\n");
#endif

    uintptr_t stack_limit = ((uintptr_t)thread->stack_base + aligned_stack) & ~(uintptr_t)0xF;
    uintptr_t usable_limit = stack_limit;
    uintptr_t redzone = THREAD_CONTEXT_REDZONE_BYTES;
    if (aligned_stack <= redzone + 64)
    {
        redzone = 64;
    }
    if (usable_limit > (uintptr_t)thread->stack_base + redzone)
    {
        usable_limit -= redzone;
        usable_limit &= ~(uintptr_t)0xF;
    }
    uintptr_t stack_ptr = usable_limit;
    uint64_t *stack64 = (uint64_t *)stack_ptr;

    /*
     * Build the initial context frame to exactly mirror context_switch:
     * low addresses -> r15, r14, r13, r12, rbx, rbp, rflags, return RIP <- high.
     * After the first return, RSP will be restored to usable_limit.
     */
    *(--stack64) = (uint64_t)thread_trampoline; /* return address (below saved frame) */
    *(--stack64) = RFLAGS_DEFAULT;              /* rflags */
    *(--stack64) = 0;                           /* rbp */
    *(--stack64) = 0;                           /* rbx */
    *(--stack64) = 0;                           /* r12 */
    *(--stack64) = 0;                           /* r13 */
    *(--stack64) = 0;                           /* r14 */
    *(--stack64) = 0;                           /* r15 */

    thread->tls.preempt_resume_rip = 0;
    thread->context = (cpu_context_t *)stack64;
    thread->context_valid = true;
    thread->kernel_stack_top = stack_limit;
    thread->process = process;
    thread->entry = entry;
    thread->arg = arg;
    thread->state = THREAD_STATE_READY;
    thread->queue_next = NULL;
    thread->in_run_queue = false;
    thread->is_idle = is_idle;
    thread->exited = false;
    thread->exit_status = 0;
    thread->time_slice_remaining = scheduler_time_slice_ticks();
    thread_priority_t default_priority = is_idle ? THREAD_PRIORITY_IDLE : THREAD_PRIORITY_NORMAL;
    thread->base_priority = default_priority;
    thread->priority = default_priority;
    thread->priority_override = default_priority;
    thread->priority_override_active = false;
    thread->in_transition = false;
    thread->preempt_pending = false;
    thread->fs_base = 0;
    thread->gs_base = (uint64_t)&thread->tls;
    thread->fpu_initialized = true;
    thread->waiting_queue = NULL;
    thread->wait_queue_next = NULL;
    thread->magic = THREAD_MAGIC;
    thread->stack_guard_failed = false;
    thread->stack_guard_reason = NULL;
    thread->is_user = is_user_thread;
    thread->context_guard_enabled = !is_idle;
    thread->fault_reason = NULL;
    thread->fault_error_code = 0;
    thread->fault_address = 0;
    thread->fault_has_address = false;
    memcpy(&thread->fpu_state, &g_fpu_initial_state, sizeof(fpu_state_t));
#if THREAD_CREATE_DEBUG
    serial_printf("%s", "[thread_create] stack_frame built sp=0x");
    serial_printf("%016llX", (unsigned long long)((uintptr_t)stack64));
    serial_printf("%s", " limit=0x");
    serial_printf("%016llX", (unsigned long long)stack_limit);
    serial_printf("%s", " usable_limit=0x");
    serial_printf("%016llX", (unsigned long long)usable_limit);
    serial_printf("%s", "\r\n");
    serial_printf("%s", "[thread_create] context set name=");
    serial_printf("%s", name ? name : "<null>");
    serial_printf("%s", " stack_base=0x");
    serial_printf("%016llX", (unsigned long long)((uintptr_t)thread->stack_base));
    serial_printf("%s", " stack_top=0x");
    serial_printf("%016llX", (unsigned long long)((uintptr_t)thread->kernel_stack_top));
    serial_printf("%s", " context=0x");
    serial_printf("%016llX", (unsigned long long)((uintptr_t)thread->context));
    serial_printf("%s", "\r\n");
#endif

#if THREAD_CREATE_DEBUG
    serial_printf("%s", "[thread_create] pre_watch name=");
    serial_printf("%s", name ? name : "<null>");
    serial_printf("%s", "\r\n");
#endif

    if (name)
    {
        size_t len = strlen(name);
        if (len >= PROCESS_NAME_MAX)
        {
            len = PROCESS_NAME_MAX - 1;
        }
        memcpy(thread->name, name, len);
        thread->name[len] = '\0';
    }
    else
    {
        thread->name[0] = '\0';
    }

    static int thread_log_count = 0;
    if (thread_log_count < 8)
    {
        serial_printf("%s", "process: thread created gs base=0x");
        serial_printf("%016llX", (unsigned long long)(thread->gs_base));
        serial_printf("%s", " name=");
        serial_printf("%s", thread->name);
        serial_printf("%s", "\r\n");
        thread_log_count++;
    }

#if ENABLE_STACK_WRITE_DEBUG
    const char *watch_context = thread->name[0] ? thread->name : "thread";
    if (!thread->is_idle)
    {
        uintptr_t watch_addr = thread->context
                               ? (uintptr_t)thread->context
                               : (uintptr_t)thread->stack_base;
#if THREAD_CREATE_DEBUG
        serial_printf("%s", "[thread_create] activating_stack_watch ctx=");
        serial_printf("%s", watch_context);
        serial_printf("%s", " addr=0x");
        serial_printf("%016llX", (unsigned long long)watch_addr);
        serial_printf("%s", "\r\n");
#endif
        thread_stack_watch_activate(thread, watch_context, watch_addr);
    }
#endif

#if ENABLE_CONTEXT_GUARD
    if (thread->context_guard_enabled)
    {
#if THREAD_CREATE_DEBUG
        serial_printf("%s", "[thread_create] context_guard_update name=");
        serial_printf("%s", thread->name);
        serial_printf("%s", "\r\n");
#endif
        thread_context_guard_update(thread, "thread_create");
    }
#endif

    stack_owner_register(thread);
    thread_registry_add(thread);
    scheduler_shell_log("created", thread);
#if THREAD_CREATE_DEBUG
    serial_printf("%s", "[thread_create] done name=");
    serial_printf("%s", thread->name);
    serial_printf("%s", " thread=0x");
    serial_printf("%016llX", (unsigned long long)((uintptr_t)thread));
    serial_printf("%s", "\r\n");
#endif
    return thread;
}

static inline uint32_t scheduler_cpu_limit(void)
{
    uint32_t count = smp_cpu_count();
    if (count == 0 || count > SMP_MAX_CPUS)
    {
        count = SMP_MAX_CPUS;
    }
    return count;
}

static inline run_queue_t *scheduler_run_queue(uint32_t cpu_index)
{
    if (cpu_index >= SMP_MAX_CPUS)
    {
        cpu_index = 0;
    }
    return &g_run_queues[cpu_index];
}

static void scheduler_log_run_queue_lock_warning(const run_queue_t *queue,
                                                 uint64_t ms,
                                                 const thread_t *owner,
                                                 const char *label,
                                                 const void *caller)
{
    serial_printf("%s", "[sched] run_queue lock held ");
    serial_printf("%llu", (unsigned long long)ms);
    serial_printf("%s", "ms cpu=");
    serial_printf("%u", queue ? queue->cpu_index : 0);
    serial_printf("%s", " owner=");
    if (owner)
    {
        if (owner->name[0])
        {
            serial_printf("%s", owner->name);
        }
        else
        {
            serial_printf("%s", "<unnamed>");
        }
        serial_printf("%s", " pid=0x");
        serial_printf("%016llX", (unsigned long long)(owner->process ? owner->process->pid : 0));
    }
    else
    {
        serial_printf("%s", "<none>");
    }
    serial_printf("%s", " label=");
    serial_printf("%s", label ? label : "<unset>");
    serial_printf("%s", " caller=0x");
    serial_printf("%016llX", (unsigned long long)(uintptr_t)caller);
    serial_printf("%s", "\r\n");
}

static void scheduler_log_run_queue_lock_wait(const run_queue_t *queue,
                                              uint64_t ms,
                                              const thread_t *owner,
                                              const char *owner_label,
                                              const void *owner_caller,
                                              const thread_t *waiter,
                                              const char *wait_label)
{
    serial_printf("%s", "[sched] run_queue lock wait ");
    serial_printf("%llu", (unsigned long long)ms);
    serial_printf("%s", "ms cpu=");
    serial_printf("%u", queue ? queue->cpu_index : 0);
    serial_printf("%s", " owner=");
    if (owner)
    {
        if (owner->name[0])
        {
            serial_printf("%s", owner->name);
        }
        else
        {
            serial_printf("%s", "<unnamed>");
        }
        serial_printf("%s", " pid=0x");
        serial_printf("%016llX", (unsigned long long)(owner->process ? owner->process->pid : 0));
    }
    else
    {
        serial_printf("%s", "<none>");
    }
    serial_printf("%s", " owner_label=");
    serial_printf("%s", owner_label ? owner_label : "<unset>");
    serial_printf("%s", " owner_caller=0x");
    serial_printf("%016llX", (unsigned long long)(uintptr_t)owner_caller);
    serial_printf("%s", " waiter=");
    if (waiter)
    {
        if (waiter->name[0])
        {
            serial_printf("%s", waiter->name);
        }
        else
        {
            serial_printf("%s", "<unnamed>");
        }
        serial_printf("%s", " pid=0x");
        serial_printf("%016llX", (unsigned long long)(waiter->process ? waiter->process->pid : 0));
    }
    else
    {
        serial_printf("%s", "<none>");
    }
    serial_printf("%s", " waiter_label=");
    serial_printf("%s", wait_label ? wait_label : "<unset>");
    serial_printf("%s", "\r\n");
}

static void scheduler_log_thread_brief(const thread_t *thread)
{
    if (!thread)
    {
        serial_printf("%s", "<none>");
        return;
    }
    const char *name = (thread->name[0] != '\0') ? thread->name : "<unnamed>";
    uint64_t pid = thread->process ? thread->process->pid : 0;
    serial_printf("%s pid=0x%016llX", name, (unsigned long long)pid);
}

static void scheduler_log_switch_latency(uint64_t ms,
                                         const thread_t *prev,
                                         const thread_t *next,
                                         bool deferred_work,
                                         const deferred_free_stats_t *stats)
{
    const char *pname = (prev && prev->name[0] != '\0') ? prev->name : (prev ? "<unnamed>" : "<none>");
    uint64_t ppid = (prev && prev->process) ? prev->process->pid : 0;
    const char *nname = (next && next->name[0] != '\0') ? next->name : (next ? "<unnamed>" : "<none>");
    uint64_t npid = (next && next->process) ? next->process->pid : 0;

    if (stats && stats->grabbed > 0)
    {
        uint64_t df_ms = scheduler_ticks_to_ms(stats->duration_ticks);
        serial_printf("[sched] switch latency %llu ms prev=%s pid=0x%016llX next=%s pid=0x%016llX deferred=%s grabbed=0x%016llX freed=0x%016llX requeued=0x%016llX df_ms=%llu\r\n",
                      (unsigned long long)ms,
                      pname,
                      (unsigned long long)ppid,
                      nname,
                      (unsigned long long)npid,
                      deferred_work ? "true" : "false",
                      (unsigned long long)stats->grabbed,
                      (unsigned long long)stats->freed,
                      (unsigned long long)stats->requeued,
                      (unsigned long long)df_ms);
    }
    else
    {
        serial_printf("[sched] switch latency %llu ms prev=%s pid=0x%016llX next=%s pid=0x%016llX deferred=%s\r\n",
                      (unsigned long long)ms,
                      pname,
                      (unsigned long long)ppid,
                      nname,
                      (unsigned long long)npid,
                      deferred_work ? "true" : "false");
    }
}

static inline void run_queue_lock_acquire(run_queue_t *queue, const char *label)
{
    if (!queue)
    {
        return;
    }
    uint64_t start = timer_ticks();
    bool wait_logged = false;
    thread_t *waiter = current_thread_local();
    while (__sync_lock_test_and_set(&queue->lock.value, 1) != 0)
    {
        while (queue->lock.value)
        {
            __asm__ volatile ("pause");
            if (!wait_logged)
            {
                uint64_t now = timer_ticks();
                uint64_t ms = scheduler_ticks_to_ms(now - start);
                if (ms >= RUN_QUEUE_LOCK_WARN_MS)
                {
                    scheduler_log_run_queue_lock_wait(queue,
                                                      ms,
                                                      queue->lock_owner,
                                                      queue->lock_owner_label,
                                                      queue->lock_owner_caller,
                                                      waiter,
                                                      label);
                    wait_logged = true;
                }
            }
        }
    }
    queue->lock_owner = current_thread_local();
    queue->lock_owner_label = label;
    queue->lock_owner_caller = __builtin_return_address(0);
    queue->lock_acquired_ticks = timer_ticks();
}

static inline void run_queue_lock_release(run_queue_t *queue)
{
    if (!queue)
    {
        return;
    }
    uint64_t start = queue->lock_acquired_ticks;
    thread_t *owner = queue->lock_owner;
    const char *label = queue->lock_owner_label;
    const void *caller = queue->lock_owner_caller;
    queue->lock_owner = NULL;
    queue->lock_owner_label = NULL;
    queue->lock_owner_caller = NULL;
    queue->lock_acquired_ticks = 0;
    spinlock_unlock(&queue->lock);
    if (start)
    {
        uint64_t delta = timer_ticks() - start;
        uint64_t ms = scheduler_ticks_to_ms(delta);
        if (ms >= RUN_QUEUE_LOCK_WARN_MS)
        {
            scheduler_log_run_queue_lock_warning(queue, ms, owner, label, caller);
        }
    }
}

static uint32_t scheduler_select_target_cpu(thread_t *thread)
{
    uint32_t cpu_count = scheduler_cpu_limit();
    if (cpu_count <= 1)
    {
        return 0;
    }

    uint32_t preferred = current_cpu_index();
    if (thread && thread->last_cpu_index < cpu_count)
    {
        preferred = thread->last_cpu_index;
    }
    if (preferred >= cpu_count)
    {
        preferred = 0;
    }

    uint32_t best_cpu = preferred;
    run_queue_t *best_queue = scheduler_run_queue(best_cpu);
    uint32_t best_load = __atomic_load_n(&best_queue->total, __ATOMIC_RELAXED);

    for (uint32_t i = 0; i < cpu_count; ++i)
    {
        if (i == preferred)
        {
            continue;
        }
        run_queue_t *queue = scheduler_run_queue(i);
        uint32_t load = __atomic_load_n(&queue->total, __ATOMIC_RELAXED);
        if (load == 0)
        {
            return i;
        }
        if (load < best_load)
        {
            best_cpu = i;
            best_load = load;
        }
    }

    return best_cpu;
}

static bool run_queue_detach_locked(run_queue_t *queue, thread_t *thread)
{
    if (!queue || !thread)
    {
        return false;
    }

    thread_priority_t priority = thread->priority;
    if (priority < THREAD_PRIORITY_IDLE || priority >= THREAD_PRIORITY_COUNT)
    {
        priority = THREAD_PRIORITY_NORMAL;
    }

    thread_t *head = queue->heads[priority];
    thread_t *prev = thread->queue_prev;
    thread_t *next = thread->queue_next;

    if (prev || head == thread)
    {
        if (prev)
        {
            prev->queue_next = next;
        }
        else
        {
            queue->heads[priority] = next;
        }
        if (next)
        {
            next->queue_prev = prev;
        }
        else if (queue->tails[priority] == thread)
        {
            queue->tails[priority] = prev;
        }
    }
    else
    {
        thread_t *cursor = head;
        thread_t *cursor_prev = NULL;
        while (cursor)
        {
            if (cursor == thread)
            {
                thread_t *cursor_next = cursor->queue_next;
                if (cursor_prev)
                {
                    cursor_prev->queue_next = cursor_next;
                }
                else
                {
                    queue->heads[priority] = cursor_next;
                }
                if (cursor_next)
                {
                    cursor_next->queue_prev = cursor_prev;
                }
                else
                {
                    queue->tails[priority] = cursor_prev;
                }
                break;
            }
            cursor_prev = cursor;
            cursor = cursor->queue_next;
        }
        if (!cursor)
        {
            return false;
        }
    }

    if (queue->counts[priority] > 0)
    {
        queue->counts[priority]--;
    }
    if (queue->total > 0)
    {
        queue->total--;
    }
    thread->in_run_queue = false;
    thread->queue_next = NULL;
    thread->queue_prev = NULL;
    return true;
}

static thread_t *run_queue_pop_locked(run_queue_t *queue)
{
    if (!queue)
    {
        return NULL;
    }

    for (int pr = THREAD_PRIORITY_COUNT - 1; pr >= THREAD_PRIORITY_IDLE; --pr)
    {
        thread_t *thread = queue->heads[pr];
        while (thread)
        {
            thread_t *next = thread->queue_next;
            if (!thread_can_run(thread))
            {
                thread = next;
                continue;
            }

            if (!run_queue_detach_locked(queue, thread))
            {
                return NULL;
            }

            if (!thread->context_valid)
            {
                scheduler_trace("[sched] dequeue forcing context_valid=true;", thread);
                thread->context_valid = true;
            }
            return thread;
        }
    }
    return NULL;
}

static thread_t *dequeue_thread_for_cpu(uint32_t cpu_index)
{
    run_queue_t *local = scheduler_run_queue(cpu_index);
    run_queue_lock_acquire(local, "dequeue");
    thread_t *thread = run_queue_pop_locked(local);
    run_queue_lock_release(local);
    if (thread)
    {
        thread->run_queue_cpu = cpu_index;
        return thread;
    }

    //serial_printf("%s", "[sched] dequeue: no runnable threads\n");
    return NULL;
}

static void enqueue_thread_on_cpu(thread_t *thread, uint32_t cpu_index)
{
    if (!thread || thread->in_run_queue || thread->is_idle)
    {
        return;
    }

    run_queue_t *queue = scheduler_run_queue(cpu_index);
    run_queue_lock_acquire(queue, "enqueue");
    thread_priority_t priority = thread->priority;
    if (priority < THREAD_PRIORITY_IDLE || priority >= THREAD_PRIORITY_COUNT)
    {
        priority = THREAD_PRIORITY_NORMAL;
        thread->priority = priority;
    }
    thread->queue_prev = queue->tails[priority];
    thread->queue_next = NULL;
    thread->run_queue_cpu = cpu_index;
    thread->in_run_queue = true;
    if (!queue->heads[priority])
    {
        queue->heads[priority] = thread;
        queue->tails[priority] = thread;
    }
    else
    {
        queue->tails[priority]->queue_next = thread;
        queue->tails[priority] = thread;
    }
    queue->counts[priority]++;
    queue->total++;
    run_queue_lock_release(queue);
    scheduler_shell_log("enqueued", thread);
}

static void enqueue_thread(thread_t *thread)
{
    if (!thread || thread->in_run_queue || thread->is_idle)
    {
        return;
    }
    uint32_t cpu_index = scheduler_select_target_cpu(thread);
    enqueue_thread_on_cpu(thread, cpu_index);
}

static void thread_freeze_for_stack_watch(thread_t *thread, const char *context)
{
#if ENABLE_STACK_WRITE_DEBUG
    if (!thread)
    {
        return;
    }
    uint64_t now = timer_ticks();
    uint64_t timeout_ticks = timer_frequency();
    if (timeout_ticks == 0)
    {
        timeout_ticks = 100;
    }
    timeout_ticks /= 2; /* ~500ms default */
    if (timeout_ticks == 0)
    {
        timeout_ticks = 50;
    }
    if (!thread->stack_watch_blocked)
    {
        thread->stack_watch_blocked = true;
        thread->stack_watch_timeout_logged = false;
        thread->context_guard_frozen = true;
        thread->context_guard_freeze_label = context;
        thread->state = THREAD_STATE_BLOCKED;
        thread->in_run_queue = false;
        thread->stack_watch_next = g_stack_watch_frozen_head;
        g_stack_watch_frozen_head = thread;
        serial_printf("%s", "[sched] stack watch freeze thread=");
        if (thread->name[0])
        {
            serial_printf("%s", thread->name);
        }
        else
        {
            serial_printf("%s", "<unnamed>");
        }
        serial_printf("%s", " pid=0x");
        serial_printf("%016llX", (unsigned long long)(thread->process ? thread->process->pid : 0));
        serial_printf("%s", " context=");
        serial_printf("%s", context ? context : "<none>");
        serial_printf("%s", "\r\n");
    }
    thread->stack_watch_freeze_deadline = now + timeout_ticks;
#else
    (void)thread;
    (void)context;
#endif
}

static void stack_watch_remove_frozen(thread_t *thread)
{
#if ENABLE_STACK_WRITE_DEBUG
    if (!thread)
    {
        return;
    }
    thread_t **cursor = &g_stack_watch_frozen_head;
    while (*cursor)
    {
        if (*cursor == thread)
        {
            *cursor = thread->stack_watch_next;
            thread->stack_watch_next = NULL;
            return;
        }
        cursor = &(*cursor)->stack_watch_next;
    }
#else
    (void)thread;
#endif
}

static void thread_unfreeze_after_stack_watch(thread_t *thread)
{
#if ENABLE_STACK_WRITE_DEBUG
    if (!thread)
    {
        return;
    }
    bool was_blocked = thread->stack_watch_blocked;
    thread->stack_watch_blocked = false;
    thread->stack_watch_timeout_logged = false;
    thread->context_guard_frozen = false;
    thread->context_guard_freeze_label = NULL;
    if (!was_blocked || thread->exited || thread->state == THREAD_STATE_ZOMBIE)
    {
        stack_watch_remove_frozen(thread);
        thread->stack_watch_next = NULL;
        thread->stack_watch_freeze_deadline = 0;
        return;
    }
    stack_watch_remove_frozen(thread);
    thread->stack_watch_next = NULL;
    thread->stack_watch_freeze_deadline = 0;
    thread->state = THREAD_STATE_READY;
    thread->preempt_pending = false;
#if ENABLE_CONTEXT_GUARD
    thread_context_guard_update(thread, "stack_watch_resume");
#endif
    enqueue_thread(thread);
#else
    (void)thread;
#endif
}

static void stack_watch_check_timeouts(void)
{
#if ENABLE_STACK_WRITE_DEBUG
    uint64_t now = timer_ticks();
    thread_t **cursor = &g_stack_watch_frozen_head;
    while (*cursor)
    {
        thread_t *thread = *cursor;
        if (!thread->stack_watch_blocked)
        {
            *cursor = thread->stack_watch_next;
            thread->stack_watch_next = NULL;
            continue;
        }
        if (now >= thread->stack_watch_freeze_deadline)
        {
            uintptr_t delta_addr = 0;
            uint8_t old_byte = 0;
            uint8_t new_byte = 0;
            if (thread_stack_watch_snapshot_changed(thread, &delta_addr, &old_byte, &new_byte))
            {
                serial_printf("%s", "[sched] stack watch delta thread=");
                if (thread->name[0])
                {
                    serial_printf("%s", thread->name);
                }
                else
                {
                    serial_printf("%s", "<unnamed>");
                }
                serial_printf("%s", " pid=0x");
                serial_printf("%016llX", (unsigned long long)(thread->process ? thread->process->pid : 0));
                serial_printf("%s", " addr=0x");
                serial_printf("%016llX", (unsigned long long)(delta_addr));
                serial_printf("%s", " old=0x");
                serial_printf("%02X", (unsigned int)(old_byte));
                serial_printf("%s", " new=0x");
                serial_printf("%02X", (unsigned int)(new_byte));
                serial_printf("%s", "\r\n");
                thread_scan_stack_for_suspicious_values(thread,
                                                        delta_addr,
                                                        true,
                                                        "stack_watch_delta");
                thread_stack_watch_deactivate(thread);
                thread_unfreeze_after_stack_watch(thread);
                continue;
            }

            if (!thread->stack_watch_timeout_logged)
            {
                serial_printf("%s", "[sched] stack watch timeout thread=");
                if (thread->name[0])
                {
                    serial_printf("%s", thread->name);
                }
                else
                {
                    serial_printf("%s", "<unnamed>");
                }
                serial_printf("%s", " pid=0x");
                serial_printf("%016llX", (unsigned long long)(thread->process ? thread->process->pid : 0));
                serial_printf("%s", " suspect=0x");
                serial_printf("%016llX", (unsigned long long)(thread->stack_watch_suspect));
                serial_printf("%s", "\r\n");
                thread->stack_watch_timeout_logged = true;
            }

            thread->stack_watch_timeout_count++;
            if (thread->stack_watch_timeout_count >= STACK_WATCH_TIMEOUT_LIMIT)
            {
                serial_printf("%s", "[sched] stack watch release thread=");
                if (thread->name[0])
                {
                    serial_printf("%s", thread->name);
                }
                else
                {
                    serial_printf("%s", "<unnamed>");
                }
                serial_printf("%s", " pid=0x");
                serial_printf("%016llX", (unsigned long long)(thread->process ? thread->process->pid : 0));
                serial_printf("%s", " reason=timeout_limit\r\n");
                thread_stack_watch_deactivate(thread);
                thread_unfreeze_after_stack_watch(thread);
                continue;
            }

            uint64_t extension = timer_frequency();
            if (extension == 0)
            {
                extension = 100;
            }
            extension /= 2;
            if (extension == 0)
            {
                extension = 50;
            }
            thread->stack_watch_freeze_deadline = now + extension;
            cursor = &thread->stack_watch_next;
            continue;
        }
        cursor = &thread->stack_watch_next;
    }
#else
    (void)0;
#endif
}

static bool thread_can_run(const thread_t *thread)
{
    if (!thread)
    {
        return false;
    }
    if (thread->in_transition)
    {
        return false;
    }
    if (thread->state != THREAD_STATE_READY)
    {
        return false;
    }
    return true;
}

static void remove_from_run_queue(thread_t *thread)
{
    if (!thread || !thread->in_run_queue)
    {
        return;
    }

    uint32_t cpu_index = thread->run_queue_cpu;
    uint32_t cpu_count = scheduler_cpu_limit();
    for (uint32_t attempt = 0; attempt < cpu_count; ++attempt)
    {
        uint32_t target = (cpu_index + attempt) % cpu_count;
        run_queue_t *queue = scheduler_run_queue(target);
        run_queue_lock_acquire(queue, "remove");
        bool removed = run_queue_detach_locked(queue, thread);
        run_queue_lock_release(queue);
        if (removed)
        {
            return;
        }
    }
}

static bool scheduler_thread_in_any_queue(thread_t *thread)
{
    if (!thread)
    {
        return false;
    }

    uint32_t cpu_count = scheduler_cpu_limit();
    for (uint32_t cpu = 0; cpu < cpu_count; ++cpu)
    {
        run_queue_t *queue = scheduler_run_queue(cpu);
        run_queue_lock_acquire(queue, "contains");
        for (int pr = THREAD_PRIORITY_COUNT - 1; pr >= THREAD_PRIORITY_IDLE; --pr)
        {
            for (thread_t *cursor = queue->heads[pr]; cursor; cursor = cursor->queue_next)
            {
                if (cursor == thread)
                {
                    run_queue_lock_release(queue);
                    return true;
                }
            }
        }
        run_queue_lock_release(queue);
    }

    return false;
}

static thread_priority_t thread_clamp_priority(thread_priority_t priority)
{
    if (priority < THREAD_PRIORITY_IDLE)
    {
        return THREAD_PRIORITY_IDLE;
    }
    if (priority >= THREAD_PRIORITY_COUNT)
    {
        return (thread_priority_t)(THREAD_PRIORITY_COUNT - 1);
    }
    return priority;
}

static thread_priority_t thread_effective_priority(const thread_t *thread)
{
    if (!thread)
    {
        return THREAD_PRIORITY_NORMAL;
    }
    thread_priority_t priority = thread->priority_override_active
                                 ? thread->priority_override
                                 : thread->base_priority;
    return thread_clamp_priority(priority);
}

static void thread_refresh_priority(thread_t *thread)
{
    if (!thread_pointer_valid(thread))
    {
        return;
    }
    thread_priority_t desired = thread_effective_priority(thread);
    if (thread->priority == desired)
    {
        return;
    }
    if (thread->in_run_queue)
    {
        remove_from_run_queue(thread);
    }
    thread->priority = desired;
    if (thread->state == THREAD_STATE_READY)
    {
        enqueue_thread(thread);
    }
}

static void thread_set_base_priority(thread_t *thread, thread_priority_t priority)
{
    if (!thread_pointer_valid(thread))
    {
        return;
    }
    thread->base_priority = thread_clamp_priority(priority);
    if (!thread->priority_override_active)
    {
        thread_refresh_priority(thread);
    }
}

static void thread_set_priority_override(thread_t *thread, bool enabled, thread_priority_t priority)
{
    if (!thread_pointer_valid(thread))
    {
        return;
    }
    if (enabled)
    {
        thread->priority_override_active = true;
        thread->priority_override = thread_clamp_priority(priority);
    }
    else
    {
        thread->priority_override_active = false;
    }
    thread_refresh_priority(thread);
}

static void thread_remove_from_wait_queue(thread_t *thread)
{
    wait_queue_t *queue = (thread && thread->waiting_queue) ? thread->waiting_queue : NULL;
    if (!queue)
    {
        return;
    }

    thread_t *prev = NULL;
    thread_t *cursor = queue->head;
    while (cursor)
    {
        if (cursor == thread)
        {
            if (prev)
            {
                prev->wait_queue_next = cursor->wait_queue_next;
            }
            else
            {
                queue->head = cursor->wait_queue_next;
            }
            if (queue->tail == cursor)
            {
                queue->tail = prev;
            }
            break;
        }
        prev = cursor;
        cursor = cursor->wait_queue_next;
    }

    thread->waiting_queue = NULL;
    thread->wait_queue_next = NULL;
}

static void sleep_queue_insert(thread_t *thread)
{
    if (!thread)
    {
        return;
    }
    spinlock_lock(&g_sleep_queue_lock);
    thread->sleeping = true;
    thread->sleep_queue_next = NULL;

    if (!g_sleep_queue_head || thread->sleep_until_tick < g_sleep_queue_head->sleep_until_tick)
    {
        thread->sleep_queue_next = g_sleep_queue_head;
        g_sleep_queue_head = thread;
        spinlock_unlock(&g_sleep_queue_lock);
        return;
    }

    thread_t *prev = g_sleep_queue_head;
    thread_t *cursor = g_sleep_queue_head->sleep_queue_next;
    while (cursor && cursor->sleep_until_tick <= thread->sleep_until_tick)
    {
        prev = cursor;
        cursor = cursor->sleep_queue_next;
    }
    prev->sleep_queue_next = thread;
    thread->sleep_queue_next = cursor;
    spinlock_unlock(&g_sleep_queue_lock);
}

static void sleep_queue_remove(thread_t *thread)
{
    if (!thread || !thread->sleeping)
    {
        return;
    }

    spinlock_lock(&g_sleep_queue_lock);
    if (g_sleep_queue_head == thread)
    {
        g_sleep_queue_head = thread->sleep_queue_next;
        thread->sleep_queue_next = NULL;
        thread->sleeping = false;
        spinlock_unlock(&g_sleep_queue_lock);
        return;
    }

    thread_t *prev = g_sleep_queue_head;
    thread_t *cursor = g_sleep_queue_head ? g_sleep_queue_head->sleep_queue_next : NULL;
    while (cursor)
    {
        if (cursor == thread)
        {
            prev->sleep_queue_next = cursor->sleep_queue_next;
            thread->sleep_queue_next = NULL;
            thread->sleeping = false;
            spinlock_unlock(&g_sleep_queue_lock);
            return;
        }
        prev = cursor;
        cursor = cursor->sleep_queue_next;
    }
    thread->sleeping = false;
    thread->sleep_queue_next = NULL;
    spinlock_unlock(&g_sleep_queue_lock);
}

static void sleep_queue_wake_due(uint64_t now)
{
    spinlock_lock(&g_sleep_queue_lock);
    while (g_sleep_queue_head && g_sleep_queue_head->sleep_until_tick <= now)
    {
        thread_t *thread = g_sleep_queue_head;
        g_sleep_queue_head = thread->sleep_queue_next;
        thread->sleep_queue_next = NULL;
        thread->sleeping = false;
        spinlock_unlock(&g_sleep_queue_lock);
        if (thread->state == THREAD_STATE_BLOCKED)
        {
            thread->state = THREAD_STATE_READY;
            enqueue_thread(thread);
        }
        spinlock_lock(&g_sleep_queue_lock);
    }
    spinlock_unlock(&g_sleep_queue_lock);
}

static void process_attach_child(process_t *parent, process_t *child)
{
    if (!child)
    {
        return;
    }

    uint64_t flags = cpu_save_flags();
    cpu_cli();

    child->parent = parent;
    child->sibling_prev = NULL;
    if (parent)
    {
        child->sibling_next = parent->first_child;
        if (child->sibling_next)
        {
            child->sibling_next->sibling_prev = child;
        }
        parent->first_child = child;
    }
    else
    {
        child->sibling_next = NULL;
    }

    cpu_restore_flags(flags);
}

static void process_detach_child(process_t *child)
{
    if (!child)
    {
        return;
    }

    uint64_t flags = cpu_save_flags();
    cpu_cli();

    process_t *parent = child->parent;
    if (parent && parent->first_child == child)
    {
        parent->first_child = child->sibling_next;
    }
    if (child->sibling_prev)
    {
        child->sibling_prev->sibling_next = child->sibling_next;
    }
    if (child->sibling_next)
    {
        child->sibling_next->sibling_prev = child->sibling_prev;
    }

    child->parent = NULL;
    child->sibling_prev = NULL;
    child->sibling_next = NULL;

    cpu_restore_flags(flags);
}

static process_t *process_detach_first_child(process_t *parent)
{
    if (!parent)
    {
        return NULL;
    }

    uint64_t flags = cpu_save_flags();
    cpu_cli();

    process_t *child = parent->first_child;
    if (child)
    {
        if (parent->first_child == child)
        {
            parent->first_child = child->sibling_next;
        }
        if (child->sibling_prev)
        {
            child->sibling_prev->sibling_next = child->sibling_next;
        }
        if (child->sibling_next)
        {
            child->sibling_next->sibling_prev = child->sibling_prev;
        }
        child->parent = NULL;
        child->sibling_prev = NULL;
        child->sibling_next = NULL;
    }

    cpu_restore_flags(flags);
    return child;
}

static void process_reap_orphans(void)
{
    while (1)
    {
        process_t *target = NULL;

        uint64_t flags = cpu_save_flags();
        cpu_cli();

        spinlock_lock(&g_process_lock);
        for (process_t *proc = g_process_list; proc; proc = proc->next)
        {
            if (proc->state == PROCESS_STATE_ZOMBIE &&
                proc->parent == NULL &&
                proc != g_idle_process)
            {
                target = proc;
                break;
            }
        }
        spinlock_unlock(&g_process_lock);

        cpu_restore_flags(flags);

        if (!target)
        {
            break;
        }

        process_destroy(target);
    }
}

static bool switch_to_thread(thread_t *next)
{
    uint64_t switch_start_ticks = timer_ticks();
    deferred_free_stats_t deferred_stats = { 0 };
    bool deferred_work = false;
    thread_t *prev = current_thread_local();
    process_t *prev_process = prev ? prev->process : NULL;
    process_t *next_process = next ? next->process : NULL;

    if (next && !thread_pointer_valid(next))
    {
        scheduler_trace("[sched] switch_to: invalid next pointer;", next);
        return false;
    }
    if (next && (next->state == THREAD_STATE_ZOMBIE || next->pending_destroy))
    {
        scheduler_trace("[sched] switch_to: next is zombie/pending_destroy;", next);
        return false;
    }
    if (next && !thread_fpu_region_valid(next))
    {
        scheduler_trace("[sched] switch_to: invalid fpu region;", next);
        return false;
    }
    if (next && (!next->context || !next->stack_base || next->kernel_stack_top == 0))
    {
        serial_printf("%s", "[sched] switch_to cancelled: missing context thread=");
        if (next->name[0])
        {
            serial_printf("%s", next->name);
        }
        else
        {
            serial_printf("%s", "<unnamed>");
        }
        serial_printf("%s", " pid=0x");
        serial_printf("%016llX", (unsigned long long)(next->process ? next->process->pid : 0));
        serial_printf("%s", " context=0x");
        serial_printf("%016llX", (unsigned long long)(uintptr_t)next->context);
        serial_printf("%s", " stack_base=0x");
        serial_printf("%016llX", (unsigned long long)(uintptr_t)next->stack_base);
        serial_printf("%s", " stack_top=0x");
        serial_printf("%016llX", (unsigned long long)next->kernel_stack_top);
        serial_printf("%s", "\r\n");
        return false;
    }

    if (prev)
    {
        thread_context_in_bounds(prev, "switch_from");
    }
    if (next)
    {
        thread_context_in_bounds(next, "switch_to");
    }

    if (prev)
    {
        prev->last_cpu_index = current_cpu_index();
        thread_assert_stack_current(prev, "switch_from");
        fpu_save_state(&prev->fpu_state);
        prev->fs_base = rdmsr(MSR_FS_BASE);
        prev->gs_base = rdmsr(MSR_GS_BASE);
        if (prev_process)
        {
            prev_process->current_thread = prev;
        }
    }

    if (prev_process && prev_process->state != PROCESS_STATE_ZOMBIE && prev != next)
    {
        prev_process->state = PROCESS_STATE_READY;
    }

    set_current_thread_local(next);
    set_current_process_local(next_process);
    uint32_t cpu_idx = current_cpu_index();
    if (prev_process && prev_process != next_process)
    {
        paging_space_clear_active_cpu(&prev_process->address_space, cpu_idx);
    }
    if (next_process)
    {
        paging_space_mark_active_cpu(&next_process->address_space, cpu_idx);
    }

    if (next)
    {
        next->last_cpu_index = current_cpu_index();
        next->state = THREAD_STATE_RUNNING;
        next->context_valid = false;
        scheduler_shell_log("context_valid=false (switch_to)", next);
        if (next_process)
        {
            next_process->state = PROCESS_STATE_RUNNING;
            next_process->current_thread = next;
        }

        next->time_slice_remaining = scheduler_time_slice_ticks();
        next->preempt_pending = false;

        thread_context_guard_release_pages(next);
        thread_context_guard_verify(next, "switch_to");
        if (next->stack_watch_blocked)
        {
            serial_printf("%s", "[sched] switch_to cancelled: stack watch active thread=");
            if (next->name[0])
            {
                serial_printf("%s", next->name);
            }
            else
            {
                serial_printf("%s", "<unnamed>");
            }
            serial_printf("%s", " pid=0x");
            serial_printf("%016llX", (unsigned long long)(next->process ? next->process->pid : 0));
            serial_printf("%s", " context=");
            serial_printf("%s", next->context_guard_freeze_label ? next->context_guard_freeze_label : "<none>");
            serial_printf("%s", "\r\n");
            next->context_valid = true;
            next->state = THREAD_STATE_BLOCKED;
            if (prev)
            {
                prev->state = THREAD_STATE_RUNNING;
            }
            if (prev_process)
            {
                prev_process->state = PROCESS_STATE_RUNNING;
            }
            set_current_thread_local(prev);
            set_current_process_local(prev_process);
            if (prev_process && prev_process != next_process)
            {
                paging_space_mark_active_cpu(&prev_process->address_space, cpu_idx);
            }
            return false;
        }
        thread_assert_stack_guard_only(next, "switch_to");
        scheduler_debug_dump_thread_stack(next, "switch_to");
        thread_scan_stack_for_suspicious_values(next,
                                                next->kernel_stack_top - sizeof(uint64_t),
                                                true,
                                                "switch_to");
        sanitize_gs_base(next);
        thread_stack_watch_deactivate(next);

        uint64_t desired_cr3 = next_process ? next_process->cr3 : read_cr3();
        if (desired_cr3 && desired_cr3 != read_cr3())
        {
            write_cr3(desired_cr3);
        }

        arch_cpu_set_kernel_stack(current_cpu_index(), next->kernel_stack_top);
        wrmsr(MSR_FS_BASE, next->fs_base);
        wrmsr(MSR_GS_BASE, next->gs_base);
        fpu_restore_state(&next->fpu_state);

    scheduler_debug_check_resume(next, "switch_to");
}

cpu_context_t **prev_ctx = prev ? &prev->context : &g_bootstrap_context;
cpu_context_t *next_ctx = next ? next->context : NULL;
    uint8_t *prev_transition_flag = prev ? (uint8_t *)&prev->in_transition : &g_context_switch_dummy_flag;

    if (!next_ctx)
    {
        if (prev_process && prev_process != next_process)
        {
            paging_space_mark_active_cpu(&prev_process->address_space, cpu_idx);
        }
        return false;
    }

    context_switch(prev_ctx, next_ctx, prev_transition_flag);

    thread_t *resumed = current_thread_local();
    if (resumed)
    {
        /*
         * Be defensive: ensure segment registers are sane after a context
         * switch. If a corrupted context ever clobbers SS/DS/ES, reload them
         * here so subsequent checks and stack accesses stay in kernel space.
         */
        if (!resumed->is_idle)
        {
            uint16_t kdata = GDT_SELECTOR_KERNEL_DATA;
            __asm__ volatile (
                "mov %0, %%ds\n\t"
                "mov %0, %%es\n\t"
                "mov %0, %%ss\n\t"
                :
                : "r"(kdata)
                : "memory");
        }

        /* Validate that we resumed on a sane stack to catch corruption early. */
        uintptr_t rsp_after = 0;
        __asm__ volatile ("mov %%rsp, %0" : "=r"(rsp_after));
        uint16_t ss_after = 0;
        __asm__ volatile ("mov %%ss, %0" : "=r"(ss_after));
        if (!thread_stack_pointer_valid(resumed, rsp_after))
        {
            serial_printf("%s", "[sched] fatal: resumed with invalid RSP thread=");
            serial_printf("%s", resumed->name[0] ? resumed->name : "<unnamed>");
            serial_printf("%s", " pid=0x");
            serial_printf("%016llX", (unsigned long long)(resumed->process ? resumed->process->pid : 0));
            serial_printf("%s", " rsp=0x");
            serial_printf("%016llX", (unsigned long long)rsp_after);
            serial_printf("%s", " stack=[0x");
            serial_printf("%016llX", (unsigned long long)(uintptr_t)resumed->stack_base);
            serial_printf("%s", ",0x");
            serial_printf("%016llX", (unsigned long long)resumed->kernel_stack_top);
            serial_printf("%s", ")\r\n");
            fatal("resumed with invalid stack pointer");
        }
        if (!resumed->is_idle && ss_after != GDT_SELECTOR_KERNEL_DATA)
        {
            serial_printf("%s", "[sched] fatal: resumed with invalid SS thread=");
            serial_printf("%s", resumed->name[0] ? resumed->name : "<unnamed>");
            serial_printf("%s", " pid=0x");
            serial_printf("%016llX", (unsigned long long)(resumed->process ? resumed->process->pid : 0));
            serial_printf("%s", " ss=0x");
            serial_printf("%04X", ss_after);
            serial_printf("%s", " stack=[0x");
            serial_printf("%016llX", (unsigned long long)(uintptr_t)resumed->stack_base);
            serial_printf("%s", ",0x");
            serial_printf("%016llX", (unsigned long long)resumed->kernel_stack_top);
            serial_printf("%s", ")\r\n");
            fatal("resumed with invalid stack segment");
        }
        thread_context_guard_release_pages(resumed);
        resumed->context_valid = true;
        scheduler_shell_log("context_valid=true (resumed)", resumed);
    }
#if ENABLE_STACK_WRITE_DEBUG
    if (prev)
    {
        thread_stack_watch_maybe_arm(prev);
    }
#endif
#if ENABLE_CONTEXT_GUARD
    if (prev)
    {
        thread_context_guard_update(prev, "switch_from");
    }
#endif
#if ENABLE_STACK_GUARD_PROTECT
    if (prev)
    {
        thread_context_guard_protect_pages(prev);
    }
#endif
    deferred_work = thread_process_deferred_frees(current_cpu_index(), &deferred_stats);

    uint64_t switch_elapsed_ms = scheduler_ticks_to_ms(timer_ticks() - switch_start_ticks);
    if (switch_elapsed_ms >= SCHED_SWITCH_WARN_MS)
    {
        scheduler_log_switch_latency(switch_elapsed_ms, prev, next, deferred_work, &deferred_stats);
    }

    return true;
}

static void scheduler_schedule(bool requeue_current)
{
    uint64_t sched_watch = timer_ticks();
    uint64_t flags = cpu_save_flags();
    cpu_cli();

    uint32_t cpu_index = current_cpu_index();
    thread_t *current = current_thread_local();

    if (!current)
    {
        requeue_current = false;
    }

    if (current && current->is_idle)
    {
        requeue_current = false;
    }

    if (requeue_current && current && current->state == THREAD_STATE_RUNNING)
    {
        thread_context_in_bounds(current, "requeue_current");
        current->state = THREAD_STATE_READY;
        current->time_slice_remaining = scheduler_time_slice_ticks();
        current->preempt_pending = false;
        current->context_valid = true;
        current->in_transition = true;
        // scheduler_shell_log("context_valid=true (requeue)", current);
        // scheduler_trace("[sched] requeue current;", current);
        enqueue_thread_on_cpu(current, cpu_index);
    }

    thread_t *next = dequeue_thread_for_cpu(cpu_index);
    if (!next)
    {
        thread_t *idle = g_idle_threads[cpu_index];
        if (!idle)
        {
            idle = g_idle_threads[0];
        }
        next = idle;
    }

    if (!next)
    {
        cpu_restore_flags(flags);
        scheduler_log_if_stalled("scheduler_schedule(no_next)", sched_watch);
        return;
    }

    if (next == current)
    {
        current->state = THREAD_STATE_RUNNING;
        current->preempt_pending = false;
        current->context_valid = true;
        current->in_transition = false;
        cpu_restore_flags(flags);
        scheduler_log_if_stalled("scheduler_schedule(run_current)", sched_watch);
        return;
    }

    while (!switch_to_thread(next))
    {
        scheduler_trace("[sched] switch_to failed; retry", next);
        next = dequeue_thread_for_cpu(cpu_index);
        if (!next)
        {
            thread_t *idle = g_idle_threads[cpu_index];
            if (!idle)
            {
                idle = g_idle_threads[0];
            }
            next = idle;
            if (!next)
            {
                cpu_restore_flags(flags);
                scheduler_log_if_stalled("scheduler_schedule(no_next_retry)", sched_watch);
                return;
            }
        }
            if (next == current)
            {
                current->state = THREAD_STATE_RUNNING;
                current->preempt_pending = false;
                current->context_valid = true;
                current->in_transition = false;
                cpu_restore_flags(flags);
                scheduler_log_if_stalled("scheduler_schedule(requeue)", sched_watch);
                return;
            }
    }
    cpu_restore_flags(flags);
    scheduler_log_if_stalled("scheduler_schedule", sched_watch);
    process_reap_orphans();
}

static void idle_thread_entry(void *arg)
{
    (void)arg;
    while (1)
    {
        __asm__ volatile ("hlt");
        scheduler_schedule(false);
    }
}

void process_preempt_hook(void)
{
    thread_t *thread = current_thread_local();
    if (!thread)
    {
        return;
    }

    thread->preempt_pending = false;

    process_yield();

    thread = current_thread_local();
    if (thread)
    {
        thread->preempt_pending = false;
    }
}

static __attribute__((noreturn)) void process_jump_to_user(uintptr_t entry,
                                                           uintptr_t user_stack_top,
                                                           uint64_t argc,
                                                           uintptr_t argv_ptr)
{
    uintptr_t aligned_stack = align_down_uintptr(user_stack_top, 16ULL);
    uintptr_t stack_value = aligned_stack;
    uintptr_t entry_value = entry;
    uint64_t rflags = RFLAGS_DEFAULT;
    uint64_t cs = (uint64_t)(GDT_SELECTOR_USER_CODE | 0x3u);
    uint64_t ss = (uint64_t)(GDT_SELECTOR_USER_DATA | 0x3u);
    uint64_t data_sel = (uint64_t)(GDT_SELECTOR_USER_DATA | 0x3u);

    __asm__ volatile (
        "mov %[ds], %%rax\n\t"
        "mov %%ax, %%ds\n\t"
        "mov %%ax, %%es\n\t"
        "xor %%rdx, %%rdx\n\t"
        "xor %%rcx, %%rcx\n\t"
        "xor %%r8, %%r8\n\t"
        "xor %%r9, %%r9\n\t"
        "xor %%r10, %%r10\n\t"
        "xor %%r11, %%r11\n\t"
        "mov %[ss], %%rax\n\t"
        "push %%rax\n\t"
        "mov %[stack], %%rax\n\t"
        "push %%rax\n\t"
        "mov %[rflags], %%rax\n\t"
        "push %%rax\n\t"
        "mov %[cs], %%rax\n\t"
        "push %%rax\n\t"
        "mov %[entry], %%rax\n\t"
        "push %%rax\n\t"
        "mov %[argc], %%rdi\n\t"
        "mov %[argv], %%rsi\n\t"
        "iretq\n\t"
        :
        : [ds]"r"(data_sel),
          [ss]"r"(ss),
          [stack]"m"(stack_value),
          [rflags]"r"(rflags),
          [cs]"r"(cs),
          [entry]"m"(entry_value),
          [argc]"r"(argc),
          [argv]"r"(argv_ptr)
        : "rax", "rdx", "rcx", "r8", "r9", "r10", "r11", "memory");
    __builtin_unreachable();
}

static void user_thread_entry(void *arg)
{
    user_thread_bootstrap_t params = { 0 };
    if (arg)
    {
        memcpy(&params, arg, sizeof(params));
        free(arg);
    }
    if (!params.entry || !params.stack_top)
    {
        fatal("user thread bootstrap missing entry/stack");
    }
    process_jump_to_user(params.entry, params.stack_top, params.argc, params.argv_ptr);
}

static void thread_trampoline(void)
{
    thread_t *self = current_thread_local();
    if (self && self->entry)
    {
        self->entry(self->arg);
    }
    process_exit(0);
}

static void process_handle_stack_guard_fault(void)
{
    thread_t *current = current_thread_local();
    if (!current)
    {
        fatal("stack guard fault with no current thread");
    }

    serial_printf("%s", "process: stack guard violation in thread ");
    if (current->name[0] != '\0')
    {
        serial_printf("%s", current->name);
    }
    else
    {
        serial_printf("%s", "(anon)");
    }
    if (current->stack_guard_reason)
    {
        serial_printf("%s", " reason=");
        serial_printf("%s", current->stack_guard_reason);
    }
    serial_printf("%s", "\r\n");

    current->exit_status = -1;
    current->exited = true;
    current->state = THREAD_STATE_ZOMBIE;
    current->preempt_pending = false;
    current->time_slice_remaining = 0;

    process_t *proc = current->process;
    if (proc)
    {
        proc->exit_status = -1;
        proc->state = PROCESS_STATE_ZOMBIE;
        wait_queue_wake_all(&proc->wait_queue);
    }

    scheduler_schedule(false);
    fatal("stack guard handler returned");
}

static void process_handle_fatal_fault(void)
{
    thread_t *current = current_thread_local();
    if (!current)
    {
        fatal("fatal fault handler without current thread");
    }

    current->exit_status = -1;
    current->exited = true;
    current->state = THREAD_STATE_ZOMBIE;
    current->preempt_pending = false;
    current->time_slice_remaining = 0;
    if (current->process)
    {
        current->process->exit_status = -1;
        current->process->state = PROCESS_STATE_ZOMBIE;
        wait_queue_wake_all(&current->process->wait_queue);
    }

    serial_printf("%s", "process: fatal fault in thread ");
    if (current->name[0] != '\0')
    {
        serial_printf("%s", current->name);
    }
    else
    {
        serial_printf("%s", "(anon)");
    }
    serial_printf("%s", " reason=");
    if (current->fault_reason)
    {
        serial_printf("%s", current->fault_reason);
    }
    else
    {
        serial_printf("%s", "unknown");
    }
    serial_printf("%s", " error=0x");
    serial_printf("%016llX", (unsigned long long)(current->fault_error_code));
    if (current->fault_has_address)
    {
        serial_printf("%s", " addr=0x");
        serial_printf("%016llX", (unsigned long long)(current->fault_address));
    }
    serial_printf("%s", "\r\n");

    scheduler_schedule(false);
    fatal("fatal fault handler returned");
}

bool process_handle_exception(interrupt_frame_t *frame,
                              const char *reason,
                              uint64_t error_code,
                              bool has_address,
                              uint64_t address)
{
    bool user_mode = frame && ((frame->cs & 0x3u) == 0x3u);
    if (!frame)
    {
        return false;
    }
    thread_t *thread = current_thread_local();
    if (!thread || !(thread->is_user || user_mode))
    {
        return false;
    }
    /* If the thread came from CPL=3 but was mislabeled, forgive the flag so we can unwind it. */
    if (user_mode)
    {
        thread->is_user = true;
    }

    thread->exit_status = -1;
    thread->exited = true;
    thread->state = THREAD_STATE_ZOMBIE;
    thread->preempt_pending = false;
    thread->time_slice_remaining = 0;

    process_t *proc = thread->process;
    if (proc)
    {
        proc->exit_status = -1;
        proc->state = PROCESS_STATE_ZOMBIE;
        wait_queue_wake_all(&proc->wait_queue);
    }

    process_trigger_fatal_fault(thread, frame, reason, error_code, has_address, address);
    return true;
}

void process_system_init(void)
{
    fpu_prepare_initial_state();

    if (g_console_stdout_fd < 0)
    {
        g_console_stdout_fd = fd_install(1, &console_stdout_ops, NULL);
        if (g_console_stdout_fd < 0)
        {
            g_console_stdout_fd = fd_allocate(&console_stdout_ops, NULL);
        }
        if (g_console_stdout_fd < 0)
        {
            fatal("unable to allocate console stdout fd");
        }
    }

    g_process_list = NULL;
    for (uint32_t i = 0; i < SMP_MAX_CPUS; ++i)
    {
        g_current_processes[i] = NULL;
        g_current_threads[i] = NULL;
        g_idle_threads[i] = NULL;
    }
    for (uint32_t i = 0; i < SMP_MAX_CPUS; ++i)
    {
        run_queue_t *queue = &g_run_queues[i];
        spinlock_init(&queue->lock);
        queue->total = 0;
        queue->lock_owner = NULL;
        queue->lock_owner_label = NULL;
        queue->lock_owner_caller = NULL;
        queue->lock_acquired_ticks = 0;
        queue->cpu_index = i;
        for (int pr = 0; pr < THREAD_PRIORITY_COUNT; ++pr)
        {
            queue->heads[pr] = NULL;
            queue->tails[pr] = NULL;
            queue->counts[pr] = 0;
        }
    }
#if ENABLE_STACK_WRITE_DEBUG
    for (uint32_t i = 0; i < STACK_OWNER_BUCKET_COUNT; ++i)
    {
        g_stack_owner_buckets[i] = NULL;
        spinlock_init(&g_stack_owner_locks[i]);
    }
#endif
    spinlock_init(&g_sleep_queue_lock);
    spinlock_init(&g_process_lock);
    spinlock_init(&g_thread_registry_lock);
    g_thread_registry_head = NULL;
    for (uint32_t i = 0; i < SMP_MAX_CPUS; ++i)
    {
        spinlock_init(&g_deferred_free_locks[i]);
        g_deferred_thread_frees[i] = NULL;
    }
    g_sleep_queue_head = NULL;
    g_next_pid = 1;

    uint32_t freq = timer_frequency();
    if (freq)
    {
        const uint32_t desired_slice_ms = 10;
        uint64_t ticks = ((uint64_t)freq * desired_slice_ms + 999ULL) / 1000ULL;
        if (ticks == 0)
        {
            ticks = 1;
        }
        if (ticks > UINT32_MAX)
        {
            ticks = UINT32_MAX;
        }
        g_time_slice_ticks = (uint32_t)ticks;
    }
    else
    {
        g_time_slice_ticks = PROCESS_TIME_SLICE_DEFAULT_TICKS;
    }

    process_t *idle_process = allocate_process("idle", false);
    if (!idle_process)
    {
        fatal("unable to allocate idle process");
    }
    idle_process->pid = 0;
    idle_process->state = PROCESS_STATE_READY;
    idle_process->is_user = false;
    idle_process->cr3 = read_cr3();
    spinlock_lock(&g_process_lock);
    idle_process->next = g_process_list;
    g_process_list = idle_process;
    spinlock_unlock(&g_process_lock);
    g_idle_process = idle_process;

    uint32_t cpu_count = smp_cpu_count();
    if (cpu_count == 0)
    {
        cpu_count = 1;
    }
    for (uint32_t cpu = 0; cpu < cpu_count; ++cpu)
    {
        char name[PROCESS_NAME_MAX];
        const char prefix[] = "idle";
        size_t pos = 0;
        while (prefix[pos] && pos < PROCESS_NAME_MAX - 1)
        {
            name[pos] = prefix[pos];
            pos++;
        }
        uint32_t value = cpu;
        char digits[10];
        size_t dpos = 0;
        do
        {
            digits[dpos++] = (char)('0' + (value % 10));
            value /= 10;
        } while (value > 0 && dpos < sizeof(digits));
        while (dpos > 0 && pos < PROCESS_NAME_MAX - 1)
        {
            name[pos++] = digits[--dpos];
        }
        name[pos] = '\0';

        thread_t *idle_thread = thread_create(idle_process,
                                              name,
                                              idle_thread_entry,
                                              NULL,
                                              PROCESS_DEFAULT_STACK_SIZE,
                                              true,
                                              false);
        if (!idle_thread)
        {
            fatal("unable to allocate idle thread");
        }
        idle_thread->state = THREAD_STATE_READY;
        idle_thread->is_idle = true;
        g_idle_threads[cpu] = idle_thread;
        if (cpu == 0)
        {
            idle_process->main_thread = idle_thread;
            idle_process->current_thread = idle_thread;
        }
    }
#if ENABLE_STACK_WRITE_DEBUG
    g_stack_write_debug_enabled = true;
#endif
}

static void scheduler_main_loop(void)
{
    scheduler_wait_for_boot_ready();
    while (1)
    {
        scheduler_schedule(false);
        __asm__ volatile ("hlt");
    }
}

void process_start_scheduler(void)
{
    scheduler_main_loop();
}

void process_run_secondary_cpu(uint32_t cpu_index)
{
    (void)cpu_index;
    interrupts_enable();
    scheduler_main_loop();
}

void process_scheduler_set_ready(void)
{
    __atomic_store_n(&g_scheduler_boot_ready, true, __ATOMIC_RELEASE);
}

static process_t *process_create_kernel_internal(const char *name,
                                                 thread_entry_t entry,
                                                 void *arg,
                                                 size_t stack_size,
                                                 int stdout_fd,
                                                 process_t *parent)
{
    process_create_log(name, "begin");
    if (!entry)
    {
        process_create_log(name, "no_entry");
        return NULL;
    }

    process_create_log(name, "alloc_start");
    process_t *proc = allocate_process(name, false);
    if (!proc)
    {
        process_create_log(name, "alloc_fail");
        return NULL;
    }

    process_create_log(name, "thread_create_start");
    thread_t *thread = thread_create(proc, name, entry, arg, stack_size, false, proc->is_user);
    if (!thread)
    {
        paging_destroy_space(&proc->address_space);
        free(proc);
        process_create_log(name, "thread_create_fail");
        return NULL;
    }

    process_create_log(name, "thread_create_done");
    process_create_log(name, "finalize_start");
    process_t *result = process_finalize_new_process(proc, thread, stdout_fd, parent);
    process_create_log(name, result ? "success" : "finalize_fail");
    return result;
}

static process_t *process_create_user_dummy_internal(const char *name,
                                                     size_t stack_size,
                                                     int stdout_fd,
                                                     process_t *parent)
{
    process_t *proc = allocate_process(name, true);
    if (!proc)
    {
        return NULL;
    }

    if (!process_setup_dummy_user_space(proc))
    {
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        free(proc);
        return NULL;
    }

    if (!process_store_args(proc, NULL, 0) || !process_prepare_stack_with_args(proc))
    {
        process_clear_args(proc);
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        free(proc);
        return NULL;
    }

    user_thread_bootstrap_t *bootstrap = (user_thread_bootstrap_t *)malloc(sizeof(user_thread_bootstrap_t));
    if (!bootstrap)
    {
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        free(proc);
        return NULL;
    }
    bootstrap->entry = proc->user_entry_point;
    bootstrap->stack_top = proc->user_initial_stack ? proc->user_initial_stack : proc->user_stack_top;
    bootstrap->argc = proc->user_argc;
    bootstrap->argv_ptr = proc->user_argv_ptr;

    thread_t *thread = thread_create(proc,
                                     name,
                                     user_thread_entry,
                                     bootstrap,
                                     stack_size,
                                     false,
                                     true);
    if (!thread)
    {
        free(bootstrap);
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        free(proc);
        return NULL;
    }

    return process_finalize_new_process(proc, thread, stdout_fd, parent);
}

static process_t *process_create_user_elf_internal(const char *name,
                                                   const uint8_t *image,
                                                   size_t size,
                                                   int stdout_fd,
                                                   process_t *parent,
                                                   const char *const *argv,
                                                   size_t argc)
{
    if (!image || size == 0)
    {
        return NULL;
    }

    process_t *proc = allocate_process(name, true);
    if (!proc)
    {
        return NULL;
    }

    if (!process_setup_basic_user_memory(proc))
    {
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        free(proc);
        return NULL;
    }

    if (!process_store_args(proc, argv, argc) || !process_prepare_stack_with_args(proc))
    {
        process_clear_args(proc);
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        free(proc);
        return NULL;
    }

    uintptr_t entry_point = 0;
    if (!elf_load_process(proc, image, size, &entry_point))
    {
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        free(proc);
        return NULL;
    }

    if (entry_point == 0)
    {
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        free(proc);
        return NULL;
    }

    proc->user_entry_point = entry_point;

    user_thread_bootstrap_t *bootstrap = (user_thread_bootstrap_t *)malloc(sizeof(user_thread_bootstrap_t));
    if (!bootstrap)
    {
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        free(proc);
        return NULL;
    }
    bootstrap->entry = proc->user_entry_point;
    bootstrap->stack_top = proc->user_initial_stack ? proc->user_initial_stack : proc->user_stack_top;
    bootstrap->argc = proc->user_argc;
    bootstrap->argv_ptr = proc->user_argv_ptr;

    thread_t *thread = thread_create(proc,
                                     name,
                                     user_thread_entry,
                                     bootstrap,
                                     PROCESS_DEFAULT_STACK_SIZE,
                                     false,
                                     true);
    if (!thread)
    {
        free(bootstrap);
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        free(proc);
        return NULL;
    }

    return process_finalize_new_process(proc, thread, stdout_fd, parent);
}

process_t *process_create_kernel(const char *name,
                                 thread_entry_t entry,
                                 void *arg,
                                 size_t stack_size,
                                 int stdout_fd)
{
    return process_create_kernel_internal(name, entry, arg, stack_size, stdout_fd, NULL);
}

process_t *process_create_kernel_with_parent(const char *name,
                                             thread_entry_t entry,
                                             void *arg,
                                             size_t stack_size,
                                             int stdout_fd,
                                             process_t *parent)
{
    return process_create_kernel_internal(name, entry, arg, stack_size, stdout_fd, parent);
}

process_t *process_create_user_dummy(const char *name,
                                     int stdout_fd)
{
    return process_create_user_dummy_internal(name,
                                              PROCESS_DEFAULT_STACK_SIZE,
                                              stdout_fd,
                                              NULL);
}

process_t *process_create_user_dummy_with_parent(const char *name,
                                                 int stdout_fd,
                                                 process_t *parent)
{
    return process_create_user_dummy_internal(name,
                                              PROCESS_DEFAULT_STACK_SIZE,
                                              stdout_fd,
                                              parent);
}

process_t *process_create_user_elf(const char *name,
                                   const uint8_t *image,
                                   size_t size,
                                   int stdout_fd,
                                   const char *const *argv,
                                   size_t argc)
{
    return process_create_user_elf_internal(name, image, size, stdout_fd, NULL, argv, argc);
}

process_t *process_create_user_elf_with_parent(const char *name,
                                               const uint8_t *image,
                                               size_t size,
                                               int stdout_fd,
                                               process_t *parent,
                                               const char *const *argv,
                                               size_t argc)
{
    return process_create_user_elf_internal(name, image, size, stdout_fd, parent, argv, argc);
}

void process_yield(void)
{
    scheduler_schedule(true);
}

void process_sleep_ticks(uint64_t ticks)
{
    if (ticks == 0)
    {
        process_yield();
        return;
    }

    thread_t *thread = current_thread_local();
    if (!thread || thread->is_idle)
    {
        process_yield();
        return;
    }

    uint64_t wake_tick = timer_ticks() + ticks;
    uint64_t flags = cpu_save_flags();
    cpu_cli();
    thread->state = THREAD_STATE_BLOCKED;
    thread->sleep_until_tick = wake_tick;
    sleep_queue_insert(thread);
    cpu_restore_flags(flags);
    scheduler_schedule(false);
}

void process_sleep_ms(uint32_t ms)
{
    uint32_t freq = timer_frequency();
    if (freq == 0)
    {
        process_sleep_ticks(1);
        return;
    }
    uint64_t ticks = ((uint64_t)ms * (uint64_t)freq + 999ULL) / 1000ULL;
    if (ticks == 0)
    {
        ticks = 1;
    }
    process_sleep_ticks(ticks);
}

void process_destroy(process_t *process)
{
    if (!process || process->state != PROCESS_STATE_ZOMBIE || process == g_idle_process)
    {
        return;
    }

    serial_printf("[proc] destroy pid=0x%016llX name=%s main_thread=0x%016llX\r\n",
                  (unsigned long long)process->pid,
                  process->name,
                  (unsigned long long)(uintptr_t)process->main_thread);

    user_atk_on_process_destroy(process);
    shell_service_cleanup_process(process);

    if (process->first_child)
    {
        process_t *child = process->first_child;
        while (child)
        {
            process_t *next = child->sibling_next;
            process_detach_child(child);
            child = next;
        }
    }

    process_detach_child(process);

    thread_t *thread = process->main_thread;
    if (thread)
    {
        process->main_thread = NULL;
        process->current_thread = NULL;
        thread_remove_from_wait_queue(thread);
        if (thread->sleeping)
        {
            sleep_queue_remove(thread);
        }
        if (thread->in_run_queue)
        {
            remove_from_run_queue(thread);
        }
        thread_context_guard_release_pages(thread);
        thread->magic = 0;
        thread_enqueue_deferred_free(thread);
        thread = NULL;
    }

    spinlock_lock(&g_process_lock);
    process_t **cursor = &g_process_list;
    while (*cursor)
    {
        if (*cursor == process)
        {
            *cursor = process->next;
            break;
        }
        cursor = &(*cursor)->next;
    }
    spinlock_unlock(&g_process_lock);

    process->magic = 0;
    process_free_user_regions(process);
    paging_destroy_space(&process->address_space);
    free(process);
}

void process_exit(int status)
{
    thread_t *current = current_thread_local();
    if (!current)
    {
        fatal("process_exit with no current thread");
    }

    current->exit_status = status;
    current->exited = true;
    current->state = THREAD_STATE_ZOMBIE;

    if (current->process)
    {
        current->process->exit_status = status;
        current->process->state = PROCESS_STATE_ZOMBIE;
        wait_queue_wake_all(&current->process->wait_queue);
    }

    scheduler_schedule(false);
    fatal("process_exit returned");
}

static bool process_has_exited(void *context)
{
    process_t *proc = (process_t *)context;
    return !proc || !process_pointer_valid(proc) || proc->state == PROCESS_STATE_ZOMBIE;
}

int process_join_with_hook(process_t *process,
                          int *status_out,
                          process_wait_hook_t hook,
                          void *context)
{
    if (!process)
    {
        return -1;
    }

    while (process->state != PROCESS_STATE_ZOMBIE)
    {
        if (hook)
        {
            hook(context);
            if (process->state == PROCESS_STATE_ZOMBIE)
            {
                break;
            }
            process_yield();
            continue;
        }
        wait_queue_wait(&process->wait_queue, process_has_exited, process);
    }

    if (status_out)
    {
        *status_out = process->exit_status;
    }
    return process->exit_status;
}

int process_join(process_t *process, int *status_out)
{
    return process_join_with_hook(process, status_out, NULL, NULL);
}

bool process_kill(process_t *process, int status)
{
    if (!process)
    {
        return false;
    }

    uint64_t flags = cpu_save_flags();
    cpu_cli();

    thread_t *thread = process->current_thread ? process->current_thread : process->main_thread;
    if (!thread)
    {
        cpu_restore_flags(flags);
        return false;
    }

    if (process->state == PROCESS_STATE_ZOMBIE || thread->state == THREAD_STATE_ZOMBIE)
    {
        process->state = PROCESS_STATE_ZOMBIE;
        process->exit_status = status;
        cpu_restore_flags(flags);
        return true;
    }

    bool target_running = (thread == current_thread_local());

    if (thread->in_run_queue)
    {
        remove_from_run_queue(thread);
    }

    thread->exit_status = status;
    thread->exited = true;
    thread->state = THREAD_STATE_ZOMBIE;
    thread->preempt_pending = false;
    thread->time_slice_remaining = 0;

    process->exit_status = status;
    process->state = PROCESS_STATE_ZOMBIE;
    wait_queue_wake_all(&process->wait_queue);

    cpu_restore_flags(flags);

    if (target_running)
    {
        process_exit(status);
    }

    return true;
}

void process_kill_tree(process_t *process)
{
    if (!process)
    {
        return;
    }

    process_t *child = NULL;
    while ((child = process_detach_first_child(process)) != NULL)
    {
        process_kill_tree(child);
        process_destroy(child);
    }

    process_kill(process, -1);
}

process_t *process_current(void)
{
    return current_process_local();
}

thread_t *thread_current(void)
{
    return current_thread_local();
}

bool process_thread_stack_bounds(const thread_t *thread,
                                 uintptr_t *base_out,
                                 uintptr_t *top_out)
{
    if (!thread || !thread->stack_base)
    {
        return false;
    }
    if (base_out)
    {
        *base_out = (uintptr_t)thread->stack_base;
    }
    if (top_out)
    {
        *top_out = thread->kernel_stack_top;
    }
    return true;
}

const char *process_thread_name_const(const thread_t *thread)
{
    if (!thread || thread->name[0] == '\0')
    {
        return NULL;
    }
    return thread->name;
}

process_t *process_thread_owner(const thread_t *thread)
{
    return thread ? thread->process : NULL;
}

bool process_is_zombie(const process_t *process)
{
    return process && process->state == PROCESS_STATE_ZOMBIE;
}

uint64_t process_current_pid(void)
{
    process_t *proc = current_process_local();
    return proc ? proc->pid : 0;
}

vfs_node_t *process_current_cwd(void)
{
    process_t *proc = process_current();
    if (!proc || !proc->cwd)
    {
        return vfs_root();
    }
    return proc->cwd;
}

void process_set_cwd(process_t *process, vfs_node_t *dir)
{
    if (!process)
    {
        return;
    }

    vfs_node_t *target = dir;
    if (target && !vfs_is_dir(target))
    {
        return;
    }
    if (!target)
    {
        target = vfs_root();
    }
    process->cwd = target;
}

static void wait_queue_enqueue_locked(wait_queue_t *queue, thread_t *thread)
{
    if (!queue || !thread)
    {
        return;
    }
    thread->wait_queue_next = NULL;
    if (queue->tail)
    {
        queue->tail->wait_queue_next = thread;
    }
    else
    {
        queue->head = thread;
    }
    queue->tail = thread;
}

static thread_t *wait_queue_dequeue_locked(wait_queue_t *queue)
{
    if (!queue)
    {
        return NULL;
    }
    thread_t *thread = queue->head;
    if (!thread)
    {
        return NULL;
    }
    queue->head = thread->wait_queue_next;
    if (!queue->head)
    {
        queue->tail = NULL;
    }
    thread->wait_queue_next = NULL;
    return thread;
}

void wait_queue_init(wait_queue_t *queue)
{
    if (!queue)
    {
        return;
    }
    spinlock_init(&queue->lock);
    queue->head = NULL;
    queue->tail = NULL;
}

static void wait_queue_remove_thread_locked(wait_queue_t *queue, thread_t *thread)
{
    if (!queue || !thread)
    {
        return;
    }
    if (queue->head == thread)
    {
        queue->head = thread->wait_queue_next;
        if (!queue->head)
        {
            queue->tail = NULL;
        }
        thread->wait_queue_next = NULL;
        return;
    }
    thread_t *prev = queue->head;
    while (prev && prev->wait_queue_next != thread)
    {
        prev = prev->wait_queue_next;
    }
    if (prev)
    {
        prev->wait_queue_next = thread->wait_queue_next;
        if (queue->tail == thread)
        {
            queue->tail = prev;
        }
        thread->wait_queue_next = NULL;
    }
}

void wait_queue_wait(wait_queue_t *queue, wait_queue_predicate_t predicate, void *context)
{
    if (!queue)
    {
        process_yield();
        return;
    }
    thread_t *thread = current_thread_local();
    if (!thread)
    {
        process_yield();
        return;
    }

    uint64_t flags = cpu_save_flags();
    cpu_cli();

    spinlock_lock(&queue->lock);

    if (thread->in_run_queue)
    {
        remove_from_run_queue(thread);
    }
    thread->state = THREAD_STATE_BLOCKED;
    thread->waiting_queue = queue;
    wait_queue_enqueue_locked(queue, thread);

    spinlock_unlock(&queue->lock);

    if (predicate && predicate(context))
    {
        spinlock_lock(&queue->lock);
        if (thread->waiting_queue == queue)
        {
            wait_queue_remove_thread_locked(queue, thread);
            thread->waiting_queue = NULL;
        }
        thread->state = THREAD_STATE_RUNNING;
        spinlock_unlock(&queue->lock);

        cpu_restore_flags(flags);
        return;
    }

    scheduler_schedule(false);
    cpu_restore_flags(flags);
}

void wait_queue_wake_one(wait_queue_t *queue)
{
    if (!queue)
    {
        return;
    }
    uint64_t flags = cpu_save_flags();
    cpu_cli();
    spinlock_lock(&queue->lock);

    thread_t *thread = wait_queue_dequeue_locked(queue);
    if (thread)
    {
        thread->waiting_queue = NULL;
        if (thread->state == THREAD_STATE_BLOCKED &&
            !thread->exited &&
            !thread->in_run_queue)
        {
            thread->state = THREAD_STATE_READY;
            enqueue_thread(thread);
        }
    }

    spinlock_unlock(&queue->lock);
    cpu_restore_flags(flags);
}

void wait_queue_wake_all(wait_queue_t *queue)
{
    if (!queue)
    {
        return;
    }
    uint64_t flags = cpu_save_flags();
    cpu_cli();
    spinlock_lock(&queue->lock);

    thread_t *thread = wait_queue_dequeue_locked(queue);
    while (thread)
    {
        thread->waiting_queue = NULL;
        if (thread->state == THREAD_STATE_BLOCKED &&
            !thread->exited &&
            !thread->in_run_queue)
        {
            thread->state = THREAD_STATE_READY;
            enqueue_thread(thread);
        }
        thread = wait_queue_dequeue_locked(queue);
    }

    spinlock_unlock(&queue->lock);
    cpu_restore_flags(flags);
}

void process_set_priority(process_t *process, thread_priority_t priority)
{
    if (!process_pointer_valid(process) || !thread_pointer_valid(process->main_thread))
    {
        return;
    }
    thread_set_base_priority(process->main_thread, priority);
}

void process_set_priority_override(process_t *process, thread_priority_t priority)
{
    if (!process_pointer_valid(process) || !thread_pointer_valid(process->main_thread))
    {
        return;
    }
    thread_set_priority_override(process->main_thread, true, priority);
}

void process_clear_priority_override(process_t *process)
{
    if (!process_pointer_valid(process) || !thread_pointer_valid(process->main_thread))
    {
        return;
    }
    thread_set_priority_override(process->main_thread, false, THREAD_PRIORITY_NORMAL);
}

uint64_t process_take_preempt_resume_rip(void)
{
    thread_t *thread = current_thread_local();
    if (!thread)
    {
        return 0;
    }
    uint64_t rip = thread->tls.preempt_resume_rip;
    thread->tls.preempt_resume_rip = 0;
    return rip;
}

uint64_t process_get_pid(const process_t *process)
{
    if (!process)
    {
        return 0;
    }
    return process->pid;
}

int process_current_stdout_fd(void)
{
    process_t *proc = current_process_local();
    if (proc && proc->stdout_fd >= 0)
    {
        return proc->stdout_fd;
    }
    return g_console_stdout_fd;
}

bool process_query_user_layout(const process_t *process,
                               process_user_layout_t *layout)
{
    if (!process || !layout)
    {
        return false;
    }

    layout->is_user = process->is_user;
    layout->cr3 = process->cr3;
    layout->entry_point = process->user_entry_point;
    layout->stack_top = process->user_stack_top;
    layout->stack_size = process->user_stack_size;
    return process->is_user && process->user_entry_point != 0 && process->user_stack_top != 0;
}

int64_t process_user_sbrk(process_t *process, int64_t increment)
{
    if (!process || !process->is_user || process->user_heap_base == 0)
    {
        return -1;
    }

    uintptr_t base = process->user_heap_base;
    uintptr_t limit = process->user_heap_limit;
    uintptr_t current = process->user_heap_brk;
    process_log("sbrk pid=", process->pid);
    process_log("sbrk inc=", (uint64_t)increment);
    process_log("sbrk current=", current);
    if (base == 0 || limit <= base || current < base || current > limit)
    {
        process_log("sbrk invalid bounds pid=", process->pid);
        return -1;
    }
    uintptr_t new_brk = current;

    if (increment > 0)
    {
        uint64_t inc = (uint64_t)increment;
        if (inc > (limit - current))
        {
            process_log("sbrk clamp inc=", inc);
            process_log("sbrk avail=", limit - current);
            return -1;
        }
        new_brk = current + inc;
        uintptr_t commit_start = process->user_heap_committed;
        uintptr_t commit_end = align_up_uintptr(new_brk, PAGE_SIZE_BYTES_LOCAL);
        if (commit_end > limit)
        {
            commit_end = limit;
        }
        if (commit_end > commit_start)
        {
            if (!process_heap_commit_range(process, commit_start, commit_end))
            {
                process_log("sbrk commit failed pid=", process->pid);
                process_log("sbrk commit avail=", user_memory_available());
                return -1;
            }
        }
        if (!process_heap_zero_range(process, current, inc))
        {
            process_log("sbrk zero failed pid=", process->pid);
            return -1;
        }
    }
    else if (increment < 0)
    {
        uint64_t dec = (uint64_t)(-increment);
        if (dec > (current - base))
        {
            process_log("sbrk negative clamp dec=", dec);
            return -1;
        }
        new_brk = current - dec;
        uintptr_t new_commit = align_up_uintptr(new_brk, PAGE_SIZE_BYTES_LOCAL);
        if (new_commit < process->user_heap_committed)
        {
            process_heap_release_from(process, new_commit);
            process->user_heap_committed = new_commit;
        }
    }

    process->user_heap_brk = new_brk;
    process_log("sbrk new=", new_brk);
    process_log("sbrk return=", current);
    return (int64_t)current;
}

ssize_t process_stdout_write(const char *data, size_t len)
{
    int fd = process_current_stdout_fd();
    if (fd < 0)
    {
        return -1;
    }
    return fd_write(fd, data, len);
}

size_t process_snapshot(process_info_t *buffer, size_t capacity)
{
    if (!buffer || capacity == 0)
    {
        return 0;
    }

    uint64_t flags = cpu_save_flags();
    cpu_cli();

    size_t count = 0;
    spinlock_lock(&g_process_lock);
    process_t *proc_iter = g_process_list;
    while (proc_iter && count < capacity)
    {
        process_t *proc = proc_iter;
        proc_iter = proc_iter->next;
        process_info_t *info = &buffer[count++];
        info->pid = proc->pid;
        info->state = proc->state;
        info->name = proc->name[0] ? proc->name : "(anon)";
        info->stdout_fd = proc->stdout_fd;
        thread_t *thread = proc->current_thread ? proc->current_thread : proc->main_thread;
        if (thread)
        {
            info->thread_state = thread->state;
            info->thread_name = thread->name[0] ? thread->name : "";
            info->is_idle = thread->is_idle;
            info->time_slice_remaining = thread->time_slice_remaining;
        }
        else
        {
            info->thread_state = THREAD_STATE_ZOMBIE;
            info->thread_name = "";
            info->is_idle = false;
            info->time_slice_remaining = 0;
        }
        info->is_current = (proc == current_process_local());

        if (proc->is_user && proc->user_heap_base != 0 && proc->user_heap_brk >= proc->user_heap_base)
        {
            uintptr_t committed = proc->user_heap_committed;
            if (committed < proc->user_heap_base)
            {
                committed = proc->user_heap_base;
            }
            info->heap_used_bytes = (uint64_t)(proc->user_heap_brk - proc->user_heap_base);
            info->heap_committed_bytes = (uint64_t)(committed - proc->user_heap_base);
        }
        else
        {
            info->heap_used_bytes = 0;
            info->heap_committed_bytes = 0;
        }
    }
    spinlock_unlock(&g_process_lock);

    cpu_restore_flags(flags);
    return count;
}

const char *process_state_name(process_state_t state)
{
    switch (state)
    {
        case PROCESS_STATE_READY:   return "ready";
        case PROCESS_STATE_RUNNING: return "running";
        case PROCESS_STATE_ZOMBIE:  return "zombie";
    }
    return "unknown";
}

const char *thread_state_name(thread_state_t state)
{
    switch (state)
    {
        case THREAD_STATE_READY:   return "ready";
        case THREAD_STATE_RUNNING: return "running";
        case THREAD_STATE_BLOCKED: return "blocked";
        case THREAD_STATE_ZOMBIE:  return "zombie";
    }
    return "unknown";
}

void process_dump_current_thread(void)
{
    thread_t *thread = current_thread_local();
    if (!thread)
    {
        serial_printf("%s", "  thread: <none>\r\n");
        return;
    }
    serial_printf("%s", "  thread name=");
    if (thread->name[0])
    {
        serial_printf("%s", thread->name);
    }
    else
    {
        serial_printf("%s", "<unnamed>");
    }
    serial_printf("%s", " state=");
    serial_printf("%s", thread_state_name(thread->state));
    serial_printf("%s", " stack_base=0x");
    serial_printf("%016llX", (unsigned long long)((uintptr_t)thread->stack_base));
    serial_printf("%s", " stack_top=0x");
    serial_printf("%016llX", (unsigned long long)(thread->kernel_stack_top));
    serial_printf("%s", " guard=");
    serial_printf("%s", thread_stack_guard_intact(thread) ? "ok" : "CORRUPT");
    serial_printf("%s", "\r\n");
}

void process_debug_scan_current_kernel_stack(const char *context,
                                             uintptr_t rsp_hint,
                                             bool full_stack)
{
    thread_t *thread = current_thread_local();
    if (!thread)
    {
        return;
    }
    uintptr_t hint = rsp_hint ? rsp_hint : (uintptr_t)thread->stack_base;
    thread_scan_stack_for_suspicious_values(thread, hint, full_stack, context);
}

bool process_handle_stack_watch_fault(uintptr_t fault_addr,
                                      interrupt_frame_t *frame,
                                      uint64_t error_code)
{
#if ENABLE_STACK_WRITE_DEBUG
    thread_t *target = thread_find_stack_owner(fault_addr, 0);
    if (!target || !target->stack_watch_active)
    {
        return false;
    }

    thread_t *writer = current_thread_local();
    serial_printf("%s", "[sched] stack watch fault hit\r\n");
    serial_printf("%s", "  target=");
    if (target->name[0])
    {
        serial_printf("%s", target->name);
    }
    else
    {
        serial_printf("%s", "<unnamed>");
    }
    serial_printf("%s", " pid=0x");
    serial_printf("%016llX", (unsigned long long)(target->process ? target->process->pid : 0));
    serial_printf("%s", " addr=0x");
    serial_printf("%016llX", (unsigned long long)(fault_addr));
    serial_printf("%s", " watch_base=0x");
    serial_printf("%016llX", (unsigned long long)(target->stack_watch_base));
    serial_printf("%s", " watch_len=0x");
    serial_printf("%016llX", (unsigned long long)(target->stack_watch_len));
    serial_printf("%s", " suspect=0x");
    serial_printf("%016llX", (unsigned long long)(target->stack_watch_suspect));
    serial_printf("%s", " context=");
    serial_printf("%s", target->stack_watch_context ? target->stack_watch_context : "<none>");
    serial_printf("%s", "\r\n");

    serial_printf("%s", "  writer=");
    if (writer && writer->name[0])
    {
        serial_printf("%s", writer->name);
    }
    else
    {
        serial_printf("%s", writer ? "<unnamed>" : "<none>");
    }
    serial_printf("%s", " pid=0x");
    serial_printf("%016llX", (unsigned long long)(writer && writer->process ? writer->process->pid : 0));
    serial_printf("%s", " rip=0x");
    serial_printf("%016llX", (unsigned long long)(frame ? frame->rip : 0));
    serial_printf("%s", " err=0x");
    serial_printf("%016llX", (unsigned long long)(error_code));
    serial_printf("%s", "\r\n");

    target->stack_watch_enabled = false;
    thread_stack_watch_deactivate(target);
    thread_unfreeze_after_stack_watch(target);

    if (writer && frame)
    {
        process_trigger_fatal_fault(writer,
                                    frame,
                                    "stack_watch_fault",
                                    error_code,
                                    true,
                                    fault_addr);
    }
    else
    {
        fatal("stack watch fault without writer/frame");
    }
    return true;
#else
    (void)fault_addr;
    (void)frame;
    (void)error_code;
    return false;
#endif
}

bool process_stack_watch_thread(thread_t *thread, const char *context)
{
#if ENABLE_STACK_WRITE_DEBUG
    return thread_stack_watch_activate(thread, context, 0);
#else
    (void)thread;
    (void)context;
    return false;
#endif
}

bool process_stack_watch_process(process_t *process, const char *context)
{
#if ENABLE_STACK_WRITE_DEBUG
    if (!process || !process->main_thread)
    {
        return false;
    }
    return process_stack_watch_thread(process->main_thread, context);
#else
    (void)process;
    (void)context;
    return false;
#endif
}

void process_on_timer_tick(interrupt_frame_t *frame)
{
    if (!frame)
    {
        return;
    }

    sleep_queue_wake_due(timer_ticks());
    stack_watch_check_timeouts();

    thread_t *thread = current_thread_local();
    if (!thread || thread->is_idle)
    {
        return;
    }

    uint64_t kernel_rsp = 0;
    __asm__ volatile ("mov %%rsp, %0" : "=r"(kernel_rsp));

    if (!thread_stack_pointer_valid(thread, kernel_rsp))
    {
        thread_trigger_stack_guard(thread, frame, "rsp_out_of_bounds");
        return;
    }

    if (!thread_stack_guard_intact(thread))
    {
        thread_trigger_stack_guard(thread, frame, "guard_corrupted");
        return;
    }

    thread_scan_stack_for_suspicious_values(thread, kernel_rsp, false, "timer_tick");

    sanitize_gs_base(thread);

    if (thread->preempt_pending)
    {
        return;
    }

    if (thread->time_slice_remaining > 0)
    {
        thread->time_slice_remaining--;
    }

    if (thread->time_slice_remaining > 0)
    {
        return;
    }

    thread->preempt_pending = true;
    thread->time_slice_remaining = scheduler_time_slice_ticks();

    bool user_mode = frame && ((frame->cs & 0x3u) == 0x3u);
    if (!frame)
    {
        return;
    }

    thread->tls.preempt_resume_rip = frame->rip;
    if (user_mode)
    {
        frame->rip = USER_PREEMPT_STUB_BASE;
    }
    else
    {
        frame->rip = (uint64_t)process_preempt_trampoline;
    }
}

#if ENABLE_STACK_WRITE_DEBUG
#define STACK_WRITE_SELF_WINDOW_BYTES (THREAD_CONTEXT_REDZONE_BYTES + 1024ULL)

void process_debug_log_stack_write(const char *label,
                                   const void *caller,
                                   void *dest,
                                   size_t len)
{
    if (!g_stack_write_debug_enabled || !dest || len == 0)
    {
        return;
    }

    uintptr_t addr = (uintptr_t)dest;
    thread_t *owner = thread_find_stack_owner(addr, len);
    thread_t *writer = current_thread_local();
    bool self_write = false;
    bool cross_write = false;
    if (owner && owner == writer)
    {
        uintptr_t top = owner->kernel_stack_top;
        if (top >= addr && (top - addr) <= STACK_WRITE_SELF_WINDOW_BYTES)
        {
            self_write = true;
        }
        else
        {
            return;
        }
    }
    else if (owner)
    {
        cross_write = true;
    }
    if (!owner || (!self_write && !cross_write))
    {
        return;
    }

    serial_printf("%s", self_write ? "[stack-write-self] label="
                                   : (cross_write ? "[stack-write-cross] label=" : "[stack-write] label="));
    serial_printf("%s", label ? label : "<none>");
    serial_printf("%s", " writer=");
    if (writer && writer->name[0])
    {
        serial_printf("%s", writer->name);
    }
    else
    {
        serial_printf("%s", "<none>");
    }
    serial_printf("%s", " writer_pid=0x");
    serial_printf("%016llX", (unsigned long long)(writer && writer->process ? writer->process->pid : 0));
    serial_printf("%s", " target=");
    if (owner->name[0])
    {
        serial_printf("%s", owner->name);
    }
    else
    {
        serial_printf("%s", "<unnamed>");
    }
    serial_printf("%s", " target_pid=0x");
    serial_printf("%016llX", (unsigned long long)(owner->process ? owner->process->pid : 0));
    serial_printf("%s", " dest=0x");
    serial_printf("%016llX", (unsigned long long)(addr));
    serial_printf("%s", " len=0x");
    serial_printf("%016llX", (unsigned long long)(len));
    serial_printf("%s", " stack_base=0x");
    serial_printf("%016llX", (unsigned long long)((uintptr_t)owner->stack_base));
    serial_printf("%s", " stack_top=0x");
    serial_printf("%016llX", (unsigned long long)(owner->kernel_stack_top));
    serial_printf("%s", " caller=0x");
    serial_printf("%016llX", (unsigned long long)((uintptr_t)caller));
    serial_printf("%s", "\r\n");
}
#else
void process_debug_log_stack_write(const char *label,
                                   const void *caller,
                                   void *dest,
                                   size_t len)
{
    (void)label;
    (void)caller;
    (void)dest;
    (void)len;
}
#endif
