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
#include "lapic.h"
#include "spinlock.h"
#include "build_features.h"
#include "procfs.h"
#include "sched_log.h"
#include <stddef.h>

extern uintptr_t kernel_heap_base;
extern uintptr_t kernel_heap_end;
extern uint8_t __kernel_text_start[];
extern uint8_t __kernel_data_end[];

#define MSR_FS_BASE         0xC0000100
#define MSR_GS_BASE         0xC0000101
#define RFLAGS_RESERVED_BIT (1ULL << 1)
#define RFLAGS_IF_BIT       (1ULL << 9)
#define RFLAGS_DEFAULT      (RFLAGS_RESERVED_BIT | RFLAGS_IF_BIT)
#define CONTEXT_SWITCH_SAVED_WORDS 7ULL

#define PROCESS_STACK_GUARD_SIZE         (4096UL)
#define STACK_GUARD_PATTERN              0x5A
#define ENABLE_SMP_BOOT_STACK_SCAN         1
#define SMP_BOOT_STACK_SCAN_MAX_QWORDS     8192ULL
#define STACK_SCAN_DUMP_CONTEXT_QWORDS     16ULL
#ifndef ENABLE_SCHEDULER_STACK_DUMP
#define ENABLE_SCHEDULER_STACK_DUMP      0
#endif
#define SCHEDULER_STACK_DUMP_QWORDS      32ULL
#ifndef ENABLE_CONTEXT_GUARD
#define ENABLE_CONTEXT_GUARD             1
#endif
#define CONTEXT_GUARD_WORDS              CONTEXT_SWITCH_SAVED_WORDS
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

static inline bool canonical_u64(uint64_t v)
{
    uint64_t sign = v >> 47;
    return sign == 0 || sign == 0x1FFFFu;
}

static const char *const g_context_guard_reg_names[] = {
    "r15",
    "r14",
    "r13",
    "r12",
    "rbx",
    "rbp",
    "rflags",
    "ret"
};

enum context_frame_index
{
    CTX_R15 = 0,
    CTX_R14,
    CTX_R13,
    CTX_R12,
    CTX_RBX,
    CTX_RBP,
    CTX_RFLAGS,
    CTX_RET,
    CTX_WORD_COUNT
};
#undef CONTEXT_SWITCH_SAVED_WORDS
#define CONTEXT_SWITCH_SAVED_WORDS CTX_RET

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

typedef enum
{
    THREAD_LIFETIME_ALIVE = 0,
    THREAD_LIFETIME_DEFERRED,
    THREAD_LIFETIME_FREED
} thread_lifetime_state_t;

struct thread
{
    thread_tls_t tls;
    process_t *process;
    cpu_context_t *context;
    spinlock_t context_lock;
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
    bool wake_pending;
    uint64_t sleep_until_tick;
    struct thread *sleep_queue_next;
    uint32_t running_cpu;
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
    thread_lifetime_state_t lifetime_state;
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

#ifndef ENABLE_RUN_QUEUE_DEBUG
#define ENABLE_RUN_QUEUE_DEBUG 1
#endif

#define RUN_QUEUE_CPU_INVALID 0xFFFFFFFFu
#define RUN_QUEUE_CPU_CLAIMED 0xFFFFFFFEu

static inline bool thread_in_run_queue_load(const thread_t *thread)
{
    if (!thread)
    {
        return false;
    }
    return __atomic_load_n(&thread->in_run_queue, __ATOMIC_ACQUIRE);
}

static inline void thread_in_run_queue_store(thread_t *thread, bool value)
{
    if (!thread)
    {
        return;
    }
    __atomic_store_n(&thread->in_run_queue, value, __ATOMIC_RELEASE);
}

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
static spinlock_t g_scheduler_lock;
static thread_t *g_sleep_queue_head = NULL;
static uint64_t g_next_pid = 1;
static spinlock_t g_sleep_queue_lock;
static spinlock_t g_process_lock;
static volatile bool g_scheduler_boot_ready = false;
#if ENABLE_STACK_WRITE_DEBUG
static bool g_stack_owner_ready = false;
#endif

static fpu_state_t g_fpu_initial_state;
static bool g_fpu_template_ready = false;
static int g_console_stdout_fd = -1;
static uint32_t g_time_slice_ticks = PROCESS_TIME_SLICE_DEFAULT_TICKS;
static thread_t *g_stack_watch_frozen_head = NULL;
static thread_t *g_thread_registry_head = NULL;
static spinlock_t g_thread_registry_lock;
static uint8_t g_context_switch_dummy_flag __attribute__((unused)) = 0;
static const uint64_t SCHEDULER_STALL_LOG_MS = 2000ULL;
static const uint64_t RUN_QUEUE_LOCK_WARN_MS __attribute__((unused)) = 1000ULL;
static const uint64_t SCHED_SWITCH_WARN_MS = 500ULL;
static const uint64_t DEFERRED_FREE_WARN_MS = 250ULL;
static bool g_bad_saved_rflags_tripped __attribute__((unused)) = false;
uint64_t g_scheduler_switch_count = 0;
uint32_t g_sched_log_enable = 1;
uint32_t g_sched_dbg_enable = 1;
uint32_t g_sched_sleep_log_enable = 1;
static uint32_t g_scheduler_rr_cursor = 0;

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
static void thread_quarantine_corrupt(thread_t *thread, const char *reason);

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
        SCHED_LOG("[sched] stall label=%s duration=%llu ms uptime=%llu s\r\n",
                  label,
                  (unsigned long long)ms,
                  (unsigned long long)(ms / 1000ULL));
    }
}

static inline uint64_t cpu_save_flags(void);
static inline void cpu_restore_flags(uint64_t flags);
static inline void cpu_cli(void);

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
    if (idx < SMP_MAX_CPUS)
    {
        return idx;
    }

    /* Capture corruption as early as possible. */
    SCHED_LOG("[sched] bad cpu index=0x%08X caller=0x%016llX\r\n",
              idx,
              (unsigned long long)(uintptr_t)__builtin_return_address(0));
    for (uint32_t i = 0; i < SMP_MAX_CPUS; ++i)
    {
        thread_t *t = g_current_threads[i];
        process_t *p = g_current_processes[i];
        SCHED_LOG("[sched] slot=%u thread=0x%016llX pid=0x%016llX lock=0x%08X\r\n",
                  (unsigned)i,
                  (unsigned long long)(uintptr_t)t,
                  (unsigned long long)(p ? p->pid : 0),
                  g_deferred_free_locks[i].value);
    }
    return 0;
}

static inline thread_t *current_thread_local(void)
{
    uint32_t idx = smp_current_cpu_index();
    if (idx >= SMP_MAX_CPUS)
    {
        fatal("current_thread_local: cpu index out of range");
    }
    return g_current_threads[idx];
}

static inline int32_t thread_find_running_cpu(const thread_t *thread)
{
    if (!thread)
    {
        return -1;
    }
    for (uint32_t i = 0; i < SMP_MAX_CPUS; ++i)
    {
        if (g_current_threads[i] == thread)
        {
            return (int32_t)i;
        }
    }
    return -1;
}

static inline process_t *current_process_local(void)
{
    uint32_t idx = smp_current_cpu_index();
    if (idx >= SMP_MAX_CPUS)
    {
        fatal("current_process_local: cpu index out of range");
    }
    return g_current_processes[idx];
}

static inline void set_current_thread_local(thread_t *thread)
{
    uint32_t idx = smp_current_cpu_index();
    if (idx >= SMP_MAX_CPUS)
    {
        fatal("set_current_thread_local: cpu index out of range");
    }
    uint64_t flags = cpu_save_flags();
    cpu_cli();
    g_current_threads[idx] = thread;
    cpu_restore_flags(flags);
}

static inline void set_current_process_local(process_t *process)
{
    uint32_t idx = smp_current_cpu_index();
    if (idx >= SMP_MAX_CPUS)
    {
        fatal("set_current_process_local: cpu index out of range");
    }
    uint64_t flags = cpu_save_flags();
    cpu_cli();
    g_current_processes[idx] = process;
    cpu_restore_flags(flags);
}

static bool thread_running_on_any_cpu(const thread_t *thread)
{
    if (!thread)
    {
        return false;
    }
    uint32_t running = __atomic_load_n(&((thread_t *)thread)->running_cpu, __ATOMIC_ACQUIRE);
    if (running != RUN_QUEUE_CPU_INVALID)
    {
        return true;
    }
    for (uint32_t i = 0; i < SMP_MAX_CPUS; ++i)
    {
        if (g_current_threads[i] == thread)
        {
            return true;
        }
    }
    return false;
}

static bool thread_running_elsewhere(const thread_t *thread)
{
    if (!thread)
    {
        return false;
    }
    uint32_t running = __atomic_load_n(&((thread_t *)thread)->running_cpu, __ATOMIC_ACQUIRE);
    thread_t *self = current_thread_local();
    return (running != RUN_QUEUE_CPU_INVALID &&
            running < SMP_MAX_CPUS &&
            g_current_threads[running] == thread &&
            g_current_threads[running] != self);
}

static inline void thread_clear_running_cpu(thread_t *thread)
{
    if (!thread)
    {
        return;
    }
    uint32_t rc = __atomic_load_n(&thread->running_cpu, __ATOMIC_ACQUIRE);
    if (rc == RUN_QUEUE_CPU_INVALID)
    {
        return;
    }
    uint32_t self = current_cpu_index();
    if (rc != self)
    {
        /* Only the owning CPU should clear running_cpu. */
        return;
    }
    __atomic_store_n(&thread->running_cpu, RUN_QUEUE_CPU_INVALID, __ATOMIC_RELEASE);
}

static void thread_debug_check_ownership(const thread_t *thread, const char *where)
{
    if (!sched_dbg_enabled() || !thread)
    {
        return;
    }
    uint32_t rc = __atomic_load_n(&((thread_t *)thread)->running_cpu, __ATOMIC_ACQUIRE);
    int32_t actual = thread_find_running_cpu(thread);
    if (actual >= 0 && rc != (uint32_t)actual)
    {
        SCHED_DBG("[sched dbg] ownership mismatch %s thread=%s pid=0x%016llX running_cpu=%u actual_cpu=%d state=%s in_run_queue=%s\r\n",
                  where ? where : "<unknown>",
                  thread->name[0] ? thread->name : "<unnamed>",
                  (unsigned long long)(thread->process ? thread->process->pid : 0),
                  rc,
                  actual,
                  thread_state_name(thread->state),
                  thread_in_run_queue_load(thread) ? "true" : "false");
    }
}

static bool thread_lifetime_active(const thread_t *thread)
{
    if (!thread)
    {
        return false;
    }
    thread_lifetime_state_t state = __atomic_load_n(&((thread_t *)thread)->lifetime_state,
                                                    __ATOMIC_ACQUIRE);
    return state == THREAD_LIFETIME_ALIVE;
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
    }
    /* Emit the same bytes to the serial port without log prefixes. */
    serial_output_bytes(data, count);
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

static bool pointer_in_heap(uint64_t addr, size_t size)
{
    uint64_t heap_start = (uint64_t)kernel_heap_base;
    uint64_t heap_end = (uint64_t)kernel_heap_end;
    if (addr == 0 || addr < heap_start || addr >= heap_end)
    {
        return false;
    }
    uint64_t max_len = heap_end - addr;
    if (size > max_len)
    {
        return false;
    }
    return true;
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
        serial_printf("[proc] priority thread ptr invalid addr=0x%016llX\r\n",
                      (unsigned long long)((uint64_t)(uintptr_t)thread));
        return false;
    }
    if (thread->magic != THREAD_MAGIC)
    {
        serial_printf("[proc] priority thread magic mismatch addr=0x%016llX magic=0x%016llX\r\n",
                      (unsigned long long)((uint64_t)(uintptr_t)thread),
                      (unsigned long long)((uint64_t)thread->magic));
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
        serial_printf("[proc] process ptr invalid addr=0x%016llX\r\n",
                      (unsigned long long)((uint64_t)(uintptr_t)process));
        return false;
    }
    if (process->magic != PROCESS_MAGIC)
    {
        serial_printf("[proc] process magic mismatch addr=0x%016llX magic=0x%016llX\r\n",
                      (unsigned long long)((uint64_t)(uintptr_t)process),
                      (unsigned long long)((uint64_t)process->magic));
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
        serial_printf("process: repaired GS base for thread %s old=0x%016llX new=0x%016llX\r\n",
                      thread->name,
                      (unsigned long long)old_base,
                      (unsigned long long)thread->gs_base);
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
    serial_printf("[proc] %s0x%016llX\r\n",
                  msg ? msg : "",
                  (unsigned long long)(value));
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

    if (!thread->context_valid)
    {
        return 0;              // ADD THIS
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

static void thread_quarantine_corrupt(thread_t *thread, const char *reason);
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

static bool thread_saved_frame_valid(thread_t *thread, const char *label)
{
#if ENABLE_STACK_WRITE_DEBUG
    if (!thread || !thread->context || !thread->stack_base)
    {
        return true;
    }
    if (!thread_lifetime_active(thread))
    {
        return true;
    }

    if (!thread->context_valid)
    {
        return 0;              // ADD THIS
    }

    /* Avoid spinning on the lock if the thread is currently running. */
    if (thread->state == THREAD_STATE_RUNNING)
    {
        return true;
    }

    spinlock_lock(&thread->context_lock);

    uintptr_t ctx = (uintptr_t)thread->context;
    uintptr_t lower = (uintptr_t)thread->stack_base;
    uintptr_t upper = thread->kernel_stack_top;
    size_t needed = (size_t)((CONTEXT_SWITCH_SAVED_WORDS + 1ULL) * sizeof(uint64_t));
    if (ctx < lower || upper < ctx || (upper - ctx) < needed)
    {
        SCHED_LOG("[sched] stack watch: context out of range thread=%s pid=0x%016llX ctx=0x%016llX bounds=[0x%016llX,0x%016llX) label=%s\r\n",
                  thread->name[0] ? thread->name : "<unnamed>",
                  (unsigned long long)(thread->process ? thread->process->pid : 0),
                  (unsigned long long)ctx,
                  (unsigned long long)lower,
                  (unsigned long long)upper,
                  label ? label : "<none>");
        spinlock_unlock(&thread->context_lock);
        thread_quarantine_corrupt(thread, "stack_watch_ctx_oob");
        return false;
    }

    const uint64_t *ctx_words = (const uint64_t *)ctx;
    uint64_t saved_rflags = ctx_words[CTX_RFLAGS];
    uint64_t resume_rip = ctx_words[CTX_RET];
    bool rip_canonical = pointer_is_canonical((uintptr_t)resume_rip);
    bool rip_in_kernel = rip_canonical &&
                         resume_rip >= (uint64_t)(uintptr_t)__kernel_text_start &&
                         resume_rip <  (uint64_t)(uintptr_t)__kernel_data_end;
    bool rflags_reserved_ok = (saved_rflags & RFLAGS_RESERVED_BIT) != 0;
    if (!rflags_reserved_ok)
    {
        uint64_t patched = saved_rflags | RFLAGS_RESERVED_BIT;
        uint64_t *ctx_mut = (uint64_t *)ctx;
        ctx_mut[CTX_RFLAGS] = patched;
        rflags_reserved_ok = true;
        SCHED_LOG("[sched] patched reserved rflags bit thread=%s pid=0x%016llX where=%s old=0x%016llX new=0x%016llX\r\n",
                  thread->name[0] ? thread->name : "<unnamed>",
                  (unsigned long long)(thread->process ? thread->process->pid : 0),
                  label ? label : "<none>",
                  (unsigned long long)saved_rflags,
                  (unsigned long long)patched);
    }
    spinlock_unlock(&thread->context_lock);

    if (rip_in_kernel && rflags_reserved_ok)
    {
        return true;
    }

    SCHED_LOG("[sched] stack watch: invalid saved frame thread=%s pid=0x%016llX rip=0x%016llX rflags=0x%016llX label=%s\r\n",
              thread->name[0] ? thread->name : "<unnamed>",
              (unsigned long long)(thread->process ? thread->process->pid : 0),
              (unsigned long long)resume_rip,
              (unsigned long long)saved_rflags,
              label ? label : "<none>");
    thread_quarantine_corrupt(thread, rip_in_kernel ? "stack_watch_rflags" : "stack_watch_rip");
    return false;
#else
    (void)thread;
    (void)label;
    return true;
#endif
}

static void thread_stack_watch_capture_snapshot(thread_t *thread)
{
#if ENABLE_STACK_WRITE_DEBUG
    if (!thread)
    {
        return;
    }
    if (!thread_lifetime_active(thread))
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
    if (!thread_lifetime_active(thread))
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
static bool thread_saved_frame_valid(thread_t *thread, const char *label);
static void thread_remove_from_wait_queue(thread_t *thread);
static void sleep_queue_remove(thread_t *thread);

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
    if (!thread || !thread_lifetime_active(thread) || thread->stack_watch_active || !thread->stack_base)
    {
        return false;
    }
    /* Do not arm before the scheduler is fully up or while any CPU is using
     * this thread as its current context, even if state flags are stale. */
    if (!__atomic_load_n(&g_scheduler_boot_ready, __ATOMIC_ACQUIRE))
    {
        return false;
    }
    if (__atomic_load_n(&((thread_t *)thread)->running_cpu, __ATOMIC_ACQUIRE) != RUN_QUEUE_CPU_INVALID)
    {
        return false;
    }
    if (thread->in_transition)
    {
        return false;
    }
    for (uint32_t i = 0; i < SMP_MAX_CPUS; ++i)
    {
        if (g_current_threads[i] == thread)
        {
            return false;
        }
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
    /* Harden against corrupted metadata before we touch page tables. */
    uintptr_t stack_base = (uintptr_t)thread->stack_base;
    uintptr_t stack_top = thread->kernel_stack_top;
    if (!pointer_is_canonical(stack_base) ||
        !pointer_is_canonical(stack_top) ||
        stack_top <= stack_base ||
        thread->stack_allocation_raw == NULL ||
        thread->stack_size == 0)
    {
#if ENABLE_STACK_WRITE_DEBUG_LOGS
        SCHED_LOG("%s", "[sched] stack watch abort: bad stack metadata\r\n");
#endif
        return false;
    }

    const char *label = thread->stack_watch_context ? thread->stack_watch_context : "stack_watch";
    if (!thread_saved_frame_valid(thread, label))
    {
        return false;
    }

    uintptr_t base = align_down_uintptr((uintptr_t)thread->stack_base, PAGE_SIZE_BYTES_LOCAL);
    uintptr_t top = align_up_uintptr(thread->kernel_stack_top, PAGE_SIZE_BYTES_LOCAL);
    /* Cap range to the allocation we actually own to avoid poisoning unrelated pages. */
    uintptr_t allocation_start = align_down_uintptr((uintptr_t)thread->stack_allocation_raw, PAGE_SIZE_BYTES_LOCAL);
    uintptr_t allocation_end = allocation_start + align_up_uintptr(thread->stack_allocation_size ? thread->stack_allocation_size : 0, PAGE_SIZE_BYTES_LOCAL);
    if (top <= base || allocation_end <= allocation_start || base < allocation_start || top > allocation_end)
    {
        return false;
    }
    size_t length = (size_t)(top - base);
    if (!paging_set_kernel_range_writable(base, length, false))
    {
        SCHED_LOG("%s", "[sched] warning: unable to arm stack watch\r\n");
        return false;
    }
    thread->stack_watch_active = true;
    thread->stack_watch_base = base;
    thread->stack_watch_len = length;

#if ENABLE_STACK_WRITE_DEBUG_LOGS
    const char *name = thread->name[0] ? thread->name : "<unnamed>";
    SCHED_LOG("[sched] stack watch armed thread=%s pid=0x%016llX context=%s suspect=0x%016llX base=0x%016llX top=0x%016llX\r\n",
              name,
              (unsigned long long)(thread->process ? thread->process->pid : 0),
              thread->stack_watch_context ? thread->stack_watch_context : "<none>",
              (unsigned long long)(thread->stack_watch_suspect),
              (unsigned long long)(base),
              (unsigned long long)(top));
#endif
    thread->stack_watch_timeout_logged = false;
    thread_stack_watch_capture_snapshot(thread);
    return true;
}

static bool thread_stack_watch_activate(thread_t *thread,
                                        const char *context,
                                        uintptr_t suspect_addr)
{
    if (!thread || !thread_lifetime_active(thread))
    {
        return false;
    }

    if (!thread->context_valid)
    {
        return false; 
    }


    if (suspect_addr == 0)
    {
        /* Default to the current saved context frame so we catch corruptors. */
        suspect_addr = (uintptr_t)thread->context;
    }
    if (!__atomic_load_n(&g_scheduler_boot_ready, __ATOMIC_ACQUIRE))
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
        SCHED_LOG("[sched] stack watch pending thread=%s pid=0x%016llX context=%s\r\n",
                  thread->name[0] ? thread->name : "<unnamed>",
                  (unsigned long long)(thread->process ? thread->process->pid : 0),
                  thread->stack_watch_context ? thread->stack_watch_context : "<none>");
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
        SCHED_LOG("%s", "[sched] warning: unable to disarm stack watch\r\n");
    }
#if ENABLE_STACK_WRITE_DEBUG_LOGS
    SCHED_LOG("[sched] stack watch cleared thread=%s pid=0x%016llX\r\n",
              thread->name[0] ? thread->name : "<unnamed>",
              (unsigned long long)(thread->process ? thread->process->pid : 0));
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

#if ENABLE_STACK_WRITE_DEBUG
    if (thread->stack_watch_active || thread->stack_watch_blocked)
    {
        SCHED_LOG("[sched] warning: freeing thread with stack_watch state active=%s blocked=%s name=%s pid=0x%016llX\r\n",
                  thread->stack_watch_active ? "true" : "false",
                  thread->stack_watch_blocked ? "true" : "false",
                  thread->name[0] ? thread->name : "<unnamed>",
                  (unsigned long long)(thread->process ? thread->process->pid : 0));
        thread_stack_watch_deactivate(thread);
        thread_unfreeze_after_stack_watch(thread);
    }
#endif
    if (thread->waiting_queue || thread->sleeping)
    {
        SCHED_LOG("[sched] warning: freeing thread still linked waiting_queue=%s sleeping=%s name=%s pid=0x%016llX\r\n",
                  thread->waiting_queue ? "true" : "false",
                  thread->sleeping ? "true" : "false",
                  thread->name[0] ? thread->name : "<unnamed>",
                  (unsigned long long)(thread->process ? thread->process->pid : 0));
        thread_remove_from_wait_queue(thread);
        if (thread->sleeping)
        {
            sleep_queue_remove(thread);
            thread->sleeping = false;
        }
    }
    const char *name = thread->name[0] ? thread->name : "<unnamed>";
    uint64_t pid = thread->process ? thread->process->pid : 0;
    uintptr_t ctx_ptr = (uintptr_t)thread->context;
    uintptr_t stack_base = (uintptr_t)thread->stack_base;
    uintptr_t stack_top = thread->kernel_stack_top;
    SCHED_LOG("[sched] thread_free_resources name=%s pid=0x%016llX context=0x%016llX stack=[0x%016llX,0x%016llX)\r\n",
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
    __atomic_store_n(&thread->lifetime_state, THREAD_LIFETIME_FREED, __ATOMIC_RELEASE);
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
    __atomic_store_n(&thread->lifetime_state, THREAD_LIFETIME_DEFERRED, __ATOMIC_RELEASE);
    uint32_t owner = thread->last_cpu_index;
    if (owner >= SMP_MAX_CPUS)
    {
        owner = 0;
    }
    uint64_t flags = cpu_save_flags();
    cpu_cli();
    spinlock_lock(&g_deferred_free_locks[owner]);
    thread->deferred_next = g_deferred_thread_frees[owner];
    g_deferred_thread_frees[owner] = thread;
    spinlock_unlock(&g_deferred_free_locks[owner]);
    cpu_restore_flags(flags);
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
        thread_lifetime_state_t lifetime = __atomic_load_n(&cursor->lifetime_state, __ATOMIC_ACQUIRE);
        if (lifetime == THREAD_LIFETIME_FREED)
        {
            cursor = next;
            continue;
        }
        uint32_t running_cpu = __atomic_load_n(&cursor->running_cpu, __ATOMIC_ACQUIRE);
        if (running_cpu != RUN_QUEUE_CPU_INVALID)
        {
            in_use = true;
        }
        /* Avoid freeing anything still running or referenced as current. */
        for (uint32_t i = 0; i < SMP_MAX_CPUS && !in_use; ++i)
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
        if (cursor->state != THREAD_STATE_ZOMBIE || thread_in_run_queue_load(cursor) || cursor->sleeping ||
            cursor->waiting_queue || cursor->in_transition)
        {
            in_use = true;
        }
        if (cursor->stack_watch_blocked || cursor->stack_watch_active)
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
        (void)ms;
        (void)DEFERRED_FREE_WARN_MS;
        // serial_printf("[sched] deferred_free cpu=%u grabbed=0x%016llX freed=0x%016llX requeued=0x%016llX duration=%llu ms%s\r\n",
        //               local_stats.cpu_index,
        //               (unsigned long long)local_stats.grabbed,
        //               (unsigned long long)local_stats.freed,
        //               (unsigned long long)local_stats.requeued,
        //               (unsigned long long)ms,
        //               (ms >= DEFERRED_FREE_WARN_MS) ? " (slow)" : "");
    }

    return did_work;
}

static bool thread_context_in_bounds(thread_t *thread,
                                     const char *reason)
{
    if (!thread || !thread_lifetime_active(thread))
    {
        return true;
    }
    if (thread_running_on_any_cpu(thread))
    {
        return true;
    }

    bool ok = true;
    spinlock_lock(&thread->context_lock);
    if (!thread->context_valid || !thread->context || !thread->stack_base)
    {
        ok = true;
    }
    else
    {
        uintptr_t ctx = (uintptr_t)thread->context;
        uintptr_t lower = (uintptr_t)thread->stack_base;
        uintptr_t upper = thread->kernel_stack_top;
        if (lower != 0 && upper > lower)
        {
            if (!(ctx >= lower && ctx < upper))
            {
                ok = false;
                SCHED_LOG("[sched] context pointer out of bounds %s thread=%s pid=0x%016llX ctx=0x%016llX stack=[0x%016llX,0x%016llX)\r\n",
                          reason ? reason : "<none>",
                          thread->name[0] ? thread->name : "<unnamed>",
                          (unsigned long long)(thread->process ? thread->process->pid : 0),
                          (unsigned long long)ctx,
                          (unsigned long long)lower,
                          (unsigned long long)upper);
            }
        }
    }
    spinlock_unlock(&thread->context_lock);
    return ok;
}

static void thread_check_context_bounds(const thread_t *thread,
                                        const char *label)
{
#if ENABLE_CONTEXT_GUARD
    if (!thread || !thread_lifetime_active(thread))
    {
        return;
    }
    if (thread_running_on_any_cpu(thread))
    {
        return;
    }
    if (!thread->context || !thread->stack_base || !thread->context_valid)
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

    SCHED_LOG("[sched] context ptr out of range label=%s thread=%s pid=0x%016llX ptr=0x%016llX stack_base=0x%016llX stack_top=0x%016llX\r\n",
              label ? label : "<none>",
              thread->name[0] ? thread->name : "<unnamed>",
              (unsigned long long)(thread->process ? thread->process->pid : 0),
              (unsigned long long)(ctx),
              (unsigned long long)(lower),
              (unsigned long long)(upper));

#if ENABLE_STACK_WRITE_DEBUG
    thread_t *owner = thread_find_stack_owner(ctx, 0);
    if (owner)
    {
        SCHED_LOG("  ctx points into stack owned by thread=%s pid=0x%016llX\r\n",
                  owner->name[0] ? owner->name : "<unnamed>",
                  (unsigned long long)(owner->process ? owner->process->pid : 0));
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
    const char *name = (thread && thread->name[0]) ? thread->name : "<unnamed>";
    serial_printf("[proc] stack issue thread=%s ctx=%s reason=%s stack_base=0x%016llX stack_top=0x%016llX rsp=0x%016llX\r\n",
                  name,
                  context ? context : "<none>",
                  reason ? reason : "<unknown>",
                  (unsigned long long)((uintptr_t)(thread ? thread->stack_base : 0)),
                  (unsigned long long)(thread ? thread->kernel_stack_top : 0),
                  (unsigned long long)rsp);
}

static void thread_assert_stack_current(thread_t *thread, const char *context)
{
    if (!thread)
    {
        return;
    }
    if (thread->is_idle)
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

static void thread_assert_current_stack_owner(const char *context)
{
    thread_t *current = current_thread_local();
    if (!current)
    {
        return;
    }

    uint64_t rsp = 0;
    __asm__ volatile ("mov %%rsp, %0" : "=r"(rsp));
    if (thread_stack_range_contains(current, rsp, 1))
    {
        return;
    }

    thread_t *owner = thread_find_stack_owner(rsp, 1);
    SCHED_LOG("[sched] fatal: stack owner mismatch ctx=%s current=%s pid=0x%016llX rsp=0x%016llX stack=[0x%016llX,0x%016llX) owner=%s owner_pid=0x%016llX\r\n",
              context ? context : "<none>",
              current->name[0] ? current->name : "<unnamed>",
              (unsigned long long)(current->process ? current->process->pid : 0),
              (unsigned long long)rsp,
              (unsigned long long)((uintptr_t)current->stack_base),
              (unsigned long long)current->kernel_stack_top,
              (owner && owner->name[0]) ? owner->name : (owner ? "<unnamed>" : "<none>"),
              (unsigned long long)(owner && owner->process ? owner->process->pid : 0));
    fatal("current stack owner mismatch");
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
    SCHED_LOG("[sched] stack snapshot label=%s thread=%s pid=0x%016llX entries=0x%016llX ctx=0x%016llX\r\n",
              label ? label : "<none>",
              thread->name[0] ? thread->name : "<unnamed>",
              (unsigned long long)(thread->process ? thread->process->pid : 0),
              (unsigned long long)(dump_qwords),
              (unsigned long long)(ctx_ptr));
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

    if (!thread_lifetime_active(thread))
    {
        return;
    }
    if (thread_running_on_any_cpu(thread))
    {
        return;
    }

    uint64_t ctx_copy[CTX_WORD_COUNT] = { 0 };
    uintptr_t ctx_ptr = 0;
    uintptr_t lower = 0;
    uintptr_t upper = 0;
    bool context_ok = true;

    spinlock_lock(&thread->context_lock);
    if (!thread->context_valid || !thread->context || !thread->stack_base)
    {
        context_ok = false;
    }
    else
    {
        ctx_ptr = (uintptr_t)thread->context;
        lower = (uintptr_t)thread->stack_base;
        upper = thread->kernel_stack_top;
        if (!pointer_is_canonical(ctx_ptr) || lower == 0 || upper <= lower ||
            ctx_ptr < lower || ctx_ptr >= upper)
        {
            context_ok = false;
        }
        else
        {
            size_t available = (size_t)((upper - ctx_ptr) / sizeof(uint64_t));
            if (available < CTX_WORD_COUNT)
            {
                context_ok = false;
            }
            else
            {
                memcpy(ctx_copy, (const uint64_t *)ctx_ptr, sizeof(ctx_copy));
            }
        }
    }
    spinlock_unlock(&thread->context_lock);

    if (!context_ok)
    {
        return;
    }

    uint64_t resume_rip = ctx_copy[CTX_RET];
    bool resume_zero = (resume_rip == 0);
    bool resume_boot = (resume_rip >= SMP_BOOT_DATA_PHYS &&
                        resume_rip < SMP_BOOT_DATA_PHYS + 0x1000);
    if (!resume_zero && !resume_boot)
    {
        return;
    }

    process_t *proc = thread->process;
    SCHED_LOG("[sched] resume rip anomaly label=%s reason=%s cpu=%016llX thread=%s pid=0x%016llX resume_rip=0x%016llX ctx=0x%016llX stack_base=0x%016llX stack_top=0x%016llX\r\n",
              label ? label : "<none>",
              resume_zero ? "zero" : "smp_boot",
              (unsigned long long)(current_cpu_index()),
              thread->name[0] ? thread->name : "<unnamed>",
              (unsigned long long)(proc ? proc->pid : 0),
              (unsigned long long)(resume_rip),
              (unsigned long long)((uintptr_t)thread->context),
              (unsigned long long)((uintptr_t)thread->stack_base),
              (unsigned long long)(thread->kernel_stack_top));

    const uint64_t *stack_dump = ctx_copy + (CTX_WORD_COUNT - 1);
    size_t dump_qwords = 16;
    uintptr_t dump_start = (uintptr_t)stack_dump;
    size_t max_qwords = 0;
    if (dump_start >= lower && dump_start < upper)
    {
        max_qwords = (size_t)((upper - dump_start) / sizeof(uint64_t));
    }
    if (dump_qwords > max_qwords)
    {
        dump_qwords = max_qwords;
    }
    if (dump_qwords > 0)
    {
        scheduler_debug_dump_stack(stack_dump, dump_qwords);
    }

    fatal("scheduler detected context rip inside SMP bootstrap page");
}

static void thread_scan_stack_for_suspicious_values(thread_t *thread,
                                                    uintptr_t rsp,
                                                    bool full_stack,
                                                    const char *context)
{
#if ENABLE_SMP_BOOT_STACK_SCAN
    if (!thread ||
        !thread_lifetime_active(thread) ||
        thread_running_elsewhere(thread) ||
        (thread->state == THREAD_STATE_RUNNING && thread != current_thread_local()) ||
        !thread->stack_base ||
        !thread->stack_allocation_raw ||
        thread->is_idle ||
        thread->pending_destroy ||
        thread->state == THREAD_STATE_ZOMBIE)
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

static size_t thread_context_guard_collect_locked(const thread_t *thread,
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
    if (!thread_lifetime_active(thread))
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
    if (!sched_log_enabled())
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
    SCHED_LOG("[sched] context_guard window thread=%s pid=0x%016llX focus=0x%016llX range=[0x%016llX,0x%016llX)\r\n",
              thread->name[0] ? thread->name : "<unnamed>",
              (unsigned long long)(thread->process ? thread->process->pid : 0),
              (unsigned long long)(focus_addr),
              (unsigned long long)(start),
              (unsigned long long)(end));
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
    size_t available = thread_context_guard_collect_locked(thread, &words);
    if (available == 0 || !words)
    {
        return 0;
    }
    size_t count = available;
    if (count > CONTEXT_SWITCH_SAVED_WORDS)
    {
        count = CONTEXT_SWITCH_SAVED_WORDS;
    }
    if (count > CONTEXT_GUARD_WORDS)
    {
        count = CONTEXT_GUARD_WORDS;
    }
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
        SCHED_LOG("%s", "[sched] warning: failed to unprotect stack guard region\r\n");
    }
    thread->context_guard_protected = false;
    thread->context_guard_protect_base = 0;
    thread->context_guard_protect_len = 0;
#else
    (void)thread;
#endif
}

static void __attribute__((unused)) thread_context_guard_protect_pages(thread_t *thread)
{
#if ENABLE_CONTEXT_GUARD
    if (!thread || thread->context_guard_protected || !thread->context_guard_enabled)
    {
        return;
    }
    /* Do not attempt to protect the stack while it is actively in use. */
    if (thread == current_thread_local())
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
        SCHED_LOG("%s", "[sched] warning: failed to protect stack guard region\r\n");
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
    if (!thread || !thread_lifetime_active(thread))
    {
        return;
    }
    thread_t *current = current_thread_local();
    if (current && current != thread)
    {
        SCHED_LOG("[sched] context_guard_update skipped wrong_thread target=%s pid=0x%016llX current=%s current_pid=0x%016llX label=%s\r\n",
                  thread->name[0] ? thread->name : "<unnamed>",
                  (unsigned long long)(thread->process ? thread->process->pid : 0),
                  current->name[0] ? current->name : "<unnamed>",
                  (unsigned long long)(current->process ? current->process->pid : 0),
                  label ? label : "<none>");
        return;
    }
    uint64_t rsp_now = 0;
    __asm__ volatile ("mov %%rsp, %0" : "=r"(rsp_now));
    thread_t *rsp_owner = thread_find_stack_owner(rsp_now, 1);
    if (rsp_owner && rsp_owner != thread)
    {
        SCHED_LOG("[sched] context_guard_update skipped wrong_stack thread=%s pid=0x%016llX rsp=0x%016llX owner=%s owner_pid=0x%016llX label=%s\r\n",
                  thread->name[0] ? thread->name : "<unnamed>",
                  (unsigned long long)(thread->process ? thread->process->pid : 0),
                  (unsigned long long)rsp_now,
                  rsp_owner->name[0] ? rsp_owner->name : "<unnamed>",
                  (unsigned long long)(rsp_owner->process ? rsp_owner->process->pid : 0),
                  label ? label : "<none>");
        return;
    }
    if (thread_running_on_any_cpu(thread))
    {
        return;
    }

    spinlock_lock(&thread->context_lock);

    if (thread_running_on_any_cpu(thread))
    {
        spinlock_unlock(&thread->context_lock);
        return;
    }
    if (!thread->context_guard_enabled)
    {
        spinlock_unlock(&thread->context_lock);
        return;
    }
    if (!thread->context_valid)
    {
        spinlock_unlock(&thread->context_lock);
        return;
    }
    thread_check_context_bounds(thread, label);
    if (!thread || !thread->context)
    {
        spinlock_unlock(&thread->context_lock);
        return;
    }
    const uint64_t *words = NULL;
    size_t available = thread_context_guard_collect_locked(thread, &words);
    if (available == 0 || !words)
    {
        thread->context_guard_hash = 0;
        thread->context_guard_ptr = 0;
        thread->context_guard_count = 0;
        memset(thread->context_guard_words, 0, sizeof(thread->context_guard_words));
        spinlock_unlock(&thread->context_lock);
        return;
    }
    size_t copy_words = available;
    if (copy_words > CONTEXT_SWITCH_SAVED_WORDS)
    {
        copy_words = CONTEXT_SWITCH_SAVED_WORDS;
    }
    if (copy_words > CONTEXT_GUARD_WORDS)
    {
        copy_words = CONTEXT_GUARD_WORDS;
    }
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
    spinlock_unlock(&thread->context_lock);
#else
    (void)thread;
    (void)label;
#endif
}

static void __attribute__((unused)) thread_context_guard_verify(thread_t *thread, const char *label)
{
#if ENABLE_CONTEXT_GUARD
    if (!thread || !thread->context_valid || !thread_lifetime_active(thread))
    {
        return;
    }
    if (thread->state == THREAD_STATE_RUNNING && thread != current_thread_local())
    {
        return;
    }
    if (thread_running_elsewhere(thread))
    {
        return;
    }
    spinlock_lock(&thread->context_lock);
    if (thread_running_on_any_cpu(thread))
    {
        spinlock_unlock(&thread->context_lock);
        return;
    }
    if (!thread->context_valid || !thread->context_guard_enabled)
    {
        spinlock_unlock(&thread->context_lock);
        return;
    }
    thread_check_context_bounds(thread, label);
    if (!thread || !thread->context_guard_hash || !thread->context)
    {
        spinlock_unlock(&thread->context_lock);
        return;
    }
    if (thread->context_guard_ptr != (uintptr_t)thread->context)
    {
        spinlock_unlock(&thread->context_lock);
        thread_context_guard_update(thread, "context_guard_resync");
        return;
    }
    const uint64_t *current_words = NULL;
    size_t available = thread_context_guard_collect_locked(thread, &current_words);
    if (available == 0 || !current_words)
    {
        spinlock_unlock(&thread->context_lock);
        return;
    }
    size_t compare_words = thread->context_guard_count;
    if (compare_words > CONTEXT_GUARD_WORDS)
    {
        compare_words = CONTEXT_GUARD_WORDS;
    }
    if (compare_words > CONTEXT_SWITCH_SAVED_WORDS)
    {
        compare_words = CONTEXT_SWITCH_SAVED_WORDS;
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
        spinlock_unlock(&thread->context_lock);
        return;
    }
    bool log_guard = sched_log_enabled();
    /* If the saved context pointer is unchanged and the thread is not running,
     * a mismatch likely means the context was legitimately updated (e.g., during
     * a switch-out) after the last guard snapshot. Resync once instead of
     * treating it as corruption. */
    if (thread->context_guard_ptr == (uintptr_t)thread->context &&
        thread->state != THREAD_STATE_RUNNING &&
        thread->context_valid)
    {
        if (log_guard)
        {
            SCHED_LOG("[sched] context guard mismatch (resync) label=%s thread=%s pid=0x%016llX saved_hash=0x%016llX current_hash=0x%016llX\r\n",
                      label ? label : "<none>",
                      thread->name[0] ? thread->name : "<unnamed>",
                      (unsigned long long)(thread->process ? thread->process->pid : 0),
                      (unsigned long long)(thread->context_guard_hash),
                      (unsigned long long)(current_hash));
        }
        spinlock_unlock(&thread->context_lock);
        thread_context_guard_update(thread, "context_guard_resync_soft");
        return;
    }
#if !CONTEXT_GUARD_STRICT
    if (log_guard)
    {
        SCHED_LOG("[sched] context guard mismatch (resync) label=%s thread=%s pid=0x%016llX saved_ptr=0x%016llX current_ptr=0x%016llX saved_hash=0x%016llX current_hash=0x%016llX\r\n",
                  label ? label : "<none>",
                  thread->name[0] ? thread->name : "<unnamed>",
                  (unsigned long long)(thread->process ? thread->process->pid : 0),
                  (unsigned long long)(thread->context_guard_ptr),
                  (unsigned long long)((uintptr_t)thread->context),
                  (unsigned long long)(thread->context_guard_hash),
                  (unsigned long long)(current_hash));
    }
    spinlock_unlock(&thread->context_lock);
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
    if (log_guard)
    {
        SCHED_LOG("[sched] context guard mismatch label=%s thread=%s pid=0x%016llX saved_ptr=0x%016llX current_ptr=0x%016llX saved_hash=0x%016llX current_hash=0x%016llX\r\n",
                  label ? label : "<none>",
                  thread->name[0] ? thread->name : "<unnamed>",
                  (unsigned long long)(thread->process ? thread->process->pid : 0),
                  (unsigned long long)(thread->context_guard_ptr),
                  (unsigned long long)((uintptr_t)thread->context),
                  (unsigned long long)(thread->context_guard_hash),
                  (unsigned long long)(current_hash));
    }
    uintptr_t diff_addr = 0;
    if (diff_index != (size_t)-1)
    {
        diff_addr = thread->context_guard_ptr + diff_index * sizeof(uint64_t);
        if (log_guard)
        {
            SCHED_LOG("[sched] context guard diff diff_index=0x%016llX addr=0x%016llX saved=0x%016llX current=0x%016llX\r\n",
                      (unsigned long long)(diff_index),
                      (unsigned long long)(diff_addr),
                      (unsigned long long)(thread->context_guard_words[diff_index]),
                      (unsigned long long)(current_words[diff_index]));
        }
    }
    const char *reg_name = "<unknown>";
    if (diff_index != (size_t)-1 &&
        diff_index < STATIC_ARRAY_SIZE(g_context_guard_reg_names))
    {
        reg_name = g_context_guard_reg_names[diff_index];
    }
    if (log_guard)
    {
        serial_printf("%s", "  register=");
        serial_printf("%s", reg_name);
        serial_printf("%s", "\r\n");
    }
    if (diff_addr)
    {
        context_guard_dump_window(thread, diff_addr, 4, 4);
    }
    scheduler_debug_dump_thread_stack(thread, label);
    thread_scan_stack_for_suspicious_values(thread,
                                            (uintptr_t)thread->context,
                                            true,
                                            "context_guard");
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
                                                 uint8_t *,
                                                 uint32_t *)
{
    __asm__ volatile (
        "pushfq\n\t"
        "push %%rbp\n\t"
        "push %%rbx\n\t"
        "push %%r12\n\t"
        "push %%r13\n\t"
        "push %%r14\n\t"
        "push %%r15\n\t"
        /* Ensure reserved bit stays set in saved RFLAGS. */
        "orl $0x2, 48(%%rsp)\n\t"
        "mov %%rsp, (%%rdi)\n\t"
        "mov %%rsi, %%rsp\n\t"
        "test %%rdx, %%rdx\n\t"
        "jz 1f\n\t"
        "movb $0, (%%rdx)\n\t"
        "1:\n\t"
        "test %%rcx, %%rcx\n\t"
        "jz 2f\n\t"
        "movl $0xFFFFFFFF, (%%rcx)\n\t"
        "2:\n\t"
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
