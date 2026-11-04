#ifndef PROCESS_INTERNAL_H
#define PROCESS_INTERNAL_H

#include "process.h"
#include "process_signal.h"

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
#include "io_request.h"
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

#define MSR_FS_BASE         0xC0000100
#define MSR_GS_BASE         0xC0000101
#define RFLAGS_RESERVED_BIT (1ULL << 1)
#define RFLAGS_IF_BIT       (1ULL << 9)
#define RFLAGS_DEFAULT      (RFLAGS_RESERVED_BIT | RFLAGS_IF_BIT)

#define PROCESS_STACK_GUARD_SIZE         (4096UL)
#define STACK_GUARD_PATTERN              0x5A
#ifndef ENABLE_SMP_BOOT_STACK_SCAN
/* Optional bootstrap-pointer diagnostics; scheduling keeps its bounds,
 * canary, saved-context and stack-owner checks without scanning every word. */
#define ENABLE_SMP_BOOT_STACK_SCAN         0
#endif
#define SMP_BOOT_STACK_SCAN_MAX_QWORDS     8192ULL
#define STACK_SCAN_DUMP_CONTEXT_QWORDS     16ULL
#ifndef ENABLE_SCHEDULER_STACK_DUMP
#define ENABLE_SCHEDULER_STACK_DUMP      0
#endif
#define SCHEDULER_STACK_DUMP_QWORDS      32ULL
#ifndef ENABLE_CONTEXT_GUARD
#define ENABLE_CONTEXT_GUARD             1
#endif
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
#define THREAD_CREATE_DEBUG              0
#endif
#ifndef ENABLE_RUN_QUEUE_DEBUG
#define ENABLE_RUN_QUEUE_DEBUG 1
#endif
#ifndef ENABLE_SHELL_TRACE
#define ENABLE_SHELL_TRACE 0
#endif
#define SCHED_SWITCH_WARN_MS 500ULL

#define THREAD_CONTEXT_REDZONE_BYTES (64ULL * 1024ULL)
#define PROCESS_TIME_SLICE_DEFAULT_MS    20U
#define PROCESS_TIME_SLICE_DEFAULT_TICKS 2U
#define THREAD_MAGIC 0x54485244u /* 'THRD' */
#define PROCESS_MAGIC 0x50524353u /* 'PRCS' */
#define STACK_OWNER_BUCKET_SHIFT 15
#define STACK_OWNER_BUCKET_SIZE (1UL << STACK_OWNER_BUCKET_SHIFT)
#define STACK_OWNER_BUCKET_COUNT 256u
#define STACK_OWNER_BUCKET_MASK (STACK_OWNER_BUCKET_COUNT - 1)

typedef uint64_t cpu_context_t;

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
#define CONTEXT_GUARD_WORDS       CONTEXT_SWITCH_SAVED_WORDS

#define PAGE_SIZE_BYTES_LOCAL     4096ULL
#define USER_ADDRESS_SPACE_BASE   (g_mem_layout.user_pointer_base)
#define USER_ADDRESS_SPACE_LIMIT  (g_mem_layout.user_pointer_limit)
#define USER_STACK_TOP            (g_mem_layout.user_stack_top)
#define USER_STACK_SIZE           (g_mem_layout.user_stack_size)
#define USER_HEAP_BASE            (g_mem_layout.user_heap_base)
#define USER_HEAP_SIZE            (g_mem_layout.user_heap_size)
#define USER_STUB_REGION_TOP      ((USER_ADDRESS_SPACE_LIMIT + 1ULL) & ~(PAGE_SIZE_BYTES_LOCAL - 1ULL))
#define USER_STUB_CODE_BASE       (USER_STUB_REGION_TOP - (2ULL * PAGE_SIZE_BYTES_LOCAL))
#define USER_PREEMPT_STUB_BASE    (USER_STUB_CODE_BASE + PAGE_SIZE_BYTES_LOCAL)
#define PROCESS_HEAP_L2_SHIFT     9ULL
#define PROCESS_HEAP_L2_ENTRIES   (1ULL << PROCESS_HEAP_L2_SHIFT)
#define PROCESS_HEAP_L2_MASK      (PROCESS_HEAP_L2_ENTRIES - 1ULL)
#define PROCESS_HEAP_PRESENT_WORDS ((PROCESS_HEAP_L2_ENTRIES + 63ULL) / 64ULL)
#define PROCESS_HEAP_L2_SPAN      (PROCESS_HEAP_L2_ENTRIES * PAGE_SIZE_BYTES_LOCAL)

typedef struct
{
    uint64_t preempt_resume_rip;
} thread_tls_t;

typedef struct
{
    uint8_t bytes[512];
} __attribute__((aligned(64))) fpu_state_t;

typedef struct process_user_region
{
    paddr_t phys_base;
    size_t mapped_size;
    uintptr_t user_base;
    bool writable;
    bool executable;
    struct process_retired_memory *retirement;
    struct process_user_region *next;
} process_user_region_t;

typedef struct user_thread_bootstrap
{
    uintptr_t entry;
    uintptr_t stack_top;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rdx;
} user_thread_bootstrap_t;

typedef enum
{
    THREAD_LIFETIME_ALIVE = 0,
    THREAD_LIFETIME_DEFERRED,
    THREAD_LIFETIME_FREED
} thread_lifetime_state_t;

typedef enum
{
    PROCESS_LIFETIME_ALIVE = 0,
    PROCESS_LIFETIME_DESTROYING,
    PROCESS_LIFETIME_FREED
} process_lifetime_state_t;

typedef struct process_heap_l2
{
    paddr_t phys[PROCESS_HEAP_L2_ENTRIES];
    uint64_t present[PROCESS_HEAP_PRESENT_WORDS];
} process_heap_l2_t;

typedef struct stack_owner_entry stack_owner_entry_t;

struct stack_owner_entry
{
    struct stack_owner_entry *bucket_next;
    struct stack_owner_entry *thread_next;
    thread_t *thread;
    uintptr_t base;
    uintptr_t top;
    uint32_t bucket_index;
};

typedef struct deferred_free_stats
{
    uint32_t cpu_index;
    size_t grabbed;
    size_t freed;
    size_t requeued;
    uint64_t duration_ticks;
} deferred_free_stats_t;

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
    thread_t *process_next;
    uint64_t tid;
    uint64_t owner_pid;
    wait_queue_t join_queue;
    uint32_t join_claimed;
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
    uint32_t preempt_disable_depth;
    uint64_t runtime_ticks;
    thread_priority_t base_priority;
    thread_priority_t priority;
    thread_priority_t priority_override;
    bool priority_override_active;
    bool affinity_enabled;
    uint32_t affinity_cpu;
    int exit_status;
    bool in_run_queue;
    bool is_idle;
    bool exited;
    bool in_transition;
    bool preempt_pending;
    bool fpu_initialized;
    wait_queue_t *waiting_queue;
    /* Scheduler-protected WAITER ownership; detached only after off-CPU quiescence. */
    io_request_t *io_request;
    bool io_interruptible;
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
    bool counted_running;
    uintptr_t user_stack_base;
    size_t user_stack_size;
    uintptr_t user_tls_base;
    size_t user_tls_size;
    bool detached;
    bool user_cleanup_complete;
    uint64_t context_guard_hash;
    uintptr_t context_guard_ptr;
    uint64_t context_guard_generation;
    uint64_t context_guard_words[CONTEXT_GUARD_WORDS];
    size_t context_guard_count;
    uint64_t last_scheduled_tick;
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
    /* Process-private user waits live with the heap-owned thread, never on a
     * syscall stack. Scheduler locking protects registration and notification. */
    wait_queue_t futex_queue;
    uintptr_t futex_address;
    bool futex_waiting;
    bool futex_notified;
    bool futex_interrupted;
    alix_sigset_t signal_mask,signal_pending;
    alix_siginfo_t signal_info[ALIX_SIGNAL_COUNT];
    alix_stack_t signal_altstack;
    struct process_signal_frame *signal_frames;
    uint64_t signal_sequence;
    uint64_t signal_jump_epoch;
    uint32_t signal_depth;
    int signal_fault_number;
    bool signal_onstack,signal_sleeping,signal_sleep_interrupted;
    wait_queue_t signal_wait_queue;
    alix_sigset_t sigwait_mask;
    bool sigwait_active;
    wait_queue_t sigwait_queue;
    fd_description_t *vm_file_prepare; /* Caller-independent ownership until VM publication. */
};

struct process
{
    uint64_t pid;
    uint64_t started_monotonic_ticks; /* Immutable creation timestamp. */
    /* Absolute path snapshot before publication; empty for anonymous images.
     * Storage shares the process lifetime, never a launcher or user stack. */
    char executable_path[SYSCALL_EXECUTABLE_PATH_MAX];
    process_state_t state;
    process_lifetime_state_t lifetime_state;
    char name[PROCESS_NAME_MAX];
    uint64_t cr3;
    paging_space_t address_space;
    thread_t *main_thread;
    thread_t *current_thread;
    spinlock_t threads_lock;
    spinlock_t memory_lock;
    spinlock_t context_lock;
    thread_t *threads;
    uint32_t thread_count;
    uint32_t running_thread_count;
    uint32_t join_waiters;
    uint64_t user_exit_owner_tid;
    alix_sigaction_t signal_actions[ALIX_SIGNAL_COUNT];
    alix_sigset_t signal_pending;
    alix_siginfo_t signal_info[ALIX_SIGNAL_COUNT];
    int exit_status;
    uint32_t wait_status; /* Immutable after first terminal transition; POSIX encoding. */
    fd_table_t *child_processes; /* Private waitable-child descriptions; never user FDs. */
    struct process *next;
    int stdout_fd;
    uint32_t uid;
    uint32_t gid;
    uint32_t creation_mask;
    uint64_t alarm_deadline;
    process_t *alarm_next; /* Scheduler-owned list; removed before termination. */
    uint64_t runtime_ticks;
    bool is_user;
    spinlock_t usage_lock;
    uint64_t usage_user_ticks, usage_system_ticks, usage_minor_faults, usage_major_faults;
    bool kernel_service; /* Immutable after publication; public kill is refused. */
    process_t *parent;
    process_t *first_child;
    process_t *sibling_prev;
    process_t *sibling_next;
    vfs_node_t *cwd; /* Borrowed compatibility view, protected by cwd_owner. */
    fd_description_t *cwd_owner;
    fd_table_t *directory_streams; /* Private opaque handles, separate from legacy FDs. */
    process_user_region_t *user_regions;
    struct process_vm_area *vm_areas;
    struct process_vm_transaction *vm_pending;
    uintptr_t user_entry_point;
    void *user_elf_metadata;
    size_t user_elf_metadata_size;
    uintptr_t user_stack_top;
    size_t user_stack_size;
    uintptr_t user_stack_committed;
    paddr_t *user_stack_pages;
    size_t user_stack_page_count;
    uintptr_t user_thread_stack_next;
    uint8_t *user_tls_image;
    size_t user_tls_filesz;
    size_t user_tls_memsz;
    size_t user_tls_align;
    size_t user_tls_offset;
    uintptr_t user_heap_base;
    uintptr_t user_heap_brk;
    uintptr_t user_heap_limit;
    uintptr_t user_heap_committed;
    process_heap_l2_t **heap_page_dirs;
    size_t heap_dir_count;
    uintptr_t user_initial_stack;
    size_t arg_count;
    char **arg_values;
    char *arg_storage;
    size_t arg_storage_size;
    size_t env_count;
    char **env_values;
    char *env_storage;
    size_t user_argc;
    uintptr_t user_argv_ptr;
    uintptr_t user_envp_ptr;
    wait_queue_t wait_queue;
    thread_priority_t default_priority;
    thread_priority_t default_priority_override;
    bool default_priority_override_active;
    bool default_affinity_enabled;
    uint32_t default_affinity_cpu;
    uint32_t magic;
};

#define RUN_QUEUE_CPU_INVALID 0xFFFFFFFFu
#define RUN_QUEUE_CPU_CLAIMED 0xFFFFFFFEu

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

typedef struct cpu_usage_counters
{
    uint64_t total_ticks;
    uint64_t idle_ticks;
    uint64_t last_tick;
} __attribute__((aligned(64))) cpu_usage_counters_t;

extern const uint8_t g_user_exit_stub[7];
extern const uint8_t g_user_thread_exit_stub[10];
extern const uint8_t g_user_preempt_stub[ALIX_PREEMPT_STUB_SIZE];
extern const uint8_t g_user_signal_restorer[ALIX_SIGNAL_RESTORER_SIZE];
#define USER_EXIT_STUB_SIZE    7u
#define USER_THREAD_EXIT_STUB_SIZE 10u
#define USER_PREEMPT_STUB_SIZE ALIX_PREEMPT_STUB_SIZE
#define USER_THREAD_EXIT_STUB_OFFSET 0x100u

extern process_t *g_process_list;
extern process_t *g_current_processes[SMP_MAX_CPUS];
extern thread_t *g_current_threads[SMP_MAX_CPUS];
extern thread_t *g_switch_out_threads[SMP_MAX_CPUS];
extern uint64_t g_switch_restore_rflags[SMP_MAX_CPUS];
extern thread_t *g_idle_threads[SMP_MAX_CPUS];
extern thread_t *g_deferred_thread_frees[SMP_MAX_CPUS];
extern spinlock_t g_deferred_free_locks[SMP_MAX_CPUS];
extern process_t *g_idle_process;
extern cpu_context_t *g_bootstrap_context;
extern run_queue_t g_run_queues[SMP_MAX_CPUS];
extern cpu_usage_counters_t g_cpu_usage[SMP_MAX_CPUS];
extern uint64_t g_cpu_switch_counts[SMP_MAX_CPUS];
extern spinlock_t g_scheduler_lock;
extern thread_t *g_sleep_queue_head;
extern uint64_t g_next_pid;
extern uint64_t g_next_tid;
extern spinlock_t g_sleep_queue_lock;
extern spinlock_t g_process_lock;
extern volatile bool g_scheduler_boot_ready;
extern int g_console_stdout_fd;
extern uint32_t g_time_slice_ticks;
extern thread_t *g_stack_watch_frozen_head;
extern thread_t *g_thread_registry_head;
extern spinlock_t g_thread_registry_lock;
extern fpu_state_t g_fpu_initial_state;
extern uint64_t g_scheduler_switch_count;
extern const fd_ops_t console_stdout_ops;
extern uint32_t g_sched_priority_enable;
extern uint32_t g_sched_steal_enable;
extern uint32_t g_sched_default_priority;
extern uintptr_t kernel_heap_base;
extern uintptr_t kernel_heap_end;

#if ENABLE_STACK_WRITE_DEBUG
extern bool g_stack_write_debug_enabled;
extern stack_owner_entry_t *g_stack_owner_buckets[STACK_OWNER_BUCKET_COUNT];
extern spinlock_t g_stack_owner_locks[STACK_OWNER_BUCKET_COUNT];
extern bool g_stack_owner_ready;
#endif

static inline bool string_name_equals(const char *lhs, const char *rhs)
{
    if (!lhs || !rhs)
    {
        return false;
    }
    return strncmp(lhs, rhs, PROCESS_NAME_MAX) == 0;
}

static inline void process_create_log(const char *name, const char *event)
{
    if (!ENABLE_SHELL_TRACE || !sched_log_enabled())
    {
        return;
    }

    SCHED_LOG("[proc-trace] process_create %s name=%s\r\n",
              event ? event : "<none>",
              name ? name : "<none>");
}

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

static inline uint32_t current_cpu_index(void)
{
    uint32_t idx = smp_current_cpu_index();
    if (idx >= SMP_MAX_CPUS)
    {
        idx = 0;
    }
    return idx;
}

static inline uint32_t scheduler_time_slice_ticks(void)
{
    uint32_t ticks = __atomic_load_n(&g_time_slice_ticks, __ATOMIC_RELAXED);
    if (ticks == 0)
    {
        ticks = PROCESS_TIME_SLICE_DEFAULT_TICKS;
    }
    return ticks;
}

static inline uint32_t scheduler_thread_time_slice_ticks(const thread_t *thread)
{
    uint32_t ticks = scheduler_time_slice_ticks();
    /* Input pollers, the compositor, and focused UI share the reserved UI CPU.
     * A 100 ms normal quantum lets one UI peer hide entire short key/mouse
     * presses from another. Bound interactive peers to one 10 ms timer tick. */
    return thread && thread->priority == THREAD_PRIORITY_UI && ticks > 1 ? 1 : ticks;
}

static inline uint64_t cpu_save_flags(void)
{
    uint64_t flags;
    __asm__ volatile ("pushfq; pop %0" : "=r"(flags) :: "memory");
    return flags;
}

static inline void cpu_restore_flags(uint64_t flags)
{
    __asm__ volatile ("push %0; popfq" :: "r"(flags) : "cc", "memory");
}

static inline void cpu_cli(void)
{
    __asm__ volatile ("cli" ::: "memory");
}

static inline bool scheduler_priority_enabled(void)
{
    return __atomic_load_n(&g_sched_priority_enable, __ATOMIC_RELAXED) != 0;
}

static inline thread_priority_t scheduler_default_priority(void)
{
    uint32_t value = __atomic_load_n(&g_sched_default_priority, __ATOMIC_RELAXED);
    if (value >= THREAD_PRIORITY_COUNT)
    {
        value = THREAD_PRIORITY_NORMAL;
    }
    return (thread_priority_t)value;
}

static inline thread_t *current_thread_local(void)
{
    /* CPU-index lookup and its slot access form one local snapshot. A timer
     * migration between them would otherwise read another thread's slot. */
    uint64_t flags = cpu_save_flags();
    cpu_cli();
    uint32_t idx = smp_current_cpu_index();
    thread_t *thread = idx < SMP_MAX_CPUS ? __atomic_load_n(&g_current_threads[idx], __ATOMIC_ACQUIRE) : NULL;
    cpu_restore_flags(flags);
    return thread;
}

static inline process_t *current_process_local(void)
{
    uint64_t flags = cpu_save_flags();
    cpu_cli();
    uint32_t idx = smp_current_cpu_index();
    process_t *process = idx < SMP_MAX_CPUS ? __atomic_load_n(&g_current_processes[idx], __ATOMIC_ACQUIRE) : NULL;
    cpu_restore_flags(flags);
    return process;
}

static inline void set_current_thread_local(thread_t *thread)
{
    uint64_t flags = cpu_save_flags();
    cpu_cli();
    uint32_t idx = smp_current_cpu_index();
    if (idx < SMP_MAX_CPUS) __atomic_store_n(&g_current_threads[idx], thread, __ATOMIC_RELEASE);
    cpu_restore_flags(flags);
}

static inline void set_current_process_local(process_t *process)
{
    uint64_t flags = cpu_save_flags();
    cpu_cli();
    uint32_t idx = smp_current_cpu_index();
    if (idx < SMP_MAX_CPUS) __atomic_store_n(&g_current_processes[idx], process, __ATOMIC_RELEASE);
    cpu_restore_flags(flags);
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
        return;
    }
    __atomic_store_n(&thread->running_cpu, RUN_QUEUE_CPU_INVALID, __ATOMIC_RELEASE);
}

static inline bool thread_lifetime_active(const thread_t *thread)
{
    if (!thread)
    {
        return false;
    }
    thread_lifetime_state_t state = __atomic_load_n(&((thread_t *)thread)->lifetime_state,
                                                    __ATOMIC_ACQUIRE);
    return state == THREAD_LIFETIME_ALIVE;
}

static inline uint64_t scheduler_lock_acquire(const char *where)
{
    (void)where;
    uint64_t flags = cpu_save_flags();
    cpu_cli();
    /* context_switch releases this lock from assembly after changing stacks,
     * so it must not participate in the C spinlock preemption-depth pairing. */
    spinlock_lock_raw(&g_scheduler_lock);
    return flags;
}

static inline void scheduler_lock_release(uint64_t flags)
{
    spinlock_unlock_raw(&g_scheduler_lock);
    cpu_restore_flags(flags);
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

uint64_t scheduler_ticks_to_ms(uint64_t ticks);
void scheduler_log_if_stalled(const char *label, uint64_t start_ticks);
bool thread_stack_pointer_valid(const thread_t *thread, uint64_t rsp);
bool thread_stack_guard_intact(const thread_t *thread);
void thread_scan_stack_for_suspicious_values(thread_t *thread, uintptr_t rsp, bool full_stack, const char *context);
uint64_t sanitize_gs_base(thread_t *thread);
void fpu_prepare_initial_state(void);
void fpu_save_state(fpu_state_t *state);
void fpu_restore_state(const fpu_state_t *state);
void fatal(const char *msg) __attribute__((noreturn));
void context_switch(cpu_context_t **prev_ctx,
                    cpu_context_t *next_ctx,
                    uint8_t *transition_flag,
                    uint32_t *running_cpu_ptr,
                    uint64_t saved_rflags,
                    spinlock_t *scheduler_lock,
                    uint64_t *restore_rflags_ptr);
void process_handle_stack_guard_fault(void);
void process_handle_fatal_fault(void);

process_t *allocate_process(const char *name, bool is_user);
thread_t *thread_create(process_t *process,
                        const char *name,
                        thread_entry_t entry,
                        void *arg,
                        size_t stack_size,
                        bool is_idle,
                        bool user_mode);
process_t *process_finalize_new_process(process_t *proc,
                                        thread_t *thread,
                                        int stdout_fd,
                                        process_t *parent);
process_t *process_finalize_launched_process(process_t *proc, thread_t *thread, uint64_t parent_pid);
typedef struct
{
    fd_description_t *cwd;
    fd_table_t *files;
    uint32_t uid, gid, creation_mask;
    uint64_t parent_pid;
    const char *const *environment;
    size_t environment_count;
    uint64_t signal_mask, ignored_signals;
    const char *executable_path; /* Protected constructor input, copied before publication. */
} process_launch_context_t;
/* Persistent protected constructor. Context refs transfer into the new child;
 * remaining refs on failure still belong to the caller. The watch owns the
 * child before publication, including an immediately exiting main thread. */
process_t *process_create_user_elf_prepared(const char *name, const uint8_t *image, size_t size,
                                            process_launch_context_t *context,
                                            const char *const *argv, size_t argc,
                                            process_creation_watch_t *watch);
void process_attach_child_pid(uint64_t parent_pid, process_t *child);
bool process_setup_dummy_user_space(process_t *process);
bool process_setup_basic_user_memory(process_t *process);
typedef struct process_tls_allocation
{
    uintptr_t base;
    size_t size;
    uintptr_t thread_pointer;
} process_tls_allocation_t;
bool process_allocate_user_tls(process_t *process, process_tls_allocation_t *out);
void process_clear_user_tls_template(process_t *process);
bool process_store_args(process_t *process,
                        const char *const *argv,
                        size_t argc);
bool process_prepare_stack_with_args(process_t *process);
void process_clear_args(process_t *process);
bool process_store_environment(process_t *process, const char *const *environment, size_t count);
void process_clear_environment(process_t *process);
void process_free_user_regions(process_t *process);
bool process_heap_release_from(process_t *process, uintptr_t virt_start);
void process_reap_retired_memory(void);
bool process_memory_read_user_u32(process_t *process, uintptr_t address, uint32_t *value_out);
bool process_vm_contains_locked(process_t *process, uintptr_t address);
bool process_vm_fault_locked(process_t *process, uintptr_t address, bool write_access, bool execute_access);
bool process_vm_resolve_locked(process_t *process, uintptr_t address, bool write_access,
                               uint8_t **host_out, size_t *available_out);
bool process_vm_range_reserved(uintptr_t address, size_t length);
uintptr_t process_vm_auxiliary_base(void);
void process_vm_destroy(process_t *process);
bool process_allocate_aux_user_segment_locked(process_t *process, size_t bytes,
                                              uintptr_t *base_out, void **host_out);
bool process_complete_user_mapping(process_t *process);
/* Caller holds memory_lock for the complete use of the returned physmap span. */
bool process_memory_resolve_user_locked(process_t *process, uintptr_t address,
                                        bool write_access, uint8_t **host_out,
                                        size_t *available_out);
void process_free_heap_pages(process_t *process);
void sleep_queue_insert(thread_t *thread);
void sleep_queue_remove(thread_t *thread);
void sleep_queue_wake_due(uint64_t now);
void user_thread_entry(void *arg) __attribute__((noreturn));
void scheduler_wait_for_boot_ready(void);
void idle_thread_entry(void *arg) __attribute__((noreturn));
void thread_trampoline(void) __attribute__((noreturn));
void process_attach_child(process_t *parent, process_t *child);
void process_detach_child(process_t *child);
void process_orphan_children(process_t *parent);
process_t *process_retain_first_child(process_t *parent);
void process_release_reference(process_t *process);
bool process_threads_quiescent_locked(process_t *process);
/* Caller must hold g_scheduler_lock. */
void wait_queue_wake_all_locked(wait_queue_t *queue);
/* Preparation/result APIs require a bounded preemption guard, with no other
 * caller-held locks. Register transfers WAITER on success; on failure the
 * preparer still owns it and must enqueue abandonment before dropping guard.
 * Wait requires no preemption guard. Borrowed result pointers remain valid
 * only until finish, within the caller's guard. Workers never borrow them. */
int process_io_register_current(io_request_t *request);
int process_io_wait_current(io_request_status_t *out);
int process_io_wait_current_interruptible(io_request_status_t *out);
int process_io_result_current(io_request_t **request_out, io_request_status_t *out);
int process_io_finish_current(bool abandon);
/* Caller holds scheduler_lock; abandon also requires off-CPU quiescence. */
void process_io_cancel_thread_locked(thread_t *thread);
bool process_io_abandon_thread_locked(thread_t *thread);
void process_io_notify_completion(void);
int process_io_complete_request(io_request_t *request, int64_t result,
                                fd_description_t *result_description_owned);
void thread_remove_from_wait_queue(thread_t *thread);
void remove_from_run_queue(thread_t *thread);
void remove_from_run_queue_locked(thread_t *thread);
void thread_context_guard_release_pages(thread_t *thread);
void thread_enqueue_deferred_free(thread_t *thread);
bool process_try_mark_destroying(process_t *process);
bool process_pointer_valid(const process_t *process);
bool thread_pointer_valid(const thread_t *thread);
bool process_heap_commit_range(process_t *process, uintptr_t start, uintptr_t end);
bool process_heap_zero_range(process_t *process, uintptr_t start, size_t bytes);
bool process_stack_handle_page_fault(process_t *process, uintptr_t fault_addr, uintptr_t rsp);
uint64_t process_memory_lock(process_t *process);
void process_memory_unlock(process_t *process, uint64_t flags);
bool process_unmap_user_segment(process_t *process, uintptr_t user_base, size_t bytes);
bool process_map_user_segment_locked(process_t *process,
                                     uintptr_t user_base,
                                     size_t bytes,
                                     bool writable,
                                     bool executable,
                                     bool allow_reserved,
                                     void **host_ptr_out);
thread_t *thread_find_stack_owner(uintptr_t addr, size_t len);
bool thread_stack_watch_activate(thread_t *thread, const char *context, uintptr_t suspect);
void thread_stack_watch_deactivate(thread_t *thread);
void thread_unfreeze_after_stack_watch(thread_t *thread);
void stack_watch_check_timeouts(void);
void process_trigger_fatal_fault(thread_t *thread,
                                 interrupt_frame_t *frame,
                                 const char *reason,
                                 uint64_t error_code,
                                 bool has_address,
                                 uintptr_t address);
thread_priority_t thread_effective_priority(const thread_t *thread);
bool scheduler_thread_in_any_queue(thread_t *thread);
void cpu_account_tick(thread_t *thread, bool user_mode);
/* Caller owns the process through a running thread or independent reference. */
void process_usage_add_cpu(process_t *process, uint64_t ticks, bool user_mode);
void process_usage_add_fault(process_t *process, bool major);
void thread_trigger_stack_guard(thread_t *thread, interrupt_frame_t *frame, const char *reason);
extern void process_preempt_trampoline(void);
void thread_set_base_priority(thread_t *thread, thread_priority_t priority);
void thread_set_priority_override(thread_t *thread, bool enabled, thread_priority_t priority);
void thread_set_affinity(thread_t *thread, bool enabled, uint32_t cpu_index);
void thread_set_base_priority_locked(thread_t *thread, thread_priority_t priority);
void thread_set_priority_override_locked(thread_t *thread, bool enabled, thread_priority_t priority);
void thread_set_affinity_locked(thread_t *thread, bool enabled, uint32_t cpu_index);
void enqueue_thread(thread_t *thread);
uint32_t scheduler_select_target_cpu(thread_t *thread);
void enqueue_thread_on_cpu_locked(thread_t *thread, uint32_t cpu_index);
void thread_quarantine_corrupt(thread_t *thread, const char *reason);
void stack_owner_register(thread_t *thread);
void stack_owner_unregister(thread_t *thread);
void thread_context_guard_update(thread_t *thread, const char *label);
bool thread_stack_watch_snapshot_changed(thread_t *thread,
                                         uintptr_t *addr_out,
                                         uint8_t *old_out,
                                         uint8_t *new_out);
bool thread_context_in_bounds(thread_t *thread, const char *reason);
bool thread_fpu_region_valid(const thread_t *thread);
bool thread_assert_stack_current(thread_t *thread, const char *context);
/* Caller must hold g_scheduler_lock. */
bool thread_process_deferred_frees_locked(uint32_t cpu_index, deferred_free_stats_t *stats);
/* Ordinary idle context only; skips IRQ-disabled or preempt-guarded calls. */
void process_reap_deferred_threads(void);
void thread_stack_watch_maybe_arm(thread_t *thread);
void thread_registry_add(thread_t *thread);
void procfs_register_process_priority(process_t *process);
void procfs_unregister_process(process_t *process);
void process_destroy_marked(process_t *process);
int64_t process_alarm(unsigned seconds);
void process_alarm_tick(uint64_t ticks);
/* Caller holds scheduler_lock, before the process can become reclaimable. */
void process_alarm_cancel_locked(process_t *process);
void process_exit_signal(int number) __attribute__((noreturn));
bool process_kill_signal(process_t *process, int number);
/* Caller owns a retained process; output is written only after terminal state
 * and actual CPU/queue/transition quiescence are observed together. */
int process_wait_status_snapshot(process_t *process, uint32_t *output);
bool process_prepare_inherited_context(process_t *process, process_t *parent, bool parentless);
bool process_prepare_user_fds(process_t *process, process_t *parent, int stdout_fd);
void process_release_context(process_t *process);
void thread_debug_check_ownership(const thread_t *thread, const char *where);
void scheduler_trace(const char *prefix, thread_t *thread);
void scheduler_log_state_event(const char *tag, const thread_t *thread, const char *where);
void scheduler_shell_log(const char *event, thread_t *thread);
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

#endif /* PROCESS_INTERNAL_H */
