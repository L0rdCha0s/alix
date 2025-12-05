#ifndef PROCESS_INTERNAL_H
#define PROCESS_INTERNAL_H

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

#define MSR_FS_BASE         0xC0000100
#define MSR_GS_BASE         0xC0000101
#define RFLAGS_RESERVED_BIT (1ULL << 1)
#define RFLAGS_IF_BIT       (1ULL << 9)
#define RFLAGS_DEFAULT      (RFLAGS_RESERVED_BIT | RFLAGS_IF_BIT)

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
#ifndef ENABLE_RUN_QUEUE_DEBUG
#define ENABLE_RUN_QUEUE_DEBUG 1
#endif
#ifndef ENABLE_SHELL_TRACE
#define ENABLE_SHELL_TRACE 0
#endif
#define SCHED_SWITCH_WARN_MS 500ULL

#define THREAD_CONTEXT_REDZONE_BYTES (64ULL * 1024ULL)
#define PROCESS_TIME_SLICE_DEFAULT_TICKS 10U
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
    void *raw_allocation;
    void *aligned_allocation;
    size_t mapped_size;
    uintptr_t user_base;
    bool writable;
    bool executable;
    struct process_user_region *next;
} process_user_region_t;

typedef struct user_thread_bootstrap
{
    uintptr_t entry;
    uintptr_t stack_top;
    uint64_t argc;
    uintptr_t argv_ptr;
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
    uintptr_t phys[PROCESS_HEAP_L2_ENTRIES];
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
    uint64_t runtime_ticks;
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

struct process
{
    uint64_t pid;
    process_state_t state;
    process_lifetime_state_t lifetime_state;
    char name[PROCESS_NAME_MAX];
    uint64_t cr3;
    paging_space_t address_space;
    thread_t *main_thread;
    thread_t *current_thread;
    int exit_status;
    struct process *next;
    int stdout_fd;
    uint64_t runtime_ticks;
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
extern const uint8_t g_user_preempt_stub[9];
#define USER_EXIT_STUB_SIZE    7u
#define USER_PREEMPT_STUB_SIZE 9u

extern process_t *g_process_list;
extern process_t *g_current_processes[SMP_MAX_CPUS];
extern thread_t *g_current_threads[SMP_MAX_CPUS];
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
    uint32_t idx = smp_current_cpu_index();
    if (idx >= SMP_MAX_CPUS)
    {
        return NULL;
    }
    return g_current_threads[idx];
}

static inline process_t *current_process_local(void)
{
    uint32_t idx = smp_current_cpu_index();
    if (idx >= SMP_MAX_CPUS)
    {
        return NULL;
    }
    return g_current_processes[idx];
}

static inline void set_current_thread_local(thread_t *thread)
{
    uint32_t idx = smp_current_cpu_index();
    if (idx >= SMP_MAX_CPUS)
    {
        return;
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
        return;
    }
    uint64_t flags = cpu_save_flags();
    cpu_cli();
    g_current_processes[idx] = process;
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
    spinlock_lock(&g_scheduler_lock);
    return flags;
}

static inline void scheduler_lock_release(uint64_t flags)
{
    spinlock_unlock(&g_scheduler_lock);
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
void context_switch(cpu_context_t **prev_ctx, cpu_context_t *next_ctx, uint8_t *transition_flag, uint32_t *stack_guard_label);
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
bool process_setup_dummy_user_space(process_t *process);
bool process_setup_basic_user_memory(process_t *process);
bool process_store_args(process_t *process,
                        const char *const *argv,
                        size_t argc);
bool process_prepare_stack_with_args(process_t *process);
void process_clear_args(process_t *process);
void process_free_user_regions(process_t *process);
void process_heap_release_from(process_t *process, uintptr_t virt_start);
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
process_t *process_detach_first_child(process_t *parent);
void thread_remove_from_wait_queue(thread_t *thread);
void remove_from_run_queue(thread_t *thread);
void thread_context_guard_release_pages(thread_t *thread);
void thread_enqueue_deferred_free(thread_t *thread);
bool process_try_mark_destroying(process_t *process);
bool process_pointer_valid(const process_t *process);
bool thread_pointer_valid(const thread_t *thread);
bool process_heap_commit_range(process_t *process, uintptr_t start, uintptr_t end);
bool process_heap_zero_range(process_t *process, uintptr_t start, size_t bytes);
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
void cpu_account_tick(thread_t *thread);
void thread_trigger_stack_guard(thread_t *thread, interrupt_frame_t *frame, const char *reason);
extern void process_preempt_trampoline(void);
void thread_set_base_priority(thread_t *thread, thread_priority_t priority);
void thread_set_priority_override(thread_t *thread, bool enabled, thread_priority_t priority);
void enqueue_thread(thread_t *thread);
void thread_quarantine_corrupt(thread_t *thread, const char *reason);
void process_log(const char *msg, uint64_t value);
void stack_owner_register(thread_t *thread);
void stack_owner_unregister(thread_t *thread);
void thread_context_guard_update(thread_t *thread, const char *label);
bool thread_stack_watch_snapshot_changed(thread_t *thread,
                                         uintptr_t *addr_out,
                                         uint8_t *old_out,
                                         uint8_t *new_out);
bool thread_context_in_bounds(thread_t *thread, const char *reason);
bool thread_fpu_region_valid(const thread_t *thread);
void thread_assert_stack_current(thread_t *thread, const char *context);
bool thread_process_deferred_frees(uint32_t cpu_index, deferred_free_stats_t *stats);
void thread_stack_watch_maybe_arm(thread_t *thread);
void thread_registry_add(thread_t *thread);
void procfs_register_process_priority(process_t *process);
void process_destroy_marked(process_t *process);
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
