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
#include "timer.h"
#include "interrupts.h"
#include "smp.h"
#include "spinlock.h"
#include "build_features.h"

extern uintptr_t kernel_heap_end;

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
#define ENABLE_CONTEXT_GUARD             1
#define CONTEXT_GUARD_WORDS              8ULL
#define ENABLE_STACK_WRITE_DEBUG         1
#define STACK_WATCH_SNAPSHOT_BYTES       128ULL
#define STACK_WATCH_TIMEOUT_LIMIT        20U
#ifndef ENABLE_STACK_WRITE_DEBUG_LOGS
#define ENABLE_STACK_WRITE_DEBUG_LOGS    1
#endif
#ifndef ENABLE_STACK_SCAN_LOGS
#define ENABLE_STACK_SCAN_LOGS           0
#endif
#ifndef ENABLE_STACK_GUARD_PROTECT
#define ENABLE_STACK_GUARD_PROTECT       0
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

static void fatal(const char *msg) __attribute__((noreturn));

#define USER_ADDRESS_SPACE_BASE   0x0000008000000000ULL
#define USER_STUB_CODE_BASE       (USER_ADDRESS_SPACE_BASE + 0x00100000ULL)
#define USER_PREEMPT_STUB_BASE    (USER_ADDRESS_SPACE_BASE + 0x00110000ULL)
#define USER_STACK_TOP            (USER_ADDRESS_SPACE_BASE + 0x01000000ULL)
#define USER_STACK_SIZE           (64ULL * 1024ULL)
#define USER_HEAP_BASE            (USER_ADDRESS_SPACE_BASE + 0x02000000ULL)
#define USER_HEAP_SIZE            (1024ULL * 1024ULL * 1024ULL)
#define PAGE_SIZE_BYTES_LOCAL     4096ULL

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

typedef struct process_heap_page
{
    uintptr_t virt;
    uintptr_t phys;
    struct process_heap_page *next;
} process_heap_page_t;

typedef struct user_thread_bootstrap
{
    uintptr_t entry;
    uintptr_t stack_top;
    uint64_t argc;
    uintptr_t argv_ptr;
} user_thread_bootstrap_t;

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
    process_heap_page_t *heap_pages;
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

static process_t *g_process_list = NULL;
static process_t *g_current_processes[SMP_MAX_CPUS] = { NULL };
static thread_t *g_current_threads[SMP_MAX_CPUS] = { NULL };
static thread_t *g_idle_threads[SMP_MAX_CPUS] = { NULL };
static thread_t *g_deferred_thread_frees[SMP_MAX_CPUS] = { NULL };
static spinlock_t g_deferred_free_locks[SMP_MAX_CPUS];
#if ENABLE_STACK_WRITE_DEBUG
static bool g_stack_write_debug_enabled = false;
#endif
static process_t *g_idle_process = NULL;
static cpu_context_t *g_bootstrap_context = NULL;
static thread_t *g_run_queue_heads[THREAD_PRIORITY_COUNT] = { NULL };
static thread_t *g_run_queue_tails[THREAD_PRIORITY_COUNT] = { NULL };
static thread_t *g_sleep_queue_head = NULL;
static uint64_t g_next_pid = 1;
static spinlock_t g_run_queue_lock;
static spinlock_t g_sleep_queue_lock;
static spinlock_t g_process_lock;

static fpu_state_t g_fpu_initial_state;
static bool g_fpu_template_ready = false;
static int g_console_stdout_fd = -1;
static uint32_t g_time_slice_ticks = PROCESS_TIME_SLICE_DEFAULT_TICKS;
static thread_t *g_stack_watch_frozen_head = NULL;

static void thread_freeze_for_stack_watch(thread_t *thread, const char *context);
static void thread_unfreeze_after_stack_watch(thread_t *thread);
static void stack_watch_check_timeouts(void);
static void stack_watch_remove_frozen(thread_t *thread);

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
    if (idx >= SMP_MAX_CPUS)
    {
        idx = 0;
    }
    return idx;
}

static inline thread_t *current_thread_local(void)
{
    return g_current_threads[current_cpu_index()];
}

static inline process_t *current_process_local(void)
{
    return g_current_processes[current_cpu_index()];
}

static inline void set_current_thread_local(thread_t *thread)
{
    g_current_threads[current_cpu_index()] = thread;
}

static inline void set_current_process_local(process_t *process)
{
    g_current_processes[current_cpu_index()] = process;
}

static void thread_scan_stack_for_suspicious_values(thread_t *thread,
                                                    uintptr_t rsp,
                                                    bool full_stack,
                                                    const char *context);

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
        if (c == '\n')
        {
            serial_write_char('\r');
        }
        serial_write_char(c);
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

static bool thread_pointer_valid(const thread_t *thread)
{
    if (!thread)
    {
        return false;
    }
    bool valid = pointer_in_heap((uint64_t)(uintptr_t)thread, sizeof(thread_t));
    if (!valid)
    {
        serial_write_string("[proc] priority thread ptr invalid addr=0x");
        serial_write_hex64((uint64_t)(uintptr_t)thread);
        serial_write_string("\r\n");
        return false;
    }
    if (thread->magic != THREAD_MAGIC)
    {
        serial_write_string("[proc] priority thread magic mismatch addr=0x");
        serial_write_hex64((uint64_t)(uintptr_t)thread);
        serial_write_string(" magic=0x");
        serial_write_hex64((uint64_t)thread->magic);
        serial_write_string("\r\n");
        return false;
    }
    return true;
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
        serial_write_string("[proc] process ptr invalid addr=0x");
        serial_write_hex64((uint64_t)(uintptr_t)process);
        serial_write_string("\r\n");
        return false;
    }
    if (process->magic != PROCESS_MAGIC)
    {
        serial_write_string("[proc] process magic mismatch addr=0x");
        serial_write_hex64((uint64_t)(uintptr_t)process);
        serial_write_string(" magic=0x");
        serial_write_hex64((uint64_t)process->magic);
        serial_write_string("\r\n");
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

    if (!pointer_in_heap(thread->gs_base, sizeof(thread_tls_t)))
    {
        uint64_t old_base = thread->gs_base;
        thread->gs_base = (uint64_t)&thread->tls;
        serial_write_string("process: repaired GS base for thread ");
        serial_write_string(thread->name);
        serial_write_string(" old=0x");
        serial_write_hex64(old_base);
        serial_write_string(" new=0x");
        serial_write_hex64(thread->gs_base);
        serial_write_string("\r\n");
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

static process_heap_page_t *process_heap_find_page(const process_t *process, uintptr_t virt_page);
static bool process_heap_add_page(process_t *process, uintptr_t virt, uintptr_t phys);
static bool process_heap_zero_range(process_t *process, uintptr_t start, size_t bytes);
static void process_heap_release_from(process_t *process, uintptr_t virt_start);
static void process_free_heap_pages(process_t *process);
static bool process_heap_commit_range(process_t *process, uintptr_t start, uintptr_t end);

static void process_log(const char *msg, uint64_t value)
{
    serial_write_string("[proc] ");
    serial_write_string(msg);
    serial_write_string("0x");
    serial_write_hex64(value);
    serial_write_string("\r\n");
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

static thread_t *thread_find_stack_owner(uintptr_t addr, size_t len)
{
    thread_t *owner = NULL;
    process_t *proc = g_process_list;
    while (proc)
    {
        if (thread_stack_candidate_matches(proc->main_thread, addr, len, &owner))
        {
            return owner;
        }
        if (proc->current_thread && proc->current_thread != proc->main_thread &&
            thread_stack_candidate_matches(proc->current_thread, addr, len, &owner))
        {
            return owner;
        }
        proc = proc->next;
    }

    for (int pr = THREAD_PRIORITY_IDLE; pr < THREAD_PRIORITY_COUNT; ++pr)
    {
        thread_t *cursor = g_run_queue_heads[pr];
        while (cursor)
        {
            if (thread_stack_candidate_matches(cursor, addr, len, &owner))
            {
                return owner;
            }
            cursor = cursor->queue_next;
        }
    }

    thread_t *sleep_cursor = g_sleep_queue_head;
    while (sleep_cursor)
    {
        if (thread_stack_candidate_matches(sleep_cursor, addr, len, &owner))
        {
            return owner;
        }
        sleep_cursor = sleep_cursor->sleep_queue_next;
    }

    for (uint32_t cpu = 0; cpu < SMP_MAX_CPUS; ++cpu)
    {
        if (thread_stack_candidate_matches(g_current_threads[cpu], addr, len, &owner))
        {
            return owner;
        }
        if (thread_stack_candidate_matches(g_idle_threads[cpu], addr, len, &owner))
        {
            return owner;
        }
    }

    return NULL;
}
#endif

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
static void thread_process_deferred_frees(uint32_t cpu_index);

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
        serial_write_string("[sched] warning: unable to arm stack watch\r\n");
        return false;
    }
    thread->stack_watch_active = true;
    thread->stack_watch_base = base;
    thread->stack_watch_len = length;

#if ENABLE_STACK_WRITE_DEBUG_LOGS
    serial_write_string("[sched] stack watch armed thread=");
    if (thread->name[0])
    {
        serial_write_string(thread->name);
    }
    else
    {
        serial_write_string("<unnamed>");
    }
    serial_write_string(" pid=0x");
    serial_write_hex64(thread->process ? thread->process->pid : 0);
    serial_write_string(" context=");
    serial_write_string(thread->stack_watch_context ? thread->stack_watch_context : "<none>");
    serial_write_string(" suspect=0x");
    serial_write_hex64(thread->stack_watch_suspect);
    serial_write_string(" base=0x");
    serial_write_hex64(base);
    serial_write_string(" top=0x");
    serial_write_hex64(top);
    serial_write_string("\r\n");
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
        serial_write_string("[sched] stack watch pending thread=");
        if (thread->name[0])
        {
            serial_write_string(thread->name);
        }
        else
        {
            serial_write_string("<unnamed>");
        }
        serial_write_string(" pid=0x");
        serial_write_hex64(thread->process ? thread->process->pid : 0);
        serial_write_string(" context=");
        serial_write_string(thread->stack_watch_context ? thread->stack_watch_context : "<none>");
        serial_write_string("\r\n");
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
        serial_write_string("[sched] warning: unable to disarm stack watch\r\n");
    }
#if ENABLE_STACK_WRITE_DEBUG_LOGS
    serial_write_string("[sched] stack watch cleared thread=");
    if (thread->name[0])
    {
        serial_write_string(thread->name);
    }
    else
    {
        serial_write_string("<unnamed>");
    }
    serial_write_string(" pid=0x");
    serial_write_hex64(thread->process ? thread->process->pid : 0);
    serial_write_string("\r\n");
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
    if (thread->stack_allocation_raw)
    {
        free(thread->stack_allocation_raw);
    }
    else if (thread->stack_guard_base)
    {
        free(thread->stack_guard_base);
    }
    else if (thread->stack_base)
    {
        free(thread->stack_base);
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

static void thread_process_deferred_frees(uint32_t cpu_index)
{
    if (cpu_index >= SMP_MAX_CPUS)
    {
        cpu_index = 0;
    }
    spinlock_lock(&g_deferred_free_locks[cpu_index]);
    thread_t *list = g_deferred_thread_frees[cpu_index];
    g_deferred_thread_frees[cpu_index] = NULL;
    spinlock_unlock(&g_deferred_free_locks[cpu_index]);

    while (list)
    {
        thread_t *next = list->deferred_next;
        list->deferred_next = NULL;
        thread_free_resources(list);
        list = next;
    }
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

    serial_write_string("[sched] context ptr out of range label=");
    serial_write_string(label ? label : "<none>");
    serial_write_string(" thread=");
    if (thread->name[0])
    {
        serial_write_string(thread->name);
    }
    else
    {
        serial_write_string("<unnamed>");
    }
    serial_write_string(" pid=0x");
    serial_write_hex64(thread->process ? thread->process->pid : 0);
    serial_write_string(" ptr=0x");
    serial_write_hex64(ctx);
    serial_write_string(" stack_base=0x");
    serial_write_hex64(lower);
    serial_write_string(" stack_top=0x");
    serial_write_hex64(upper);
    serial_write_string("\r\n");

#if ENABLE_STACK_WRITE_DEBUG
    thread_t *owner = thread_find_stack_owner(ctx, 0);
    if (owner)
    {
        serial_write_string("  ctx points into stack owned by thread=");
        if (owner->name[0])
        {
            serial_write_string(owner->name);
        }
        else
        {
            serial_write_string("<unnamed>");
        }
        serial_write_string(" pid=0x");
        serial_write_hex64(owner->process ? owner->process->pid : 0);
        serial_write_string("\r\n");
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
    serial_write_string("[proc] stack issue thread=");
    if (thread && thread->name[0])
    {
        serial_write_string(thread->name);
    }
    else
    {
        serial_write_string("<unnamed>");
    }
    serial_write_string(" ctx=");
    serial_write_string(context ? context : "<none>");
    serial_write_string(" reason=");
    serial_write_string(reason ? reason : "<unknown>");
    serial_write_string(" stack_base=0x");
    serial_write_hex64((uintptr_t)(thread ? thread->stack_base : 0));
    serial_write_string(" stack_top=0x");
    serial_write_hex64(thread ? thread->kernel_stack_top : 0);
    serial_write_string("\r\n");
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
        serial_write_string("    [0x");
        serial_write_hex64((uintptr_t)(base + i));
        serial_write_string("] = 0x");
        serial_write_hex64(base[i]);
        serial_write_string("\r\n");
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
    serial_write_string("[sched] stack snapshot label=");
    serial_write_string(label ? label : "<none>");
    serial_write_string(" thread=");
    if (thread->name[0])
    {
        serial_write_string(thread->name);
    }
    else
    {
        serial_write_string("<unnamed>");
    }
    serial_write_string(" pid=0x");
    serial_write_hex64(thread->process ? thread->process->pid : 0);
    serial_write_string(" entries=");
    serial_write_hex64(dump_qwords);
    serial_write_string(" ctx=0x");
    serial_write_hex64(ctx_ptr);
    serial_write_string("\r\n");
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
    serial_write_string("[proc] stack scan hit reason=");
    serial_write_string(reason ? reason : "<unknown>");
    serial_write_string(" ctx=");
    serial_write_string(context ? context : "<none>");
    serial_write_string(" thread=");
    if (thread && thread->name[0])
    {
        serial_write_string(thread->name);
    }
    else
    {
        serial_write_string("<unnamed>");
    }
    serial_write_string(" pid=0x");
    serial_write_hex64(thread && thread->process ? thread->process->pid : 0);
    serial_write_string(" addr=0x");
    serial_write_hex64(addr);
    serial_write_string(" value=0x");
    serial_write_hex64(value);
    serial_write_string("\r\n");

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

    const size_t saved_context_words = 7; /* pushfq + rbp + rbx + r12-15 */
    const uint64_t *context_words = (const uint64_t *)thread->context;
    uint64_t resume_rip = context_words[saved_context_words];
    bool resume_zero = (resume_rip == 0);
    bool resume_boot = (resume_rip >= SMP_BOOT_DATA_PHYS &&
                        resume_rip < SMP_BOOT_DATA_PHYS + 0x1000);
    if (!resume_zero && !resume_boot)
    {
        return;
    }

    process_t *proc = thread->process;
    serial_write_string("[sched] resume rip anomaly label=");
    serial_write_string(label ? label : "<none>");
    serial_write_string(" reason=");
    serial_write_string(resume_zero ? "zero" : "smp_boot");
    serial_write_string(" cpu=");
    serial_write_hex64(current_cpu_index());
    serial_write_string(" thread=");
    if (thread->name[0])
    {
        serial_write_string(thread->name);
    }
    else
    {
        serial_write_string("<unnamed>");
    }
    serial_write_string(" pid=0x");
    serial_write_hex64(proc ? proc->pid : 0);
    serial_write_string(" resume_rip=0x");
    serial_write_hex64(resume_rip);
    serial_write_string(" ctx=0x");
    serial_write_hex64((uintptr_t)thread->context);
    serial_write_string(" stack_base=0x");
    serial_write_hex64((uintptr_t)thread->stack_base);
    serial_write_string(" stack_top=0x");
    serial_write_hex64(thread->kernel_stack_top);
    serial_write_string("\r\n");

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
            thread_stack_watch_activate(thread, context, (uintptr_t)cursor);
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
    serial_write_string("[sched] context_guard window thread=");
    if (thread->name[0])
    {
        serial_write_string(thread->name);
    }
    else
    {
        serial_write_string("<unnamed>");
    }
    serial_write_string(" pid=0x");
    serial_write_hex64(thread->process ? thread->process->pid : 0);
    serial_write_string(" focus=0x");
    serial_write_hex64(focus_addr);
    serial_write_string(" range=[0x");
    serial_write_hex64(start);
    serial_write_string(",0x");
    serial_write_hex64(end);
    serial_write_string(")\r\n");
    for (uintptr_t addr = start; addr + sizeof(uint64_t) <= end; addr += sizeof(uint64_t))
    {
        serial_write_string("  [");
        serial_write_hex64(addr);
        serial_write_string("] = 0x");
        serial_write_hex64(*(const uint64_t *)addr);
        if (addr == focus_addr)
        {
            serial_write_string(" <-- target");
        }
        serial_write_string("\r\n");
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
        serial_write_string("[sched] warning: failed to unprotect stack guard region\r\n");
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
        serial_write_string("[sched] warning: failed to protect stack guard region\r\n");
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
    serial_write_string("[sched] context guard mismatch label=");
    serial_write_string(label ? label : "<none>");
    serial_write_string(" thread=");
    if (thread->name[0])
    {
        serial_write_string(thread->name);
    }
    else
    {
        serial_write_string("<unnamed>");
    }
    serial_write_string(" pid=0x");
    serial_write_hex64(thread->process ? thread->process->pid : 0);
    serial_write_string(" saved_ptr=0x");
    serial_write_hex64(thread->context_guard_ptr);
    serial_write_string(" current_ptr=0x");
    serial_write_hex64((uintptr_t)thread->context);
    serial_write_string(" saved_hash=0x");
    serial_write_hex64(thread->context_guard_hash);
    serial_write_string(" current_hash=0x");
    serial_write_hex64(current_hash);
    serial_write_string("\r\n");
    uintptr_t diff_addr = 0;
    if (diff_index != (size_t)-1)
    {
        diff_addr = thread->context_guard_ptr + diff_index * sizeof(uint64_t);
        serial_write_string("  diff_index=0x");
        serial_write_hex64(diff_index);
        serial_write_string(" addr=0x");
        serial_write_hex64(diff_addr);
        serial_write_string(" saved=0x");
        serial_write_hex64(thread->context_guard_words[diff_index]);
        serial_write_string(" current=0x");
        serial_write_hex64(current_words[diff_index]);
        serial_write_string("\r\n");
    }
    const char *reg_name = "<unknown>";
    if (diff_index != (size_t)-1 &&
        diff_index < STATIC_ARRAY_SIZE(g_context_guard_reg_names))
    {
        reg_name = g_context_guard_reg_names[diff_index];
    }
    serial_write_string("  register=");
    serial_write_string(reg_name);
    serial_write_string("\r\n");
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
        serial_write_string("[sched] context_guard mismatch -> stack watch armed\r\n");
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

__attribute__((naked)) static void context_switch(cpu_context_t **, cpu_context_t *)
{
    __asm__ volatile (
        "pushfq\n\t"
        "push %rbp\n\t"
        "push %rbx\n\t"
        "push %r12\n\t"
        "push %r13\n\t"
        "push %r14\n\t"
        "push %r15\n\t"
        "mov %rsp, (%rdi)\n\t"
        "mov %rsi, %rsp\n\t"
        "pop %r15\n\t"
        "pop %r14\n\t"
        "pop %r13\n\t"
        "pop %r12\n\t"
        "pop %rbx\n\t"
        "pop %rbp\n\t"
        "popfq\n\t"
        "ret\n\t"
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
    serial_write_string("process fatal: ");
    serial_write_string(msg);
    serial_write_string("\r\n");
    for (;;)
    {
        __asm__ volatile ("hlt");
    }
}

static process_t *allocate_process(const char *name, bool is_user)
{
    process_t *proc = (process_t *)malloc(sizeof(process_t));
    if (!proc)
    {
        return NULL;
    }
    memset(proc, 0, sizeof(*proc));
    proc->pid = g_next_pid++;
    proc->state = PROCESS_STATE_READY;
    if (!paging_clone_kernel_space(&proc->address_space))
    {
        free(proc);
        return NULL;
    }
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
    proc->heap_pages = NULL;
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

static process_heap_page_t *process_heap_find_page(const process_t *process, uintptr_t virt_page)
{
    if (!process)
    {
        return NULL;
    }
    for (process_heap_page_t *page = process->heap_pages; page; page = page->next)
    {
        if (page->virt == virt_page)
        {
            return page;
        }
    }
    return NULL;
}

static bool process_heap_add_page(process_t *process, uintptr_t virt, uintptr_t phys)
{
    if (!process)
    {
        return false;
    }
    process_heap_page_t *page = (process_heap_page_t *)malloc(sizeof(process_heap_page_t));
    if (!page)
    {
        return false;
    }
    page->virt = virt;
    page->phys = phys;
    page->next = process->heap_pages;
    process->heap_pages = page;
    return true;
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
        process_heap_page_t *page = process_heap_find_page(process, page_base);
        if (!page)
        {
            return false;
        }
        size_t page_offset = (size_t)(addr - page_base);
        size_t chunk = PAGE_SIZE_BYTES_LOCAL - page_offset;
        if (chunk > remaining)
        {
            chunk = remaining;
        }
        memset((uint8_t *)(uintptr_t)page->phys + page_offset, 0, chunk);
        addr += chunk;
        remaining -= chunk;
    }
    return true;
}

static void process_heap_release_from(process_t *process, uintptr_t virt_start)
{
    if (!process)
    {
        return;
    }
    process_heap_page_t **cursor = &process->heap_pages;
    while (*cursor)
    {
        process_heap_page_t *page = *cursor;
        if (page->virt >= virt_start)
        {
            paging_unmap_user_page(&process->address_space, page->virt);
            user_memory_free_page(page->phys);
            *cursor = page->next;
            free(page);
        }
        else
        {
            cursor = &page->next;
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
    process->heap_pages = NULL;
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
        if (!user_memory_alloc_page(&phys))
        {
            process_heap_release_from(process, start);
            process->user_heap_committed = start;
            return false;
        }
        process_heap_page_t *page_node = (process_heap_page_t *)malloc(sizeof(process_heap_page_t));
        if (!page_node)
        {
            user_memory_free_page(phys);
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
            free(page_node);
            user_memory_free_page(phys);
            process_heap_release_from(process, start);
             process->user_heap_committed = start;
            return false;
        }
        page_node->virt = page_addr;
        page_node->phys = phys;
        page_node->next = process->heap_pages;
        process->heap_pages = page_node;
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
    process->user_heap_base = USER_HEAP_BASE;
    process->user_heap_brk = USER_HEAP_BASE;
    process->user_heap_limit = USER_HEAP_BASE + USER_HEAP_SIZE;
    process->user_heap_committed = USER_HEAP_BASE;
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
    serial_write_string("    [");
    serial_write_hex64(addr);
    serial_write_string("] = 0x");
    serial_write_hex64(value);
    if (mark_rsp)
    {
        serial_write_string(" <-- rsp");
    }
    serial_write_string("\r\n");
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
        serial_write_string("  user stack: unavailable\r\n");
        return;
    }

    uintptr_t stack_top = process->user_stack_top;
    uintptr_t stack_bottom = stack_top - process->user_stack_size;

    serial_write_string("  user stack: range=[");
    serial_write_hex64(stack_bottom);
    serial_write_string(", ");
    serial_write_hex64(stack_top);
    serial_write_string(") rsp=");
    serial_write_hex64(rsp);
    serial_write_string("\r\n");

    if (rsp < stack_bottom || rsp >= stack_top)
    {
        serial_write_string("  user stack: rsp outside stack bounds\r\n");
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
    uint8_t *raw_allocation = NULL;
    uint8_t *guard_base = NULL;
    const int max_layout_attempts = 4;
    for (int attempt = 0; attempt < max_layout_attempts; ++attempt)
    {
        raw_allocation = (uint8_t *)malloc(allocation_size);
        if (!raw_allocation)
        {
            break;
        }
        guard_base = (uint8_t *)align_up_uintptr((uintptr_t)raw_allocation, PAGE_SIZE_BYTES_LOCAL);
        uintptr_t stack_end = (uintptr_t)(guard_base + guard_bytes + aligned_stack);
        if (stack_end <= heap_limit)
        {
            break;
        }
        free(raw_allocation);
        raw_allocation = NULL;
    }

    if (!raw_allocation)
    {
        free(thread);
        return NULL;
    }

    memset(guard_base, STACK_GUARD_PATTERN, guard_bytes);
    thread->stack_allocation_raw = raw_allocation;
    thread->stack_allocation_size = allocation_size;
    thread->stack_guard_base = guard_base;
    thread->stack_base = guard_base + guard_bytes;
    thread->stack_size = aligned_stack;

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
    uintptr_t stack_ptr = usable_limit - 8;
    uint64_t *stack64 = (uint64_t *)stack_ptr;

    *(--stack64) = (uint64_t)thread_trampoline; /* return address */
    *(--stack64) = RFLAGS_DEFAULT;              /* rflags */
    *(--stack64) = 0;                           /* rbp */
    *(--stack64) = 0;                           /* rbx */
    *(--stack64) = 0;                           /* r12 */
    *(--stack64) = 0;                           /* r13 */
    *(--stack64) = 0;                           /* r14 */
    *(--stack64) = 0;                           /* r15 */

    thread->tls.preempt_resume_rip = 0;
    thread->context = (cpu_context_t *)stack64;
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
        serial_write_string("process: thread created gs base=0x");
        serial_write_hex64(thread->gs_base);
        serial_write_string(" name=");
        serial_write_string(thread->name);
        serial_write_string("\r\n");
        thread_log_count++;
    }

#if ENABLE_STACK_WRITE_DEBUG
    const char *watch_context = thread->name[0] ? thread->name : "thread";
    if (!thread->is_idle)
    {
        thread_stack_watch_activate(thread, watch_context, 0);
    }
#endif

#if ENABLE_CONTEXT_GUARD
    if (thread->context_guard_enabled)
    {
        thread_context_guard_update(thread, "thread_create");
    }
#endif

    return thread;
}

static void enqueue_thread(thread_t *thread)
{
    if (!thread || thread->in_run_queue)
    {
        return;
    }
    spinlock_lock(&g_run_queue_lock);
    thread_priority_t priority = thread->priority;
    if (priority < THREAD_PRIORITY_IDLE || priority >= THREAD_PRIORITY_COUNT)
    {
        priority = THREAD_PRIORITY_NORMAL;
        thread->priority = priority;
    }
    thread->queue_next = NULL;
    thread->in_run_queue = true;
    thread_t **head = &g_run_queue_heads[priority];
    thread_t **tail = &g_run_queue_tails[priority];
    if (!*head)
    {
        *head = thread;
        *tail = thread;
    }
    else
    {
        (*tail)->queue_next = thread;
        *tail = thread;
    }
    spinlock_unlock(&g_run_queue_lock);
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
        serial_write_string("[sched] stack watch freeze thread=");
        if (thread->name[0])
        {
            serial_write_string(thread->name);
        }
        else
        {
            serial_write_string("<unnamed>");
        }
        serial_write_string(" pid=0x");
        serial_write_hex64(thread->process ? thread->process->pid : 0);
        serial_write_string(" context=");
        serial_write_string(context ? context : "<none>");
        serial_write_string("\r\n");
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
                serial_write_string("[sched] stack watch delta thread=");
                if (thread->name[0])
                {
                    serial_write_string(thread->name);
                }
                else
                {
                    serial_write_string("<unnamed>");
                }
                serial_write_string(" pid=0x");
                serial_write_hex64(thread->process ? thread->process->pid : 0);
                serial_write_string(" addr=0x");
                serial_write_hex64(delta_addr);
                serial_write_string(" old=0x");
                serial_write_hex8(old_byte);
                serial_write_string(" new=0x");
                serial_write_hex8(new_byte);
                serial_write_string("\r\n");
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
                serial_write_string("[sched] stack watch timeout thread=");
                if (thread->name[0])
                {
                    serial_write_string(thread->name);
                }
                else
                {
                    serial_write_string("<unnamed>");
                }
                serial_write_string(" pid=0x");
                serial_write_hex64(thread->process ? thread->process->pid : 0);
                serial_write_string(" suspect=0x");
                serial_write_hex64(thread->stack_watch_suspect);
                serial_write_string("\r\n");
                thread->stack_watch_timeout_logged = true;
            }

            thread->stack_watch_timeout_count++;
            if (thread->stack_watch_timeout_count >= STACK_WATCH_TIMEOUT_LIMIT)
            {
                serial_write_string("[sched] stack watch release thread=");
                if (thread->name[0])
                {
                    serial_write_string(thread->name);
                }
                else
                {
                    serial_write_string("<unnamed>");
                }
                serial_write_string(" pid=0x");
                serial_write_hex64(thread->process ? thread->process->pid : 0);
                serial_write_string(" reason=timeout_limit\r\n");
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

static thread_t *dequeue_thread(void)
{
    spinlock_lock(&g_run_queue_lock);
    for (int pr = THREAD_PRIORITY_COUNT - 1; pr >= THREAD_PRIORITY_IDLE; --pr)
    {
        thread_t *thread = g_run_queue_heads[pr];
        if (!thread)
        {
            continue;
        }
        g_run_queue_heads[pr] = thread->queue_next;
        if (!g_run_queue_heads[pr])
        {
            g_run_queue_tails[pr] = NULL;
        }
        thread->queue_next = NULL;
        thread->in_run_queue = false;
        spinlock_unlock(&g_run_queue_lock);
        return thread;
    }
    spinlock_unlock(&g_run_queue_lock);
    return NULL;
}

static void remove_from_run_queue(thread_t *thread)
{
    if (!thread || !thread->in_run_queue)
    {
        return;
    }

    spinlock_lock(&g_run_queue_lock);
    thread_t *prev = NULL;
    thread_priority_t priority = thread->priority;
    if (priority < THREAD_PRIORITY_IDLE || priority >= THREAD_PRIORITY_COUNT)
    {
        priority = THREAD_PRIORITY_NORMAL;
    }
    thread_t *cursor = g_run_queue_heads[priority];
    while (cursor)
    {
        if (cursor == thread)
        {
            if (prev)
            {
                prev->queue_next = thread->queue_next;
            }
            else
            {
                g_run_queue_heads[priority] = thread->queue_next;
            }
            if (g_run_queue_tails[priority] == thread)
            {
                g_run_queue_tails[priority] = prev;
            }
            thread->queue_next = NULL;
            thread->in_run_queue = false;
            spinlock_unlock(&g_run_queue_lock);
            return;
        }
        prev = cursor;
        cursor = cursor->queue_next;
    }
    spinlock_unlock(&g_run_queue_lock);
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
    thread_t *prev = current_thread_local();
    process_t *prev_process = prev ? prev->process : NULL;
    process_t *next_process = next ? next->process : NULL;

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

    if (next)
    {
        next->last_cpu_index = current_cpu_index();
        next->state = THREAD_STATE_RUNNING;
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
            serial_write_string("[sched] switch_to cancelled: stack watch active thread=");
            if (next->name[0])
            {
                serial_write_string(next->name);
            }
            else
            {
                serial_write_string("<unnamed>");
            }
            serial_write_string(" pid=0x");
            serial_write_hex64(next->process ? next->process->pid : 0);
            serial_write_string(" context=");
            serial_write_string(next->context_guard_freeze_label ? next->context_guard_freeze_label : "<none>");
            serial_write_string("\r\n");
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

    if (!next_ctx)
    {
        return false;
    }

    context_switch(prev_ctx, next_ctx);

    thread_t *resumed = current_thread_local();
    if (resumed)
    {
        thread_context_guard_release_pages(resumed);
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
    thread_process_deferred_frees(current_cpu_index());

    return true;
}

static void scheduler_schedule(bool requeue_current)
{
    uint64_t flags = cpu_save_flags();
    cpu_cli();

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
        current->state = THREAD_STATE_READY;
        current->time_slice_remaining = scheduler_time_slice_ticks();
        current->preempt_pending = false;
        enqueue_thread(current);
    }

    thread_t *next = dequeue_thread();
    if (!next)
    {
        thread_t *idle = g_idle_threads[current_cpu_index()];
        if (!idle)
        {
            idle = g_idle_threads[0];
        }
        next = idle;
    }

    if (!next)
    {
        cpu_restore_flags(flags);
        return;
    }

    if (next == current)
    {
        current->state = THREAD_STATE_RUNNING;
        current->preempt_pending = false;
        cpu_restore_flags(flags);
        return;
    }

    while (!switch_to_thread(next))
    {
        next = dequeue_thread();
        if (!next)
        {
            thread_t *idle = g_idle_threads[current_cpu_index()];
            if (!idle)
            {
                idle = g_idle_threads[0];
            }
            next = idle;
            if (!next)
            {
                cpu_restore_flags(flags);
                return;
            }
        }
        if (next == current)
        {
            current->state = THREAD_STATE_RUNNING;
            current->preempt_pending = false;
            cpu_restore_flags(flags);
            return;
        }
    }
    cpu_restore_flags(flags);
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

    serial_write_string("process: stack guard violation in thread ");
    if (current->name[0] != '\0')
    {
        serial_write_string(current->name);
    }
    else
    {
        serial_write_string("(anon)");
    }
    if (current->stack_guard_reason)
    {
        serial_write_string(" reason=");
        serial_write_string(current->stack_guard_reason);
    }
    serial_write_string("\r\n");

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

    serial_write_string("process: fatal fault in thread ");
    if (current->name[0] != '\0')
    {
        serial_write_string(current->name);
    }
    else
    {
        serial_write_string("(anon)");
    }
    serial_write_string(" reason=");
    if (current->fault_reason)
    {
        serial_write_string(current->fault_reason);
    }
    else
    {
        serial_write_string("unknown");
    }
    serial_write_string(" error=0x");
    serial_write_hex64(current->fault_error_code);
    if (current->fault_has_address)
    {
        serial_write_string(" addr=0x");
        serial_write_hex64(current->fault_address);
    }
    serial_write_string("\r\n");

    scheduler_schedule(false);
    fatal("fatal fault handler returned");
}

bool process_handle_exception(interrupt_frame_t *frame,
                              const char *reason,
                              uint64_t error_code,
                              bool has_address,
                              uint64_t address)
{
    if (!frame)
    {
        return false;
    }
    thread_t *thread = current_thread_local();
    if (!thread || !thread->is_user)
    {
        return false;
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
    spinlock_init(&g_run_queue_lock);
    spinlock_init(&g_sleep_queue_lock);
    spinlock_init(&g_process_lock);
    for (uint32_t i = 0; i < SMP_MAX_CPUS; ++i)
    {
        spinlock_init(&g_deferred_free_locks[i]);
        g_deferred_thread_frees[i] = NULL;
    }
    for (int i = 0; i < THREAD_PRIORITY_COUNT; ++i)
    {
        g_run_queue_heads[i] = NULL;
        g_run_queue_tails[i] = NULL;
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

static process_t *process_create_kernel_internal(const char *name,
                                                 thread_entry_t entry,
                                                 void *arg,
                                                 size_t stack_size,
                                                 int stdout_fd,
                                                 process_t *parent)
{
    if (!entry)
    {
        return NULL;
    }

    process_t *proc = allocate_process(name, false);
    if (!proc)
    {
        return NULL;
    }

    thread_t *thread = thread_create(proc, name, entry, arg, stack_size, false, proc->is_user);
    if (!thread)
    {
        paging_destroy_space(&proc->address_space);
        free(proc);
        return NULL;
    }

    return process_finalize_new_process(proc, thread, stdout_fd, parent);
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

static bool process_waiting_still_running(void *context)
{
    process_t *proc = (process_t *)context;
    return proc && process_pointer_valid(proc) && proc->state != PROCESS_STATE_ZOMBIE;
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
        wait_queue_wait(&process->wait_queue, process_waiting_still_running, process);
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
    queue->head = NULL;
    queue->tail = NULL;
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

    if (predicate && !predicate(context))
    {
        cpu_restore_flags(flags);
        return;
    }

    if (thread->in_run_queue)
    {
        remove_from_run_queue(thread);
    }
    thread->state = THREAD_STATE_BLOCKED;
    thread->waiting_queue = queue;
    wait_queue_enqueue_locked(queue, thread);

    cpu_restore_flags(flags);
    scheduler_schedule(false);
}

void wait_queue_wake_one(wait_queue_t *queue)
{
    if (!queue)
    {
        return;
    }
    uint64_t flags = cpu_save_flags();
    cpu_cli();

    thread_t *thread = wait_queue_dequeue_locked(queue);
    if (thread)
    {
        thread->waiting_queue = NULL;
        if (thread->state == THREAD_STATE_BLOCKED && !thread->exited)
        {
            thread->state = THREAD_STATE_READY;
            enqueue_thread(thread);
        }
    }

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

    thread_t *thread = wait_queue_dequeue_locked(queue);
    while (thread)
    {
        thread->waiting_queue = NULL;
        if (thread->state == THREAD_STATE_BLOCKED && !thread->exited)
        {
            thread->state = THREAD_STATE_READY;
            enqueue_thread(thread);
        }
        thread = wait_queue_dequeue_locked(queue);
    }

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
        serial_write_string("  thread: <none>\r\n");
        return;
    }
    serial_write_string("  thread name=");
    if (thread->name[0])
    {
        serial_write_string(thread->name);
    }
    else
    {
        serial_write_string("<unnamed>");
    }
    serial_write_string(" state=");
    serial_write_string(thread_state_name(thread->state));
    serial_write_string(" stack_base=0x");
    serial_write_hex64((uintptr_t)thread->stack_base);
    serial_write_string(" stack_top=0x");
    serial_write_hex64(thread->kernel_stack_top);
    serial_write_string(" guard=");
    serial_write_string(thread_stack_guard_intact(thread) ? "ok" : "CORRUPT");
    serial_write_string("\r\n");
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
    serial_write_string("[sched] stack watch fault hit\r\n");
    serial_write_string("  target=");
    if (target->name[0])
    {
        serial_write_string(target->name);
    }
    else
    {
        serial_write_string("<unnamed>");
    }
    serial_write_string(" pid=0x");
    serial_write_hex64(target->process ? target->process->pid : 0);
    serial_write_string(" addr=0x");
    serial_write_hex64(fault_addr);
    serial_write_string(" watch_base=0x");
    serial_write_hex64(target->stack_watch_base);
    serial_write_string(" watch_len=0x");
    serial_write_hex64(target->stack_watch_len);
    serial_write_string(" suspect=0x");
    serial_write_hex64(target->stack_watch_suspect);
    serial_write_string(" context=");
    serial_write_string(target->stack_watch_context ? target->stack_watch_context : "<none>");
    serial_write_string("\r\n");

    serial_write_string("  writer=");
    if (writer && writer->name[0])
    {
        serial_write_string(writer->name);
    }
    else
    {
        serial_write_string(writer ? "<unnamed>" : "<none>");
    }
    serial_write_string(" pid=0x");
    serial_write_hex64(writer && writer->process ? writer->process->pid : 0);
    serial_write_string(" rip=0x");
    serial_write_hex64(frame ? frame->rip : 0);
    serial_write_string(" err=0x");
    serial_write_hex64(error_code);
    serial_write_string("\r\n");

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

    serial_write_string(self_write ? "[stack-write-self] label="
                                   : (cross_write ? "[stack-write-cross] label=" : "[stack-write] label="));
    serial_write_string(label ? label : "<none>");
    serial_write_string(" writer=");
    if (writer && writer->name[0])
    {
        serial_write_string(writer->name);
    }
    else
    {
        serial_write_string("<none>");
    }
    serial_write_string(" writer_pid=0x");
    serial_write_hex64(writer && writer->process ? writer->process->pid : 0);
    serial_write_string(" target=");
    if (owner->name[0])
    {
        serial_write_string(owner->name);
    }
    else
    {
        serial_write_string("<unnamed>");
    }
    serial_write_string(" target_pid=0x");
    serial_write_hex64(owner->process ? owner->process->pid : 0);
    serial_write_string(" dest=0x");
    serial_write_hex64(addr);
    serial_write_string(" len=0x");
    serial_write_hex64(len);
    serial_write_string(" stack_base=0x");
    serial_write_hex64((uintptr_t)owner->stack_base);
    serial_write_string(" stack_top=0x");
    serial_write_hex64(owner->kernel_stack_top);
    serial_write_string(" caller=0x");
    serial_write_hex64((uintptr_t)caller);
    serial_write_string("\r\n");
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
