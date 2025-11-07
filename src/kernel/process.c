#include "process.h"

#include "heap.h"
#include "arch/x86/segments.h"
#include "paging.h"
#include "libc.h"
#include "serial.h"
#include "msr.h"
#include "console.h"
#include "fd.h"

#define MSR_FS_BASE         0xC0000100
#define MSR_GS_BASE         0xC0000101
#define TSS_RSP0_OFFSET     4

#define RFLAGS_RESERVED_BIT (1ULL << 1)
#define RFLAGS_IF_BIT       (1ULL << 9)
#define RFLAGS_DEFAULT      (RFLAGS_RESERVED_BIT | RFLAGS_IF_BIT)

#define PROCESS_STACK_GUARD_SIZE (4096UL)
#define STACK_GUARD_PATTERN      0x5A

#define USER_ADDRESS_SPACE_BASE   0x0000008000000000ULL
#define USER_DUMMY_CODE_BASE      (USER_ADDRESS_SPACE_BASE + 0x00100000ULL)
#define USER_DUMMY_STACK_TOP      (USER_ADDRESS_SPACE_BASE + 0x01000000ULL)
#define USER_DUMMY_STACK_SIZE     (64ULL * 1024ULL)
#define PAGE_SIZE_BYTES_LOCAL     4096ULL

typedef uint64_t cpu_context_t;

#define PROCESS_TIME_SLICE_TICKS 10U

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

typedef struct user_thread_bootstrap
{
    uintptr_t entry;
    uintptr_t stack_top;
} user_thread_bootstrap_t;

static const uint8_t g_user_exit_stub[] = {
    0x31, 0xFF,       /* xor edi, edi */
    0x31, 0xC0,       /* xor eax, eax */
    0xCD, 0x80,       /* int 0x80 */
    0xF4              /* hlt (should not reach) */
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
    size_t stack_size;
    uintptr_t kernel_stack_top;
    thread_entry_t entry;
    void *arg;
    thread_state_t state;
    struct thread *queue_next;
    fpu_state_t fpu_state;
    uint64_t fs_base;
    uint64_t gs_base;
    uint32_t time_slice_remaining;
    int exit_status;
    bool in_run_queue;
    bool is_idle;
    bool exited;
    bool preempt_pending;
    bool fpu_initialized;
    char name[PROCESS_NAME_MAX];
    bool stack_guard_failed;
    const char *stack_guard_reason;
    bool is_user;
    const char *fault_reason;
    uint64_t fault_error_code;
    uint64_t fault_address;
    bool fault_has_address;
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
    process_user_region_t *user_regions;
    uintptr_t user_entry_point;
    uintptr_t user_stack_top;
    size_t user_stack_size;
};

static process_t *g_process_list = NULL;
static process_t *g_current_process = NULL;
static thread_t *g_current_thread = NULL;
static thread_t *g_idle_thread = NULL;
static cpu_context_t *g_bootstrap_context = NULL;
static thread_t *g_run_queue_head = NULL;
static thread_t *g_run_queue_tail = NULL;
static uint64_t g_next_pid = 1;

static fpu_state_t g_fpu_initial_state;
static bool g_fpu_template_ready = false;
static int g_console_stdout_fd = -1;

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

extern uint8_t tss64[];
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

static void tss_set_rsp0(uint64_t rsp0)
{
    uint64_t *slot = (uint64_t *)(tss64 + TSS_RSP0_OFFSET);
    *slot = rsp0;
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
    frame->rflags &= ~RFLAGS_IF_BIT;
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

static void fatal(const char *msg) __attribute__((noreturn));
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
    proc->user_regions = NULL;
    proc->user_entry_point = 0;
    proc->user_stack_top = 0;
    proc->user_stack_size = 0;
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
        if (region->raw_allocation)
        {
            free(region->raw_allocation);
        }
        free(region);
        region = next;
    }
    process->user_regions = NULL;
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
    size_t raw_bytes = aligned_bytes + PAGE_SIZE_BYTES_LOCAL;
    uint8_t *raw = (uint8_t *)malloc(raw_bytes);
    if (!raw)
    {
        return false;
    }
    uintptr_t aligned = align_up_uintptr((uintptr_t)raw, PAGE_SIZE_BYTES_LOCAL);
    memset((void *)aligned, 0, aligned_bytes);

    process_user_region_t *region = (process_user_region_t *)malloc(sizeof(process_user_region_t));
    if (!region)
    {
        free(raw);
        return false;
    }

    region->raw_allocation = raw;
    region->aligned_allocation = (void *)aligned;
    region->mapped_size = aligned_bytes;
    region->user_base = user_base;
    region->writable = writable;
    region->executable = executable;
    region->next = process->user_regions;
    process->user_regions = region;

    if (region_out)
    {
        *region_out = region;
    }
    return true;
}

static bool process_setup_dummy_user_space(process_t *process)
{
    if (!process)
    {
        return false;
    }

    process_user_region_t *code_region = NULL;
    if (!process_user_region_allocate(process,
                                      USER_DUMMY_CODE_BASE,
                                      PAGE_SIZE_BYTES_LOCAL,
                                      false,
                                      true,
                                      &code_region))
    {
        return false;
    }

    memcpy(code_region->aligned_allocation, g_user_exit_stub, sizeof(g_user_exit_stub));
    if (!process_map_user_region(process, code_region))
    {
        return false;
    }

    process_user_region_t *stack_region = NULL;
    if (!process_user_region_allocate(process,
                                      USER_DUMMY_STACK_TOP - USER_DUMMY_STACK_SIZE,
                                      USER_DUMMY_STACK_SIZE,
                                      true,
                                      false,
                                      &stack_region))
    {
        return false;
    }
    if (!process_map_user_region(process, stack_region))
    {
        return false;
    }

    process->user_entry_point = USER_DUMMY_CODE_BASE;
    process->user_stack_top = USER_DUMMY_STACK_TOP;
    process->user_stack_size = USER_DUMMY_STACK_SIZE;
    return true;
}

static void scheduler_schedule(bool requeue_current);
static void idle_thread_entry(void *arg) __attribute__((noreturn));
static void thread_trampoline(void) __attribute__((noreturn));
static void user_thread_entry(void *arg) __attribute__((noreturn));
static void enqueue_thread(thread_t *thread);
static void remove_from_run_queue(thread_t *thread);
static void process_attach_child(process_t *parent, process_t *child);
static void process_detach_child(process_t *child);
static process_t *process_detach_first_child(process_t *parent);

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
    proc->next = g_process_list;
    g_process_list = proc;

    process_t *actual_parent = parent ? parent : g_current_process;
    if (actual_parent)
    {
        process_attach_child(actual_parent, proc);
    }

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
    bool is_user_thread = user_mode;
    if (!is_user_thread && process)
    {
        is_user_thread = process->is_user;
    }

    size_t actual_stack = stack_size ? stack_size : PROCESS_DEFAULT_STACK_SIZE;
    size_t guard_size = PROCESS_STACK_GUARD_SIZE;
    size_t allocation_size = actual_stack + guard_size;
    uint8_t *stack_allocation = (uint8_t *)malloc(allocation_size);
    if (!stack_allocation)
    {
        free(thread);
        return NULL;
    }
    memset(stack_allocation, STACK_GUARD_PATTERN, guard_size);
    thread->stack_guard_base = stack_allocation;
    thread->stack_base = stack_allocation + guard_size;
    thread->stack_size = actual_stack;

    uintptr_t stack_limit = ((uintptr_t)thread->stack_base + actual_stack) & ~(uintptr_t)0xF;
    uintptr_t stack_ptr = stack_limit - 8;
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
    thread->time_slice_remaining = PROCESS_TIME_SLICE_TICKS;
    thread->preempt_pending = false;
    thread->fs_base = 0;
    thread->gs_base = (uint64_t)&thread->tls;
    thread->fpu_initialized = true;
    thread->stack_guard_failed = false;
    thread->stack_guard_reason = NULL;
    thread->is_user = is_user_thread;
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

    return thread;
}

static void enqueue_thread(thread_t *thread)
{
    if (!thread || thread->in_run_queue)
    {
        return;
    }
    thread->queue_next = NULL;
    thread->in_run_queue = true;
    if (!g_run_queue_head)
    {
        g_run_queue_head = thread;
        g_run_queue_tail = thread;
    }
    else
    {
        g_run_queue_tail->queue_next = thread;
        g_run_queue_tail = thread;
    }
}

static thread_t *dequeue_thread(void)
{
    thread_t *thread = g_run_queue_head;
    if (!thread)
    {
        return NULL;
    }
    g_run_queue_head = thread->queue_next;
    if (!g_run_queue_head)
    {
        g_run_queue_tail = NULL;
    }
    thread->queue_next = NULL;
    thread->in_run_queue = false;
    return thread;
}

static void remove_from_run_queue(thread_t *thread)
{
    if (!thread || !thread->in_run_queue)
    {
        return;
    }

    thread_t *prev = NULL;
    thread_t *cursor = g_run_queue_head;
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
                g_run_queue_head = thread->queue_next;
            }
            if (g_run_queue_tail == thread)
            {
                g_run_queue_tail = prev;
            }
            thread->queue_next = NULL;
            thread->in_run_queue = false;
            return;
        }
        prev = cursor;
        cursor = cursor->queue_next;
    }
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

static void switch_to_thread(thread_t *next)
{
    thread_t *prev = g_current_thread;
    process_t *prev_process = prev ? prev->process : NULL;
    process_t *next_process = next ? next->process : NULL;

    if (prev)
    {
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

    g_current_thread = next;
    g_current_process = next_process;

    if (next)
    {
        next->state = THREAD_STATE_RUNNING;
        if (next_process)
        {
            next_process->state = PROCESS_STATE_RUNNING;
            next_process->current_thread = next;
        }

        next->time_slice_remaining = PROCESS_TIME_SLICE_TICKS;
        next->preempt_pending = false;

        if (!pointer_in_heap(next->gs_base, sizeof(thread_tls_t)))
        {
            serial_write_string("process: invalid next GS base=0x");
            serial_write_hex64(next->gs_base);
            serial_write_string("\r\n");
            fatal("invalid GS base for next thread");
        }

        uint64_t desired_cr3 = next_process ? next_process->cr3 : read_cr3();
        if (desired_cr3 && desired_cr3 != read_cr3())
        {
            write_cr3(desired_cr3);
        }

        tss_set_rsp0(next->kernel_stack_top);
        wrmsr(MSR_FS_BASE, next->fs_base);
        wrmsr(MSR_GS_BASE, next->gs_base);
        fpu_restore_state(&next->fpu_state);
    }

    cpu_context_t **prev_ctx = prev ? &prev->context : &g_bootstrap_context;
    cpu_context_t *next_ctx = next ? next->context : NULL;

    if (!next_ctx)
    {
        fatal("no next context");
    }

    context_switch(prev_ctx, next_ctx);
}

static void scheduler_schedule(bool requeue_current)
{
    uint64_t flags = cpu_save_flags();
    cpu_cli();

    thread_t *current = g_current_thread;

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
        current->time_slice_remaining = PROCESS_TIME_SLICE_TICKS;
        current->preempt_pending = false;
        enqueue_thread(current);
    }

    thread_t *next = dequeue_thread();
    if (!next)
    {
        next = g_idle_thread;
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

    switch_to_thread(next);
    cpu_restore_flags(flags);
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
    thread_t *thread = g_current_thread;
    if (!thread)
    {
        return;
    }

    thread->preempt_pending = false;

    process_yield();

    thread = g_current_thread;
    if (thread)
    {
        thread->preempt_pending = false;
    }
}

static __attribute__((noreturn)) void process_jump_to_user(uintptr_t entry,
                                                           uintptr_t user_stack_top)
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
        "mov %%ax, %%fs\n\t"
        "mov %%ax, %%gs\n\t"
        "xor %%rdi, %%rdi\n\t"
        "xor %%rsi, %%rsi\n\t"
        "xor %%rdx, %%rdx\n\t"
        "xor %%rcx, %%rcx\n\t"
        "xor %%r8, %%r8\n\t"
        "xor %%r9, %%r9\n\t"
        "xor %%r10, %%r10\n\t"
        "xor %%r11, %%r11\n\t"
        "push %[ss]\n\t"
        "pushq %[stack]\n\t"
        "push %[rflags]\n\t"
        "push %[cs]\n\t"
        "pushq %[entry]\n\t"
        "iretq\n\t"
        :
        : [ds]"r"(data_sel),
          [ss]"r"(ss),
          [stack]"m"(stack_value),
          [rflags]"r"(rflags),
          [cs]"r"(cs),
          [entry]"m"(entry_value)
        : "rax", "rdi", "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11", "memory");
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
    process_jump_to_user(params.entry, params.stack_top);
}

static void thread_trampoline(void)
{
    thread_t *self = g_current_thread;
    if (self && self->entry)
    {
        self->entry(self->arg);
    }
    process_exit(0);
}

static void process_handle_stack_guard_fault(void)
{
    thread_t *current = g_current_thread;
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
    }

    scheduler_schedule(false);
    fatal("stack guard handler returned");
}

static void process_handle_fatal_fault(void)
{
    thread_t *current = g_current_thread;
    if (!current)
    {
        fatal("fatal fault handler without current thread");
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
    thread_t *thread = g_current_thread;
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
    }

    process_trigger_fatal_fault(thread, frame, reason, error_code, has_address, address);
    return true;
}

void process_system_init(void)
{
    fpu_prepare_initial_state();

    if (g_console_stdout_fd < 0)
    {
        g_console_stdout_fd = fd_allocate(&console_stdout_ops, NULL);
        if (g_console_stdout_fd < 0)
        {
            fatal("unable to allocate console stdout fd");
        }
    }

    g_process_list = NULL;
    g_current_process = NULL;
    g_current_thread = NULL;
    g_run_queue_head = NULL;
    g_run_queue_tail = NULL;
    g_next_pid = 1;

    process_t *idle_process = allocate_process("idle", false);
    if (!idle_process)
    {
        fatal("unable to allocate idle process");
    }
    idle_process->pid = 0;
    idle_process->state = PROCESS_STATE_READY;
    idle_process->is_user = false;
    idle_process->cr3 = read_cr3();
    idle_process->next = g_process_list;
    g_process_list = idle_process;
    g_next_pid = 1;

    g_idle_thread = thread_create(idle_process, "idle", idle_thread_entry, NULL, PROCESS_DEFAULT_STACK_SIZE, true, false);
    if (!g_idle_thread)
    {
        fatal("unable to allocate idle thread");
    }
    idle_process->main_thread = g_idle_thread;
    idle_process->current_thread = g_idle_thread;
    g_idle_thread->state = THREAD_STATE_READY;
}

void process_start_scheduler(void)
{
    scheduler_schedule(false);
    while (1)
    {
        __asm__ volatile ("hlt");
    }
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

    user_thread_bootstrap_t *bootstrap = (user_thread_bootstrap_t *)malloc(sizeof(user_thread_bootstrap_t));
    if (!bootstrap)
    {
        process_free_user_regions(proc);
        paging_destroy_space(&proc->address_space);
        free(proc);
        return NULL;
    }
    bootstrap->entry = proc->user_entry_point;
    bootstrap->stack_top = proc->user_stack_top;

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

void process_yield(void)
{
    scheduler_schedule(true);
}

void process_destroy(process_t *process)
{
    if (!process || process->state != PROCESS_STATE_ZOMBIE || process->main_thread == g_idle_thread)
    {
        return;
    }

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
        if (thread->in_run_queue)
        {
            remove_from_run_queue(thread);
        }
        if (thread->stack_guard_base)
        {
            free(thread->stack_guard_base);
            thread->stack_guard_base = NULL;
            thread->stack_base = NULL;
        }
        else if (thread->stack_base)
        {
            free(thread->stack_base);
            thread->stack_base = NULL;
        }
        free(thread);
    }

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

    process_free_user_regions(process);
    paging_destroy_space(&process->address_space);
    free(process);
}

void process_exit(int status)
{
    thread_t *current = g_current_thread;
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
    }

    scheduler_schedule(false);
    fatal("process_exit returned");
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
        }
        process_yield();
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

    bool target_running = (thread == g_current_thread);

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
    return g_current_process;
}

thread_t *thread_current(void)
{
    return g_current_thread;
}

uint64_t process_current_pid(void)
{
    if (!g_current_process)
    {
        return 0;
    }
    return g_current_process->pid;
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
    if (g_current_process && g_current_process->stdout_fd >= 0)
    {
        return g_current_process->stdout_fd;
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
    for (process_t *proc = g_process_list; proc && count < capacity; proc = proc->next)
    {
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
        info->is_current = (proc == g_current_process);
    }

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

void process_on_timer_tick(interrupt_frame_t *frame)
{
    if (!frame)
    {
        return;
    }

    thread_t *thread = g_current_thread;
    if (!thread || thread->is_idle)
    {
        return;
    }

    if (!thread_stack_pointer_valid(thread, frame->rsp))
    {
        thread_trigger_stack_guard(thread, frame, "rsp_out_of_bounds");
        return;
    }

    if (!thread_stack_guard_intact(thread))
    {
        thread_trigger_stack_guard(thread, frame, "guard_corrupted");
        return;
    }

    if (!pointer_in_heap(thread->gs_base, sizeof(thread_tls_t)))
    {
        serial_write_string("process: invalid current GS base=0x");
        serial_write_hex64(thread->gs_base);
        serial_write_string("\r\n");
        fatal("invalid GS base for current thread");
    }

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
    thread->time_slice_remaining = PROCESS_TIME_SLICE_TICKS;
    thread->tls.preempt_resume_rip = frame->rip;
    frame->rip = (uint64_t)process_preempt_trampoline;
}
