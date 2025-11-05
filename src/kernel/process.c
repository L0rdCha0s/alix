#include "process.h"

#include "heap.h"
#include "libc.h"
#include "serial.h"
#include "msr.h"

#define MSR_FS_BASE         0xC0000100
#define MSR_GS_BASE         0xC0000101
#define TSS_RSP0_OFFSET     4

#define RFLAGS_RESERVED_BIT (1ULL << 1)
#define RFLAGS_IF_BIT       (1ULL << 9)
#define RFLAGS_DEFAULT      (RFLAGS_RESERVED_BIT | RFLAGS_IF_BIT)

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
};

struct process
{
    uint64_t pid;
    process_state_t state;
    char name[PROCESS_NAME_MAX];
    uint64_t cr3;
    thread_t *main_thread;
    thread_t *current_thread;
    int exit_status;
    struct process *next;
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

static void tss_set_rsp0(uint64_t rsp0)
{
    uint64_t *slot = (uint64_t *)(tss64 + TSS_RSP0_OFFSET);
    *slot = rsp0;
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

static process_t *allocate_process(const char *name)
{
    process_t *proc = (process_t *)malloc(sizeof(process_t));
    if (!proc)
    {
        return NULL;
    }
    memset(proc, 0, sizeof(*proc));
    proc->pid = g_next_pid++;
    proc->state = PROCESS_STATE_READY;
    proc->cr3 = read_cr3();
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
    return proc;
}

static void scheduler_schedule(bool requeue_current);
static void idle_thread_entry(void *arg) __attribute__((noreturn));
static void thread_trampoline(void) __attribute__((noreturn));
static void remove_from_run_queue(thread_t *thread);

static thread_t *thread_create(process_t *process,
                               const char *name,
                               thread_entry_t entry,
                               void *arg,
                               size_t stack_size,
                               bool is_idle)
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

    size_t actual_stack = stack_size ? stack_size : PROCESS_DEFAULT_STACK_SIZE;
    thread->stack_base = (uint8_t *)malloc(actual_stack);
    if (!thread->stack_base)
    {
        free(thread);
        return NULL;
    }
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

static void thread_trampoline(void)
{
    thread_t *self = g_current_thread;
    if (self && self->entry)
    {
        self->entry(self->arg);
    }
    process_exit(0);
}

void process_system_init(void)
{
    fpu_prepare_initial_state();

    g_process_list = NULL;
    g_current_process = NULL;
    g_current_thread = NULL;
    g_run_queue_head = NULL;
    g_run_queue_tail = NULL;
    g_next_pid = 1;

    process_t *idle_process = allocate_process("idle");
    if (!idle_process)
    {
        fatal("unable to allocate idle process");
    }
    idle_process->pid = 0;
    idle_process->state = PROCESS_STATE_READY;
    idle_process->cr3 = read_cr3();
    idle_process->next = g_process_list;
    g_process_list = idle_process;
    g_next_pid = 1;

    g_idle_thread = thread_create(idle_process, "idle", idle_thread_entry, NULL, PROCESS_DEFAULT_STACK_SIZE, true);
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

process_t *process_create_kernel(const char *name,
                                 thread_entry_t entry,
                                 void *arg,
                                 size_t stack_size)
{
    if (!entry)
    {
        return NULL;
    }

    process_t *proc = allocate_process(name);
    if (!proc)
    {
        return NULL;
    }

    thread_t *thread = thread_create(proc, name, entry, arg, stack_size, false);
    if (!thread)
    {
        free(proc);
        return NULL;
    }

    proc->main_thread = thread;
    proc->current_thread = thread;
    proc->next = g_process_list;
    g_process_list = proc;

    enqueue_thread(thread);
    return proc;
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

    thread_t *thread = process->main_thread;
    if (thread)
    {
        if (thread->in_run_queue)
        {
            remove_from_run_queue(thread);
        }
        if (thread->stack_base)
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

int process_join(process_t *process, int *status_out)
{
    if (!process)
    {
        return -1;
    }

    while (process->state != PROCESS_STATE_ZOMBIE)
    {
        process_yield();
    }

    if (status_out)
    {
        *status_out = process->exit_status;
    }
    return process->exit_status;
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
