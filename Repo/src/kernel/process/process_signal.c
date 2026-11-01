#include "errno.h"
#include "process_internal.h"
#include "signal_abi.h"
#include "syscall.h"

#define SIGNAL_USER_CS (GDT_SELECTOR_USER_CODE | 3u)
#define SIGNAL_USER_SS (GDT_SELECTOR_USER_DATA | 3u)
#define SIGNAL_RFLAGS_ALLOWED 0x0000000000210ED7ULL
#define SIGNAL_UNBLOCKABLE ((1ULL << (ALIX_SIGKILL - 1)) | (1ULL << (ALIX_SIGSTOP - 1)))

typedef struct process_signal_frame
{
    struct process_signal_frame *previous;
    uintptr_t address;
    uint64_t owner_tid, sequence;
    alix_signal_frame_t image;
    uint8_t scratch_fp[512] __attribute__((aligned(16)));
} process_signal_frame_t;

_Static_assert(sizeof(alix_sigaction_t) == 24, "signal action wire");
_Static_assert(sizeof(alix_siginfo_t) == 64, "signal info wire");
_Static_assert(sizeof(alix_stack_t) == 24, "alternate stack wire");
_Static_assert(sizeof(alix_mcontext_t) == 704, "native mcontext wire");
_Static_assert(__builtin_offsetof(alix_mcontext_t, fpregs) == 192, "native FP area");
_Static_assert(sizeof(alix_ucontext_t) == 768 && __builtin_offsetof(alix_ucontext_t, uc_mcontext) == 64,
               "native ucontext wire");
_Static_assert(sizeof(alix_signal_frame_t) == 896, "native signal frame");
_Static_assert(__builtin_offsetof(syscall_frame_t, rip) == 120, "syscall register prefix");
_Static_assert(__builtin_offsetof(exception_frame_t, vector) == 120, "exception register prefix");
_Static_assert((__builtin_offsetof(process_signal_frame_t, image) +
                __builtin_offsetof(alix_signal_frame_t, context) +
                __builtin_offsetof(alix_ucontext_t, uc_mcontext) +
                __builtin_offsetof(alix_mcontext_t, fpregs)) %
                       16 ==
                   0,
               "heap signal FP alignment");

static bool signal_number_valid(int number)
{
    return number > 0 && number < (int)ALIX_SIGNAL_COUNT;
}
static bool signal_job_control(int number)
{
    return number >= ALIX_SIGCONT && number <= ALIX_SIGTTOU;
}
static uint64_t signal_bit(int number)
{
    return 1ULL << (number - 1);
}
static uint64_t signal_mask_valid(uint64_t mask)
{
    return mask & ALIX_SIGNAL_MASK & ~SIGNAL_UNBLOCKABLE;
}
static bool signal_default_ignored(int number)
{
    return number == ALIX_SIGCHLD || number == ALIX_SIGURG || number == ALIX_SIGWINCH;
}
static bool signal_ignored(const alix_sigaction_t *action, int number)
{
    return action->handler == 1 || (!action->handler && signal_default_ignored(number));
}
static bool signal_user_thread(thread_t *thread)
{
    return thread && thread->is_user && thread->process && thread->process->is_user &&
           thread_lifetime_active(thread) && !thread->exited && !thread->pending_destroy;
}

/* A single queued record distinguishes policy termination from an unrelated
 * user fault, while retaining the PID/TID and original hardware instruction. */
static void signal_report_termination(thread_t *thread, int number, const char *source, uint64_t vector,
                                      uint64_t rip)
{
    serial_printf(
        "process: default signal pid=%llu tid=%llu signo=%d status=%d source=%s vector=%llu rip=0x%016llX",
        (unsigned long long)thread->process->pid, (unsigned long long)thread->tid, number, 128 + number,
        source, (unsigned long long)vector, (unsigned long long)rip);
}

bool process_signal_pending_locked(thread_t *thread)
{
    return signal_user_thread(thread) && ((thread->signal_pending | thread->process->signal_pending) &
                                          ~thread->signal_mask & ALIX_SIGNAL_MASK) != 0;
}

static void signal_notify_locked(thread_t *thread)
{
    /* Running/queued I/O cancellation has caller-abandonment semantics today.
     * Preserve its result and defer caught delivery until the caller finishes. */
    if (thread->io_request)
        return;
    if (thread->futex_waiting)
    {
        thread->futex_interrupted = true;
        __atomic_store_n(&thread->futex_notified, true, __ATOMIC_RELEASE);
        wait_queue_wake_all_locked(&thread->futex_queue);
    }
    else if (thread->signal_sleeping)
    {
        thread->signal_sleep_interrupted = true;
        wait_queue_wake_all_locked(&thread->signal_wait_queue);
    }
    thread->time_slice_remaining = 0;
}

static int signal_select_locked(thread_t *thread, alix_sigaction_t *action, alix_siginfo_t *info)
{
    uint64_t pending =
        (thread->signal_pending | thread->process->signal_pending) & ~thread->signal_mask & ALIX_SIGNAL_MASK;
    while (pending)
    {
        int number = __builtin_ctzll(pending) + 1;
        uint64_t bit = signal_bit(number);
        *action = thread->process->signal_actions[number];
        if (thread->signal_pending & bit)
        {
            *info = thread->signal_info[number];
            thread->signal_pending &= ~bit;
        }
        else
        {
            *info = thread->process->signal_info[number];
            thread->process->signal_pending &= ~bit;
        }
        if (!signal_ignored(action, number))
        {
            /* Selection and the one-shot reset are one scheduler transaction.
             * A later sigaction must not be erased by frame publication. */
            if (action->handler > 1 && (action->flags & ALIX_SA_RESETHAND))
                memset(&thread->process->signal_actions[number], 0, sizeof(*action));
            return number;
        }
        pending &= ~bit;
    }
    return 0;
}

static void signal_fxsave(uint8_t *image)
{
    memset(image, 0, 512);
    __asm__ volatile("fxsave64 %0" : "=m"(*(uint8_t (*)[512])image));
}

static bool signal_stack_contains(const alix_stack_t *stack, uintptr_t address)
{
    uintptr_t base = (uintptr_t)stack->ss_sp;
    return stack->ss_size && !(stack->ss_flags & ALIX_SS_DISABLE) && address >= base &&
           address - base < stack->ss_size;
}

/* A downward-growing stack can have RSP exactly at its upper boundary.
 * Use the saved instruction's actual RSP, never a historical handler flag. */
static bool signal_stack_pointer_on_stack(const alix_stack_t *stack, uintptr_t rsp)
{
    uintptr_t base = (uintptr_t)stack->ss_sp;
    return stack->ss_size && !(stack->ss_flags & ALIX_SS_DISABLE) && rsp >= base &&
           rsp - base <= stack->ss_size;
}

/* Called with local IRQs disabled. The only kernel frame pointers are these
 * call-bounded inputs/outputs; the durable record contains value copies only. */
static bool signal_install(thread_t *thread, void *gprs, interrupt_frame_t *cpu,
                           const alix_sigaction_t *action, const alix_siginfo_t *info, uint64_t trap,
                           uint64_t error, uintptr_t fault, uint64_t preempt_resume)
{
    if (thread->signal_depth >= ALIX_SIGNAL_MAX_DEPTH || thread->signal_sequence == UINT64_MAX)
        return false;
    process_signal_frame_t *record = calloc(1, sizeof(*record));
    if (!record)
        return false;
    if (((uintptr_t)&record->image.context.uc_mcontext.fpregs & 15u) || ((uintptr_t)record->scratch_fp & 15u))
    {
        free(record);
        return false;
    }
    alix_ucontext_t *context = &record->image.context;
    alix_mcontext_t *machine = &context->uc_mcontext;
    signal_fxsave(machine->fpregs);
    memcpy(machine, gprs, 120);
    memcpy(&machine->rip, cpu, sizeof(*cpu));
    if (preempt_resume)
    {
        /* The preempt stub stores flags,r15..rax below its protected red zone. */
        uint64_t *saved = calloc(16, sizeof(*saved));
        if (!saved || !user_copy_from_user(saved, (const void *)(uintptr_t)cpu->rsp, 16 * sizeof(*saved)))
        {
            free(saved);
            free(record);
            return false;
        }
        /* The legacy user stub push order differs from exception_entry. */
        memcpy(machine, saved + 1, 8 * sizeof(uint64_t));
        machine->rdi = saved[9];
        machine->rsi = saved[10];
        machine->rbp = saved[11];
        machine->rbx = saved[12];
        machine->rdx = saved[13];
        machine->rcx = saved[14];
        machine->rax = saved[15];
        machine->rflags = saved[0];
        free(saved);
        if (cpu->rsp > UINTPTR_MAX - ALIX_PREEMPT_SAVE_BYTES)
        {
            free(record);
            return false;
        }
        machine->rsp = cpu->rsp + ALIX_PREEMPT_SAVE_BYTES;
        machine->rip = preempt_resume;
    }
    machine->trapno = trap;
    machine->error_code = error;
    machine->cr2 = fault;
    context->uc_version = ALIX_SIGNAL_ABI_VERSION;
    context->uc_size = sizeof(*context);
    context->uc_flags = ALIX_UC_FXSAVE64;
    context->uc_sigmask = thread->signal_mask;
    context->uc_stack = thread->signal_altstack;
    context->uc_stack.reserved = 0;
    bool interrupted_onstack = signal_stack_pointer_on_stack(&thread->signal_altstack, machine->rsp);
    if (!context->uc_stack.ss_size)
        context->uc_stack.ss_flags = ALIX_SS_DISABLE;
    else if (interrupted_onstack)
        context->uc_stack.ss_flags = ALIX_SS_ONSTACK;
    uintptr_t top = machine->rsp;
    bool use_altstack = interrupted_onstack;
    if ((action->flags & ALIX_SA_ONSTACK) && !interrupted_onstack && thread->signal_altstack.ss_size &&
        !(thread->signal_altstack.ss_flags & ALIX_SS_DISABLE))
    {
        top = (uintptr_t)thread->signal_altstack.ss_sp + thread->signal_altstack.ss_size;
        use_altstack = true;
    }
    if (top < 128 + sizeof(record->image) + 16)
    {
        free(record);
        return false;
    }
    uintptr_t address = (top - 128 - sizeof(record->image)) & ~(uintptr_t)15;
    uintptr_t entry_rsp = address - 8;
    if (!user_ptr_range_valid((void *)entry_rsp, sizeof(record->image) + 8) ||
        !user_ptr_range_valid((void *)(uintptr_t)machine->rip, 1) || machine->rsp < USER_ADDRESS_SPACE_BASE ||
        machine->rsp > USER_ADDRESS_SPACE_LIMIT + 1)
    {
        free(record);
        return false;
    }
    if (use_altstack && !signal_stack_contains(&thread->signal_altstack, entry_rsp))
    {
        free(record);
        return false;
    }
    if (!process_signal_prepare_user_frame(thread->process, entry_rsp, sizeof(record->image) + 8))
    {
        free(record);
        return false;
    }
    record->address = address;
    record->owner_tid = thread->tid;
    record->sequence = ++thread->signal_sequence;
    record->image.magic = ALIX_SIGNAL_FRAME_MAGIC;
    record->image.version = ALIX_SIGNAL_ABI_VERSION;
    record->image.size = sizeof(record->image);
    record->image.owner_tid = thread->tid;
    record->image.sequence = record->sequence;
    record->image.frame_address = address;
    record->image.info = *info;
    uintptr_t restorer = USER_STUB_CODE_BASE + ALIX_SIGNAL_RESTORER_OFFSET;
    if (!user_copy_to_user((void *)address, &record->image, sizeof(record->image)) ||
        !user_copy_to_user((void *)entry_rsp, &restorer, sizeof(restorer)))
    {
        free(record);
        return false;
    }
    uint64_t lock = scheduler_lock_acquire("signal_publish_frame");
    record->previous = thread->signal_frames;
    thread->signal_frames = record;
    ++thread->signal_depth;
    thread->signal_mask =
        signal_mask_valid(thread->signal_mask | action->mask |
                          ((action->flags & ALIX_SA_NODEFER) ? 0 : signal_bit(info->si_signo)));
    thread->signal_onstack = signal_stack_contains(&thread->signal_altstack, entry_rsp);
    scheduler_lock_release(lock);
    /* Every handler enters the native C ABI with DF clear and IF enabled. */
    machine->rdi = (uint64_t)info->si_signo;
    machine->rsi = address + __builtin_offsetof(alix_signal_frame_t, info);
    machine->rdx = address + __builtin_offsetof(alix_signal_frame_t, context);
    machine->rip = action->handler;
    machine->rsp = entry_rsp;
    machine->cs = SIGNAL_USER_CS;
    machine->ss = SIGNAL_USER_SS;
    machine->rflags = (machine->rflags & SIGNAL_RFLAGS_ALLOWED & ~(1ULL << 10)) | RFLAGS_DEFAULT;
    memcpy(gprs, machine, 120);
    memcpy(cpu, &machine->rip, sizeof(*cpu));
    return true;
}

bool process_signal_fault(exception_frame_t *frame, uintptr_t fault)
{
    if (!frame || (frame->cpu.cs & 3u) != 3u)
        return false;
    thread_t *thread = current_thread_local();
    if (!signal_user_thread(thread))
        return false;
    int number = frame->vector == 6 ? ALIX_SIGILL : frame->vector == 0 ? ALIX_SIGFPE : ALIX_SIGSEGV;
    uint64_t flags = cpu_save_flags();
    cpu_cli();
    uint64_t lock = scheduler_lock_acquire("signal_fault_select");
    alix_sigaction_t action = thread->process->signal_actions[number];
    bool caught = action.handler > 1 && !(thread->signal_mask & signal_bit(number));
    if (caught && (action.flags & ALIX_SA_RESETHAND))
        memset(&thread->process->signal_actions[number], 0, sizeof(action));
    scheduler_lock_release(lock);
    alix_siginfo_t *info = calloc(1, sizeof(*info));
    if (!info)
        caught = false;
    if (caught)
    {
        info->si_signo = number;
        info->si_addr = (void *)(frame->vector == 14 ? fault : frame->cpu.rip);
        info->si_code = number == ALIX_SIGSEGV
                            ? (process_signal_address_mapped(thread->process, fault) ? ALIX_SEGV_ACCERR
                                                                                     : ALIX_SEGV_MAPERR)
                        : number == ALIX_SIGILL ? ALIX_ILL_ILLOPC
                                                : ALIX_FPE_INTDIV;
        info->si_pid = (int32_t)thread->process->pid;
        info->si_uid = thread->process->uid;
        info->si_tid = thread->tid;
        info->si_trapno = frame->vector;
        info->si_error = frame->error_code;
        caught = signal_install(thread, frame, &frame->cpu, &action, info, frame->vector, frame->error_code,
                                fault, 0);
    }
    free(info);
    if (!caught)
    {
        thread->signal_fault_number = number;
        signal_report_termination(thread, number, "fault", frame->vector, frame->cpu.rip);
    }
    cpu_restore_flags(flags);
    return caught;
}

void process_signal_syscall_return(syscall_frame_t *frame, uint64_t preempt_resume)
{
    if (!frame || (frame->cs & 3u) != 3u)
        return;
    thread_t *thread = current_thread_local();
    if (!signal_user_thread(thread) || thread->io_request)
        return;
    if (preempt_resume && frame->rip != USER_PREEMPT_STUB_BASE + ALIX_PREEMPT_RETURN_OFFSET)
        preempt_resume = 0;
    uint64_t flags = cpu_save_flags();
    cpu_cli();
    uint64_t lock = scheduler_lock_acquire("signal_pending_check");
    bool pending = process_signal_pending_locked(thread);
    scheduler_lock_release(lock);
    if (!pending)
    {
        cpu_restore_flags(flags);
        return;
    }
    alix_sigaction_t *action = calloc(1, sizeof(*action));
    alix_siginfo_t *info = calloc(1, sizeof(*info));
    if (!action || !info)
    {
        free(action);
        free(info);
        cpu_restore_flags(flags);
        /* An unmasked self-raise must not report success without delivery. */
        process_exit_signal(ALIX_SIGSEGV);
    }
    lock = scheduler_lock_acquire("signal_pending_select");
    int number = signal_select_locked(thread, action, info);
    scheduler_lock_release(lock);
    if (!number)
    {
        free(action);
        free(info);
        cpu_restore_flags(flags);
        return;
    }
    bool okay = action->handler > 1 && signal_install(thread, frame, (interrupt_frame_t *)&frame->rip, action,
                                                      info, 0, 0, 0, preempt_resume);
    free(action);
    free(info);
    if (!okay)
    {
        cpu_restore_flags(flags);
        process_exit_signal(number ? number : ALIX_SIGSEGV);
    }
    cpu_restore_flags(flags);
}

static bool signal_return_valid(thread_t *thread, process_signal_frame_t *record, uintptr_t address,
                                uint32_t mxcsr_mask)
{
    const alix_signal_frame_t *image = &record->image;
    const alix_ucontext_t *context = &image->context;
    const alix_mcontext_t *machine = &context->uc_mcontext;
    uint32_t mxcsr;
    memcpy(&mxcsr, machine->fpregs + 24, sizeof(mxcsr));
    if (!mxcsr_mask)
        mxcsr_mask = 0x0000FFBFu;
    return record->owner_tid == thread->tid && record->address == address &&
           image->magic == ALIX_SIGNAL_FRAME_MAGIC && image->version == ALIX_SIGNAL_ABI_VERSION &&
           image->size == sizeof(*image) && image->owner_tid == thread->tid &&
           image->sequence == record->sequence && image->frame_address == address &&
           context->uc_version == ALIX_SIGNAL_ABI_VERSION && context->uc_size == sizeof(*context) &&
           context->uc_flags == ALIX_UC_FXSAVE64 && !(context->uc_sigmask & ~ALIX_SIGNAL_MASK) &&
           machine->cs == SIGNAL_USER_CS && machine->ss == SIGNAL_USER_SS &&
           !(machine->rflags & ~SIGNAL_RFLAGS_ALLOWED) &&
           (machine->rflags & RFLAGS_DEFAULT) == RFLAGS_DEFAULT &&
           user_ptr_range_valid((const void *)(uintptr_t)machine->rip, 1) &&
           machine->rsp >= USER_ADDRESS_SPACE_BASE && machine->rsp <= USER_ADDRESS_SPACE_LIMIT + 1 &&
           !(mxcsr & ~mxcsr_mask);
}

int process_signal_return(syscall_frame_t *frame, uintptr_t address)
{
    thread_t *thread = current_thread_local();
    if (!frame || !signal_user_thread(thread))
        return -EPERM;
    uint64_t flags = cpu_save_flags();
    cpu_cli();
    process_signal_frame_t *record = thread->signal_frames;
    if (!record || record->address != address || record->owner_tid != thread->tid)
    {
        cpu_restore_flags(flags);
        return -EPERM;
    }
    if (!user_copy_from_user(&record->image, (const void *)address, sizeof(record->image)))
    {
        cpu_restore_flags(flags);
        return -EFAULT;
    }
    signal_fxsave(record->scratch_fp);
    uint32_t mxcsr_mask;
    memcpy(&mxcsr_mask, record->scratch_fp + 28, sizeof(mxcsr_mask));
    if (!signal_return_valid(thread, record, address, mxcsr_mask))
    {
        cpu_restore_flags(flags);
        return -EINVAL;
    }
    uint64_t lock = scheduler_lock_acquire("signal_return_commit");
    thread->signal_mask = signal_mask_valid(record->image.context.uc_sigmask);
    thread->signal_onstack =
        signal_stack_pointer_on_stack(&thread->signal_altstack, record->image.context.uc_mcontext.rsp);
    thread->signal_frames = record->previous;
    --thread->signal_depth;
    scheduler_lock_release(lock);
    memcpy(frame, &record->image.context.uc_mcontext, sizeof(*frame));
    memcpy(&thread->fpu_state, record->image.context.uc_mcontext.fpregs, 512);
    free(record);
    fpu_restore_state(&thread->fpu_state);
    /* Leave IRQs off until syscall_entry's IRET restores validated user flags. */
    return 0;
}

int process_signal_sigaction(int number, uintptr_t input, uintptr_t output, size_t size)
{
    thread_t *thread = current_thread_local();
    if (!signal_user_thread(thread))
        return -EPERM;
    if (!signal_number_valid(number) || size != sizeof(alix_sigaction_t) || (input && number == ALIX_SIGKILL))
        return -EINVAL;
    if (signal_job_control(number))
        return -ENOTSUP;
    spinlock_preempt_disable();
    alix_sigaction_t *action = calloc(1, sizeof(*action));
    if (!action)
    {
        spinlock_preempt_enable();
        return -ENOMEM;
    }
    int result = 0;
    if (input)
    {
        if (!user_copy_from_user(action, (void *)input, sizeof(*action)))
            result = -EFAULT;
        else if ((action->flags & ~0x1fu) || (action->mask & ~ALIX_SIGNAL_MASK))
            result = -EINVAL;
        else if (action->handler > 1 && !user_ptr_range_valid((void *)action->handler, 1))
            result = -EINVAL;
        action->reserved = 0;
    }
    if (!result)
    {
        uint64_t lock = scheduler_lock_acquire("signal_action");
        process_t *process = thread->process;
        if (output && !user_copy_to_user((void *)output, &process->signal_actions[number], sizeof(*action)))
            result = -EFAULT;
        if (!result && input)
        {
            process->signal_actions[number] = *action;
            if (signal_ignored(action, number))
            {
                process->signal_pending &= ~signal_bit(number);
                spinlock_lock(&process->threads_lock);
                for (thread_t *target = process->threads; target; target = target->process_next)
                    target->signal_pending &= ~signal_bit(number);
                spinlock_unlock(&process->threads_lock);
            }
        }
        scheduler_lock_release(lock);
    }
    free(action);
    spinlock_preempt_enable();
    return result;
}

int process_signal_sigprocmask(int how, uintptr_t input, uintptr_t output)
{
    thread_t *thread = current_thread_local();
    if (!signal_user_thread(thread))
        return -EPERM;
    uint64_t value = 0;
    if (input && !user_copy_from_user(&value, (void *)input, sizeof(value)))
        return -EFAULT;
    if (value & ~ALIX_SIGNAL_MASK)
        return -EINVAL;
    if (input && (how < ALIX_SIG_BLOCK || how > ALIX_SIG_SETMASK))
        return -EINVAL;
    if (how == ALIX_SIG_PENDING && (input || !output))
        return -EINVAL;
    uint64_t lock = scheduler_lock_acquire("signal_mask");
    uint64_t old = how == ALIX_SIG_PENDING ? thread->signal_pending | thread->process->signal_pending
                                           : thread->signal_mask;
    int result = output && !user_copy_to_user((void *)output, &old, sizeof(old)) ? -EFAULT : 0;
    if (!result && input)
    {
        if (how == ALIX_SIG_BLOCK)
            value |= old;
        else if (how == ALIX_SIG_UNBLOCK)
            value = old & ~value;
        thread->signal_mask = signal_mask_valid(value);
    }
    scheduler_lock_release(lock);
    return result;
}

int process_signal_sigaltstack(uintptr_t input, uintptr_t output, size_t size, uintptr_t current_rsp)
{
    thread_t *thread = current_thread_local();
    if (!signal_user_thread(thread))
        return -EPERM;
    if (size != sizeof(alix_stack_t))
        return -EINVAL;
    spinlock_preempt_disable();
    alix_stack_t *stack = calloc(1, sizeof(*stack));
    if (!stack)
    {
        spinlock_preempt_enable();
        return -ENOMEM;
    }
    int result = 0;
    if (input)
    {
        if (!user_copy_from_user(stack, (void *)input, sizeof(*stack)))
            result = -EFAULT;
        else if (stack->ss_flags != 0 && stack->ss_flags != ALIX_SS_DISABLE)
            result = -EINVAL;
        else if (!(stack->ss_flags & ALIX_SS_DISABLE) && stack->ss_size < ALIX_MINSIGSTKSZ)
            result = -ENOMEM;
        else if (!(stack->ss_flags & ALIX_SS_DISABLE) && !user_ptr_range_valid(stack->ss_sp, stack->ss_size))
            result = -EINVAL;
        stack->reserved = 0;
    }
    if (!result)
    {
        uint64_t lock = scheduler_lock_acquire("signal_altstack");
        thread->signal_onstack = signal_stack_pointer_on_stack(&thread->signal_altstack, current_rsp);
        if (input && thread->signal_onstack)
            result = -EPERM;
        alix_stack_t old = thread->signal_altstack;
        old.ss_flags = thread->signal_onstack ? ALIX_SS_ONSTACK : old.ss_size ? 0 : ALIX_SS_DISABLE;
        old.reserved = 0;
        if (!result && output && !user_copy_to_user((void *)output, &old, sizeof(old)))
            result = -EFAULT;
        if (!result && input)
        {
            if (stack->ss_flags & ALIX_SS_DISABLE)
                memset(&thread->signal_altstack, 0, sizeof(*stack));
            else
                thread->signal_altstack = *stack;
            thread->signal_onstack = signal_stack_pointer_on_stack(&thread->signal_altstack, current_rsp);
        }
        scheduler_lock_release(lock);
    }
    free(stack);
    spinlock_preempt_enable();
    return result;
}

static void signal_queue_thread_locked(thread_t *target, int number, const alix_siginfo_t *info)
{
    uint64_t bit = signal_bit(number);
    if (!(target->signal_pending & bit))
        target->signal_info[number] = *info;
    target->signal_pending |= bit;
    if (!(target->signal_mask & bit))
        signal_notify_locked(target);
}

int process_signal_raise(int number, uint64_t tid)
{
    thread_t *self = current_thread_local();
    if (!signal_user_thread(self))
        return -EPERM;
    if (number && !signal_number_valid(number))
        return -EINVAL;
    if (signal_job_control(number))
        return -ENOTSUP;
    if (!tid)
        tid = self->tid;
    uint64_t lock = scheduler_lock_acquire("signal_raise");
    process_t *process = self->process;
    spinlock_lock(&process->threads_lock);
    thread_t *target = process->threads;
    while (target && target->tid != tid)
        target = target->process_next;
    int result = signal_user_thread(target) ? 0 : -ESRCH;
    bool terminate = false;
    if (!result && number)
    {
        alix_sigaction_t action = process->signal_actions[number];
        if (number == ALIX_SIGKILL || (!action.handler && !signal_default_ignored(number) &&
                                       !(target->signal_mask & signal_bit(number))))
            terminate = true;
        else if (!signal_ignored(&action, number))
        {
            alix_siginfo_t info = {.si_signo = number,
                                   .si_code = ALIX_SI_TKILL,
                                   .si_pid = (int32_t)process->pid,
                                   .si_uid = process->uid,
                                   .si_tid = self->tid};
            signal_queue_thread_locked(target, number, &info);
        }
    }
    spinlock_unlock(&process->threads_lock);
    scheduler_lock_release(lock);
    if (terminate)
    {
        signal_report_termination(self, number, "raise", 0, 0);
        process_exit_signal(number);
    }
    if (!result && number)
        smp_broadcast_schedule_ipi(false);
    return result;
}

int process_signal_kill(int32_t pid, int number)
{
    thread_t *self = current_thread_local();
    if (!signal_user_thread(self))
        return -EPERM;
    if (number && !signal_number_valid(number))
        return -EINVAL;
    if (pid <= 0 || signal_job_control(number))
        return -ENOTSUP;
    spinlock_preempt_disable();
    uint64_t flags = spinlock_lock_irqsave(&g_process_lock);
    process_t *process = g_process_list;
    while (process && process->pid != (uint64_t)pid)
        process = process->next;
    int result =
        !process || process->magic != PROCESS_MAGIC || process->lifetime_state != PROCESS_LIFETIME_ALIVE
            ? -ESRCH
        : !process->is_user || (self->process->uid != 0 && self->process->uid != process->uid) ? -EPERM
        : process->join_waiters == UINT32_MAX                                                  ? -EAGAIN
                                                                                               : 0;
    if (!result)
        __atomic_add_fetch(&process->join_waiters, 1u, __ATOMIC_ACQ_REL);
    spinlock_unlock_irqrestore(&g_process_lock, flags);
    if (result)
    {
        spinlock_preempt_enable();
        return result;
    }
    bool terminate = false;
    uint64_t lock = scheduler_lock_acquire("signal_kill");
    if (number && process->state != PROCESS_STATE_ZOMBIE)
    {
        alix_sigaction_t action = process->signal_actions[number];
        if (number == ALIX_SIGKILL)
            terminate = true;
        else if (!signal_ignored(&action, number))
        {
            uint64_t bit = signal_bit(number);
            alix_siginfo_t info = {.si_signo = number,
                                   .si_code = ALIX_SI_USER,
                                   .si_pid = (int32_t)self->process->pid,
                                   .si_uid = self->process->uid,
                                   .si_tid = self->tid};
            spinlock_lock(&process->threads_lock);
            thread_t *target = NULL;
            for (thread_t *cursor = process->threads; cursor; cursor = cursor->process_next)
                if (signal_user_thread(cursor) && !(cursor->signal_mask & bit))
                {
                    target = cursor;
                    if (!cursor->io_request)
                        break;
                }
            if (target)
            {
                if (!action.handler)
                    terminate = true;
                else
                {
                    if (process->signal_pending & bit)
                    {
                        info = process->signal_info[number];
                        process->signal_pending &= ~bit;
                    }
                    signal_queue_thread_locked(target, number, &info);
                }
            }
            else
            {
                if (!(process->signal_pending & bit))
                    process->signal_info[number] = info;
                process->signal_pending |= bit;
            }
            spinlock_unlock(&process->threads_lock);
        }
    }
    scheduler_lock_release(lock);
    bool self_target = process == self->process;
    if (terminate && !self_target)
        (void)process_kill_signal(process, number);
    process_release_reference(process);
    spinlock_preempt_enable();
    if (terminate && self_target)
        process_exit_signal(number);
    if (number)
        smp_broadcast_schedule_ipi(false);
    return 0;
}

static bool signal_sleep_ready(void *context)
{
    thread_t *thread = context;
    return thread->signal_sleep_interrupted || process_signal_pending_locked(thread);
}

int process_signal_sleep(uint32_t milliseconds, uintptr_t remaining_user)
{
    thread_t *thread = current_thread_local();
    if (!signal_user_thread(thread))
        return -EPERM;
    uint32_t remaining = 0;
    if (remaining_user && !user_copy_to_user((void *)remaining_user, &remaining, sizeof(remaining)))
        return -EFAULT;
    if (!milliseconds)
        return 0;
    uint64_t frequency = timer_frequency();
    if (!frequency)
        frequency = 1000;
    uint64_t ticks = (milliseconds / 1000u) * frequency + ((milliseconds % 1000u) * frequency + 999u) / 1000u;
    if (!ticks)
        ticks = 1;
    uint64_t start = timer_ticks(), deadline = ticks > UINT64_MAX - start ? UINT64_MAX : start + ticks;
    uint64_t lock = scheduler_lock_acquire("signal_sleep_register");
    wait_queue_init(&thread->signal_wait_queue);
    thread->signal_sleep_interrupted = false;
    thread->signal_sleeping = true;
    scheduler_lock_release(lock);
    uint64_t now = timer_ticks();
    if (now < deadline)
        (void)wait_queue_wait_timeout(&thread->signal_wait_queue, signal_sleep_ready, thread, deadline - now);
    lock = scheduler_lock_acquire("signal_sleep_finish");
    bool interrupted = signal_sleep_ready(thread);
    thread->signal_sleeping = false;
    thread->signal_sleep_interrupted = false;
    now = timer_ticks();
    scheduler_lock_release(lock);
    if (interrupted && now < deadline)
    {
        uint64_t left = deadline - now;
        uint64_t ms = (left / frequency) * 1000u + ((left % frequency) * 1000u + frequency - 1) / frequency;
        remaining = (uint32_t)(ms > milliseconds ? milliseconds : ms);
    }
    if (remaining_user && !user_copy_to_user((void *)remaining_user, &remaining, sizeof(remaining)))
        return -EFAULT;
    return interrupted ? -EINTR : 0;
}

void process_signal_thread_cleanup(thread_t *thread)
{
    if (!thread)
        return;
    process_signal_frame_t *record = thread->signal_frames;
    thread->signal_frames = NULL;
    thread->signal_depth = 0;
    while (record)
    {
        process_signal_frame_t *previous = record->previous;
        free(record);
        record = previous;
    }
}

_Static_assert(sizeof(alix_sigjmp_state_t) == 128 && __builtin_offsetof(alix_sigjmp_state_t, version) == 64 &&
               __builtin_offsetof(alix_sigjmp_state_t, reserved_words) == 112, "native signal checkpoint wire");
/* Signal-aware checkpoints contain values only. No user-buffer address or
 * per-checkpoint heap record is retained after CAPTURE returns. */
static uint64_t g_signal_jump_next_epoch = 1;

static uint64_t signal_jump_allocate_epoch(void)
{
    uint64_t next = __atomic_load_n(&g_signal_jump_next_epoch, __ATOMIC_RELAXED);
    for (;;)
    {
        if (!next || next == UINT64_MAX)
            return 0;
        if (__atomic_compare_exchange_n(&g_signal_jump_next_epoch, &next, next + 1, false, __ATOMIC_RELAXED,
                                        __ATOMIC_RELAXED))
            return next;
    }
}

static bool signal_jump_user_registers_valid(const alix_sigjmp_state_t *saved)
{
    return user_ptr_range_valid((const void *)(uintptr_t)saved->rip, 1) &&
           saved->rsp >= USER_ADDRESS_SPACE_BASE && saved->rsp <= USER_ADDRESS_SPACE_LIMIT + 1;
}

int process_signal_jump(syscall_frame_t *frame, uint32_t operation, uintptr_t buffer, size_t size,
                        uint64_t argument)
{
    thread_t *thread = current_thread_local();
    if (!frame || (frame->cs & 3u) != 3u || !signal_user_thread(thread))
        return -EPERM;
    if (size != sizeof(alix_sigjmp_state_t) || operation > ALIX_SIGJUMP_RESTORE)
        return -EINVAL;
    if (!user_ptr_range_valid((void *)buffer, size))
        return -EFAULT;
    uint64_t irq = cpu_save_flags();
    cpu_cli();
    alix_sigjmp_state_t *saved = calloc(1, sizeof(*saved));
    if (!saved)
    {
        cpu_restore_flags(irq);
        return -ENOMEM;
    }
    size_t input_size = operation == ALIX_SIGJUMP_CAPTURE ? ALIX_SIGJUMP_REGISTER_BYTES : sizeof(*saved);
    int result = user_copy_from_user(saved, (const void *)buffer, input_size) ? 0 : -EFAULT;
    if (!result && !signal_jump_user_registers_valid(saved))
        result = -EINVAL;
    if (!result && operation == ALIX_SIGJUMP_CAPTURE)
    {
        uint64_t return_pc = 0;
        if (frame->rsp > UINTPTR_MAX - 8 || saved->rsp != frame->rsp + 8)
            result = -EINVAL;
        else if (!user_copy_from_user(&return_pc, (const void *)(uintptr_t)frame->rsp, sizeof(return_pc)))
            result = -EFAULT;
        else if (saved->rip != return_pc)
            result = -EINVAL;
        if (!result && !thread->signal_jump_epoch)
        {
            thread->signal_jump_epoch = signal_jump_allocate_epoch();
            if (!thread->signal_jump_epoch)
                result = -EOVERFLOW;
        }
        if (!result)
        {
            uint64_t lock = scheduler_lock_acquire("signal_jump_capture");
            saved->version = ALIX_SIGJUMP_VERSION;
            saved->size = sizeof(*saved);
            saved->owner_tid = thread->tid;
            saved->epoch = thread->signal_jump_epoch;
            saved->frame_sequence = thread->signal_frames ? thread->signal_frames->sequence : 0;
            saved->flags = argument ? ALIX_SIGJUMP_SAVE_MASK : 0;
            saved->saved_mask = argument ? thread->signal_mask : 0;
            scheduler_lock_release(lock);
            if (!user_copy_to_user((void *)buffer, saved, sizeof(*saved)))
                result = -EFAULT;
        }
    }
    else if (!result)
    {
        if (saved->version != ALIX_SIGJUMP_VERSION || saved->size != sizeof(*saved) ||
            (saved->flags & ~ALIX_SIGJUMP_SAVE_MASK) || saved->reserved || saved->reserved_words[0] ||
            saved->reserved_words[1] || (saved->saved_mask & ~ALIX_SIGNAL_MASK) ||
            (saved->saved_mask & SIGNAL_UNBLOCKABLE) ||
            (!(saved->flags & ALIX_SIGJUMP_SAVE_MASK) && saved->saved_mask))
            result = -EINVAL;
        else if (saved->owner_tid != thread->tid || !saved->epoch ||
                 saved->epoch != thread->signal_jump_epoch)
            result = -EPERM;
        else if (thread->io_request)
            result = -EBUSY;
        if (!result)
        {
            uint64_t lock = scheduler_lock_acquire("signal_jump_restore");
            process_signal_frame_t *target = thread->signal_frames;
            unsigned drop = 0;
            while (target && target->sequence != saved->frame_sequence)
            {
                target = target->previous;
                ++drop;
            }
            if ((saved->frame_sequence && !target) || drop > thread->signal_depth)
                result = -EINVAL;
            if (!result)
            {
                process_signal_frame_t *retired = thread->signal_frames;
                thread->signal_frames = target;
                thread->signal_depth -= drop;
                if (saved->flags & ALIX_SIGJUMP_SAVE_MASK)
                    thread->signal_mask = saved->saved_mask;
                thread->signal_onstack = signal_stack_pointer_on_stack(&thread->signal_altstack, saved->rsp);
                scheduler_lock_release(lock);
                while (retired != target)
                {
                    process_signal_frame_t *previous = retired->previous;
                    free(retired);
                    retired = previous;
                }
                frame->rbx = saved->rbx;
                frame->rbp = saved->rbp;
                frame->r12 = saved->r12;
                frame->r13 = saved->r13;
                frame->r14 = saved->r14;
                frame->r15 = saved->r15;
                frame->rsp = saved->rsp;
                frame->rip = saved->rip;
                int value = (int32_t)argument;
                frame->rax = (uint64_t)(int64_t)(value ? value : 1);
                frame->cs = SIGNAL_USER_CS;
                frame->ss = SIGNAL_USER_SS;
                frame->rflags = (frame->rflags & SIGNAL_RFLAGS_ALLOWED & ~(1ULL << 10)) | RFLAGS_DEFAULT;
                free(saved);
                /* Preserve the current FP environment; abandoned handler
                 * snapshots are not ordinary sigreturn targets. Keep IRQs
                 * disabled through the direct continuation/pending delivery. */
                return 0;
            }
            scheduler_lock_release(lock);
        }
    }
    free(saved);
    cpu_restore_flags(irq);
    return result;
}
