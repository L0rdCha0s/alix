#include "process_internal.h"

typedef struct
{
    exception_frame_t frame;
    uintptr_t address;
    uint64_t preempt_resume;
    bool preempt_pending;
    fpu_state_t floating;
} vm_fault_state_t;

extern void process_resume_exception(exception_frame_t *) __attribute__((noreturn));

static void vm_fault_resume(void) __attribute__((noreturn));
static void vm_fault_resume(void)
{
    thread_t *thread = current_thread_local();
    vm_fault_state_t *state = thread->vm_fault_state;
    __asm__ volatile ("sti" ::: "memory");
    bool okay = process_vm_fault_page(thread->process, state->address,
        (state->frame.error_code & 2u) != 0, (state->frame.error_code & 16u) != 0);
    if (!okay) process_exit_signal(ALIX_SIGBUS);
    /* Only this thread accesses its saved frame. Cleanup owns it if killed
     * during a wait; the final copy/free/restore cannot be abandoned. */
    spinlock_preempt_disable();
    exception_frame_t saved = state->frame;
    fpu_state_t floating;
    memcpy(&floating, &state->floating, sizeof(floating));
    cpu_cli();
    thread->tls.preempt_resume_rip = state->preempt_resume;
    thread->preempt_pending = state->preempt_pending;
    thread->vm_fault_state = NULL;
    free(state);
    spinlock_preempt_enable();
    __asm__ volatile ("fxrstor64 %0" :: "m"(floating) : "memory");
    process_resume_exception(&saved);
}

bool process_vm_fault_enter(exception_frame_t *frame, uintptr_t address)
{
    if (!frame || (frame->cpu.cs & 3u) != 3u || (frame->error_code & 8u)) return false;
    thread_t *thread = current_thread_local();
    if (!thread || !thread->is_user || thread->vm_fault_state ||
        !process_vm_fault_access(thread->process, address,
            (frame->error_code & 2u) != 0, (frame->error_code & 16u) != 0)) return false;
    vm_fault_state_t *state = calloc(1, sizeof(*state));
    if (!state) return false;
    state->frame = *frame;
    state->address = address;
    state->preempt_resume = process_take_preempt_resume_rip();
    state->preempt_pending = thread->preempt_pending;
    thread->preempt_pending = false;
    __asm__ volatile ("fxsave64 %0" : "=m"(state->floating) :: "memory");
    thread->vm_fault_state = state;
    frame->cpu.rip = (uintptr_t)vm_fault_resume;
    frame->cpu.cs = GDT_SELECTOR_KERNEL_CODE;
    frame->cpu.ss = GDT_SELECTOR_KERNEL_DATA;
    frame->cpu.rflags = RFLAGS_RESERVED_BIT;
    frame->cpu.rsp = align_down_uintptr(thread->kernel_stack_top - 256u, 16u) - 8u;
    return true;
}
