.intel_syntax noprefix

.global process_preempt_trampoline
.extern process_preempt_hook

#ifndef ALIX_PREEMPT_RESUME_SLOT
#define ALIX_PREEMPT_RESUME_SLOT gs:[0]
#endif

# process_preempt_trampoline
#
# Used when preempting kernel-mode execution:
# - snapshots the resume PC and flags before the C hook can be preempted,
# - saves all general-purpose registers,
# - calls `process_preempt_hook()` (which yields),
# - restores the interrupted flags and returns through the owned stack copy.
process_preempt_trampoline:
    push qword ptr ALIX_PREEMPT_RESUME_SLOT
    pushfq
    mov qword ptr ALIX_PREEMPT_RESUME_SLOT, 0
    cld
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    mov rbx, rsp
    and rsp, -16
    call process_preempt_hook
    mov rsp, rbx

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax

    popfq
    ret

.section .note.GNU-stack,"",@progbits
