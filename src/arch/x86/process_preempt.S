.intel_syntax noprefix

.global process_preempt_trampoline
.extern process_preempt_hook

process_preempt_trampoline:
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

    sub rsp, 8
    call process_preempt_hook
    add rsp, 8

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

    push qword ptr gs:[0]
    ret
