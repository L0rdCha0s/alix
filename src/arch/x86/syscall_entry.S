.intel_syntax noprefix

.section .text

.global syscall_entry
.extern syscall_dispatch

syscall_entry:
    cld                     # DF = 0 for C/memcpy-safe
    push rax
    push rbx
    push rcx
    push rdx
    push rbp
    push rdi
    push rsi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    mov rdi, rsp            # frame -> saved regs (r15..rax, then HW frame)
    mov rsi, 0x80           # vector (ignored by your C)

    mov rbx, rsp            # save original RSP in a callee-saved reg
    and rsp, -16            # align for the CALL
    call syscall_dispatch
    mov rsp, rbx            # restore the exact stack pointer

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rsi
    pop rdi
    pop rbp
    pop rdx
    pop rcx
    pop rbx
    pop rax
    iretq
