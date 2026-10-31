.intel_syntax noprefix
.section .text
.extern exception_dispatch

.global exception_divide_entry
exception_divide_entry:
    push 0
    push 0
    jmp exception_common

.global exception_invalid_opcode_entry
exception_invalid_opcode_entry:
    push 0
    push 6
    jmp exception_common

.global exception_stack_entry
exception_stack_entry:
    push 12
    jmp exception_common

.global exception_protection_entry
exception_protection_entry:
    push 13
    jmp exception_common

.global exception_page_entry
exception_page_entry:
    push 14
    jmp exception_common

# All five gates use an IST. Normalize error/no-error vectors before saving
# the GPR prefix. The hardware's RIP/CS/RFLAGS/RSP/SS frame stays untouched.
exception_common:
    cld
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
    mov rdi, rsp
    mov rbx, rsp
    and rsp, -16
    call exception_dispatch
    mov rsp, rbx
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
    add rsp, 16
    iretq

.section .note.GNU-stack,"",@progbits
