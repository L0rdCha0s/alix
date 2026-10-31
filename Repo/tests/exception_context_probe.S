.intel_syntax noprefix
.section .text
.global exception_context_probe

# void exception_context_probe(void *discarded_page, struct result *out)
# All output storage belongs to the calling thread and is on its user heap.
exception_context_probe:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push rdi
    push rsi
    mov [rsi + 128], rsp
    movdqu xmm0, [rip + .Lvector]
    fld tbyte ptr [rip + .Lextended]
    mov rax, 0x1111111111111111
    mov rbx, 0x2222222222222222
    mov rcx, 0x3333333333333333
    mov rdx, 0x4444444444444444
    mov rsi, 0x5555555555555555
    mov rdi, 0x6666666666666666
    mov rbp, 0x7777777777777777
    mov r8,  0x8888888888888888
    mov r9,  0x9999999999999999
    mov r10, 0xaaaaaaaaaaaaaaaa
    mov r11, 0xbbbbbbbbbbbbbbbb
    mov r12, 0xcccccccccccccccc
    mov r13, 0xdddddddddddddddd
    mov r14, [rsp + 8]
    mov r15, 0xffffffffffffffff
    stc
    std
    mov byte ptr [r14], 0x5a       # Required non-present user page fault.
    pushfq
    push rax
    cld                          # Restore the C ABI before any library call.
    mov rax, [rsp + 16]
    mov [rax + 8], rbx
    mov [rax + 16], rcx
    mov [rax + 24], rdx
    mov [rax + 32], rsi
    mov [rax + 40], rdi
    mov [rax + 48], rbp
    mov [rax + 56], r8
    mov [rax + 64], r9
    mov [rax + 72], r10
    mov [rax + 80], r11
    mov [rax + 88], r12
    mov [rax + 96], r13
    mov [rax + 104], r14
    mov [rax + 112], r15
    mov rdx, [rsp]
    mov [rax], rdx
    lea rdx, [rsp + 16]
    mov [rax + 120], rdx
    mov rdx, [rsp + 8]
    mov [rax + 136], rdx
    movdqu [rax + 144], xmm0
    fstp tbyte ptr [rax + 160]
    stmxcsr [rax + 176]
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

.section .rodata
.balign 16
.Lvector:
    .quad 0x0123456789abcdef, 0xfedcba9876543210
.Lextended:
    .quad 0x8000000000000008
    .word 0x3fff
.section .note.GNU-stack,"",@progbits
