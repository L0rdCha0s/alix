.intel_syntax noprefix
.section .text
.global kernel_preempt_probe
.extern process_preempt_trampoline

# Exercise the production trampoline at both possible interrupted alignments.
# Only its GS:[0] operand is replaced with the fixture's owned resume slot.
kernel_preempt_probe:
    mov [rip + test_probe_output], rdi
    mov [rip + test_probe_shift], rsi
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push rdi
    test esi, esi
    jz .Lsetup
    push 0
.Lsetup:
    mov [rdi + 128], rsp
    lea rax, [rip + .Lresumed]
    mov [rip + test_resume_rip], rax
    pushfq
    pop rax
    and rax, -3286
    or rax, 0xcd5
    push rax
    popfq
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
    mov r14, 0xeeeeeeeeeeeeeeee
    mov r15, 0xffffffffffffffff
    jmp process_preempt_trampoline
.Lresumed:
    pushfq
    push rax
    cld
    mov rax, [rip + test_probe_output]
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
    add rsp, 16
    cmp qword ptr [rip + test_probe_shift], 0
    je .Lrestore
    add rsp, 8
.Lrestore:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

.global process_preempt_hook
process_preempt_hook:
    mov rax, rsp
    and eax, 15
    cmp eax, 8
    je .Laligned
    inc qword ptr [rip + test_hook_errors]
.Laligned:
    pushfq
    pop rax
    test eax, 0x400
    jz .Ldirection_ok
    inc qword ptr [rip + test_hook_errors]
.Ldirection_ok:
    cmp qword ptr [rip + test_resume_rip], 0
    je .Lcaptured
    inc qword ptr [rip + test_hook_errors]
.Lcaptured:
    # Model a nested preemption replacing the TLS slot during the C hook.
    mov rax, 0x12345678deadbeef
    mov [rip + test_resume_rip], rax
    cld
    xor eax, eax
    xor ecx, ecx
    xor edx, edx
    xor esi, esi
    xor edi, edi
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    ret
.section .note.GNU-stack,"",@progbits
