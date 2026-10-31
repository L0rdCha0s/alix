.intel_syntax noprefix
.section .text
.global signal_pf_probe
.global signal_pf_fault
.global signal_pf_resume
signal_pf_probe:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push rdi
    push rsi
    mov [rsi+128],rsp
    movdqu xmm0,[rip+.Lvectors+0]
    movdqu xmm1,[rip+.Lvectors+16]
    movdqu xmm2,[rip+.Lvectors+32]
    movdqu xmm3,[rip+.Lvectors+48]
    movdqu xmm4,[rip+.Lvectors+64]
    movdqu xmm5,[rip+.Lvectors+80]
    movdqu xmm6,[rip+.Lvectors+96]
    movdqu xmm7,[rip+.Lvectors+112]
    movdqu xmm8,[rip+.Lvectors+128]
    movdqu xmm9,[rip+.Lvectors+144]
    movdqu xmm10,[rip+.Lvectors+160]
    movdqu xmm11,[rip+.Lvectors+176]
    movdqu xmm12,[rip+.Lvectors+192]
    movdqu xmm13,[rip+.Lvectors+208]
    movdqu xmm14,[rip+.Lvectors+224]
    movdqu xmm15,[rip+.Lvectors+240]
    fld tbyte ptr [rip+.Lextended]
    mov rax,0x1111111111111111
    mov rbx,0x2222222222222222
    mov rcx,0x3333333333333333
    mov rdx,0x4444444444444444
    mov rsi,0x5555555555555555
    mov rdi,0x6666666666666666
    mov rbp,0x7777777777777777
    mov r8,0x8888888888888888
    mov r9,0x9999999999999999
    mov r10,0xaaaaaaaaaaaaaaaa
    mov r11,0xbbbbbbbbbbbbbbbb
    mov r12,0xcccccccccccccccc
    mov r13,0xdddddddddddddddd
    mov r14,[rsp+8]
    mov r15,0xffffffffffffffff
    stc
    std
signal_pf_fault:
    mov byte ptr [r14],0x5a
signal_pf_resume:
    pushfq
    push rax
    cld
    mov rax,[rsp+16]
    mov [rax+8],rbx
    mov [rax+16],rcx
    mov [rax+24],rdx
    mov [rax+32],rsi
    mov [rax+40],rdi
    mov [rax+48],rbp
    mov [rax+56],r8
    mov [rax+64],r9
    mov [rax+72],r10
    mov [rax+80],r11
    mov [rax+88],r12
    mov [rax+96],r13
    mov [rax+104],r14
    mov [rax+112],r15
    mov rdx,[rsp]
    mov [rax],rdx
    lea rdx,[rsp+16]
    mov [rax+120],rdx
    mov rdx,[rsp+8]
    mov [rax+136],rdx
    movdqu [rax+144],xmm0
    movdqu [rax+160],xmm1
    movdqu [rax+176],xmm2
    movdqu [rax+192],xmm3
    movdqu [rax+208],xmm4
    movdqu [rax+224],xmm5
    movdqu [rax+240],xmm6
    movdqu [rax+256],xmm7
    movdqu [rax+272],xmm8
    movdqu [rax+288],xmm9
    movdqu [rax+304],xmm10
    movdqu [rax+320],xmm11
    movdqu [rax+336],xmm12
    movdqu [rax+352],xmm13
    movdqu [rax+368],xmm14
    movdqu [rax+384],xmm15
    fstp tbyte ptr [rax+400]
    stmxcsr [rax+416]
    add rsp,32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.global signal_ud_probe
.global signal_ud_fault
.global signal_ud_resume
signal_ud_probe:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push rdi
    push rsi
    mov [rsi+128],rsp
    movdqu xmm0,[rip+.Lvectors+0]
    movdqu xmm1,[rip+.Lvectors+16]
    movdqu xmm2,[rip+.Lvectors+32]
    movdqu xmm3,[rip+.Lvectors+48]
    movdqu xmm4,[rip+.Lvectors+64]
    movdqu xmm5,[rip+.Lvectors+80]
    movdqu xmm6,[rip+.Lvectors+96]
    movdqu xmm7,[rip+.Lvectors+112]
    movdqu xmm8,[rip+.Lvectors+128]
    movdqu xmm9,[rip+.Lvectors+144]
    movdqu xmm10,[rip+.Lvectors+160]
    movdqu xmm11,[rip+.Lvectors+176]
    movdqu xmm12,[rip+.Lvectors+192]
    movdqu xmm13,[rip+.Lvectors+208]
    movdqu xmm14,[rip+.Lvectors+224]
    movdqu xmm15,[rip+.Lvectors+240]
    fld tbyte ptr [rip+.Lextended]
    mov rax,0x1111111111111111
    mov rbx,0x2222222222222222
    mov rcx,0x3333333333333333
    mov rdx,0x4444444444444444
    mov rsi,0x5555555555555555
    mov rdi,0x6666666666666666
    mov rbp,0x7777777777777777
    mov r8,0x8888888888888888
    mov r9,0x9999999999999999
    mov r10,0xaaaaaaaaaaaaaaaa
    mov r11,0xbbbbbbbbbbbbbbbb
    mov r12,0xcccccccccccccccc
    mov r13,0xdddddddddddddddd
    mov r14,[rsp+8]
    mov r15,0xffffffffffffffff
    stc
    std
signal_ud_fault:
    ud2
signal_ud_resume:
    pushfq
    push rax
    cld
    mov rax,[rsp+16]
    mov [rax+8],rbx
    mov [rax+16],rcx
    mov [rax+24],rdx
    mov [rax+32],rsi
    mov [rax+40],rdi
    mov [rax+48],rbp
    mov [rax+56],r8
    mov [rax+64],r9
    mov [rax+72],r10
    mov [rax+80],r11
    mov [rax+88],r12
    mov [rax+96],r13
    mov [rax+104],r14
    mov [rax+112],r15
    mov rdx,[rsp]
    mov [rax],rdx
    lea rdx,[rsp+16]
    mov [rax+120],rdx
    mov rdx,[rsp+8]
    mov [rax+136],rdx
    movdqu [rax+144],xmm0
    movdqu [rax+160],xmm1
    movdqu [rax+176],xmm2
    movdqu [rax+192],xmm3
    movdqu [rax+208],xmm4
    movdqu [rax+224],xmm5
    movdqu [rax+240],xmm6
    movdqu [rax+256],xmm7
    movdqu [rax+272],xmm8
    movdqu [rax+288],xmm9
    movdqu [rax+304],xmm10
    movdqu [rax+320],xmm11
    movdqu [rax+336],xmm12
    movdqu [rax+352],xmm13
    movdqu [rax+368],xmm14
    movdqu [rax+384],xmm15
    fstp tbyte ptr [rax+400]
    stmxcsr [rax+416]
    add rsp,32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.global signal_async_probe
.global signal_async_fault
.global signal_async_resume
signal_async_probe:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push rdi
    push rsi
    mov [rsi+128],rsp
    movdqu xmm0,[rip+.Lvectors+0]
    movdqu xmm1,[rip+.Lvectors+16]
    movdqu xmm2,[rip+.Lvectors+32]
    movdqu xmm3,[rip+.Lvectors+48]
    movdqu xmm4,[rip+.Lvectors+64]
    movdqu xmm5,[rip+.Lvectors+80]
    movdqu xmm6,[rip+.Lvectors+96]
    movdqu xmm7,[rip+.Lvectors+112]
    movdqu xmm8,[rip+.Lvectors+128]
    movdqu xmm9,[rip+.Lvectors+144]
    movdqu xmm10,[rip+.Lvectors+160]
    movdqu xmm11,[rip+.Lvectors+176]
    movdqu xmm12,[rip+.Lvectors+192]
    movdqu xmm13,[rip+.Lvectors+208]
    movdqu xmm14,[rip+.Lvectors+224]
    movdqu xmm15,[rip+.Lvectors+240]
    fld tbyte ptr [rip+.Lextended]
    mov rax,0x1111111111111111
    mov [rsp-8],rax
    mov [rsp-16],rax
    mov [rsp-24],rax
    mov [rsp-32],rax
    mov [rsp-40],rax
    mov [rsp-48],rax
    mov [rsp-56],rax
    mov [rsp-64],rax
    mov [rsp-72],rax
    mov [rsp-80],rax
    mov [rsp-88],rax
    mov [rsp-96],rax
    mov [rsp-104],rax
    mov [rsp-112],rax
    mov [rsp-120],rax
    mov [rsp-128],rax
    mov rax,0x1111111111111111
    mov rbx,0x2222222222222222
    mov rcx,0x3333333333333333
    mov rdx,0x4444444444444444
    mov rsi,0x5555555555555555
    mov rdi,0x6666666666666666
    mov rbp,0x7777777777777777
    mov r8,0x8888888888888888
    mov r9,0x9999999999999999
    mov r10,0xaaaaaaaaaaaaaaaa
    mov r11,0xbbbbbbbbbbbbbbbb
    mov r12,0xcccccccccccccccc
    mov r13,0xdddddddddddddddd
    mov r14,[rsp+8]
    mov r15,0xffffffffffffffff
    stc
    std
signal_async_fault:
    mov dword ptr [r14+4],1
.Lspin:
    cmp dword ptr [r14],0
    je .Lspin
signal_async_resume:
    pushfq
    push rax
    cld
    mov rax,[rsp+16]
    mov [rax+8],rbx
    mov [rax+16],rcx
    mov [rax+24],rdx
    mov [rax+32],rsi
    mov [rax+40],rdi
    mov [rax+48],rbp
    mov [rax+56],r8
    mov [rax+64],r9
    mov [rax+72],r10
    mov [rax+80],r11
    mov [rax+88],r12
    mov [rax+96],r13
    mov [rax+104],r14
    mov [rax+112],r15
    mov rdx,[rsp]
    mov [rax],rdx
    lea rdx,[rsp+16]
    mov [rax+120],rdx
    mov rdx,[rsp+8]
    mov [rax+136],rdx
    movdqu [rax+144],xmm0
    movdqu [rax+160],xmm1
    movdqu [rax+176],xmm2
    movdqu [rax+192],xmm3
    movdqu [rax+208],xmm4
    movdqu [rax+224],xmm5
    movdqu [rax+240],xmm6
    movdqu [rax+256],xmm7
    movdqu [rax+272],xmm8
    movdqu [rax+288],xmm9
    movdqu [rax+304],xmm10
    movdqu [rax+320],xmm11
    movdqu [rax+336],xmm12
    movdqu [rax+352],xmm13
    movdqu [rax+368],xmm14
    movdqu [rax+384],xmm15
    fstp tbyte ptr [rax+400]
    stmxcsr [rax+416]
    add rsp,32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.global signal_edit_stack_probe
.global signal_edit_stack_fault
.global signal_edit_stack_resume
signal_edit_stack_probe:
    push r12
    mov r12,rdi
    mov [r12],rsp
signal_edit_stack_fault:
    ud2
signal_edit_stack_resume:
    mov rdi,r12
    call signal_edited_stack_callback
    mov rsp,[r12]
    pop r12
    ret
.global signal_badframe_probe
signal_badframe_probe:
    ud2
    ret
.global signal_main_stack_probe
.global signal_main_stack_fault
.global signal_main_stack_resume
signal_main_stack_probe:
    sub rsp,1048576
signal_main_stack_fault:
    ud2
signal_main_stack_resume:
    add rsp,1048576
    ret
.global signal_clobber_fp
signal_clobber_fp:
    fninit
    ldmxcsr [rip+.Lmxcsr]
    pxor xmm0,xmm0
    pxor xmm1,xmm1
    pxor xmm2,xmm2
    pxor xmm3,xmm3
    pxor xmm4,xmm4
    pxor xmm5,xmm5
    pxor xmm6,xmm6
    pxor xmm7,xmm7
    pxor xmm8,xmm8
    pxor xmm9,xmm9
    pxor xmm10,xmm10
    pxor xmm11,xmm11
    pxor xmm12,xmm12
    pxor xmm13,xmm13
    pxor xmm14,xmm14
    pxor xmm15,xmm15
    ret
.section .rodata
.balign 16
.Lvectors:
    .quad 0x123456789abcdef,0xfedcba9876543210
    .quad 0x123456789abcdf0,0xfedcba987654320f
    .quad 0x123456789abcdf1,0xfedcba987654320e
    .quad 0x123456789abcdf2,0xfedcba987654320d
    .quad 0x123456789abcdf3,0xfedcba987654320c
    .quad 0x123456789abcdf4,0xfedcba987654320b
    .quad 0x123456789abcdf5,0xfedcba987654320a
    .quad 0x123456789abcdf6,0xfedcba9876543209
    .quad 0x123456789abcdf7,0xfedcba9876543208
    .quad 0x123456789abcdf8,0xfedcba9876543207
    .quad 0x123456789abcdf9,0xfedcba9876543206
    .quad 0x123456789abcdfa,0xfedcba9876543205
    .quad 0x123456789abcdfb,0xfedcba9876543204
    .quad 0x123456789abcdfc,0xfedcba9876543203
    .quad 0x123456789abcdfd,0xfedcba9876543202
    .quad 0x123456789abcdfe,0xfedcba9876543201
.Lextended:
    .quad 0x8000000000000008
    .word 0x3fff
.Lmxcsr:
    .long 0x1f80
.section .note.GNU-stack,"",@progbits
