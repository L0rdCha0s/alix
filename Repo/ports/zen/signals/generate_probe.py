#!/usr/bin/env python3
from pathlib import Path
p=Path(__file__).with_name('signal_context_probe.S')
s=['.intel_syntax noprefix','.section .text']
registers=['rax','rbx','rcx','rdx','rsi','rdi','rbp','r8','r9','r10','r11','r12','r13','r14','r15']
for mode in ['pf','ud','async']:
    s += [f'.global signal_{mode}_probe',f'.global signal_{mode}_fault',f'.global signal_{mode}_resume',f'signal_{mode}_probe:']
    s += ['    push '+r for r in ['rbx','rbp','r12','r13','r14','r15','rdi','rsi']]
    s += ['    mov [rsi+128],rsp']
    s += [f'    movdqu xmm{i},[rip+.Lvectors+{16*i}]' for i in range(16)]
    s += ['    fld tbyte ptr [rip+.Lextended]']
    if mode=='async':
        s += ['    mov rax,0x1111111111111111']+[f'    mov [rsp-{8*i}],rax' for i in range(1,17)]
    for i,r in enumerate(registers):
        s += [f'    mov {r},'+('[rsp+8]' if r=='r14' else hex(0x1111111111111111*(i+1)))]
    s += ['    stc','    std',f'signal_{mode}_fault:']
    if mode=='pf':s += ['    mov byte ptr [r14],0x5a']
    elif mode=='ud':s += ['    ud2']
    else:s += ['    mov dword ptr [r14+4],1','.Lspin:','    cmp dword ptr [r14],0','    je .Lspin']
    s += [f'signal_{mode}_resume:','    pushfq','    push rax','    cld','    mov rax,[rsp+16]']
    s += [f'    mov [rax+{8*i}],{r}' for i,r in enumerate(registers) if i]
    s += ['    mov rdx,[rsp]','    mov [rax],rdx','    lea rdx,[rsp+16]','    mov [rax+120],rdx','    mov rdx,[rsp+8]','    mov [rax+136],rdx']
    s += [f'    movdqu [rax+{144+16*i}],xmm{i}' for i in range(16)]
    s += ['    fstp tbyte ptr [rax+400]','    stmxcsr [rax+416]','    add rsp,32']
    s += ['    pop '+r for r in ['r15','r14','r13','r12','rbp','rbx']]+['    ret']
s += ['.global signal_edit_stack_probe','.global signal_edit_stack_fault','.global signal_edit_stack_resume',
      'signal_edit_stack_probe:','    push r12','    mov r12,rdi','    mov [r12],rsp',
      'signal_edit_stack_fault:','    ud2','signal_edit_stack_resume:','    mov rdi,r12',
      '    call signal_edited_stack_callback','    mov rsp,[r12]','    pop r12','    ret']
s += ['.global signal_badframe_probe','signal_badframe_probe:','    ud2','    ret']
s += ['.global signal_main_stack_probe','.global signal_main_stack_fault','.global signal_main_stack_resume','signal_main_stack_probe:','    sub rsp,1048576','signal_main_stack_fault:','    ud2','signal_main_stack_resume:','    add rsp,1048576','    ret']
s += ['.global signal_clobber_fp','signal_clobber_fp:','    fninit','    ldmxcsr [rip+.Lmxcsr]']
s += [f'    pxor xmm{i},xmm{i}' for i in range(16)]+['    ret']
s += ['.section .rodata','.balign 16','.Lvectors:']
s += [f'    .quad {hex(0x0123456789abcdef+i)},{hex(0xfedcba9876543210-i)}' for i in range(16)]
s += ['.Lextended:','    .quad 0x8000000000000008','    .word 0x3fff','.Lmxcsr:','    .long 0x1f80','.section .note.GNU-stack,"",@progbits']
p.write_text('\n'.join(s)+'\n')
