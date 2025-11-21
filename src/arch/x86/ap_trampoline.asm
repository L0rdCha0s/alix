BITS 16
DEFAULT ABS
ORG 0

%define TRAMP_BASE               0x8000
%define BOOT_BASE                0x7000
%define STACK_TOP_OFFSET         0x0FF0
%define SMP_BOOT_STACK_OFFSET    0x00
%define SMP_BOOT_ENTRY_OFFSET    0x08
%define SMP_BOOT_PML4_OFFSET     0x10
%define SMP_BOOT_APIC_ID_OFFSET  0x18
%define SMP_BOOT_STAGE_OFFSET    0x20
%define SMP_BOOT_CR4_OFFSET      0x28
%define SMP_BOOT_EFER_OFFSET     0x30
%define SMP_BOOT_CR0_OFFSET      0x38
%define SMP_BOOT_IDT_LIMIT_OFFSET 0x40
%define SMP_BOOT_IDT_BASE_OFFSET  0x42

%define PROTECTED_MODE_CS        0x08
%define KERNEL_DS                0x10
%define KERNEL_CS                0x18

%define TRAMP_TO_BOOT_DELTA      (TRAMP_BASE - BOOT_BASE)
%define PROTECTED_MODE_ENTRY_PHYS (TRAMP_BASE + protected_mode_entry - start)
%define LONG_MODE_ENTRY_PHYS      (TRAMP_BASE + long_mode_entry - start)
%define IA32_EFER                0xC0000080

global start

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    push cs
    pop ax
    shl ax, 4
    mov bx, ax                ; BX = physical base of this code (0x8000)
    mov si, bx
    sub si, TRAMP_TO_BOOT_DELTA
    mov [boot_ptr], si

    mov ax, si
    sub ax, 0x0010
    mov sp, ax

    mov di, gdt_descriptor - start
    add di, bx
    mov ax, gdt64_end - gdt64 - 1
    mov [di], ax
    mov ax, gdt64 - start
    add ax, bx
    mov [di + 2], ax
    mov word [di + 4], 0
    lgdt [di]

    mov byte [si + SMP_BOOT_STAGE_OFFSET], 1

    mov eax, cr0
    or eax, 0x1
    mov cr0, eax
    mov byte [si + SMP_BOOT_STAGE_OFFSET], 2
    o32 jmp PROTECTED_MODE_CS:PROTECTED_MODE_ENTRY_PHYS

BITS 32
protected_mode_entry:
    mov ax, KERNEL_DS
    mov ds, ax
    mov es, ax
    mov ss, ax
    movzx esi, word [boot_ptr]

    mov eax, dword [esi + SMP_BOOT_CR4_OFFSET]
    or eax, (1 << 5)
    mov cr4, eax

    mov eax, dword [esi + SMP_BOOT_PML4_OFFSET]
    mov cr3, eax

    mov ecx, IA32_EFER
    mov eax, dword [esi + SMP_BOOT_EFER_OFFSET]
    mov edx, dword [esi + SMP_BOOT_EFER_OFFSET + 4]
    or eax, (1 << 8)
    wrmsr

    mov eax, dword [esi + SMP_BOOT_CR0_OFFSET]
    mov cr0, eax
    jmp KERNEL_CS:LONG_MODE_ENTRY_PHYS

BITS 64
long_mode_entry:
    movzx rsi, word [boot_ptr]
    mov ax, KERNEL_DS
    mov ds, ax
    mov es, ax
    mov ss, ax

    mov rax, qword [rsi + SMP_BOOT_STACK_OFFSET]
    mov rsp, rax

    lea rax, [rsi + SMP_BOOT_IDT_LIMIT_OFFSET]
    lidt [rax]

    mov byte [rsi + SMP_BOOT_STAGE_OFFSET], 3

    mov rdi, qword [rsi + SMP_BOOT_APIC_ID_OFFSET]
    mov rax, qword [rsi + SMP_BOOT_ENTRY_OFFSET]
    jmp rax

ALIGN 8
gdt64:
    dq 0x0000000000000000
    dq 0x00CF9A000000FFFF
    dq 0x00CF92000000FFFF
    dq 0x00AF9A000000FFFF
gdt64_end:

gdt_descriptor:
    dw 0
    dd 0

boot_ptr:
    dw 0
