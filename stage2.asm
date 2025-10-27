; stage2.asm — sets up long mode and jumps to C kernel at 0x00010000

%define STAGE2_BASE   0x0000000000010000
%define STACK_TOP     0x0000000000090000
%define PML4          0x0000000000070000
%define PDP           0x0000000000071000
%define PD0           0x0000000000072000
%define PD1           0x0000000000073000
%define PD2           0x0000000000074000
%define PD3           0x0000000000075000

%define CODE32_SEL 0x08
%define DATA32_SEL 0x10
%define CODE64_SEL 0x18
%define TSS_SEL   0x20

%define TSS_RSP0_OFFSET 4
%define TSS_IOMAP_OFFSET 0x66

BITS 16

section .start16
  global start16
  extern kernel_main
  extern __bss_start
  extern __bss_end

start16:
  cli
  mov ax, 0x1000
  mov ds, ax
  mov es, ax
  mov ss, ax
  mov sp, 0xFFFC

  ; Enable A20 using port 0x92
  in   al, 0x92
  or   al, 0x02
  out  0x92, al

  ; Load our GDT descriptor without needing high addresses
  call .get_gdt_ptr
.get_gdt_ptr:
  pop si
  add si, gdt_ptr - .get_gdt_ptr
  lgdt [si]

  ; Enter protected mode
  mov eax, cr0
  or  eax, 0x1
  mov cr0, eax

  ; Far jump with 32-bit operand to flush prefetch / load CS
  o32 jmp CODE32_SEL:pmode_entry

  ALIGN 8
gdt:
  dq 0
  dq 0x00CF9A000000FFFF      ; 32-bit code
  dq 0x00CF92000000FFFF      ; 32-bit data
  dq 0x00A09A0000000000      ; 64-bit code
tss_descriptor:
  dq 0
  dq 0

gdt_ptr:
  dw gdt_end - gdt - 1
  dq gdt

gdt_end:

ALIGN 16
tss64:
  dd 0
  dd 0
  dq 0                ; rsp0
  dq 0                ; rsp1
  dq 0                ; rsp2
  dq 0                ; reserved1
  dq 0                ; ist1
  dq 0                ; ist2
  dq 0                ; ist3
  dq 0                ; ist4
  dq 0                ; ist5
  dq 0                ; ist6
  dq 0                ; ist7
  dq 0                ; reserved2
  dw 0                ; reserved3
  dw 0                ; iomap base (set later)
tss64_end:

section .pmode
BITS 32
pmode_entry:
  mov ax, DATA32_SEL
  mov ds, ax
  mov es, ax
  mov ss, ax
  mov esp, 0x90000

  ; Build paging structures for 2 MiB identity map
  xor eax, eax
  mov edi, PML4
  mov ecx, 4096/4
  rep stosd

  mov edi, PDP
  mov ecx, 4096/4
  rep stosd

  mov edi, PD0
  mov ecx, 4096/4
  rep stosd

  mov edi, PD1
  mov ecx, 4096/4
  rep stosd

  mov edi, PD2
  mov ecx, 4096/4
  rep stosd

  mov edi, PD3
  mov ecx, 4096/4
  rep stosd

  mov dword [PML4 + 0], PDP | 0x3
  mov dword [PML4 + 4], 0

  mov dword [PDP  + (0*8) + 0], PD0  | 0x3
  mov dword [PDP  + (0*8) + 4], 0

  mov dword [PDP  + (1*8) + 0], PD1 | 0x3
  mov dword [PDP  + (1*8) + 4], 0

  mov dword [PDP  + (2*8) + 0], PD2 | 0x3
  mov dword [PDP  + (2*8) + 4], 0

  mov dword [PDP  + (3*8) + 0], PD3 | 0x3
  mov dword [PDP  + (3*8) + 4], 0

  ; Identity map 0-4 GiB (using two PD tables)
  mov ecx, 512
  xor eax, eax
  mov edi, PD0
.map_low_loop:
  mov edx, eax
  or  edx, 0x83
  mov [edi + 0], edx
  mov dword [edi + 4], 0
  add eax, 0x00200000
  add edi, 8
  loop .map_low_loop

  mov ecx, 512
  mov eax, 0x40000000
  mov edi, PD1
.map_high_loop:
  mov edx, eax
  or  edx, 0x83
  mov [edi + 0], edx
  mov dword [edi + 4], 0
  add eax, 0x00200000
  add edi, 8
  loop .map_high_loop

  mov ecx, 512
  mov eax, 0x80000000
  mov edi, PD2
.map_high2_loop:
  mov edx, eax
  or  edx, 0x83
  mov [edi + 0], edx
  mov dword [edi + 4], 0
  add eax, 0x00200000
  add edi, 8
  loop .map_high2_loop

  mov ecx, 512
  mov eax, 0xC0000000
  mov edi, PD3
.map_high3_loop:
  mov edx, eax
  or  edx, 0x83
  mov [edi + 0], edx
  mov dword [edi + 4], 0
  add eax, 0x00200000
  add edi, 8
  loop .map_high3_loop

  mov eax, cr4
  or  eax, (1 << 5)          ; enable PAE
  mov cr4, eax

  mov eax, PML4
  mov cr3, eax

  mov ecx, 0xC0000080        ; EFER
  rdmsr
  or  eax, (1 << 8)          ; LME
  wrmsr

  mov eax, cr0
  or  eax, (1 << 31)         ; enable paging
  mov cr0, eax

  jmp CODE64_SEL:long_entry

section .longmode
BITS 64
default rel
long_entry:
  mov ax, DATA32_SEL
  mov ds, ax
  mov es, ax
  mov ss, ax
  mov rsp, STACK_TOP

  lea rdi, [rel tss64]
  mov rbx, STACK_TOP
  mov [rdi + TSS_RSP0_OFFSET], rbx
  mov word [rdi + TSS_IOMAP_OFFSET], (tss64_end - tss64)

  lea rcx, [rel tss_descriptor]
  mov edx, (tss64_end - tss64 - 1)
  mov word [rcx], dx
  mov rax, rdi
  mov word [rcx + 2], ax
  shr rax, 16
  mov byte [rcx + 4], al
  mov byte [rcx + 5], 0x89
  mov eax, edx
  shr eax, 16
  and eax, 0x0F
  mov byte [rcx + 6], al
  mov rax, rdi
  shr rax, 24
  mov byte [rcx + 7], al
  mov rax, rdi
  shr rax, 32
  mov dword [rcx + 8], eax
  mov dword [rcx + 12], 0

  mov ax, TSS_SEL
  ltr ax

  ; Zero .bss so C code starts with clean globals
  mov rdi, __bss_start
  mov rcx, __bss_end
  sub rcx, rdi
  xor eax, eax
  rep stosb

  call kernel_main

halt_loop:
  hlt
  jmp halt_loop
