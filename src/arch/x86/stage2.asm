; stage2.asm — sets up long mode and jumps to C kernel at 0x00010000

%define STAGE2_BASE   0x0000000000010000
%define STACK_TOP     0x0000000000090000
; Define a dedicated kernel heap region well above the VFS pool (16 MiB)
; This keeps dynamic allocations from overlapping the in-memory filesystem
%define KERNEL_HEAP_BASE 0x0000000002000000 ; 32 MiB
%define KERNEL_HEAP_SIZE 0x0000000001000000 ; 16 MiB span
; Place paging structures safely above the stage2 image (~0x70xxx)
; Use 1 MiB region to avoid overlap with loaded kernel image and BSS.
%define PML4          0x0000000000100000
%define PDP           0x0000000000101000
%define PD0           0x0000000000102000
%define PD1           0x0000000000103000
%define PD2           0x0000000000104000
%define PD3           0x0000000000105000

%define CODE32_SEL 0x08
%define DATA32_SEL 0x10
%define CODE64_SEL 0x18
%define TSS_SEL   0x20

%define TSS_RSP0_OFFSET 4
%define TSS_IOMAP_OFFSET 0x66
%define COM1 0x3F8

BITS 16

section .start16
  global start16
  extern kernel_main
  extern __bss_start
  extern __bss_end
  extern serial_write_char

start16:
  cli
  mov ax, 0x1000
  mov ds, ax
  mov es, ax
  mov ax, 0x9000           ; place real-mode stack well above stage2 image
  mov ss, ax
  mov sp, 0xFFFC

  ; BIOS serial init (COM1, 9600 8N1) and banner
  mov dx, 0
  mov ah, 0x00
  mov al, 0xE3
  int 0x14
  mov ah, 0x01
  mov al, 'S'
  int 0x14
  mov al, ':'
  int 0x14
  ; and VGA BIOS marker
  mov ah, 0x0E
  mov al, 's'
  mov bh, 0x00
  mov bl, 0x07
  int 0x10

  ; (E820 memory map collection removed for bring-up simplicity)

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

  ; Print 'P' BEFORE setting PE to avoid BIOS INT in protected mode
  mov dx, 0
  mov ah, 0x01
  mov al, 'P'
  int 0x14

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
gdt_end:

gdt_ptr:
  dw gdt_end - gdt - 1
  dq gdt

; (E820 memory map collection removed)

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

  ; Initialize COM1 quickly in I/O mode (115200 8N1)
  mov dx, COM1+1
  xor al, al
  out dx, al           ; disable interrupts
  mov dx, COM1+3
  mov al, 0x80
  out dx, al           ; DLAB on
  mov dx, COM1+0
  mov al, 0x01         ; divisor low (115200)
  out dx, al
  mov dx, COM1+1
  xor al, al           ; divisor high
  out dx, al
  mov dx, COM1+3
  mov al, 0x03         ; 8N1, DLAB off
  out dx, al
  mov dx, COM1+2
  mov al, 0xC7         ; FIFO enable/clear
  out dx, al
  mov dx, COM1+4
  mov al, 0x0B         ; OUT2=1
  out dx, al

  ; emit 'p' in pmode
  mov dx, COM1+5
.pm_wait:
  in al, dx
  test al, 0x20
  jz .pm_wait
  mov dx, COM1
  mov al, 'p'
  out dx, al

  ; Build paging structures for 2 MiB identity map
  cld
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

  ; Identity map 0-4 GiB (using four PD tables)
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

  ; emit 'L' in long mode
  mov dx, COM1+5
.lm_wait:
  in al, dx
  test al, 0x20
  jz .lm_wait
  mov dx, COM1
  mov al, 'L'
  out dx, al

  lea rdi, [rel tss64]
  mov rbx, STACK_TOP
  mov qword [rdi + TSS_RSP0_OFFSET], rbx
  mov word  [rdi + TSS_IOMAP_OFFSET], (tss64_end - tss64)

  lea rcx, [rel tss_descriptor]
  mov edx, (tss64_end - tss64 - 1)
  mov word [rcx], dx
  mov rax, rdi
  mov word [rcx + 2], ax
  shr rax, 16
  mov byte [rcx + 4], al
  mov byte [rcx + 5], 0x89          ; 64-bit available TSS
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

  ; Debug markers around BSS clear: 'c' (before), 'd' (after size calc), 'e' (after clear)
  mov dx, COM1+5
.lm_dbg1:
  in al, dx
  test al, 0x20
  jz .lm_dbg1
  mov dx, COM1
  mov al, 'c'
  out dx, al

  ; Zero .bss so C code starts with clean globals.
  ; Use absolute addresses rather than RIP-relative LEA math for clarity.
  cld
  mov rdi, __bss_start
  mov rcx, __bss_end
  sub rcx, rdi

  ; emit 'd' after computing rcx
  mov dx, COM1+5
.lm_dbg2:
  in al, dx
  test al, 0x20
  jz .lm_dbg2
  mov dx, COM1
  mov al, 'd'
  out dx, al

  xor eax, eax
  rep stosb

  ; emit 'e' after clear
  mov dx, COM1+5
.lm_dbg3:
  in al, dx
  test al, 0x20
  jz .lm_dbg3
  mov dx, COM1
  mov al, 'e'
  out dx, al

  ; emit 'B' after bss clear
  mov dx, COM1+5
.lm2_wait:
  in al, dx
  test al, 0x20
  jz .lm2_wait
  mov dx, COM1
  mov al, 'B'
  out dx, al

  call kernel_main

halt_loop:
  hlt
  jmp halt_loop

section .data
ALIGN 8
  global kernel_heap_base
kernel_heap_base: dq KERNEL_HEAP_BASE
  global kernel_heap_end
kernel_heap_end:  dq KERNEL_HEAP_BASE + KERNEL_HEAP_SIZE
  global kernel_heap_size
kernel_heap_size: dq KERNEL_HEAP_SIZE
