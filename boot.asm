; boot.asm — 16‑bit boot sector (LBA load) — NASM syntax
; Assembled with: nasm -f bin -o boot.bin boot.asm

%define STAGE2_SEG     0x1000        ; load segment for stage2 (phys 0x10000)
%define STAGE2_OFF     0x0000
%define STAGE2_LBA     1             ; start right after boot sector
%define STAGE2_SECTORS 128           ; adjust if stage2 grows beyond 64 KiB

BITS 16
ORG 0x7C00

start:
  cli
  xor ax, ax
  mov ds, ax
  mov es, ax
  mov ss, ax
  mov sp, 0x7C00

  mov [boot_drive], dl     ; BIOS passes boot drive in DL

  ; --- Enable A20 (fast 0x92 gate) ---
  in   al, 0x92
  or   al, 0x02
  out  0x92, al

  ; --- Load stage2 via INT 13h extensions (AH=42h) ---
  mov   si, dap
  mov   dl, [boot_drive]
  mov   ah, 0x42
  int   0x13
  jc    disk_error

  ; Jump to loaded stage2 (real mode)
  jmp   STAGE2_SEG:STAGE2_OFF

; --- Data ---
boot_drive: db 0

; Put the error string *before* the error routine to avoid forward-ref issues
err_msg db 'Disk read error',0

; Disk Address Packet (DAP) — 16 bytes (aligning to be tidy)
ALIGN 16

dap:
  db 0x10               ; size
  db 0x00               ; reserved
  dw STAGE2_SECTORS     ; sectors to read
  dw STAGE2_OFF         ; dest offset
  dw STAGE2_SEG         ; dest segment
  dd STAGE2_LBA         ; LBA low
  dd 0x00000000         ; LBA high

; --- Simple error print loop (no dotted local labels) ---

disk_error:
  mov si, err_msg
.de_print:
  lodsb
  test al, al
  jz   short .de_halt
  mov ah, 0x0E
  mov bh, 0x00
  mov bl, 0x07
  int 0x10
  jmp  short .de_print
.de_halt:
  hlt
  jmp  short .de_halt

; Boot signature *must* be the last two bytes of the 512‑byte sector
TIMES 510-($-$$) db 0
DW 0xAA55
