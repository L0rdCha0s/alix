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
  sub sp, 0x0200            ; move stack below code/data to avoid clobber

  mov [boot_drive], dl     ; BIOS passes boot drive in DL

  ; --- Quick serial init via BIOS (COM1, 9600 8N1) and banner ---
  mov dx, 0                 ; COM1
  mov ah, 0x00
  mov al, 0xE3              ; 9600 baud, 8N1
  int 0x14
  mov ah, 0x01
  mov al, 'B'
  int 0x14
  mov al, ':'
  int 0x14
  ; Also drop a marker to VGA text via BIOS
  mov ah, 0x0E
  mov al, 'b'
  mov bh, 0x00
  mov bl, 0x07
  int 0x10

  ; --- Enable A20 (fast 0x92 gate) ---
  in   al, 0x92
  or   al, 0x02
  out  0x92, al

  ; --- Load stage2 via INT 13h extensions (AH=42h), chunked reads ---
  mov   bx, STAGE2_SEG       ; BX holds current destination segment
  mov   ax, STAGE2_SECTORS
  mov   [remain_secs], ax    ; remaining sectors in memory (avoid clobber)
  mov   di, dap              ; DI -> DAP
  mov   byte [di + 0], 0x10  ; DAP size
  mov   byte [di + 1], 0x00  ; DAP reserved
  mov   word [di + 4], STAGE2_OFF
  mov   word [di + 6], bx
  mov   dword [di + 8], STAGE2_LBA
  mov   dword [di + 12], 0

.read_loop:
  mov   ax, [remain_secs]
  cmp   ax, 0
  je    .read_done
  cmp   ax, 127
  jbe   .count_ok
  mov   ax, 127
.count_ok:
  mov   [di + 2], ax         ; DAP sector count

  ; call BIOS to read this chunk
  mov   si, dap
  mov   dl, [boot_drive]
  mov   ah, 0x42
  int   0x13
  jc    disk_error

  ; emit a dot over serial per chunk
  push dx                  ; preserve remaining-sectors counter
  mov dx, 0               ; COM1 for BIOS INT 14h
  mov ah, 0x01
  mov al, '.'
  int 0x14
  pop dx

  ; advance LBA: lba += count (add to 32-bit little endian at [dap+8])
  mov   cx, [di + 2]
  add   word [di + 8], cx
  adc   word [di + 10], 0

  ; advance destination segment by count * 32 paragraphs (512B)
  mov   ax, cx
  shl   ax, 5
  add   [di + 6], ax

  ; remaining -= count
  sub   [remain_secs], cx
  jmp   .read_loop

.read_done:
  ; newline at the end
  mov dx, 0
  mov ah, 0x01
  mov al, 0x0D
  int 0x14
  mov al, 0x0A
  int 0x14

  ; Jump to loaded stage2 (real mode)
  ; print 'J' to serial just before jump
  mov dx, 0
  mov ah, 0x01
  mov al, 'J'
  int 0x14
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

remain_secs: dw 0

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
