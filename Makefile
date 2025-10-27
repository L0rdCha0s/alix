NASM     := nasm
CC       := x86_64-elf-gcc
LD       := x86_64-elf-ld
OBJCOPY  := x86_64-elf-objcopy
QEMU     := qemu-system-x86_64

CFLAGS := -std=c11 -ffreestanding -fno-stack-protector -fno-builtin -fno-pic \
          -m64 -mno-red-zone -mgeneral-regs-only -Wall -Wextra -Iinclude

STAGE2_OBJS := stage2.o kernel.o console.o serial.o keyboard.o vfs.o libc.o \
                idt.o interrupts.o timer.o mouse.o video.o

all: os.img

boot.bin: boot.asm
	$(NASM) -f bin -o $@ $<

stage2.o: stage2.asm
	$(NASM) -f elf64 -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

stage2.elf: $(STAGE2_OBJS) stage2.ld
	$(LD) -nostdlib -T stage2.ld -o $@ $(STAGE2_OBJS)

stage2.bin: stage2.elf
	$(OBJCOPY) -O binary $< $@

# 1.44MB **floppy/drive** image (NOT an ISO/CD)
os.img: boot.bin stage2.bin
	@# Create a 1.44MB floppy image
	dd if=/dev/zero of=$@ bs=512 count=2880 2>/dev/null
	dd if=boot.bin   of=$@ conv=notrunc 2>/dev/null
	dd if=stage2.bin of=$@ bs=512 seek=1 conv=notrunc 2>/dev/null

# Optional: small HDD-style image (no partition table, boots from LBA0 directly)
hdd.img: boot.bin stage2.bin
	dd if=/dev/zero of=$@ bs=1M count=16 2>/dev/null
	dd if=boot.bin   of=$@ conv=notrunc 2>/dev/null
	dd if=stage2.bin of=$@ bs=512 seek=1 conv=notrunc 2>/dev/null

run: os.img
	$(QEMU) -fda os.img -boot a -no-reboot -serial mon:stdio

run-hdd: hdd.img
	$(QEMU) -drive file=hdd.img,format=raw,if=ide -no-reboot -serial mon:stdio

clean:
	rm -f boot.bin stage2.bin stage2.o stage2.elf \
	      $(STAGE2_OBJS) os.img hdd.img
