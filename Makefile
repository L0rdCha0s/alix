NASM     := nasm
CC       := x86_64-elf-gcc
LD       := x86_64-elf-ld
OBJCOPY  := x86_64-elf-objcopy
QEMU     := qemu-system-x86_64

SRC_DIR     := src
ARCH_DIR    := $(SRC_DIR)/arch/x86
KERNEL_DIR  := $(SRC_DIR)/kernel
DRIVER_DIR  := $(SRC_DIR)/drivers
ATK_DIR     := $(SRC_DIR)/atk
INCLUDE_DIR := include
OBJDIR      := build

CFLAGS := -std=c11 -ffreestanding -fno-stack-protector -fno-builtin -fno-pic \
          -m64 -mno-red-zone -mgeneral-regs-only -Wall -Wextra -I$(INCLUDE_DIR) \
          -fno-merge-constants

BOOT_SRC    := $(ARCH_DIR)/boot.asm
STAGE2_SRC  := $(ARCH_DIR)/stage2.asm
STAGE2_LD   := $(ARCH_DIR)/stage2.ld

C_SOURCES := \
	$(wildcard $(KERNEL_DIR)/*.c) \
	$(wildcard $(DRIVER_DIR)/*.c) \
	$(wildcard $(ATK_DIR)/*.c) \
	$(wildcard $(ARCH_DIR)/*.c)

C_OBJECTS := $(patsubst $(SRC_DIR)/%.c,$(OBJDIR)/%.o,$(C_SOURCES))

STAGE2_OBJ := $(OBJDIR)/arch/x86/stage2.o
STAGE2_OBJS := $(STAGE2_OBJ) $(C_OBJECTS)

BOOT_BIN   := $(OBJDIR)/boot.bin
STAGE2_ELF := $(OBJDIR)/stage2.elf
STAGE2_BIN := $(OBJDIR)/stage2.bin

all: os.img

$(OBJDIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(STAGE2_OBJ): $(STAGE2_SRC)
	@mkdir -p $(dir $@)
	$(NASM) -f elf64 -o $@ $<

$(BOOT_BIN): $(BOOT_SRC) $(STAGE2_BIN)
	@mkdir -p $(dir $@)
	stsz=$$(wc -c < $(STAGE2_BIN)); \
	secs=$$(( ($$stsz + 511) / 512 )); \
	echo "Assembling boot sector with STAGE2_SECTORS=$$secs"; \
	$(NASM) -f bin -o $@ -D STAGE2_SECTORS=$$secs $<

$(STAGE2_ELF): $(STAGE2_OBJS) $(STAGE2_LD)
	$(LD) -nostdlib -T $(STAGE2_LD) -o $@ $(STAGE2_OBJS)

$(STAGE2_BIN): $(STAGE2_ELF)
	$(OBJCOPY) -O binary $< $@

# 1.44MB **floppy/drive** image (NOT an ISO/CD)
os.img: $(BOOT_BIN) $(STAGE2_BIN)
	@# Create a 1.44MB floppy image
	dd if=/dev/zero of=$@ bs=512 count=2880 2>/dev/null
	dd if=$(BOOT_BIN)   of=$@ conv=notrunc 2>/dev/null
	dd if=$(STAGE2_BIN) of=$@ bs=512 seek=1 conv=notrunc 2>/dev/null

# Optional: small HDD-style image (no partition table, boots from LBA0 directly)
hdd.img: $(BOOT_BIN) $(STAGE2_BIN)
	dd if=/dev/zero of=$@ bs=1M count=16 2>/dev/null
	dd if=$(BOOT_BIN)   of=$@ conv=notrunc 2>/dev/null
	dd if=$(STAGE2_BIN) of=$@ bs=512 seek=1 conv=notrunc 2>/dev/null

run: os.img
	$(QEMU) -fda os.img -boot a -no-reboot -monitor none -serial stdio \
		-netdev user,id=n0 -device rtl8139,netdev=n0

run-hdd: hdd.img
	$(QEMU) -drive file=hdd.img,format=raw,if=ide -no-reboot -monitor none -serial stdio \
		-netdev user,id=n0 -device rtl8139,netdev=n0

clean:
	rm -rf $(OBJDIR) os.img hdd.img
