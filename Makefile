NASM     := nasm
CC       := x86_64-elf-gcc
LD       := x86_64-elf-ld
OBJCOPY  := x86_64-elf-objcopy
QEMU     := qemu-system-x86_64
HOST_CC  ?= cc

SRC_DIR     := src
ARCH_DIR    := $(SRC_DIR)/arch/x86
KERNEL_DIR  := $(SRC_DIR)/kernel
DRIVER_DIR  := $(SRC_DIR)/drivers
ATK_DIR     := $(SRC_DIR)/atk
NET_DIR     := $(SRC_DIR)/net
SBIN_DIR    := $(SRC_DIR)/sbin
CRYPTO_DIR  := $(SRC_DIR)/crypto
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
	$(wildcard $(ATK_DIR)/util/*.c) \
	$(wildcard $(NET_DIR)/*.c) \
	$(wildcard $(CRYPTO_DIR)/*.c) \
	$(wildcard $(ARCH_DIR)/*.c) \
	$(wildcard $(SBIN_DIR)/*.c)

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

RAM ?= 4G
QEMU_DEBUG_LOG   ?= qemu-debug.log
QEMU_DEBUG_FLAGS ?= -d cpu_reset,int,guest_errors -D $(QEMU_DEBUG_LOG)
HOMEBREW_PREFIX  := $(shell brew --prefix)

# --- choose networking backend: user (slirp), vmnet-shared (NAT), vmnet-bridged (bridge en0)
NET_BACKEND ?= vmnet-shared

# Packet capture (works for all backends)
NETDUMP := -object filter-dump,id=n0dump,netdev=n0,queue=all,file=qemu-net.pcap

# Backend-specific NETDEV flags
NETDEV_user := -netdev user,id=n0,net=10.0.2.0/24,dhcpstart=10.0.2.15

# Defaults
QEMU_NET_PREFIX :=
NETDEV := $(NETDEV_user)

# vmnet-shared via socket_vmnet (rootless): wrap QEMU and use fd=3
ifeq ($(NET_BACKEND),vmnet-shared)
  VMNET_SOCKET ?= $(HOMEBREW_PREFIX)/var/run/socket_vmnet
  QEMU_NET_PREFIX := $(HOMEBREW_PREFIX)/opt/socket_vmnet/bin/socket_vmnet_client $(VMNET_SOCKET)
  NETDEV := -netdev socket,id=n0,fd=3
endif

# vmnet-bridged via socket_vmnet (rootless): choose interface with VMNET_BRIDGE=en0/en1/...
ifeq ($(NET_BACKEND),vmnet-bridged)
  VMNET_BRIDGE ?= en0
  VMNET_SOCKET ?= $(HOMEBREW_PREFIX)/var/run/socket_vmnet.bridged.$(VMNET_BRIDGE)
  QEMU_NET_PREFIX := $(HOMEBREW_PREFIX)/opt/socket_vmnet/bin/socket_vmnet_client $(VMNET_SOCKET)
  NETDEV := -netdev socket,id=n0,fd=3
endif

# Device (keep RTL8139 + MAC)
NIC := -device rtl8139,netdev=n0,mac=52:54:00:12:34:56

run: os.img
	$(QEMU_NET_PREFIX) \
	$(QEMU) -m $(RAM) -fda os.img -boot a -no-reboot -monitor none -serial stdio \
		$(QEMU_DEBUG_FLAGS) $(NETDEV) $(NETDUMP) $(NIC)

run-hdd: hdd.img
	$(QEMU_NET_PREFIX) \
	$(QEMU) -m $(RAM) -drive file=hdd.img,format=raw,if=ide -no-reboot -monitor none -serial stdio \
		$(QEMU_DEBUG_FLAGS) $(NETDEV) $(NETDUMP) $(NIC)

clean:
	rm -rf $(OBJDIR) os.img hdd.img

tests/dhcp_packet_test: tests/dhcp_packet_test.c
	$(HOST_CC) -std=c11 -Wall -Wextra -Werror -o $@ $<

test-dhcp: tests/dhcp_packet_test
	./tests/dhcp_packet_test

.PHONY: all run run-hdd clean test-dhcp
