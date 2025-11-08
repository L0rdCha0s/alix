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
          -fno-merge-constants -fno-asynchronous-unwind-tables -fno-unwind-tables \
          -fshort-wchar

KERNEL_LD   := $(ARCH_DIR)/uefi.ld
LOADER_DIR  := src/loader

ARCH_KERNEL_SOURCES := $(filter-out $(ARCH_DIR)/uefi_boot.c,$(wildcard $(ARCH_DIR)/*.c))

C_SOURCES := \
	$(wildcard $(KERNEL_DIR)/*.c) \
	$(wildcard $(DRIVER_DIR)/*.c) \
	$(wildcard $(ATK_DIR)/*.c) \
	$(wildcard $(ATK_DIR)/util/*.c) \
	$(wildcard $(NET_DIR)/*.c) \
	$(wildcard $(CRYPTO_DIR)/*.c) \
	$(ARCH_KERNEL_SOURCES) \
	$(wildcard $(SBIN_DIR)/*.c)

C_OBJECTS := $(patsubst $(SRC_DIR)/%.c,$(OBJDIR)/%.o,$(C_SOURCES))

ASM_SOURCES := $(wildcard $(ARCH_DIR)/*.S)
ASM_OBJECTS := $(patsubst $(SRC_DIR)/%.S,$(OBJDIR)/%.o,$(ASM_SOURCES))

KERNEL_ELF := $(OBJDIR)/alix.elf
EFI_DIR    := build/EFI/BOOT
EFI_BIN    := $(EFI_DIR)/BOOTX64.EFI
DATA_IMG   := data.img
LOADER_SRC := $(LOADER_DIR)/uefi_loader.c
LOADER_CC  ?= x86_64-w64-mingw32-gcc
LOADER_CFLAGS := -std=c11 -ffreestanding -fno-stack-protector -fno-builtin -fno-pic \
                 -mno-red-zone -Wall -Wextra -I$(INCLUDE_DIR) -fshort-wchar
LOADER_LDFLAGS := -nostdlib -Wl,--dll -Wl,--entry=efi_main -Wl,--subsystem,10 \
                  -Wl,--image-base,0x4000000 -Wl,--file-alignment,0x200 -Wl,--section-alignment,0x1000 \
                  -Wl,--major-subsystem-version,10 -Wl,--minor-subsystem-version,0

all: $(KERNEL_ELF) $(EFI_BIN)

$(OBJDIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJDIR)/%.o: $(SRC_DIR)/%.S
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(KERNEL_ELF): $(C_OBJECTS) $(ASM_OBJECTS) $(KERNEL_LD)
	$(LD) -nostdlib -z max-page-size=0x1000 -T $(KERNEL_LD) -o $@ $(C_OBJECTS) $(ASM_OBJECTS)

LOADER_HEADERS := \
	$(INCLUDE_DIR)/uefi.h \
	$(INCLUDE_DIR)/bootinfo.h \
	$(INCLUDE_DIR)/arch/x86/bootlayout.h

$(EFI_BIN): $(LOADER_SRC) $(KERNEL_ELF) $(LOADER_HEADERS)
	@mkdir -p $(EFI_DIR)
	$(LOADER_CC) $(LOADER_CFLAGS) $(LOADER_LDFLAGS) -o $@ $<

$(DATA_IMG):
	truncate -s 4G $@

RAM ?= 4G
OVMF_CODE ?= vendor/OVMF_CODE.fd
OVMF_VARS ?= vendor/OVMF_VARS-1024x768.fd
QEMU_DEBUG_LOG   ?= qemu.log
QEMU_DEBUG_FLAGS ?= -d cpu_reset,int,guest_errors,trace:ahci_*,trace:ide_*,trace:cmd_identify -D $(QEMU_DEBUG_LOG)
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

run: $(EFI_BIN) $(DATA_IMG)
	$(QEMU_NET_PREFIX) \
	$(QEMU) -nodefaults -m $(RAM) -machine q35,accel=kvm:tcg \
		-drive if=pflash,unit=0,format=raw,readonly=on,file=$(OVMF_CODE) \
		-drive if=pflash,unit=1,format=raw,file=$(OVMF_VARS) \
		-drive if=none,id=fsdisk,file=fat:rw:build,format=raw \
		-device ahci,id=ahci0 \
		-device ide-hd,drive=fsdisk,bus=ahci0.0 \
		-drive if=none,id=data,file=$(DATA_IMG),format=raw,media=disk \
		-device ide-hd,drive=data,bus=ahci0.1 \
		-no-reboot -monitor vc:1280x1024 -serial stdio -vga std \
		$(QEMU_DEBUG_FLAGS) $(NETDEV) $(NETDUMP) $(NIC)

run-hdd: $(EFI_BIN) $(DATA_IMG)
	$(QEMU_NET_PREFIX) \
	$(QEMU) -nodefaults -m $(RAM) -machine q35,accel=kvm:tcg \
		-drive if=pflash,unit=0,format=raw,readonly=on,file=$(OVMF_CODE) \
		-drive if=pflash,unit=1,format=raw,file=$(OVMF_VARS) \
		-drive if=none,id=fsdisk,file=fat:rw:build,format=raw \
		-device ahci,id=ahci0 \
		-device ide-hd,drive=fsdisk,bus=ahci0.0 \
		-drive if=none,id=data,file=$(DATA_IMG),format=raw,media=disk \
		-device ide-hd,drive=data,bus=ahci0.1 \
		-no-reboot -monitor vc:1280x1024 -serial stdio -vga std \
		$(QEMU_DEBUG_FLAGS) $(NETDEV) $(NETDUMP) $(NIC)

clean:
	rm -rf $(OBJDIR) $(DATA_IMG)

tests/dhcp_packet_test: tests/dhcp_packet_test.c
	$(HOST_CC) -std=c11 -Wall -Wextra -Werror -o $@ $<

test-dhcp: tests/dhcp_packet_test
	./tests/dhcp_packet_test

.PHONY: all run run-hdd clean test-dhcp
