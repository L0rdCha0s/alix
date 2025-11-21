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
USER_DIR    := user
OBJDIR      := build
GENERATED_DIR := $(OBJDIR)/generated
DL_SCRIPT_SRC := $(GENERATED_DIR)/dl_script_data.c
DL_SCRIPT_OBJ := $(GENERATED_DIR)/dl_script_data.o

BASE_CFLAGS := -O4 -std=c11 -ffreestanding -fno-stack-protector -fno-builtin -fno-pic \
               -m64 -mno-red-zone -Wall -Wextra -g -I$(INCLUDE_DIR) -I$(ATK_DIR) \
               -fno-merge-constants -fno-asynchronous-unwind-tables -fno-unwind-tables \
               -fshort-wchar

KERNEL_CFLAGS := $(BASE_CFLAGS) -mgeneral-regs-only -mfpmath=387 -mno-sse \
                  -DKERNEL_BUILD
USER_CFLAGS := $(BASE_CFLAGS) -I$(USER_DIR) -I$(ATK_DIR) -DATK_NO_DESKTOP_APPS \
               -DVIDEO_WIDTH=640 -DVIDEO_HEIGHT=360 -msse2 -mfpmath=sse -mstackrealign

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
C_SOURCES := $(filter-out $(ATK_DIR)/atk_shell.c $(ATK_DIR)/atk_task_manager.c $(ATK_DIR)/atk_terminal.c,$(C_SOURCES))

C_OBJECTS := $(patsubst $(SRC_DIR)/%.c,$(OBJDIR)/%.o,$(C_SOURCES))
C_OBJECTS += $(DL_SCRIPT_OBJ)

ASM_SOURCES := $(filter-out $(ARCH_DIR)/ap_trampoline.S,$(wildcard $(ARCH_DIR)/*.S))
ASM_OBJECTS := $(patsubst $(SRC_DIR)/%.S,$(OBJDIR)/%.o,$(ASM_SOURCES))

USER_OBJDIR := $(OBJDIR)/user
USER_COMMON_SOURCES := \
	$(USER_DIR)/crt0.c \
	$(USER_DIR)/syscall.c \
	$(USER_DIR)/libc.c \
	$(USER_DIR)/atk_user.c \
	$(USER_DIR)/video_surface.c \
	$(USER_DIR)/serial_stub.c \
	$(USER_DIR)/atk_user_host_stub.c
USER_COMMON_OBJECTS := $(patsubst $(USER_DIR)/%.c,$(USER_OBJDIR)/%.o,$(USER_COMMON_SOURCES))
USER_COMMON_OBJECTS += $(USER_OBJDIR)/kernel/font.o $(USER_OBJDIR)/kernel/ttf.o
USER_LD_SCRIPT := $(USER_DIR)/link.ld
USER_ATK_SOURCES := $(filter-out $(ATK_DIR)/atk_shell.c $(ATK_DIR)/atk_task_manager.c $(ATK_DIR)/atk_terminal.c,$(wildcard $(ATK_DIR)/*.c))
USER_ATK_SOURCES += $(wildcard $(ATK_DIR)/util/*.c)
USER_ATK_OBJECTS := $(patsubst $(SRC_DIR)/%.c,$(USER_OBJDIR)/%.o,$(USER_ATK_SOURCES))
USER_ATK_EXTRA_SOURCES := $(USER_DIR)/atk/atk_terminal.c
USER_ATK_EXTRA_OBJECTS := $(patsubst $(USER_DIR)/%.c,$(USER_OBJDIR)/%.o,$(USER_ATK_EXTRA_SOURCES))
USER_ATK_OBJECTS += $(USER_ATK_EXTRA_OBJECTS)
USER_ELFS := $(USER_OBJDIR)/atk_demo.elf \
             $(USER_OBJDIR)/ttf_demo.elf \
             $(USER_OBJDIR)/wolf3d.elf \
             $(USER_OBJDIR)/doom.elf \
             $(USER_OBJDIR)/atk_shell.elf \
             $(USER_OBJDIR)/atk_taskmgr.elf \
             $(USER_OBJDIR)/control_panel.elf \
             $(USER_OBJDIR)/loop.elf
USER_BIN_DIR := build/bin
USER_BINS := $(USER_BIN_DIR)/atk_demo \
             $(USER_BIN_DIR)/ttf_demo \
             $(USER_BIN_DIR)/wolf3d \
             $(USER_BIN_DIR)/doom \
             $(USER_BIN_DIR)/atk_shell \
             $(USER_BIN_DIR)/atk_taskmgr \
             $(USER_BIN_DIR)/control_panel \
             $(USER_BIN_DIR)/loop
HOST_TEST_DIR := $(OBJDIR)/host-tests
HOST_TEST_BIN := $(HOST_TEST_DIR)/ttf_host_test
SHA256_TEST_BIN := $(HOST_TEST_DIR)/sha256_host_test
PNG_TEST_BIN := $(HOST_TEST_DIR)/png_host_test
HOST_TEST_CFLAGS := -std=c17 -Wall -Wextra -I$(INCLUDE_DIR) -DTTF_HOST_BUILD

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

CPU_TYPE ?= EPYC
TCG_CPU_TYPE ?= qemu64
SMP_CORES ?= 8
QEMU_SMP_OPTS := -smp $(SMP_CORES),sockets=1,cores=$(SMP_CORES),threads=1

all: $(KERNEL_ELF) $(EFI_BIN) $(USER_ELFS) $(USER_BINS)

$(OBJDIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(KERNEL_CFLAGS) -c -o $@ $<

$(OBJDIR)/%.o: $(SRC_DIR)/%.S
	@mkdir -p $(dir $@)
	$(CC) $(KERNEL_CFLAGS) -c -o $@ $<

NASM ?= nasm
AP_TRAMP_BIN := $(OBJDIR)/arch/x86/ap_trampoline.bin
AP_TRAMP_OBJ := $(OBJDIR)/arch/x86/ap_trampoline.o

$(AP_TRAMP_BIN): src/arch/x86/ap_trampoline.asm
	@mkdir -p $(dir $@)
	$(NASM) -f bin -o $@ $<

$(AP_TRAMP_OBJ): $(AP_TRAMP_BIN)
	$(LD) -r -b binary -o $@ $<

ASM_OBJECTS += $(AP_TRAMP_OBJ)

$(OBJDIR)/generated/%.o: $(OBJDIR)/generated/%.c
	@mkdir -p $(dir $@)
	$(CC) $(KERNEL_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/%.o: $(USER_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/atk/%.o: $(ATK_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/atk/util/%.o: $(ATK_DIR)/util/%.c
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/kernel/%.o: $(KERNEL_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(KERNEL_ELF): $(C_OBJECTS) $(ASM_OBJECTS) $(KERNEL_LD)
	$(LD) -nostdlib -z max-page-size=0x1000 -T $(KERNEL_LD) -o $@ $(C_OBJECTS) $(ASM_OBJECTS)

$(USER_OBJDIR)/atk_demo.elf: $(USER_COMMON_OBJECTS) $(USER_ATK_OBJECTS) $(USER_OBJDIR)/atk_demo.o $(USER_LD_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_ATK_OBJECTS) $(USER_OBJDIR)/atk_demo.o

$(USER_OBJDIR)/ttf_demo.elf: $(USER_COMMON_OBJECTS) $(USER_ATK_OBJECTS) $(USER_OBJDIR)/ttf_demo.o $(USER_LD_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_ATK_OBJECTS) $(USER_OBJDIR)/ttf_demo.o

$(USER_OBJDIR)/wolf3d.elf: $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/wolf3d.o $(USER_LD_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/wolf3d.o

$(USER_OBJDIR)/doom.elf: $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/doom.o $(USER_LD_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/doom.o

$(USER_OBJDIR)/atk_shell.elf: $(USER_COMMON_OBJECTS) $(USER_ATK_OBJECTS) $(USER_OBJDIR)/atk_shell_app.o $(USER_LD_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_ATK_OBJECTS) $(USER_OBJDIR)/atk_shell_app.o

$(USER_OBJDIR)/atk_taskmgr.elf: $(USER_COMMON_OBJECTS) $(USER_ATK_OBJECTS) $(USER_OBJDIR)/atk_taskmgr_app.o $(USER_LD_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_ATK_OBJECTS) $(USER_OBJDIR)/atk_taskmgr_app.o

$(USER_OBJDIR)/control_panel.elf: $(USER_COMMON_OBJECTS) $(USER_ATK_OBJECTS) $(USER_OBJDIR)/control_panel.o $(USER_LD_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_ATK_OBJECTS) $(USER_OBJDIR)/control_panel.o

$(USER_OBJDIR)/loop.elf: $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/loop.o $(USER_LD_SCRIPT)
	@mkdir -p $(dir $@)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/loop.o

$(DL_SCRIPT_SRC): $(USER_ELFS)
	@mkdir -p $(GENERATED_DIR)
	@{ \
		echo '#include "types.h"'; \
		echo; \
		echo 'const char g_dl_script_content[] ='; \
		printf '    "%s\\n"\n' '#!/bin/sh'; \
		printf '    "%s\\n"\n' '# Auto-generated user binary downloader'; \
		printf '    "%s\\n"\n' 'cd /usr/bin'; \
		printf '    "%s\\n"\n' 'rm *.elf'; \
		found=0; \
		for elf in $(USER_OBJDIR)/*.elf; do \
			if [ -f "$$elf" ]; then \
				name=$$(basename "$$elf"); \
				printf '    "wget 192.168.105.1:8000/build/user/%s\\n"\n' "$$name"; \
				found=1; \
			fi; \
		done; \
		if [ $$found -eq 0 ]; then \
			printf '    "%s\\n"\n' '# No user ELF files were built'; \
		fi; \
		echo ';'; \
		echo 'const size_t g_dl_script_content_len = sizeof(g_dl_script_content) - 1;'; \
	} > $(DL_SCRIPT_SRC)


$(USER_BIN_DIR)/atk_demo: $(USER_OBJDIR)/atk_demo.elf
	@mkdir -p $(USER_BIN_DIR)
	cp $< $@

$(USER_BIN_DIR)/ttf_demo: $(USER_OBJDIR)/ttf_demo.elf
	@mkdir -p $(USER_BIN_DIR)
	cp $< $@

$(USER_BIN_DIR)/wolf3d: $(USER_OBJDIR)/wolf3d.elf
	@mkdir -p $(USER_BIN_DIR)
	cp $< $@

$(USER_BIN_DIR)/doom: $(USER_OBJDIR)/doom.elf
	@mkdir -p $(USER_BIN_DIR)
	cp $< $@

$(USER_BIN_DIR)/atk_shell: $(USER_OBJDIR)/atk_shell.elf
	@mkdir -p $(USER_BIN_DIR)
	cp $< $@

$(USER_BIN_DIR)/atk_taskmgr: $(USER_OBJDIR)/atk_taskmgr.elf
	@mkdir -p $(USER_BIN_DIR)
	cp $< $@

$(USER_BIN_DIR)/control_panel: $(USER_OBJDIR)/control_panel.elf
	@mkdir -p $(USER_BIN_DIR)
	cp $< $@

$(USER_BIN_DIR)/loop: $(USER_OBJDIR)/loop.elf
	@mkdir -p $(USER_BIN_DIR)
	cp $< $@

$(HOST_TEST_BIN): tests/ttf_host_test.c src/kernel/ttf.c
	@mkdir -p $(HOST_TEST_DIR)
	$(HOST_CC) $(HOST_TEST_CFLAGS) tests/ttf_host_test.c src/kernel/ttf.c -o $@

$(SHA256_TEST_BIN): tests/sha256_host_test.c src/crypto/sha256.c include/crypto/sha256.h
	@mkdir -p $(HOST_TEST_DIR)
	$(HOST_CC) $(HOST_TEST_CFLAGS) tests/sha256_host_test.c src/crypto/sha256.c -o $@

$(PNG_TEST_BIN): tests/png_host_test.c src/atk/util/png.c
	@mkdir -p $(HOST_TEST_DIR)
	$(HOST_CC) $(HOST_TEST_CFLAGS) -DPNG_HOST_BUILD tests/png_host_test.c src/atk/util/png.c -o $@

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
QEMU_DEBUG_FLAGS ?= -d cpu_reset,int,guest_errors,trace:ahci_*,trace:ide_* -D $(QEMU_DEBUG_LOG)
QEMU_GDB_FLAGS   ?=
HOMEBREW_PREFIX  := $(shell brew --prefix)
UNAME_S          := $(shell uname -s)

ifndef QEMU_ACCEL
  ifeq ($(UNAME_S),Linux)
    QEMU_ACCEL := kvm:tcg
  else ifeq ($(UNAME_S),Darwin)
    QEMU_HAS_HVF := $(shell $(QEMU) -accel help 2>/dev/null | grep -w hvf)
    ifneq ($(strip $(QEMU_HAS_HVF)),)
      QEMU_ACCEL := hvf:tcg
    else
      QEMU_ACCEL := tcg
    endif
  else
    QEMU_ACCEL := tcg
  endif
endif

ACCEL_PRIMARY := $(firstword $(subst :, ,$(QEMU_ACCEL)))
ifeq ($(ACCEL_PRIMARY),tcg)
  QEMU_CPU_OPTS := -cpu $(TCG_CPU_TYPE)
else
  QEMU_CPU_OPTS := -cpu $(CPU_TYPE)
endif
QEMU_MACHINE_OPTS := -machine q35,accel=$(QEMU_ACCEL)

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

run: $(EFI_BIN) $(DATA_IMG) $(USER_ELFS) $(USER_BINS)
	$(QEMU_NET_PREFIX) \
	$(QEMU) -nodefaults -m $(RAM) $(QEMU_MACHINE_OPTS) $(QEMU_CPU_OPTS) $(QEMU_SMP_OPTS) $(QEMU_GDB_FLAGS) \
		-drive if=pflash,unit=0,format=raw,readonly=on,file=$(OVMF_CODE) \
		-drive if=pflash,unit=1,format=raw,file=$(OVMF_VARS) \
		-drive if=none,id=fsdisk,file=fat:rw:build,format=raw \
		-device ahci,id=ahci0 \
		-device ide-hd,drive=fsdisk,bus=ahci0.0 \
		-drive if=none,id=data,file=$(DATA_IMG),format=raw,media=disk \
		-device ide-hd,drive=data,bus=ahci0.1 \
		-no-reboot -monitor vc:1280x1024 -serial stdio -vga std \
		$(QEMU_DEBUG_FLAGS) $(NETDEV) $(NETDUMP) $(NIC)

run-hdd: $(EFI_BIN) $(DATA_IMG) $(USER_ELFS) $(USER_BINS)
	$(QEMU_NET_PREFIX) \
	$(QEMU) -nodefaults -m $(RAM) $(QEMU_MACHINE_OPTS) $(QEMU_CPU_OPTS) $(QEMU_SMP_OPTS) $(QEMU_GDB_FLAGS) \
		-drive if=pflash,unit=0,format=raw,readonly=on,file=$(OVMF_CODE) \
		-drive if=pflash,unit=1,format=raw,file=$(OVMF_VARS) \
		-drive if=none,id=fsdisk,file=fat:rw:build,format=raw \
		-device ahci,id=ahci0 \
		-device ide-hd,drive=fsdisk,bus=ahci0.0 \
		-drive if=none,id=data,file=$(DATA_IMG),format=raw,media=disk \
		-device ide-hd,drive=data,bus=ahci0.1 \
		-no-reboot -monitor vc:1280x1024 -serial stdio -vga std \
		$(QEMU_DEBUG_FLAGS) $(NETDEV) $(NETDUMP) $(NIC)

run-hdd-gdb: QEMU_GDB_FLAGS = -s -S
run-hdd-gdb: run-hdd

clean:
	rm -rf $(OBJDIR) $(USER_BIN_DIR)

.PHONY: clean clean-all

clean-all: clean
	rm -f $(DATA_IMG)

tests/dhcp_packet_test: tests/dhcp_packet_test.c
	$(HOST_CC) -std=c11 -Wall -Wextra -Werror -o $@ $<

test-dhcp: tests/dhcp_packet_test
	./tests/dhcp_packet_test

ttf-test: $(HOST_TEST_BIN)
	$(HOST_TEST_BIN) SF-Pro.ttf

sha256-test: $(SHA256_TEST_BIN)
	$(SHA256_TEST_BIN)

png-test: $(PNG_TEST_BIN)
	$(PNG_TEST_BIN) lenna.png

.PHONY: all run run-hdd run-hdd-gdb clean test-dhcp ttf-test sha256-test png-test
