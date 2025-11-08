# alix

## Building (UEFI only)

The BIOS pipeline is gone. We now build two artifacts:

1. `build/alix.elf` – the actual kernel image (ELF64, linked at 0x0010_0000).
2. `build/EFI/BOOT/BOOTX64.EFI` – a tiny UEFI loader that reads `\alix.elf`, loads its PT_LOAD segments, collects firmware data (GOP, ACPI, memory map), exits boot services, and jumps into the kernel.

Run `make` and both binaries will be produced in the `build/` tree that we export to QEMU as a FAT drive. You still need the usual cross toolchain (`x86_64-elf-gcc`, `binutils`, etc.).

## Running in QEMU with OVMF

1. Download OVMF from the Tianocore project and place the firmware blobs at:
   - `vendor/OVMF_CODE.fd`
   - `vendor/OVMF_VARS-1024x768.fd`
2. Run `make run-hdd` (preferred) or `make run`. Both targets launch QEMU with:
   - `-nodefaults -machine q35,accel=kvm:tcg`
   - A virtio VGA device plus a FAT-backed drive that points at the `build/` directory (`-drive format=raw,file=fat:rw:build`)
   - The RTL8139 NIC wired through the existing socket_vmnet plumbing if enabled
   - Serial routed to stdio and a 1024x768 monitor window
   - Debug and trace channels enabled via `-d cpu_reset,int,guest_errors,trace:ahci_*,trace:ide_*,trace:cmd_identify`

The running kernel provides a shell (`shutdown` exits cleanly). If you need to terminate QEMU manually while preserving serial logs, run `killall qemu-system-x86_64`.
