# Kernel Architecture (Alix)

This folder documents how the kernel boots, schedules work, manages memory, exposes files and devices, and implements networking + syscalls.

## Start Here

- Boot + early init: `docs/kernel/boot.md`
- Processes/threads + scheduler: `docs/kernel/process.md`
- Memory (heap, paging, user mappings): `docs/kernel/memory.md`
- VFS/filesystems/mounts: `docs/kernel/vfs.md`
- AlixFS2 backend details: `docs/kernel/alixfs.md`
- Syscalls, FDs, sockets: `docs/kernel/syscalls.md`
- Networking (drivers + protocols): `docs/kernel/network.md`
- Audio streaming, counters and playback diagnostics: `docs/kernel/audio.md`
- Source tree map: `docs/kernel/source_map.md`
- Other subsystems (ACPI, console, time, logging, audio, fonts): `docs/kernel/other.md`

## Repository Layout (kernel-relevant)

- `src/kernel/`: architecture-independent kernel core (VFS, processes, syscalls, heap, procfs/devfs, etc)
- `src/arch/x86/`: x86_64 bring-up (entry, IDT/interrupts, paging, syscall/preempt stubs, LAPIC, AP trampoline)
- `src/loader/`: UEFI loader that loads `alix.elf` and builds `bootinfo_t`
- `src/drivers/`: device drivers (PCI, disks, NICs, serial, timer, keyboard/mouse, video, audio)
- `src/net/`: network stack (ARP/DHCP/DNS/ICMP/NTP/TCP/TLS + routing + interface registry)
- `include/`: public kernel headers shared across subsystems
