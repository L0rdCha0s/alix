# Kernel Architecture (Alix)

This folder documents how the kernel boots, schedules work, manages memory, exposes files and devices, and implements networking + syscalls.

## Start Here

- Boot + early init: `docs/kernel/boot.md`
- Physical hardware, USB and framebuffer support: `docs/kernel/hardware.md`
- Native C11 libc, math and threads: `docs/kernel/libc.md`
- Native performance workloads and UI latency: `docs/performance.md`
- Measured kernel performance fixes: `docs/performance-pass-2026-11-05.md`
- Processes/threads + scheduler: `docs/kernel/process.md`
- Native user child launch and waiting: `docs/kernel/child_processes.md`
- Signal delivery, masks and synchronous waiting: `docs/kernel/signals.md`
- Memory (heap, paging, user mappings): `docs/kernel/memory.md`
- Disk swap, fault continuations and pageable backing: `docs/kernel/paging.md`
- Native RLBox memory, minimum WASI and WABT trap integration: `docs/kernel/wasm_sandbox.md`
- Shared file pages, private snapshots and msync: `docs/kernel/file_mappings.md`
- Volatile named shared-memory objects: `docs/kernel/shared_memory.md`
- VFS/filesystems/mounts: `docs/kernel/vfs.md`
- Synchronous file writes and persistence: `docs/kernel/synchronous_files.md`
- Enforced process descriptor limits: `docs/kernel/descriptor_limits.md`
- AlixFS2 backend details: `docs/kernel/alixfs.md`
- Syscalls, FDs, sockets: `docs/kernel/syscalls.md`
- Kernel build identity, hostname and process credentials: `docs/kernel/system_identity.md`
- Native ELF libraries, symbols and dynamic TLS: `docs/kernel/dynamic_loading.md`
- Full NSPR library initialization, threads, networking and processes: `docs/kernel/nspr_runtime.md`
- Process-owned byte pipes: `docs/kernel/pipes.md`
- Gather writes, atomic pipe vectors and request ownership: `docs/kernel/vectored_io.md`
- Native poll/select readiness and cancellation: `docs/kernel/poll.md`
- Native socket entry points and remaining network API work: `docs/kernel/sockets.md`
- Native DNS ownership and libc address lookup: `docs/kernel/resolver.md`
- Terminal classification and current non-TTY streams: `docs/kernel/termios.md`
- Native window controls, surfaces and ownership: `docs/kernel/windows.md`
- WebRender's native FreeType glyph rasterizer: `docs/kernel/glyph_rasterization.md`
- Gecko's Thebes platform, font discovery and bundled fonts: `docs/kernel/gecko_graphics.md`
- Networking (drivers + protocols): `docs/kernel/network.md`
- Owned IPv4 UDP transport and shared port leases: `docs/kernel/udp_transport.md`
- Outgoing route snapshots and native MTU discovery: `docs/kernel/network_routes.md`
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
