# Kernel Source Map

This is a path-oriented map of the kernel codebase. It’s not a substitute for reading code, but it should answer “where do I look?” quickly.

## Core (`src/kernel/`)

- `src/kernel/kernel.c` — top-level kernel init (`kernel_main`): initialises subsystems and starts the scheduler.
- `src/kernel/startup.c` — optional startup script runner (`/etc/startup.rc`) executed via a kernel process.
- `src/kernel/smp.c` — SMP bring-up using ACPI MADT + AP trampoline; also provides scheduler/TLB IPIs.
- `src/kernel/acpi.c` — ACPI discovery + minimal table parsing (RSDP/RSDT/XSDT/FADT) for power management + MADT helpers.
- `src/kernel/bootinfo.c` — defines the global `boot_info` copy populated from the loader.
- `src/kernel/hwinfo.c` — gathers and prints basic CPU/memory info (used by `/proc` and boot summary).
- `src/kernel/timekeeping.c` — wall-clock/timezone logic layered on `timer_ticks()` + timezone DB.
- `src/kernel/tzdb.c` — timezone database loader/parser (used by `timekeeping.c`).
- `src/kernel/power.c` — shutdown/reboot glue (typically via ACPI).
- `src/kernel/console.c` — console output (VGA text + optional framebuffer-backed text cells).
- `src/kernel/logger.c` — simple append-only log file under `/var/log` (VFS-backed).
- `src/kernel/libc.c` — kernel-side libc subset (memcpy/memset/strlen/etc); kernel code uses this, not host libc.
- `src/kernel/heap.c` — kernel heap allocator + tracing + procfs controls; used by `malloc/calloc/realloc/free`.
- `src/kernel/user_memory.c` — allocator for *physical* pages intended for user-space mappings (backed by E820 “usable” RAM).
- `src/kernel/user_copy.c` — permission-checked syscall copies through owned physical backing under the process memory lock.
- `src/kernel/vfs.c` — in-memory VFS tree + path resolution + mount/writeback plumbing.
- `src/kernel/vfs_internal.h` — internal node/mount structures for `vfs.c` + filesystem backends.
- `src/kernel/alixfs.c` — on-disk filesystem backend (AlixFS2) used for VFS mounts on block devices.
- `src/kernel/block.c` — block device registry + common `block_read/write/flush` wrappers.
- `src/kernel/devfs.c` — `/dev` population for block devices + callback-backed device nodes.
- `src/kernel/procfs.c` — `/proc` creation + callback-backed files (control + stats endpoints).
- `src/kernel/proc_devices.c` — `/proc/devices/*` information endpoints (CPU/mem/block/net/pci).
- `src/kernel/fd.c` — small kernel file descriptor table (`fd_ops_t` + `ctx`), shared by files and sockets.
- `src/kernel/fd/table.c` — refcounted descriptions and private descriptor-table foundation; user syscalls still use the legacy global table.
- `src/kernel/io/request.c`, `src/kernel/io/service.c` — heap-owned requests, protected storage workers and independent cleanup; VFS/socket syscall migration is pending.
- `src/kernel/syscall.c` — syscall dispatcher + syscall implementations (VFS files, sockets, shell service, UI, snapshots).
- `src/kernel/shell_service.c` — long-lived shell sessions exposed to userland via syscalls.
- `src/kernel/elf.c` — ELF parsing/loading used for user process creation.
- `src/kernel/audio.c` — audio subsystem glue and procfs controls.
- `src/kernel/font.c`, `src/kernel/ttf.c`, `src/kernel/font_cache.c` — font loading/raster + caching.
- `src/kernel/user_atk.c` — “remote ATK window” host: userland UI surfaces presented into kernel UI.
- `src/kernel/userbin.c` — optional injection/population of built-in user binaries.
- `src/kernel/process.c` — historical compatibility stub, excluded from the build.

## Process Subsystem (`src/kernel/process/`)

These are separate translation units. Shared internal contracts are declared in
`include/process_internal.h`; static helpers are local to their source file.

- `process_common.c` — shared helpers, global registries, low-level context switch (`context_switch`), user-mode stubs.
- `process_thread.c` — thread creation, stack allocation/guards, per-thread metadata.
- `process_scheduler.c` — run queues, dequeue/enqueue, priority + affinity, context switching, stack guard handling.
- `process_memory.c` — user address space creation, mapping user segments (stack/heap/ELF), teardown.
- `process_vm.c` — anonymous VM reservations, protection, discard and transactional mapping changes.
- `process_tls.c` — ELF TLS and thread-control-block construction.
- `process_futex.c` — process-private address waits with scheduler-serialized publication and wakeup.
- `process_io.c` — thread request ownership, completion waits and cancellation/reclamation integration.
- `process_init.c` — `process_system_init`, idle threads, scheduler start for BSP/APs.
- `process_api.c` — public API in `include/process.h` (create/join/kill, sleep/yield, timer tick preempt hook, snapshots).

## x86_64 (`src/arch/x86/`)

- `kernel_entry.c` — kernel entry point (`kernel_entry`): copies `bootinfo_t`, sets memory layout, builds page tables, enters `kernel_main`.
- `paging.c` — page table management: kernel space init + per-process spaces + user mappings + TLB flushing (incl. remote).
- `interrupts.c`, `idt.c` — IDT and interrupt handlers; timer IRQ drives preemption and broadcasts schedule IPIs.
- `syscall_entry.S` — vector 0x80 entry stub: saves regs and calls `syscall_dispatch`.
- `exception_entry.S` — normalized full-register entry for divide, invalid-opcode, stack, general-protection and page faults.
- `process_preempt.S` — kernel-mode preempt trampoline used by timer/IPI to force a `process_yield`.
- `lapic.c`, `cpu.c`, `segments.*` — CPU/LAPIC setup, per-CPU stack pointers, GDT selectors.
- `ap_trampoline.asm` — AP bootstrap blob copied to low memory by `smp.c`.
- `uefi.ld` — kernel linker script (keep this in sync with layout changes).

## Loader (`src/loader/`)

- `uefi_loader.c` — UEFI loader: reads `\\alix.elf`, loads segments, captures framebuffer/ACPI, builds `bootinfo_t`, exits boot services, jumps to `kernel_entry`.

## Networking (`src/net/`, `src/drivers/`)

- `src/net/interface.c` — interface registry + safe TX helpers (including stack/DMA guard copies).
- `src/net/route.c` — routing table + default gateway selection.
- `src/net/arp.c` — ARP cache + request/reply + announcements.
- `src/net/icmp.c` — ICMP echo (ping) handling.
- `src/net/dhcp.c` — DHCP client logic (UDP-based).
- `src/net/dns.c` — DNS query client (UDP-based).
- `src/net/ntp.c` — NTP client (UDP-based).
- `src/net/tcp.c` — small TCP stack + client sockets integrated with `fd.c`.
- `src/net/tls*.c` — TLS client support layered on TCP sockets.
- `src/drivers/rtl8139.c`, `src/drivers/igb.c` — NIC drivers that dispatch Ethernet frames into ARP/IP/ICMP/TCP/(UDP: DHCP/DNS/NTP).

