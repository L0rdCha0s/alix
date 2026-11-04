# Boot + UEFI Path

This document follows the boot flow from UEFI → `kernel_entry` → `kernel_main`, and where SMP fits in.

## QEMU volumes

`make` stages a dedicated boot volume in `build/boot/` containing only:

```text
alix.elf
EFI/BOOT/BOOTX64.EFI
```

`make run`, `make run-hdd`, `make run-hdd-rtl` and `make run-ps2-hdd`
attach two separate disks in this order:

| Volume | Host source | Guest device | Purpose |
| --- | --- | --- | --- |
| Boot | `build/boot/` (read-only virtual FAT) | `/dev/ahci0` | Firmware loads the EFI loader and kernel. |
| Main | `data.img` (writable AlixFS2) | `/dev/ahci1`, mounted at `/root` | Persistent applications, configuration and home directories. |

The AHCI disk model requires a writable device, so the boot disk has a temporary
write overlay (`snapshot=on`). Guest writes to it are discarded when QEMU exits;
the staged host files remain read-only. Main-volume writes persist in `data.img`.

`/usr`, `/etc` and `/home` point into the main volume. User binaries still
build under `build/bin/` and `build/user/`; the existing `/usr/bin/dl.sh` workflow installs
them to `/root/usr/bin`. They do not belong on the firmware boot volume.
The bundle includes the native SpiderMonkey CLI as `js.elf`; after running
`dl.sh`, use `js --help`, `js -e print(6*7)`, or `js path/to/script.js`.
See [SpiderMonkey setup and CLI](../../ports/zen/README.md#installed-javascript-cli)
for the upstream build prerequisite and package acceptance test.

The same installer downloads `build/fonts.zip` and extracts its OFL-licensed
Public Sans and Noto families, language fonts, CJK collection, symbols, math and
emoji into `/root/usr/share/fonts`, exposed through `/usr/share/fonts`.
The normal build packages the vendored, hash-pinned files without network
access. See [system font assets](../../vendor/fonts/README.md) for the inventory,
source revisions and Gecko integration boundary.

Boot also seeds `/usr/bin/dl-zen.sh` from the repository's `dl-zen.sh`. With
`./serve-dl.sh` running on the host, run `./dl-zen.sh` from `/usr/bin` (or
`/usr/bin/dl-zen.sh` from anywhere) to install `build/ports/zen/zen-browser.zip`
into `/usr/lib/zen`, together with the system fonts. It bootstraps its own
unzip executable, so it can run before `dl.sh`. Close Zen before updating;
start it afterward with the desktop Browser tile or `runelf /usr/lib/zen/zen`.
See [Zen installation](../zen_port.md#installing-and-launching-zen) for host
build and packaging instructions.

The full `build/` tree is never exported to QEMU. Its debug symbols, object
files, ports and test output can grow beyond virtual FAT16's capacity without
affecting boot. The staged files refresh when the kernel or loader changes.
`BOOT_DIR=/path/to/staging` overrides the generated boot directory and
`DATA_IMG=/path/to/main.img` selects another main disk. Existing main disks
are reused without truncation or formatting. A missing main image is created
as a blank 4 GiB disk; formatting it requires an explicit guest `mkfs` command.

## 1) UEFI Loader (`src/loader/uefi_loader.c`)

Entry point is `efi_main(...)`.

High-level flow:

1. Initialise early serial for debug (`serial_early_init` / `serial_early_write_*`).
2. Open the boot volume and read `\\alix.elf` into memory.
3. Parse and load kernel ELF segments (`load_kernel_segments(...)`), producing a callable `kernel_entry_t`.
4. Populate a `bootinfo_t`:
   - Framebuffer info (`capture_framebuffer`)
   - ACPI RSDP pointer + optional copy (`capture_acpi_rsdp`)
   - E820-style memory map derived from the UEFI memory map (`convert_to_e820` inside `exit_boot_services`)
5. Reserve bootstrap stack, page tables and `bootinfo_t` below 4 GiB through
   UEFI; reserve the fixed AP real-mode region or select single-CPU fallback.
   Record framebuffer RGB masks and validate the final memory map, then `ExitBootServices`.
6. Jump to the kernel entry: `kernel_entry((bootinfo_t*)boot_info_phys)`.

`bootinfo_t` (see `include/bootinfo.h`) is the only structured handoff between the loader and kernel.

## 2) Kernel Entry (`src/arch/x86/kernel_entry.c`)

The UEFI loader jumps to `kernel_entry(bootinfo_t *loader_info)`.

`kernel_entry` is a naked function that:

- Disables interrupts (`cli`)
- Switches to the firmware-reserved bootstrap stack in `bootinfo_t.stack_top`
- Calls `kernel_entry_main(loader_info)`

`kernel_entry_main(...)` then performs early setup in a predictable order:

1. Zero the `.bss` section.
2. Bring up bounded, optional serial logging (`serial_init`).
3. Copy the loader-provided `bootinfo_t` into the global `boot_info`.
4. Derive kernel heap bounds and the global `g_mem_layout` from the E820 map:
   - Heap placement is bounded by usable RAM (`configure_heap_from_e820`)
   - User pointer window is kept *above* the identity-mapped low region (`configure_memory_layout_from_e820`)
5. Build initial page tables in the firmware-reserved pages (`page_table_base`) and load CR3.
6. Initialise BSP CPU state/segments (`arch_cpu_init_bsp`).
7. Call `kernel_main()` (defined in `src/kernel/kernel.c`).

## 3) Kernel Main (`src/kernel/kernel.c`)

`kernel_main` is the “bring up subsystems, then start scheduling” function.

Key ordering constraints worth remembering:

- `heap_init()` happens early because most subsystems allocate dynamically.
- `user_memory_init()` relies on `boot_info.e820` and is used for user-space page backing.
- `paging_init()` occurs after `heap_init` so it can allocate additional structures.
- `process_system_init()` prepares run queues/idle threads and must occur before starting SMP scheduling.

Near the end of `kernel_main`, the kernel:

- Starts APs (`smp_start_secondary_cpus`)
- Binds the BSP to its idle thread stack (`process_bind_idle_to_bsp`)
- Marks the scheduler as ready, enables interrupts, and enters the scheduler loop (`process_start_scheduler`)

## 4) SMP Bring-up (`src/kernel/smp.c`, `src/arch/x86/ap_trampoline.asm`)

SMP has two distinct phases:

1. **Discovery + trampoline setup** (`smp_init`):
   - Uses ACPI (MADT) and LAPIC IDs to enumerate CPUs.
   - Copies the AP trampoline blob (`ap_trampoline`) to a reserved low physical region (`SMP_TRAMPOLINE_PHYS`).
   - Prepares `smp_bootstrap_data_t` at `SMP_BOOT_DATA_PHYS` for APs to read during startup.
2. **Start APs** (`smp_start_secondary_cpus`):
   - Sends INIT/SIPI sequences via LAPIC to wake APs.
   - APs run the trampoline and enter `smp_secondary_entry(apic_id)`.
   - `smp_secondary_entry` initialises per-CPU state then hands control to the scheduler via `process_run_secondary_cpu(cpu_index)`.

## 5) Linker Scripts / Layout

- Kernel layout: `src/arch/x86/uefi.ld` and constants in `include/arch/x86/bootlayout.h`
- User layout: `user/lib/link.ld`

If you change virtual/physical layout assumptions, update both the linker scripts and `g_mem_layout` logic.

See [physical hardware support](hardware.md) for disk safety, xHCI/BOT storage,
GOP graphics, interrupt/timer assumptions and the isolated acceptance runners.

### Periodic timer rate

The PIT uses rate-generator mode (channel 0 command 0x34). The previous
square-wave setup produced about 200 kernel ticks per host second in q35 QEMU
while advertising 100 Hz. The rate-generator setup measures about 100; this
restores real durations for input repeat, sleeps, animation and periodic work.
The observed host comparison includes short debugger-attachment overhead and
is recorded in `build/ports/zen/performance-20261104/clock-rate.json`. Physical
machine timing is not established by this QEMU measurement.
