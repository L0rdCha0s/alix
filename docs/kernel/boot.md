# Boot + UEFI Path

This document follows the boot flow from UEFI → `kernel_entry` → `kernel_main`, and where SMP fits in.

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
5. Allocate pages for the final `bootinfo_t` in physical memory, copy it there, then `ExitBootServices`.
6. Jump to the kernel entry: `kernel_entry((bootinfo_t*)boot_info_phys)`.

`bootinfo_t` (see `include/bootinfo.h`) is the only structured handoff between the loader and kernel.

## 2) Kernel Entry (`src/arch/x86/kernel_entry.c`)

The UEFI loader jumps to `kernel_entry(bootinfo_t *loader_info)`.

`kernel_entry` is a naked function that:

- Disables interrupts (`cli`)
- Switches to a known-good bootstrap stack (`STACK_TOP` from `include/arch/x86/bootlayout.h`)
- Calls `kernel_entry_main(loader_info)`

`kernel_entry_main(...)` then performs early setup in a predictable order:

1. Bring up serial logging (`serial_init`) for early kernel logs.
2. Zero the `.bss` section.
3. Copy the loader-provided `bootinfo_t` into the global `boot_info`.
4. Derive kernel heap bounds and the global `g_mem_layout` from the E820 map:
   - Heap placement is bounded by usable RAM (`configure_heap_from_e820`)
   - User pointer window is kept *above* the identity-mapped low region (`configure_memory_layout_from_e820`)
5. Build initial page tables (`build_page_tables`) and load CR3.
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
- User layout: `user/link.ld`

If you change virtual/physical layout assumptions, update both the linker scripts and `g_mem_layout` logic.

