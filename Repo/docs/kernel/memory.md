# Memory Management (Heap, Paging, Physical RAM, User Mappings)

This kernel has four major memory layers:

1. **Kernel heap** (`malloc`/`free`): dynamic allocations for kernel objects.
2. **Paging and address spaces**: kernel mappings + per-process user mappings.
3. **Physical memory manager (PMM)**: tracks free physical RAM ranges from E820 and hands out page-aligned allocations.
4. **User memory backing**: physical pages used to back user virtual ranges (currently a thin wrapper over PMM).

## Global Layout (`include/memory_layout.h`, `src/arch/x86/kernel_entry.c`)

`g_mem_layout` defines:

- Kernel heap virtual range (`kernel_heap_base`..`kernel_heap_end`)
- User pointer window (`user_pointer_base`..`user_pointer_limit`)
- User stack and heap virtual regions
- Identity-mapped low physical limit (`identity_map_limit`)
- Minimum physical address reserved for user page backing (`user_phys_min`)

`kernel_entry_main` computes/adjusts parts of this layout from the E820 map in `boot_info`.

## Kernel Heap (`src/kernel/heap.c`)

The heap is a bin-based allocator with:

- A global heap lock (spinlock) and optional lock tracing.
- Per-bin free lists (`HEAP_BIN_COUNT`) to speed up allocation.
- Optional tracing + procfs controls via `heap_sys_controls_init`.

Important operational notes:

- Kernel code should prefer heap allocation for objects that outlive the current call path or might be accessed by other CPUs later.
- Deep stack allocations are risky in an SMP kernel, especially when pointers escape to async work.

## Paging (`include/paging.h`, `src/arch/x86/paging.c`)

Paging code provides:

- Kernel page table initialisation and feature detection (NX/SMEP/SMAP).
- Per-process `paging_space_t` objects that can:
  - Clone or share kernel mappings
  - Map user pages/ranges (`paging_map_user_page/range`)
  - Unmap user pages
  - Flush TLBs locally and remotely

Locking:

- There is a global paging lock, plus optional per-space locks (`paging_space_t.lock`).
- Remote TLB flush uses SMP IPIs (see `smp_broadcast_tlb_flush` and `paging_handle_remote_tlb_flush`).

### Kernel Mappings

The kernel maintains a few always-present mappings:

- **Low identity map**: an identity mapping of the first 4 GiB of physical address space, used for early boot and legacy assumptions.
- **Physmap (direct map)**: a high-half direct mapping of physical RAM at `KERNEL_PHYSMAP_BASE` (see `include/physmem.h`).
  - Kernel code can access any PMM-allocated physical page `p` via `phys_to_virt(p)`.
- **Ioremap window**: a high-half virtual window at `KERNEL_IOREMAP_BASE` used to map device MMIO ranges on demand (see `include/ioremap.h` and `src/kernel/ioremap.c`).

These upper-half mappings are shared into all address spaces via `paging_clone_kernel_space` so the kernel can run while a user CR3 is active.

## Physical Memory Manager (PMM) (`include/pmm.h`, `src/kernel/pmm.c`)

The PMM builds a free-range list from the E820 map (`boot_info.e820`, type=1 usable RAM) and then **reserves** physical ranges that must not be allocated:

- Low memory (BIOS/real-mode data), bootstrap stack, bootstrap page tables
- Kernel image
- SMP trampoline / AP boot data
- Kernel heap region
- Loader-provided bootinfo copy and framebuffer ranges (if present)

The PMM exposes page/range allocation APIs returning `paddr_t` physical addresses.

## User Physical Backing (`include/user_memory.h`, `src/kernel/user_memory.c`)

`user_memory.c` is currently a thin wrapper over the PMM used by the process subsystem to allocate/free physical pages for user mappings.

## User Virtual Memory and Address Spaces (`src/kernel/process/process_memory.c`)

User processes have:

- A per-process page table (`process->address_space`)
- A list of mapped user regions (`process->user_regions`)

Mapping path:

- `process_map_user_segment(process, user_base, bytes, writable, executable, &host_ptr_out)`
  1. Allocates physical backing from `user_memory_alloc` (PMM).
  2. Tracks the mapping as a `process_user_region_t`.
  3. Maps the user virtual range to the physical pages via paging helpers.
  4. Returns a kernel host pointer for initialisation/copying via the physmap (`phys_to_virt`).

User stack and heap:

- The user stack is mapped near `USER_STACK_TOP` with a fixed size.
- The user heap is a large reserved window; `process_user_sbrk` grows it by mapping additional pages on demand.

## Stack Guards and Diagnostics

The process subsystem contains multiple safety mechanisms:

- Guard regions filled with a known pattern.
- Optional guard page protection (depending on build flags).
- Stack-owner tracking and “stack write debug” utilities to catch cross-thread/async stack misuse.
