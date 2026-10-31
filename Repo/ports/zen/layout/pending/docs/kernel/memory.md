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

### TLB completion and retired backing

`paging_request_tlb_flush(space)` publishes page-table changes with a monotonic
generation and returns a value-only `{generation, cpu_mask}` ticket. The local
CPU invalidates immediately; each remote IPI handler captures the requested
generation **before** its flush and publishes an acknowledgement afterward.
Acknowledgements never move backwards. Local invalidation includes global PTEs
by toggling CR4.PGE; reloading CR3 alone would leave those translations cached.

`paging_tlb_flush_complete(ticket)` is a nonblocking query. The existing
`paging_flush_space_tlb` remains an asynchronous request. No caller waits for
an IPI while holding the memory, paging, scheduler, or heap locks. CPU startup
publishes its online-mask participation before flushing and acknowledging prior
requests, then publishes `online=true`; address-space switches publish the
incoming active bit before loading CR3 and clear the outgoing bit afterward.

User segment unmapping, heap shrinking, and failed mapping/commit rollback now
transfer physical backing into heap-owned retirement batches. Those records
contain physical ranges and the completion ticket, never a process pointer or
another thread's stack pointer. Region retirement metadata is reserved at map
time, including secondary-thread stacks. Heap shrink and heap/stack growth
reserve their complete retirement/rollback batch before changing mappings, so
allocation failure cannot force premature reclamation or a partial shrink.

`process_reap_retired_memory()` detaches batches under its queue lock, checks
acknowledgements without waiting, and returns completed backing to the PMM
outside that lock. Scheduler/idle hooks only reap with interrupts enabled and
without a generic spinlock held. The reaper defers preemption while it owns a
detached list, keeping IRQ delivery enabled; process cancellation cannot strand
other processes' retired memory on a discarded kernel stack. Final process teardown and creation-failure
cleanup may free still-owned pages directly because the process has no active
threads/address-space users at those call sites.

These legacy helpers establish **safe backing reuse** while retaining their
asynchronous completion contract. The native anonymous VM interfaces described
below additionally await their completion tickets outside all locks before
returning from mapping, protection and unmapping transactions.
`tests/vm_reclamation_test.py` exercises production generation/retirement code
with delayed CPU acknowledgement, a request arriving during invalidation, OOM,
heap/stack rollback, and unmapped-word access.

### Kernel Mappings

The kernel maintains a few always-present mappings:

- **Low identity map**: an identity mapping of the first 4 GiB of physical address space, used for early boot and legacy assumptions.
- **Physmap (direct map)**: a high-half direct mapping of physical RAM at `KERNEL_PHYSMAP_BASE` (see `include/physmem.h`).
  - Kernel code can access any PMM-allocated physical page `p` via `phys_to_virt(p)`.
- **Ioremap window**: a high-half virtual window at `KERNEL_IOREMAP_BASE` used to map device MMIO ranges on demand (see `include/ioremap.h` and `src/kernel/ioremap.c`).

These upper-half mappings are shared into all address spaces via `paging_clone_kernel_space` so the kernel can run while a user CR3 is active.

Kernel permission updates invalidate each affected local virtual address even
when a user CR3 is active or another CPU already set the requested PTE bits.
The local CPU can still hold an older global translation in either case.
Remote flush publication remains conditional on actual PTE changes; local
invalidation does not fabricate a remote acknowledgement. This lets scheduler
stack activation restore local write access before entering the stack.
`tests/kernel_permission_tlb_test.py` covers changed and unchanged PTEs under
both kernel and user address spaces.

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

`process_memory_resolve_user_locked` resolves heap, stack, ELF and anonymous VM
backing while holding `memory_lock`, enforcing write permissions and bounding
the returned span to one page. General syscall copies use that physical mapping
under the lock, then release it before processing the next page. Unmapping and
protection changes therefore cannot free or invalidate backing during a copy;
invalid input fails instead of faulting on an unchecked user virtual address.
A failed multi-page copy may have copied earlier pages. The resolver does not
permit a physical pointer to escape its lock. `process_memory_read_user_u32`
uses the same resolver for the atomic futex comparison.

## Stack Guards and Diagnostics

The process subsystem contains multiple safety mechanisms:

- Guard regions filled with a known pattern.
- Optional guard page protection (depending on build flags).
- Stack-owner tracking and “stack write debug” utilities to catch cross-thread/async stack misuse.

## Native anonymous VM (`src/kernel/process/process_vm.c`)

User libc exposes `mmap`, `mprotect` and `munmap` through `<sys/mman.h>` and
syscalls 48–50. The current backend supports process-private anonymous mappings,
`MAP_FIXED_NOREPLACE`, and atomic `MAP_FIXED` replacement. File-backed and shared
mappings remain unsupported. The caller must pass `fd=-1` and `offset=0`.

`PROT_NONE` reserves an interval without physical backing. Granting access
commits zeroed pages; removing all access from an already committed mapping
preserves its data for a later protection restore. Partial protection and
unmapping split intervals while retaining unaffected fragments. Unmapping holes
is harmless; protecting a range containing a hole fails without changing it.
`MAP_FIXED` allocates fresh zeroed backing before replacing all intersecting VM
areas and holes, retaining both outside fragments and the old physical pages
until remote TLB acknowledgement. `MAP_FIXED_NOREPLACE` returns `EEXIST` on any
overlap, including a `PROT_NONE` reservation.

All defined `PROT_*` combinations are supported, including RWX mappings used by
upstream SpiderMonkey. On x86-64, write or execute permission implies readable
pages; the software-copy resolver uses the same effective permissions. Unknown
protection bits are rejected without changing a mapping. Generated-code tests
exercise both RW-to-RX transitions and direct RWX allocation.
Each transaction prepares all metadata, new backing and page-table levels before
changing leaf PTEs. Physical or metadata allocation failure preserves the prior
mapping. Prepared empty page tables remain owned as address-space cache if later
preparation fails; their allocation tracking is now dynamic instead of a fixed
512-table ceiling.

The process owns an in-flight transaction journal. It contains removed metadata,
retired backing and the completion ticket, so killing the requesting thread's
process cannot strand allocations on its kernel stack. Native VM operations are
serialized until the journal completes. Leaf/metadata publication happens under
`memory_lock`; the caller releases every lock and restores interrupts before
waiting for remote acknowledgement. Only then are retired backing and metadata
reclaimed and the syscall allowed to return. Quiescent process teardown also
owns a journal abandoned by process termination.

`madvise(address, length, MADV_DONTNEED)` uses syscall 56 to discard private
anonymous backing without changing the mapping's address or permissions. The
address must be page-aligned; the length rounds up to a page boundary. The
entire range must be mapped, including any `PROT_NONE` portions, or the request
fails without discarding a partial range. Physical pages are removed from PTEs
and placed in the process-owned transaction journal; they are freed only after
the TLB completion ticket is acknowledged. Discarding already sparse pages is
valid and never frees physical address zero.

A discarded page is a null entry in its VMA's backing array. The first allowed
user instruction fault or safe syscall copy allocates one zero-filled page
under `memory_lock` and publishes its prepared PTE. Permission checks happen
before allocation, so a write to read-only memory, any access to `PROT_NONE`,
and execution without `PROT_EXEC` remain rejected. The fault path never waits
for an IPI: a refill during an outstanding discard uses new backing while the
journal retains the old page until acknowledgement. Two first touches serialize
under the lock and share the one committed page. A failed allocation leaves the
page sparse; a failed syscall copy reports failure and a failed user fault takes
the existing fatal-user-fault path. Protection changes, fixed replacement,
splitting, unmapping, and teardown all accept sparse backing arrays.

`posix_madvise` has deliberately different semantics: POSIX advice must preserve
the contents. Its syscall advice namespace (`0x100 | advice`) validates the
complete mapping and accepts NORMAL, RANDOM, SEQUENTIAL, WILLNEED, and DONTNEED
as performance hints. Alix currently ignores those hints because it has no
paging replacement/prefetch policy. It returns positive error codes and does
not modify `errno`. This never invokes destructive discard; see the
[POSIX interface specification](https://www.man7.org/linux/man-pages/man3/posix_madvise.3p.html).

`tests/native_vm_contract_test.py` checks physical reclamation, partial-range
preservation, allocation failures, sparse PTEs, first touches before delayed CPU
acknowledgement, and cancellation during discard. The native
`thread_vm_advice_test.elf` checks zero-fill through instructions and syscall
copies, POSIX content/errno preservation, and 64 discard/refill rounds on four
CPUs. `tests/vm_advice_qemu_test.py` also verifies that post-discard write,
`PROT_NONE`, and execute violations remain fatal.

The native user address window is 4 GiB through 64 TiB minus one, below
SpiderMonkey's 47-bit pointer ceiling. Static ELF images start at 4 GiB and must
end before the guard beneath the 8 MiB main stack, whose top is 5 GiB. The brk
heap reserves 16 GiB starting at 6 GiB; its initial two-level directory costs
64 KiB, and physical pages are committed as brk grows. Main-stack backing
metadata costs 16 KiB and its pages are committed on stack growth.

The anonymous VM arena starts 16 MiB above the heap limit and ends beneath an
8 GiB descending thread/TLS pool. Two stub pages remain at the top of the user
window. Legacy segment allocation rejects the whole anonymous arena, including
uncommitted holes. Nonfixed mmap addresses are advisory: usable hints are
page-rounded, while occupied/out-of-range hints fall back to free space. Fixed
and NOREPLACE addresses retain strict bounds/alignment checks.

`include/memory_layout.h`, `user/lib/link.ld` and `src/arch/x86/uefi.ld` expose
the same checked contract. Both linker scripts publish absolute layout symbols
and reject overlap; ELF validation independently enforces the image ceiling and
main-stack guard. `make user-layout-contract-test` compares C values with both
linked symbol sets and proves oversized images fail their linker assertions.
The separate `ports/zen/layout/user_layout_test.c` fixture contains a real
32 MiB constant payload and reserves 12 GiB across PML4 entries 63/64, committing
only eight pages. It checks high syscall copies, eight-CPU protection/TLS and
high generated code; compilation alone is not guest acceptance. Stack and TLS allocation now searches existing region
gaps in the auxiliary pool, preserving a guard page below each allocation. It
reuses freed holes instead of permanently consuming a descending cursor. A new
stack/TLS mapping also completes a cross-CPU TLB barrier before the new thread
can use it, preventing a recycled VA from accessing retired physical backing.

Validation targets: `make vm-reclamation-test`, `make native-vm-contract-test`
and `make user-copy-contract-test`. `tests/auxiliary_pool_test.py` checks pool
exhaustion, fragmentation, guard preservation, 4096 hole-reuse cycles, and the
publication barrier. `thread_pool_reuse_test.elf` creates and joins 256 threads
with 2 MiB of TLS each, exceeding the pool size cumulatively without exceeding
its concurrent capacity. `virtual_memory_test.elf` exercises sparse
reservation, partial protections, fixed replacement, generated code, and four
CPUs reading during protection/replacement changes. Its `fault-write`,
`fault-none` and `fault-exec` modes deliberately trigger user page faults to
check hardware permissions; those cases require a fault-aware guest harness.
