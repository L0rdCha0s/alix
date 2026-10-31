# Native address-layout expansion

The reviewed layout patch is now applied and passed native acceptance on
2026-10-31. Active headers, kernel sources and both linker scripts are the
authoritative implementation. This directory retains the original review
artifact and before/after SHA-256 fingerprints. `prepare_pending.py` and
`check_pending.py` were used before application; their old-baseline checks are
not intended to run against the already-applied tree.

The change addresses the real engine's static image size and virtual-memory
reservations. The previous image-to-stack gap was about 15 MiB; pinned ICU data
and allocated Rust sections already exceeded it before the JS C++ image linked.

| Region | Applied contract |
| --- | --- |
| User window | `0x100000000` through `0x3FFFFFFFFFFF` (4 GiB to 64 TiB minus one) |
| Static ELF | Starts at 4 GiB; exclusive end `0x13F7FF000` |
| Main stack guard | One page at `0x13F7FF000` |
| Main stack | 8 MiB, ending at `0x140000000` (5 GiB) |
| brk heap | 16 GiB starting at `0x180000000` (6 GiB), ending at 22 GiB |
| Anonymous VM | `0x581000000` through exclusive `0x3FFDFFFFE000` |
| Thread/TLS pool | 8 GiB ending immediately below the stub pages |
| Exit/thread stub | `0x3FFFFFFFE000` |
| Preemption stub | `0x3FFFFFFFF000` |

Both ELF scripts publish identical absolute contract symbols. The user linker
rejects images entering the main-stack guard; the kernel linker rejects kernel
images crossing into the user window. Independent ELF validation enforces the
image ceiling. Generic high thread/TLS segment allocation remains supported.
Main-thread stack metadata now reports the real reserved guard page.

## Audit findings

- The actual non-Windows x64 path in pinned SpiderMonkey
  `js/src/jit/ProcessExecutableMemory.cpp:434` uses 46-bit random mmap hints.
  Its 2 GiB–4 TiB range belongs to the Windows branch. The proposed window fits
  the active hint range and remains below GC's 47-bit mask in
  `js/src/gc/Memory.cpp:568` and `js/public/Value.h:293`.
- `MaxCodeBytesPerProcess` is 2044 MiB. Relative executable-pool branches remain
  within that pool; a VM arena beginning at 22 GiB is not a near-jump violation.
  x64 absolute runtime pointers already use 64-bit immediate/register paths.
  The pinned huge wasm32 reservation is 4 GiB plus 32 MiB and 64 KiB; the new
  arena can accommodate it without changing that upstream requirement.
- `paging_clone_kernel_space` shares only PML4 entries 256–511. These userspace
  mappings occupy entries 0–127; kernel physmap and MMIO mappings remain in the
  shared upper half. `ensure_page_table`, page indices and physical masks retain
  64-bit addresses, with dynamically tracked page-table allocations.
- User-copy limits and scheduler user-RIP validation derive from `g_mem_layout`.
  TLS uses full-width FS bases and TCB self pointers. The preemption bytecode
  stores full RAX into its saved-RIP slot and returns through a 64-bit address.
  User-page invalidation uses a full `uintptr_t` register operand. The kernel
  heap, physical-memory layout and AP bootstrap CR3 remain unchanged.
- The heap reservation initially allocates 8192 directory pointers (64 KiB),
  while the main stack allocates 2048 backing pointers (16 KiB). brk growth
  still eagerly commits the grown range; this patch does not turn sbrk into
  a fully lazy allocator. `PROT_NONE` anonymous VM has neither a backing array
  nor prepared page tables until small subranges gain access.
- The previous mmap implementation rejected unusable nonfixed hints before its
  fallback allocator. The pending change rounds valid advisory hints down and
  ignores unusable hints; fixed/NOREPLACE mappings stay strict. Host regressions
  cover outside, unaligned and occupied hints.
- Static ELF LOAD segments still need contiguous physical backing and the
  existing whole-file loading path. A larger virtual window is not a guarantee
  that a process can commit 16 GiB or load a 1 GiB physical image on a 4 GiB guest.
  Future ELF demand paging/shared images and broader memory pressure remain
  separate work.

The active implementations audited include `kernel_entry.c`, `process_memory.c`,
`process_vm.c`, `process_tls.c`, `process_api.c`, `process_scheduler.c`, the
preemption stubs, `paging.c`, kernel heap/user backing allocators, SMP and user
libc allocation. The old explicit 4–8 GiB limits were confined to the shared
layout header and host models; the linker origin was explicitly 4 GiB. Host
models now import the actual layout constants, retaining deliberately small
allocation capacities where they test exhaustion.

## Review evidence and current validation

These commands describe the completed pre-application review:

```sh
python3 ports/zen/layout/prepare_pending.py
python3 ports/zen/layout/check_pending.py
python3 ports/zen/layout/build_fixture.py
git -C .. apply --check Repo/ports/zen/layout/memory-layout.pending.patch
```

Checks passed for the pending C/user-linker/kernel-linker agreement, oversized
linker rejection, ELF guard/image boundaries, production VM transactions,
12 GiB sparse reservation with two committed endpoints, high-address auxiliary
pool reuse and delayed TLB acknowledgement/reclamation. Host behavior tests run
with ASan/UBSan. The actual native fixture linked with a 32 MiB constant payload;
its text LOAD has more than 32 MiB of file-backed bytes. The full Alix build,
five host contract gates and the native guest test completed successfully.

The review patch is rooted at the parent Git checkout (`Repo/...`). The current
build and guest validation sequence is:

```sh
make
make user-layout-contract-test native-vm-contract-test auxiliary-pool-test
make vm-reclamation-test elf-validation-test
python3 ports/zen/layout/build_fixture.py --active
python3 ports/zen/layout/guest_test.py
```

The guest helper refuses to boot unless the built kernel exports the expanded
contract. It uses the existing disposable-image `run-via-agent.sh` harness,
with a bounded 180-second run and a 90-second allowance for the larger ELF
download. The native fixture reserves 12 GiB across PML4 entries 63/64 and
commits only eight pages. Heap-owned shared state drives eight threads through
all CPUs, checking high stack/TLS addresses, user copies, protection changes
and generated code. Its required marker is:

```
USER_LAYOUT_TEST: PASS payload=32MiB sparse=12GiB pages=8 workers=8 cpu_mask=0xFF pml4=63,64 tls_high=1 jit=42
```

The PASS marker is recorded in `build/test-out/user-layout-qemu.log`. This gate proves the
expanded native memory contract; it does not establish that SpiderMonkey or
Zen executes successfully.
