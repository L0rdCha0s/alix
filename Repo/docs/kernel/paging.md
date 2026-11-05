# Disk swap and demand paging

Alix now pages anonymous VM backing, committed sbrk heap pages, main-stack
pages and dirty private file pages to a dedicated block device. A protected
pager selects resident pages when PMM free memory falls below its target,
unmaps a selected page, waits for all remote TLB acknowledgements outside
locks, then writes it to an owned swap slot. The physical page is released
only after successful I/O. A failed write reinstalls the original mapping.

Page-in occurs when the user accesses evicted backing. Fault entry copies the
complete exception/GPR/FP state into thread-owned heap storage and returns
from the per-CPU IST onto that thread's own kernel stack. Protected I/O workers
retain process ownership, perform disk reads, verify the in-memory slot checksum
and publish the new physical backing. No disk wait holds a VM, paging, heap or
scheduler spinlock. Process termination cannot abandon an in-flight worker or
free its process/page metadata. Failed reads preserve the slot and cause SIGBUS.
Fork can retain immutable swap slots; each process independently reads and
releases its ownership. Final VM/heap/stack cleanup releases outstanding slots.

The fault continuation also preserves a pending user preemption destination
across kernel waits and restores the full FP environment. Syscall entry captures
the preemption-stub return address before any paging work can reuse that TLS
slot. AHCI now bounces high-half physmap payloads through its owned low heap
buffers: a kernel virtual address must never be programmed as a DMA address.

## Configuring a dedicated device

Run `make swap-image` to create a new 256 MiB `swap.img`. The tool uses exclusive
creation and never overwrites an existing path. An alternative is:

```sh
python3 scripts/mkswap.py /path/to/new-swap.img --size-mib 512
make run-hdd SWAP_IMG=/path/to/new-swap.img
```

The normal QEMU targets attach an existing signed image as `/dev/ahci2`, using a
private snapshot overlay per VM. `run-via-agent.sh` uses those targets too.
`SWAP_IMG` or `QEMU_SWAP_IMG` selects an alternative source. No image is created
by normal `make` or boot. Only devices whose first page contains `ALIXSWP1` and
a valid bounded page count are accepted. Discovery never formats or changes a
filesystem disk. Swap contents and allocation metadata are volatile across boot.
The current swap store is unencrypted.

`cat /proc/memory/swap` reports enablement, used slots, successful page reads,
writes and errors. The default free-memory target is one sixteenth of RAM,
clamped to 8–64 MiB. Writing a decimal MiB value to
`/proc/memory/swap_target_mib` overrides it; zero restores the default. A value
above currently available memory deliberately makes reclamation aggressive.
Successful disk restores increment the process major-fault counter.

## Current scope and limits

The initial safe-copy policy restores a process's evicted pages before entering
a syscall and excludes that process from reclamation until all its concurrent
syscalls leave. This prevents disk waits inside existing scheduler-locked copies,
futex comparisons and request-preparation guards. It also means blocked syscalls
pin their process, and a syscall may need the complete pageable working set to
fit in RAM. Per-request page pinning and restartable kernel copies remain future
work; this implementation is not a general overcommit guarantee.

ELF regions, TLS and auxiliary thread-stack regions remain pinned. Clean file
cache pages and the VFS's resident file contents remain resident as well.
File-backed `MAP_PRIVATE` now uses COW, with dirty private pages eligible for
swap. This pager provides disk demand restoration of evicted anonymous/private
backing; it does not make AlixFS itself a disk-demand-loaded page cache.

Existing native eight-CPU libc/math/thread and VM programs have been executed
through the new userland `time` launcher with aggressive reclamation. Receipts
under `build/test-out/` record actual page-out/page-in, checksummed payload
recovery, C11 runtime markers and child/parent exit status. These are bounded
QEMU results; physical-device stress and long-duration low-memory reliability
remain separate acceptance work.
