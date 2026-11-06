# Native file mappings and synchronization

The owned descriptor runtime supports regular-file `mmap` with `MAP_SHARED` or
`MAP_PRIVATE`, and `msync`. These use native syscalls 76 and 77. Existing anonymous
mapping calls and address-space layout are unchanged. The legacy global FD
runtime rejects file mappings with `ENOTSUP`; it can synchronize valid anonymous
ranges. No legacy descriptor integer is translated into the private table.

## File contents and permissions

Shared mappings of the same VFS node and file page use the same physical page,
including mappings in independently spawned processes. VFS reads observe mapped
stores, and VFS writes update the affected shared bytes. Closing, duplicating or
reusing the source FD does not change a mapping. Rename preserves the retained
node identity. Private mappings initially share read-only file-cache pages.
A first write fault allocates and copies just that process page; private stores are never
written back to the file. Protection changes and VMA splits preserve private
page ownership, and fork copies already dirty private pages into the child.
Shared mappings from read-only descriptors allocate/cache physical pages on
first use. Splits preserve their original backing offsets. The per-file page
index avoids repeated linked-list searches while constructing large mappings.
Private mappings now use copy-on-write. Mapping preparation materializes a lazy
AlixFS payload on a protected storage worker before publishing a mapping. Clean
source file contents then remain resident in the VFS; dirty private pages can use the [swap pager](paging.md).
This does not introduce a disk-backed, evictable AlixFS file cache.
Hardware COW faults complete their TLB barrier before resuming. COW performed
by a checked kernel copy records a completion ticket under the memory lock;
syscall exit awaits that ticket outside locks before returning to user space.

The descriptor must be open for reading. A writable shared mapping also requires
write access and a mutable node. Read-only shared descriptions cannot gain write
access through `mprotect`; private mappings can be writable from a read-only FD.
Page offsets are signed 64-bit values and must be page-aligned. A partial final
page is zero-filled, and bytes beyond the file size do not extend the file or
reach disk. The configured NSPR map helper preserves the full native file offset.

The existing VM transaction machinery handles `PROT_NONE`, protection changes,
partial unmaps and fixed replacement. Fragments retain independent references
to their backing description. Failed preparation leaves existing mappings intact.
File-backed `MADV_DONTNEED` returns `ENOTSUP`; nondestructive POSIX advice remains
available.

## Ownership and synchronization

The storage worker captures file contents into stable shared cache pages or
private snapshot pages. Its result is a deferred backing description. Before any
VM/TLB wait, the live caller transfers that reference into heap-owned thread
cleanup state. Published VM areas retain their own references. Removed areas
release them only after the transaction's remote TLB acknowledgements, or after
quiescent process teardown. The backing destructor runs on the protected cleanup
worker, releases the node and reclaims pages. No worker receives a caller stack
pointer, borrowed process pointer or user virtual address.

VFS data locks serialize cache metadata and ordinary I/O. CPU stores use the
shared physical pages directly. VFS access and filesystem serialization merge
changed cache bytes into the file buffer and dirty metadata. Flushd snapshots only nodes with shared mappings that can become writable,
then merges their changed bytes outside the filesystem namespace lock.
Read-only library mappings do not participate in dirty discovery. Changed
nodes enter a reference-owned writeback queue, so ordinary writeback does not
walk the mounted filesystem. The final backing release merges remaining stores before
reclaiming the cache.

`msync` validates the entire rounded mapping range before submitting I/O. It
captures backing references into a deferred bundle and binds that bundle to a
registered storage request. Concurrent unmap/close or caller termination cannot
free the worker's pages. Shared backing is merged and flushed through the existing
AlixFS data/ancestor metadata commit and device-cache flush. I/O failures return
`EIO`, retaining existing writeback recovery state. A flush can include other
dirty bytes in the same file. Private and anonymous mappings validate successfully
without writing private contents to disk.

Exactly one of `MS_SYNC` and `MS_ASYNC` is required; `MS_INVALIDATE` is optional.
Both write modes currently complete synchronously. Shared aliases already use
coherent pages, so invalidation requires no separate stale-cache replacement.
The general contracts are described by the official
[mmap](https://man.openbsd.org/mmap.2) and
[msync](https://man.openbsd.org/msync.2) manuals.

## Current limits

Mappings containing whole pages beyond EOF return `ENXIO`. Shrinking or truncating
a file with a live mapping returns `EBUSY`, including `O_TRUNC`; extending it is
supported. Supporting truncation underneath active mappings requires coordinated
cross-process invalidation and `SIGBUS` delivery. These restrictions prevent
stale backing and silent zero-page substitution while that path remains absent.
Devices, callback-backed nodes and shared anonymous mappings remain unsupported.
Named volatile objects use this same mapping machinery through
[`shm_open` and `shm_unlink`](shared_memory.md), with a separate kernel namespace
and no persistent filesystem backing.
This establishes file mapping components, not full POSIX VM conformance or a
complete NSPR/Zen runtime.

## Validation

`make zen-file-mapping-qemu-test` passes three eight-CPU guests. The main fixture
checks 512 atomic updates, independent aliases and processes, private isolation,
source close/offset preservation, access checks, protection splits, checked
sync ranges, killed-owner cleanup, exact tail/size behavior and truncate rejection.
An independent AlixFS boot reads 32,785 persisted bytes after `msync`, with no
explicit `fsync`. The third guest checks legacy namespace isolation.

Evidence is in `build/test-out/file-mapping-qemu.log`,
`file-mapping-remount-qemu.log` and `file-mapping-legacy-qemu.log`.
`tests/native_vm_contract_test.py` covers production VM ownership, splitting,
allocation failure, delayed acknowledgements and cancellation with file backing.
`tests/filesystem_writeback_test.py` runs the production cache and AlixFS code
against a faultable disk, checking shared/private pages, allocation rollback,
write/cache-flush errors, recovery and remount contents. Both pass ASan/UBSan.
Actual Gecko Rust libc bindings and extracted NSPR map/sync/unmap helpers are
also exercised in Alix; their error sink is instrumented and full NSPR
initialization is outside that fixture.
