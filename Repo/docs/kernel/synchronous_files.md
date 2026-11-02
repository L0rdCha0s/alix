# Synchronous file writes

The upstream runtime supports `open(..., O_SYNC)` on process-owned regular
files. A successful nonempty `write` waits for the existing VFS single-file
flush: new parent-directory metadata, file data and metadata, the AlixFS
commit, and the block device's cache-flush completion. Files on the in-memory
VFS have no persistent backing to flush.

The open description retains the synchronous flag. Duplicated and inherited
descriptors share it along with their file offset. `F_GETFL` reports `O_SYNC`;
`F_SETFL` can change append/nonblocking flags and cannot enable or disable
synchronous writes. Partial `FIONBIO` updates preserve it too. Read-only
access stays read-only, and a zero-length write does not issue a flush.

The protected storage worker holds the description/node references and the
shared-offset gate across writing and flushing. It receives copied request
data, with no borrowed user buffer or caller stack. An abandoned caller does
not cancel the worker's ownership. Independent descriptions continue to use
the VFS node data lock and mount flush serialization.

If persistence fails, write returns EIO. The data may already have changed
in memory and the shared offset may already have advanced; this is not a
rollback operation. Existing VFS failure handling leaves the mount queued
for recovery. Short successful writes flush the bytes actually written.

The legacy global descriptor runtime rejects `O_SYNC` with ENOTSUP before
opening or truncating a file. Its raw kernel entry also rejects the flag.
The normal Alix applications retain their existing descriptor namespace.

`make zen-synchronous-file-qemu-test` verifies 64 synchronous append writes
from eight CPU-pinned callers, shared aliases/offsets, immutable flags,
nonblocking open, checked-copy errors and legacy rejection. A stopped-VM
snapshot of a private 64 MiB AlixFS disk then passes a separate boot/remount
check of all 32 KiB and metadata, without an explicit fsync or guest shutdown
before the snapshot. This is QEMU persistence evidence; physical power loss
has not been tested.

The host synchronous-file contract executes the production write and FD
status code under ASan/UBSan and TSan. It checks 512 concurrent writes,
blocked flush completion, alias serialization, short writes, overflow and
write/flush failures. The separate production VFS/AlixFS writeback contract
uses a counted, faultable disk and checks actual cache-flush calls, failure
recovery and remount readback.

Gecko's actual Rust libc FFI fixture checks the 64-bit native open flag ABI,
synchronous status and writes. The configured NSPR file fixture executes
its actual nonblocking helper with synchronous status retained. These
component results do not establish complete NSPR or Zen startup.
