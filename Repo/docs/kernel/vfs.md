# VFS / Filesystems / Mounts

The kernel’s VFS is a heap-backed tree of nodes with optional backing storage for mounts.

## Core Data Structures (`src/kernel/vfs_internal.h`)

`vfs_node_t` represents a directory, file, block device, or symlink:

- Tree links: `parent`, `first_child`, `next_sibling`
- Identity: `name`, `type`, `uid/gid`
- Data:
  - For regular files: `data` buffer + `size/capacity` (heap-backed)
  - For callback-backed nodes: `read_cb`/`write_cb` + `callback_context` (procfs/devfs style)
- Lifetime: `refcount` (tree refs + FD refs)
- Concurrency: per-node `data_lock` for file data mutations

`vfs_mount_t` ties a block device to a subtree and tracks dirty/writeback state.

## Locking Model (`src/kernel/vfs.c`)

- `g_vfs_tree_lock`: protects tree shape (parent/child links, node creation/removal, mount list). It uses an adaptive scheduler-friendly acquisition path because mount loading can poll storage and yield; contenders yield instead of pinning every CPU behind a preempted owner.
- `node->data_lock`: protects per-file content buffer + dirty tracking fields.

Callers generally:

- Take the tree lock for path resolution and structural operations.
- Take the data lock only around file contents (read/write/truncate).

## Path Resolution

Public entry points:

- `vfs_resolve(cwd, path)` — resolves to an existing node.
- `vfs_mkdir(cwd, path)` — creates one directory; its parent must already exist.
- `vfs_mkdir_exclusive(cwd, path, uid, gid)` — strict userspace creation under
  the tree lock; existing leaves return EEXIST and new nodes use captured caller
  credentials. It does not change the older kernel create-or-return contract.
- `vfs_open_file(cwd, path, create, truncate)` — resolves/creates a file node.

Resolution supports:

- Absolute (`/foo`) and relative paths (from `cwd`)
- `.` and `..`
- Symlinks (bounded by `VFS_MAX_SYMLINK_DEPTH`)
- Mount point traversal

## Protected user I/O

Regular-file mappings use stable shared physical cache pages, with VFS I/O
coherence and protected storage-worker synchronization. See
[file mappings](file_mappings.md) for ownership and the active-mapping shrink
restriction.

Process-owned regular files support `O_SYNC` writes through the protected
storage worker. Each successful nonempty write waits for data/metadata
commit and a device cache flush. See [synchronous files](synchronous_files.md)
for ownership, failure semantics and independent remount evidence.

Syscall 66 implements native `readlink` through persistent VFS workers. The
caller copies its path into a heap request and captures an owned cwd description
with its credentials. Workers receive no caller stack or user address. Results
are copied out only after the live caller obtains its registered completion.
Killed callers abandon their waiter ownership; a running worker finishes and
cleanup releases the remaining resources.

`vfs_readlink_snapshot` holds tree/data locks while copying target bytes,
follows intermediate symlinks, and leaves the final symlink unexpanded. It
returns bounded bytes without a NUL. Native path/target limits are 4095 bytes;
overlong replacement fails before mutation. Existing oversized targets remain
stored and report `ENAMETOOLONG` through the checked APIs.

Regular-file adapters retain nodes before releasing the tree lock and
serialize shared offsets with an ownership gate. Registered requests first try
bounded resident READ/PREAD, SEEK and metadata operations in the caller. Offset,
data and namespace locks are tried once; contention falls back to a protected
worker. Reads requiring persistent relatime updates, shared writable mapping
coherence, callbacks or nonresident data also fall back before any copy or
offset change. SET/CUR seeks need only offset ownership; END needs a size
snapshot. Writes, path operations, mapping preparation and persistence remain
worker operations. No caller stack or user pointer enters a continuation.
The ordinary data adapters reject callback-backed
nodes, whose identity and context lifetimes require separate adapters. The
original user open/read/write syscall IDs retain the legacy global FD table.
The upstream runtime instead selects syscall 71 and private descriptors, with
registered storage requests and independent event-driven TCP waits. Private
OPEN reserves a slot before create/truncate, preserving files when admission
fails. See [syscalls.md](syscalls.md).

The native VFS fixture passed real symlink snapshots, owned cwd changes,
4095/4096-byte boundaries, a caller killed while a worker waited on the real
tree lock, cleanup and a fresh successful request. The public `readlink` fixture
also passed. Evidence is in `build/test-out/vfs-owned-bridge-qemu.log`; the
runner removed its optional hooks and restored the ordinary kernel.

## Directory streams

`opendir`, `readdir`, `rewinddir` and `closedir` use syscall 70 and protected
VFS workers. Each user process owns a 256-slot private table shared by directory
streams, syscall 71 files/sockets and its threads. These integers never index
the legacy global FD table. Kernel-launched processes begin with three owned
stdio slots, leaving 253 slots for additional descriptions. User-parent
construction clones completed entries with CLOEXEC filtering; in-flight OPEN
reservations are omitted. Quiescent process teardown transfers the table to
the protected retirement worker.

An open stream retains its directory node and owns a compact immutable blob of
names, types and runtime object identities, including `.` and `..`. Names are
copied under the tree lock, retain their raw encoding and accept up to 4095
bytes without truncation. Identities are nonzero 64-bit counters which never
wrap or expose kernel addresses; they remain stable for the node's runtime
lifetime and are not persisted on disk. Concurrent changes are reflected by a
new open or a successful rewind. A failed rewind preserves the previous view.

Workers serialize each shared cursor with a sleeping gate and copy value
records into registered heap requests. A caller killed during a wait cannot
leave its stack/user address in a worker. Close removes a handle immediately;
already pinned operations retain their stream until completion and deferred
cleanup. `DIR` itself is heap-owned; callers must synchronize shared uses of
its returned entry buffer and quiesce users before `closedir`.

Deferred node close and worker rollback use `vfs_node_release_owned`, which
holds the tree lock through final orphan-subtree destruction. This prevents a
retained child from observing a freed parent during snapshot/resolve. Internal
tree-held releases retain the raw non-locking release; guarded permanent-root
rollback is also non-final and does not enter a waiting tree operation.

Native eight-CPU acceptance passed independent streams, 180-byte and UTF-8
names, refreshed rewind, stable parent identities, 50 entries consumed exactly
once through a shared cursor, EOF/error behavior and 256-handle exhaustion with
recovery. See `build/test-out/directory-stream-qemu.log`. Host snapshot/cursor
tests also passed ASan/UBSan and TSan, including 21,000 snapshots concurrent with
256 orphan-parent final releases. `dirfd`, `fdopendir`, seek/tell and
`scandir` are not exposed yet; integration with the future private POSIX file
table is still required.

## Mutability Controls

The VFS supports “read-only subtrees”:

- `vfs_set_subtree_mutable(node, allow)`

This is used to “lock” parts of the tree while leaving dynamic trees (like `/proc`) writable.

## Filesystems and Mounts

The default block-backed filesystem backend is AlixFS2:

- Backend implementation: `src/kernel/alixfs.c`
- Mount operations: `vfs_mount_device`, `vfs_format`, `vfs_sync_*` in `src/kernel/vfs.c`

AlixFS2 specifics (on-disk layout, chunk table, writeback ordering, limitations):

- `docs/kernel/alixfs.md`

Dirty tracking is per-node and per-mount; `vfs_sync_dirty()` writes back dirty nodes and may apply backpressure when dirty bytes exceed thresholds.

Growing regular files receive a short writeback grace period. Flushd leaves a
file dirty while writes are still arriving, then persists it after 300 ms of
quiescence; this avoids repeatedly serializing and rewriting the whole AlixFS
node during a download. The mount-wide dirty-data limit is 64 MiB, while a
single actively growing node is flushed early at 48 MiB so backpressure still
has a bounded recovery path. Forced sync and shutdown always bypass the grace
period.

If synchronous writeback fails while a writer waits for dirty-data space,
the wait fails too: regular writes and resize return `EIO`, and append reports
failure. This prevents an exhausted AlixFS node table or failed device from
leaving a download/extraction blocked indefinitely. Smaller legacy AlixFS
tables are expanded on mount; see [AlixFS allocation](alixfs.md#node-ids).

Forced sync commits dirty nodes and flushes the device cache; it does not
rewrite clean files. Writeback failures retain dirty records and backend
metadata for incremental retry. `vfs_flush_node()` immediately persists the file and its directory
ancestors, commits the chunk table/header, and flushes the device cache. It is
a successful no-op for RAM-backed files such as `/tmp`.

`make filesystem-writeback-test` executes the production VFS and AlixFS code
against an in-memory block device. It checks IO counts, remount integrity,
active-writer deferral, forced sync, directory creation, and injected failures.
For QEMU storage timing investigations, compile `src/drivers/ahci.c` with
`-DAHCI_TRACE_PERF=1`. Each device-cache flush then emits cumulative command,
byte, scheduler-yield, and tick counts in one `[ahci] perf` line. Compare
successive lines to measure the work attributable to a download. Enable
`/proc/sys/vfs/log_enable` for per-file sync durations.

## File identity and ownership

The full metadata snapshot reports a numeric filesystem/device identity,
inode, link count and uid/gid along with size/type/timestamps. Inodes share the
tree-locked runtime identity used by readdir. Independent opens and aliases
agree; rename retains identity, unlink reports zero links while a descriptor
still owns the node, and recreation receives a different identity. Mounted
filesystems receive distinct device identities. These numbers are stable for
the live VFS object, rather than persistent on-disk inode numbers across boots.
Directories report two links plus their immediate child directories; hard links
remain unsupported. Anonymous descriptions report zero filesystem identity.

`vfs_chown_owned` applies captured caller credentials under tree/data locks.
Root may change owner/group. Other callers must own the node, retain its owner
and choose either its existing group or their primary group. UINT32_MAX leaves
that field unchanged. Successful updates mark metadata/ctime dirty. Immutable
nodes, callbacks and old version-2 mounts without ownership storage fail.
Existing version-3/4 AlixFS records persist ownership without a format change.

`make zen-file-identity-qemu-test` verifies 512 snapshots on eight CPUs, both
stat ABIs with adjacent canaries, readdir/rename/unlink/recreation, directory
links, mount identities and checked output errors. An independent boot reads
back a synced file with owner 12345 and group 23456. Host ASan/UBSan and TSan
contracts cover owner policy and 4,000 coherent snapshots during 4,000 updates.
Basic mode bits and fchmod now use the same captured-credential/storage path.
Owner or root may change `0777`; file-type bits are ignored and unsupported
set-ID/sticky modes return EOPNOTSUPP. Existing descriptions retain their granted
read/write directions. New owned opens check the final file's owner/group/other
bits before truncation; creation checks its parent's write/search bits. Full
ancestor-search policy, per-open creation modes, umask and ACLs remain work.
File creation currently retains the previous `0666` default. Native process-owned
byte-range locks now have [separate acceptance](flock.md#process-owned-byte-range-locks).

Modes persist in AlixFS's optional versioned node trailer. The independent
readback test now also verifies `0640`; host contracts check versions 2/3/4,
unknown-extension rejection, unchanged file data and retry after the mode write
fails. Mode/owner snapshot contention tests cover 4,000 updates of each kind.
The protected utimes path now also persists explicit access/modify seconds and
checks captured caller authority. The independent remount verifies those times
without changing file content or mode.

## devfs and procfs

- `src/kernel/devfs.c`:
  - Ensures `/dev` exists.
  - Populates block devices as VFS nodes of type `VFS_NODE_BLOCK`.
  - Can create callback-backed files under `/dev` via `devfs_register_file`.
- `src/kernel/procfs.c`:
  - Creates `/proc` and leaves it mutable.
  - Allows creating callback-backed files anywhere under `/proc/...` via `procfs_create_file_at`.

### Large browser files and profile writeback

Atomic profile-file renames dirty the moved node and its old/new directories.
They do not request a rewrite of unchanged files in the mounted filesystem.
Writeback retries retain the failed records and uncommitted backend metadata;
they also avoid escalating a transient allocation failure into a full rewrite.
This prevents repeated 197 MiB libxul serialization while Zen saves its profile.
Large resident file buffers grow by at most 16 MiB of spare capacity per growth
instead of doubling a mounted, exact-size library after a small update.
The new kernel installs the full bundle and runs the desktop-launched Zen
profile without writeback failures, then exits the browser with status 0.
The actual run is recorded in build/ports/zen/zen-launch-6/serial.log.

## Incremental writeback

Mutations queue retained nodes on the mount's writeback list. A flush detaches a
bounded batch and writes only those nodes and their directory ancestors; full
tree traversal is reserved for an explicit full rebuild. Failed and active
writes retain their queue ownership for retry. Unlinked subtrees are excluded
from serialization, and synchronous file flush removes clean live queue entries.
Shared mapping discovery visits only writable-capable mapped nodes, outside
the namespace lock. Node reference counting does not scan mapped contents.
Read access updates in-memory atime; persistence follows a relatime policy
(after metadata/data change, clock rollback, or 24 hours).
