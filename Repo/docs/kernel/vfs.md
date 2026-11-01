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

Regular-file worker adapters retain nodes before releasing the tree lock and
serialize shared offsets with a sleeping gate. They reject callback-backed
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

Forced sync commits dirty nodes and flushes the device cache; it does not
rewrite clean files. A full rewrite is reserved for recovery after a writeback
failure. `vfs_flush_node()` immediately persists the file and its directory
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

## devfs and procfs

- `src/kernel/devfs.c`:
  - Ensures `/dev` exists.
  - Populates block devices as VFS nodes of type `VFS_NODE_BLOCK`.
  - Can create callback-backed files under `/dev` via `devfs_register_file`.
- `src/kernel/procfs.c`:
  - Creates `/proc` and leaves it mutable.
  - Allows creating callback-backed files anywhere under `/proc/...` via `procfs_create_file_at`.
