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
- `vfs_mkdir(cwd, path)` — creates intermediate directories as needed.
- `vfs_open_file(cwd, path, create, truncate)` — resolves/creates a file node.

Resolution supports:

- Absolute (`/foo`) and relative paths (from `cwd`)
- `.` and `..`
- Symlinks (bounded by `VFS_MAX_SYMLINK_DEPTH`)
- Mount point traversal

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
