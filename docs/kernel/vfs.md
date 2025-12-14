# VFS / Filesystems / Mounts

The kernel’s VFS is a heap-backed tree of nodes with optional backing storage for mounts.

## Core Data Structures (`src/kernel/vfs_internal.h`)

`vfs_node_t` represents a directory, file, block device, or symlink:

- Tree links: `parent`, `first_child`, `next_sibling`
- Identity: `name`, `type`
- Data:
  - For regular files: `data` buffer + `size/capacity` (heap-backed)
  - For callback-backed nodes: `read_cb`/`write_cb` + `callback_context` (procfs/devfs style)
- Lifetime: `refcount` (tree refs + FD refs)
- Concurrency: per-node `data_lock` for file data mutations

`vfs_mount_t` ties a block device to a subtree and tracks dirty/writeback state.

## Locking Model (`src/kernel/vfs.c`)

- `g_vfs_tree_lock`: protects tree shape (parent/child links, node creation/removal, mount list).
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

Dirty tracking is per-node and per-mount; `vfs_sync_dirty()` writes back dirty nodes and may apply backpressure when dirty bytes exceed thresholds.

## devfs and procfs

- `src/kernel/devfs.c`:
  - Ensures `/dev` exists.
  - Populates block devices as VFS nodes of type `VFS_NODE_BLOCK`.
  - Can create callback-backed files under `/dev` via `devfs_register_file`.
- `src/kernel/procfs.c`:
  - Creates `/proc` and leaves it mutable.
  - Allows creating callback-backed files anywhere under `/proc/...` via `procfs_create_file_at`.

