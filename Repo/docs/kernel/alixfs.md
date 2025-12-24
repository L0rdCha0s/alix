# AlixFS2 (On-Disk Filesystem Backend)

AlixFS2 is the block-device filesystem backend used by the VFS mount layer. It persists a mounted VFS subtree onto a block device via a simple, fixed-capacity “chunk table” plus per-node records.

Implementation: `src/kernel/alixfs.c`  
VFS integration: `src/kernel/vfs.c` (mount + writeback orchestration)  
Public API: `include/alixfs.h`

## Goals and Scope

AlixFS2 is intentionally small and pragmatic:

- Persist directories, regular files, and symlinks for the kernel VFS.
- Keep allocation logic simple (single extent per node; first-fit free list).
- Support incremental writeback (only rewrite nodes that are dirty).
- Avoid stack/DMA pitfalls by keeping all persistent metadata heap-backed and guarded by VFS locking.

Non-goals (current):

- No journaling.
- No permissions or ACLs.
- No timestamps.
- No hardlinks.
- No checksums or corruption hardening.
- No multi-extent / sparse files.

## On-Disk Layout

Offsets are byte offsets from the start of the block device (not LBAs). The driver-facing layer (`block_read/write`) still operates in sectors; `alixfs_device_io` handles read-modify-write when writes are not sector-aligned.

Layout:

1. **Header span** (sector-aligned) at offset `0`
2. **Chunk table** at offset `header_span` (sector-aligned array of fixed-size entries)
3. **Data region** at offset `data_region_offset` (node payload storage)

The header records:

- `data_region_offset`: where payload chunks begin
- `data_region_size`: current high-water mark within the data region
- `free_chunks[]`: a small free-list for released chunks

## Header (`alixfs2_header_t`)

Defined in `src/kernel/alixfs.c` as a packed struct.

Key fields:

- `magic[8]`: `"ALIXFS2"`
- `version`: currently `3` (version `2` is accepted for legacy mounts without ownership metadata)
- `node_capacity`: fixed number of chunk table entries (default `4096` at format time)
- `node_count`: count of allocated node IDs (best-effort bookkeeping)
- `root_id`: chunk table ID for the mount root
- `free_chunk_count` + `free_chunks[]`: free list of released payload spans
- `data_region_offset` + `data_region_size`: data-region bookkeeping

Notes:

- `node_capacity` is fixed; AlixFS2 does not currently grow the chunk table.
- The free list is capped (`ALIXFS2_MAX_FREE_CHUNKS`); if it fills up, additional frees may be dropped (space leak until reformat).

## Chunk Table (`alixfs2_chunk_entry_t`)

The chunk table is an array of `node_capacity` entries. Each entry acts like a tiny “inode pointer”:

- `offset` (u64): byte offset of the node’s payload chunk in the data region
- `length` (u32): number of valid bytes stored for this node
- `capacity` (u32): allocated chunk size (sector-aligned)

Conventions:

- `capacity == 0` means the node ID is unused/free.
- `length` can be smaller than `capacity` because chunks are sector-aligned.

AlixFS2 keeps the chunk table in memory while mounted. During writeback it writes only the chunk entries that changed, tracked by a dirty bitmap (`chunk_dirty_bitmap`).

## Node Payload Format (`alixfs_node_disk_t` + data)

Each allocated node ID points to a payload chunk containing:

1. `alixfs_node_disk_t` header (packed):
   - `id`: node ID (must match the chunk table index)
   - `parent_id`: node ID of parent directory (or `0xFFFFFFFF` for root)
   - `type`: VFS node type (`VFS_NODE_DIR`, `VFS_NODE_FILE`, `VFS_NODE_SYMLINK`, …)
   - `name_len`: bytes of the name (no implicit NUL)
   - `data_len`: bytes of file data / symlink target
   - `uid`: owner user ID (version `3+`)
   - `gid`: owner group ID (version `3+`)
2. `name[name_len]`
3. `data[data_len]` (only meaningful for file/symlink)

Directory membership is implicit via `parent_id`; directories do not store their own child lists on disk.

## Mount Load Path

Mounting is initiated by VFS:

- `vfs_mount_device` (`src/kernel/vfs.c`) creates a `vfs_mount_t` and an AlixFS backend (`alixfs_mount_create`), then calls `alixfs_mount_load`.

`alixfs_mount_load` does:

1. Read and validate the on-disk header.
2. Read the chunk table into `fs->chunks`.
3. For each chunk entry with `capacity != 0`:
   - Read `entry->length` bytes from `entry->offset`
   - Parse the payload header and create/initialise a `vfs_node_t`
4. Second pass: re-read each node header to link nodes into the VFS tree using `parent_id`.

The mount point directory in VFS (`mount->mount_point`) is treated as the on-disk root node (`root_id`).

## Writeback and Dirty Tracking

Writeback orchestration lives in VFS (`src/kernel/vfs.c`). AlixFS2 supplies the persistence operations.

Key concepts:

- VFS tracks per-node dirty bits (`disk_meta_dirty`, `disk_name_dirty`, `disk_data_dirty`) and a `dirty_seq`.
- VFS tracks per-mount dirty bytes for backpressure.

Flush flow (typical):

1. VFS decides which mounts/nodes need syncing (`vfs_sync_dirty` / `vfs_sync_all`).
2. VFS calls `alixfs_mount_flush_nodes(..., force_all)` (subtree) or `alixfs_mount_flush_single(...)` (one node).
3. AlixFS writes dirty node payloads to their chunks (`alixfs_write_node`), updating in-memory chunk entries and marking those entries dirty in `chunk_dirty_bitmap`.
4. VFS calls `alixfs_mount_commit` to persist:
   - dirty chunk table entries (`alixfs_flush_chunk_table`)
   - the header if dirty (`alixfs_flush_header`)

Design note: payload writes happen before the chunk table entry is persisted, which tends to avoid pointing on-disk metadata at unwritten payload data. This is not a journal, but it is an intentional “data first, metadata later” ordering.

## Allocation and Free Space

### Node IDs

Node IDs are indices into the chunk table. A node ID is considered free when `chunks[id].capacity == 0`.

`alixfs_assign_node_id` uses a simple “next hint then wraparound” scan to find a free entry.

### Payload chunk allocation

Node payload storage is managed by:

- `alixfs_chunk_allocate`: first-fit search of the on-disk free list; if no chunk fits, extend `data_region_size` to allocate from the end of the data region.
- `alixfs_chunk_release`: returns chunks to the free list and coalesces adjacent chunks when possible.

All chunk capacities are sector-aligned.

### File growth/shrink behavior

Files and symlinks store their contents inline in the node payload chunk. When contents grow beyond `entry->capacity`, AlixFS:

1. allocates a new chunk,
2. writes the new payload there,
3. updates the chunk entry,
4. releases the old chunk (header free list), and
5. commits metadata at sync time.

This means large file edits rewrite the whole file payload (no streaming or partial block updates).

## Features and Limitations Summary

Supported:

- Directories, regular files, symlinks
- Mounting a filesystem at an empty VFS directory
- Formatting via shell `mkfs` (calls `vfs_format` → `alixfs_mount_format`)
- Incremental writeback with mount dirty tracking and backpressure integration

Current limitations (important for expectations):

- Fixed maximum node count per filesystem (`node_capacity`)
- No metadata beyond name/type/parent + uid/gid + file bytes
- No integrity features (checksums, journal, fsck)
- Not hardened against media corruption (assumes trusted storage and relatively clean shutdown)

## Useful Entry Points / Commands

- Format a device: shell `mkfs /dev/<disk>`
- Mount a device: shell `mount /dev/<disk> /mnt`
- List mounts and dirty state: shell `mount` (no args) uses `vfs_snapshot_mounts`
