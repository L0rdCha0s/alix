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
- No ACLs, set-ID execution or sticky-directory policy.
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
- `version`: currently `4` (version `2` is accepted for legacy mounts without ownership metadata; version `3` omits timestamps)
- `node_capacity`: number of chunk table entries (default `65536` at format time; smaller legacy tables grow to this capacity on mount when space and memory permit)
- `node_count`: count of allocated node IDs (best-effort bookkeeping)
- `root_id`: chunk table ID for the mount root
- `free_chunk_count` + `free_chunks[]`: free list of released payload spans
- `data_region_offset` + `data_region_size`: data-region bookkeeping

Notes:

- The table remains fixed during a mounted session. Mounting an older volume
  expands a smaller table to `65536` entries without reformatting or changing
  existing node IDs, record versions, names or file contents. Relocation uses
  a heap-owned 64 KiB buffer. Payloads overlapping the enlarged table move to
  reserved tail space; their original-table pointers are flushed before the
  extension is written, and the new capacity is published last. A volume
  without enough tail space or scratch memory keeps its original capacity.
- The free list is capped (`ALIXFS2_MAX_FREE_CHUNKS`); if it fills up, additional frees may be dropped (space leak until reformat).

## Chunk Table (`alixfs2_chunk_entry_t`)

The chunk table is an array of `node_capacity` entries. Each entry acts like a tiny “inode pointer”:

- `offset` (u64): byte offset of the node’s payload chunk in the data region
- `length` (u32): number of valid bytes stored for this node
- `capacity` (u32): allocated chunk size (sector-aligned)

Conventions:

- `capacity == 0` means the node ID is unused/free.
- `length` can be smaller than `capacity` because chunks are sector-aligned.

AlixFS2 keeps the chunk table in memory while mounted. During writeback it writes
each sector containing changed chunk entries once, tracked by a dirty bitmap
(`chunk_dirty_bitmap`). This uses the resident sector contents, avoiding a disk
read and write for every individual 16-byte entry.

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
   - `atime`: access time in UTC seconds (version `4+`)
   - `mtime`: modification time in UTC seconds (version `4+`)
   - `ctime`: status change time in UTC seconds (version `4+`)
2. `name[name_len]`
3. `data[data_len]` (only meaningful for file/symlink)
4. Optional 16-byte mode extension: 64-bit `ALIXMODE` tag, uint32 version `1`
   and uint32 permission bits (`0777`). It follows the data, so existing header,
   name and file-data offsets are unchanged. Records without the extension use
   the previous defaults: files `0666`, directories/symlinks `0777`, blocks `0600`.

The versioned extension works with filesystem versions 2, 3 and 4. New writes
include it; existing records are read without rewriting them. Unknown or invalid
extensions fail loading rather than silently granting default permissions.
Older kernels can read the unchanged file payload but ignore the extension and
may discard modes when rewriting a record.

Directory membership is implicit via `parent_id`; directories do not store their own child lists on disk.

## Mount Load Path

Mounting is initiated by VFS:

- `vfs_mount_device` (`src/kernel/vfs.c`) creates a `vfs_mount_t` and an AlixFS backend (`alixfs_mount_create`), then calls `alixfs_mount_load`.

`alixfs_mount_load` does:

1. Read and validate the on-disk header.
2. Read the chunk table into `fs->chunks`.
3. For each chunk entry with `capacity != 0`:
   - Read the record header, name and optional mode extension
   - Parse the payload header and create/initialise a `vfs_node_t`
   - Read file and symlink contents into their final owned buffers in bounded chunks
   - Retain `parent_id` in mount-only heap metadata
4. Link nodes into the VFS tree using the retained parent IDs, without more disk reads.

Mount reads share a 64 KiB, sector-aligned read-ahead window for adjacent
metadata and payload chunks. Large files no longer require a second file-sized
temporary allocation. Symlink targets use the same buffer-loading path as files.
The window is clipped to the device boundary;
failed speculative reads fall back to the requested record. All scratch memory
is heap-owned and released before mount returns. This avoids thousands of tiny
AHCI requests and the former second read of every complete file payload.

The VFS tree lock still protects mount publication, so `/proc` process
registration and `/dev` USB registration wait for this load. That contention
made a slow root mount appear to hang audio and USB initialization together.
Boot logs now report the fstab mount start, result and elapsed milliseconds.

The mount point directory in VFS (`mount->mount_point`) is treated as the on-disk root node (`root_id`).

Its name and parent belong to the containing VFS tree. Loading the root never
replaces the destination mount-point name with a saved name. New root records
have an empty name and the no-parent sentinel; serialization never writes a
parent ID from another mounted filesystem. Older records containing their
former mount name remain readable without renaming the destination directory.
The serialized-length calculation uses the same root-name policy as the
payload writer, including metadata-only updates.

`statvfs` and the owned-descriptor `fstatvfs` report AlixFS data-block capacity,
free blocks (unused tail plus tracked free chunks), fixed inode capacity and
currently unused inode slots. VFS serializes the snapshot with mount writeback
and supplies the same filesystem identity used by `stat`. There are no reserved
user blocks or inode slots. Memory-only VFS trees currently return `ENOTSUP`.

`tests/alixfs_mount_root_contract_test.py` executes the complete backend with a
memory block device, old named roots, file payload readback, foreign parent IDs
and write-failure retry. `make zen-gecko-os-interfaces-qemu-test` additionally
persists a file at one mount path and reads it at `/root` in an independent
eight-CPU boot using a private disk snapshot. The original failed-test image
also passes native readback after the root-identity fix.

The same two-boot fixture now checks ftruncate shrink/grow: the resized file
retains its first three bytes and the following 8189 bytes remain zero after
fsync and remount. The new snapshot is `fsync-resized-committed.img`; earlier
`fsync-committed.img` and legacy-name fixture images are retained. Use the
fixture's `read-legacy` mode when replaying the older image without resize.bin.
Mounted resize requests conservatively reserve metadata/name/sector headroom
below the 32-bit chunk-length limit. This is not sparse-file support: the
in-memory VFS allocates and zero-fills the extended data.

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

Legacy 4096-entry tables can exhaust node IDs while gigabytes of data space
remain free. The mount-time expansion handles those volumes. If writeback
still fails (for example, a full device or failed IO), VFS backpressure returns
an error to a blocked writer rather than retrying indefinitely at its 64 MiB
dirty-data limit. Existing dirty records remain available for a sync retry.

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

Content changes still rewrite the whole file payload (no streaming or partial
data updates). Metadata-only updates such as access time or ownership write
only the node header/name prefix and mode trailer, preserving the existing data
and chunk-table entry. An 8 MiB file therefore needs two 512-byte metadata writes
when its access time changes, rather than rewriting its unchanged contents.
Partial metadata-write failures retain dirty state for retry. A record without
the trailer is rewritten once in full when first changed, retaining its payload.

On growth, the old extent remains allocated until the replacement payload is
successfully written. An allocation or write failure retains the old chunk
entry and leaves the node dirty for retry.

## Features and Limitations Summary

Supported:

- Directories, regular files, symlinks
- Mounting a filesystem at an empty VFS directory
- Formatting via shell `mkfs` (calls `vfs_format` → `alixfs_mount_format`)
- Incremental writeback with mount dirty tracking and backpressure integration

Current limitations (important for expectations):

- Fixed maximum node count per filesystem (`node_capacity`)
- No extended attributes or ACLs
- No integrity features (checksums, journal, fsck)
- Not hardened against media corruption (assumes trusted storage and relatively clean shutdown)

## Useful Entry Points / Commands

- Format a device: shell `mkfs /dev/<disk>`
- Mount a device: shell `mount /dev/<disk> /mnt`
- List mounts and dirty state: shell `mount` (no args) uses `vfs_snapshot_mounts`
