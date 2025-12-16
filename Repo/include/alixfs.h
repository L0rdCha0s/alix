#ifndef ALIXFS_H
#define ALIXFS_H

#include "types.h"
#include "block.h"

struct vfs_node;
struct vfs_mount;

typedef struct alixfs_mount alixfs_mount_t;

/*
 * AlixFS2 filesystem backend API.
 *
 * This backend persists a mounted VFS subtree to a block device using:
 * - a fixed-size header,
 * - a fixed-capacity chunk table (node ID → {offset,length,capacity}), and
 * - per-node payload records (type, parent_id, name, data).
 *
 * The VFS mount layer (`src/kernel/vfs.c`) owns writeback policy; AlixFS2
 * supplies the persistence operations used by `vfs_mount_device`/`vfs_sync_*`.
 *
 * See docs/kernel/alixfs.md for the on-disk format and design notes.
 */

/* Create/destroy in-memory mount backend state for `device`. */
alixfs_mount_t *alixfs_mount_create(block_device_t *device);
void alixfs_mount_destroy(alixfs_mount_t *fs);

/* Load filesystem metadata from disk and populate `mount->mount_point` subtree. */
bool alixfs_mount_load(alixfs_mount_t *fs, struct vfs_mount *mount);

/* Flush dirty nodes in a subtree (invoked by VFS writeback). */
bool alixfs_mount_flush_nodes(alixfs_mount_t *fs,
                              struct vfs_node *root,
                              struct vfs_mount *mount,
                              bool force_all);

/* Flush a single node to disk (invoked by targeted VFS flush). */
bool alixfs_mount_flush_single(alixfs_mount_t *fs,
                               struct vfs_node *node,
                               struct vfs_mount *mount,
                               bool force_all);

/* Persist metadata updates (chunk table + header). */
bool alixfs_mount_commit(alixfs_mount_t *fs);

/* Release persistent storage associated with a node ID when a mounted node is deleted. */
void alixfs_mount_release_node(alixfs_mount_t *fs, struct vfs_node *node);

/* Format a block device with a fresh AlixFS2 filesystem. */
bool alixfs_mount_format(block_device_t *device);

/* Snapshot lightweight backend state for mount status reporting. */
void alixfs_mount_snapshot(const alixfs_mount_t *fs, bool *header_dirty);

#endif /* ALIXFS_H */
