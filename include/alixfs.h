#ifndef ALIXFS_H
#define ALIXFS_H

#include "types.h"
#include "block.h"

struct vfs_node;
struct vfs_mount;

typedef struct alixfs_mount alixfs_mount_t;

alixfs_mount_t *alixfs_mount_create(block_device_t *device);
void alixfs_mount_destroy(alixfs_mount_t *fs);
bool alixfs_mount_load(alixfs_mount_t *fs, struct vfs_mount *mount);
bool alixfs_mount_flush_nodes(alixfs_mount_t *fs,
                              struct vfs_node *root,
                              struct vfs_mount *mount,
                              bool force_all);
bool alixfs_mount_flush_single(alixfs_mount_t *fs,
                               struct vfs_node *node,
                               struct vfs_mount *mount);
bool alixfs_mount_commit(alixfs_mount_t *fs);
void alixfs_mount_release_node(alixfs_mount_t *fs, struct vfs_node *node);
bool alixfs_mount_format(block_device_t *device);
void alixfs_mount_snapshot(const alixfs_mount_t *fs, bool *header_dirty);

#endif /* ALIXFS_H */
