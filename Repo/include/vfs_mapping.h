#ifndef VFS_MAPPING_H
#define VFS_MAPPING_H
#include "vfs.h"
#include "fd_table.h"
typedef struct vfs_file_mapping vfs_file_mapping_t;
bool vfs_mapping_write_allowed(const vfs_node_t *node);
/* Protected storage workers only. Each successful object owns a node reference
 * and all page metadata. owner stays alive until release unlinks the registry. */
int vfs_mapping_create(vfs_node_t *node, uint64_t offset, size_t length,
                       bool shared, fd_description_t *owner, vfs_file_mapping_t **out);
void vfs_mapping_release(vfs_file_mapping_t *mapping);
paddr_t vfs_mapping_page(const vfs_file_mapping_t *mapping, size_t index);
int vfs_mapping_sync(vfs_file_mapping_t *mapping);
/* Node data lock held. CPU stores and VFS I/O use the same shared pages. */
void vfs_mapping_pull_locked(vfs_node_t *node);
void vfs_mapping_push_locked(vfs_node_t *node, size_t offset, size_t count);
bool vfs_mapping_busy_locked(vfs_node_t *node);
void vfs_mapping_destroy_locked(vfs_node_t *node);
#endif
