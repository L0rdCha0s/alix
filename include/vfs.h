#ifndef VFS_H
#define VFS_H

#include "types.h"

typedef struct vfs_node vfs_node_t;

void vfs_init(void);
vfs_node_t *vfs_root(void);
vfs_node_t *vfs_resolve(vfs_node_t *cwd, const char *path);
vfs_node_t *vfs_mkdir(vfs_node_t *cwd, const char *path);
vfs_node_t *vfs_open_file(vfs_node_t *cwd, const char *path, bool create, bool truncate);
bool vfs_is_dir(const vfs_node_t *node);
bool vfs_truncate(vfs_node_t *file);
bool vfs_append(vfs_node_t *file, const char *data, size_t len);
const char *vfs_data(const vfs_node_t *file, size_t *size);
const char *vfs_name(const vfs_node_t *node);
vfs_node_t *vfs_first_child(vfs_node_t *dir);
vfs_node_t *vfs_next_sibling(vfs_node_t *node);

#endif
