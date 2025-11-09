#ifndef VFS_H
#define VFS_H

#include "types.h"

#include "block.h"

typedef struct vfs_node vfs_node_t;
typedef struct vfs_mount vfs_mount_t;

typedef enum
{
    VFS_NODE_DIR = 0,
    VFS_NODE_FILE = 1,
    VFS_NODE_BLOCK = 2,
    VFS_NODE_SYMLINK = 3
} vfs_node_type_t;

typedef ssize_t (*vfs_read_cb_t)(vfs_node_t *node, size_t offset, void *buffer, size_t count, void *context);
typedef ssize_t (*vfs_write_cb_t)(vfs_node_t *node, size_t offset, const void *buffer, size_t count, void *context);

void vfs_init(void);
vfs_node_t *vfs_root(void);
vfs_node_t *vfs_resolve(vfs_node_t *cwd, const char *path);
vfs_node_t *vfs_mkdir(vfs_node_t *cwd, const char *path);
vfs_node_t *vfs_open_file(vfs_node_t *cwd, const char *path, bool create, bool truncate);
vfs_node_t *vfs_symlink(vfs_node_t *cwd, const char *target_path, const char *link_path);
bool vfs_is_dir(const vfs_node_t *node);
bool vfs_is_file(const vfs_node_t *node);
bool vfs_is_block(const vfs_node_t *node);
bool vfs_is_symlink(const vfs_node_t *node);
block_device_t *vfs_block_device(const vfs_node_t *node);
vfs_node_type_t vfs_node_type(const vfs_node_t *node);
const char *vfs_symlink_target(const vfs_node_t *node);
bool vfs_truncate(vfs_node_t *file);
bool vfs_append(vfs_node_t *file, const char *data, size_t len);
ssize_t vfs_read_at(vfs_node_t *file, size_t offset, void *buffer, size_t count);
ssize_t vfs_write_at(vfs_node_t *file, size_t offset, const void *data, size_t count);
bool vfs_set_file_callbacks(vfs_node_t *file,
                            vfs_read_cb_t read_cb,
                            vfs_write_cb_t write_cb,
                            void *context);
const char *vfs_data(const vfs_node_t *file, size_t *size);
const char *vfs_name(const vfs_node_t *node);
bool vfs_remove_file(vfs_node_t *cwd, const char *path);
vfs_node_t *vfs_first_child(vfs_node_t *dir);
vfs_node_t *vfs_next_sibling(vfs_node_t *node);
vfs_node_t *vfs_add_block_device(vfs_node_t *dir, const char *name, block_device_t *device);
void vfs_clear_directory(vfs_node_t *dir);
bool vfs_format(block_device_t *device);
bool vfs_mount_device(block_device_t *device, vfs_node_t *mount_point);
bool vfs_is_mount_point(const vfs_node_t *node);
bool vfs_sync_all(void);
bool vfs_flush_node(vfs_node_t *node);

#endif
