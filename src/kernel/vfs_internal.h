#ifndef VFS_INTERNAL_H
#define VFS_INTERNAL_H

#include "vfs.h"
#include "block.h"
#include "spinlock.h"

struct alixfs_mount;

struct vfs_node
{
    vfs_node_type_t type;
    char *name;
    struct vfs_node *parent;
    struct vfs_node *first_child;
    struct vfs_node *next_sibling;
    struct vfs_mount *mount;
    bool allow_mutation;

    size_t refcount;
    size_t size;
    size_t capacity;
    char *data;
    size_t pending_dirty_bytes;
    spinlock_t data_lock;

    uint32_t disk_id;
    bool disk_meta_dirty;
    bool disk_name_dirty;
    bool disk_data_dirty;

    block_device_t *block_device;
    bool dirty;

    vfs_read_cb_t read_cb;
    vfs_write_cb_t write_cb;
    void *callback_context;
};

struct vfs_mount
{
    block_device_t *device;
    vfs_node_t *mount_point;
    struct vfs_mount *next;
    bool dirty;
    bool needs_full_sync;
    size_t dirty_bytes;
    size_t dirty_bytes_limit;
    spinlock_t dirty_lock;
    spinlock_t sync_lock;
    struct alixfs_mount *backend;
};

#endif /* VFS_INTERNAL_H */
