#ifndef VFS_INTERNAL_H
#define VFS_INTERNAL_H

#include "vfs.h"
#include "block.h"
#include "process.h"
#include "spinlock.h"

struct alixfs_mount;

typedef struct
{
    wait_queue_t waiters;
    bool locked;
} vfs_sync_lock_t;

struct vfs_node
{
    vfs_node_type_t type;
    char *name;
    struct vfs_node *parent;
    struct vfs_node *first_child;
    struct vfs_node *next_sibling;
    struct vfs_mount *mount;
    bool allow_mutation;
    uint32_t uid;
    uint32_t gid;
    uint64_t atime;
    uint64_t mtime;
    uint64_t ctime;

    size_t refcount;
    size_t size;
    size_t capacity;
    char *data;
    size_t pending_dirty_bytes;
    uint64_t dirty_seq;
    uint64_t last_data_write_tick;
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
    bool supports_times;
    size_t dirty_bytes;
    size_t dirty_bytes_limit;
    uint64_t dirty_seq;
    spinlock_t dirty_lock;
    vfs_sync_lock_t sync_lock;
    uint64_t sync_owner_pid;
    uint32_t sync_owner_cpu;
    uint64_t sync_owner_ticks;
    struct alixfs_mount *backend;
};

#endif /* VFS_INTERNAL_H */
