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
    uint32_t permissions;
    uint64_t atime;
    uint64_t mtime;
    uint64_t ctime;
    uint64_t object_id; /* Runtime identity, assigned under the tree lock. */

    size_t refcount;
    size_t size;
    size_t capacity;
    char *data;
    size_t pending_dirty_bytes;
    uint64_t dirty_seq;
    uint64_t last_data_write_tick;
    spinlock_t data_lock;
    struct vfs_mapped_page *mapped_pages;
    struct vfs_mapped_page **mapped_page_index;
    size_t mapped_page_capacity;
    size_t mapped_writers;
    struct vfs_node *mapped_writer_next;
    struct vfs_node *writeback_next;
    struct vfs_node *retired_next;
    bool writeback_queued;
    struct vfs_file_mapping *mappings;
    struct io_pipe *fifo;

    uint32_t disk_id;
    bool disk_meta_dirty;
    bool disk_name_dirty;
    bool disk_data_dirty;

    block_device_t *block_device;
    uint32_t character_kind;
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
    bool shutdown_frozen;
    bool supports_times;
    size_t dirty_bytes;
    size_t mapped_files; /* Shared page caches scanned for CPU stores by flushd. */
    struct vfs_node *mapped_writer_head;
    struct vfs_node *writeback_head;
    struct vfs_node *retired_head; /* Zero-reference nodes; backend gate owns reclamation. */
    size_t dirty_bytes_limit;
    uint64_t dirty_seq;
    spinlock_t dirty_lock;
    vfs_sync_lock_t sync_lock;
    uint64_t sync_owner_pid;
    uint32_t sync_owner_cpu;
    uint64_t sync_owner_ticks;
    struct alixfs_mount *backend;
};

/* Queue ownership is a node reference. Safe with node data_lock held. */
void vfs_queue_dirty_node(vfs_node_t *node);

#endif /* VFS_INTERNAL_H */
