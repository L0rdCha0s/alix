#ifndef VFS_H
#define VFS_H

#include "types.h"

#include "block.h"

typedef struct vfs_node vfs_node_t;
typedef struct vfs_mount vfs_mount_t;

typedef struct
{
    vfs_node_t *mount_point;
    block_device_t *device;
    bool dirty;
    bool needs_full_sync;
} vfs_mount_info_t;

typedef enum
{
    VFS_NODE_DIR = 0,
    VFS_NODE_FILE = 1,
    VFS_NODE_BLOCK = 2,
    VFS_NODE_SYMLINK = 3
} vfs_node_type_t;

/* Maximum path/target storage including NUL. Existing oversized disk targets
 * are preserved; snapshot/resolve rejects them instead of truncating success. */
#define VFS_PATH_MAX 4096u
#define VFS_UID_ROOT 0u
#define VFS_GID_ROOT 0u

/* Immutable, heap-owned directory contents. Records are 8-byte aligned and
 * followed by name_length bytes plus NUL; no node pointer enters this buffer.
 * Caller supplies an empty snapshot and releases it on a protected worker. */
typedef struct
{
    uint64_t inode;
    uint32_t type, name_length;
    unsigned char name[];
} vfs_directory_record_t;
typedef struct
{
    unsigned char *data;
    size_t bytes, count;
} vfs_directory_snapshot_t;
int vfs_directory_snapshot(vfs_node_t *directory, vfs_directory_snapshot_t *out);
void vfs_directory_snapshot_release(vfs_directory_snapshot_t *snapshot);

typedef ssize_t (*vfs_read_cb_t)(vfs_node_t *node, size_t offset, void *buffer, size_t count, void *context);
typedef ssize_t (*vfs_write_cb_t)(vfs_node_t *node, size_t offset, const void *buffer, size_t count, void *context);

void vfs_init(void);
void vfs_sys_controls_init(void);
vfs_node_t *vfs_root(void);
vfs_node_t *vfs_resolve(vfs_node_t *cwd, const char *path);
vfs_node_t *vfs_mkdir(vfs_node_t *cwd, const char *path);
vfs_node_t *vfs_open_file(vfs_node_t *cwd, const char *path, bool create, bool truncate);
/* Protected storage-worker APIs. cwd is explicitly retained by the caller;
 * success returns one owned node reference acquired before tree unlock. New
 * files use captured uid/gid. Existing subtree mutability rules still apply;
 * this does not invent POSIX mode/ACL enforcement absent from the VFS.
 * Callback-backed nodes return -ENOTSUP before truncate; their borrowed
 * callback contexts/current-thread semantics need a separate adapter. */
int vfs_open_data_owned(vfs_node_t *cwd, const char *path, bool create, bool truncate,
                        uint32_t uid, uint32_t gid, vfs_node_t **out);
/* Resolve intermediate links, snapshot the final symlink without following it,
 * and copy at most capacity raw bytes (no appended NUL). No target pointer
 * escapes tree/data locks. Path and output may overlap after resolution.
 * cwd is retained, credentials captured, caller is a protected storage worker. */
ssize_t vfs_readlink_snapshot(vfs_node_t *cwd, const char *path, void *buffer,
                              size_t capacity, uint32_t uid, uint32_t gid);
/* Recheck callback exclusion under data_lock on every operation, so a later
 * vfs_set_file_callbacks cannot execute a callback with service identity. */
ssize_t vfs_read_data_at(vfs_node_t *file, size_t offset, void *buffer, size_t count);
ssize_t vfs_write_data_at(vfs_node_t *file, size_t offset, const void *data, size_t count);
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
bool vfs_reserve(vfs_node_t *file, size_t size_hint);
ssize_t vfs_read_at(vfs_node_t *file, size_t offset, void *buffer, size_t count);
ssize_t vfs_write_at(vfs_node_t *file, size_t offset, const void *data, size_t count);
bool vfs_set_file_callbacks(vfs_node_t *file,
                            vfs_read_cb_t read_cb,
                            vfs_write_cb_t write_cb,
                            void *context);
char *vfs_data(vfs_node_t *file, size_t *size);
bool vfs_stat(const vfs_node_t *node,
              size_t *size_out,
              vfs_node_type_t *type_out,
              uint64_t *atime_out,
              uint64_t *mtime_out,
              uint64_t *ctime_out);
const char *vfs_name(const vfs_node_t *node);
vfs_node_t *vfs_parent(const vfs_node_t *node);
size_t vfs_build_path(const vfs_node_t *node, char *buffer, size_t capacity);
bool vfs_remove_file(vfs_node_t *cwd, const char *path);
bool vfs_remove_tree(vfs_node_t *cwd, const char *path);
vfs_node_t *vfs_first_child(vfs_node_t *dir);
vfs_node_t *vfs_next_sibling(vfs_node_t *node);
void vfs_node_get_owner(const vfs_node_t *node, uint32_t *uid_out, uint32_t *gid_out);
void vfs_node_set_owner(vfs_node_t *node, uint32_t uid, uint32_t gid);
typedef bool (*vfs_enum_cb_t)(const vfs_node_t *child, void *context);
size_t vfs_enum_children(vfs_node_t *dir, vfs_enum_cb_t callback, void *context);
vfs_node_t *vfs_add_block_device(vfs_node_t *dir, const char *name, block_device_t *device);
void vfs_clear_directory(vfs_node_t *dir);
bool vfs_format(block_device_t *device);
bool vfs_mount_device(block_device_t *device, vfs_node_t *mount_point);
bool vfs_is_mount_point(const vfs_node_t *node);
bool vfs_sync_all(void);
bool vfs_sync_dirty(void);
bool vfs_flush_node(vfs_node_t *node);
/* Snapshot current mounts; returns total count, fills up to max entries. */
size_t vfs_snapshot_mounts(vfs_mount_info_t *out, size_t max);
/* Replace link_path with a symlink to target_path, removing an existing node if needed (but never a mount). */
bool vfs_force_symlink(vfs_node_t *cwd, const char *target_path, const char *link_path);
/* Allow or disallow mutations within a subtree (used to lock slash while leaving /proc mutable). */
void vfs_set_subtree_mutable(vfs_node_t *node, bool allow);
/* Acquire/release references; nodes live until the last ref (tree + FDs) is released. */
void vfs_node_retain(vfs_node_t *node);
/* Input must already have an owning reference or tree/owner lock protection. */
bool vfs_node_try_retain(vfs_node_t *node);
/* Protected worker only. Follows the final link; retains before tree unlock. */
int vfs_resolve_owned(vfs_node_t *cwd, const char *path, vfs_node_t **out);
void vfs_node_release(vfs_node_t *node);
/* Protected worker, without caller locks/preemption guard. Serializes final
 * orphan-directory subtree teardown with tree readers, and consumes one owner.
 * Internal tree-held releases continue using vfs_node_release directly. */
void vfs_node_release_owned(vfs_node_t *node);

#endif
