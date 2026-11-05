#ifndef VFS_H
#define VFS_H

#include "types.h"

#include "block.h"

typedef struct vfs_node vfs_node_t;
typedef struct vfs_mount vfs_mount_t;
typedef struct vfs_filesystem_info
{
    uint64_t block_size, fragment_size, blocks, free_blocks, available_blocks;
    uint64_t files, free_files, available_files, filesystem_id, flags, name_max;
} vfs_filesystem_info_t;
int vfs_node_filesystem_info(vfs_node_t *node, vfs_filesystem_info_t *output);
int vfs_path_filesystem_info(vfs_node_t *cwd, const char *path, vfs_filesystem_info_t *output);

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
    VFS_NODE_SYMLINK = 3,
    VFS_NODE_CHARACTER = 5,
    VFS_NODE_FIFO = 6
} vfs_node_type_t;

typedef struct
{
    uint64_t size_bytes;
    vfs_node_type_t type;
    uint64_t atime, mtime, ctime;
} vfs_stat_snapshot_t;

typedef struct
{
    vfs_stat_snapshot_t metadata;
    uint64_t device, inode, links;
    uint32_t uid, gid, permissions;
} vfs_stat_info_t;
/* Protected worker, caller retains node/cwd. Identity is shared with readdir,
 * stable across rename and independent opens, and never exposes a pointer.
 * An unlinked but retained node has zero links. No hard links are supported. */
int vfs_node_stat_info(vfs_node_t *node, vfs_stat_info_t *output);
int vfs_path_stat_info(vfs_node_t *cwd, const char *path, bool follow_final,
                        uint32_t uid, uint32_t gid, vfs_stat_info_t *output);

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
/* Caller retains file. Allocate one coherent NUL-terminated raw-data copy
 * under its data lock; callbacks are excluded. Output belongs to the caller. */
int vfs_file_snapshot_owned(vfs_node_t *file, size_t maximum, unsigned char **data, size_t *size);
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
 * files use captured uid/gid. The mode-aware entry point applies basic
 * permissions before tree unlock. Existing subtree mutability rules apply;
 * full path-search/ACL enforcement remains separate.
 * Callback-backed nodes return -ENOTSUP before truncate; their borrowed
 * callback contexts/current-thread semantics need a separate adapter. */
int vfs_open_data_owned(vfs_node_t *cwd, const char *path, bool create, bool truncate,
                        uint32_t uid, uint32_t gid, vfs_node_t **out);
int vfs_open_data_flags_owned(vfs_node_t *cwd, const char *path, bool create, bool truncate,
                              bool exclusive, uint32_t uid, uint32_t gid, vfs_node_t **out);
int vfs_open_data_access_owned(vfs_node_t *cwd, const char *path, bool create, bool truncate,
                               bool exclusive, uint32_t uid, uint32_t gid, uint32_t access, vfs_node_t **out);
int vfs_open_data_mode_owned(vfs_node_t *cwd, const char *path, bool create, bool truncate,
                             bool exclusive, uint32_t uid, uint32_t gid, uint32_t access,
                             uint32_t mode, vfs_node_t **out);
int vfs_open_data_nofollow_owned(vfs_node_t *cwd, const char *path, bool create, bool truncate,
                                 bool exclusive, uint32_t uid, uint32_t gid, uint32_t access,
                                 uint32_t mode, bool nofollow, vfs_node_t **out);
int vfs_symlink_create(vfs_node_t *cwd, const char *target, const char *path, uint32_t uid, uint32_t gid);
int vfs_mkfifo_exclusive(vfs_node_t *cwd, const char *path, uint32_t uid, uint32_t gid, uint32_t mode);
struct io_pipe;
/* Caller owns the FIFO node; its lifetime protects the returned stream. */
struct io_pipe *vfs_fifo_state(vfs_node_t *node);
int vfs_access_path(vfs_node_t *cwd, const char *path, bool follow, uint32_t mode, uint32_t uid, uint32_t gid);
/* Volatile named memory objects. The namespace and open handles own separate
 * references; no filesystem path exposes or persists these nodes. */
int vfs_shm_open_owned(const char *name, bool create, bool truncate, bool exclusive,
                       uint32_t uid, uint32_t gid, uint32_t mode, uint32_t access,
                       vfs_node_t **out);
int vfs_shm_unlink_owned(const char *name, uint32_t uid);
int vfs_open_legacy_handle(vfs_node_t *cwd, const char *path, bool create, bool truncate,
                            bool exclusive, vfs_node_t **out);
int vfs_remove_path(vfs_node_t *cwd, const char *path, bool allow_directory);
int vfs_remove_directory_path(vfs_node_t *cwd, const char *path);
int vfs_mkdir_exclusive(vfs_node_t *cwd, const char *path, uint32_t uid, uint32_t gid);
int vfs_mkdir_mode_exclusive(vfs_node_t *cwd, const char *path, uint32_t uid, uint32_t gid, uint32_t mode);
/* Resize an owned regular node under its data lock; no callback execution. */
int vfs_resize_data(vfs_node_t *file, uint64_t length);
ssize_t vfs_realpath_snapshot(vfs_node_t *cwd, const char *path, char *buffer, size_t capacity);
int vfs_rename_path(vfs_node_t *cwd, const char *old_path, const char *new_path);
/* Resolve intermediate links, snapshot the final symlink without following it,
 * and copy at most capacity raw bytes (no appended NUL). No target pointer
 * escapes tree/data locks. Path and output may overlap after resolution.
 * cwd is retained, credentials captured, caller is a protected storage worker. */
ssize_t vfs_readlink_snapshot(vfs_node_t *cwd, const char *path, void *buffer,
                              size_t capacity, uint32_t uid, uint32_t gid);
/* Recheck callback exclusion under data_lock on every operation, so a later
 * vfs_set_file_callbacks cannot execute a callback with service identity. */
ssize_t vfs_read_data_at(vfs_node_t *file, size_t offset, void *buffer, size_t count);
/* Bounded resident-file steps. Caller retains the node and holds a preparation
 * guard. A false return changes no data, offset, metadata or output: use the
 * protected worker instead. No callback, allocation, persistence or wait. */
bool vfs_try_read_data_at(vfs_node_t *file, size_t offset, void *buffer, size_t count,
                          ssize_t *result);
bool vfs_try_stat_data(vfs_node_t *file, vfs_stat_snapshot_t *output);
bool vfs_try_node_stat_info(vfs_node_t *file, vfs_stat_info_t *output);
ssize_t vfs_write_data_at(vfs_node_t *file, size_t offset, const void *data, size_t count);
/* Select EOF and commit the complete write under the same node data lock.
 * position is caller-owned synchronous state, never retained by the VFS. */
ssize_t vfs_write_append(vfs_node_t *file, const void *data, size_t count,
                         bool callbacks, size_t *position);
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
int vfs_chown_owned(vfs_node_t *node, uint32_t caller_uid, uint32_t caller_gid,
                     uint32_t uid, uint32_t gid);
int vfs_chmod_owned(vfs_node_t *node, uint32_t caller_uid, uint32_t mode);
int vfs_set_times_owned(vfs_node_t *node, uint32_t uid, uint32_t gid, bool explicit_times,
                         uint64_t access_seconds, uint64_t modify_seconds);
typedef bool (*vfs_enum_cb_t)(const vfs_node_t *child, void *context);
size_t vfs_enum_children(vfs_node_t *dir, vfs_enum_cb_t callback, void *context);
vfs_node_t *vfs_add_block_device(vfs_node_t *dir, const char *name, block_device_t *device);
enum { VFS_CHARACTER_ENTROPY = 1 };
vfs_node_t *vfs_add_character_device(vfs_node_t *dir, const char *name, uint32_t kind);
ssize_t vfs_character_read(vfs_node_t *node, void *buffer, size_t count, bool nonblock);
void vfs_clear_directory(vfs_node_t *dir);
bool vfs_format(block_device_t *device);
bool vfs_mount_device(block_device_t *device, vfs_node_t *mount_point);
bool vfs_is_mount_point(const vfs_node_t *node);
bool vfs_sync_all(void);
/* Final shutdown checkpoint; stops subsequent backend writes. Thaws on failure. */
bool vfs_prepare_shutdown(void);
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
/* Coherent path metadata under the tree/data locks, without opening a file.
 * Explicit captured credentials preserve the caller/worker policy boundary. */
int vfs_path_stat_snapshot(vfs_node_t *cwd, const char *path, bool follow_final,
                            uint32_t uid, uint32_t gid, vfs_stat_snapshot_t *output);
/* Owned directory, protected worker. Build one complete absolute path under
 * the tree lock, or return negative errno without reporting truncated success.
 * Success excludes NUL, which is also written into the supplied storage. */
ssize_t vfs_path_snapshot(vfs_node_t *directory, char *buffer, size_t capacity);
/* Same coherent path snapshot for an owned node of any type. */
ssize_t vfs_node_path_snapshot(vfs_node_t *node, char *buffer, size_t capacity);
void vfs_node_release(vfs_node_t *node);
/* Protected worker, without caller locks/preemption guard. Serializes final
 * orphan-directory subtree teardown with tree readers, and consumes one owner.
 * Internal tree-held releases continue using vfs_node_release directly. */
void vfs_node_release_owned(vfs_node_t *node);

#endif
