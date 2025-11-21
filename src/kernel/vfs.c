#include "types.h"  
#include "vfs.h"
#include "vfs_internal.h"
#include "alixfs.h"
#include "libc.h"
#include "heap.h"
#include "serial.h"
#include "spinlock.h"
#include "process.h"
#include <limits.h>
#include <stdint.h>
#include "timer.h"
#include "build_features.h"

extern void storage_request_flush(void);

/*
 * Heap-backed VFS:
 *  - Nodes and names allocated dynamically.
 *  - File data grows via realloc (doubling strategy).
 *  - No fixed limits on node count, name length, or file size (bounded by RAM).
 */

#define VFS_DIRTY_BACKPRESSURE_LIMIT   (2ULL * 1024ULL * 1024ULL)

static bool vfs_mount_writeback(vfs_mount_t *mount, bool force);

static vfs_node_t *root = NULL;
static vfs_mount_t *mounts = NULL;
static spinlock_t g_vfs_tree_lock;
static const uint64_t VFS_SYNC_LOG_MS_THRESHOLD = 100ULL;

#define VFS_MAX_SYMLINK_DEPTH 8

static uint64_t vfs_ticks_to_ms(uint64_t ticks)
{
    uint64_t freq = timer_frequency();
    if (freq == 0)
    {
        freq = 1000;
    }
    return (ticks * 1000ULL) / freq;
}

static void vfs_log_sync_result(const char *dev_name,
                                const char *status,
                                uint64_t start_ticks,
                                size_t total_bytes)
{
    if (!dev_name || !status || start_ticks == 0)
    {
        return;
    }
    uint64_t elapsed_ms = vfs_ticks_to_ms(timer_ticks() - start_ticks);
    if (elapsed_ms < VFS_SYNC_LOG_MS_THRESHOLD && status[0] != 'f')
    {
        return;
    }
    serial_printf("%s", "[vfs] sync ");
    serial_printf("%s", status);
    serial_printf("%s", " dev=");
    serial_printf("%s", dev_name);
    serial_printf("%s", " bytes=0x");
    serial_printf("%016llX", (unsigned long long)total_bytes);
    serial_printf("%s", " duration=");
    serial_printf("%llu", (unsigned long long)elapsed_ms);
    serial_printf("%s", "ms\r\n");
}

static void vfs_log(const char *msg, uint64_t value)
{
    serial_printf("%s", "[vfs] ");
    serial_printf("%s", msg);
    serial_printf("%s", "0x");
    serial_printf("%016llX", (unsigned long long)(value));
    serial_printf("%s", "\r\n");
}

static bool vfs_mount_sync_node(vfs_node_t *node);
static void vfs_mark_mount_dirty(vfs_mount_t *mount);
static void vfs_mark_meta_dirty(vfs_node_t *node);
static void vfs_mark_data_dirty(vfs_node_t *node, size_t len);
static void vfs_lock_node_data(vfs_node_t *node);
static void vfs_unlock_node_data(vfs_node_t *node);
static void vfs_free_subtree(vfs_node_t *node);
static bool vfs_node_allows_mutation(const vfs_node_t *node);
static void vfs_inherit_mutability(vfs_node_t *parent, vfs_node_t *child);
static void vfs_set_subtree_mutable_locked(vfs_node_t *node, bool allow);
static void vfs_clear_dirty_subtree(vfs_node_t *node, vfs_mount_t *mount);
static bool vfs_mount_writeback(vfs_mount_t *mount, bool force);
static bool vfs_mount_flush_tree(vfs_mount_t *mount, bool force_all);
static bool vfs_mount_flush_single(vfs_node_t *node);
void vfs_node_retain(vfs_node_t *node);
void vfs_node_release(vfs_node_t *node);
static bool vfs_device_is_mounted(block_device_t *device);
size_t vfs_snapshot_mounts(vfs_mount_info_t *out, size_t max);
bool vfs_force_symlink(vfs_node_t *cwd, const char *target_path, const char *link_path);
static void vfs_backpressure_wait(vfs_mount_t *mount, size_t pending_bytes);
static void vfs_account_dirty_bytes(vfs_mount_t *mount, size_t bytes);

/* ---------- helpers ---------- */

static inline const char *skip_separators(const char *p)
{
    while (*p == '/') ++p;
    return p;
}

static bool is_dot(const char *s)
{
    return s[0] == '.' && s[1] == '\0';
}

static bool is_dot_dot(const char *s)
{
    return s[0] == '.' && s[1] == '.' && s[2] == '\0';
}

static char *vfs_strdup(const char *s)
{
    if (!s) return NULL;
    size_t len = strlen(s);
    char *p = (char *)malloc(len + 1);
    if (!p) return NULL;
    memcpy(p, s, len + 1);
    return p;
}

static void vfs_lock_node_data(vfs_node_t *node)
{
    if (node)
    {
        spinlock_lock(&node->data_lock);
    }
}

static void vfs_unlock_node_data(vfs_node_t *node)
{
    if (node)
    {
        spinlock_unlock(&node->data_lock);
    }
}

void vfs_node_retain(vfs_node_t *node)
{
    if (!node)
    {
        return;
    }
    vfs_lock_node_data(node);
    node->refcount++;
    vfs_unlock_node_data(node);
}

void vfs_node_release(vfs_node_t *node)
{
    if (!node)
    {
        return;
    }
    bool free_now = false;
    vfs_lock_node_data(node);
    if (node->refcount > 0)
    {
        node->refcount--;
        free_now = (node->refcount == 0);
    }
    vfs_unlock_node_data(node);
    if (free_now)
    {
        vfs_free_subtree(node);
    }
}

static void vfs_log_backpressure_event(const vfs_mount_t *mount,
                                       const char *phase,
                                       size_t dirty_bytes,
                                       size_t limit,
                                       size_t pending_bytes)
{
    char path[128];
    path[0] = '\0';
    if (mount && mount->mount_point)
    {
        vfs_build_path(mount->mount_point, path, sizeof(path));
    }
    if (path[0] == '\0')
    {
        const char fallback[] = "<unknown>";
        size_t copy_len = sizeof(fallback);
        if (copy_len > sizeof(path))
        {
            copy_len = sizeof(path);
        }
        memcpy(path, fallback, copy_len);
        path[sizeof(fallback) - 1] = '\0';
    }

    thread_t *thread = thread_current();
    const char *thread_name = thread ? process_thread_name_const(thread) : NULL;
    if (!thread_name || thread_name[0] == '\0')
    {
        thread_name = "<thread>";
    }
    process_t *proc = thread ? process_thread_owner(thread) : NULL;
    uint64_t pid = proc ? process_get_pid(proc) : 0;

    serial_printf("%s", "[vfs] backpressure ");
    serial_printf("%s", phase ? phase : "?");
    serial_printf("%s", " mount=");
    serial_printf("%s", path);
    serial_printf("%s", " dirty=");
    serial_printf("%016llX", (unsigned long long)dirty_bytes);
    serial_printf("%s", " limit=");
    serial_printf("%016llX", (unsigned long long)limit);
    serial_printf("%s", " pending=");
    serial_printf("%016llX", (unsigned long long)pending_bytes);
    serial_printf("%s", " thread=");
    serial_printf("%s", thread_name);
    serial_printf("%s", " pid=0x");
    serial_printf("%016llX", (unsigned long long)pid);
    serial_printf("%s", "\r\n");
}

static void vfs_backpressure_wait(vfs_mount_t *mount, size_t pending_bytes)
{
    if (!mount || pending_bytes == 0)
    {
        return;
    }
    bool logged_wait = false;
#if !ENABLE_FLUSHD
    bool flushed = false;
#endif
    while (1)
    {
        bool over = false;
        size_t dirty = 0;
        size_t limit = 0;
        spinlock_lock(&mount->dirty_lock);
        limit = mount->dirty_bytes_limit;
        dirty = mount->dirty_bytes;
        if (limit == 0 || dirty + pending_bytes <= limit)
        {
            over = false;
        }
        else
        {
            over = true;
        }
        spinlock_unlock(&mount->dirty_lock);
        if (!over)
        {
            if (logged_wait)
            {
                vfs_log_backpressure_event(mount, "resume", dirty, limit, pending_bytes);
                logged_wait = false;
            }
            break;
        }
        if (!logged_wait)
        {
            vfs_log_backpressure_event(mount, "wait", dirty, limit, pending_bytes);
            logged_wait = true;
        }
#if ENABLE_FLUSHD
        storage_request_flush();
        process_yield();
#else
        if (!flushed)
        {
            flushed = true;
            if (!vfs_mount_writeback(mount, false))
            {
                process_yield();
            }
            continue;
        }
        process_yield();
#endif
    }
}

static void vfs_account_dirty_bytes(vfs_mount_t *mount, size_t bytes)
{
    if (!mount || bytes == 0)
    {
        return;
    }
    spinlock_lock(&mount->dirty_lock);
    mount->dirty_bytes += bytes;
    spinlock_unlock(&mount->dirty_lock);
}

/* Extract next path component into a freshly malloc'd string; caller must free(). */
static bool next_component(const char **path_ptr, char **out_name)
{
    const char *p = skip_separators(*path_ptr);
    if (*p == '\0')
    {
        *path_ptr = p;
        *out_name = NULL;
        return false;
    }

    const char *start = p;
    while (*p && *p != '/') ++p;

    size_t len = (size_t)(p - start);
    char *name = (char *)malloc(len + 1);
    if (!name) { *out_name = NULL; return false; }
    memcpy(name, start, len);
    name[len] = '\0';

    *out_name = name;
    *path_ptr = p;  /* now at '/' or '\0' */
    return true;
}

static const char *vfs_node_symlink_target(const vfs_node_t *node)
{
    if (!node || node->type != VFS_NODE_SYMLINK)
    {
        return NULL;
    }
    return node->data ? node->data : "";
}

static bool vfs_assign_symlink_target(vfs_node_t *node, const char *target)
{
    if (!node || node->type != VFS_NODE_SYMLINK || !target || *target == '\0')
    {
        return false;
    }
    size_t len = strlen(target);
    char *copy = (char *)malloc(len + 1);
    if (!copy)
    {
        return false;
    }
    memcpy(copy, target, len + 1);
    vfs_lock_node_data(node);
    char *old = node->data;
    node->data = copy;
    node->size = len;
    node->capacity = len + 1;
    vfs_unlock_node_data(node);
    if (old)
    {
        free(old);
    }
    vfs_mark_data_dirty(node, len);
    vfs_mark_meta_dirty(node);
    return true;
}

static char *vfs_combine_symlink_path(const char *target, const char *remainder)
{
    if (!target)
    {
        return NULL;
    }
    const char *rest = remainder ? remainder : "";
    size_t target_len = strlen(target);
    size_t rest_len = strlen(rest);
    bool need_sep = false;
    if (rest_len > 0 && target_len > 0 && target[target_len - 1] != '/')
    {
        need_sep = true;
    }
    size_t total = target_len + (need_sep ? 1 : 0) + rest_len + 1;
    char *joined = (char *)malloc(total);
    if (!joined)
    {
        return NULL;
    }
    size_t pos = 0;
    if (target_len > 0)
    {
        memcpy(joined + pos, target, target_len);
        pos += target_len;
    }
    if (need_sep)
    {
        joined[pos++] = '/';
    }
    if (rest_len > 0)
    {
        memcpy(joined + pos, rest, rest_len);
        pos += rest_len;
    }
    joined[pos] = '\0';
    return joined;
}

static vfs_node_t *vfs_alloc_node(vfs_node_type_t type)
{
    vfs_node_t *n = (vfs_node_t *)calloc(1, sizeof(vfs_node_t));
    if (n)
    {
        n->type = type;
        n->disk_id = UINT32_MAX;
        n->allow_mutation = true;
        n->refcount = 1;
        n->pending_dirty_bytes = 0;
        spinlock_init(&n->data_lock);
    }
    return n;
}

static bool vfs_node_allows_mutation(const vfs_node_t *node)
{
    if (!node)
    {
        return false;
    }
    if (node->mount)
    {
        return true;
    }
    return node->allow_mutation;
}

static void vfs_inherit_mutability(vfs_node_t *parent, vfs_node_t *child)
{
    if (!child)
    {
        return;
    }
    if (parent)
    {
        child->allow_mutation = parent->allow_mutation || (parent->mount != NULL);
    }
}

static void vfs_set_subtree_mutable_locked(vfs_node_t *node, bool allow)
{
    if (!node)
    {
        return;
    }
    node->allow_mutation = allow;
    for (vfs_node_t *child = node->first_child; child; child = child->next_sibling)
    {
        vfs_set_subtree_mutable_locked(child, allow);
    }
}

static void vfs_attach_child(vfs_node_t *parent, vfs_node_t *child)
{
    if (!parent || !child) return;
    child->parent = parent;
    child->mount = parent->mount;
    vfs_inherit_mutability(parent, child);
    child->next_sibling = parent->first_child;
    parent->first_child = child;
}

static void vfs_attach_child_tail(vfs_node_t *parent, vfs_node_t *child)
{
    if (!parent || !child) return;
    child->parent = parent;
    child->mount = parent->mount;
    vfs_inherit_mutability(parent, child);
    child->next_sibling = NULL;
    if (!parent->first_child)
    {
        parent->first_child = child;
        return;
    }
    vfs_node_t *cursor = parent->first_child;
    while (cursor->next_sibling)
    {
        cursor = cursor->next_sibling;
    }
    cursor->next_sibling = child;
}

static void vfs_detach_child(vfs_node_t *child)
{
    if (!child || !child->parent)
    {
        return;
    }
    vfs_node_t *parent = child->parent;
    vfs_node_t **cursor = &parent->first_child;
    while (*cursor && *cursor != child)
    {
        cursor = &(*cursor)->next_sibling;
    }
    if (*cursor == child)
    {
        *cursor = child->next_sibling;
    }
    child->parent = NULL;
    child->next_sibling = NULL;
}

static vfs_node_t *vfs_find_child(vfs_node_t *parent, const char *name)
{
    if (!parent || !name) return NULL;
    for (vfs_node_t *n = parent->first_child; n; n = n->next_sibling)
    {
        if (n->name && strcmp(n->name, name) == 0)
            return n;
    }
    return NULL;
}

static void vfs_free_subtree(vfs_node_t *node)
{
    if (!node) return;
    vfs_mount_t *mount = node->mount;
    vfs_node_t *child = node->first_child;
    while (child)
    {
        vfs_node_t *next = child->next_sibling;
        child->parent = NULL;
        child->next_sibling = NULL;
        vfs_node_release(child);
        child = next;
    }
    vfs_lock_node_data(node);
    node->first_child = NULL;
    char *name = node->name;
    node->name = NULL;
    char *data = node->data;
    node->data = NULL;
    node->size = 0;
    node->capacity = 0;
    if (mount && mount->backend && mount->mount_point != node)
    {
        alixfs_mount_release_node(mount->backend, node);
    }
    vfs_unlock_node_data(node);
    if (name) free(name);
    if (data) free(data);
    free(node);
}

/* Ensure file has room for at least `need` bytes (+1 for trailing NUL). */
static bool ensure_capacity_locked(vfs_node_t *file, size_t need)
{
    if (!file || file->type != VFS_NODE_FILE) return false;

    size_t req = need + 1; /* keep a trailing '\0' */
    if (file->capacity >= req) return true;

    size_t new_cap = (file->capacity == 0) ? 64 : file->capacity;
    while (new_cap < req)
    {
        size_t next = new_cap << 1;
        if (next <= new_cap) { new_cap = req; break; } /* overflow guard */
        new_cap = next;
        if (new_cap < req) new_cap = req;
    }

    char *nbuf = (char *)realloc(file->data, new_cap);
    if (!nbuf) return false;

    file->data = nbuf;
    file->capacity = new_cap;
    if (file->size + 1 <= file->capacity)
        file->data[file->size] = '\0';
    return true;
}

bool vfs_reserve(vfs_node_t *file, size_t size_hint)
{
    if (size_hint == 0)
    {
        return true;
    }
    bool ok = false;
    vfs_lock_node_data(file);
    ok = ensure_capacity_locked(file, size_hint);
    vfs_unlock_node_data(file);
    return ok;
}

static void ensure_terminator_locked(vfs_node_t *node)
{
    if (!node || node->type != VFS_NODE_FILE) return;
    if (node->capacity == 0)
    {
        if (ensure_capacity_locked(node, 0))
            node->data[0] = '\0';
        return;
    }
    if (node->size + 1 <= node->capacity)
        node->data[node->size] = '\0';
    else
        node->data[node->capacity - 1] = '\0';
}

static void vfs_mark_mount_dirty(vfs_mount_t *mount)
{
    if (!mount)
    {
        return;
    }
    spinlock_lock(&mount->dirty_lock);
    mount->dirty = true;
    spinlock_unlock(&mount->dirty_lock);
}

static void vfs_mark_meta_dirty(vfs_node_t *node)
{
    if (!node)
    {
        return;
    }
    vfs_lock_node_data(node);
    node->dirty = true;
    node->disk_meta_dirty = true;
    vfs_unlock_node_data(node);
    vfs_mark_mount_dirty(node->mount);
}

static void vfs_mark_data_dirty(vfs_node_t *node, size_t len)
{
    if (!node)
    {
        return;
    }
    bool mounted = false;
    vfs_mount_t *mount = NULL;
    vfs_lock_node_data(node);
    node->dirty = true;
    node->disk_data_dirty = true;
    if (node->mount)
    {
        node->pending_dirty_bytes += len;
        mounted = true;
        mount = node->mount;
    }
    vfs_unlock_node_data(node);
    if (mounted && mount)
    {
        vfs_account_dirty_bytes(mount, len);
        vfs_mark_mount_dirty(mount);
    }
}

static void vfs_note_file_dirty(vfs_node_t *node, size_t start, size_t len, bool size_changed)
{
    (void)start;
    if (!node || node->type != VFS_NODE_FILE)
    {
        return;
    }
    vfs_mark_data_dirty(node, len);
    if (size_changed)
    {
        vfs_mark_meta_dirty(node);
    }
}

static void vfs_clear_dirty_subtree(vfs_node_t *node, vfs_mount_t *mount)
{
    if (!node)
    {
        return;
    }
    if (mount && node->mount != mount)
    {
        return;
    }
    vfs_lock_node_data(node);
    node->dirty = false;
    node->disk_meta_dirty = false;
    node->disk_data_dirty = false;
    node->disk_name_dirty = false;
    node->pending_dirty_bytes = 0;
    vfs_unlock_node_data(node);
    for (vfs_node_t *child = node->first_child; child; child = child->next_sibling)
    {
        vfs_clear_dirty_subtree(child, mount);
    }
}

static bool vfs_mount_flush_tree(vfs_mount_t *mount, bool force_all)
{
    if (!mount || !mount->backend || !mount->mount_point)
    {
        return true;
    }
    bool ok = false;
    spinlock_lock(&g_vfs_tree_lock);
    ok = alixfs_mount_flush_nodes(mount->backend, mount->mount_point, mount, force_all);
    if (ok)
    {
        vfs_clear_dirty_subtree(mount->mount_point, mount);
    }
    spinlock_unlock(&g_vfs_tree_lock);
    return ok;
}

static bool vfs_mount_flush_single(vfs_node_t *node)
{
    if (!node || !node->mount || !node->mount->backend)
    {
        return true;
    }
    vfs_mount_t *mount = node->mount;
    bool ok = true;
    spinlock_lock(&mount->sync_lock);
    spinlock_lock(&g_vfs_tree_lock);
    ok = alixfs_mount_flush_single(mount->backend, node, mount);
    spinlock_unlock(&g_vfs_tree_lock);
    if (ok)
    {
        ok = alixfs_mount_commit(mount->backend);
    }
    spinlock_unlock(&mount->sync_lock);

    if (!ok)
    {
        spinlock_lock(&mount->dirty_lock);
        mount->dirty = true;
        mount->needs_full_sync = true;
        spinlock_unlock(&mount->dirty_lock);
    }
    return ok;
}

/* Resolve existing node by path (no creation). Returns NULL if any component is missing. */
static vfs_node_t *resolve_node_internal(vfs_node_t *cwd, const char *path, int depth)
{
    if (!cwd)
    {
        cwd = root;
    }
    if (depth >= VFS_MAX_SYMLINK_DEPTH)
    {
        return NULL;
    }
    if (!path || *path == '\0')
    {
        return cwd;
    }

    vfs_node_t *node = (path[0] == '/') ? root : cwd;
    const char *cursor = skip_separators(path);
    if (*cursor == '\0')
    {
        return node;
    }

    char *component = NULL;
    while (next_component(&cursor, &component))
    {
        cursor = skip_separators(cursor);

        if (is_dot(component))
        {
            free(component);
            continue;
        }
        if (is_dot_dot(component))
        {
            if (node && node->parent)
            {
                node = node->parent;
            }
            free(component);
            continue;
        }

        vfs_node_t *child = vfs_find_child(node, component);
        free(component);
        if (!child)
        {
            return NULL;
        }

        if (child->type == VFS_NODE_SYMLINK)
        {
            const char *target = vfs_node_symlink_target(child);
            if (!target || *target == '\0')
            {
                return NULL;
            }
            char *combined = vfs_combine_symlink_path(target, cursor);
            if (!combined)
            {
                return NULL;
            }
            vfs_node_t *base = (target[0] == '/') ? root : node;
            vfs_node_t *resolved = resolve_node_internal(base, combined, depth + 1);
            free(combined);
            return resolved;
        }

        node = child;
    }

    return node;
}

static vfs_node_t *resolve_node(vfs_node_t *cwd, const char *path)
{
    vfs_node_t *base = NULL;
    if (path && path[0] == '/')
    {
        base = root;
    }
    else
    {
        base = cwd ? cwd : root;
    }
    return resolve_node_internal(base, path, 0);
}

/*
 * Split a path into (parent dir, final name).
 * Returns true on success and provides:
 *   - *parent_out = parent directory node
 *   - *name_out   = malloc'd last component (caller owns/free)
 */
static bool split_parent_and_name(vfs_node_t *cwd, const char *path,
                                  vfs_node_t **parent_out, char **name_out)
{
    if (!cwd)
    {
        cwd = root;
    }
    if (!path || *path == '\0')
    {
        return false;
    }

    char *copy = vfs_strdup(path);
    if (!copy)
    {
        return false;
    }

    size_t len = strlen(copy);
    while (len > 1 && copy[len - 1] == '/')
    {
        copy[--len] = '\0';
    }
    if (len == 0 || (len == 1 && copy[0] == '/'))
    {
        free(copy);
        return false;
    }

    char *name_part = NULL;
    const char *parent_spec = NULL;
    char *slash = NULL;
    for (char *p = copy; *p; ++p)
    {
        if (*p == '/')
        {
            slash = p;
        }
    }
    if (!slash)
    {
        name_part = copy;
    }
    else if (slash == copy)
    {
        name_part = slash + 1;
        parent_spec = "/";
    }
    else
    {
        *slash = '\0';
        name_part = slash + 1;
        parent_spec = copy;
    }

    if (!name_part || *name_part == '\0' || is_dot(name_part) || is_dot_dot(name_part))
    {
        free(copy);
        return false;
    }

    vfs_node_t *parent = NULL;
    if (!parent_spec)
    {
        parent = (path[0] == '/') ? root : cwd;
    }
    else
    {
        parent = resolve_node(cwd, parent_spec);
    }

    if (!parent)
    {
        free(copy);
        return false;
    }

    if (parent->type != VFS_NODE_DIR)
    {
        free(copy);
        return false;
    }

    char *name = vfs_strdup(name_part);
    free(copy);
    if (!name)
    {
        return false;
    }

    if (parent_out)
    {
        *parent_out = parent;
    }
    if (name_out)
    {
        *name_out = name;
    }
    else
    {
        free(name);
    }
    return true;
}

/* ---------- public API ---------- */

void vfs_init(void)
{
    if (root) return;

    spinlock_init(&g_vfs_tree_lock);

    vfs_node_t *node = vfs_alloc_node(VFS_NODE_DIR);
    if (!node) return; /* OOM: VFS disabled */

    node->name   = vfs_strdup("/");
    node->parent = NULL;
    node->first_child = NULL;
    node->next_sibling = NULL;
    node->size = 0;
    node->capacity = 0;
    node->data = NULL;
    root = node;
}

vfs_node_t *vfs_root(void)
{
    return root;
}

vfs_node_t *vfs_resolve(vfs_node_t *cwd, const char *path)
{
    spinlock_lock(&g_vfs_tree_lock);
    vfs_node_t *res = resolve_node(cwd ? cwd : root, path);
    spinlock_unlock(&g_vfs_tree_lock);
    return res;
}

vfs_node_t *vfs_mkdir(vfs_node_t *cwd, const char *path)
{
    vfs_node_t *parent = NULL;
    char *name = NULL;

    spinlock_lock(&g_vfs_tree_lock);

    if (!split_parent_and_name(cwd ? cwd : root, path, &parent, &name))
    {
        spinlock_unlock(&g_vfs_tree_lock);
        return NULL;
    }

    vfs_node_t *existing = vfs_find_child(parent, name);
    if (existing)
    {
        free(name);
        spinlock_unlock(&g_vfs_tree_lock);
        return (existing->type == VFS_NODE_DIR) ? existing : NULL;
    }

    if (!vfs_node_allows_mutation(parent))
    {
        free(name);
        spinlock_unlock(&g_vfs_tree_lock);
        return NULL;
    }

    vfs_node_t *dir = vfs_alloc_node(VFS_NODE_DIR);
    if (!dir)
    {
        free(name);
        spinlock_unlock(&g_vfs_tree_lock);
        return NULL;
    }

    dir->name   = name;   /* take ownership */
    dir->size = 0;
    dir->capacity = 0;
    dir->data = NULL;
    vfs_inherit_mutability(parent, dir);

    vfs_attach_child(parent, dir);
    vfs_mark_meta_dirty(parent);
    vfs_mark_meta_dirty(dir);
    spinlock_unlock(&g_vfs_tree_lock);
    return dir;
}

vfs_node_t *vfs_open_file(vfs_node_t *cwd, const char *path, bool create, bool truncate)
{
    vfs_node_t *parent = NULL;
    char *name = NULL;

    bool trace_proc = (path && strncmp(path, "/proc/devices", 13) == 0);

    spinlock_lock(&g_vfs_tree_lock);

    if (!split_parent_and_name(cwd ? cwd : root, path, &parent, &name))
    {
        if (trace_proc)
        {
            serial_printf("%s", "[vfs] split failed ");
            serial_printf("%s", path ? path : "<null>");
            serial_printf("%s", "\r\n");
        }
        spinlock_unlock(&g_vfs_tree_lock);
        return NULL;
    }

    vfs_node_t *file = vfs_find_child(parent, name);
    if (!file)
    {
        if (!create)
        {
            if (trace_proc)
            {
                serial_printf("%s", "[vfs] missing child name=");
                serial_printf("%s", name ? name : "<null>");
                serial_printf("%s", " path=");
                serial_printf("%s", path ? path : "<null>");
                serial_printf("%s", "\r\n");
            }
            free(name);
            spinlock_unlock(&g_vfs_tree_lock);
            return NULL;
        }
        if (!vfs_node_allows_mutation(parent))
        {
            free(name);
            spinlock_unlock(&g_vfs_tree_lock);
            return NULL;
        }
        file = vfs_alloc_node(VFS_NODE_FILE);
        if (!file)
        {
            free(name);
            spinlock_unlock(&g_vfs_tree_lock);
            return NULL;
        }
        file->name   = name;   /* take ownership */
        file->size = 0;
        file->capacity = 0;
        file->data = NULL;
        vfs_inherit_mutability(parent, file);
        vfs_attach_child(parent, file);
        vfs_mark_meta_dirty(parent);
        vfs_mark_meta_dirty(file);
    }
    else
    {
        free(name);
    }

    if (file->type != VFS_NODE_FILE)
    {
        if (trace_proc)
        {
            serial_printf("%s", "[vfs] wrong type name=");
            serial_printf("%s", file->name ? file->name : "<noname>");
            serial_printf("%s", " type=");
            serial_printf("%016llX", (unsigned long long)file->type);
            serial_printf("%s", "\r\n");
        }
        spinlock_unlock(&g_vfs_tree_lock);
        return NULL;
    }

    if (truncate)
    {
        if (!vfs_node_allows_mutation(file))
        {
            spinlock_unlock(&g_vfs_tree_lock);
            return NULL;
        }
        vfs_lock_node_data(file);
        file->size = 0;
        bool ok_trunc = ensure_capacity_locked(file, 0);
        if (!ok_trunc)
        {
            vfs_unlock_node_data(file);
            if (trace_proc)
            {
                serial_printf("%s", "[vfs] ensure_capacity failed ");
                serial_printf("%s", file->name ? file->name : "<noname>");
                serial_printf("%s", "\r\n");
            }
            spinlock_unlock(&g_vfs_tree_lock);
            return NULL;
        }
        file->data[0] = '\0';
        vfs_unlock_node_data(file);
        vfs_mark_data_dirty(file, 0);
        vfs_mark_meta_dirty(file);
    }

    vfs_lock_node_data(file);
    ensure_terminator_locked(file);
    vfs_unlock_node_data(file);
    spinlock_unlock(&g_vfs_tree_lock);
    return file;
}

static vfs_node_t *vfs_symlink_locked(vfs_node_t *cwd,
                                      const char *target_path,
                                      const char *link_path,
                                      bool force)
{
    if (!target_path || !link_path || *target_path == '\0')
    {
        return NULL;
    }

    (void)force;

    vfs_node_t *parent = NULL;
    char *name = NULL;
    if (!split_parent_and_name(cwd ? cwd : root, link_path, &parent, &name))
    {
        return NULL;
    }

    vfs_node_t *existing = vfs_find_child(parent, name);
    if (existing)
    {
        if (!vfs_node_allows_mutation(existing))
        {
            free(name);
            return NULL;
        }
        if (!force && existing->type != VFS_NODE_SYMLINK)
        {
            free(name);
            return NULL;
        }
        if (existing->type == VFS_NODE_SYMLINK)
        {
            bool updated = vfs_assign_symlink_target(existing, target_path);
            free(name);
            return updated ? existing : NULL;
        }
        if (existing->type == VFS_NODE_DIR && vfs_is_mount_point(existing))
        {
            free(name);
            return NULL;
        }
        if (existing->type == VFS_NODE_DIR && existing->first_child)
        {
            vfs_clear_directory(existing);
        }
        vfs_detach_child(existing);
        vfs_node_release(existing);
        existing = NULL;
    }

    if (!vfs_node_allows_mutation(parent))
    {
        free(name);
        return NULL;
    }

    vfs_node_t *node = vfs_alloc_node(VFS_NODE_SYMLINK);
    if (!node)
    {
        free(name);
        return NULL;
    }
    node->name = name;
    if (!vfs_assign_symlink_target(node, target_path))
    {
        vfs_free_subtree(node);
        return NULL;
    }

    vfs_attach_child(parent, node);
    vfs_mark_meta_dirty(parent);
    vfs_mark_meta_dirty(node);
    return node;
}

vfs_node_t *vfs_symlink(vfs_node_t *cwd, const char *target_path, const char *link_path)
{
    spinlock_lock(&g_vfs_tree_lock);
    vfs_node_t *node = vfs_symlink_locked(cwd, target_path, link_path, false);
    spinlock_unlock(&g_vfs_tree_lock);
    return node;
}

bool vfs_force_symlink(vfs_node_t *cwd, const char *target_path, const char *link_path)
{
    spinlock_lock(&g_vfs_tree_lock);
    vfs_node_t *node = vfs_symlink_locked(cwd, target_path, link_path, true);
    spinlock_unlock(&g_vfs_tree_lock);
    return node != NULL;
}

bool vfs_is_dir(const vfs_node_t *node)
{
    return node ? (node->type == VFS_NODE_DIR) : false;
}

bool vfs_is_file(const vfs_node_t *node)
{
    return node ? (node->type == VFS_NODE_FILE) : false;
}

bool vfs_is_block(const vfs_node_t *node)
{
    return node ? (node->type == VFS_NODE_BLOCK) : false;
}

bool vfs_is_symlink(const vfs_node_t *node)
{
    return node ? (node->type == VFS_NODE_SYMLINK) : false;
}

block_device_t *vfs_block_device(const vfs_node_t *node)
{
    if (!node || node->type != VFS_NODE_BLOCK)
    {
        return NULL;
    }
    return node->block_device;
}

vfs_node_type_t vfs_node_type(const vfs_node_t *node)
{
    return node ? node->type : VFS_NODE_FILE;
}

const char *vfs_symlink_target(const vfs_node_t *node)
{
    return vfs_node_symlink_target(node);
}

bool vfs_truncate(vfs_node_t *file)
{
    if (!file || file->type != VFS_NODE_FILE) return false;
    if (!vfs_node_allows_mutation(file)) return false;
    vfs_lock_node_data(file);
    file->size = 0;
    bool ok = ensure_capacity_locked(file, 0);
    if (ok)
    {
        file->data[0] = '\0';
    }
    vfs_unlock_node_data(file);
    if (!ok) return false;
    vfs_note_file_dirty(file, 0, 0, true);
    return true;
}

bool vfs_append(vfs_node_t *file, const char *data, size_t len)
{
    if (!file || file->type != VFS_NODE_FILE) return false;
    if (!vfs_node_allows_mutation(file)) return false;
    if (!data || len == 0)
    {
        vfs_lock_node_data(file);
        ensure_terminator_locked(file);
        vfs_unlock_node_data(file);
        return true;
    }

    if (file->mount)
    {
        vfs_backpressure_wait(file->mount, len);
    }
    vfs_lock_node_data(file);
    if (!ensure_capacity_locked(file, file->size + len))
    {
        vfs_unlock_node_data(file);
        return false;
    }

    memmove(file->data + file->size, data, len);
    size_t start = file->size;
    file->size += len;
    ensure_terminator_locked(file);
    vfs_unlock_node_data(file);
    vfs_note_file_dirty(file, start, len, true);
    return true;
}

ssize_t vfs_read_at(vfs_node_t *file, size_t offset, void *buffer, size_t count)
{
    vfs_log("read file=", (uint64_t)(uintptr_t)file);
    vfs_log("read off=", offset);
    vfs_log("read cnt=", count);
    if (!file || file->type != VFS_NODE_FILE || !buffer)
    {
        return -1;
    }

    if (file->read_cb)
    {
        return file->read_cb(file, offset, buffer, count, file->callback_context);
    }

    vfs_lock_node_data(file);
    ensure_terminator_locked(file);
    if (offset >= file->size || count == 0)
    {
        vfs_unlock_node_data(file);
        return 0;
    }
    size_t available = file->size - offset;
    if (count > available)
    {
        count = available;
    }
    memcpy(buffer, file->data + offset, count);
    vfs_unlock_node_data(file);
    vfs_log("read dst=", (uint64_t)(uintptr_t)buffer);
    vfs_log("read bytes=", count);
    return (ssize_t)count;
}

ssize_t vfs_write_at(vfs_node_t *file, size_t offset, const void *data, size_t count)
{
    vfs_log("write file=", (uint64_t)(uintptr_t)file);
    vfs_log("write off=", offset);
    vfs_log("write cnt=", count);
    if (!file || file->type != VFS_NODE_FILE)
    {
        return -1;
    }
    if (!vfs_node_allows_mutation(file))
    {
        return -1;
    }

    if (file->write_cb)
    {
        return file->write_cb(file, offset, data, count, file->callback_context);
    }

    if (count > 0 && !data)
    {
        return -1;
    }
    if (count == 0)
    {
        return 0;
    }
    if (offset > (size_t)-1 - count)
    {
        return -1;
    }
    size_t end = offset + count;
    if (file->mount)
    {
        vfs_backpressure_wait(file->mount, count);
    }
    vfs_lock_node_data(file);
    if (!ensure_capacity_locked(file, end))
    {
        vfs_unlock_node_data(file);
        return -1;
    }
    size_t previous_size = file->size;
    if (offset > file->size)
    {
        size_t gap = offset - file->size;
        memset(file->data + file->size, 0, gap);
    }
    memcpy(file->data + offset, data, count);
    vfs_log("write src=", (uint64_t)(uintptr_t)data);
    if (end > file->size)
    {
        file->size = end;
    }
    ensure_terminator_locked(file);
    bool size_changed = (file->size != previous_size);
    vfs_unlock_node_data(file);
    vfs_note_file_dirty(file, offset, count, size_changed);
    return (ssize_t)count;
}

bool vfs_set_file_callbacks(vfs_node_t *file,
                            vfs_read_cb_t read_cb,
                            vfs_write_cb_t write_cb,
                            void *context)
{
    if (!file || file->type != VFS_NODE_FILE)
    {
        return false;
    }
    file->read_cb = read_cb;
    file->write_cb = write_cb;
    file->callback_context = context;
    return true;
}

char *vfs_data(vfs_node_t *file, size_t *size)
{
    if (!file || file->type != VFS_NODE_FILE)
    {
        if (size) *size = 0;
        return NULL;
    }
    vfs_lock_node_data(file);
    ensure_terminator_locked(file);
    if (size) *size = file->size;
    char *data = file->data;
    vfs_unlock_node_data(file);
    return data;
}

const char *vfs_name(const vfs_node_t *node)
{
    return node ? node->name : NULL;
}

vfs_node_t *vfs_parent(const vfs_node_t *node)
{
    return node ? node->parent : NULL;
}

size_t vfs_build_path(const vfs_node_t *node, char *buffer, size_t capacity)
{
    if (!buffer || capacity == 0)
    {
        return 0;
    }

    if (!node)
    {
        node = root;
    }

    const char *segments[64];
    size_t count = 0;
    const vfs_node_t *current = node;
    while (current && current != root && count < (sizeof(segments) / sizeof(segments[0])))
    {
        segments[count++] = current->name ? current->name : "";
        current = current->parent;
    }

    size_t idx = 0;
    buffer[idx++] = '/';
    if (idx >= capacity)
    {
        buffer[capacity - 1] = '\0';
        return capacity - 1;
    }

    if (count == 0)
    {
        buffer[idx] = '\0';
        return idx;
    }

    for (size_t i = 0; i < count && idx < capacity - 1; ++i)
    {
        const char *segment = segments[count - 1 - i];
        if (!segment || segment[0] == '\0')
        {
            continue;
        }
        size_t seg_len = strlen(segment);
        if (seg_len >= capacity - idx)
        {
            seg_len = capacity - idx - 1;
        }
        if (seg_len == 0)
        {
            break;
        }
        memcpy(buffer + idx, segment, seg_len);
        idx += seg_len;
        buffer[idx] = '\0';
        if (i + 1 < count && idx < capacity - 1)
        {
            buffer[idx++] = '/';
            buffer[idx] = '\0';
        }
    }

    return idx;
}

bool vfs_remove_file(vfs_node_t *cwd, const char *path)
{
    if (!path || *path == '\0')
    {
        return false;
    }

    spinlock_lock(&g_vfs_tree_lock);

    vfs_node_t *parent = NULL;
    char *name = NULL;
    if (!split_parent_and_name(cwd ? cwd : root, path, &parent, &name))
    {
        spinlock_unlock(&g_vfs_tree_lock);
        return false;
    }
    if (!parent)
    {
        free(name);
        spinlock_unlock(&g_vfs_tree_lock);
        return false;
    }

    vfs_node_t *node = vfs_find_child(parent, name);
    free(name);
    if (!node || (node->type != VFS_NODE_FILE && node->type != VFS_NODE_SYMLINK))
    {
        spinlock_unlock(&g_vfs_tree_lock);
        return false;
    }

    if (!vfs_node_allows_mutation(parent))
    {
        spinlock_unlock(&g_vfs_tree_lock);
        return false;
    }

    vfs_detach_child(node);
    vfs_node_release(node);

    vfs_mark_meta_dirty(parent);
    spinlock_unlock(&g_vfs_tree_lock);
    return true;
}

vfs_node_t *vfs_first_child(vfs_node_t *dir)
{
    if (!dir || dir->type != VFS_NODE_DIR) return NULL;
    return dir->first_child;
}

vfs_node_t *vfs_next_sibling(vfs_node_t *node)
{
    return node ? node->next_sibling : NULL;
}

vfs_node_t *vfs_add_block_device(vfs_node_t *dir, const char *name, block_device_t *device)
{
    if (!dir || dir->type != VFS_NODE_DIR || !name || !device)
    {
        return NULL;
    }

    spinlock_lock(&g_vfs_tree_lock);

    vfs_node_t *existing = vfs_find_child(dir, name);
    if (existing)
    {
        if (existing->type == VFS_NODE_BLOCK)
        {
            existing->block_device = device;
            spinlock_unlock(&g_vfs_tree_lock);
            return existing;
        }
        spinlock_unlock(&g_vfs_tree_lock);
        return NULL;
    }

    if (!vfs_node_allows_mutation(dir))
    {
        spinlock_unlock(&g_vfs_tree_lock);
        return NULL;
    }

    vfs_node_t *node = vfs_alloc_node(VFS_NODE_BLOCK);
    if (!node)
    {
        spinlock_unlock(&g_vfs_tree_lock);
        return NULL;
    }

    node->name = vfs_strdup(name);
    if (!node->name)
    {
        free(node);
        spinlock_unlock(&g_vfs_tree_lock);
        return NULL;
    }
    node->block_device = device;
    node->size = 0;
    node->capacity = 0;
    node->data = NULL;

    vfs_attach_child_tail(dir, node);
    vfs_mark_meta_dirty(dir);
    spinlock_unlock(&g_vfs_tree_lock);
    return node;
}

void vfs_clear_directory(vfs_node_t *dir)
{
    if (!dir || dir->type != VFS_NODE_DIR)
    {
        return;
    }
    if (!vfs_node_allows_mutation(dir))
    {
        return;
    }

    vfs_node_t *child = dir->first_child;
    dir->first_child = NULL;
    while (child)
    {
        vfs_node_t *next = child->next_sibling;
        child->parent = NULL;
        child->next_sibling = NULL;
        vfs_node_release(child);
        child = next;
    }
    vfs_mark_meta_dirty(dir);
}

bool vfs_format(block_device_t *device)
{
    if (!device)
    {
        return false;
    }

    spinlock_lock(&g_vfs_tree_lock);
    bool mounted = vfs_device_is_mounted(device);
    spinlock_unlock(&g_vfs_tree_lock);
    if (mounted)
    {
        return false;
    }

    return alixfs_mount_format(device);
}

static bool vfs_device_is_mounted(block_device_t *device)
{
    for (vfs_mount_t *m = mounts; m; m = m->next)
    {
        if (m->device == device)
        {
            return true;
        }
    }
    return false;
}

static bool vfs_mount_writeback(vfs_mount_t *mount, bool force)
{
    if (!mount)
    {
        return true;
    }
    bool do_flush = force;
    bool force_all = force;
    size_t pending_bytes = 0;
    const char *dev_name = (mount->device && mount->device->name[0]) ? mount->device->name : "(anon)";

    spinlock_lock(&mount->dirty_lock);
    if (mount->dirty || force)
    {
        do_flush = true;
        force_all = force || mount->needs_full_sync;
        pending_bytes = mount->dirty_bytes;
        mount->dirty = false;
        mount->needs_full_sync = false;
    }
    else
    {
        do_flush = false;
    }
    spinlock_unlock(&mount->dirty_lock);

    if (!do_flush)
    {
        return true;
    }

    uint64_t start = timer_ticks();
    uint64_t lock_wait_start = timer_ticks();
    while (__sync_lock_test_and_set(&mount->sync_lock.value, 1) != 0)
    {
        while (mount->sync_lock.value)
        {
            __asm__ volatile ("pause");
            uint64_t elapsed_ticks = timer_ticks() - lock_wait_start;
            uint64_t freq = timer_frequency();
            if (freq == 0)
            {
                freq = 1000;
            }
            uint64_t elapsed_ms = (elapsed_ticks * 1000ULL) / freq;
            if (elapsed_ms >= 2000ULL)
            {
                serial_printf("[vfs] sync_lock wait timeout dev=%s force=%d\r\n",
                              dev_name,
                              force ? 1 : 0);
                return false;
            }
        }
    }
    bool ok = vfs_mount_flush_tree(mount, force_all);
    if (ok && mount->backend)
    {
        ok = alixfs_mount_commit(mount->backend);
    }
    spinlock_unlock(&mount->sync_lock);

    if (!ok)
    {
        spinlock_lock(&mount->dirty_lock);
        mount->dirty = true;
        mount->needs_full_sync = true;
        spinlock_unlock(&mount->dirty_lock);
        vfs_log_sync_result(dev_name, "fail", start, pending_bytes);
        return false;
    }

    vfs_log_sync_result(dev_name, "ok", start, pending_bytes);
    return true;
}

static bool vfs_mount_sync_node(vfs_node_t *node)
{
    if (!node)
    {
        return true;
    }
    vfs_mount_t *mount = node->mount;
    if (!mount)
    {
        return true;
    }
    return vfs_mount_flush_single(node);
}

static bool vfs_load_mount(block_device_t *device, vfs_mount_t *mount)
{
    (void)device;
    if (!mount || !mount->backend || !mount->mount_point)
    {
        return false;
    }
    return alixfs_mount_load(mount->backend, mount);
}

bool vfs_mount_device(block_device_t *device, vfs_node_t *mount_point)
{
    if (!device || !mount_point || mount_point->type != VFS_NODE_DIR)
    {
        return false;
    }

    spinlock_lock(&g_vfs_tree_lock);

    if (vfs_is_mount_point(mount_point) ||
        mount_point->first_child ||
        mount_point->mount ||
        vfs_device_is_mounted(device))
    {
        spinlock_unlock(&g_vfs_tree_lock);
        return false;
    }

    vfs_mount_t *mount = (vfs_mount_t *)calloc(1, sizeof(vfs_mount_t));
    if (!mount)
    {
        spinlock_unlock(&g_vfs_tree_lock);
        return false;
    }

    mount->device = device;
    mount->mount_point = mount_point;
    mount->dirty_bytes_limit = VFS_DIRTY_BACKPRESSURE_LIMIT;
    spinlock_init(&mount->dirty_lock);
    spinlock_init(&mount->sync_lock);
    mount->backend = alixfs_mount_create(device);
    if (!mount->backend)
    {
        free(mount);
        spinlock_unlock(&g_vfs_tree_lock);
        return false;
    }

    mount_point->mount = mount;

    if (!vfs_load_mount(device, mount))
    {
        vfs_clear_directory(mount_point);
        mount_point->mount = NULL;
        alixfs_mount_destroy(mount->backend);
        free(mount);
        spinlock_unlock(&g_vfs_tree_lock);
        return false;
    }

    mount->next = mounts;
    mounts = mount;
    spinlock_unlock(&g_vfs_tree_lock);
    return true;
}

bool vfs_is_mount_point(const vfs_node_t *node)
{
    if (!node || node->type != VFS_NODE_DIR)
    {
        return false;
    }
    vfs_mount_t *mount = node->mount;
    return mount && mount->mount_point == node;
}

bool vfs_sync_all(void)
{
    bool ok = true;
    spinlock_lock(&g_vfs_tree_lock);
    vfs_mount_t *head = mounts;
    spinlock_unlock(&g_vfs_tree_lock);

    for (vfs_mount_t *mount = head; mount; mount = mount->next)
    {
        if (!vfs_mount_writeback(mount, true))
        {
            ok = false;
        }
    }
    return ok;
}

bool vfs_sync_dirty(void)
{
    bool ok = true;
    spinlock_lock(&g_vfs_tree_lock);
    vfs_mount_t *head = mounts;
    spinlock_unlock(&g_vfs_tree_lock);

    for (vfs_mount_t *mount = head; mount; mount = mount->next)
    {
        bool dirty = false;
        bool need_full = false;
        spinlock_lock(&mount->dirty_lock);
        dirty = mount->dirty;
        need_full = mount->needs_full_sync;
        spinlock_unlock(&mount->dirty_lock);

        if (!dirty && !need_full)
        {
            continue;
        }
        if (!vfs_mount_writeback(mount, false))
        {
            ok = false;
        }
    }
    return ok;
}

bool vfs_flush_node(vfs_node_t *node)
{
    return vfs_mount_sync_node(node);
}

void vfs_set_subtree_mutable(vfs_node_t *node, bool allow)
{
    spinlock_lock(&g_vfs_tree_lock);
    vfs_set_subtree_mutable_locked(node ? node : root, allow);
    spinlock_unlock(&g_vfs_tree_lock);
}

size_t vfs_snapshot_mounts(vfs_mount_info_t *out, size_t max)
{
    size_t count = 0;
    spinlock_lock(&g_vfs_tree_lock);
    for (vfs_mount_t *m = mounts; m; m = m->next)
    {
        if (out && count < max)
        {
            out[count].mount_point = m->mount_point;
            out[count].device = m->device;
            spinlock_lock(&m->dirty_lock);
            out[count].dirty = m->dirty;
            bool needs_full = m->needs_full_sync;
            spinlock_unlock(&m->dirty_lock);
            bool header_dirty = false;
            if (m->backend)
            {
                alixfs_mount_snapshot(m->backend, &header_dirty);
            }
            out[count].needs_full_sync = needs_full || header_dirty;
        }
        count++;
    }
    spinlock_unlock(&g_vfs_tree_lock);
    return count;
}
