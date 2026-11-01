#include "types.h"  
#include "vfs.h"
#include "errno.h"
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
#include "timekeeping.h"
#include "build_features.h"
#include "procfs.h"
#include "smp.h"

extern void storage_request_flush(void);

/*
 * Heap-backed VFS:
 *  - Nodes and names allocated dynamically.
 *  - File data grows via realloc (doubling strategy).
 *  - No fixed limits on node count, name length, or file size (bounded by RAM).
 *
 * Locking model:
 *  - `g_vfs_tree_lock` protects tree structure (parents/children, mounts list,
 *    node creation/removal, mount point checks).
 *  - `node->data_lock` protects the per-file data buffer and dirty tracking.
 *
 * See docs/kernel/vfs.md for an overview of the VFS and mount/writeback flow.
 */

#define VFS_DIRTY_BACKPRESSURE_LIMIT     (64ULL * 1024ULL * 1024ULL)
#define VFS_ACTIVE_WRITE_FLUSH_THRESHOLD (48ULL * 1024ULL * 1024ULL)
#define VFS_ACTIVE_WRITE_GRACE_MS        300ULL

static bool vfs_mount_writeback(vfs_mount_t *mount, bool force);

static vfs_node_t *root = NULL;
static vfs_mount_t *mounts = NULL;
static spinlock_t g_vfs_tree_lock;
static const uint64_t VFS_SYNC_LOG_MS_THRESHOLD = 100ULL;
static uint32_t g_vfs_log_enable = 0;

/*
 * Tree operations can include filesystem load paths that poll storage and
 * voluntarily yield.  This is therefore an adaptive scheduler-friendly lock,
 * not a generic non-preemptible spinlock: a contending process yields so a
 * preempted owner can run and complete the operation.  Before the scheduler is
 * available, contention falls back to a normal pause loop.
 */
static void vfs_tree_lock_acquire(void)
{
    while (__sync_lock_test_and_set(&g_vfs_tree_lock.value, 1) != 0)
    {
        while (__atomic_load_n(&g_vfs_tree_lock.value, __ATOMIC_ACQUIRE) != 0)
        {
            if (process_scheduler_ready() && thread_current())
            {
                process_yield();
            }
            else
            {
                __asm__ volatile ("pause");
            }
        }
    }
}

static void vfs_tree_lock_release(void)
{
    spinlock_unlock_raw(&g_vfs_tree_lock);
}

static uint64_t vfs_now_seconds(void)
{
    return timekeeping_now_seconds();
}

static inline bool vfs_logs_enabled(void)
{
    return __atomic_load_n(&g_vfs_log_enable, __ATOMIC_RELAXED) != 0;
}

static inline uint64_t ticks_to_ms(uint64_t ticks)
{
    uint64_t freq = timer_frequency();
    if (freq == 0)
    {
        freq = 1000;
    }
    return (ticks * 1000ULL) / freq;
}

static bool vfs_sync_lock_predicate(void *context)
{
    vfs_mount_t *mount = (vfs_mount_t *)context;
    if (!mount)
    {
        return false;
    }
    if (!mount->sync_lock.locked)
    {
        mount->sync_lock.locked = true;
        mount->sync_owner_pid = process_current_pid();
        mount->sync_owner_cpu = smp_current_cpu_index();
        mount->sync_owner_ticks = timer_ticks();
        return true;
    }
    return false;
}

static bool vfs_sync_lock_acquire(vfs_mount_t *mount)
{
    if (!mount)
    {
        return false;
    }
    wait_queue_wait(&mount->sync_lock.waiters, vfs_sync_lock_predicate, mount);
    return true;
}

static void vfs_sync_lock_release(vfs_mount_t *mount)
{
    if (!mount)
    {
        return;
    }
    uint64_t owner_pid = 0;
    uint32_t owner_cpu = UINT32_MAX;
    uint64_t owner_ticks = 0;
    uint64_t held_ms = 0;

    spinlock_lock(&mount->sync_lock.waiters.lock);
    owner_pid = mount->sync_owner_pid;
    owner_cpu = mount->sync_owner_cpu;
    owner_ticks = mount->sync_owner_ticks;
    if (owner_ticks)
    {
        held_ms = ticks_to_ms(timer_ticks() - owner_ticks);
    }
    mount->sync_owner_pid = 0;
    mount->sync_owner_cpu = UINT32_MAX;
    mount->sync_owner_ticks = 0;
    mount->sync_lock.locked = false;
    spinlock_unlock(&mount->sync_lock.waiters.lock);

    wait_queue_wake_all(&mount->sync_lock.waiters);

    if (held_ms >= 2000ULL)
    {
        const char *dev_name = (mount->device && mount->device->name[0]) ? mount->device->name : "(anon)";
        serial_printf("[vfs] sync_lock held_long dev=%s owner_pid=0x%016llX owner_cpu=%u held_ms=%llu",
                      dev_name,
                      (unsigned long long)owner_pid,
                      (unsigned)owner_cpu,
                      (unsigned long long)held_ms);
    }
}

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
    serial_printf("[vfs] sync %s dev=%s bytes=0x%016llX duration=%llums",
                  status,
                  dev_name,
                  (unsigned long long)total_bytes,
                  (unsigned long long)elapsed_ms);
}

static void vfs_log(const char *msg, uint64_t value)
{
    if (!vfs_logs_enabled())
    {
        return;
    }
    serial_printf("[vfs] %s0x%016llX\r\n",
                  msg ? msg : "",
                  (unsigned long long)(value));
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
static void vfs_inherit_ownership(vfs_node_t *parent, vfs_node_t *child);
static void vfs_set_subtree_mutable_locked(vfs_node_t *node, bool allow);
static bool vfs_mount_writeback(vfs_mount_t *mount, bool force);
static bool vfs_mount_flush_tree(vfs_mount_t *mount, bool force_all, bool force_sync);
static bool vfs_mount_flush_single(vfs_node_t *node);
void vfs_node_retain(vfs_node_t *node);
void vfs_node_release(vfs_node_t *node);
static bool vfs_device_is_mounted(block_device_t *device);
size_t vfs_snapshot_mounts(vfs_mount_info_t *out, size_t max);
bool vfs_force_symlink(vfs_node_t *cwd, const char *target_path, const char *link_path);
static void vfs_backpressure_wait(vfs_mount_t *mount, size_t pending_bytes);
static void vfs_account_dirty_bytes(vfs_mount_t *mount, size_t bytes);

static ssize_t vfs_log_read(vfs_node_t *node, size_t offset, void *buffer, size_t count, void *context)
{
    (void)node;
    (void)context;
    (void)offset;
    if (!buffer || count == 0)
    {
        return 0;
    }
    char out[2];
    out[0] = (__atomic_load_n(&g_vfs_log_enable, __ATOMIC_RELAXED) != 0) ? '1' : '0';
    size_t len = (count > 1) ? 2 : 1;
    if (len == 2)
    {
        out[1] = '\n';
    }
    memcpy(buffer, out, len);
    return (ssize_t)len;
}

static ssize_t vfs_log_write(vfs_node_t *node, size_t offset, const void *buffer, size_t count, void *context)
{
    (void)node;
    (void)context;
    (void)offset;
    if (!buffer || count == 0)
    {
        return -1;
    }
    const char *cbuf = (const char *)buffer;
    int value = -1;
    size_t idx = 0;
    while (idx < count && (cbuf[idx] == ' ' || cbuf[idx] == '\t'))
    {
        ++idx;
    }
    if (idx < count)
    {
        if (cbuf[idx] == '0')
        {
            value = 0;
        }
        else if (cbuf[idx] == '1')
        {
            value = 1;
        }
    }
    if (value < 0)
    {
        return -1;
    }
    for (size_t tail = idx + 1; tail < count; ++tail)
    {
        char t = cbuf[tail];
        if (t == ' ' || t == '\t' || t == '\r' || t == '\n')
        {
            continue;
        }
        return -1;
    }
    __atomic_store_n(&g_vfs_log_enable, (uint32_t)value, __ATOMIC_RELEASE);
    return (ssize_t)count;
}

/*
 * Register procfs controls for VFS debug/trace toggles.
 *
 * Current controls live under `/proc/sys/vfs/...` and are implemented as
 * callback-backed VFS files via procfs.
 */
void vfs_sys_controls_init(void)
{
    (void)procfs_create_file_at("sys/vfs/log_enable", vfs_log_read, vfs_log_write, NULL);
}

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

/*
 * Increment a VFS node reference count.
 *
 * Nodes are owned by:
 *  - the VFS tree itself (parent/child links), and
 *  - any external holders (FDs, mounts, etc).
 *
 * A node may be freed only once its refcount reaches zero.
 */
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

/*
 * Decrement a VFS node reference count; frees the subtree when it hits zero.
 *
 * Callers must ensure they are releasing their own reference and not a tree
 * ownership link (i.e. this is for “external” references).
 */
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

void vfs_node_release_owned(vfs_node_t *node)
{
    if (!node) return;
    vfs_tree_lock_acquire();
    vfs_node_release(node);
    vfs_tree_lock_release();
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

    serial_printf("[vfs] backpressure %s mount=%s dirty=0x%016llX limit=0x%016llX pending=0x%016llX thread=%s pid=0x%016llX",
                  phase ? phase : "?",
                  path,
                  (unsigned long long)dirty_bytes,
                  (unsigned long long)limit,
                  (unsigned long long)pending_bytes,
                  thread_name,
                  (unsigned long long)pid);
}

static void vfs_backpressure_wait(vfs_mount_t *mount, size_t pending_bytes)
{
    if (!mount || pending_bytes == 0)
    {
        return;
    }
    bool logged_wait = false;
#if ENABLE_FLUSHD
    uint64_t start_ticks = timer_ticks();
#endif
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
        /* If flushd is not keeping up, fall back to a synchronous writeback after ~100ms. */
        uint64_t freq = timer_frequency();
        if (freq == 0)
        {
            freq = 1000;
        }
        uint64_t elapsed_ms = ((timer_ticks() - start_ticks) * 1000ULL) / freq;
        if (elapsed_ms >= 100)
        {
            vfs_mount_writeback(mount, false);
            start_ticks = timer_ticks();
        }
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
    size_t len = 0;
    while (len < VFS_PATH_MAX && target[len]) ++len;
    if (len == VFS_PATH_MAX) return false;
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

static void vfs_init_times(vfs_node_t *node)
{
    if (!node)
    {
        return;
    }
    uint64_t now = vfs_now_seconds();
    node->atime = now;
    node->mtime = now;
    node->ctime = now;
}

static vfs_node_t *vfs_alloc_node(vfs_node_type_t type)
{
    vfs_node_t *n = (vfs_node_t *)calloc(1, sizeof(vfs_node_t));
    if (n)
    {
        n->type = type;
        n->disk_id = UINT32_MAX;
        n->allow_mutation = true;
        n->uid = VFS_UID_ROOT;
        n->gid = VFS_GID_ROOT;
        n->refcount = 1;
        n->pending_dirty_bytes = 0;
        spinlock_init(&n->data_lock);
        vfs_init_times(n);
    }
    return n;
}

static bool vfs_node_allows_mutation(const vfs_node_t *node)
{
    if (!node)
    {
        return false;
    }
    /* Callback-backed nodes (e.g., procfs control files) should be writable
     * even if they were not explicitly marked mutable. */
    if (node->write_cb)
    {
        return true;
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

static void vfs_inherit_ownership(vfs_node_t *parent, vfs_node_t *child)
{
    if (!child)
    {
        return;
    }
    if (parent)
    {
        child->uid = parent->uid;
        child->gid = parent->gid;
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
    vfs_inherit_ownership(parent, child);
    child->next_sibling = parent->first_child;
    parent->first_child = child;
}

static void vfs_attach_child_tail(vfs_node_t *parent, vfs_node_t *child)
{
    if (!parent || !child) return;
    child->parent = parent;
    child->mount = parent->mount;
    vfs_inherit_mutability(parent, child);
    vfs_inherit_ownership(parent, child);
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
    size_t guard = 0;
    const size_t guard_limit = 16384;
    for (vfs_node_t *n = parent->first_child; n; n = n->next_sibling)
    {
        if (++guard > guard_limit)
        {
            serial_printf("[vfs] sibling loop detected parent=%s name=%s head=0x%016llX last=0x%016llX\r\n",
                          parent->name ? parent->name : "<noname>",
                          name,
                          (unsigned long long)(uintptr_t)parent->first_child,
                          (unsigned long long)(uintptr_t)n);
            break;
        }
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

/*
 * Pre-grow a file's backing buffer.
 *
 * This is a performance hint used to avoid repeated realloc growth when a
 * caller knows it will append/write a large amount of data.
 */
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
    mount->dirty_seq++;
    spinlock_unlock(&mount->dirty_lock);
}

static void vfs_touch_atime(vfs_node_t *node)
{
    if (!node)
    {
        return;
    }
    uint64_t now = vfs_now_seconds();
    vfs_mount_t *mount = NULL;
    bool mark_dirty = false;
    vfs_lock_node_data(node);
    if (node->atime != now)
    {
        node->atime = now;
        if (node->mount && node->mount->supports_times)
        {
            node->dirty = true;
            node->disk_meta_dirty = true;
            node->dirty_seq++;
            mount = node->mount;
            mark_dirty = true;
        }
    }
    vfs_unlock_node_data(node);
    if (mark_dirty && mount)
    {
        vfs_mark_mount_dirty(mount);
    }
}

static void vfs_mark_meta_dirty(vfs_node_t *node)
{
    if (!node)
    {
        return;
    }
    vfs_lock_node_data(node);
    uint64_t now = vfs_now_seconds();
    node->dirty = true;
    node->disk_meta_dirty = true;
    node->dirty_seq++;
    node->ctime = now;
    if (node->type == VFS_NODE_DIR)
    {
        node->mtime = now;
    }
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
    uint64_t now = vfs_now_seconds();
    node->dirty = true;
    node->disk_data_dirty = true;
    node->last_data_write_tick = timer_ticks();
    node->mtime = now;
    node->ctime = now;
    if (node->mount)
    {
        node->pending_dirty_bytes += len;
        mounted = true;
        mount = node->mount;
    }
    node->dirty_seq++;
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

static bool vfs_mount_flush_tree(vfs_mount_t *mount, bool force_all, bool force_sync)
{
    if (!mount || !mount->backend || !mount->mount_point)
    {
        return true;
    }
    bool ok = true;

    vfs_node_t **stack = NULL;
    size_t stack_count = 0;
    size_t stack_cap = 0;

    vfs_node_t **flush_nodes = NULL;
    size_t flush_count = 0;
    size_t flush_cap = 0;

    const size_t initial_cap = 64;
    stack = (vfs_node_t **)malloc(initial_cap * sizeof(*stack));
    flush_nodes = (vfs_node_t **)malloc(initial_cap * sizeof(*flush_nodes));
    if (!stack || !flush_nodes)
    {
        free(stack);
        free(flush_nodes);
        return false;
    }
    stack_cap = initial_cap;
    flush_cap = initial_cap;

    vfs_tree_lock_acquire();
    stack[stack_count++] = mount->mount_point;
    while (stack_count > 0)
    {
        vfs_node_t *node = stack[--stack_count];
        if (!node)
        {
            continue;
        }

        for (vfs_node_t *child = node->first_child; child; child = child->next_sibling)
        {
            if (stack_count == stack_cap)
            {
                size_t next_cap = (stack_cap < (SIZE_MAX / 2)) ? (stack_cap * 2) : 0;
                if (!next_cap)
                {
                    ok = false;
                    break;
                }
                vfs_node_t **resized = (vfs_node_t **)realloc(stack, next_cap * sizeof(*stack));
                if (!resized)
                {
                    ok = false;
                    break;
                }
                stack = resized;
                stack_cap = next_cap;
            }
            stack[stack_count++] = child;
        }
        if (!ok)
        {
            break;
        }

        if (node->mount != mount)
        {
            continue;
        }

        bool needs_flush = force_all;
        bool defer_active_write = false;
        if (!needs_flush)
        {
            vfs_lock_node_data(node);
            needs_flush = node->disk_meta_dirty || node->disk_data_dirty || node->disk_name_dirty;
            if (!needs_flush && node->disk_id == UINT32_MAX)
            {
                needs_flush = true;
            }
            if (!force_sync && needs_flush && node->disk_data_dirty &&
                node->pending_dirty_bytes < VFS_ACTIVE_WRITE_FLUSH_THRESHOLD &&
                node->last_data_write_tick != 0)
            {
                uint64_t freq = timer_frequency();
                if (freq == 0)
                {
                    freq = 1000;
                }
                uint64_t grace_ticks =
                    (VFS_ACTIVE_WRITE_GRACE_MS * freq + 999ULL) / 1000ULL;
                uint64_t now_ticks = timer_ticks();
                defer_active_write = now_ticks >= node->last_data_write_tick &&
                    now_ticks - node->last_data_write_tick < grace_ticks;
            }
            vfs_unlock_node_data(node);
        }

        if (defer_active_write)
        {
            /* Keep the mount dirty so flushd retries after the writer goes idle. */
            vfs_mark_mount_dirty(mount);
            continue;
        }

        if (!needs_flush)
        {
            continue;
        }

        if (flush_count == flush_cap)
        {
            size_t next_cap = (flush_cap < (SIZE_MAX / 2)) ? (flush_cap * 2) : 0;
            if (!next_cap)
            {
                ok = false;
                break;
            }
            vfs_node_t **resized = (vfs_node_t **)realloc(flush_nodes, next_cap * sizeof(*flush_nodes));
            if (!resized)
            {
                ok = false;
                break;
            }
            flush_nodes = resized;
            flush_cap = next_cap;
        }
        vfs_node_retain(node);
        flush_nodes[flush_count++] = node;
    }
    vfs_tree_lock_release();

    if (ok)
    {
        for (size_t i = 0; i < flush_count; ++i)
        {
            if (!alixfs_mount_flush_single(mount->backend, flush_nodes[i], mount, force_all))
            {
                ok = false;
                break;
            }
        }
    }

    for (size_t i = 0; i < flush_count; ++i)
    {
        vfs_node_release(flush_nodes[i]);
    }

    free(stack);
    free(flush_nodes);
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
    uint64_t start_ticks = timer_ticks();
    if (!vfs_sync_lock_acquire(mount))
    {
        return false;
    }
    /* Persist new directory ancestors first so a freshly downloaded file has
     * valid parent IDs on the next mount. Retain the chain across yielding IO. */
    size_t count = 0;
    size_t capacity = 16;
    vfs_node_t **chain = (vfs_node_t **)malloc(capacity * sizeof(*chain));
    if (!chain)
    {
        vfs_sync_lock_release(mount);
        return false;
    }
    vfs_tree_lock_acquire();
    for (vfs_node_t *parent = node; parent && parent->mount == mount; parent = parent->parent)
    {
        if (count == capacity)
        {
            if (capacity > SIZE_MAX / (2 * sizeof(*chain)))
            {
                ok = false;
                break;
            }
            capacity *= 2;
            vfs_node_t **resized = (vfs_node_t **)realloc(chain, capacity * sizeof(*chain));
            if (!resized)
            {
                ok = false;
                break;
            }
            chain = resized;
        }
        vfs_node_retain(parent);
        chain[count++] = parent;
    }
    vfs_tree_lock_release();
    for (size_t i = count; ok && i > 0; --i)
    {
        ok = alixfs_mount_flush_single(mount->backend, chain[i - 1], mount, false);
    }
    if (ok)
    {
        ok = alixfs_mount_commit(mount->backend);
    }
    if (ok)
    {
        ok = block_flush(mount->device);
    }
    for (size_t i = 0; i < count; ++i)
    {
        vfs_node_release(chain[i]);
    }
    free(chain);
    vfs_sync_lock_release(mount);

    if (vfs_logs_enabled())
    {
        serial_printf("[vfs] file_sync status=%s duration_ms=%llu",
                      ok ? "ok" : "fail",
                      (unsigned long long)vfs_ticks_to_ms(timer_ticks() - start_ticks));
    }

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
            /* Preserve oversized loaded nodes, but do not follow targets that
             * cannot be represented by the native path contract. */
            if (child->size >= VFS_PATH_MAX) return NULL;
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

/*
 * Initialise the in-memory VFS tree.
 *
 * Creates the root directory node and initialises the global tree lock. Must
 * be called before other VFS operations. Safe to call multiple times.
 */
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

    /* Common scratch directory for userland programs. Keep it heap-backed. */
    vfs_node_t *tmp = vfs_alloc_node(VFS_NODE_DIR);
    if (tmp)
    {
        tmp->name = vfs_strdup("tmp");
        if (tmp->name)
        {
            vfs_attach_child(root, tmp);
        }
        else
        {
            free(tmp);
        }
    }
}

/*
 * Return the VFS root node (`/`).
 *
 * The root node is created by `vfs_init()`.
 */
vfs_node_t *vfs_root(void)
{
    return root;
}

/*
 * Resolve a path to an existing node.
 *
 * - `cwd` is used only for relative paths; absolute paths resolve from `/`.
 * - Holds the global tree lock during traversal.
 * - Returns NULL if the path cannot be resolved.
 */
vfs_node_t *vfs_resolve(vfs_node_t *cwd, const char *path)
{
    vfs_tree_lock_acquire();
    vfs_node_t *res = resolve_node(cwd ? cwd : root, path);
    vfs_tree_lock_release();
    return res;
}

/*
 * Create (or return) a directory node at `path`.
 *
 * - Requires the parent directory to exist.
 * - Respects subtree mutability (see `vfs_set_subtree_mutable`).
 * - Returns NULL on failure or if the path exists but is not a directory.
 */
vfs_node_t *vfs_mkdir(vfs_node_t *cwd, const char *path)
{
    vfs_node_t *parent = NULL;
    char *name = NULL;

    vfs_tree_lock_acquire();

    if (!split_parent_and_name(cwd ? cwd : root, path, &parent, &name))
    {
        vfs_tree_lock_release();
        return NULL;
    }

    vfs_node_t *existing = vfs_find_child(parent, name);
    if (existing)
    {
        free(name);
        vfs_tree_lock_release();
        return (existing->type == VFS_NODE_DIR) ? existing : NULL;
    }

    if (!vfs_node_allows_mutation(parent))
    {
        free(name);
        vfs_tree_lock_release();
        return NULL;
    }

    vfs_node_t *dir = vfs_alloc_node(VFS_NODE_DIR);
    if (!dir)
    {
        free(name);
        vfs_tree_lock_release();
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
    vfs_tree_lock_release();
    return dir;
}

/*
 * Open a file node at `path`.
 *
 * - If `create` is true, the node is created if missing.
 * - If `truncate` is true and the node exists, its contents are cleared.
 * - Returns NULL on failure or if the existing node is not a file.
 */
static vfs_node_t *vfs_open_file_internal(vfs_node_t *cwd, const char *path, bool create, bool truncate,
                                           bool owned_data, bool pin_result, bool exclusive, uint32_t uid, uint32_t gid, int *error)
{
    if (error) *error = -EIO;
    vfs_node_t *parent = NULL;
    char *name = NULL;

    bool trace_proc = (path && strncmp(path, "/proc/devices", 13) == 0);

    vfs_tree_lock_acquire();

    if (!split_parent_and_name(cwd ? cwd : root, path, &parent, &name))
    {
        if (error) *error = -ENOENT;
        if (trace_proc)
        {
            serial_printf("%s", "[vfs] split failed ");
            serial_printf("%s", path ? path : "<null>");
            serial_printf("%s", "\r\n");
        }
        vfs_tree_lock_release();
        return NULL;
    }

    vfs_node_t *file = vfs_find_child(parent, name);
    if (file && create && exclusive)
    {
        free(name);
        if (error) *error = -EEXIST;
        vfs_tree_lock_release();
        return NULL;
    }
    if (!file)
    {
        if (!create)
        {
            if (error) *error = -ENOENT;
            if (trace_proc)
            {
                serial_printf("%s", "[vfs] missing child name=");
                serial_printf("%s", name ? name : "<null>");
                serial_printf("%s", " path=");
                serial_printf("%s", path ? path : "<null>");
                serial_printf("%s", "\r\n");
            }
            free(name);
            vfs_tree_lock_release();
            return NULL;
        }
        if (!vfs_node_allows_mutation(parent))
        {
            if (error) *error = -EROFS;
            free(name);
            vfs_tree_lock_release();
            return NULL;
        }
        file = vfs_alloc_node(VFS_NODE_FILE);
        if (!file)
        {
            if (error) *error = -ENOMEM;
            free(name);
            vfs_tree_lock_release();
            return NULL;
        }
        file->name   = name;   /* take ownership */
        file->size = 0;
        file->capacity = 0;
        file->data = NULL;
        vfs_inherit_mutability(parent, file);
        vfs_attach_child(parent, file);
        if (owned_data)
        {
            /* Caller credentials are explicit; never inherit service root. */
            file->uid = uid;
            file->gid = gid;
        }
        vfs_mark_meta_dirty(parent);
        vfs_mark_meta_dirty(file);
    }
    else
    {
        free(name);
    }

    if (file->type != VFS_NODE_FILE)
    {
        if (error) *error = file->type == VFS_NODE_DIR ? -EISDIR : -EINVAL;
        if (trace_proc)
        {
            serial_printf("%s", "[vfs] wrong type name=");
            serial_printf("%s", file->name ? file->name : "<noname>");
            serial_printf("%s", " type=");
            serial_printf("%016llX", (unsigned long long)file->type);
            serial_printf("%s", "\r\n");
        }
        vfs_tree_lock_release();
        return NULL;
    }

    if (pin_result)
    {
        /* Tree ownership prevents a concurrent unlink from freeing the node
         * before this external reference is acquired. Callback-backed nodes
         * need a separate lifetime/identity-aware adapter. */
        vfs_lock_node_data(file);
        int result = 0;
        if (owned_data && (file->read_cb || file->write_cb)) result = -ENOTSUP;
        else if (!file->refcount || file->refcount == (uint32_t)-1) result = -EOVERFLOW;
        else ++file->refcount;
        vfs_unlock_node_data(file);
        if (result)
        {
            if (error) *error = result;
            vfs_tree_lock_release();
            return NULL;
        }
    }

    if (truncate)
    {
        if (!owned_data && !vfs_node_allows_mutation(file))
        {
            if (error) *error = -EROFS;
            if (pin_result) vfs_node_release(file);
            vfs_tree_lock_release();
            return NULL;
        }
        vfs_lock_node_data(file);
        if (owned_data && ((file->read_cb || file->write_cb) || !vfs_node_allows_mutation(file)))
        {
            if (error) *error = (file->read_cb || file->write_cb) ? -ENOTSUP : -EROFS;
            vfs_unlock_node_data(file);
            vfs_node_release(file);
            vfs_tree_lock_release();
            return NULL;
        }
        file->size = 0;
        bool ok_trunc = ensure_capacity_locked(file, 0);
        if (!ok_trunc)
        {
            if (error) *error = -ENOMEM;
            vfs_unlock_node_data(file);
            if (pin_result) vfs_node_release(file);
            if (trace_proc)
            {
                serial_printf("%s", "[vfs] ensure_capacity failed ");
                serial_printf("%s", file->name ? file->name : "<noname>");
                serial_printf("%s", "\r\n");
            }
            vfs_tree_lock_release();
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
    if (error) *error = 0;
    vfs_tree_lock_release();
    return file;
}

vfs_node_t *vfs_open_file(vfs_node_t *cwd, const char *path, bool create, bool truncate)
{
    return vfs_open_file_internal(cwd, path, create, truncate, false, false, false, 0, 0, NULL);
}

int vfs_open_data_owned(vfs_node_t *cwd, const char *path, bool create, bool truncate,
                        uint32_t uid, uint32_t gid, vfs_node_t **out)
{
    if (!out) return -EINVAL;
    *out = NULL;
    if (!cwd || !path || !path[0]) return -EINVAL;
    if (!vfs_is_dir(cwd)) return -ENOTDIR;
    int error = -EIO;
    *out = vfs_open_file_internal(cwd, path, create, truncate, true, true, false, uid, gid, &error);
    return *out ? 0 : error;
}

int vfs_open_data_flags_owned(vfs_node_t *cwd, const char *path, bool create, bool truncate,
                              bool exclusive, uint32_t uid, uint32_t gid, vfs_node_t **out)
{
    if (!out || !cwd || !path || !*path) return -EINVAL;
    int error;
    *out = vfs_open_file_internal(cwd, path, create, truncate, true, true, exclusive, uid, gid, &error);
    return *out ? 0 : error;
}

int vfs_open_legacy_handle(vfs_node_t *cwd, const char *path, bool create, bool truncate,
                            bool exclusive, vfs_node_t **out)
{
    if (!out || !path || !*path) return -EINVAL;
    int error;
    *out = vfs_open_file_internal(cwd, path, create, truncate, false, true, exclusive, 0, 0, &error);
    return *out ? 0 : error;
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

    size_t target_length = 0, path_length = 0;
    while (target_length < VFS_PATH_MAX && target_path[target_length]) ++target_length;
    while (path_length < VFS_PATH_MAX && link_path[path_length]) ++path_length;
    if (target_length == VFS_PATH_MAX || path_length == VFS_PATH_MAX) return NULL;

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

/*
 * Create a symlink node at `link_path` pointing to `target_path`.
 *
 * Returns the symlink node on success; returns NULL if the path exists as a
 * non-symlink (unless `vfs_force_symlink` is used).
 */
vfs_node_t *vfs_symlink(vfs_node_t *cwd, const char *target_path, const char *link_path)
{
    vfs_tree_lock_acquire();
    vfs_node_t *node = vfs_symlink_locked(cwd, target_path, link_path, false);
    vfs_tree_lock_release();
    return node;
}

/*
 * Create or replace `link_path` with a symlink to `target_path`.
 *
 * Unlike `vfs_symlink`, this will remove an existing node at `link_path`
 * (except mount points) before creating the symlink.
 */
bool vfs_force_symlink(vfs_node_t *cwd, const char *target_path, const char *link_path)
{
    vfs_tree_lock_acquire();
    vfs_node_t *node = vfs_symlink_locked(cwd, target_path, link_path, true);
    vfs_tree_lock_release();
    return node != NULL;
}

/* Simple type predicates for callers that want to avoid peeking at internals. */
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

/*
 * Return the backing block device for a `VFS_NODE_BLOCK`.
 */
block_device_t *vfs_block_device(const vfs_node_t *node)
{
    if (!node || node->type != VFS_NODE_BLOCK)
    {
        return NULL;
    }
    return node->block_device;
}

/*
 * Return the node type (dir/file/block/symlink).
 */
vfs_node_type_t vfs_node_type(const vfs_node_t *node)
{
    return node ? node->type : VFS_NODE_FILE;
}

/*
 * For symlink nodes, return their target path string.
 */
const char *vfs_symlink_target(const vfs_node_t *node)
{
    return vfs_node_symlink_target(node);
}

/*
 * Truncate a regular file node to size 0.
 *
 * This updates dirty tracking so mounts will write the change back if the node
 * is backed by a block device.
 */
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

/*
 * Append bytes to a regular file.
 *
 * - When `file->mount` is non-NULL, this may apply writeback backpressure to
 *   keep dirty bytes bounded.
 * - Always ensures the file buffer is NUL-terminated for convenience/debug.
 */
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

/*
 * Read bytes from a regular file at an explicit offset.
 *
 * If the node has `read_cb`, the callback provides the implementation (used
 * for procfs/devfs pseudo-files). Otherwise this reads from the heap-backed
 * `file->data` buffer.
 */
static ssize_t vfs_read_at_internal(vfs_node_t *file, size_t offset, void *buffer, size_t count, bool callbacks)
{
    vfs_log("read file=", (uint64_t)(uintptr_t)file);
    vfs_log("read off=", offset);
    vfs_log("read cnt=", count);
    if (!file || file->type != VFS_NODE_FILE || !buffer)
    {
        return -1;
    }

    if (callbacks && file->read_cb)
    {
        ssize_t read_bytes = file->read_cb(file, offset, buffer, count, file->callback_context);
        if (read_bytes > 0)
        {
            vfs_touch_atime(file);
        }
        return read_bytes;
    }

    vfs_lock_node_data(file);
    if (!callbacks && (file->read_cb || file->write_cb))
    {
        vfs_unlock_node_data(file);
        return -ENOTSUP;
    }
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
    if (count > 0)
    {
        vfs_touch_atime(file);
    }
    return (ssize_t)count;
}

ssize_t vfs_read_at(vfs_node_t *file, size_t offset, void *buffer, size_t count)
{
    return vfs_read_at_internal(file, offset, buffer, count, true);
}

ssize_t vfs_read_data_at(vfs_node_t *file, size_t offset, void *buffer, size_t count)
{
    return vfs_read_at_internal(file, offset, buffer, count, false);
}


/*
 * Write bytes to a regular file at an explicit offset.
 *
 * If the node has `write_cb`, the callback provides the implementation (used
 * for procfs/devfs control files). Otherwise this writes into the heap-backed
 * `file->data` buffer and grows the file as needed.
 */
static ssize_t vfs_write_at_internal(vfs_node_t *file, size_t offset, const void *data, size_t count, bool callbacks, bool append, size_t *position)
{
    vfs_log("write file=", (uint64_t)(uintptr_t)file);
    vfs_log("write off=", offset);
    vfs_log("write cnt=", count);
    if (!file || file->type != VFS_NODE_FILE)
    {
        return -1;
    }
    if (callbacks && !vfs_node_allows_mutation(file))
    {
        return -1;
    }

    if (callbacks && file->write_cb)
    {
        ssize_t result = file->write_cb(file, offset, data, count, file->callback_context);
        if (result > 0 && position) *position = offset + (size_t)result;
        return result;
    }

    if (count > 0 && !data)
    {
        return -1;
    }
    if (count == 0)
    {
        return 0;
    }
    if (file->mount)
    {
        vfs_backpressure_wait(file->mount, count);
    }
    vfs_lock_node_data(file);
    if (!callbacks && (file->read_cb || file->write_cb))
    {
        vfs_unlock_node_data(file);
        return -ENOTSUP;
    }
    if (!callbacks && !vfs_node_allows_mutation(file))
    {
        vfs_unlock_node_data(file);
        return -EROFS;
    }
    if (append) offset = file->size;
    if (count > (size_t)INT64_MAX || offset > (size_t)INT64_MAX - count)
    {
        vfs_unlock_node_data(file);
        return -EFBIG;
    }
    size_t end = offset + count;
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
    if (position) *position = end;
    vfs_unlock_node_data(file);
    vfs_note_file_dirty(file, offset, count, size_changed);
    return (ssize_t)count;
}

ssize_t vfs_write_at(vfs_node_t *file, size_t offset, const void *data, size_t count)
{
    return vfs_write_at_internal(file, offset, data, count, true, false, NULL);
}

ssize_t vfs_write_data_at(vfs_node_t *file, size_t offset, const void *data, size_t count)
{
    return vfs_write_at_internal(file, offset, data, count, false, false, NULL);
}

ssize_t vfs_write_append(vfs_node_t *file, const void *data, size_t count,
                         bool callbacks, size_t *position)
{
    if (!position) return -EINVAL;
    return vfs_write_at_internal(file, *position, data, count, callbacks, true, position);
}


/*
 * Convert a regular file into a callback-backed file node.
 *
 * When callbacks are installed, `vfs_read_at`/`vfs_write_at` will delegate to
 * them instead of the heap-backed data buffer.
 */
bool vfs_set_file_callbacks(vfs_node_t *file,
                            vfs_read_cb_t read_cb,
                            vfs_write_cb_t write_cb,
                            void *context)
{
    if (!file || file->type != VFS_NODE_FILE)
    {
        return false;
    }
    vfs_lock_node_data(file);
    file->read_cb = read_cb;
    file->write_cb = write_cb;
    file->callback_context = context;
    vfs_unlock_node_data(file);
    return true;
}

/*
 * Return a pointer to a file's backing buffer.
 *
 * This is a convenience API primarily used for read-mostly consumers and small
 * configuration files. The returned pointer aliases the internal storage and
 * may be invalidated by future writes/resizes.
 */
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
    vfs_touch_atime(file);
    return data;
}

/*
 * Fetch basic node metadata (size and type).
 */
bool vfs_stat(const vfs_node_t *node,
              size_t *size_out,
              vfs_node_type_t *type_out,
              uint64_t *atime_out,
              uint64_t *mtime_out,
              uint64_t *ctime_out)
{
    if (!node)
    {
        return false;
    }
    vfs_node_t *mutable_node = (vfs_node_t *)node;
    vfs_lock_node_data(mutable_node);
    if (size_out)
    {
        *size_out = mutable_node->size;
    }
    if (type_out)
    {
        *type_out = mutable_node->type;
    }
    if (atime_out)
    {
        *atime_out = mutable_node->atime;
    }
    if (mtime_out)
    {
        *mtime_out = mutable_node->mtime;
    }
    if (ctime_out)
    {
        *ctime_out = mutable_node->ctime;
    }
    vfs_unlock_node_data(mutable_node);
    return true;
}

/*
 * Return the node's name component (not a full path).
 */
const char *vfs_name(const vfs_node_t *node)
{
    return node ? node->name : NULL;
}

/*
 * Return the parent directory of `node` (or NULL for root/invalid nodes).
 */
vfs_node_t *vfs_parent(const vfs_node_t *node)
{
    return node ? node->parent : NULL;
}

/*
 * Build the absolute path for a node into `buffer`.
 *
 * This walks the parent chain up to `/` and writes a slash-separated path.
 * Returns the number of bytes written (excluding any implicit NUL).
 */
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

/*
 * Remove a file or symlink node at `path`.
 *
 * - Only removes `VFS_NODE_FILE` and `VFS_NODE_SYMLINK` nodes.
 * - Respects subtree mutability on the parent directory.
 * - Does not remove directories or mount points.
 */
int vfs_remove_path(vfs_node_t *cwd, const char *path, bool allow_directory)
{
    if (!path || !*path) return -ENOENT;
    vfs_tree_lock_acquire();
    vfs_node_t *parent = NULL;
    char *name = NULL;
    int error = -ENOENT;
    if (split_parent_and_name(cwd ? cwd : root, path, &parent, &name))
    {
        vfs_node_t *node = vfs_find_child(parent, name);
        if (!node) error = -ENOENT;
        else if (node->mount && node->mount->mount_point == node) error = -EBUSY;
        else if (!vfs_node_allows_mutation(parent)) error = -EROFS;
        else if (node->type == VFS_NODE_BLOCK || node->read_cb || node->write_cb) error = -ENOTSUP;
        else if (node->type == VFS_NODE_DIR && !allow_directory) error = -EISDIR;
        else if (node->type == VFS_NODE_DIR && node->first_child) error = -ENOTEMPTY;
        else
        {
            /* Open descriptions retain their own reference. Removing the tree
             * reference cannot reclaim data while an open stream still uses it. */
            vfs_detach_child(node);
            vfs_node_release(node);
            vfs_mark_meta_dirty(parent);
            error = 0;
        }
    }
    free(name);
    vfs_tree_lock_release();
    return error;
}

int vfs_rename_path(vfs_node_t *cwd, const char *old_path, const char *new_path)
{
    if (!old_path || !new_path || !*old_path || !*new_path) return -ENOENT;
    vfs_tree_lock_acquire();
    vfs_node_t *old_parent = NULL, *new_parent = NULL;
    char *old_name = NULL, *new_name = NULL;
    int error = -ENOENT;
    if (!split_parent_and_name(cwd ? cwd : root, old_path, &old_parent, &old_name) ||
        !split_parent_and_name(cwd ? cwd : root, new_path, &new_parent, &new_name)) goto done;
    vfs_node_t *node = vfs_find_child(old_parent, old_name);
    vfs_node_t *target = vfs_find_child(new_parent, new_name);
    if (!node) goto done;
    if (target == node) { error = 0; goto done; }
    if (old_parent->mount != new_parent->mount) { error = -EXDEV; goto done; }
    if ((node->mount && node->mount->mount_point == node) ||
        (target && target->mount && target->mount->mount_point == target)) { error = -EBUSY; goto done; }
    if (!vfs_node_allows_mutation(old_parent) || !vfs_node_allows_mutation(new_parent))
    { error = -EROFS; goto done; }
    if (node->type == VFS_NODE_BLOCK || node->read_cb || node->write_cb ||
        (target && (target->type == VFS_NODE_BLOCK || target->read_cb || target->write_cb)))
    { error = -ENOTSUP; goto done; }
    if (target && (node->type == VFS_NODE_DIR) != (target->type == VFS_NODE_DIR))
    { error = node->type == VFS_NODE_DIR ? -ENOTDIR : -EISDIR; goto done; }
    if (target && target->first_child) { error = -ENOTEMPTY; goto done; }
    for (vfs_node_t *ancestor = new_parent; ancestor; ancestor = ancestor->parent)
        if (ancestor == node) { error = -EINVAL; goto done; }
    if (target)
    {
        vfs_detach_child(target);
        vfs_node_release(target);
    }
    uint32_t uid = node->uid, gid = node->gid;
    vfs_detach_child(node);
    free(node->name);
    node->name = new_name;
    new_name = NULL;
    vfs_attach_child(new_parent, node);
    node->uid = uid;
    node->gid = gid;
    node->disk_name_dirty = true;
    vfs_mark_meta_dirty(old_parent);
    vfs_mark_meta_dirty(new_parent);
    vfs_mark_meta_dirty(node);
    if (node->mount)
    {
        spinlock_lock(&node->mount->dirty_lock);
        node->mount->needs_full_sync = true;
        spinlock_unlock(&node->mount->dirty_lock);
    }
    error = 0;
done:
    free(old_name);
    free(new_name);
    vfs_tree_lock_release();
    return error;
}

bool vfs_remove_file(vfs_node_t *cwd, const char *path)
{
    if (!path || *path == '\0')
    {
        return false;
    }

    vfs_tree_lock_acquire();

    vfs_node_t *parent = NULL;
    char *name = NULL;
    if (!split_parent_and_name(cwd ? cwd : root, path, &parent, &name))
    {
        vfs_tree_lock_release();
        return false;
    }
    if (!parent)
    {
        free(name);
        vfs_tree_lock_release();
        return false;
    }

    vfs_node_t *node = vfs_find_child(parent, name);
    free(name);
    if (!node || (node->type != VFS_NODE_FILE && node->type != VFS_NODE_SYMLINK))
    {
        vfs_tree_lock_release();
        return false;
    }

    if (!vfs_node_allows_mutation(parent))
    {
        vfs_tree_lock_release();
        return false;
    }

    vfs_detach_child(node);
    vfs_node_release(node);

    vfs_mark_meta_dirty(parent);
    vfs_tree_lock_release();
    return true;
}

/*
 * Remove a file, symlink, or directory subtree at `path`.
 *
 * - Directories are removed recursively (children released).
 * - Refuses to remove mount points.
 * - Respects subtree mutability on the parent and target directory.
 */
bool vfs_remove_tree(vfs_node_t *cwd, const char *path)
{
    if (!path || *path == '\0')
    {
        return false;
    }

    vfs_tree_lock_acquire();

    vfs_node_t *parent = NULL;
    char *name = NULL;
    if (!split_parent_and_name(cwd ? cwd : root, path, &parent, &name))
    {
        vfs_tree_lock_release();
        return false;
    }
    if (!parent)
    {
        free(name);
        vfs_tree_lock_release();
        return false;
    }

    vfs_node_t *node = vfs_find_child(parent, name);
    free(name);
    if (!node)
    {
        vfs_tree_lock_release();
        return false;
    }

    if (!vfs_node_allows_mutation(parent))
    {
        vfs_tree_lock_release();
        return false;
    }

    if (node->type == VFS_NODE_DIR)
    {
        if (vfs_is_mount_point(node))
        {
            vfs_tree_lock_release();
            return false;
        }
        if (!vfs_node_allows_mutation(node))
        {
            vfs_tree_lock_release();
            return false;
        }
        vfs_clear_directory(node);
    }
    else if (node->type != VFS_NODE_FILE && node->type != VFS_NODE_SYMLINK)
    {
        vfs_tree_lock_release();
        return false;
    }

    vfs_detach_child(node);
    vfs_node_release(node);
    vfs_mark_meta_dirty(parent);
    vfs_tree_lock_release();
    return true;
}

/*
 * Return the first child of a directory (or NULL).
 *
 * Note: this is a raw pointer into the tree; callers should avoid mutating the
 * tree concurrently without holding the VFS tree lock.
 */
vfs_node_t *vfs_first_child(vfs_node_t *dir)
{
    if (!dir || dir->type != VFS_NODE_DIR) return NULL;
    return dir->first_child;
}

/*
 * Return the next sibling in a directory's child list.
 */
vfs_node_t *vfs_next_sibling(vfs_node_t *node)
{
    return node ? node->next_sibling : NULL;
}

void vfs_node_get_owner(const vfs_node_t *node, uint32_t *uid_out, uint32_t *gid_out)
{
    if (!node)
    {
        if (uid_out)
        {
            *uid_out = VFS_UID_ROOT;
        }
        if (gid_out)
        {
            *gid_out = VFS_GID_ROOT;
        }
        return;
    }
    vfs_node_t *mutable_node = (vfs_node_t *)node;
    vfs_lock_node_data(mutable_node);
    if (uid_out)
    {
        *uid_out = mutable_node->uid;
    }
    if (gid_out)
    {
        *gid_out = mutable_node->gid;
    }
    vfs_unlock_node_data(mutable_node);
}

void vfs_node_set_owner(vfs_node_t *node, uint32_t uid, uint32_t gid)
{
    if (!node)
    {
        return;
    }
    bool changed = false;
    vfs_lock_node_data(node);
    if (node->uid != uid || node->gid != gid)
    {
        node->uid = uid;
        node->gid = gid;
        changed = true;
    }
    vfs_unlock_node_data(node);
    if (changed)
    {
        vfs_mark_meta_dirty(node);
    }
}

/*
 * Enumerate directory children under the VFS tree lock.
 *
 * Stops early if `callback` returns false. Returns the number of children
 * visited.
 */
size_t vfs_enum_children(vfs_node_t *dir, vfs_enum_cb_t callback, void *context)
{
    if (!dir || dir->type != VFS_NODE_DIR || !callback)
    {
        return 0;
    }

    size_t count = 0;
    vfs_tree_lock_acquire();
    for (vfs_node_t *child = dir->first_child; child; child = child->next_sibling)
    {
        ++count;
        if (!callback(child, context))
        {
            break;
        }
    }
    vfs_tree_lock_release();
    return count;
}

/*
 * Add a block device node under `dir`.
 *
 * This is used by devfs to expose block devices (e.g. `/dev/ahci0`) as
 * `VFS_NODE_BLOCK` nodes that carry a `block_device_t*`.
 */
vfs_node_t *vfs_add_block_device(vfs_node_t *dir, const char *name, block_device_t *device)
{
    if (!dir || dir->type != VFS_NODE_DIR || !name || !device)
    {
        return NULL;
    }

    vfs_tree_lock_acquire();

    vfs_node_t *existing = vfs_find_child(dir, name);
    if (existing)
    {
        if (existing->type == VFS_NODE_BLOCK)
        {
            existing->block_device = device;
            vfs_tree_lock_release();
            return existing;
        }
        vfs_tree_lock_release();
        return NULL;
    }

    if (!vfs_node_allows_mutation(dir))
    {
        vfs_tree_lock_release();
        return NULL;
    }

    vfs_node_t *node = vfs_alloc_node(VFS_NODE_BLOCK);
    if (!node)
    {
        vfs_tree_lock_release();
        return NULL;
    }

    node->name = vfs_strdup(name);
    if (!node->name)
    {
        free(node);
        vfs_tree_lock_release();
        return NULL;
    }
    node->block_device = device;
    node->size = 0;
    node->capacity = 0;
    node->data = NULL;

    vfs_attach_child_tail(dir, node);
    vfs_mark_meta_dirty(dir);
    vfs_tree_lock_release();
    return node;
}

/*
 * Remove all children from a directory.
 *
 * - Does not remove the directory node itself.
 * - Respects subtree mutability.
 * - Releases references for removed children (they are freed when refcount hits zero).
 */
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

/*
 * Format a block device with the default on-disk filesystem (AlixFS2).
 *
 * This will fail if the device is currently mounted.
 */
bool vfs_format(block_device_t *device)
{
    if (!device)
    {
        return false;
    }

    vfs_tree_lock_acquire();
    bool mounted = vfs_device_is_mounted(device);
    vfs_tree_lock_release();
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
    bool force_all = false;
    size_t pending_bytes = 0;
    uint64_t start_seq = 0;
    const char *dev_name = (mount->device && mount->device->name[0]) ? mount->device->name : "(anon)";

    spinlock_lock(&mount->dirty_lock);
    if (mount->dirty || mount->needs_full_sync || force)
    {
        do_flush = true;
        force_all = mount->needs_full_sync;
        pending_bytes = mount->dirty_bytes;
        start_seq = mount->dirty_seq;
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
    if (!vfs_sync_lock_acquire(mount))
    {
        return false;
    }
    bool ok = vfs_mount_flush_tree(mount, force_all, force);
    if (ok && mount->backend)
    {
        ok = alixfs_mount_commit(mount->backend);
    }
    if (ok && force && mount->device)
    {
        ok = block_flush(mount->device);
    }
    vfs_sync_lock_release(mount);

    if (!ok)
    {
        vfs_mark_mount_dirty(mount);
        spinlock_lock(&mount->dirty_lock);
        mount->needs_full_sync = true;
        spinlock_unlock(&mount->dirty_lock);
        vfs_log_sync_result(dev_name, "fail", start, pending_bytes);
        return false;
    }

    spinlock_lock(&mount->dirty_lock);
    mount->needs_full_sync = false;
    if (mount->dirty_seq == start_seq)
    {
        mount->dirty_bytes = 0;
        mount->dirty = false;
    }
    spinlock_unlock(&mount->dirty_lock);

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

/*
 * Mount a block device filesystem at an existing directory node.
 *
 * Mount points must be empty directories with no existing mount. The mount
 * backend is currently AlixFS2 (`src/kernel/alixfs.c`).
 */
bool vfs_mount_device(block_device_t *device, vfs_node_t *mount_point)
{
    if (!device || !mount_point || mount_point->type != VFS_NODE_DIR)
    {
        return false;
    }

    vfs_tree_lock_acquire();

    if (vfs_is_mount_point(mount_point) ||
        mount_point->first_child ||
        mount_point->mount ||
        vfs_device_is_mounted(device))
    {
        vfs_tree_lock_release();
        return false;
    }

    vfs_mount_t *mount = (vfs_mount_t *)calloc(1, sizeof(vfs_mount_t));
    if (!mount)
    {
        vfs_tree_lock_release();
        return false;
    }

    mount->device = device;
    mount->mount_point = mount_point;
    mount->dirty_bytes_limit = VFS_DIRTY_BACKPRESSURE_LIMIT;
    spinlock_init(&mount->dirty_lock);
    wait_queue_init(&mount->sync_lock.waiters);
    mount->sync_lock.locked = false;
    mount->sync_owner_pid = 0;
    mount->sync_owner_cpu = UINT32_MAX;
    mount->sync_owner_ticks = 0;
    mount->backend = alixfs_mount_create(device);
    if (!mount->backend)
    {
        free(mount);
        vfs_tree_lock_release();
        return false;
    }

    mount_point->mount = mount;

    if (!vfs_load_mount(device, mount))
    {
        vfs_clear_directory(mount_point);
        mount_point->mount = NULL;
        alixfs_mount_destroy(mount->backend);
        free(mount);
        vfs_tree_lock_release();
        return false;
    }
    mount->supports_times = alixfs_mount_supports_times(mount->backend);

    mount->next = mounts;
    mounts = mount;
    vfs_tree_lock_release();
    return true;
}

/*
 * Test whether a node is the root of a mounted filesystem.
 */
bool vfs_is_mount_point(const vfs_node_t *node)
{
    if (!node || node->type != VFS_NODE_DIR)
    {
        return false;
    }
    vfs_mount_t *mount = node->mount;
    return mount && mount->mount_point == node;
}

/*
 * Flush *all* mounts (force writeback).
 *
 * This walks the mount list and writes dirty metadata and file data to the
 * block device backends.
 */
bool vfs_sync_all(void)
{
    bool ok = true;
    vfs_tree_lock_acquire();
    vfs_mount_t *head = mounts;
    vfs_tree_lock_release();

    for (vfs_mount_t *mount = head; mount; mount = mount->next)
    {
        if (!vfs_mount_writeback(mount, true))
        {
            ok = false;
        }
    }
    return ok;
}

/*
 * Flush only mounts that are currently dirty.
 *
 * Returns false if any mount writeback fails (other mounts may still succeed).
 */
bool vfs_sync_dirty(void)
{
    bool ok = true;
    vfs_tree_lock_acquire();
    vfs_mount_t *head = mounts;
    vfs_tree_lock_release();

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

/*
 * Flush a single node if it belongs to a mount.
 *
 * For non-mounted nodes this is effectively a no-op that returns true.
 */
bool vfs_flush_node(vfs_node_t *node)
{
    return vfs_mount_sync_node(node);
}

/*
 * Enable/disable mutations (create/remove/write) within a subtree.
 *
 * This is used to lock large parts of the tree read-only while leaving dynamic
 * areas like `/proc` and `/dev` mutable.
 */
void vfs_set_subtree_mutable(vfs_node_t *node, bool allow)
{
    vfs_tree_lock_acquire();
    vfs_set_subtree_mutable_locked(node ? node : root, allow);
    vfs_tree_lock_release();
}

/*
 * Snapshot current mount list state.
 *
 * Fills up to `max` entries in `out` (if non-NULL) and returns the total number
 * of mounts present.
 */
size_t vfs_snapshot_mounts(vfs_mount_info_t *out, size_t max)
{
    size_t count = 0;
    vfs_tree_lock_acquire();
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
    vfs_tree_lock_release();
    return count;
}


/* Caller owns the tree lock. Keep path expansion on the heap and return a
 * borrowed node only to the lock-holding snapshot operation below. */
static vfs_node_t *vfs_readlink_resolve_locked(vfs_node_t *cwd, const char *path, bool follow_final, int *error)
{
    char *walk = vfs_strdup(path);
    if (!walk) { *error = -ENOMEM; return NULL; }
    vfs_node_t *node = walk[0] == '/' ? root : cwd;
    const char *cursor = skip_separators(walk);
    unsigned links = 0;
    while (*cursor)
    {
        if (!node || node->type != VFS_NODE_DIR) { *error = -ENOTDIR; goto failed; }
        char *component = NULL;
        if (!next_component(&cursor, &component)) { *error = -ENOMEM; goto failed; }
        if (is_dot(component) || is_dot_dot(component))
        {
            if (is_dot_dot(component) && node->parent) node = node->parent;
            free(component);
            cursor = skip_separators(cursor);
            continue;
        }
        vfs_node_t *child = vfs_find_child(node, component);
        free(component);
        if (!child) { *error = -ENOENT; goto failed; }
        /* A separator requires traversal, even when only a trailing slash
         * remains. A final symlink with no separator is never followed. */
        if (child->type == VFS_NODE_SYMLINK && (*cursor || follow_final))
        {
            if (++links > VFS_MAX_SYMLINK_DEPTH) { *error = -ELOOP; goto failed; }
            if (child->size >= VFS_PATH_MAX) { *error = -ENAMETOOLONG; goto failed; }
            const char *target = vfs_node_symlink_target(child);
            if (!target || !target[0]) { *error = -ENOENT; goto failed; }
            size_t target_length = strlen(target), remainder = strlen(cursor);
            if (target_length >= 4096u || remainder >= 4096u - target_length)
            { *error = -ENAMETOOLONG; goto failed; }
            char *expanded = malloc(target_length + remainder + 1);
            if (!expanded) { *error = -ENOMEM; goto failed; }
            memcpy(expanded, target, target_length);
            memcpy(expanded + target_length, cursor, remainder + 1);
            node = target[0] == '/' ? root : node;
            free(walk);
            walk = expanded;
            cursor = skip_separators(walk);
            continue;
        }
        bool separator = *cursor != 0;
        node = child;
        cursor = skip_separators(cursor);
        if (separator && !*cursor && node->type != VFS_NODE_DIR)
        { *error = -ENOTDIR; goto failed; }
    }
    free(walk);
    *error = 0;
    return node;
failed:
    free(walk);
    return NULL;
}

ssize_t vfs_readlink_snapshot(vfs_node_t *cwd, const char *path, void *buffer,
                              size_t capacity, uint32_t uid, uint32_t gid)
{
    /* VFS currently has subtree mutability, but no Unix mode/ACL lookup
     * enforcement. Keep caller credentials explicit for that policy boundary;
     * never derive caller authority from the protected worker's identity. */
    (void)uid;
    (void)gid;
    if (!cwd || !path || !buffer || !capacity || capacity > 0x7fffffffffffffffULL) return -EINVAL;
    if (!vfs_is_dir(cwd)) return -ENOTDIR;
    size_t length = 0;
    while (length < 4096u && path[length]) ++length;
    if (!length) return -ENOENT;
    if (length == 4096u) return -ENAMETOOLONG;
    vfs_tree_lock_acquire();
    int error = 0;
    vfs_node_t *node = vfs_readlink_resolve_locked(cwd, path, false, &error);
    if (!node || node->type != VFS_NODE_SYMLINK)
    {
        vfs_tree_lock_release();
        return node ? -EINVAL : error;
    }
    vfs_lock_node_data(node);
    if (node->size >= VFS_PATH_MAX)
    {
        vfs_unlock_node_data(node);
        vfs_tree_lock_release();
        return -ENAMETOOLONG;
    }
    size_t bytes = node->size < capacity ? node->size : capacity;
    if (bytes && !node->data)
    {
        vfs_unlock_node_data(node);
        vfs_tree_lock_release();
        return -EIO;
    }
    if (bytes) memmove(buffer, node->data, bytes);
    vfs_unlock_node_data(node);
    vfs_tree_lock_release();
    return (ssize_t)bytes;
}

ssize_t vfs_path_snapshot(vfs_node_t *directory, char *buffer, size_t capacity)
{
    if (!directory || !buffer || !capacity || capacity > VFS_PATH_MAX) return -EINVAL;
    if (!vfs_is_dir(directory)) return -ENOTDIR;
    vfs_tree_lock_acquire();
    size_t position = capacity - 1;
    buffer[position] = 0;
    vfs_node_t *current = directory;
    int error = 0;
    while (current && current != root)
    {
        if (!current->parent) { error = -ENOENT; break; }
        const char *name = current->name;
        size_t length = 0;
        while (name && length < VFS_PATH_MAX && name[length]) ++length;
        if (!length) { error = -ENOENT; break; }
        if (length == VFS_PATH_MAX) { error = -ENAMETOOLONG; break; }
        if (length >= position) { error = -ERANGE; break; }
        position -= length;
        memcpy(buffer + position, name, length);
        buffer[--position] = '/';
        current = current->parent;
    }
    if (!error && current != root) error = -ENOENT;
    if (!error && directory == root)
    {
        if (!position) error = -ERANGE;
        else buffer[--position] = '/';
    }
    size_t length = capacity - position - 1;
    if (!error) memmove(buffer, buffer + position, length + 1);
    vfs_tree_lock_release();
    return error ? error : (ssize_t)length;
}

int vfs_path_stat_snapshot(vfs_node_t *cwd, const char *path, bool follow_final,
                            uint32_t uid, uint32_t gid, vfs_stat_snapshot_t *output)
{
    /* Unix lookup-mode/ACL enforcement does not yet exist in the VFS. Keep
     * the captured caller identity explicit, independent of a worker's uid. */
    (void)uid; (void)gid;
    if (!cwd || !path || !output) return -EINVAL;
    if (!vfs_is_dir(cwd)) return -ENOTDIR;
    size_t length = 0;
    while (length < VFS_PATH_MAX && path[length]) ++length;
    if (!length) return -ENOENT;
    if (length == VFS_PATH_MAX) return -ENAMETOOLONG;
    vfs_tree_lock_acquire();
    int error = 0;
    vfs_node_t *node = vfs_readlink_resolve_locked(cwd, path, follow_final, &error);
    if (node)
    {
        size_t size = 0;
        vfs_node_type_t type;
        if (!vfs_stat(node, &size, &type, &output->atime, &output->mtime, &output->ctime)) error = -EIO;
        else
        {
            output->size_bytes = size;
            output->type = type;
        }
    }
    vfs_tree_lock_release();
    return node ? error : error ? error : -ENOENT;
}

bool vfs_node_try_retain(vfs_node_t *node)
{
    if (!node) return false;
    vfs_lock_node_data(node);
    bool ok = node->refcount && node->refcount != (uint32_t)-1;
    if (ok) ++node->refcount;
    vfs_unlock_node_data(node);
    return ok;
}

int vfs_resolve_owned(vfs_node_t *cwd, const char *path, vfs_node_t **out)
{
    if (!out) return -EINVAL;
    *out = NULL;
    if (!cwd || !path) return -EINVAL;
    if (!vfs_is_dir(cwd)) return -ENOTDIR;
    size_t length = 0;
    while (length < 4096u && path[length]) ++length;
    if (!length) return -ENOENT;
    if (length == 4096u) return -ENAMETOOLONG;
    vfs_tree_lock_acquire();
    int error = 0;
    vfs_node_t *node = vfs_readlink_resolve_locked(cwd, path, true, &error);
    if (node && !vfs_node_try_retain(node)) { node = NULL; error = -EOVERFLOW; }
    *out = node;
    vfs_tree_lock_release();
    return node ? 0 : error;
}


#if defined(IO_VFS_SELFTEST) && IO_VFS_SELFTEST
/* Boot-only acceptance deliberately blocks real worker path resolution. */
void vfs_selftest_lock_tree(void) { vfs_tree_lock_acquire(); }
void vfs_selftest_unlock_tree(void) { vfs_tree_lock_release(); }
#endif

static uint64_t g_vfs_next_object_id = 1;

static uint64_t vfs_directory_object_id_locked(vfs_node_t *node)
{
    if (node->object_id) return node->object_id;
    if (!g_vfs_next_object_id || g_vfs_next_object_id == UINT64_MAX) return 0;
    node->object_id = g_vfs_next_object_id++;
    return node->object_id;
}

static int vfs_directory_name_length(const char *name, size_t *length)
{
    if (!name || !*name) return -EIO;
    size_t size = 0;
    while (size < VFS_PATH_MAX && name[size]) ++size;
    if (size == VFS_PATH_MAX) return -ENAMETOOLONG;
    *length = size;
    return 0;
}

static size_t vfs_directory_record_bytes(size_t length)
{
    /* length was bounded by VFS_PATH_MAX; padding never exposes heap bytes. */
    return (sizeof(vfs_directory_record_t) + length + 1u + 7u) & ~(size_t)7u;
}

static int vfs_directory_emit_locked(vfs_node_t *node, const char *name, size_t length,
                                      unsigned char *destination)
{
    uint64_t identity = vfs_directory_object_id_locked(node);
    if (!identity) return -EOVERFLOW;
    vfs_directory_record_t *record = (vfs_directory_record_t *)destination;
    record->inode = identity;
    record->type = (uint32_t)node->type;
    record->name_length = (uint32_t)length;
    memcpy(record->name, name, length);
    record->name[length] = 0;
    return 0;
}

int vfs_directory_snapshot(vfs_node_t *directory, vfs_directory_snapshot_t *out)
{
    if (!directory || !out || out->data || out->bytes || out->count) return -EINVAL;
    vfs_tree_lock_acquire();
    if (directory->type != VFS_NODE_DIR) { vfs_tree_lock_release(); return -ENOTDIR; }
    size_t bytes = vfs_directory_record_bytes(1) + vfs_directory_record_bytes(2);
    size_t count = 2;
    int result = 0;
    for (vfs_node_t *child = directory->first_child; child; child = child->next_sibling)
    {
        size_t length;
        result = vfs_directory_name_length(child->name, &length);
        if (result) break;
        size_t record_bytes = vfs_directory_record_bytes(length);
        if (__builtin_add_overflow(bytes, record_bytes, &bytes) || count == SIZE_MAX)
        { result = -EOVERFLOW; break; }
        ++count;
    }
    if (result) { vfs_tree_lock_release(); return result; }
    unsigned char *data = calloc(1, bytes);
    if (!data) { vfs_tree_lock_release(); return -ENOMEM; }
    /* Tree membership and every name stay fixed through both sizing and copy.
     * The stream owns only value records after this lock is released. */
    size_t offset = 0;
    result = vfs_directory_emit_locked(directory, ".", 1, data);
    offset += vfs_directory_record_bytes(1);
    if (!result) result = vfs_directory_emit_locked(directory->parent ? directory->parent : directory,
                                                    "..", 2, data + offset);
    offset += vfs_directory_record_bytes(2);
    for (vfs_node_t *child = directory->first_child; child && !result; child = child->next_sibling)
    {
        size_t length;
        result = vfs_directory_name_length(child->name, &length);
        if (!result)
        {
            result = vfs_directory_emit_locked(child, child->name, length, data + offset);
            offset += vfs_directory_record_bytes(length);
        }
    }
    vfs_tree_lock_release();
    if (result) { free(data); return result; }
    out->data = data;
    out->bytes = bytes;
    out->count = count;
    return 0;
}

void vfs_directory_snapshot_release(vfs_directory_snapshot_t *snapshot)
{
    if (!snapshot) return;
    free(snapshot->data);
    snapshot->data = NULL;
    snapshot->bytes = snapshot->count = 0;
}
