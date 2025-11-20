#include "types.h"  
#include "vfs.h"
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

#define ALIXFS_MAGIC "ALIXFS__"

#define VFS_DIRTY_BACKPRESSURE_LIMIT   (2ULL * 1024ULL * 1024ULL)

typedef struct __attribute__((packed))
{
    char     magic[8];
    uint32_t version;
    uint32_t node_count;
    uint32_t payload_size;
    uint32_t root_id;
    uint32_t reserved[3];
} alixfs_header_t;

typedef struct __attribute__((packed))
{
    uint32_t id;
    uint32_t parent_id;
    uint32_t type;
    uint32_t name_len;
    uint32_t data_len;
} alixfs_node_disk_t;

struct vfs_mount
{
    block_device_t *device;
    vfs_node_t *mount_point;
    struct vfs_mount *next;
    bool dirty;
    bool needs_full_sync;
    uint8_t *image_cache;
    size_t cache_size;
    size_t cache_capacity;
    uint8_t *sync_buffer;
    size_t sync_capacity;
    size_t sector_size;
    uint8_t *dirty_sectors;
    size_t dirty_sector_count;
    spinlock_t dirty_lock;
    spinlock_t sync_lock;
    size_t dirty_bytes;
    size_t dirty_bytes_limit;
};

static bool vfs_mount_writeback(vfs_mount_t *mount, bool force);

struct vfs_node
{
    vfs_node_type_t type;
    char *name;                      /* dynamically allocated */
    struct vfs_node *parent;
    struct vfs_node *first_child;
    struct vfs_node *next_sibling;
    vfs_mount_t *mount;

    /* file payload (for regular files) */
    size_t size;                     /* bytes used (not incl. '\0') */
    size_t capacity;                 /* bytes allocated in data[] */
    char *data;                      /* dynamically allocated, NUL-terminated when capacity > 0 */
    uint32_t image_offset;           /* offset of Node record in serialized image */
    uint32_t image_total_len;        /* total bytes of Node record + name + data */
    uint32_t image_data_offset;      /* offset of file data inside image (0xFFFFFFFF if none) */
    uint32_t image_data_len;         /* bytes of data in image */

    /* device backing (for block nodes) */
    block_device_t *block_device;
    bool dirty;

    vfs_read_cb_t read_cb;
    vfs_write_cb_t write_cb;
    void *callback_context;
};

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
static void vfs_mark_node_dirty(vfs_node_t *node);
static void vfs_clear_dirty_subtree(vfs_node_t *node, vfs_mount_t *mount);
static bool vfs_mount_writeback(vfs_mount_t *mount, bool force);
static bool vfs_mount_sync(vfs_mount_t *mount, bool force_full);
static bool vfs_device_is_mounted(block_device_t *device);
size_t vfs_snapshot_mounts(vfs_mount_info_t *out, size_t max);
bool vfs_force_symlink(vfs_node_t *cwd, const char *target_path, const char *link_path);
static void vfs_backpressure_wait(vfs_mount_t *mount, size_t pending_bytes);
static void vfs_account_dirty_bytes(vfs_mount_t *mount, size_t bytes);
static void vfs_reset_dirty_bytes(vfs_mount_t *mount);

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
            mount->needs_full_sync = true;
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
    if (mount->dirty_bytes_limit &&
        mount->dirty_bytes > mount->dirty_bytes_limit)
    {
        mount->needs_full_sync = true;
    }
    spinlock_unlock(&mount->dirty_lock);
}

static void vfs_reset_dirty_bytes(vfs_mount_t *mount)
{
    if (!mount)
    {
        return;
    }
    spinlock_lock(&mount->dirty_lock);
    mount->dirty_bytes = 0;
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
    if (node->data)
    {
        free(node->data);
    }
    node->data = copy;
    node->size = len;
    node->capacity = len + 1;
    vfs_mark_node_dirty(node);
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
        n->image_data_offset = 0xFFFFFFFFu;
    }
    return n;
}

static void vfs_attach_child(vfs_node_t *parent, vfs_node_t *child)
{
    if (!parent || !child) return;
    child->parent = parent;
    child->mount = parent->mount;
    child->next_sibling = parent->first_child;
    parent->first_child = child;
}

static void vfs_attach_child_tail(vfs_node_t *parent, vfs_node_t *child)
{
    if (!parent || !child) return;
    child->parent = parent;
    child->mount = parent->mount;
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
    child->mount = NULL;
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
    vfs_node_t *child = node->first_child;
    while (child)
    {
        vfs_node_t *next = child->next_sibling;
        vfs_free_subtree(child);
        child = next;
    }
    node->first_child = NULL;
    if (node->name)
    {
        free(node->name);
        node->name = NULL;
    }
    if ((node->type == VFS_NODE_FILE || node->type == VFS_NODE_SYMLINK) && node->data)
    {
        free(node->data);
        node->data = NULL;
        node->size = 0;
        node->capacity = 0;
    }
    free(node);
}

/* Ensure file has room for at least `need` bytes (+1 for trailing NUL). */
static bool ensure_capacity(vfs_node_t *file, size_t need)
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
    return ensure_capacity(file, size_hint);
}

static void ensure_terminator(vfs_node_t *node)
{
    if (!node || node->type != VFS_NODE_FILE) return;
    if (node->capacity == 0)
    {
        if (ensure_capacity(node, 0))
            node->data[0] = '\0';
        return;
    }
    if (node->size + 1 <= node->capacity)
        node->data[node->size] = '\0';
    else
        node->data[node->capacity - 1] = '\0';
}

static void vfs_mark_node_dirty(vfs_node_t *node)
{
    if (!node)
    {
        return;
    }
    node->dirty = true;
    if (node->mount)
    {
        spinlock_lock(&node->mount->dirty_lock);
        node->mount->dirty = true;
        if (node->type != VFS_NODE_FILE)
        {
            node->mount->needs_full_sync = true;
        }
        spinlock_unlock(&node->mount->dirty_lock);
    }
}

static void vfs_note_file_dirty(vfs_node_t *node, size_t start, size_t len, bool size_changed)
{
    (void)start;
    (void)size_changed;
    if (!node || node->type != VFS_NODE_FILE)
    {
        return;
    }
    vfs_mount_t *mount = node->mount;
    vfs_mark_node_dirty(node);
    if (!mount)
    {
        return;
    }
    /* For stability, defer to full sync rather than incremental cache updates. */
    spinlock_lock(&mount->dirty_lock);
    mount->needs_full_sync = true;
    mount->dirty = true;
    spinlock_unlock(&mount->dirty_lock);
    vfs_account_dirty_bytes(mount, len);
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
    node->dirty = false;
    for (vfs_node_t *child = node->first_child; child; child = child->next_sibling)
    {
        vfs_clear_dirty_subtree(child, mount);
    }
}

static bool vfs_measure_node(const vfs_node_t *node,
                             vfs_mount_t *mount,
                             bool is_root,
                             size_t *node_count,
                             size_t *payload_size)
{
    if (!node || !node_count || !payload_size)
    {
        return false;
    }
    if (!is_root && node->mount != mount)
    {
        return true;
    }
    if (node->type == VFS_NODE_BLOCK)
    {
        return true;
    }

    size_t name_len = 0;
    if (!is_root)
    {
        if (!node->name)
        {
            return false;
        }
        name_len = strlen(node->name);
        if (name_len > 0xFFFFFFFFu)
        {
            return false;
        }
    }

    if ((node->type == VFS_NODE_FILE || node->type == VFS_NODE_SYMLINK) &&
        node->size > 0xFFFFFFFFu)
    {
        return false;
    }

    size_t add = sizeof(alixfs_node_disk_t) + name_len;
    if (node->type == VFS_NODE_FILE || node->type == VFS_NODE_SYMLINK)
    {
        add += node->size;
    }
    if (*payload_size > UINT32_MAX - add)
    {
        return false;
    }
    (*node_count) += 1;
    (*payload_size) += add;

    for (const vfs_node_t *child = node->first_child; child; child = child->next_sibling)
    {
        if (!vfs_measure_node(child, mount, false, node_count, payload_size))
        {
            return false;
        }
    }
    return true;
}

typedef struct
{
    block_device_t *device;
    uint8_t *buffer;
    uint64_t sector_index;
    size_t sector_size;
    size_t max_bytes;
    size_t total_bytes;   /* logical bytes written (excludes zero padding) */
    uint8_t *sector_buf;
    size_t fill;
    bool ok;
    bool to_buffer;
} vfs_stream_writer_t;

static void vfs_stream_writer_init(vfs_stream_writer_t *w,
                                   block_device_t *device,
                                   size_t sector_size,
                                   size_t max_bytes)
{
    if (!w)
    {
        return;
    }
    w->device = device;
    w->buffer = NULL;
    w->sector_index = 0;
    w->sector_size = sector_size;
    w->max_bytes = max_bytes;
    w->total_bytes = 0;
    w->sector_buf = (uint8_t *)malloc(sector_size);
    w->fill = 0;
    w->ok = (w->sector_buf != NULL);
    w->to_buffer = false;
    if (w->sector_buf)
    {
        memset(w->sector_buf, 0, sector_size);
    }
}

static void vfs_stream_writer_init_buffer(vfs_stream_writer_t *w,
                                           uint8_t *buffer,
                                           size_t buffer_size,
                                           size_t sector_size)
{
    if (!w)
    {
        return;
    }
    vfs_stream_writer_init(w, NULL, sector_size, buffer_size);
    w->buffer = buffer;
    w->to_buffer = true;
    if (!buffer || buffer_size == 0)
    {
        w->ok = false;
    }
    if (w->sector_buf)
    {
        memset(w->sector_buf, 0, sector_size);
    }
}

static size_t vfs_stream_writer_offset(const vfs_stream_writer_t *w)
{
    if (!w)
    {
        return 0;
    }
    return w->total_bytes + w->fill;
}

static bool vfs_stream_writer_flush(vfs_stream_writer_t *w)
{
    if (!w || !w->ok)
    {
        return false;
    }
    if (w->fill == 0)
    {
        return true;
    }
    if (w->to_buffer)
    {
        size_t offset = (size_t)(w->sector_index * w->sector_size);
        if (!w->buffer || offset + w->sector_size > w->max_bytes)
        {
            w->ok = false;
            return false;
        }
        memcpy(w->buffer + offset, w->sector_buf, w->sector_size);
    }
    else
    {
        if (!block_write(w->device, w->sector_index, 1, w->sector_buf))
        {
            w->ok = false;
            return false;
        }
    }
    w->total_bytes += w->fill;
    w->sector_index++;
    memset(w->sector_buf, 0, w->sector_size);
    w->fill = 0;
    return true;
}

static bool vfs_stream_writer_write(vfs_stream_writer_t *w,
                                    const void *data,
                                    size_t len)
{
    if (!w || !w->ok || !data || len == 0)
    {
        return true;
    }

    const uint8_t *bytes = (const uint8_t *)data;
    size_t remaining = len;
    while (remaining > 0)
    {
        if (w->total_bytes + w->fill >= w->max_bytes)
        {
            w->ok = false;
            return false;
        }
        size_t space = w->sector_size - w->fill;
        size_t chunk = (remaining < space) ? remaining : space;
        if (w->total_bytes + w->fill + chunk > w->max_bytes)
        {
            chunk = w->max_bytes - w->total_bytes - w->fill;
            if (chunk == 0)
            {
                w->ok = false;
                return false;
            }
        }
        memcpy(w->sector_buf + w->fill, bytes, chunk);
        w->fill += chunk;
        bytes += chunk;
        remaining -= chunk;
        if (w->fill == w->sector_size)
        {
            if (!vfs_stream_writer_flush(w))
            {
                return false;
            }
        }
    }
    return true;
}

static void vfs_stream_writer_destroy(vfs_stream_writer_t *w)
{
    if (!w)
    {
        return;
    }
    if (w->sector_buf)
    {
        free(w->sector_buf);
    }
    w->sector_buf = NULL;
}

static bool vfs_serialize_node_stream(vfs_node_t *node,
                                      vfs_mount_t *mount,
                                      bool is_root,
                                      uint32_t parent_id,
                                      uint32_t *next_id,
                                      vfs_stream_writer_t *writer)
{
    if (!node || !next_id || !writer || !writer->ok)
    {
        return false;
    }
    if (!is_root && node->mount != mount)
    {
        return true;
    }
    if (node->type == VFS_NODE_BLOCK)
    {
        return true;
    }

    uint32_t node_id = (*next_id)++;
    size_t name_len_sz = (!is_root && node->name) ? strlen(node->name) : 0;
    uint32_t name_len = (uint32_t)name_len_sz;
    uint32_t data_len = (node->type == VFS_NODE_FILE || node->type == VFS_NODE_SYMLINK)
                            ? (uint32_t)node->size
                            : 0;

    uint32_t type_field = (uint32_t)(is_root ? VFS_NODE_DIR : node->type);

    size_t node_offset = vfs_stream_writer_offset(writer);
    alixfs_node_disk_t disk = {
        .id = node_id,
        .parent_id = parent_id,
        .type = type_field,
        .name_len = name_len,
        .data_len = data_len
    };

    if (!vfs_stream_writer_write(writer, &disk, sizeof(disk)))
    {
        return false;
    }

    if (!is_root && name_len > 0)
    {
        if (!vfs_stream_writer_write(writer, node->name, name_len))
        {
            return false;
        }
    }

    size_t data_offset = 0;
    if ((node->type == VFS_NODE_FILE || node->type == VFS_NODE_SYMLINK) && data_len > 0)
    {
        if (!node->data)
        {
            return false;
        }
        data_offset = vfs_stream_writer_offset(writer);
        if (!vfs_stream_writer_write(writer, node->data, data_len))
        {
            return false;
        }
    }

    node->image_offset = (uint32_t)node_offset;
    node->image_total_len = (uint32_t)(vfs_stream_writer_offset(writer) - node_offset);
    if (node->type == VFS_NODE_FILE || node->type == VFS_NODE_SYMLINK)
    {
        node->image_data_offset = (data_len > 0) ? (uint32_t)data_offset : 0xFFFFFFFFu;
        node->image_data_len = data_len;
    }
    else
    {
        node->image_data_offset = 0xFFFFFFFFu;
        node->image_data_len = 0;
    }

    for (vfs_node_t *child = node->first_child; child; child = child->next_sibling)
    {
        if (!vfs_serialize_node_stream(child, mount, false, node_id, next_id, writer))
        {
            return false;
        }
    }
    return true;
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
    node->image_offset = 0;
    node->image_total_len = 0;
    node->image_data_offset = 0xFFFFFFFFu;
    node->image_data_len = 0;

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
    dir->image_offset = 0;
    dir->image_total_len = 0;
    dir->image_data_offset = 0xFFFFFFFFu;
    dir->image_data_len = 0;

    vfs_attach_child(parent, dir);
    vfs_mark_node_dirty(parent);
    vfs_mark_node_dirty(dir);
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
        vfs_attach_child(parent, file);
        vfs_mark_node_dirty(parent);
        vfs_mark_node_dirty(file);
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
        file->size = 0;
        if (!ensure_capacity(file, 0))
        {
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
        vfs_mark_node_dirty(file);
    }

    ensure_terminator(file);
    spinlock_unlock(&g_vfs_tree_lock);
    return file;
}

vfs_node_t *vfs_symlink(vfs_node_t *cwd, const char *target_path, const char *link_path)
{
    if (!target_path || !link_path || *target_path == '\0')
    {
        return NULL;
    }

    vfs_node_t *parent = NULL;
    char *name = NULL;
    spinlock_lock(&g_vfs_tree_lock);
    if (!split_parent_and_name(cwd ? cwd : root, link_path, &parent, &name))
    {
        spinlock_unlock(&g_vfs_tree_lock);
        return NULL;
    }

    vfs_node_t *existing = vfs_find_child(parent, name);
    if (existing)
    {
        if (existing->type == VFS_NODE_SYMLINK)
        {
            bool updated = vfs_assign_symlink_target(existing, target_path);
            free(name);
            spinlock_unlock(&g_vfs_tree_lock);
            return updated ? existing : NULL;
        }
        if (existing->type == VFS_NODE_DIR && vfs_is_mount_point(existing))
        {
            free(name);
            spinlock_unlock(&g_vfs_tree_lock);
            return NULL;
        }
        if (existing->type == VFS_NODE_DIR && existing->first_child)
        {
            vfs_clear_directory(existing);
        }
        vfs_detach_child(existing);
        vfs_free_subtree(existing);
        existing = NULL;
    }

    vfs_node_t *node = vfs_alloc_node(VFS_NODE_SYMLINK);
    if (!node)
    {
        free(name);
        spinlock_unlock(&g_vfs_tree_lock);
        return NULL;
    }
    node->name = name;
    if (!vfs_assign_symlink_target(node, target_path))
    {
        vfs_free_subtree(node);
        spinlock_unlock(&g_vfs_tree_lock);
        return NULL;
    }

    vfs_attach_child(parent, node);
    vfs_mark_node_dirty(parent);
    vfs_mark_node_dirty(node);
    spinlock_unlock(&g_vfs_tree_lock);
    return node;
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
    file->size = 0;
    if (!ensure_capacity(file, 0)) return false;
    file->data[0] = '\0';
    vfs_note_file_dirty(file, 0, 0, true);
    return true;
}

bool vfs_append(vfs_node_t *file, const char *data, size_t len)
{
    if (!file || file->type != VFS_NODE_FILE) return false;
    if (!data || len == 0) { ensure_terminator(file); return true; }

    if (file->mount)
    {
        vfs_backpressure_wait(file->mount, len);
    }
    if (!ensure_capacity(file, file->size + len)) return false;

    memmove(file->data + file->size, data, len);
    size_t start = file->size;
    file->size += len;
    ensure_terminator(file);
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

    ensure_terminator(file);
    if (offset >= file->size || count == 0)
    {
        return 0;
    }
    size_t available = file->size - offset;
    if (count > available)
    {
        count = available;
    }
    memcpy(buffer, file->data + offset, count);
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
    if (!ensure_capacity(file, end))
    {
        return -1;
    }
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
    ensure_terminator(file);
    bool size_changed = (file->size != file->image_data_len);
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
    ensure_terminator(file);
    if (size) *size = file->size;
    return file->data;
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

    vfs_detach_child(node);
    vfs_free_subtree(node);

    vfs_mark_node_dirty(parent);
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
    spinlock_unlock(&g_vfs_tree_lock);
    return node;
}

void vfs_clear_directory(vfs_node_t *dir)
{
    if (!dir || dir->type != VFS_NODE_DIR)
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
        vfs_free_subtree(child);
        child = next;
    }
}

static size_t vfs_sector_size(block_device_t *device)
{
    return (device && device->sector_size) ? device->sector_size : 512;
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

    size_t sector_size = vfs_sector_size(device);
    size_t payload_size = sizeof(alixfs_node_disk_t);
    size_t total_bytes = sizeof(alixfs_header_t) + payload_size;
    uint32_t sectors_needed = (uint32_t)((total_bytes + sector_size - 1) / sector_size);
    if (sectors_needed == 0)
    {
        sectors_needed = 1;
    }
    if ((uint64_t)sectors_needed > device->sector_count)
    {
        return false;
    }

    size_t buffer_size = (size_t)sectors_needed * sector_size;
    uint8_t *buffer = (uint8_t *)malloc(buffer_size);
    if (!buffer)
    {
        return false;
    }
    memset(buffer, 0, buffer_size);

    alixfs_header_t *header = (alixfs_header_t *)buffer;
    memcpy(header->magic, ALIXFS_MAGIC, sizeof(header->magic));
    header->version = 1;
    header->node_count = 1;
    header->payload_size = (uint32_t)payload_size;
    header->root_id = 0;
    header->reserved[0] = header->reserved[1] = header->reserved[2] = 0;

    alixfs_node_disk_t *root_disk = (alixfs_node_disk_t *)(buffer + sizeof(alixfs_header_t));
    root_disk->id = 0;
    root_disk->parent_id = 0xFFFFFFFFu;
    root_disk->type = VFS_NODE_DIR;
    root_disk->name_len = 0;
    root_disk->data_len = 0;

    bool ok = block_write(device, 0, sectors_needed, buffer);
    free(buffer);
    return ok;
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

static bool vfs_mount_sync(vfs_mount_t *mount, bool force_full)
{
    (void)force_full;
    if (!mount || !mount->device || !mount->mount_point)
    {
        serial_printf("%s", "[vfs] sync abort: invalid mount\r\n");
        return false;
    }

    const char *dev_name = (mount->device->name[0]) ? mount->device->name : "(anon)";

    size_t node_count = 0;
    size_t payload_size = 0;
    spinlock_lock(&g_vfs_tree_lock);
    bool measured = vfs_measure_node(mount->mount_point, mount, true, &node_count, &payload_size);
    spinlock_unlock(&g_vfs_tree_lock);
    if (!measured)
    {
        serial_printf("%s", "[vfs] sync measure failed\r\n");
        return false;
    }
    if (node_count == 0)
    {
        serial_printf("%s", "[vfs] sync measure produced zero nodes\r\n");
        return false;
    }
    if (node_count > UINT32_MAX)
    {
        serial_printf("%s", "[vfs] sync fail: node_count overflow\r\n");
        return false;
    }

    size_t sector_size = vfs_sector_size(mount->device);
    size_t total_bytes = sizeof(alixfs_header_t) + payload_size;
    uint32_t sectors_needed = (uint32_t)((total_bytes + sector_size - 1) / sector_size);
    if (sectors_needed == 0)
    {
        sectors_needed = 1;
    }
    if ((uint64_t)sectors_needed > mount->device->sector_count)
    {
        serial_printf("%s", "[vfs] sync fail: capacity exhausted sectors_needed=0x");
        serial_printf("%016llX", (unsigned long long)sectors_needed);
        serial_printf("%s", " sector_count=0x");
        serial_printf("%016llX", (unsigned long long)mount->device->sector_count);
        serial_printf("%s", "\r\n");
        return false;
    }

    serial_printf("%s", "[vfs] writeback start dev=");
    serial_printf("%s", dev_name);
    serial_printf("%s", " sectors_needed=");
    serial_printf("%016llX", (unsigned long long)sectors_needed);
    serial_printf("%s", " total_bytes=");
    serial_printf("%016llX", (unsigned long long)total_bytes);
    serial_printf("%s", "\r\n");

    size_t max_bytes = (size_t)sectors_needed * sector_size;
    uint8_t *scratch = mount->sync_buffer;
    size_t scratch_capacity = mount->sync_capacity;
    if (!scratch || scratch_capacity < max_bytes)
    {
        uint8_t *new_buf = (uint8_t *)realloc(scratch, max_bytes);
        if (!new_buf)
        {
            serial_printf("%s", "[vfs] sync fail: scratch alloc\r\n");
            return false;
        }
        scratch = new_buf;
        scratch_capacity = max_bytes;
        mount->sync_buffer = scratch;
        mount->sync_capacity = scratch_capacity;
    }
    memset(scratch, 0, max_bytes);
    if (!mount->dirty_sectors || mount->dirty_sector_count < sectors_needed)
    {
        uint8_t *dirty = (uint8_t *)realloc(mount->dirty_sectors, sectors_needed);
        if (!dirty)
        {
            serial_printf("%s", "[vfs] sync fail: dirty map alloc\r\n");
            return false;
        }
        mount->dirty_sectors = dirty;
        mount->dirty_sector_count = sectors_needed;
    }
    else
    {
        /* Keep tracking capacity but clamp logical span to new requirement. */
        mount->dirty_sector_count = sectors_needed;
    }
    if (mount->dirty_sectors && mount->dirty_sector_count > 0)
    {
        memset(mount->dirty_sectors, 0, mount->dirty_sector_count);
    }

    vfs_stream_writer_t writer;
    vfs_stream_writer_init_buffer(&writer, scratch, max_bytes, sector_size);
    if (!writer.ok)
    {
        serial_printf("%s", "[vfs] sync fail: stream buffer alloc\r\n");
        return false;
    }

    alixfs_header_t header;
    memcpy(header.magic, ALIXFS_MAGIC, sizeof(header.magic));
    header.version = 1;
    header.node_count = (uint32_t)node_count;
    header.payload_size = (uint32_t)payload_size;
    header.root_id = 0;
    header.reserved[0] = header.reserved[1] = header.reserved[2] = 0;

    bool ok = vfs_stream_writer_write(&writer, &header, sizeof(header));
    uint32_t next_id = 0;
    if (ok)
    {
        spinlock_lock(&g_vfs_tree_lock);
        ok = vfs_serialize_node_stream(mount->mount_point,
                                       mount,
                                       true,
                                       0xFFFFFFFFu,
                                       &next_id,
                                       &writer);
        spinlock_unlock(&g_vfs_tree_lock);
    }
    if (ok)
    {
        ok = vfs_stream_writer_flush(&writer);
    }

    vfs_stream_writer_destroy(&writer);

    if (!ok)
    {
        return false;
    }

    /* Write only sectors that changed vs cached image. */
    size_t new_size = (size_t)sectors_needed * sector_size;
    uint8_t *old = mount->image_cache;
    size_t old_size = mount->cache_size;
    size_t old_capacity = mount->cache_capacity;
    uint32_t run_start = UINT32_MAX;
    uint32_t run_len = 0;
    for (uint32_t sector = 0; sector < sectors_needed; ++sector)
    {
        size_t offset = (size_t)sector * sector_size;
        bool changed = true;
        if (old && offset + sector_size <= old_size)
        {
            if (memcmp(old + offset, scratch + offset, sector_size) == 0)
            {
                changed = false;
            }
        }
        if (changed)
        {
            if (run_start == UINT32_MAX)
            {
                run_start = sector;
                run_len = 1;
            }
            else if (run_start + run_len == sector)
            {
                run_len++;
            }
            else
            {
                if (!block_write(mount->device, run_start, run_len, scratch + (size_t)run_start * sector_size))
                {
                    serial_printf("%s", "[vfs] block_write failed dev=");
                    serial_printf("%s", dev_name);
                    serial_printf("%s", " lba=");
                    serial_printf("%016llX", (unsigned long long)run_start);
                    serial_printf("%s", " count=");
                    serial_printf("%016llX", (unsigned long long)run_len);
                    serial_printf("%s", "\r\n");
                    return false;
                }
                else
                {
                    serial_printf("%s", "[vfs] block_write dev=");
                    serial_printf("%s", dev_name);
                    serial_printf("%s", " lba=");
                    serial_printf("%016llX", (unsigned long long)run_start);
                    serial_printf("%s", " count=");
                    serial_printf("%016llX", (unsigned long long)run_len);
                    serial_printf("%s", "\r\n");
                }
                run_start = sector;
                run_len = 1;
            }
        }
    }
    if (run_start != UINT32_MAX)
    {
        if (!block_write(mount->device, run_start, run_len, scratch + (size_t)run_start * sector_size))
        {
            serial_printf("%s", "[vfs] block_write failed dev=");
            serial_printf("%s", dev_name);
            serial_printf("%s", " lba=");
            serial_printf("%016llX", (unsigned long long)run_start);
            serial_printf("%s", " count=");
            serial_printf("%016llX", (unsigned long long)run_len);
            serial_printf("%s", "\r\n");
            return false;
        }
        else
        {
            serial_printf("%s", "[vfs] block_write dev=");
            serial_printf("%s", dev_name);
            serial_printf("%s", " lba=");
            serial_printf("%016llX", (unsigned long long)run_start);
            serial_printf("%s", " count=");
            serial_printf("%016llX", (unsigned long long)run_len);
            serial_printf("%s", "\r\n");
        }
    }

    /* If the new image shrank, clear trailing old sectors. */
    uint32_t old_sectors = (old_size > 0 && sector_size > 0) ? (uint32_t)(old_size / sector_size) : 0;
    if (old_sectors > sectors_needed)
    {
        size_t zeros_len = sector_size;
        uint8_t *zero_buf = (uint8_t *)calloc(1, zeros_len);
        if (!zero_buf)
        {
            return false;
        }
        uint32_t start = sectors_needed;
        uint32_t len = old_sectors - sectors_needed;
        while (len > 0)
        {
            if (!block_write(mount->device, start, 1, zero_buf))
            {
                free(zero_buf);
                return false;
            }
            start += 1;
            len -= 1;
        }
        free(zero_buf);
    }

    uint8_t *previous_cache = mount->image_cache;
    mount->image_cache = scratch;
    mount->cache_size = new_size;
    mount->cache_capacity = scratch_capacity;
    mount->sync_buffer = previous_cache;
    mount->sync_capacity = old_capacity;
    mount->needs_full_sync = false;
    return true;
}

static bool vfs_mount_writeback(vfs_mount_t *mount, bool force)
{
    if (!mount)
    {
        return true;
    }
    bool dirty = false;
    const char *dev_name = (mount && mount->device && mount->device->name[0]) ? mount->device->name : "(anon)";
    uint64_t sync_start = timer_ticks();
    serial_printf("%s", "[vfs] writeback acquire dev=");
    serial_printf("%s", dev_name);
    serial_printf("%s", "\r\n");

    spinlock_lock(&mount->dirty_lock);
    dirty = mount->dirty || force;
    mount->dirty = false;
    mount->needs_full_sync = false;
    spinlock_unlock(&mount->dirty_lock);

    if (!dirty)
    {
        return true;
    }

    spinlock_lock(&mount->sync_lock);
    bool ok_sync = vfs_mount_sync(mount, true);
    spinlock_unlock(&mount->sync_lock);
    uint64_t sync_ms = vfs_ticks_to_ms(timer_ticks() - sync_start);
    serial_printf("%s", "[vfs] writeback ");
    serial_printf("%s", ok_sync ? "ok" : "fail");
    serial_printf("%s", " dev=");
    serial_printf("%s", dev_name);
    serial_printf("%s", " duration=");
    serial_printf("%llu", (unsigned long long)sync_ms);
    serial_printf("%s", "ms\r\n");

        if (!ok_sync)
        {
            spinlock_lock(&mount->dirty_lock);
            mount->needs_full_sync = true;
            mount->dirty = true;
            spinlock_unlock(&mount->dirty_lock);
            serial_printf("%s", "[vfs] writeback FAILED dev=");
            serial_printf("%s", (mount && mount->device && mount->device->name[0]) ? mount->device->name : "(anon)");
            serial_printf("%s", "\r\n");
            return false;
        }

        spinlock_lock(&g_vfs_tree_lock);
        vfs_clear_dirty_subtree(mount->mount_point, mount);
        spinlock_unlock(&g_vfs_tree_lock);
        vfs_reset_dirty_bytes(mount);

    spinlock_lock(&mount->dirty_lock);
    if (mount->dirty_sectors && mount->dirty_sector_count > 0)
    {
        memset(mount->dirty_sectors, 0, mount->dirty_sector_count);
    }
    spinlock_unlock(&mount->dirty_lock);
    serial_printf("%s", "[vfs] writeback OK dev=");
    serial_printf("%s", (mount && mount->device && mount->device->name[0]) ? mount->device->name : "(anon)");
    serial_printf("%s", "\r\n");
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
    bool dirty = false;
    spinlock_lock(&mount->dirty_lock);
    dirty = mount->dirty;
    spinlock_unlock(&mount->dirty_lock);
    if (!dirty)
    {
        node->dirty = false;
        return true;
    }
    return vfs_mount_writeback(mount, false);
}

static bool vfs_load_mount(block_device_t *device, vfs_mount_t *mount)
{
    if (!device || !mount || !mount->mount_point)
    {
        return false;
    }

    const char *dev_name = device->name[0] ? device->name : "(anon)";

    size_t sector_size = vfs_sector_size(device);
    uint8_t *first_sector = (uint8_t *)malloc(sector_size);
    if (!first_sector)
    {
        return false;
    }

    if (!block_read(device, 0, 1, first_sector))
    {
        serial_printf("%s", "[vfs] mount ");
        serial_printf("%s", dev_name);
        serial_printf("%s", ": block_read sector0 failed\r\n");
        free(first_sector);
        return false;
    }

    alixfs_header_t header_copy;
    memcpy(&header_copy, first_sector, sizeof(alixfs_header_t));
    free(first_sector);

    if (memcmp(header_copy.magic, ALIXFS_MAGIC, sizeof(header_copy.magic)) != 0 ||
        header_copy.version != 1 ||
        header_copy.node_count == 0)
    {
        serial_printf("%s", "[vfs] mount ");
        serial_printf("%s", dev_name);
        serial_printf("%s", ": bad header (magic/version/node_count)\r\n");
        return false;
    }

    size_t total_bytes = sizeof(alixfs_header_t) + header_copy.payload_size;
    uint32_t sectors_needed = (uint32_t)((total_bytes + sector_size - 1) / sector_size);
    if (sectors_needed == 0)
    {
        sectors_needed = 1;
    }
    if ((uint64_t)sectors_needed > device->sector_count)
    {
        serial_printf("%s", "[vfs] mount ");
        serial_printf("%s", dev_name);
        serial_printf("%s", ": header exceeds device capacity\r\n");
        return false;
    }

    size_t buffer_size = (size_t)sectors_needed * sector_size;
    uint8_t *buffer = (uint8_t *)malloc(buffer_size);
    if (!buffer)
    {
        return false;
    }

    if (!block_read(device, 0, sectors_needed, buffer))
    {
        serial_printf("%s", "[vfs] mount ");
        serial_printf("%s", dev_name);
        serial_printf("%s", ": block_read image failed\r\n");
        free(buffer);
        return false;
    }

    alixfs_header_t *header = (alixfs_header_t *)buffer;
    if (memcmp(header->magic, ALIXFS_MAGIC, sizeof(header->magic)) != 0 ||
        header->version != 1 ||
        header->node_count == 0)
    {
        serial_printf("%s", "[vfs] mount ");
        serial_printf("%s", dev_name);
        serial_printf("%s", ": bad header after read\r\n");
        free(buffer);
        return false;
    }

    uint32_t node_count = header->node_count;
    if (header->root_id >= node_count)
    {
        serial_printf("%s", "[vfs] mount ");
        serial_printf("%s", dev_name);
        serial_printf("%s", ": invalid root_id\r\n");
        free(buffer);
        return false;
    }

    size_t header_total_bytes = sizeof(alixfs_header_t) + header->payload_size;
    if (header_total_bytes > buffer_size)
    {
        serial_printf("%s", "[vfs] mount ");
        serial_printf("%s", dev_name);
        serial_printf("%s", ": payload overflow\r\n");
        free(buffer);
        return false;
    }

    vfs_node_t **nodes = (vfs_node_t **)calloc(node_count, sizeof(vfs_node_t *));
    uint32_t *parents = (uint32_t *)malloc(node_count * sizeof(uint32_t));
    if (!nodes || !parents)
    {
        free(nodes);
        free(parents);
        free(buffer);
        return false;
    }

    for (uint32_t i = 0; i < node_count; ++i)
    {
        parents[i] = 0xFFFFFFFFu;
    }

    nodes[header->root_id] = mount->mount_point;
    parents[header->root_id] = 0xFFFFFFFFu;

    bool success = false;
    size_t offset = sizeof(alixfs_header_t);
    bool failure_logged = false;

    for (uint32_t idx = 0; idx < node_count; ++idx)
    {
        if (offset + sizeof(alixfs_node_disk_t) > header_total_bytes)
        {
            serial_printf("%s", "[vfs] mount ");
            serial_printf("%s", dev_name);
            serial_printf("%s", ": node header overflow idx=");
            serial_printf("%016llX", (unsigned long long)idx);
            serial_printf("%s", " off=");
            serial_printf("%016llX", (unsigned long long)offset);
            serial_printf("%s", " total=");
            serial_printf("%016llX", (unsigned long long)header_total_bytes);
            serial_printf("%s", "\r\n");
            failure_logged = true;
            goto cleanup;
        }

        size_t node_offset = offset;
        alixfs_node_disk_t disk;
        memcpy(&disk, buffer + offset, sizeof(disk));
        offset += sizeof(disk);

        if (disk.id >= node_count)
        {
            serial_printf("%s", "[vfs] mount ");
            serial_printf("%s", dev_name);
            serial_printf("%s", ": invalid node id\r\n");
            failure_logged = true;
            goto cleanup;
        }
        if (nodes[disk.id] && disk.id != header->root_id)
        {
            serial_printf("%s", "[vfs] mount ");
            serial_printf("%s", dev_name);
            serial_printf("%s", ": duplicate node id\r\n");
            failure_logged = true;
            goto cleanup;
        }
        if (disk.parent_id != 0xFFFFFFFFu && disk.parent_id >= node_count)
        {
            serial_printf("%s", "[vfs] mount ");
            serial_printf("%s", dev_name);
            serial_printf("%s", ": invalid parent id\r\n");
            failure_logged = true;
            goto cleanup;
        }

        if (offset + disk.name_len > header_total_bytes)
        {
            serial_printf("%s", "[vfs] mount ");
            serial_printf("%s", dev_name);
            serial_printf("%s", ": name overflow\r\n");
            failure_logged = true;
            goto cleanup;
        }
        const uint8_t *name_bytes = buffer + offset;
        offset += disk.name_len;

        uint32_t data_len = disk.data_len;
        size_t data_offset = 0;
        if (offset + data_len > header_total_bytes)
        {
            serial_printf("%s", "[vfs] mount ");
            serial_printf("%s", dev_name);
            serial_printf("%s", ": data overflow\r\n");
            failure_logged = true;
            goto cleanup;
        }
        const uint8_t *data_bytes = buffer + offset;
        data_offset = offset;
        offset += data_len;

        if (disk.id == header->root_id)
        {
            if (disk.type != VFS_NODE_DIR)
            {
                serial_printf("%s", "[vfs] mount ");
                serial_printf("%s", dev_name);
                serial_printf("%s", ": root not dir\r\n");
                failure_logged = true;
                goto cleanup;
            }
            parents[disk.id] = disk.parent_id;
            continue;
        }

        if (disk.type > VFS_NODE_SYMLINK || disk.name_len == 0)
        {
            serial_printf("%s", "[vfs] mount ");
            serial_printf("%s", dev_name);
            serial_printf("%s", ": invalid node type or name_len\r\n");
            failure_logged = true;
            goto cleanup;
        }

        vfs_node_type_t node_type = VFS_NODE_FILE;
        if (disk.type == VFS_NODE_DIR)
        {
            node_type = VFS_NODE_DIR;
        }
        else if (disk.type == VFS_NODE_SYMLINK)
        {
            node_type = VFS_NODE_SYMLINK;
        }
        vfs_node_t *node = vfs_alloc_node(node_type);
        if (!node)
        {
            serial_printf("%s", "[vfs] mount ");
            serial_printf("%s", dev_name);
            serial_printf("%s", ": node alloc failed\r\n");
            failure_logged = true;
            goto cleanup;
        }

        char *name = (char *)malloc(disk.name_len + 1);
        if (!name)
        {
            vfs_free_subtree(node);
            serial_printf("%s", "[vfs] mount ");
            serial_printf("%s", dev_name);
            serial_printf("%s", ": name alloc failed\r\n");
            failure_logged = true;
            goto cleanup;
        }
        memcpy(name, name_bytes, disk.name_len);
        name[disk.name_len] = '\0';
        node->name = name;

        if ((node_type == VFS_NODE_FILE || node_type == VFS_NODE_SYMLINK) && data_len > 0)
        {
            size_t cap = (size_t)data_len + 1;
            char *data = (char *)malloc(cap);
            if (!data)
            {
                vfs_free_subtree(node);
                serial_printf("%s", "[vfs] mount ");
                serial_printf("%s", dev_name);
                serial_printf("%s", ": data alloc failed\r\n");
                failure_logged = true;
                goto cleanup;
            }
            memcpy(data, data_bytes, data_len);
            data[data_len] = '\0';
            node->data = data;
            node->size = data_len;
            node->capacity = cap;
        }

        node->image_offset = (uint32_t)node_offset;
        node->image_total_len = (uint32_t)(offset - node_offset);
        if (node_type == VFS_NODE_FILE || node_type == VFS_NODE_SYMLINK)
        {
            node->image_data_offset = (data_len > 0) ? (uint32_t)data_offset : 0xFFFFFFFFu;
            node->image_data_len = data_len;
        }
        else
        {
            node->image_data_offset = 0xFFFFFFFFu;
            node->image_data_len = 0;
        }

        nodes[disk.id] = node;
        parents[disk.id] = disk.parent_id;
    }

    if (parents[header->root_id] != 0xFFFFFFFFu)
    {
        serial_printf("%s", "[vfs] mount ");
        serial_printf("%s", dev_name);
        serial_printf("%s", ": root parent mismatch\r\n");
        failure_logged = true;
        goto cleanup;
    }

    for (uint32_t i = 0; i < node_count; ++i)
    {
        if (i == header->root_id)
        {
            continue;
        }
        vfs_node_t *node = nodes[i];
        if (!node)
        {
            serial_printf("%s", "[vfs] mount ");
            serial_printf("%s", dev_name);
            serial_printf("%s", ": missing node in table\r\n");
            failure_logged = true;
            goto cleanup;
        }
        uint32_t parent_id = parents[i];
        if (parent_id >= node_count)
        {
            serial_printf("%s", "[vfs] mount ");
            serial_printf("%s", dev_name);
            serial_printf("%s", ": parent id overflow\r\n");
            failure_logged = true;
            goto cleanup;
        }
        vfs_node_t *parent = nodes[parent_id];
        if (!parent || parent->type != VFS_NODE_DIR)
        {
            serial_printf("%s", "[vfs] mount ");
            serial_printf("%s", dev_name);
            serial_printf("%s", ": parent missing or not dir\r\n");
            failure_logged = true;
            goto cleanup;
        }
        vfs_attach_child_tail(parent, node);
    }

    mount->image_cache = buffer;
    mount->cache_size = buffer_size;
    mount->cache_capacity = buffer_size;
    mount->sector_size = sector_size;
    free(mount->dirty_sectors);
    uint32_t sectors = (uint32_t)(buffer_size / sector_size);
    mount->dirty_sectors = (uint8_t *)calloc(sectors, 1);
    mount->dirty_sector_count = sectors;
    buffer = NULL;
    success = true;

cleanup:
    if (!success)
    {
        /* Detach anything we may have attached. */
        vfs_clear_directory(mount->mount_point);
        /* Free any nodes that were allocated but never attached. */
        for (uint32_t i = 0; i < node_count; ++i)
        {
            if (i == header->root_id)
            {
                continue;
            }
            if (nodes[i] && nodes[i]->parent == NULL)
            {
                vfs_free_subtree(nodes[i]);
            }
        }
        if (!failure_logged)
        {
            serial_printf("%s", "[vfs] mount ");
            serial_printf("%s", dev_name);
            serial_printf("%s", ": aborted\r\n");
        }
    }

    free(nodes);
    free(parents);
    free(buffer);
    return success;
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

    vfs_mount_t *mount = (vfs_mount_t *)malloc(sizeof(vfs_mount_t));
    if (!mount)
    {
        spinlock_unlock(&g_vfs_tree_lock);
        return false;
    }

    mount->device = device;
    mount->mount_point = mount_point;
    mount->next = NULL;
    mount->dirty = false;
    mount->needs_full_sync = false;
    mount->image_cache = NULL;
    mount->cache_size = 0;
    mount->cache_capacity = 0;
    mount->sync_buffer = NULL;
    mount->sync_capacity = 0;
    mount->sector_size = 0;
    mount->dirty_sectors = NULL;
    mount->dirty_sector_count = 0;
    mount->dirty_bytes = 0;
    mount->dirty_bytes_limit = VFS_DIRTY_BACKPRESSURE_LIMIT;
    spinlock_init(&mount->dirty_lock);
    spinlock_init(&mount->sync_lock);

    mount_point->mount = mount;

    if (!vfs_load_mount(device, mount))
    {
        mount_point->mount = NULL;
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
        spinlock_lock(&mount->dirty_lock);
        dirty = mount->dirty;
        spinlock_unlock(&mount->dirty_lock);

        if (!dirty)
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
            out[count].needs_full_sync = m->needs_full_sync;
            spinlock_unlock(&m->dirty_lock);
        }
        count++;
    }
    spinlock_unlock(&g_vfs_tree_lock);
    return count;
}
