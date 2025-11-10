#include "types.h"  
#include "vfs.h"
#include "libc.h"
#include "heap.h"
#include "serial.h"

/*
 * Heap-backed VFS:
 *  - Nodes and names allocated dynamically.
 *  - File data grows via realloc (doubling strategy).
 *  - No fixed limits on node count, name length, or file size (bounded by RAM).
 */

#define ALIXFS_MAGIC "ALIXFS__"

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
    uint8_t *image_cache;
    size_t cache_size;
    size_t sector_size;
};

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

    /* device backing (for block nodes) */
    block_device_t *block_device;
    bool dirty;

    vfs_read_cb_t read_cb;
    vfs_write_cb_t write_cb;
    void *callback_context;
};

static vfs_node_t *root = NULL;
static vfs_mount_t *mounts = NULL;

#define VFS_MAX_SYMLINK_DEPTH 8

static void vfs_log(const char *msg, uint64_t value)
{
    serial_write_string("[vfs] ");
    serial_write_string(msg);
    serial_write_string("0x");
    serial_write_hex64(value);
    serial_write_string("\r\n");
}

static bool vfs_mount_sync_node(vfs_node_t *node);
static void vfs_mark_node_dirty(vfs_node_t *node);
static void vfs_clear_dirty_subtree(vfs_node_t *node, vfs_mount_t *mount);
static bool vfs_mount_writeback(vfs_mount_t *mount, bool force);
static bool vfs_mount_sync(vfs_mount_t *mount, bool force_full);
static bool vfs_device_is_mounted(block_device_t *device);

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
        node->mount->dirty = true;
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

    (*node_count) += 1;
    (*payload_size) += sizeof(alixfs_node_disk_t) + name_len;
    if (node->type == VFS_NODE_FILE || node->type == VFS_NODE_SYMLINK)
    {
        (*payload_size) += node->size;
    }

    for (const vfs_node_t *child = node->first_child; child; child = child->next_sibling)
    {
        if (!vfs_measure_node(child, mount, false, node_count, payload_size))
        {
            return false;
        }
    }
    return true;
}

static bool vfs_serialize_node(const vfs_node_t *node,
                               vfs_mount_t *mount,
                               bool is_root,
                               uint32_t parent_id,
                               uint8_t *buffer,
                               size_t buffer_size,
                               size_t *offset,
                               uint32_t *next_id)
{
    if (!node || !buffer || !offset || !next_id)
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
    size_t name_len_sz = 0;
    if (!is_root)
    {
        name_len_sz = node->name ? strlen(node->name) : 0;
    }
    uint32_t name_len = (uint32_t)name_len_sz;
    uint32_t data_len = (node->type == VFS_NODE_FILE || node->type == VFS_NODE_SYMLINK)
                            ? (uint32_t)node->size
                            : 0;

    uint32_t type_field = (uint32_t)(is_root ? VFS_NODE_DIR : node->type);

    alixfs_node_disk_t disk = {
        .id = node_id,
        .parent_id = parent_id,
        .type = type_field,
        .name_len = name_len,
        .data_len = data_len
    };

    if ((*offset) + sizeof(disk) > buffer_size)
    {
        return false;
    }
    memcpy(buffer + (*offset), &disk, sizeof(disk));
    (*offset) += sizeof(disk);

    if (!is_root && name_len > 0)
    {
        if ((*offset) + name_len > buffer_size)
        {
            return false;
        }
        memcpy(buffer + (*offset), node->name, name_len);
        (*offset) += name_len;
    }

    if ((node->type == VFS_NODE_FILE || node->type == VFS_NODE_SYMLINK) && data_len > 0)
    {
        if (!node->data)
        {
            return false;
        }
        if ((*offset) + data_len > buffer_size)
        {
            return false;
        }
        memcpy(buffer + (*offset), node->data, data_len);
        (*offset) += data_len;
    }

    for (const vfs_node_t *child = node->first_child; child; child = child->next_sibling)
    {
        if (!vfs_serialize_node(child, mount, false, node_id, buffer, buffer_size, offset, next_id))
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
    return resolve_node_internal(cwd ? cwd : root, path, 0);
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
    return resolve_node(cwd ? cwd : root, path);
}

vfs_node_t *vfs_mkdir(vfs_node_t *cwd, const char *path)
{
    vfs_node_t *parent = NULL;
    char *name = NULL;

    if (!split_parent_and_name(cwd ? cwd : root, path, &parent, &name))
        return NULL;

    vfs_node_t *existing = vfs_find_child(parent, name);
    if (existing)
    {
        free(name);
        return (existing->type == VFS_NODE_DIR) ? existing : NULL;
    }

    vfs_node_t *dir = vfs_alloc_node(VFS_NODE_DIR);
    if (!dir)
    {
        free(name);
        return NULL;
    }

    dir->name   = name;   /* take ownership */
    dir->size = 0;
    dir->capacity = 0;
    dir->data = NULL;

    vfs_attach_child(parent, dir);
    vfs_mark_node_dirty(parent);
    vfs_mark_node_dirty(dir);
    return dir;
}

vfs_node_t *vfs_open_file(vfs_node_t *cwd, const char *path, bool create, bool truncate)
{
    vfs_node_t *parent = NULL;
    char *name = NULL;

    if (!split_parent_and_name(cwd ? cwd : root, path, &parent, &name))
        return NULL;

    vfs_node_t *file = vfs_find_child(parent, name);
    if (!file)
    {
        if (!create)
        {
            free(name);
            return NULL;
        }
        file = vfs_alloc_node(VFS_NODE_FILE);
        if (!file)
        {
            free(name);
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
        return NULL;

    if (truncate)
    {
        file->size = 0;
        if (!ensure_capacity(file, 0)) return NULL;
        file->data[0] = '\0';
        vfs_mark_node_dirty(file);
    }

    ensure_terminator(file);
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
    if (!split_parent_and_name(cwd ? cwd : root, link_path, &parent, &name))
    {
        return NULL;
    }

    vfs_node_t *existing = vfs_find_child(parent, name);
    if (existing)
    {
        if (existing->type != VFS_NODE_SYMLINK)
        {
            free(name);
            return NULL;
        }
        bool updated = vfs_assign_symlink_target(existing, target_path);
        free(name);
        return updated ? existing : NULL;
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
    vfs_mark_node_dirty(parent);
    vfs_mark_node_dirty(node);
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
    vfs_mark_node_dirty(file);
    return true;
}

bool vfs_append(vfs_node_t *file, const char *data, size_t len)
{
    if (!file || file->type != VFS_NODE_FILE) return false;
    if (!data || len == 0) { ensure_terminator(file); return true; }

    if (!ensure_capacity(file, file->size + len)) return false;

    memmove(file->data + file->size, data, len);
    file->size += len;
    ensure_terminator(file);
    vfs_mark_node_dirty(file);
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
    vfs_mark_node_dirty(file);
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

const char *vfs_data(const vfs_node_t *file, size_t *size)
{
    if (!file || file->type != VFS_NODE_FILE)
    {
        if (size) *size = 0;
        return NULL;
    }
    if (size) *size = file->size;
    return file->data ? file->data : "";
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

    vfs_node_t *parent = NULL;
    char *name = NULL;
    if (!split_parent_and_name(cwd ? cwd : root, path, &parent, &name))
    {
        return false;
    }
    if (!parent)
    {
        free(name);
        return false;
    }

    vfs_node_t *node = vfs_find_child(parent, name);
    free(name);
    if (!node || (node->type != VFS_NODE_FILE && node->type != VFS_NODE_SYMLINK))
    {
        return false;
    }

    vfs_detach_child(node);
    vfs_free_subtree(node);

    vfs_mark_node_dirty(parent);
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

    vfs_node_t *existing = vfs_find_child(dir, name);
    if (existing)
    {
        if (existing->type == VFS_NODE_BLOCK)
        {
            existing->block_device = device;
            return existing;
        }
        return NULL;
    }

    vfs_node_t *node = vfs_alloc_node(VFS_NODE_BLOCK);
    if (!node)
    {
        return NULL;
    }

    node->name = vfs_strdup(name);
    if (!node->name)
    {
        free(node);
        return NULL;
    }
    node->block_device = device;
    node->size = 0;
    node->capacity = 0;
    node->data = NULL;

    vfs_attach_child_tail(dir, node);
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
    if (!device || vfs_device_is_mounted(device))
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
    if (!mount || !mount->device || !mount->mount_point)
    {
        return false;
    }

    size_t node_count = 0;
    size_t payload_size = 0;
    if (!vfs_measure_node(mount->mount_point, mount, true, &node_count, &payload_size))
    {
        return false;
    }
    if (node_count == 0)
    {
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
    header->node_count = 0;
    header->payload_size = 0;
    header->root_id = 0;
    header->reserved[0] = header->reserved[1] = header->reserved[2] = 0;

    size_t offset = sizeof(alixfs_header_t);
    uint32_t next_id = 0;
    if (!vfs_serialize_node(mount->mount_point,
                            mount,
                            true,
                            0xFFFFFFFFu,
                            buffer,
                            buffer_size,
                            &offset,
                            &next_id))
    {
        free(buffer);
        return false;
    }

    size_t payload_written = offset - sizeof(alixfs_header_t);
    if (payload_written > 0xFFFFFFFFu)
    {
        free(buffer);
        return false;
    }

    header->node_count = next_id;
    header->payload_size = (uint32_t)payload_written;

    size_t written_bytes = sizeof(alixfs_header_t) + payload_written;
    uint32_t sectors_to_write = (uint32_t)((written_bytes + sector_size - 1) / sector_size);
    if (sectors_to_write == 0)
    {
        sectors_to_write = 1;
    }
    if (sectors_to_write > sectors_needed)
    {
        free(buffer);
        return false;
    }

    bool can_diff = !force_full &&
                    mount->image_cache &&
                    mount->cache_size == buffer_size &&
                    mount->sector_size == sector_size;
    bool ok = true;

    if (can_diff)
    {
        size_t sectors = buffer_size / sector_size;
        for (size_t s = 0; s < sectors; ++s)
        {
            uint8_t *new_sector = buffer + s * sector_size;
            uint8_t *old_sector = mount->image_cache + s * sector_size;
            if (memcmp(new_sector, old_sector, sector_size) != 0)
            {
                if (!block_write(mount->device, (uint64_t)s, 1, new_sector))
                {
                    ok = false;
                    break;
                }
                memcpy(old_sector, new_sector, sector_size);
            }
        }
    }
    else
    {
        ok = block_write(mount->device, 0, sectors_to_write, buffer);
        if (ok)
        {
            uint8_t *new_cache = (uint8_t *)realloc(mount->image_cache, buffer_size);
            if (!new_cache)
            {
                free(mount->image_cache);
                mount->image_cache = NULL;
                mount->cache_size = 0;
            }
            else
            {
                mount->image_cache = new_cache;
                mount->cache_size = buffer_size;
                mount->sector_size = sector_size;
                memcpy(mount->image_cache, buffer, buffer_size);
            }
        }
    }

    if (!mount->image_cache && ok)
    {
        mount->image_cache = (uint8_t *)malloc(buffer_size);
        if (mount->image_cache)
        {
            memcpy(mount->image_cache, buffer, buffer_size);
            mount->cache_size = buffer_size;
            mount->sector_size = sector_size;
        }
    }

    free(buffer);
    return ok;
}

static bool vfs_mount_writeback(vfs_mount_t *mount, bool force)
{
    if (!mount)
    {
        return true;
    }
    if (!mount->dirty && !force)
    {
        return true;
    }
    if (!vfs_mount_sync(mount, force))
    {
        return false;
    }
    mount->dirty = false;
    vfs_clear_dirty_subtree(mount->mount_point, mount);
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
    if (!mount->dirty)
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

    size_t sector_size = vfs_sector_size(device);
    uint8_t *first_sector = (uint8_t *)malloc(sector_size);
    if (!first_sector)
    {
        return false;
    }

    if (!block_read(device, 0, 1, first_sector))
    {
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
        free(buffer);
        return false;
    }

    alixfs_header_t *header = (alixfs_header_t *)buffer;
    if (memcmp(header->magic, ALIXFS_MAGIC, sizeof(header->magic)) != 0 ||
        header->version != 1 ||
        header->node_count == 0)
    {
        free(buffer);
        return false;
    }

    uint32_t node_count = header->node_count;
    if (header->root_id >= node_count)
    {
        free(buffer);
        return false;
    }

    size_t header_total_bytes = sizeof(alixfs_header_t) + header->payload_size;
    if (header_total_bytes > buffer_size)
    {
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
    bool attached = false;
    size_t offset = sizeof(alixfs_header_t);

    for (uint32_t idx = 0; idx < node_count; ++idx)
    {
        if (offset + sizeof(alixfs_node_disk_t) > header_total_bytes)
        {
            goto cleanup;
        }

        alixfs_node_disk_t disk;
        memcpy(&disk, buffer + offset, sizeof(disk));
        offset += sizeof(disk);

        if (disk.id >= node_count)
        {
            goto cleanup;
        }
        if (nodes[disk.id] && disk.id != header->root_id)
        {
            goto cleanup;
        }
        if (disk.parent_id != 0xFFFFFFFFu && disk.parent_id >= node_count)
        {
            goto cleanup;
        }

        if (offset + disk.name_len > header_total_bytes)
        {
            goto cleanup;
        }
        const uint8_t *name_bytes = buffer + offset;
        offset += disk.name_len;

        if (offset + disk.data_len > header_total_bytes)
        {
            goto cleanup;
        }
        const uint8_t *data_bytes = buffer + offset;
        offset += disk.data_len;

        if (disk.id == header->root_id)
        {
            if (disk.type != VFS_NODE_DIR)
            {
                goto cleanup;
            }
            parents[disk.id] = disk.parent_id;
            continue;
        }

        if (disk.type > VFS_NODE_SYMLINK || disk.name_len == 0)
        {
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
            goto cleanup;
        }

        char *name = (char *)malloc(disk.name_len + 1);
        if (!name)
        {
            vfs_free_subtree(node);
            goto cleanup;
        }
        memcpy(name, name_bytes, disk.name_len);
        name[disk.name_len] = '\0';
        node->name = name;

        if ((node_type == VFS_NODE_FILE || node_type == VFS_NODE_SYMLINK) && disk.data_len > 0)
        {
            size_t cap = (size_t)disk.data_len + 1;
            char *data = (char *)malloc(cap);
            if (!data)
            {
                vfs_free_subtree(node);
                goto cleanup;
            }
            memcpy(data, data_bytes, disk.data_len);
            data[disk.data_len] = '\0';
            node->data = data;
            node->size = disk.data_len;
            node->capacity = cap;
        }

        nodes[disk.id] = node;
        parents[disk.id] = disk.parent_id;
    }

    if (parents[header->root_id] != 0xFFFFFFFFu)
    {
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
            goto cleanup;
        }
        uint32_t parent_id = parents[i];
        if (parent_id >= node_count)
        {
            goto cleanup;
        }
        vfs_node_t *parent = nodes[parent_id];
        if (!parent || parent->type != VFS_NODE_DIR)
        {
            goto cleanup;
        }
        vfs_attach_child_tail(parent, node);
    }

    mount->image_cache = buffer;
    mount->cache_size = buffer_size;
    mount->sector_size = sector_size;
    buffer = NULL;

    attached = true;
    success = true;

cleanup:
    if (!success)
    {
        if (attached)
        {
            vfs_clear_directory(mount->mount_point);
        }
        else
        {
            for (uint32_t i = 0; i < node_count; ++i)
            {
                if (i == header->root_id)
                {
                    continue;
                }
                if (nodes[i])
                {
                    vfs_free_subtree(nodes[i]);
                }
            }
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
    if (vfs_is_mount_point(mount_point))
    {
        return false;
    }
    if (mount_point->first_child)
    {
        return false; /* require empty mount location */
    }
    if (mount_point->mount)
    {
        return false;
    }
    if (vfs_device_is_mounted(device))
    {
        return false;
    }

    vfs_mount_t *mount = (vfs_mount_t *)malloc(sizeof(vfs_mount_t));
    if (!mount)
    {
        return false;
    }

    mount->device = device;
    mount->mount_point = mount_point;
    mount->next = NULL;
    mount->dirty = false;
    mount->image_cache = NULL;
    mount->cache_size = 0;
    mount->sector_size = 0;

    mount_point->mount = mount;

    if (!vfs_load_mount(device, mount))
    {
        mount_point->mount = NULL;
        free(mount);
        return false;
    }

    mount->next = mounts;
    mounts = mount;
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
    for (vfs_mount_t *mount = mounts; mount; mount = mount->next)
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
    for (vfs_mount_t *mount = mounts; mount; mount = mount->next)
    {
        if (!mount->dirty)
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
