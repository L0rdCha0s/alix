#include "types.h"  
#include "vfs.h"
#include "libc.h"
#include "heap.h"

/*
 * Heap-backed VFS:
 *  - Nodes and names allocated dynamically.
 *  - File data grows via realloc (doubling strategy).
 *  - No fixed limits on node count, name length, or file size (bounded by RAM).
 */

struct vfs_node
{
    bool is_dir;
    char *name;                      /* dynamically allocated */
    struct vfs_node *parent;
    struct vfs_node *first_child;
    struct vfs_node *next_sibling;

    /* file payload (unused for directories) */
    size_t size;                     /* bytes used (not incl. '\0') */
    size_t capacity;                 /* bytes allocated in data[] */
    char *data;                      /* dynamically allocated, NUL-terminated when capacity > 0 */
};

static vfs_node_t *root = NULL;

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

static vfs_node_t *vfs_alloc_node(void)
{
    vfs_node_t *n = (vfs_node_t *)calloc(1, sizeof(vfs_node_t));
    return n;
}

static void vfs_attach_child(vfs_node_t *parent, vfs_node_t *child)
{
    if (!parent || !child) return;
    child->parent = parent;
    child->next_sibling = parent->first_child;
    parent->first_child = child;
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

/* Ensure file has room for at least `need` bytes (+1 for trailing NUL). */
static bool ensure_capacity(vfs_node_t *file, size_t need)
{
    if (!file || file->is_dir) return false;

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
    if (!node || node->is_dir) return;
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

/* Resolve existing node by path (no creation). Returns NULL if any component is missing. */
static vfs_node_t *resolve_node(vfs_node_t *cwd, const char *path)
{
    if (!path || !*path) return cwd;

    vfs_node_t *node = (path[0] == '/') ? root : cwd;
    const char *cursor = path;

    cursor = skip_separators(cursor);
    if (*cursor == '\0') return node;

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
            if (node && node->parent) node = node->parent;
            free(component);
            continue;
        }

        vfs_node_t *child = vfs_find_child(node, component);
        free(component);
        if (!child) return NULL;
        node = child;
    }

    return node;
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
    if (!path || !*path) return false;

    vfs_node_t *current = (path[0] == '/') ? root : cwd;
    const char *cursor = path;

    cursor = skip_separators(cursor);
    if (*cursor == '\0') return false;

    char *component = NULL;
    bool saw_any = false;

    while (next_component(&cursor, &component))
    {
        cursor = skip_separators(cursor);
        bool last = (*cursor == '\0');
        saw_any = true;

        if (is_dot(component))
        {
            if (last) { free(component); return false; }
            free(component);
            continue;
        }
        if (is_dot_dot(component))
        {
            if (last) { free(component); return false; }
            if (current && current->parent) current = current->parent;
            free(component);
            continue;
        }

        if (last)
        {
            *parent_out = current;
            *name_out   = component; /* ownership to caller */
            return true;
        }

        vfs_node_t *child = vfs_find_child(current, component);
        if (!child || !child->is_dir)
        {
            free(component);
            return false;
        }
        current = child;
        free(component);
    }

    return saw_any;
}

/* ---------- public API ---------- */

void vfs_init(void)
{
    if (root) return;

    vfs_node_t *node = vfs_alloc_node();
    if (!node) return; /* OOM: VFS disabled */

    node->is_dir = true;
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
        return existing->is_dir ? existing : NULL;
    }

    vfs_node_t *dir = vfs_alloc_node();
    if (!dir)
    {
        free(name);
        return NULL;
    }

    dir->is_dir = true;
    dir->name   = name;   /* take ownership */
    dir->size = 0;
    dir->capacity = 0;
    dir->data = NULL;

    vfs_attach_child(parent, dir);
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
        file = vfs_alloc_node();
        if (!file)
        {
            free(name);
            return NULL;
        }
        file->is_dir = false;
        file->name   = name;   /* take ownership */
        file->size = 0;
        file->capacity = 0;
        file->data = NULL;
        vfs_attach_child(parent, file);
    }
    else
    {
        free(name);
    }

    if (file->is_dir)
        return NULL;

    if (truncate)
    {
        file->size = 0;
        if (!ensure_capacity(file, 0)) return NULL;
        file->data[0] = '\0';
    }

    ensure_terminator(file);
    return file;
}

bool vfs_is_dir(const vfs_node_t *node)
{
    return node ? node->is_dir : false;
}

bool vfs_truncate(vfs_node_t *file)
{
    if (!file || file->is_dir) return false;
    file->size = 0;
    if (!ensure_capacity(file, 0)) return false;
    file->data[0] = '\0';
    return true;
}

bool vfs_append(vfs_node_t *file, const char *data, size_t len)
{
    if (!file || file->is_dir) return false;
    if (!data || len == 0) { ensure_terminator(file); return true; }

    if (!ensure_capacity(file, file->size + len)) return false;

    memmove(file->data + file->size, data, len);
    file->size += len;
    ensure_terminator(file);
    return true;
}

const char *vfs_data(const vfs_node_t *file, size_t *size)
{
    if (!file || file->is_dir)
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

vfs_node_t *vfs_first_child(vfs_node_t *dir)
{
    if (!dir || !dir->is_dir) return NULL;
    return dir->first_child;
}

vfs_node_t *vfs_next_sibling(vfs_node_t *node)
{
    return node ? node->next_sibling : NULL;
}
