#include <stddef.h>
#include "vfs.h"
#include "libc.h"
#include "serial.h"


#define VFS_POOL_BASE      0x0000000001000000ULL /* 16 MiB, safely past firmware/VGA */
#define VFS_MAX_NODES      512
#define VFS_NAME_MAX       32
#define VFS_FILE_CAPACITY  4096

struct vfs_node
{
    bool used;
    bool is_dir;
    char name[VFS_NAME_MAX];
    struct vfs_node *parent;
    struct vfs_node *first_child;
    struct vfs_node *next_sibling;
    size_t size;
    size_t capacity;
    char data[VFS_FILE_CAPACITY];
};

#define VFS_POOL_SIZE      (sizeof(struct vfs_node) * VFS_MAX_NODES)

static struct vfs_node *const nodes = (struct vfs_node *)VFS_POOL_BASE;
static vfs_node_t *root = NULL;

static void vfs_zero_node(vfs_node_t *node)
{
    if (!node)
    {
        return;
    }
    node->used = false;
    node->is_dir = false;
    node->name[0] = '\0';
    node->parent = NULL;
    node->first_child = NULL;
    node->next_sibling = NULL;
    node->size = 0;
    node->capacity = VFS_FILE_CAPACITY;
    node->data[0] = '\0';
}

static vfs_node_t *vfs_alloc_node(void)
{
    for (size_t i = 0; i < VFS_MAX_NODES; ++i)
    {
        if (!nodes[i].used)
        {
            nodes[i].used = true;
            nodes[i].size = 0;
            nodes[i].capacity = VFS_FILE_CAPACITY;
            nodes[i].data[0] = '\0';
            nodes[i].first_child = NULL;
            nodes[i].next_sibling = NULL;
            nodes[i].parent = NULL;
            nodes[i].name[0] = '\0';
            serial_write_char('A');
            serial_write_hex64((uint64_t)&nodes[i]);
            serial_write_char('\n');
            return &nodes[i];
        }
    }
    return NULL;
}

static void vfs_attach_child(vfs_node_t *parent, vfs_node_t *child)
{
    if (!parent || !child)
    {
        return;
    }
    child->parent = parent;
    child->next_sibling = parent->first_child;
    parent->first_child = child;
}

static vfs_node_t *vfs_find_child(vfs_node_t *parent, const char *name)
{
    if (!parent)
    {
        return NULL;
    }
    vfs_node_t *node = parent->first_child;
    while (node)
    {
        if (strcmp(node->name, name) == 0)
        {
            return node;
        }
        node = node->next_sibling;
    }
    return NULL;
}

static const char *skip_separators(const char *path)
{
    while (*path == '/')
    {
        ++path;
    }
    return path;
}

static bool next_component(const char **path_ptr, char *out)
{
    const char *path = skip_separators(*path_ptr);
    if (*path == '\0')
    {
        *path_ptr = path;
        return false;
    }

    size_t len = 0;
    while (*path && *path != '/')
    {
        if (len < VFS_NAME_MAX - 1)
        {
            out[len++] = *path;
        }
        ++path;
    }
    out[len] = '\0';
    *path_ptr = path;
    return true;
}

static bool is_dot(const char *name)
{
    return name[0] == '.' && name[1] == '\0';
}

static bool is_dot_dot(const char *name)
{
    return name[0] == '.' && name[1] == '.' && name[2] == '\0';
}

static void copy_name(char *dst, const char *src)
{
    size_t i = 0;
    for (; i < VFS_NAME_MAX - 1 && src[i]; ++i)
    {
        dst[i] = src[i];
    }
    dst[i] = '\0';
}

static vfs_node_t *resolve_node(vfs_node_t *cwd, const char *path)
{
    serial_write_char('1');
    if (!path || !*path)
    {
        return cwd;
    }

    vfs_node_t *node = (path[0] == '/') ? root : cwd;
    const char *cursor = path;
    char component[VFS_NAME_MAX];

    cursor = skip_separators(cursor);
    if (*cursor == '\0')
    {
        return node;
    }

    while (next_component(&cursor, component))
    {
        cursor = skip_separators(cursor);
        if (is_dot(component))
        {
            continue;
        }
        if (is_dot_dot(component))
        {
            if (node && node->parent)
            {
                node = node->parent;
            }
            continue;
        }

        vfs_node_t *child = vfs_find_child(node, component);
        if (!child)
        {
            return NULL;
        }
        node = child;
    }

    return node;
}

static bool split_parent_and_name(vfs_node_t *cwd, const char *path, vfs_node_t **parent_out, char *name_out)
{
    if (!path || !*path)
    {
        return false;
    }

    vfs_node_t *current = (path[0] == '/') ? root : cwd;
    const char *cursor = path;
    char component[VFS_NAME_MAX];
    bool found_component = false;

    cursor = skip_separators(cursor);
    if (*cursor == '\0')
    {
        return false;
    }

    while (next_component(&cursor, component))
    {
        cursor = skip_separators(cursor);
        bool last = (*cursor == '\0');

        if (is_dot(component) || is_dot_dot(component))
        {
            if (last)
            {
                return false;
            }

            if (is_dot_dot(component) && current && current->parent)
            {
                current = current->parent;
            }
            continue;
        }

        found_component = true;

        if (last)
        {
            copy_name(name_out, component);
            *parent_out = current;
            return true;
        }

        vfs_node_t *child = vfs_find_child(current, component);
        if (!child || !child->is_dir)
        {
            return false;
        }
        current = child;
    }

    return found_component;
}

void vfs_init(void)
{
    memset(nodes, 0, VFS_POOL_SIZE);
    for (size_t i = 0; i < VFS_MAX_NODES; ++i)
    {
        vfs_zero_node(&nodes[i]);
    }

    serial_write_char('Z');
    for (int i = 0; i < 8; ++i)
    {
        uint8_t byte = ((uint8_t *)&nodes[0])[i];
        static const char hex[] = "0123456789ABCDEF";
        serial_write_char(hex[(byte >> 4) & 0xF]);
        serial_write_char(hex[byte & 0xF]);
    }
    serial_write_char('\n');

    serial_write_char('U');
    serial_write_hex64((uint64_t)root);
    serial_write_char('\n');
    vfs_node_t *node = vfs_alloc_node();
    serial_write_char('N');
    serial_write_hex64((uint64_t)node);
    serial_write_char('\n');
    root = node;
    serial_write_char('0');
    serial_write_hex64((uint64_t)root);
    serial_write_char('\n');
    root = (vfs_node_t *)0x12345678ULL;
    serial_write_char('1');
    serial_write_hex64((uint64_t)root);
    serial_write_char('\n');
    root = node;
    serial_write_char('B');
    static const char hex[] = "0123456789ABCDEF";
    uint8_t *root_bytes = (uint8_t *)&root;
    for (int i = 0; i < 8; ++i)
    {
        uint8_t byte = root_bytes[i];
        serial_write_char(hex[(byte >> 4) & 0xF]);
        serial_write_char(hex[byte & 0xF]);
    }
    serial_write_char('\n');
    if (root)
    {
        root->is_dir = true;
        root->parent = NULL;
        root->name[0] = '/';
        root->name[1] = '\0';
        serial_write_char('R');
        serial_write_hex64((uint64_t)root);
        serial_write_char('\n');
    }
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
    char name[VFS_NAME_MAX];
    if (!split_parent_and_name(cwd ? cwd : root, path, &parent, name))
    {
        return NULL;
    }

    vfs_node_t *existing = vfs_find_child(parent, name);
    if (existing)
    {
        return existing->is_dir ? existing : NULL;
    }

    vfs_node_t *dir = vfs_alloc_node();
    if (!dir)
    {
        return NULL;
    }

    dir->is_dir = true;
    copy_name(dir->name, name);
    dir->size = 0;
    dir->data[0] = '\0';
    vfs_attach_child(parent, dir);
    return dir;
}

static void ensure_terminator(vfs_node_t *node)
{
    if (!node)
    {
        return;
    }
    if (node->size < node->capacity)
    {
        node->data[node->size] = '\0';
    }
    else if (node->capacity > 0)
    {
        node->data[node->capacity - 1] = '\0';
    }
}

vfs_node_t *vfs_open_file(vfs_node_t *cwd, const char *path, bool create, bool truncate)
{
    vfs_node_t *parent = NULL;
    char name[VFS_NAME_MAX];
    if (!split_parent_and_name(cwd ? cwd : root, path, &parent, name))
    {
        return NULL;
    }

    vfs_node_t *file = vfs_find_child(parent, name);
    if (!file)
    {
        if (!create)
        {
            return NULL;
        }
        file = vfs_alloc_node();
        if (!file)
        {
            return NULL;
        }
        file->is_dir = false;
        copy_name(file->name, name);
        file->size = 0;
        file->data[0] = '\0';
        vfs_attach_child(parent, file);
    }

    if (file->is_dir)
    {
        return NULL;
    }

    if (truncate)
    {
        file->size = 0;
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
    if (!file || file->is_dir)
    {
        return false;
    }
    file->size = 0;
    file->data[0] = '\0';
    return true;
}

bool vfs_append(vfs_node_t *file, const char *data, size_t len)
{
    if (!file || file->is_dir)
    {
        return false;
    }
    if (file->size + len > file->capacity)
    {
        return false;
    }
    memmove(file->data + file->size, data, len);
    file->size += len;
    ensure_terminator(file);
    return true;
}

const char *vfs_data(const vfs_node_t *file, size_t *size)
{
    if (!file || file->is_dir)
    {
        if (size)
        {
            *size = 0;
        }
        return NULL;
    }
    if (size)
    {
        *size = file->size;
    }
    return file->data;
}

const char *vfs_name(const vfs_node_t *node)
{
    return node ? node->name : NULL;
}

vfs_node_t *vfs_first_child(vfs_node_t *dir)
{
    serial_write_char('3');
    if (!dir || !dir->is_dir)
    {
        serial_write_char('4');
        return NULL;
    }

    serial_write_char('5');
    return dir->first_child;
}

vfs_node_t *vfs_next_sibling(vfs_node_t *node)
{
    serial_write_char('6');
    return node ? node->next_sibling : NULL;
}
