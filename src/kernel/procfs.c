#include "procfs.h"

#include "libc.h"
#include "serial.h"
#include "vfs.h"

static vfs_node_t *g_proc_dir = NULL;

static vfs_node_t *procfs_ensure_dir_path(const char *path)
{
    if (!g_proc_dir)
    {
        return NULL;
    }
    if (!path || *path == '\0')
    {
        return g_proc_dir;
    }

    vfs_node_t *current = g_proc_dir;
    const char *cursor = path;
    while (*cursor)
    {
        while (*cursor == '/')
        {
            ++cursor;
        }
        if (*cursor == '\0')
        {
            break;
        }

        const char *start = cursor;
        while (*cursor && *cursor != '/')
        {
            ++cursor;
        }
        size_t len = (size_t)(cursor - start);
        char *component = (char *)malloc(len + 1);
        if (!component)
        {
            return NULL;
        }
        memcpy(component, start, len);
        component[len] = '\0';

        vfs_node_t *next = vfs_mkdir(current, component);
        free(component);
        if (!next)
        {
            return NULL;
        }
        current = next;
    }
    return current;
}

void procfs_init(void)
{
    if (g_proc_dir)
    {
        return;
    }
    vfs_node_t *root = vfs_root();
    if (!root)
    {
        serial_printf("%s", "[procfs] missing VFS root\r\n");
        return;
    }

    g_proc_dir = vfs_mkdir(root, "proc");
    if (!g_proc_dir)
    {
        serial_printf("%s", "[procfs] failed to create /proc\r\n");
        return;
    }

    vfs_set_subtree_mutable(g_proc_dir, true);
}

vfs_node_t *procfs_root(void)
{
    return g_proc_dir;
}

vfs_node_t *procfs_mkdir(const char *path)
{
    if (!g_proc_dir)
    {
        return NULL;
    }
    return procfs_ensure_dir_path(path);
}

vfs_node_t *procfs_create_file(const char *name,
                               vfs_read_cb_t read_cb,
                               vfs_write_cb_t write_cb,
                               void *context)
{
    return procfs_create_file_at(name, read_cb, write_cb, context);
}

vfs_node_t *procfs_create_file_at(const char *path,
                                  vfs_read_cb_t read_cb,
                                  vfs_write_cb_t write_cb,
                                  void *context)
{
    if (!g_proc_dir || !path)
    {
        return NULL;
    }

    const char *filename = path;
    vfs_node_t *parent = g_proc_dir;
    char *dir_path = NULL;

    const char *slash = NULL;
    for (const char *p = path; *p; ++p)
    {
        if (*p == '/')
        {
            slash = p;
        }
    }
    if (slash)
    {
        size_t dir_len = (size_t)(slash - path);
        if (dir_len > 0)
        {
            dir_path = (char *)malloc(dir_len + 1);
            if (!dir_path)
            {
                return NULL;
            }
            memcpy(dir_path, path, dir_len);
            dir_path[dir_len] = '\0';
            parent = procfs_ensure_dir_path(dir_path);
            free(dir_path);
            if (!parent)
            {
                return NULL;
            }
        }
        filename = slash + 1;
    }

    if (!filename || *filename == '\0')
    {
        return NULL;
    }

    vfs_node_t *file = vfs_open_file(parent, filename, true, true);
    if (!file)
    {
        return NULL;
    }

    if (!vfs_set_file_callbacks(file, read_cb, write_cb, context))
    {
        return NULL;
    }

    return file;
}
