#include "shell_commands.h"

#include "vfs.h"
#include "libc.h"

static char *next_token(const char **cursor)
{
    if (!cursor || !*cursor)
    {
        return NULL;
    }
    const char *p = *cursor;
    while (*p == ' ' || *p == '\t')
    {
        ++p;
    }
    if (*p == '\0')
    {
        *cursor = p;
        return NULL;
    }
    const char *start = p;
    while (*p && *p != ' ' && *p != '\t')
    {
        ++p;
    }
    size_t len = (size_t)(p - start);
    char *token = (char *)malloc(len + 1);
    if (!token)
    {
        *cursor = p;
        return NULL;
    }
    memcpy(token, start, len);
    token[len] = '\0';
    while (*p == ' ' || *p == '\t')
    {
        ++p;
    }
    *cursor = p;
    return token;
}

bool shell_cmd_mount(shell_state_t *shell, shell_output_t *out, const char *args)
{
    if (!shell || !out)
    {
        return false;
    }

    const char *cursor = args ? args : "";
    char *device_path = next_token(&cursor);
    char *target_path = next_token(&cursor);
    char *extra = next_token(&cursor);

    if (!device_path && !target_path && !extra)
    {
        /* List mounts. */
        size_t total = vfs_snapshot_mounts(NULL, 0);
        if (total == 0)
        {
            return shell_output_write(out, "no mounts\n");
        }
        vfs_mount_info_t *entries = (vfs_mount_info_t *)calloc(total, sizeof(vfs_mount_info_t));
        if (!entries)
        {
            return shell_output_error(out, "out of memory");
        }
        size_t filled = vfs_snapshot_mounts(entries, total);
        for (size_t i = 0; i < filled; ++i)
        {
            char path_buf[256];
            size_t len = vfs_build_path(entries[i].mount_point, path_buf, sizeof(path_buf));
            (void)len;
            const char *dev = (entries[i].device && entries[i].device->name[0]) ? entries[i].device->name : "(none)";
            char line[320];
            size_t pos = 0;
            size_t dev_len = strlen(dev);
            if (dev_len >= sizeof(line)) dev_len = sizeof(line) - 1;
            memmove(line + pos, dev, dev_len);
            pos += dev_len;
            const char arrow[] = " -> ";
            size_t arrow_len = sizeof(arrow) - 1;
            if (pos + arrow_len < sizeof(line))
            {
                memmove(line + pos, arrow, arrow_len);
                pos += arrow_len;
            }
            size_t path_len = strlen(path_buf);
            if (path_len >= sizeof(line) - pos) path_len = sizeof(line) - pos - 1;
            memmove(line + pos, path_buf, path_len);
            pos += path_len;
            if (entries[i].dirty && pos + 16 < sizeof(line))
            {
                const char *dirty = entries[i].needs_full_sync ? " (dirty,full)" : " (dirty)";
                size_t dlen = strlen(dirty);
                if (dlen >= sizeof(line) - pos) dlen = sizeof(line) - pos - 1;
                memmove(line + pos, dirty, dlen);
                pos += dlen;
            }
            if (pos < sizeof(line) - 1)
            {
                line[pos++] = '\n';
            }
            line[pos] = '\0';
            shell_output_write(out, line);
        }
        free(entries);
        return true;
    }

    if (!device_path || !target_path || extra)
    {
        if (device_path) free(device_path);
        if (target_path) free(target_path);
        if (extra) free(extra);
        return shell_output_error(out, "mount <device> <path>");
    }

    vfs_node_t *device_node = vfs_resolve(shell->cwd, device_path);
    if (!device_node || !vfs_is_block(device_node))
    {
        free(device_path);
        free(target_path);
        return shell_output_error(out, "mount device must be a block node");
    }

    block_device_t *device = vfs_block_device(device_node);
    if (!device)
    {
        free(device_path);
        free(target_path);
        return shell_output_error(out, "block device unavailable");
    }

    vfs_node_t *target_dir = vfs_mkdir(shell->cwd, target_path);
    if (!target_dir || !vfs_is_dir(target_dir))
    {
        free(device_path);
        free(target_path);
        return shell_output_error(out, "mount path must resolve to a directory");
    }
    if (vfs_is_mount_point(target_dir))
    {
        free(device_path);
        free(target_path);
        return shell_output_error(out, "mount point already in use");
    }

    if (!vfs_mount_device(device, target_dir))
    {
        free(device_path);
        free(target_path);
        return shell_output_error(out, "mount failed");
    }

    shell_output_write(out, "mount complete\n");

    free(device_path);
    free(target_path);
    return true;
}
