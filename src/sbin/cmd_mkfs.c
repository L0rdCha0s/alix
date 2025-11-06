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

bool shell_cmd_mkfs(shell_state_t *shell, shell_output_t *out, const char *args)
{
    if (!shell || !out)
    {
        return false;
    }

    const char *cursor = args ? args : "";
    char *device_path = next_token(&cursor);
    char *extra = next_token(&cursor);
    if (!device_path || extra)
    {
        if (device_path) free(device_path);
        if (extra) free(extra);
        return shell_output_error(out, "mkfs <device>");
    }

    vfs_node_t *device_node = vfs_resolve(shell->cwd, device_path);
    if (!device_node || !vfs_is_block(device_node))
    {
        free(device_path);
        return shell_output_error(out, "mkfs device must be a block node");
    }

    block_device_t *device = vfs_block_device(device_node);
    if (!device)
    {
        free(device_path);
        return shell_output_error(out, "block device unavailable");
    }

    if (!vfs_format(device))
    {
        free(device_path);
        return shell_output_error(out, "mkfs failed");
    }

    shell_output_write(out, "mkfs complete\n");

    free(device_path);
    return true;
}
