#include "shell_commands.h"

#include "vfs.h"
#include "libc.h"

bool shell_cmd_cat(shell_state_t *shell, shell_output_t *out, const char *path)
{
    if (!path || *path == '\0')
    {
        return shell_output_error(out, "cat needs a path");
    }

    vfs_node_t *node = vfs_resolve(shell->cwd, path);
    if (!node)
    {
        return shell_output_error(out, "file not found");
    }
    if (vfs_is_dir(node))
    {
        return shell_output_error(out, "path is a directory");
    }
    if (vfs_is_block(node))
    {
        return shell_output_error(out, "path is a block device");
    }

    size_t size = 0;
    const char *data = vfs_data(node, &size);
    if (!data)
    {
        return true;
    }
    if (!shell_output_write_len(out, data, size))
    {
        return shell_output_error(out, "write failed");
    }
    if (!out->to_file && (size == 0 || data[size - 1] != '\n'))
    {
        shell_output_write(out, "\n");
    }
    return true;
}
