#include "shell_commands.h"

#include "vfs.h"
#include "libc.h"

bool shell_cmd_cat(shell_state_t *shell, shell_output_t *out, const char *path)
{
    (void)out;
    if (!path || *path == '\0')
    {
        shell_print_error("cat needs a path");
        return false;
    }

    vfs_node_t *node = vfs_resolve(shell->cwd, path);
    if (!node)
    {
        shell_print_error("file not found");
        return false;
    }
    if (vfs_is_dir(node))
    {
        shell_print_error("path is a directory");
        return false;
    }

    size_t size = 0;
    const char *data = vfs_data(node, &size);
    if (!data)
    {
        return true;
    }
    if (!shell_output_write_len(out, data, size))
    {
        shell_print_error("write failed");
        return false;
    }
    if (!out->to_file && (size == 0 || data[size - 1] != '\n'))
    {
        shell_output_write(out, "\n");
    }
    return true;
}
