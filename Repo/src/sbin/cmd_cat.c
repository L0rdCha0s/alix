#include "shell_commands.h"

#include "vfs.h"
#include "libc.h"

#define CAT_CHUNK_SIZE 4096

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

    char *buffer = (char *)malloc(CAT_CHUNK_SIZE);
    if (!buffer)
    {
        return shell_output_error(out, "out of memory");
    }

    size_t snapshot_size = 0;
    bool limit_read = vfs_stat(node, &snapshot_size, NULL, NULL, NULL, NULL) && snapshot_size > 0;

    size_t offset = 0;
    bool saw_data = false;
    char last_char = '\0';
    while (1)
    {
        if (limit_read && offset >= snapshot_size)
        {
            break;
        }
        size_t to_read = CAT_CHUNK_SIZE;
        if (limit_read)
        {
            size_t remaining = snapshot_size - offset;
            if (remaining < to_read)
            {
                to_read = remaining;
            }
        }
        if (to_read == 0)
        {
            break;
        }
        ssize_t read = vfs_read_at(node, offset, buffer, to_read);
        if (read < 0)
        {
            free(buffer);
            return shell_output_error(out, "read failed");
        }
        if (read == 0)
        {
            break;
        }
        if (!shell_output_write_len(out, buffer, (size_t)read))
        {
            free(buffer);
            return shell_output_error(out, "write failed");
        }
        saw_data = true;
        last_char = buffer[read - 1];
        offset += (size_t)read;
    }

    free(buffer);

    if (!out->to_file && (!saw_data || last_char != '\n'))
    {
        shell_output_write(out, "\n");
    }
    return true;
}
