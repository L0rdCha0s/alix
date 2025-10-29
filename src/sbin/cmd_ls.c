#include <stddef.h>

#include "shell_commands.h"

#include "serial.h"
#include "vfs.h"
#include "libc.h"

bool shell_cmd_ls(shell_state_t *shell, shell_output_t *out, const char *path)
{
    vfs_node_t *target = NULL;

    serial_write_char('{');
    serial_write_hex64((uint64_t)shell);
    serial_write_char('/');
    serial_write_hex64((uint64_t)shell->cwd);
    serial_write_char('}');

    serial_write_string("Trying path..\n");
    serial_write_string("...");

    if (!path || *path == '\0')
    {
        target = shell->cwd;
    }
    else
    {
        target = vfs_resolve(shell->cwd, path);
    }

    serial_write_string("In shell command ls\n");

    if (!target)
    {
        shell_print_error("path not found");
        return false;
    }
    if (!vfs_is_dir(target))
    {
        shell_print_error("path is not a directory");
        return false;
    }

    serial_write_string("In shell command ls 2\n");
    for (vfs_node_t *child = vfs_first_child(target); child; child = vfs_next_sibling(child))
    {
        shell_output_write(out, vfs_name(child));
        if (vfs_is_dir(child))
        {
            shell_output_write(out, "/");
        }
        shell_output_write(out, "\n");
    }
    return true;
}
