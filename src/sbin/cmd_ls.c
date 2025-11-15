#include <stddef.h>

#include "shell_commands.h"

#include "serial.h"
#include "vfs.h"
#include "libc.h"

bool shell_cmd_ls(shell_state_t *shell, shell_output_t *out, const char *path)
{
    vfs_node_t *target = NULL;

    serial_printf("%c", '{');
    serial_printf("%016llX", (unsigned long long)((uint64_t)shell));
    serial_printf("%c", '/');
    serial_printf("%016llX", (unsigned long long)((uint64_t)shell->cwd));
    serial_printf("%c", '}');

    serial_printf("%s", "Trying path..\n");
    serial_printf("%s", "...");

    if (!path || *path == '\0')
    {
        target = shell->cwd;
    }
    else
    {
        target = vfs_resolve(shell->cwd, path);
    }

    serial_printf("%s", "In shell command ls\n");

    if (!target)
    {
        return shell_output_error(out, "path not found");
    }
    if (!vfs_is_dir(target))
    {
        return shell_output_error(out, "path is not a directory");
    }

    serial_printf("%s", "In shell command ls 2\n");
    for (vfs_node_t *child = vfs_first_child(target); child; child = vfs_next_sibling(child))
    {
        const char *name = vfs_name(child);
        shell_output_write(out, name ? name : "");
        if (vfs_is_dir(child))
        {
            shell_output_write(out, "/");
        }
        else if (vfs_is_block(child))
        {
            shell_output_write(out, "@");
        }
        shell_output_write(out, "\n");
    }
    return true;
}
