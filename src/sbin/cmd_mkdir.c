#include "shell_commands.h"

#include "vfs.h"

bool shell_cmd_mkdir(shell_state_t *shell, shell_output_t *out, const char *path)
{
    (void)out;
    if (!path || *path == '\0')
    {
        shell_print_error("mkdir needs a path");
        return false;
    }
    if (!vfs_mkdir(shell->cwd, path))
    {
        shell_print_error("mkdir failed");
        return false;
    }
    return true;
}
