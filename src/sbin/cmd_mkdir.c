#include "shell_commands.h"

#include "vfs.h"

bool shell_cmd_mkdir(shell_state_t *shell, shell_output_t *out, const char *path)
{
    if (!path || *path == '\0')
    {
        return shell_output_error(out, "mkdir needs a path");
    }
    if (!vfs_mkdir(shell->cwd, path))
    {
        return shell_output_error(out, "mkdir failed");
    }
    return true;
}
