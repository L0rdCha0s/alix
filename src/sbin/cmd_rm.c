#include "shell_commands.h"

#include "vfs.h"

bool shell_cmd_rm(shell_state_t *shell, shell_output_t *out, const char *path)
{
    if (!path || *path == '\0')
    {
        return shell_output_error(out, "rm needs a file path");
    }
    if (!vfs_remove_file(shell ? shell->cwd : vfs_root(), path))
    {
        return shell_output_error(out, "rm failed");
    }
    return true;
}
