#include "shell_commands.h"

#include "libc.h"
#include "vfs.h"

bool shell_cmd_pwd(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)args;
    if (!shell || !out)
    {
        return false;
    }

    char path[256];
    vfs_node_t *cwd = shell->cwd ? shell->cwd : vfs_root();
    size_t written = vfs_build_path(cwd, path, sizeof(path));
    if (written == 0 || written >= sizeof(path))
    {
        return shell_output_error(out, "pwd: path too long");
    }

    return shell_output_write_len(out, path, written) &&
           shell_output_write(out, "\n");
}

