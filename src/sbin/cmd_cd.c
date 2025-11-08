#include "shell_commands.h"

#include "vfs.h"

bool shell_cmd_cd(shell_state_t *shell, shell_output_t *out, const char *path)
{
    if (!shell)
    {
        return shell_output_error(out, "cd internal error");
    }

    const char *target_path = path;
    if (!target_path || *target_path == '\0')
    {
        shell->cwd = vfs_root();
        return true;
    }

    vfs_node_t *target = vfs_resolve(shell->cwd, target_path);
    if (!target)
    {
        return shell_output_error(out, "path not found");
    }
    if (!vfs_is_dir(target))
    {
        return shell_output_error(out, "not a directory");
    }

    shell->cwd = target;
    process_set_cwd(process_current(), target);
    if (shell && shell->owner_process)
    {
        process_set_cwd(shell->owner_process, target);
    }
    return true;
}
