#include "shell_commands.h"

#include "vfs.h"
#include "io_vfs_service.h"
#include "errno.h"

bool shell_cmd_cd(shell_state_t *shell, shell_output_t *out, const char *path)
{
    if (!shell) return shell_output_error(out, "cd internal error");
    const char *target_path = path && *path ? path : "/";
    int result = io_vfs_change_cwd_kernel(target_path, shell->owner_pid);
    if (result)
    {
        const char *message = result == -ENOENT ? "path not found" :
                              result == -ENOTDIR ? "not a directory" : "unable to change directory";
        return shell_output_error(out, message);
    }
    shell->cwd = process_current_cwd();
    if (shell->cwd_changed_fn) shell->cwd_changed_fn(shell->cwd_changed_context, shell->cwd);
    return true;
}
