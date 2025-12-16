#include "shell_commands.h"

#include "power.h"
#include "vfs.h"

bool shell_cmd_shutdown(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;
    (void)args;

    shell_output_write(out, "Syncing disks... ");
    if (!vfs_sync_all())
    {
        return shell_output_error(out, "failed to sync mounted filesystems");
    }
    shell_output_write(out, "done\n");

    shell_output_write(out, "Powering off...\n");
    power_shutdown();
    return true;
}
