#include "shell.h"
#include "logger.h"
#include "vfs.h"

bool shell_cmd_logcat(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;
    (void)args;

    vfs_node_t *file = vfs_resolve(vfs_root(), LOGGER_FILE_PATH);
    if (!file || !vfs_is_file(file))
    {
        return shell_output_error(out, "log file not available");
    }

    size_t size = 0;
    char *data = vfs_data(file, &size);
    if (!data)
    {
        return shell_output_error(out, "unable to read log");
    }

    if (size == 0)
    {
        shell_output_write(out, "<log empty>\n");
        return true;
    }

    return shell_output_write_len(out, data, size);
}
