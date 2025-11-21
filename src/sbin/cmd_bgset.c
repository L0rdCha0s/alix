#include "shell_commands.h"

#include "libc.h"
#include "video.h"
#include "vfs.h"
#include "atk_internal.h"

static const char *bgset_skip_ws(const char *s)
{
    while (s && (*s == ' ' || *s == '\t'))
    {
        ++s;
    }
    return s;
}

bool shell_cmd_bgset(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;
    const char *path = bgset_skip_ws(args);
    if (!path || *path == '\0')
    {
        return shell_output_error(out, "bgset needs a full png path");
    }
    if (*path != '/')
    {
        return shell_output_error(out, "bgset requires an absolute path");
    }

    vfs_node_t *root = vfs_root();
    if (!root)
    {
        return shell_output_error(out, "vfs unavailable");
    }

    vfs_mkdir(root, "/etc");
    vfs_mkdir(root, "/etc/display");
    vfs_node_t *file = vfs_open_file(root, "/etc/display/background", true, true);
    if (!file)
    {
        return shell_output_error(out, "failed to open /etc/display/background");
    }

    size_t len = strlen(path);
    if (!vfs_truncate(file))
    {
        return shell_output_error(out, "failed to truncate background file");
    }
    if (len > 0)
    {
        ssize_t written = vfs_write_at(file, 0, path, len);
        if (written < 0 || (size_t)written != len)
        {
            return shell_output_error(out, "failed to write background path");
        }
    }

    shell_output_write(out, "Background path updated\n");

    if (video_is_active())
    {
        atk_dirty_mark_all();
        video_request_refresh();
        video_pump_events();
    }
    return true;
}
