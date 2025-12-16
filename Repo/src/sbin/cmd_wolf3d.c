#include "shell.h"

#include "libc.h"
#include "process.h"
#include "types.h"
#include "vfs.h"

static const char *const WOLF3D_PATH = "/bin/wolf3d";

bool shell_cmd_wolf3d(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;
    (void)args;

    vfs_node_t *root = vfs_root();
    if (!root)
    {
        return shell_output_error(out, "wolf3d: filesystem unavailable");
    }

    vfs_node_t *node = vfs_resolve(root, WOLF3D_PATH);
    if (!node || !vfs_is_file(node))
    {
        return shell_output_error(out, "wolf3d: binary not found");
    }

    size_t size = 0;
    char *data = vfs_data(node, &size);
    if (!data || size == 0)
    {
        return shell_output_error(out, "wolf3d: empty binary");
    }

    process_t *proc = process_create_user_elf_with_parent("wolf3d",
                                                          (const uint8_t *)data,
                                                          size,
                                                          -1,
                                                          process_current(),
                                                          NULL,
                                                          0);
    if (!proc)
    {
        return shell_output_error(out, "wolf3d: failed to start process");
    }

    process_join(proc, NULL);
    process_destroy(proc);
    return true;
}
