#include "shell.h"

#include "libc.h"
#include "process.h"
#include "types.h"
#include "vfs.h"

static const char *const QUAKE_PATH = "/usr/bin/quake";
static const char *const QUAKE_PATH_FALLBACK = "/bin/quake";

bool shell_cmd_quake(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;
    (void)args;

    vfs_node_t *root = vfs_root();
    if (!root)
    {
        return shell_output_error(out, "quake: filesystem unavailable");
    }

    vfs_node_t *node = vfs_resolve(root, QUAKE_PATH);
    if (!node)
    {
        node = vfs_resolve(root, QUAKE_PATH_FALLBACK);
    }
    if (!node || !vfs_is_file(node))
    {
        return shell_output_error(out, "quake: binary not found");
    }

    size_t size = 0;
    char *data = vfs_data(node, &size);
    if (!data || size == 0)
    {
        return shell_output_error(out, "quake: empty binary");
    }

    process_t *proc = process_create_user_elf_with_parent("quake",
                                                          (const uint8_t *)data,
                                                          size,
                                                          -1,
                                                          process_current(),
                                                          NULL,
                                                          0);
    if (!proc)
    {
        return shell_output_error(out, "quake: failed to start process");
    }

    process_join(proc, NULL);
    process_destroy(proc);
    return true;
}

