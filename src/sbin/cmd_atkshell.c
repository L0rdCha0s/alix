#include "shell.h"

#include "vfs.h"
#include "libc.h"
#include "process.h"

static const char *const ATK_SHELL_PATH = "/bin/atk_shell";

bool shell_cmd_atkshell(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;
    (void)args;

    vfs_node_t *root = vfs_root();
    if (!root)
    {
        return shell_output_error(out, "atkshell: filesystem unavailable");
    }

    vfs_node_t *node = vfs_resolve(root, ATK_SHELL_PATH);
    if (!node || !vfs_is_file(node))
    {
        return shell_output_error(out, "atkshell: binary not found");
    }

    size_t size = 0;
    const char *data = vfs_data(node, &size);
    if (!data || size == 0)
    {
        return shell_output_error(out, "atkshell: empty binary");
    }

    process_t *proc = process_create_user_elf_with_parent("atk_shell",
                                                          (const uint8_t *)data,
                                                          size,
                                                          -1,
                                                          process_current(),
                                                          NULL,
                                                          0);
    if (!proc)
    {
        return shell_output_error(out, "atkshell: failed to start process");
    }

    process_join(proc, NULL);
    process_destroy(proc);
    return true;
}
