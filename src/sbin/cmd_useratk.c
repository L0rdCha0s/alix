#include "shell.h"

#include "vfs.h"
#include "libc.h"
#include "process.h"
#include "types.h"

static const char *const ATK_DEMO_PATH = "/bin/atk_demo";

bool shell_cmd_useratk(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;
    (void)args;

    vfs_node_t *root = vfs_root();
    if (!root)
    {
        return shell_output_error(out, "useratk: filesystem unavailable");
    }

    vfs_node_t *node = vfs_resolve(root, ATK_DEMO_PATH);
    if (!node || !vfs_is_file(node))
    {
        return shell_output_error(out, "useratk: binary not found");
    }

    size_t size = 0;
    const char *data = vfs_data(node, &size);
    if (!data || size == 0)
    {
        return shell_output_error(out, "useratk: empty binary");
    }

    process_t *proc = process_create_user_elf_with_parent("atk_demo",
                                                          (const uint8_t *)data,
                                                          size,
                                                          -1,
                                                          process_current(),
                                                          NULL,
                                                          0);
    if (!proc)
    {
        return shell_output_error(out, "useratk: failed to start process");
    }

    process_join(proc, NULL);
    process_destroy(proc);
    return true;
}
