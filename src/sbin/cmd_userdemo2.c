#include "shell.h"

#include "vfs.h"
#include "libc.h"
#include "process.h"
#include "types.h"

static const char *const USERDEMO2_PATH = "/bin/userdemo2";

bool shell_cmd_userdemo2(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;
    (void)args;

    vfs_node_t *root = vfs_root();
    if (!root)
    {
        return shell_output_error(out, "userdemo2: root filesystem unavailable");
    }

    vfs_node_t *node = vfs_resolve(root, USERDEMO2_PATH);
    if (!node || !vfs_is_file(node))
    {
        return shell_output_error(out, "userdemo2: binary not found");
    }

    size_t size = 0;
    const char *data = vfs_data(node, &size);
    if (!data || size == 0)
    {
        return shell_output_error(out, "userdemo2: empty binary");
    }

    process_t *proc = process_create_user_elf_with_parent("userdemo2",
                                                          (const uint8_t *)data,
                                                          size,
                                                          -1,
                                                          process_current());
    if (!proc)
    {
        return shell_output_error(out, "userdemo2: failed to start process");
    }

    process_join(proc, NULL);
    return true;
}
