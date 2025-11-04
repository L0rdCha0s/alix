#include "shell_commands.h"

#include "crypto/sha1.h"
#include "vfs.h"
#include "libc.h"

static const char *skip_ws(const char *s)
{
    while (s && (*s == ' ' || *s == '\t'))
    {
        ++s;
    }
    return s;
}

bool shell_cmd_sha1sum(shell_state_t *shell, shell_output_t *out, const char *args)
{
    const char *path = skip_ws(args);
    if (!path || *path == '\0')
    {
        return shell_output_error(out, "sha1sum needs a path");
    }

    vfs_node_t *node = vfs_resolve(shell->cwd, path);
    if (!node)
    {
        return shell_output_error(out, "file not found");
    }
    if (vfs_is_dir(node))
    {
        return shell_output_error(out, "path is a directory");
    }

    size_t size = 0;
    const char *data = vfs_data(node, &size);
    if (!data)
    {
        return shell_output_error(out, "unable to read file");
    }

    sha1_ctx_t ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data, size);
    uint8_t digest[20];
    sha1_final(&ctx, digest);

    char hex[41];
    static const char hexchars[] = "0123456789abcdef";
    for (int i = 0; i < 20; ++i)
    {
        hex[i * 2 + 0] = hexchars[(digest[i] >> 4) & 0xF];
        hex[i * 2 + 1] = hexchars[digest[i] & 0xF];
    }
    hex[40] = '\0';

    shell_output_write(out, hex);
    shell_output_write(out, "  ");
    shell_output_write(out, path);
    shell_output_write(out, "\n");
    return true;
}
