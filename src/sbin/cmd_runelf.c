#include "shell.h"

#include "vfs.h"
#include "libc.h"
#include "process.h"

static const char *skip_spaces(const char *text)
{
    while (text && (*text == ' ' || *text == '\t'))
    {
        ++text;
    }
    return text;
}

static char *extract_path_argument(const char *args)
{
    const char *start = skip_spaces(args ? args : "");
    if (!start || *start == '\0')
    {
        return NULL;
    }

    const char *end = start;
    while (*end && *end != ' ' && *end != '\t')
    {
        ++end;
    }

    size_t length = (size_t)(end - start);
    char *path = (char *)malloc(length + 1);
    if (!path)
    {
        return NULL;
    }
    memcpy(path, start, length);
    path[length] = '\0';
    return path;
}

bool shell_cmd_runelf(shell_state_t *shell, shell_output_t *out, const char *args)
{
    char *path = extract_path_argument(args);
    if (!path)
    {
        return shell_output_error(out, "runelf: path required");
    }

    vfs_node_t *cwd = (shell && shell->cwd) ? shell->cwd : vfs_root();
    vfs_node_t *node = vfs_resolve(cwd, path);
    if (!node)
    {
        /* allow absolute paths even if cwd is NULL */
        node = vfs_resolve(vfs_root(), path);
    }

    if (!node || !vfs_is_file(node))
    {
        free(path);
        return shell_output_error(out, "runelf: file not found");
    }

    size_t size = 0;
    const char *data = vfs_data(node, &size);
    if (!data || size == 0)
    {
        free(path);
        return shell_output_error(out, "runelf: empty file");
    }

    process_t *proc = process_create_user_elf_with_parent(path,
                                                          (const uint8_t *)data,
                                                          size,
                                                          -1,
                                                          process_current());
    free(path);

    if (!proc)
    {
        return shell_output_error(out, "runelf: failed to start process");
    }

    process_join(proc, NULL);
    return true;
}
