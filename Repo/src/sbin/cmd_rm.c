#include "shell_commands.h"

#include "libc.h"
#include "vfs.h"

static bool is_rm_space(char c)
{
    return c == ' ' || c == '\t';
}

static bool rm_has_wildcard(const char *text)
{
    if (!text)
    {
        return false;
    }
    while (*text)
    {
        if (*text == '*' || *text == '?')
        {
            return true;
        }
        ++text;
    }
    return false;
}

bool shell_cmd_rm(shell_state_t *shell, shell_output_t *out, const char *path)
{
    const char *cursor = (path && *path) ? path : "";
    bool any = false;
    bool all_ok = true;

    while (*cursor)
    {
        while (is_rm_space(*cursor))
        {
            ++cursor;
        }
        if (*cursor == '\0')
        {
            break;
        }

        const char *start = cursor;
        while (*cursor && !is_rm_space(*cursor))
        {
            ++cursor;
        }
        size_t len = (size_t)(cursor - start);
        char *target = (char *)malloc(len + 1);
        if (!target)
        {
            return shell_output_error(out, "rm: out of memory");
        }
        memcpy(target, start, len);
        target[len] = '\0';
        any = true;

        if (!vfs_remove_file(shell ? shell->cwd : vfs_root(), target))
        {
            if (rm_has_wildcard(target))
            {
                free(target);
                continue;
            }
            all_ok = false;
            shell_output_write(out, "Error: rm failed for ");
            shell_output_write(out, target);
            shell_output_write(out, "\n");
        }

        free(target);
    }

    if (!any)
    {
        return shell_output_error(out, "rm needs a file path");
    }

    return all_ok;
}
