#include <stddef.h>

#include "shell_commands.h"

#include "libc.h"
#include "vfs.h"

static size_t ls_write_number(char *buffer, size_t capacity, size_t value)
{
    if (!buffer || capacity == 0)
    {
        return 0;
    }
    char temp[32];
    size_t pos = 0;
    do
    {
        temp[pos++] = (char)('0' + (value % 10));
        value /= 10;
    } while (value > 0 && pos < sizeof(temp));

    size_t written = 0;
    while (pos > 0 && written + 1 < capacity)
    {
        buffer[written++] = temp[--pos];
    }
    buffer[written] = '\0';
    return written;
}

static void ls_format_size(size_t size, bool human, char *buffer, size_t capacity)
{
    if (!buffer || capacity == 0)
    {
        return;
    }

    const char *units[] = { "B", "K", "M", "G" };
    if (!human || size < 1024)
    {
        ls_write_number(buffer, capacity, size);
        return;
    }

    size_t value = size;
    size_t unit_index = 0;
    while (value >= 1024 && unit_index + 1 < sizeof(units) / sizeof(units[0]))
    {
        value /= 1024;
        unit_index++;
    }
    size_t written = ls_write_number(buffer, capacity, value);
    if (written + 2 < capacity)
    {
        buffer[written++] = units[unit_index][0];
        buffer[written] = '\0';
    }
}

bool shell_cmd_ls(shell_state_t *shell, shell_output_t *out, const char *args)
{
    if (!shell || !out)
    {
        return false;
    }

    bool long_format = false;
    bool human = false;
    char path_buf[256];
    bool have_path = false;

    const char *cursor = args ? args : "";
    while (*cursor)
    {
        while (*cursor == ' ' || *cursor == '\t')
        {
            ++cursor;
        }
        if (*cursor == '\0')
        {
            break;
        }
        if (*cursor == '-')
        {
            ++cursor;
            while (*cursor && *cursor != ' ' && *cursor != '\t')
            {
                if (*cursor == 'l')
                {
                    long_format = true;
                }
                else if (*cursor == 'h')
                {
                    human = true;
                }
                else
                {
                    return shell_output_error(out, "ls: unknown flag");
                }
                ++cursor;
            }
        }
        else
        {
            const char *start = cursor;
            while (*cursor && *cursor != ' ' && *cursor != '\t')
            {
                ++cursor;
            }
            size_t len = (size_t)(cursor - start);
            if (len >= sizeof(path_buf))
            {
                len = sizeof(path_buf) - 1;
            }
            memcpy(path_buf, start, len);
            path_buf[len] = '\0';
            have_path = true;
        }
    }

    vfs_node_t *target = have_path ? vfs_resolve(shell->cwd, path_buf) : shell->cwd;
    if (!target)
    {
        return shell_output_error(out, "path not found");
    }
    if (!vfs_is_dir(target))
    {
        return shell_output_error(out, "path is not a directory");
    }

    for (vfs_node_t *child = vfs_first_child(target); child; child = vfs_next_sibling(child))
    {
        const char *name = vfs_name(child);
        if (!name)
        {
            name = "";
        }
        shell_output_write(out, name);

        char suffix = 0;
        if (vfs_is_dir(child))
        {
            suffix = '/';
        }
        else if (vfs_is_block(child))
        {
            suffix = '@';
        }

        if (suffix)
        {
            char s[2] = { suffix, '\0' };
            shell_output_write(out, s);
        }

        if (long_format)
        {
            size_t size = 0;
            vfs_node_type_t type = vfs_node_type(child);
            if (vfs_stat(child, &size, &type))
            {
                char size_buf[32];
                ls_format_size(size, human, size_buf, sizeof(size_buf));
                shell_output_write(out, "  ");
                shell_output_write(out, size_buf);
                if (!human)
                {
                    shell_output_write(out, " bytes");
                }
            }
        }
        shell_output_write(out, "\n");
    }
    return true;
}
