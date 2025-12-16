#include "shell_commands.h"
#include "libc.h"

bool shell_cmd_echo(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;
    const char *text = (args && *args) ? args : "";
    if (out && out->to_file)
    {
        size_t len = strlen(text);
        size_t total = len + 1; /* include newline */
        char *buffer = (char *)malloc(total);
        if (!buffer)
        {
            return false;
        }
        if (len > 0)
        {
            memcpy(buffer, text, len);
        }
        buffer[len] = '\n';
        bool ok = shell_output_write_len(out, buffer, total);
        free(buffer);
        return ok;
    }

    if (!shell_output_write(out, text))
    {
        return false;
    }
    return shell_output_write(out, "\n");
}
