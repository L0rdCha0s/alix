#include "shell_commands.h"
#include "libc.h"

bool shell_cmd_echo(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;
    const char *text = (args && *args) ? args : "";
    if (!shell_output_write(out, text))
    {
        return false;
    }
    return shell_output_write(out, "\n");
}
