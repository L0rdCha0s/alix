#include "shell.h"

bool shell_cmd_js(shell_state_t *shell, shell_output_t *out, const char *args)
{
    const char *cursor = args ? args : "";
    while (*cursor == ' ' || *cursor == '\t')
    {
        ++cursor;
    }

    /* The upstream runtime currently has EOF stdin, rather than a TTY. Show
     * usage by default; scripts and -e execute through the real native shell. */
    return shell_execute_binary(shell, out, "/usr/bin/js.elf",
                                *cursor ? cursor : "--help", "js");
}
