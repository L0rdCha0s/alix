#include "shell_commands.h"

#include "libc.h"
#include "net/dns.h"

static const char *dnsdebug_trim(const char *text)
{
    if (!text)
    {
        return "";
    }
    while (*text == ' ' || *text == '\t')
    {
        ++text;
    }
    return text;
}

static void dnsdebug_reply(shell_output_t *out, const char *state)
{
    shell_output_write(out, "dns debug is ");
    shell_output_write(out, state);
    shell_output_write(out, "\n");
}

bool shell_cmd_dnsdebug(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;

    const char *trimmed = dnsdebug_trim(args);
    if (*trimmed == '\0')
    {
        dnsdebug_reply(out, net_dns_debug_enabled() ? "on" : "off");
        return true;
    }

    char option[8];
    size_t opt_len = 0;
    while (trimmed[opt_len] &&
           trimmed[opt_len] != ' ' &&
           trimmed[opt_len] != '\t' &&
           opt_len < sizeof(option) - 1)
    {
        char c = trimmed[opt_len];
        if (c >= 'A' && c <= 'Z')
        {
            c = (char)(c + ('a' - 'A'));
        }
        option[opt_len] = c;
        ++opt_len;
    }
    option[opt_len] = '\0';

    bool enable;
    if (strcmp(option, "on") == 0 || strcmp(option, "1") == 0)
    {
        enable = true;
    }
    else if (strcmp(option, "off") == 0 || strcmp(option, "0") == 0)
    {
        enable = false;
    }
    else
    {
        return shell_output_error(out, "usage: dnsdebug [on|off]");
    }

    net_dns_set_debug(enable);
    dnsdebug_reply(out, enable ? "on" : "off");
    return true;
}
