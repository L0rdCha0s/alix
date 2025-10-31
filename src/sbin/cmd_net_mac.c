#include "shell_commands.h"

#include "net/interface.h"

bool shell_cmd_net_mac(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;
    (void)args;

    net_interface_t *iface = net_if_by_name("rtl0");
    if (!iface)
    {
        return shell_output_error(out, "network device not present");
    }

    shell_output_write(out, "rtl8139 mac: ");
    for (int i = 0; i < 6; ++i)
    {
        static const char hex[] = "0123456789ABCDEF";
        char bytes[3];
        bytes[0] = hex[(iface->mac[i] >> 4) & 0xF];
        bytes[1] = hex[iface->mac[i] & 0xF];
        bytes[2] = '\0';
        shell_output_write(out, bytes);
        if (i != 5)
        {
            shell_output_write(out, ":");
        }
    }
    shell_output_write(out, "\n");
    return true;
}
