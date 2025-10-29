#include "shell_commands.h"

#include "net/interface.h"
#include "net/dhcp.h"
#include "libc.h"

bool shell_cmd_dhclient(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;

    if (!args || *args == '\0')
    {
        shell_print_error("dhclient needs an interface name");
        return false;
    }

    char name[NET_IF_NAME_MAX];
    size_t len = strlen(args);
    if (len >= NET_IF_NAME_MAX)
    {
        len = NET_IF_NAME_MAX - 1;
    }
    memcpy(name, args, len);
    name[len] = '\0';

    net_interface_t *iface = net_if_by_name(name);
    if (!iface)
    {
        shell_print_error("interface not found");
        return false;
    }

    if (!net_dhcp_acquire(iface))
    {
        shell_print_error("dhcp acquire failed");
        return false;
    }

    shell_output_write(out, "DHCP discovery started for ");
    shell_output_write(out, name);
    shell_output_write(out, "\n");
    return true;
}
