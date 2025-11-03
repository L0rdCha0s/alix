#include "shell_commands.h"

#include "net/interface.h"
#include "net/dhcp.h"
#include "timer.h"
#include "libc.h"

bool shell_cmd_dhclient(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;

    if (!args || *args == '\0')
    {
        return shell_output_error(out, "dhclient needs an interface name");
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
        return shell_output_error(out, "interface not found");
    }

    if (!net_dhcp_acquire(iface))
    {
        return shell_output_error(out, "dhcp acquire failed");
    }

    shell_output_write(out, "DHCP discovery started for ");
    shell_output_write(out, name);
    shell_output_write(out, "\n");

    uint64_t start = timer_ticks();
    uint64_t timeout = timer_frequency() * 5; /* wait up to ~5 seconds */
    while (net_dhcp_in_progress())
    {
        net_if_poll_all();
        if (iface->ipv4_addr != 0)
        {
            break;
        }
        uint64_t elapsed = timer_ticks() - start;
        if (timeout != 0 && elapsed >= timeout)
        {
            break;
        }
    }

    if (iface->ipv4_addr != 0)
    {
        char ipbuf[32];
        net_format_ipv4(iface->ipv4_addr, ipbuf);
        shell_output_write(out, "DHCP lease acquired: ");
        shell_output_write(out, ipbuf);
        shell_output_write(out, "\n");
    }
    else
    {
        shell_output_write(out, "DHCP still in progress...\n");
    }

    return true;
}
