#include "shell_commands.h"

#include "net/interface.h"
#include "net/dhcp.h"
#include "rtl8139.h"
#include "timer.h"
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

    uint64_t start = timer_ticks();
    uint64_t timeout = timer_frequency() * 5; /* wait up to ~5 seconds */
    while (net_dhcp_in_progress())
    {
        rtl8139_poll();
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
