#include "shell_commands.h"

#include "net/interface.h"
#include "console.h"
#include "serial.h"

bool shell_cmd_net_mac(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;
    (void)out;
    (void)args;

    net_interface_t *iface = net_if_by_name("rtl0");
    if (!iface)
    {
        shell_print_error("network device not present");
        return false;
    }

    console_write("rtl8139 mac: ");
    serial_write_string("rtl8139 mac: ");
    for (int i = 0; i < 6; ++i)
    {
        static const char hex[] = "0123456789ABCDEF";
        char bytes[3];
        bytes[0] = hex[(iface->mac[i] >> 4) & 0xF];
        bytes[1] = hex[iface->mac[i] & 0xF];
        bytes[2] = '\0';
        console_write(bytes);
        serial_write_string(bytes);
        if (i != 5)
        {
            console_putc(':');
            serial_write_char(':');
        }
    }
    console_putc('\n');
    serial_write_string("\r\n");
    return true;
}
