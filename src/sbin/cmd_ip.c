#include "shell_commands.h"

#include <stddef.h>

#include "net/arp.h"
#include "net/interface.h"
#include "net/route.h"
#include "libc.h"

static bool ip_handle_link(shell_output_t *out, const char *args);
static bool ip_handle_addr(shell_output_t *out, const char *args);
static bool ip_handle_route(shell_output_t *out, const char *args);
static bool ip_addr_show(shell_output_t *out, const char *args);
static bool ip_addr_set(shell_output_t *out, const char *args);
static void ip_print_interface(shell_output_t *out, const net_interface_t *iface);
static void write_mac(shell_output_t *out, const uint8_t mac[6]);
static void write_uint(shell_output_t *out, unsigned value);
static const char *skip_ws(const char *cursor);
static bool parse_prefix(const char *text, unsigned *prefix_out);
static uint32_t netmask_from_prefix(unsigned prefix);
static int prefix_from_netmask(uint32_t netmask);
static uint32_t broadcast_from_ipv4(uint32_t addr, uint32_t netmask);
static bool ip_route_show(shell_output_t *out);
static bool ip_route_set_default(shell_output_t *out, const char *args);
static bool ip_route_clear_default(shell_output_t *out);

bool shell_cmd_ip(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;
    const char *cursor = args ? args : "";
    cursor = skip_ws(cursor);

    if (*cursor == '\0')
    {
        return ip_handle_link(out, "show");
    }

    if (strncmp(cursor, "link", 4) == 0)
    {
        cursor += 4;
        cursor = skip_ws(cursor);
        return ip_handle_link(out, cursor);
    }

    if (strncmp(cursor, "addr", 4) == 0)
    {
        cursor += 4;
        cursor = skip_ws(cursor);
        return ip_handle_addr(out, cursor);
    }

    if (strncmp(cursor, "route", 5) == 0)
    {
        cursor += 5;
        cursor = skip_ws(cursor);
        return ip_handle_route(out, cursor);
    }

    shell_print_error("Usage: ip (link|addr|route) [args]");
    return false;
}

static bool ip_handle_link(shell_output_t *out, const char *args)
{
    (void)args;
    size_t count = net_if_count();
    if (count == 0)
    {
        return shell_output_write(out, "No network interfaces detected\n");
    }

    for (size_t i = 0; i < count; ++i)
    {
        net_interface_t *iface = net_if_at(i);
        if (!iface)
        {
            continue;
        }
        write_uint(out, (unsigned)(i + 1));
        shell_output_write(out, ": ");
        shell_output_write(out, iface->name);
        shell_output_write(out, iface->link_up ? ": <UP> mtu 1500 qdisc noop state UP\n    link/ether " : ": <DOWN> mtu 1500 qdisc noop state DOWN\n    link/ether ");
        write_mac(out, iface->mac);
        shell_output_write(out, " brd ff:ff:ff:ff:ff:ff\n");
    }
    return true;
}

static bool ip_handle_addr(shell_output_t *out, const char *args)
{
    const char *cursor = skip_ws(args ? args : "");
    const char *cmd_start = cursor;
    while (*cursor && *cursor != ' ' && *cursor != '\t')
    {
        ++cursor;
    }

    size_t cmd_len = (size_t)(cursor - cmd_start);
    if (cmd_len == 0)
    {
        shell_print_error("Usage: ip addr (show|set) ...");
        return false;
    }

    if (cmd_len == 4 && strncmp(cmd_start, "show", 4) == 0)
    {
        return ip_addr_show(out, cursor);
    }
    if (cmd_len == 3 && strncmp(cmd_start, "set", 3) == 0)
    {
        return ip_addr_set(out, cursor);
    }

    shell_print_error("Usage: ip addr (show|set) ...");
    return false;
}

static bool ip_addr_show(shell_output_t *out, const char *args)
{
    const char *cursor = skip_ws(args);
    if (*cursor == '\0')
    {
        shell_print_error("Usage: ip addr show <iface>");
        return false;
    }

    size_t name_len = 0;
    while (cursor[name_len] && cursor[name_len] != ' ' && cursor[name_len] != '\t')
    {
        ++name_len;
    }
    if (name_len == 0 || name_len >= NET_IF_NAME_MAX)
    {
        shell_print_error("invalid interface name");
        return false;
    }

    char name[NET_IF_NAME_MAX];
    memcpy(name, cursor, name_len);
    name[name_len] = '\0';
    cursor += name_len;
    cursor = skip_ws(cursor);
    if (*cursor != '\0')
    {
        shell_print_error("Usage: ip addr show <iface>");
        return false;
    }

    net_interface_t *iface = net_if_by_name(name);
    if (!iface)
    {
        shell_print_error("interface not found");
        return false;
    }

    ip_print_interface(out, iface);
    return true;
}

static bool ip_addr_set(shell_output_t *out, const char *args)
{
    const char *cursor = skip_ws(args);
    if (*cursor == '\0')
    {
        shell_print_error("Usage: ip addr set <iface> <addr>[/prefix] [netmask]");
        return false;
    }

    size_t name_len = 0;
    while (cursor[name_len] && cursor[name_len] != ' ' && cursor[name_len] != '\t')
    {
        ++name_len;
    }
    if (name_len == 0 || name_len >= NET_IF_NAME_MAX)
    {
        shell_print_error("invalid interface name");
        return false;
    }

    char name[NET_IF_NAME_MAX];
    memcpy(name, cursor, name_len);
    name[name_len] = '\0';
    cursor += name_len;

    net_interface_t *iface = net_if_by_name(name);
    if (!iface)
    {
        shell_print_error("interface not found");
        return false;
    }

    cursor = skip_ws(cursor);
    if (*cursor == '\0')
    {
        shell_print_error("Usage: ip addr set <iface> <addr>[/prefix] [netmask]");
        return false;
    }

    char addr_token[32];
    size_t addr_len = 0;
    while (cursor[addr_len] && cursor[addr_len] != ' ' && cursor[addr_len] != '\t')
    {
        ++addr_len;
    }
    if (addr_len == 0 || addr_len >= sizeof(addr_token))
    {
        shell_print_error("invalid IPv4 address");
        return false;
    }
    memcpy(addr_token, cursor, addr_len);
    addr_token[addr_len] = '\0';
    cursor += addr_len;

    uint32_t addr_value = 0;
    uint32_t netmask_value = 0;
    bool netmask_set = false;

    char *slash = NULL;
    for (size_t i = 0; addr_token[i] != '\0'; ++i)
    {
        if (addr_token[i] == '/')
        {
            slash = &addr_token[i];
            break;
        }
    }

    if (slash)
    {
        *slash = '\0';
        const char *prefix_text = slash + 1;
        unsigned prefix = 0;
        if (!net_parse_ipv4(addr_token, &addr_value))
        {
            shell_print_error("invalid IPv4 address");
            return false;
        }
        if (!parse_prefix(prefix_text, &prefix))
        {
            shell_print_error("invalid prefix length");
            return false;
        }
        netmask_value = netmask_from_prefix(prefix);
        netmask_set = true;
    }
    else
    {
        if (!net_parse_ipv4(addr_token, &addr_value))
        {
            shell_print_error("invalid IPv4 address");
            return false;
        }
    }

    cursor = skip_ws(cursor);
    if (!netmask_set)
    {
        if (*cursor == '\0')
        {
            shell_print_error("Usage: ip addr set <iface> <addr>[/prefix] [netmask]");
            return false;
        }
        char mask_token[32];
        size_t mask_len = 0;
        while (cursor[mask_len] && cursor[mask_len] != ' ' && cursor[mask_len] != '\t')
        {
            ++mask_len;
        }
        if (mask_len == 0 || mask_len >= sizeof(mask_token))
        {
            shell_print_error("invalid netmask");
            return false;
        }
        memcpy(mask_token, cursor, mask_len);
        mask_token[mask_len] = '\0';
        if (!net_parse_ipv4(mask_token, &netmask_value))
        {
            shell_print_error("invalid netmask");
            return false;
        }
        cursor += mask_len;
        cursor = skip_ws(cursor);
    }

    if (*cursor != '\0')
    {
        shell_print_error("Usage: ip addr set <iface> <addr>[/prefix] [netmask]");
        return false;
    }

    net_if_set_ipv4(iface, addr_value, netmask_value, iface->ipv4_gateway);
    net_arp_flush();

    ip_print_interface(out, iface);
    return true;
}

static bool ip_handle_route(shell_output_t *out, const char *args)
{
    const char *cursor = skip_ws(args ? args : "");
    const char *cmd_start = cursor;
    while (*cursor && *cursor != ' ' && *cursor != '\t')
    {
        ++cursor;
    }

    size_t cmd_len = (size_t)(cursor - cmd_start);
    if (cmd_len == 0)
    {
        shell_print_error("Usage: ip route (show|set|clear) ...");
        return false;
    }

    if (cmd_len == 4 && strncmp(cmd_start, "show", 4) == 0)
    {
        cursor = skip_ws(cursor);
        if (*cursor != '\0')
        {
            shell_print_error("Usage: ip route show");
            return false;
        }
        return ip_route_show(out);
    }

    if (cmd_len == 3 && strncmp(cmd_start, "set", 3) == 0)
    {
        return ip_route_set_default(out, cursor);
    }

    if (cmd_len == 5 && strncmp(cmd_start, "clear", 5) == 0)
    {
        cursor = skip_ws(cursor);
        if (*cursor != '\0')
        {
            shell_print_error("Usage: ip route clear");
            return false;
        }
        return ip_route_clear_default(out);
    }

    shell_print_error("Usage: ip route (show|set|clear) ...");
    return false;
}

static bool ip_route_show(shell_output_t *out)
{
    net_interface_t *iface = NULL;
    uint32_t gateway = 0;
    if (!net_route_get_default(&iface, &gateway) || !iface)
    {
        return shell_output_write(out, "No default route configured\n");
    }

    char gw_buf[32];
    net_format_ipv4(gateway, gw_buf);
    shell_output_write(out, "default via ");
    shell_output_write(out, gw_buf);
    shell_output_write(out, " dev ");
    shell_output_write(out, iface->name);
    shell_output_write(out, "\n");
    return true;
}

static bool ip_route_set_default(shell_output_t *out, const char *args)
{
    const char *cursor = skip_ws(args);
    const char *token = cursor;
    while (*cursor && *cursor != ' ' && *cursor != '\t')
    {
        ++cursor;
    }
    size_t token_len = (size_t)(cursor - token);
    if (token_len == 0 || strncmp(token, "default", token_len) != 0)
    {
        shell_print_error("Usage: ip route set default <iface> <gateway>");
        return false;
    }

    cursor = skip_ws(cursor);
    if (*cursor == '\0')
    {
        shell_print_error("Usage: ip route set default <iface> <gateway>");
        return false;
    }

    char name[NET_IF_NAME_MAX];
    size_t name_len = 0;
    while (cursor[name_len] && cursor[name_len] != ' ' && cursor[name_len] != '\t')
    {
        ++name_len;
    }
    if (name_len == 0 || name_len >= NET_IF_NAME_MAX)
    {
        shell_print_error("invalid interface name");
        return false;
    }
    memcpy(name, cursor, name_len);
    name[name_len] = '\0';
    cursor += name_len;

    net_interface_t *iface = net_if_by_name(name);
    if (!iface || !iface->present)
    {
        shell_print_error("interface not found");
        return false;
    }

    cursor = skip_ws(cursor);
    if (*cursor == '\0')
    {
        shell_print_error("Usage: ip route set default <iface> <gateway>");
        return false;
    }

    char gateway_token[32];
    size_t gateway_len = 0;
    while (cursor[gateway_len] && cursor[gateway_len] != ' ' && cursor[gateway_len] != '\t')
    {
        ++gateway_len;
    }
    if (gateway_len == 0 || gateway_len >= sizeof(gateway_token))
    {
        shell_print_error("invalid gateway address");
        return false;
    }
    memcpy(gateway_token, cursor, gateway_len);
    gateway_token[gateway_len] = '\0';
    cursor += gateway_len;
    cursor = skip_ws(cursor);
    if (*cursor != '\0')
    {
        shell_print_error("Usage: ip route set default <iface> <gateway>");
        return false;
    }

    uint32_t gateway = 0;
    if (!net_parse_ipv4(gateway_token, &gateway))
    {
        shell_print_error("invalid gateway address");
        return false;
    }

    if (!net_route_set_default(iface, gateway))
    {
        shell_print_error("failed to set default route");
        return false;
    }

    char gw_buf[32];
    net_format_ipv4(gateway, gw_buf);
    shell_output_write(out, "default via ");
    shell_output_write(out, gw_buf);
    shell_output_write(out, " dev ");
    shell_output_write(out, iface->name);
    shell_output_write(out, "\n");
    return true;
}

static bool ip_route_clear_default(shell_output_t *out)
{
    net_interface_t *iface = NULL;
    bool had_route = net_route_get_default(&iface, NULL);
    if (!had_route)
    {
        return shell_output_write(out, "No default route configured\n");
    }

    net_route_clear_default();
    return shell_output_write(out, "default route cleared\n");
}

static void ip_print_interface(shell_output_t *out, const net_interface_t *iface)
{
    shell_output_write(out, "inet ");
    if (!iface || iface->ipv4_addr == 0)
    {
        shell_output_write(out, "unassigned scope global ");
        shell_output_write(out, iface ? iface->name : "unknown");
        shell_output_write(out, "\n");
        return;
    }

    char addr_buf[32];
    net_format_ipv4(iface->ipv4_addr, addr_buf);
    shell_output_write(out, addr_buf);
    shell_output_write(out, "/");
    int prefix = prefix_from_netmask(iface->ipv4_netmask);
    write_uint(out, (unsigned)prefix);

    shell_output_write(out, " brd ");
    char brd_buf[32];
    net_format_ipv4(broadcast_from_ipv4(iface->ipv4_addr, iface->ipv4_netmask), brd_buf);
    shell_output_write(out, brd_buf);
    shell_output_write(out, " scope global ");
    shell_output_write(out, iface->name);
    shell_output_write(out, "\n");

    if (iface->ipv4_gateway)
    {
        shell_output_write(out, "    default via ");
        char gw_buf[32];
        net_format_ipv4(iface->ipv4_gateway, gw_buf);
        shell_output_write(out, gw_buf);
        shell_output_write(out, "\n");
    }
}

static void write_mac(shell_output_t *out, const uint8_t mac[6])
{
    static const char hex[] = "0123456789ABCDEF";
    for (int i = 0; i < 6; ++i)
    {
        char buf[3];
        buf[0] = hex[(mac[i] >> 4) & 0xF];
        buf[1] = hex[mac[i] & 0xF];
        buf[2] = '\0';
        shell_output_write(out, buf);
        if (i != 5)
        {
            shell_output_write(out, ":");
        }
    }
}

static void write_uint(shell_output_t *out, unsigned value)
{
    char buf[12];
    int pos = 0;
    if (value == 0)
    {
        buf[pos++] = '0';
    }
    else
    {
        while (value > 0 && pos < (int)(sizeof(buf) - 1))
        {
            buf[pos++] = (char)('0' + (value % 10U));
            value /= 10U;
        }
    }
    for (int i = pos - 1; i >= 0; --i)
    {
        shell_output_write_len(out, &buf[i], 1);
    }
}

static const char *skip_ws(const char *cursor)
{
    while (*cursor == ' ' || *cursor == '\t')
    {
        ++cursor;
    }
    return cursor;
}

static bool parse_prefix(const char *text, unsigned *prefix_out)
{
    if (!text || !*text || !prefix_out)
    {
        return false;
    }
    unsigned value = 0;
    const char *cursor = text;
    while (*cursor)
    {
        if (*cursor < '0' || *cursor > '9')
        {
            return false;
        }
        value = value * 10U + (unsigned)(*cursor - '0');
        if (value > 32U)
        {
            return false;
        }
        ++cursor;
    }
    *prefix_out = value;
    return true;
}

static uint32_t netmask_from_prefix(unsigned prefix)
{
    if (prefix == 0)
    {
        return 0;
    }
    if (prefix >= 32)
    {
        return 0xFFFFFFFFU;
    }
    return 0xFFFFFFFFU << (32 - prefix);
}

static int prefix_from_netmask(uint32_t netmask)
{
    if (netmask == 0)
    {
        return 0;
    }
    int bits = 0;
    for (int i = 31; i >= 0; --i)
    {
        if ((netmask >> i) & 1U)
        {
            ++bits;
        }
        else
        {
            break;
        }
    }
    return bits;
}

static uint32_t broadcast_from_ipv4(uint32_t addr, uint32_t netmask)
{
    return addr | ~netmask;
}
