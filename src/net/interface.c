#include <stddef.h>

#include "net/interface.h"
#include "net/route.h"

#include "libc.h"

#define NET_MAX_INTERFACES 8

static net_interface_t g_interfaces[NET_MAX_INTERFACES];
static size_t g_interface_count = 0;

void net_if_init(void)
{
    for (size_t i = 0; i < NET_MAX_INTERFACES; ++i)
    {
        memset(&g_interfaces[i], 0, sizeof(net_interface_t));
    }
    g_interface_count = 0;
    net_route_init();
}

static net_interface_t *net_if_allocate(void)
{
    if (g_interface_count >= NET_MAX_INTERFACES)
    {
        return NULL;
    }
    net_interface_t *iface = &g_interfaces[g_interface_count++];
    memset(iface, 0, sizeof(*iface));
    return iface;
}

net_interface_t *net_if_register(const char *name, const uint8_t mac[6])
{
    net_interface_t *existing = net_if_by_name(name);
    if (existing)
    {
        if (mac)
        {
            memcpy(existing->mac, mac, 6);
            existing->present = true;
        }
        return existing;
    }

    net_interface_t *iface = net_if_allocate();
    if (!iface)
    {
        return NULL;
    }

    size_t len = strlen(name);
    if (len >= NET_IF_NAME_MAX)
    {
        len = NET_IF_NAME_MAX - 1;
    }
    memcpy(iface->name, name, len);
    iface->name[len] = '\0';
    iface->present = true;
    iface->link_up = false;
    iface->ipv4_addr = 0;
    iface->ipv4_netmask = 0;
   iface->ipv4_gateway = 0;
   iface->send = NULL;
    iface->poll = NULL;
    if (mac)
    {
        memcpy(iface->mac, mac, 6);
    }
    else
    {
        memset(iface->mac, 0, 6);
    }
    return iface;
}

net_interface_t *net_if_by_name(const char *name)
{
    if (!name)
    {
        return NULL;
    }
    for (size_t i = 0; i < g_interface_count; ++i)
    {
        if (strcmp(g_interfaces[i].name, name) == 0)
        {
            return &g_interfaces[i];
        }
    }
    return NULL;
}

size_t net_if_count(void)
{
    return g_interface_count;
}

net_interface_t *net_if_at(size_t index)
{
    if (index >= g_interface_count)
    {
        return NULL;
    }
    return &g_interfaces[index];
}

void net_if_set_link_up(net_interface_t *iface, bool up)
{
    if (!iface)
    {
        return;
    }
    iface->link_up = up;
}

void net_if_set_ipv4(net_interface_t *iface, uint32_t addr, uint32_t netmask, uint32_t gateway)
{
    if (!iface)
    {
        return;
    }
    iface->ipv4_addr = addr;
    iface->ipv4_netmask = netmask;
    iface->ipv4_gateway = gateway;

    if (gateway != 0)
    {
        net_route_set_default(iface, gateway);
    }
    else
    {
        net_interface_t *default_iface = NULL;
        if (net_route_get_default(&default_iface, NULL) && default_iface == iface)
        {
            net_route_clear_default();
        }
    }
}

void net_if_set_tx_handler(net_interface_t *iface, bool (*handler)(net_interface_t *, const uint8_t *, size_t))
{
    if (!iface)
    {
        return;
    }
    iface->send = handler;
}

void net_if_set_poll_handler(net_interface_t *iface, void (*handler)(net_interface_t *))
{
    if (!iface)
    {
        return;
    }
    iface->poll = handler;
}

bool net_if_send(net_interface_t *iface, const uint8_t *data, size_t len)
{
    if (!iface || !iface->send)
    {
        return false;
    }
    return iface->send(iface, data, len);
}

void net_if_poll_all(void)
{
    for (size_t i = 0; i < g_interface_count; ++i)
    {
        net_interface_t *iface = &g_interfaces[i];
        if (!iface->present || !iface->poll)
        {
            continue;
        }
        iface->poll(iface);
    }
}

static void write_hex_byte(uint8_t value, char *out)
{
    static const char hex[] = "0123456789ABCDEF";
    out[0] = hex[(value >> 4) & 0xF];
    out[1] = hex[value & 0xF];
}

void net_format_mac(const uint8_t mac[6], char *out)
{
    for (int i = 0; i < 6; ++i)
    {
        write_hex_byte(mac[i], out + i * 2);
    }
    out[12] = '\0';
}

void net_format_ipv4(uint32_t addr, char *out)
{
    char *ptr = out;
    for (int i = 3; i >= 0; --i)
    {
        uint8_t byte = (uint8_t)((addr >> (i * 8)) & 0xFF);
        if (byte >= 100)
        {
            *ptr++ = (char)('0' + (byte / 100));
            byte %= 100;
        }
        if (byte >= 10 || (ptr != out && *(ptr - 1) != '.'))
        {
            *ptr++ = (char)('0' + (byte / 10));
            byte %= 10;
        }
        *ptr++ = (char)('0' + byte);
        if (i != 0)
        {
            *ptr++ = '.';
        }
    }
    *ptr = '\0';
}

bool net_parse_ipv4(const char *text, uint32_t *out_addr)
{
    if (!text || !out_addr)
    {
        return false;
    }

    uint32_t result = 0;
    uint32_t value = 0;
    int octets = 0;
    bool have_digit = false;
    const char *cursor = text;

    while (true)
    {
        char c = *cursor;
        if (c >= '0' && c <= '9')
        {
            have_digit = true;
            value = value * 10U + (uint32_t)(c - '0');
            if (value > 255U)
            {
                return false;
            }
            ++cursor;
        }
        else if (c == '.' || c == '\0')
        {
            if (!have_digit)
            {
                return false;
            }
            result = (result << 8) | value;
            ++octets;
            if (octets > 4)
            {
                return false;
            }
            if (c == '\0')
            {
                break;
            }
            value = 0;
            have_digit = false;
            ++cursor;
        }
        else
        {
            return false;
        }
    }

    if (octets != 4)
    {
        return false;
    }

    *out_addr = result;
    return true;
}
