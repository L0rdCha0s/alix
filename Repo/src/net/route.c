#include "net/route.h"

#include <stddef.h>

#include "libc.h"

typedef struct
{
    bool valid;
    char iface_name[NET_IF_NAME_MAX];
    uint32_t gateway;
} net_default_route_t;

static net_default_route_t g_default_route;

static bool net_route_same_network(net_interface_t *iface, uint32_t ip);

void net_route_init(void)
{
    g_default_route.valid = false;
    g_default_route.gateway = 0;
    g_default_route.iface_name[0] = '\0';
}

bool net_route_set_default(net_interface_t *iface, uint32_t gateway)
{
    if (!iface || gateway == 0)
    {
        return false;
    }

    if (g_default_route.valid)
    {
        net_interface_t *old_iface = net_if_by_name(g_default_route.iface_name);
        if (old_iface)
        {
            old_iface->ipv4_gateway = 0;
        }
    }

    size_t len = strlen(iface->name);
    if (len >= NET_IF_NAME_MAX)
    {
        len = NET_IF_NAME_MAX - 1;
    }
    memcpy(g_default_route.iface_name, iface->name, len);
    g_default_route.iface_name[len] = '\0';
    g_default_route.gateway = gateway;
    g_default_route.valid = true;

    iface->ipv4_gateway = gateway;
    return true;
}

void net_route_clear_default(void)
{
    if (g_default_route.valid)
    {
        net_interface_t *iface = net_if_by_name(g_default_route.iface_name);
        if (iface)
        {
            iface->ipv4_gateway = 0;
        }
    }
    g_default_route.valid = false;
    g_default_route.gateway = 0;
    g_default_route.iface_name[0] = '\0';
}

bool net_route_get_default(net_interface_t **iface_out, uint32_t *gateway_out)
{
    if (!g_default_route.valid)
    {
        return false;
    }

    net_interface_t *iface = net_if_by_name(g_default_route.iface_name);
    if (!iface || !iface->present)
    {
        g_default_route.valid = false;
        g_default_route.gateway = 0;
        g_default_route.iface_name[0] = '\0';
        return false;
    }

    if (iface_out)
    {
        *iface_out = iface;
    }
    if (gateway_out)
    {
        *gateway_out = g_default_route.gateway;
    }
    return true;
}

bool net_route_next_hop(net_interface_t *preferred_iface, uint32_t dest_ip,
                        net_interface_t **iface_out, uint32_t *next_hop_ip)
{
    net_interface_t *chosen_iface = NULL;
    uint32_t hop_ip = dest_ip;

    if (preferred_iface && net_route_same_network(preferred_iface, dest_ip))
    {
        chosen_iface = preferred_iface;
        hop_ip = dest_ip;
    }

    if (!chosen_iface)
    {
        size_t count = net_if_count();
        for (size_t i = 0; i < count; ++i)
        {
            net_interface_t *iface = net_if_at(i);
            if (!iface || !iface->present || !iface->link_up || iface->ipv4_addr == 0)
            {
                continue;
            }
            if (net_route_same_network(iface, dest_ip))
            {
                chosen_iface = iface;
                hop_ip = dest_ip;
                break;
            }
        }
    }

    if (!chosen_iface)
    {
        net_interface_t *default_iface = NULL;
        uint32_t gateway = 0;
        if (!net_route_get_default(&default_iface, &gateway) || !default_iface || !default_iface->link_up || default_iface->ipv4_addr == 0 || gateway == 0)
        {
            return false;
        }
        chosen_iface = default_iface;
        hop_ip = gateway;
    }

    if (iface_out)
    {
        *iface_out = chosen_iface;
    }
    if (next_hop_ip)
    {
        *next_hop_ip = hop_ip;
    }
    return true;
}

static bool net_route_same_network(net_interface_t *iface, uint32_t ip)
{
    if (!iface || !iface->present || !iface->link_up || iface->ipv4_addr == 0)
    {
        return false;
    }

    uint32_t mask = iface->ipv4_netmask;
    if (mask == 0)
    {
        return ip == iface->ipv4_addr;
    }

    return ((iface->ipv4_addr ^ ip) & mask) == 0;
}
