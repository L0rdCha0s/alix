#include "net/route.h"

#include <stddef.h>

#include "libc.h"
#include "spinlock.h"

typedef struct
{
    bool valid;
    char iface_name[NET_IF_NAME_MAX];
    uint32_t gateway;
} net_default_route_t;

static net_default_route_t g_default_route;
static spinlock_t g_net_config_lock;
uint64_t net_config_lock(void) { return spinlock_lock_irqsave(&g_net_config_lock); }
void net_config_unlock(uint64_t flags) { spinlock_unlock_irqrestore(&g_net_config_lock, flags); }

static bool net_route_same_network(net_interface_t *iface, uint32_t ip);

void net_route_init(void)
{
    uint64_t flags = net_config_lock();
    memset(&g_default_route, 0, sizeof(g_default_route));
    net_config_unlock(flags);
}

static bool net_route_set_default_locked(net_interface_t *iface, uint32_t gateway)
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

static void net_route_clear_default_locked(void)
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

static bool net_route_get_default_locked(net_interface_t **iface_out, uint32_t *gateway_out)
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

static bool net_route_next_hop_locked(net_interface_t *preferred_iface, uint32_t dest_ip,
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
        if (!net_route_get_default_locked(&default_iface, &gateway) || !default_iface || !default_iface->link_up || default_iface->ipv4_addr == 0 || gateway == 0)
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

bool net_route_set_default(net_interface_t *iface, uint32_t gateway)
{
    uint64_t flags = net_config_lock();
    bool result = net_route_set_default_locked(iface, gateway);
    net_config_unlock(flags);
    return result;
}
void net_route_clear_default(void)
{
    uint64_t flags = net_config_lock();
    net_route_clear_default_locked();
    net_config_unlock(flags);
}
bool net_route_get_default(net_interface_t **iface, uint32_t *gateway)
{
    uint64_t flags = net_config_lock();
    bool result = net_route_get_default_locked(iface, gateway);
    net_config_unlock(flags);
    return result;
}
bool net_route_next_hop(net_interface_t *preferred, uint32_t destination,
                        net_interface_t **iface, uint32_t *next_hop)
{
    uint64_t flags = net_config_lock();
    bool result = net_route_next_hop_locked(preferred, destination, iface, next_hop);
    net_config_unlock(flags);
    return result;
}
void net_route_configure_ipv4(net_interface_t *iface, uint32_t addr,
                             uint32_t netmask, uint32_t gateway)
{
    if (!iface) return;
    uint64_t flags = net_config_lock();
    __atomic_store_n(&iface->ipv4_addr, addr, __ATOMIC_RELEASE);
    iface->ipv4_netmask = netmask;
    iface->ipv4_gateway = gateway;
    if (gateway) net_route_set_default_locked(iface, gateway);
    else if (g_default_route.valid &&
             net_if_by_name(g_default_route.iface_name) == iface)
        net_route_clear_default_locked();
    net_config_unlock(flags);
}
bool net_route_ipv4_snapshot(uint32_t destination, alix_net_route_info_t *info)
{
    /* Alix currently has Ethernet IPv4 unicast routes, without a loopback or
     * multicast interface. Never label one of those destinations as Ethernet. */
    if (!info || !destination || (destination >> 24) == 127 ||
        (destination >> 24) >= 224) return false;
    uint64_t flags = net_config_lock();
    net_interface_t *iface = NULL;
    uint32_t next_hop = 0;
    bool result = net_route_next_hop_locked(NULL, destination, &iface, &next_hop);
    if (result && iface->mtu)
    {
        memset(info, 0, sizeof(*info));
        info->version = ALIX_NET_ROUTE_VERSION;
        info->mtu = iface->mtu;
        info->source_ipv4 = iface->ipv4_addr;
        info->next_hop_ipv4 = next_hop;
        memcpy(info->interface_name, iface->name, sizeof(info->interface_name));
        info->interface_name[sizeof(info->interface_name) - 1] = 0;
    }
    else result = false;
    net_config_unlock(flags);
    return result;
}
