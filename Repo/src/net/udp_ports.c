#include "net/udp.h"
#include "spinlock.h"
#include "errno.h"

#define UDP_PORT_LEASES 512u
typedef struct { const void *owner; uint32_t address; uint16_t port; } udp_port_lease_t;
static udp_port_lease_t g_udp_ports[UDP_PORT_LEASES];
static spinlock_t g_udp_ports_lock;
static uint32_t g_udp_next_port = 49152;

static bool udp_port_conflicts(uint32_t address, uint16_t port)
{
    /* The built-in DHCP client owns its well-known local port. */
    if (port == 68) return true;
    for (size_t i = 0; i < UDP_PORT_LEASES; ++i)
        if (g_udp_ports[i].owner && g_udp_ports[i].port == port &&
            (!address || !g_udp_ports[i].address || address == g_udp_ports[i].address)) return true;
    return false;
}

int net_udp_port_claim(const void *owner, uint32_t address, uint16_t requested, uint16_t *port)
{
    if (!owner || !port) return -EINVAL;
    uint64_t flags = spinlock_lock_irqsave(&g_udp_ports_lock);
    size_t free_slot = UDP_PORT_LEASES;
    int result = 0;
    for (size_t i = 0; i < UDP_PORT_LEASES; ++i)
    {
        if (g_udp_ports[i].owner == owner) { result = -EALREADY; break; }
        if (!g_udp_ports[i].owner && free_slot == UDP_PORT_LEASES) free_slot = i;
    }
    if (!result && free_slot == UDP_PORT_LEASES) result = -ENOBUFS;
    uint16_t chosen = requested;
    if (!result && requested && udp_port_conflicts(address, requested)) result = -EADDRINUSE;
    if (!result && !requested)
    {
        for (size_t i = 0; i < 16384; ++i)
        {
            chosen = (uint16_t)g_udp_next_port++;
            if (g_udp_next_port > 65535) g_udp_next_port = 49152;
            if (!udp_port_conflicts(address, chosen)) break;
            chosen = 0;
        }
        if (!chosen) result = -EADDRINUSE;
    }
    if (!result)
    {
        g_udp_ports[free_slot] = (udp_port_lease_t){ owner, address, chosen };
        *port = chosen;
    }
    spinlock_unlock_irqrestore(&g_udp_ports_lock, flags);
    return result;
}

void net_udp_port_release(const void *owner)
{
    if (!owner) return;
    uint64_t flags = spinlock_lock_irqsave(&g_udp_ports_lock);
    for (size_t i = 0; i < UDP_PORT_LEASES; ++i)
        if (g_udp_ports[i].owner == owner) { g_udp_ports[i] = (udp_port_lease_t){0}; break; }
    spinlock_unlock_irqrestore(&g_udp_ports_lock, flags);
}
