#ifndef NET_ROUTE_H
#define NET_ROUTE_H

#include "net/interface.h"
#include "alix_network.h"

/* Configuration writers and route snapshots share this bounded IRQ-safe gate.
 * No allocation, driver callback, storage operation or wait is allowed inside. */
uint64_t net_config_lock(void);
void net_config_unlock(uint64_t flags);
void net_route_configure_ipv4(net_interface_t *iface, uint32_t addr,
                             uint32_t netmask, uint32_t gateway);
bool net_route_ipv4_snapshot(uint32_t destination, alix_net_route_info_t *info);

void net_route_init(void);
bool net_route_set_default(net_interface_t *iface, uint32_t gateway);
void net_route_clear_default(void);
bool net_route_get_default(net_interface_t **iface_out, uint32_t *gateway_out);
bool net_route_next_hop(net_interface_t *preferred_iface, uint32_t dest_ip,
                        net_interface_t **iface_out, uint32_t *next_hop_ip);

#endif
