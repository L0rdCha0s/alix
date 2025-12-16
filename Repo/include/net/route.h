#ifndef NET_ROUTE_H
#define NET_ROUTE_H

#include "net/interface.h"

void net_route_init(void);
bool net_route_set_default(net_interface_t *iface, uint32_t gateway);
void net_route_clear_default(void);
bool net_route_get_default(net_interface_t **iface_out, uint32_t *gateway_out);
bool net_route_next_hop(net_interface_t *preferred_iface, uint32_t dest_ip,
                        net_interface_t **iface_out, uint32_t *next_hop_ip);

#endif
