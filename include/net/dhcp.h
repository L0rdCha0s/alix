#ifndef NET_DHCP_H
#define NET_DHCP_H

#include "net/interface.h"

bool net_dhcp_acquire(net_interface_t *iface);
void net_dhcp_handle_frame(net_interface_t *iface, const uint8_t *frame, size_t length);
bool net_dhcp_in_progress(void);
bool net_dhcp_claims_ip(net_interface_t *iface, uint32_t ip);

#endif
