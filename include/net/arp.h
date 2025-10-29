#ifndef NET_ARP_H
#define NET_ARP_H

#include "net/interface.h"

bool net_arp_lookup(uint32_t ip, uint8_t mac_out[6]);
void net_arp_handle_frame(net_interface_t *iface, const uint8_t *frame, size_t length);
bool net_arp_send_request(net_interface_t *iface, uint32_t target_ip);
void net_arp_flush(void);

#endif
