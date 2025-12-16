#ifndef NET_ICMP_H
#define NET_ICMP_H

#include "net/interface.h"

typedef struct
{
    uint32_t from_ip;
    size_t bytes;
    uint64_t rtt_ticks;
} net_icmp_reply_t;

void net_icmp_handle_frame(net_interface_t *iface, const uint8_t *frame, size_t length);
void net_icmp_reset_pending(void);
bool net_icmp_send_echo(net_interface_t *iface, const uint8_t target_mac[6],
                        uint32_t target_ip, uint16_t identifier, uint16_t sequence,
                        size_t payload_len);
bool net_icmp_get_reply(uint16_t identifier, uint16_t sequence, net_icmp_reply_t *out_reply);

#endif
