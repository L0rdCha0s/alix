#ifndef NET_NTP_H
#define NET_NTP_H

#include "types.h"

struct net_interface;

typedef struct
{
    int64_t offset_microseconds;
    int64_t delay_microseconds;
    int64_t server_time_microseconds;
    int64_t destination_time_microseconds;
    uint32_t server_ip;
} net_ntp_result_t;

void net_ntp_init(void);
void net_ntp_set_pending(uint32_t originate_seconds,
                         uint32_t originate_fraction,
                         uint16_t local_port,
                         uint32_t server_ip);
void net_ntp_clear_pending(void);
bool net_ntp_get_result(net_ntp_result_t *out_result);
void net_ntp_handle_frame(struct net_interface *iface, const uint8_t *frame, size_t length);

#endif
