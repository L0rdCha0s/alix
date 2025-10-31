#ifndef NET_DNS_H
#define NET_DNS_H

#include "net/interface.h"

#define NET_DNS_NAME_MAX 255
#define NET_DNS_MAX_SERVERS 4

#define NET_DNS_TYPE_A     0x0001
#define NET_DNS_TYPE_CNAME 0x0005

typedef struct
{
    bool has_a;
    uint32_t addr;
    bool has_cname;
    char cname[NET_DNS_NAME_MAX + 1];
    uint16_t rr_type;
} net_dns_result_t;

void net_dns_init(void);
void net_dns_set_servers(const uint32_t *servers, size_t count);
size_t net_dns_server_count(void);

bool net_dns_resolve(const char *hostname, uint16_t qtype,
                     net_interface_t *preferred_iface, net_dns_result_t *result);
bool net_dns_resolve_ipv4(const char *hostname, net_interface_t *preferred_iface,
                          uint32_t *out_addr);
bool net_dns_resolve_cname(const char *hostname, net_interface_t *preferred_iface,
                           char *out_buffer, size_t buffer_len);

void net_dns_handle_frame(net_interface_t *iface, const uint8_t *frame, size_t length);

#endif
