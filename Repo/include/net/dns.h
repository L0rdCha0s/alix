#ifndef NET_DNS_H
#define NET_DNS_H

#include "net/interface.h"

#define NET_DNS_NAME_MAX 255
#define NET_DNS_MAX_SERVERS 4
#define NET_DNS_MAX_ADDRS 8

#define NET_DNS_TYPE_A     0x0001
#define NET_DNS_TYPE_CNAME 0x0005
#define NET_DNS_STATUS_OK 0u
#define NET_DNS_STATUS_NOT_FOUND 1u
#define NET_DNS_STATUS_AGAIN 2u
#define NET_DNS_STATUS_FAILURE 3u

typedef struct
{
    uint32_t status;
    bool has_a;
    uint32_t addr;
    uint32_t addrs[NET_DNS_MAX_ADDRS];
    size_t addr_count;
    bool has_cname;
    /* Final canonical spelling for successful A lookups as well as the
     * CNAME target for explicit CNAME queries. */
    char cname[NET_DNS_NAME_MAX + 1];
    uint16_t rr_type;
} net_dns_result_t;

void net_dns_init(void);
void net_dns_set_servers(const uint32_t *servers, size_t count);
size_t net_dns_server_count(void);

bool net_dns_resolve(const char *hostname, uint16_t qtype,
                     net_interface_t *preferred_iface, net_dns_result_t *result);
/* A per-call server avoids mutating DHCP/default resolver configuration. Both
 * server fields zero select defaults. Nondefault replies do not enter the
 * shared default-resolver cache. Caller must protect this synchronous owner
 * through completion, as the user-facing DNS service workers do. */
bool net_dns_resolve_at(const char *hostname, uint16_t qtype,
                         net_interface_t *preferred_iface, uint32_t server_ip,
                         uint16_t server_port, net_dns_result_t *result);
bool net_dns_resolve_ipv4(const char *hostname, net_interface_t *preferred_iface,
                          uint32_t *out_addr);
size_t net_dns_resolve_ipv4_all(const char *hostname,
                                net_interface_t *preferred_iface,
                                uint32_t *out_addrs,
                                size_t capacity);
bool net_dns_resolve_cname(const char *hostname, net_interface_t *preferred_iface,
                           char *out_buffer, size_t buffer_len);

void net_dns_handle_frame(net_interface_t *iface, const uint8_t *frame, size_t length);
/* Bounded receive-demux hint. Response parsing belongs to the resolver owner. */
bool net_dns_port_active(uint16_t port);
void net_dns_set_debug(bool enable);
bool net_dns_debug_enabled(void);

#endif
