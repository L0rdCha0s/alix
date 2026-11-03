#ifndef ALIX_NETWORK_NATIVE_H
#define ALIX_NETWORK_NATIVE_H
#include "types.h"

#define ALIX_NET_ROUTE_VERSION 1u
#define ALIX_NET_INTERFACE_NAME_MAX 8u
typedef struct alix_net_route_info
{
    uint32_t version;
    uint32_t mtu;
    uint32_t source_ipv4;
    uint32_t next_hop_ipv4;
    char interface_name[ALIX_NET_INTERFACE_NAME_MAX];
} alix_net_route_info_t;
/* Datagram metadata uses the same numeric IPv4 convention as route queries. */
typedef struct alix_udp_packet_info
{
    uint32_t version, source_ipv4, destination_ipv4, length, interface_index;
    uint16_t source_port;
    uint8_t tos, ttl;
} alix_udp_packet_info_t;

#ifndef KERNEL_BUILD
#ifdef __cplusplus
extern "C" {
#endif
/* IPv4 numbers use a<<24|b<<16|c<<8|d for a.b.c.d. Returns a coherent
 * outgoing-interface snapshot without opening a socket or transmitting.
 * No route/unsupported unicast addresses fail with ENETUNREACH. */
__attribute__((visibility("default")))
int alix_net_route_ipv4(uint32_t destination, alix_net_route_info_t *info);
struct sockaddr;
__attribute__((visibility("default")))
ssize_t alix_udp_send(int fd, const void *data, size_t length, const struct sockaddr *destination,
                      uint32_t destination_length, int tos, uint32_t source_ipv4);
__attribute__((visibility("default")))
ssize_t alix_udp_recv(int fd, void *data, size_t length, alix_udp_packet_info_t *info, int flags);
#ifdef __cplusplus
}
#endif
#endif
#endif
