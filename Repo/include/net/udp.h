#ifndef NET_UDP_H
#define NET_UDP_H
#include "net/interface.h"

/* Common UDP port leases for native sockets and the built-in DNS/NTP clients.
 * Tokens must have stable heap/static lifetime through release. The leaf lock
 * never allocates, waits or calls back into a protocol. Address zero is wildcard. */
int net_udp_port_claim(const void *owner, uint32_t address, uint16_t requested, uint16_t *port);
void net_udp_port_release(const void *owner);

typedef struct net_udp_socket net_udp_socket_t;
#define NET_UDP_BOUND 1u
#define NET_UDP_CONNECTED 2u
#define NET_UDP_READABLE 4u
#define NET_UDP_WRITABLE 8u
#define NET_UDP_MAX_PAYLOAD 1472u
typedef struct
{
    uint32_t source_ip, destination_ip, length, interface_index;
    uint16_t source_port;
    uint8_t tos, ttl;
} net_udp_packet_info_t;
typedef struct
{
    uint32_t references, flags, local_ip, remote_ip;
    uint16_t local_port, remote_port;
    uint32_t available, receive_capacity, send_capacity, queued_bytes;
    uint32_t tos, ttl;
    uint64_t dropped_packets;
} net_udp_socket_info_t;
typedef enum { NET_UDP_RECV_BUFFER, NET_UDP_SEND_BUFFER, NET_UDP_TOS, NET_UDP_TTL } net_udp_option_t;

/* Construct/final-put on protected workers. An existing owner is required for
 * get and every operation. No process, user pointer or caller stack is retained.
 * The registry holds only lock-protected membership, not an external owner. */
net_udp_socket_t *net_udp_socket_open_owned(void);
bool net_udp_socket_get_owned(net_udp_socket_t *socket);
int net_udp_socket_put_owned(net_udp_socket_t *socket);
int net_udp_socket_bind_owned(net_udp_socket_t *socket, uint32_t ip, uint16_t port);
int net_udp_socket_connect_owned(net_udp_socket_t *socket, uint32_t ip, uint16_t port);
int net_udp_socket_info_owned(net_udp_socket_t *socket, net_udp_socket_info_t *info);
int net_udp_socket_option_owned(net_udp_socket_t *socket, net_udp_option_t option, int value);
/* Atomic datagrams, without IP fragmentation. -EAGAIN asks the event executor
 * to retry ARP/TX readiness; next_arp_ms is caller-owned persistent work state.
 * Destination zero/zero uses a connected peer; tos=-1 selects the socket value. */
ssize_t net_udp_socket_send_owned(net_udp_socket_t *socket, const void *data, size_t length,
                                 uint32_t ip, uint16_t port, int tos, uint32_t source_ip,
                                 uint64_t *next_arp_ms);
/* Returns the copied prefix; info.length is the complete original datagram.
 * A short non-peek read consumes the entire datagram, including a zero-byte one. */
ssize_t net_udp_socket_recv_owned(net_udp_socket_t *socket, void *data, size_t capacity,
                                 bool peek, net_udp_packet_info_t *info);
bool net_udp_handle_frame(net_interface_t *iface, const uint8_t *frame, size_t length);
#endif
