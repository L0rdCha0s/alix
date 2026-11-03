#ifndef IO_UDP_H
#define IO_UDP_H
#include "io_tcp.h"
#include "net/udp.h"
#include "alix_network.h"

#define IO_UDP_OPEN 0x10000u
#define IO_UDP_BIND 0x10001u
/* Reuse the network request prefix/payload offset. UDP adds a worker-owned
 * state trailer; opaque user metadata, when present, precedes this trailer.
 * interface_index is a send source-IP override; padding encodes TOS+1 (0=default).
 * Workers never dereference any user pointers in the opaque metadata. */
typedef struct
{
    uint64_t deadline_ms, next_arp_ms;
    net_udp_packet_info_t packet;
    net_udp_socket_info_t info;
    alix_udp_packet_info_t packet_wire;
} io_udp_state_t;
io_udp_state_t *io_udp_state(io_request_t *request);
bool io_udp_description_valid(const fd_description_t *description);
bool io_udp_request_valid(io_request_t *request);
bool io_udp_execute(io_request_t *request, io_service_result_t *result, fd_retirement_queue_t *retirement);
#endif
