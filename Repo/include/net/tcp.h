#ifndef NET_TCP_H
#define NET_TCP_H

#include "net/interface.h"

typedef struct net_tcp_socket net_tcp_socket_t;

void net_tcp_init(void);
void net_tcp_poll(void);
void net_tcp_handle_frame(net_interface_t *iface, const uint8_t *frame, size_t length);

net_tcp_socket_t *net_tcp_socket_open(net_interface_t *iface);
/* Native descriptor backend. OPEN returns one owned reference without creating
 * a legacy global FD. Only an existing owner (or its publishing lock) may get
 * another reference. A successful get requires a protected caller or bounded
 * preparation guard until the new reference is registered. An owner must
 * remain registered through every operation.
 * Construct/final-put on protected workers: allocation and TCP cleanup must not
 * be abandoned with a syscall caller. No thread/process pointer is captured. */
net_tcp_socket_t *net_tcp_socket_open_owned(net_interface_t *iface);
bool net_tcp_socket_get_owned(net_tcp_socket_t *socket);
int net_tcp_socket_put_owned(net_tcp_socket_t *socket);
/* Final put consumes the last external owner immediately. An established
 * transport stays pool-owned through FIN/ACK or its bounded close deadline;
 * no external get/snapshot may resurrect that retiring incarnation. */
#define NET_TCP_OWNED_CONNECTED 1u
#define NET_TCP_OWNED_READABLE 2u
#define NET_TCP_OWNED_EOF 4u
#define NET_TCP_OWNED_ERROR 8u
#define NET_TCP_OWNED_CONNECTING 16u
#define NET_TCP_OWNED_WRITABLE 32u
typedef struct
{
    uint32_t references, flags;
    uint64_t available, event_sequence;
    uint32_t mss;
    int32_t error_code;
    uint64_t write_capacity; /* Remaining retained-payload and peer-window space. */
} net_tcp_owned_status_t;
typedef struct
{
    uint32_t local_ip, remote_ip;
    uint16_t local_port, remote_port;
    uint32_t mss, flags;
    uint64_t receive_buffer, send_buffer;
} net_tcp_owned_info_t;
int net_tcp_socket_owned_snapshot(net_tcp_socket_t *socket, net_tcp_owned_status_t *out);
int net_tcp_socket_info_owned(net_tcp_socket_t *socket, net_tcp_owned_info_t *out);
/* A pending error has one claimant until commit or cancellation. A successful
 * zero-error query returns generation zero and needs no release. Hold an owned
 * socket reference throughout; never abandon a nonzero claim on a caller stack. */
int net_tcp_socket_error_claim_owned(net_tcp_socket_t *socket, int32_t *error, uint64_t *generation);
int net_tcp_socket_error_finish_owned(net_tcp_socket_t *socket, uint64_t generation, bool commit);
bool net_tcp_socket_connect(net_tcp_socket_t *socket, uint32_t remote_ip, uint16_t remote_port);
bool net_tcp_socket_send(net_tcp_socket_t *socket, const uint8_t *data, size_t len);
size_t net_tcp_socket_available(const net_tcp_socket_t *socket);
size_t net_tcp_socket_read(net_tcp_socket_t *socket, uint8_t *buffer, size_t capacity);
/* Owned caller, kernel output storage; snapshot without consuming or ACKing. */
ssize_t net_tcp_socket_peek_owned(net_tcp_socket_t *socket, uint8_t *buffer, size_t capacity);
ssize_t net_tcp_socket_read_blocking(net_tcp_socket_t *socket, uint8_t *buffer, size_t capacity);
ssize_t net_tcp_socket_read_blocking_timeout(net_tcp_socket_t *socket,
                                             uint8_t *buffer,
                                             size_t capacity,
                                             uint64_t timeout_ticks);
bool net_tcp_socket_is_established(const net_tcp_socket_t *socket);
bool net_tcp_socket_remote_closed(const net_tcp_socket_t *socket);
bool net_tcp_socket_has_error(const net_tcp_socket_t *socket);
const char *net_tcp_socket_state(const net_tcp_socket_t *socket);
void net_tcp_socket_close(net_tcp_socket_t *socket);
void net_tcp_socket_release(net_tcp_socket_t *socket);
uint64_t net_tcp_socket_last_activity(const net_tcp_socket_t *socket);
int net_tcp_socket_fd(const net_tcp_socket_t *socket);
net_tcp_socket_t *net_tcp_socket_from_fd(int fd);
void net_tcp_log_state(const net_tcp_socket_t *socket, const char *tag);

#endif
