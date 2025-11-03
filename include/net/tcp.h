#ifndef NET_TCP_H
#define NET_TCP_H

#include "net/interface.h"

typedef struct net_tcp_socket net_tcp_socket_t;

void net_tcp_init(void);
void net_tcp_poll(void);
void net_tcp_handle_frame(net_interface_t *iface, const uint8_t *frame, size_t length);

net_tcp_socket_t *net_tcp_socket_open(net_interface_t *iface);
bool net_tcp_socket_connect(net_tcp_socket_t *socket, uint32_t remote_ip, uint16_t remote_port);
bool net_tcp_socket_send(net_tcp_socket_t *socket, const uint8_t *data, size_t len);
size_t net_tcp_socket_available(const net_tcp_socket_t *socket);
size_t net_tcp_socket_read(net_tcp_socket_t *socket, uint8_t *buffer, size_t capacity);
ssize_t net_tcp_socket_read_blocking(net_tcp_socket_t *socket, uint8_t *buffer, size_t capacity);
bool net_tcp_socket_is_established(const net_tcp_socket_t *socket);
bool net_tcp_socket_remote_closed(const net_tcp_socket_t *socket);
bool net_tcp_socket_has_error(const net_tcp_socket_t *socket);
const char *net_tcp_socket_state(const net_tcp_socket_t *socket);
void net_tcp_socket_close(net_tcp_socket_t *socket);
void net_tcp_socket_release(net_tcp_socket_t *socket);
uint64_t net_tcp_socket_last_activity(const net_tcp_socket_t *socket);
int net_tcp_socket_fd(const net_tcp_socket_t *socket);

#endif
