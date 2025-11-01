#include "net/tcp.h"

#include <stddef.h>

#include "net/arp.h"
#include "net/route.h"

#include "serial.h"
#include "timer.h"
#include "libc.h"

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10

#define NET_TCP_MAX_SOCKETS      4
#define NET_TCP_RX_CAPACITY      4096
#define NET_TCP_MAX_PAYLOAD      1460

typedef enum
{
    TCP_STATE_UNUSED = 0,
    TCP_STATE_CLOSED,
    TCP_STATE_ARP,
    TCP_STATE_SYN_SENT,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT_1,
    TCP_STATE_FIN_WAIT_2,
    TCP_STATE_CLOSE_WAIT,
    TCP_STATE_LAST_ACK,
    TCP_STATE_ERROR
} tcp_state_t;

struct net_tcp_socket
{
    tcp_state_t state;
    net_interface_t *iface;
    uint32_t remote_ip;
    uint32_t next_hop_ip;
    uint16_t remote_port;
    uint16_t local_port;
    uint32_t seq_next;       /* next sequence number to send */
    uint32_t recv_next;      /* next sequence number expected from peer */
    uint32_t unacked_seq;
    uint32_t unacked_len;
    uint8_t remote_mac[6];
    bool have_mac;
    bool awaiting_ack;
    uint8_t pending_flags;
    uint8_t pending_payload[NET_TCP_MAX_PAYLOAD];
    size_t pending_payload_len;
    uint16_t remote_window;
    uint8_t rx_buffer[NET_TCP_RX_CAPACITY];
    size_t rx_size;
    bool remote_closed;
    bool error;

    uint64_t last_send_tick;
    uint64_t last_activity_tick;
    uint64_t connect_deadline;
    uint64_t last_arp_request_tick;
    uint8_t retry_count;
    uint8_t max_retries;
};

static net_tcp_socket_t g_sockets[NET_TCP_MAX_SOCKETS];
static uint16_t g_next_ephemeral_port = 49152;
static uint64_t g_retransmit_ticks = 50;
static uint64_t g_arp_retry_ticks = 50;
static uint64_t g_connect_timeout_ticks = 400;

static uint16_t read_be16(const uint8_t *p);
static uint32_t read_be32(const uint8_t *p);
static void write_be16(uint8_t *p, uint16_t value);
static void write_be32(uint8_t *p, uint32_t value);
static uint16_t checksum16(const uint8_t *data, size_t len);
static uint16_t tcp_checksum(const net_tcp_socket_t *socket, const uint8_t *tcp, size_t tcp_len);
static net_tcp_socket_t *tcp_find_socket(net_interface_t *iface, uint16_t local_port,
                                         uint32_t remote_ip, uint16_t remote_port);
static uint16_t tcp_allocate_port(void);
static uint32_t tcp_initial_seq(void);
static void tcp_reset_socket(net_tcp_socket_t *socket);
static bool tcp_prepare_route(net_tcp_socket_t *socket, uint32_t remote_ip, uint16_t remote_port);
static bool tcp_send_segment(net_tcp_socket_t *socket, uint32_t seq, uint8_t flags,
                             const uint8_t *payload, size_t payload_len, bool advance_seq,
                             bool track_retransmit);
static bool tcp_send_syn(net_tcp_socket_t *socket);
static void tcp_handle_ack(net_tcp_socket_t *socket, uint32_t ack_num);
static void tcp_process_payload(net_tcp_socket_t *socket, uint32_t seq_num,
                                const uint8_t *payload, size_t payload_len);
static void tcp_send_ack(net_tcp_socket_t *socket);
static void tcp_retransmit(net_tcp_socket_t *socket);
static void tcp_mark_error(net_tcp_socket_t *socket, const char *reason);

void net_tcp_init(void)
{
    for (size_t i = 0; i < NET_TCP_MAX_SOCKETS; ++i)
    {
        tcp_reset_socket(&g_sockets[i]);
    }

    uint32_t freq = timer_frequency();
    if (freq == 0)
    {
        freq = 100;
    }
    g_retransmit_ticks = (freq / 2U) ? (freq / 2U) : 1U;
    g_arp_retry_ticks = (freq / 2U) ? (freq / 2U) : 1U;
    g_connect_timeout_ticks = freq * 4U;
    if (g_connect_timeout_ticks < freq)
    {
        g_connect_timeout_ticks = freq;
    }
}

static void tcp_reset_socket(net_tcp_socket_t *socket)
{
    if (!socket)
    {
        return;
    }
    memset(socket, 0, sizeof(*socket));
    socket->state = TCP_STATE_UNUSED;
    socket->remote_window = 4096;
    socket->max_retries = 6;
}

static uint16_t tcp_allocate_port(void)
{
    for (size_t attempt = 0; attempt < 0x8000; ++attempt)
    {
        if (g_next_ephemeral_port < 49152)
        {
            g_next_ephemeral_port = 49152;
        }
        uint16_t candidate = g_next_ephemeral_port++;
        bool in_use = false;
        for (size_t i = 0; i < NET_TCP_MAX_SOCKETS; ++i)
        {
            if (g_sockets[i].state != TCP_STATE_UNUSED &&
                g_sockets[i].local_port == candidate)
            {
                in_use = true;
                break;
            }
        }
        if (!in_use)
        {
            return candidate;
        }
    }
    return 0;
}

static uint32_t tcp_initial_seq(void)
{
    static uint32_t s_iss = 0x13572468U;
    s_iss += (uint32_t)(timer_ticks() & 0xFFFFU);
    s_iss += 0x01020304U;
    if (s_iss == 0)
    {
        s_iss = 1;
    }
    return s_iss;
}

net_tcp_socket_t *net_tcp_socket_open(net_interface_t *iface)
{
    for (size_t i = 0; i < NET_TCP_MAX_SOCKETS; ++i)
    {
        if (g_sockets[i].state == TCP_STATE_UNUSED)
        {
            net_tcp_socket_t *socket = &g_sockets[i];
            tcp_reset_socket(socket);
            socket->state = TCP_STATE_CLOSED;
            socket->iface = iface;
            socket->local_port = tcp_allocate_port();
            if (socket->local_port == 0)
            {
                tcp_reset_socket(socket);
                return NULL;
            }
            return socket;
        }
    }
    return NULL;
}

bool net_tcp_socket_connect(net_tcp_socket_t *socket, uint32_t remote_ip, uint16_t remote_port)
{
    if (!socket || remote_ip == 0 || remote_port == 0)
    {
        return false;
    }
    if (socket->state != TCP_STATE_CLOSED)
    {
        return false;
    }

    /* Announce our IP->MAC so the gateway learns/refreshes its neighbor entry. */
    if (socket->iface && socket->iface->ipv4_addr)
    {
        net_arp_announce(socket->iface, socket->iface->ipv4_addr);
    }

    if (!tcp_prepare_route(socket, remote_ip, remote_port))
    {
        tcp_mark_error(socket, "route failure");
        return false;
    }

    socket->seq_next = tcp_initial_seq();
    socket->unacked_seq = socket->seq_next;
    socket->unacked_len = 0;
    socket->awaiting_ack = false;
    socket->rx_size = 0;
    socket->remote_closed = false;
    socket->error = false;
    socket->pending_flags = 0;
    socket->pending_payload_len = 0;
    socket->retry_count = 0;
    socket->max_retries = 6;

    uint64_t now = timer_ticks();
    socket->last_activity_tick = now;
    socket->connect_deadline = now + g_connect_timeout_ticks;
    socket->last_arp_request_tick = 0;

    if (socket->have_mac)
    {
        if (!tcp_send_syn(socket))
        {
            tcp_mark_error(socket, "syn send failed");
            return false;
        }
        socket->state = TCP_STATE_SYN_SENT;
    }
    else
    {
        if (!net_arp_send_request(socket->iface, socket->next_hop_ip))
        {
            tcp_mark_error(socket, "arp request failed");
            return false;
        }
        socket->state = TCP_STATE_ARP;
        socket->last_arp_request_tick = now;
    }

    return true;
}


bool net_tcp_socket_send(net_tcp_socket_t *socket, const uint8_t *data, size_t len)
{
    if (!socket || !data || len == 0)
    {
        return false;
    }
    if (len > NET_TCP_MAX_PAYLOAD)
    {
        return false;
    }
    if (socket->state != TCP_STATE_ESTABLISHED)
    {
        return false;
    }
    if (socket->awaiting_ack)
    {
        return false;
    }
    if (socket->remote_closed)
    {
        return false;
    }
    if (socket->remote_window != 0 && socket->remote_window < len)
    {
        return false;
    }

    return tcp_send_segment(socket, socket->seq_next, TCP_FLAG_ACK | TCP_FLAG_PSH,
                            data, len, true, true);
}

size_t net_tcp_socket_available(const net_tcp_socket_t *socket)
{
    if (!socket)
    {
        return 0;
    }
    return socket->rx_size;
}

size_t net_tcp_socket_read(net_tcp_socket_t *socket, uint8_t *buffer, size_t capacity)
{
    if (!socket || capacity == 0 || socket->rx_size == 0)
    {
        return 0;
    }
    size_t to_copy = socket->rx_size;
    if (to_copy > capacity)
    {
        to_copy = capacity;
    }
    if (buffer)
    {
        memcpy(buffer, socket->rx_buffer, to_copy);
    }
    if (socket->rx_size > to_copy)
    {
        memmove(socket->rx_buffer, socket->rx_buffer + to_copy, socket->rx_size - to_copy);
    }
    socket->rx_size -= to_copy;
    return to_copy;
}

bool net_tcp_socket_is_established(const net_tcp_socket_t *socket)
{
    if (!socket)
    {
        return false;
    }
    return socket->state == TCP_STATE_ESTABLISHED || socket->state == TCP_STATE_CLOSE_WAIT;
}

bool net_tcp_socket_remote_closed(const net_tcp_socket_t *socket)
{
    return socket ? socket->remote_closed : false;
}

bool net_tcp_socket_has_error(const net_tcp_socket_t *socket)
{
    if (!socket)
    {
        return true;
    }
    return socket->error || socket->state == TCP_STATE_ERROR;
}

const char *net_tcp_socket_state(const net_tcp_socket_t *socket)
{
    if (!socket)
    {
        return "null";
    }
    switch (socket->state)
    {
        case TCP_STATE_UNUSED:      return "unused";
        case TCP_STATE_CLOSED:      return "closed";
        case TCP_STATE_ARP:         return "arp";
        case TCP_STATE_SYN_SENT:    return "syn_sent";
        case TCP_STATE_ESTABLISHED: return "established";
        case TCP_STATE_FIN_WAIT_1:  return "fin_wait_1";
        case TCP_STATE_FIN_WAIT_2:  return "fin_wait_2";
        case TCP_STATE_CLOSE_WAIT:  return "close_wait";
        case TCP_STATE_LAST_ACK:    return "last_ack";
        case TCP_STATE_ERROR:       return "error";
        default:                    return "unknown";
    }
}

void net_tcp_socket_close(net_tcp_socket_t *socket)
{
    if (!socket)
    {
        return;
    }

    if (socket->state == TCP_STATE_UNUSED)
    {
        return;
    }

    if (socket->state == TCP_STATE_ESTABLISHED && !socket->awaiting_ack)
    {
        if (tcp_send_segment(socket, socket->seq_next, TCP_FLAG_FIN | TCP_FLAG_ACK,
                             NULL, 0, true, true))
        {
            socket->connect_deadline = timer_ticks() + g_connect_timeout_ticks;
            socket->state = TCP_STATE_FIN_WAIT_1;
            return;
        }
        tcp_mark_error(socket, "fin send failed");
    }

    if (socket->state == TCP_STATE_CLOSE_WAIT && !socket->awaiting_ack)
    {
        if (tcp_send_segment(socket, socket->seq_next, TCP_FLAG_FIN | TCP_FLAG_ACK,
                             NULL, 0, true, true))
        {
            socket->connect_deadline = timer_ticks() + g_connect_timeout_ticks;
            socket->state = TCP_STATE_LAST_ACK;
            return;
        }
        tcp_mark_error(socket, "fin send failed");
    }

    if (socket->state == TCP_STATE_CLOSED || socket->state == TCP_STATE_ERROR)
    {
        tcp_reset_socket(socket);
    }
}

void net_tcp_socket_release(net_tcp_socket_t *socket)
{
    if (!socket)
    {
        return;
    }
    tcp_reset_socket(socket);
}

void net_tcp_poll(void)
{
    uint64_t now = timer_ticks();
    for (size_t i = 0; i < NET_TCP_MAX_SOCKETS; ++i)
    {
        net_tcp_socket_t *socket = &g_sockets[i];
        if (socket->state == TCP_STATE_UNUSED)
        {
            continue;
        }

        if (socket->state == TCP_STATE_ARP)
        {
            if (!socket->have_mac)
            {
                uint8_t mac[6];
                if (net_arp_lookup(socket->next_hop_ip, mac))
                {
                    memcpy(socket->remote_mac, mac, 6);
                    socket->have_mac = true;
                    if (tcp_send_syn(socket))
                    {
                        socket->state = TCP_STATE_SYN_SENT;
                    }
                    else
                    {
                        tcp_mark_error(socket, "syn send failed");
                    }
                    continue;
                }

                if (now - socket->last_arp_request_tick >= g_arp_retry_ticks)
                {
                    net_arp_send_request(socket->iface, socket->next_hop_ip);
                    socket->last_arp_request_tick = now;
                }
            }
            if (now > socket->connect_deadline)
            {
                tcp_mark_error(socket, "arp timeout");
            }
            continue;
        }

        if (socket->awaiting_ack)
        {
            if (now - socket->last_send_tick >= g_retransmit_ticks)
            {
                tcp_retransmit(socket);
            }
            if (socket->state == TCP_STATE_SYN_SENT || socket->state == TCP_STATE_FIN_WAIT_1 || socket->state == TCP_STATE_LAST_ACK)
            {
                if (now > socket->connect_deadline)
                {
                    tcp_mark_error(socket, "handshake timeout");
                }
            }
        }

        if (socket->state == TCP_STATE_FIN_WAIT_2 && socket->remote_closed)
        {
            socket->state = TCP_STATE_CLOSED;
        }
    }
}

static bool tcp_prepare_route(net_tcp_socket_t *socket, uint32_t remote_ip, uint16_t remote_port)
{
    net_interface_t *iface = socket->iface;
    uint32_t next_hop = remote_ip;
    if (!net_route_next_hop(iface, remote_ip, &iface, &next_hop))
    {
        return false;
    }
    socket->iface = iface;
    socket->remote_ip = remote_ip;
    socket->next_hop_ip = next_hop;
    socket->remote_port = remote_port;

    if (!socket->iface || socket->iface->ipv4_addr == 0)
    {
        return false;
    }

    /* Prefer a fresh ARP mapping; otherwise force an ARP query. */
    uint8_t mac[6];
    uint32_t freq = timer_frequency(); if (freq == 0) freq = 100;
    uint64_t max_age = (uint64_t)30 * freq; /* 30s */
    if (net_arp_lookup_fresh(next_hop, mac, max_age))
    {
        memcpy(socket->remote_mac, mac, 6);
        socket->have_mac = true;
    }
    else
    {
        socket->have_mac = false;
    }
    return true;
}



static bool tcp_send_syn(net_tcp_socket_t *socket)
{
    if (!socket->have_mac)
    {
        return false;
    }
    socket->connect_deadline = timer_ticks() + g_connect_timeout_ticks;
    return tcp_send_segment(socket, socket->seq_next, TCP_FLAG_SYN,
                            NULL, 0, true, true);
}
static void tcp_retransmit(net_tcp_socket_t *socket)
{
    if (!socket || !socket->awaiting_ack)
    {
        return;
    }

    if (socket->retry_count >= socket->max_retries)
    {
        tcp_mark_error(socket, "retry limit");
        return;
    }

    /* On the first miss, re-ARP the next hop to repair a stale neighbor entry. */
    if (socket->retry_count == 0)
    {
        net_arp_send_request(socket->iface, socket->next_hop_ip);
    }

    const uint8_t *payload = socket->pending_payload_len ? socket->pending_payload : NULL;
    size_t payload_len = socket->pending_payload_len;
    uint8_t flags = socket->pending_flags;
    uint32_t seq = socket->unacked_seq;

    if (!tcp_send_segment(socket, seq, flags, payload, payload_len, false, false))
    {
        tcp_mark_error(socket, "retransmit failed");
        return;
    }

    socket->retry_count++;
    socket->last_send_tick = timer_ticks();
}



void net_tcp_handle_frame(net_interface_t *iface, const uint8_t *frame, size_t length)
{
    if (!iface || !frame || length < 54)
    {
        return;
    }

    const uint8_t *eth = frame;
    uint16_t eth_type = (uint16_t)((eth[12] << 8) | eth[13]);
    if (eth_type != 0x0800)
    {
        return;
    }

    const uint8_t *ip = frame + 14;
    uint8_t version = (uint8_t)(ip[0] >> 4);
    uint8_t ihl = (uint8_t)(ip[0] & 0x0F);
    if (version != 4 || ihl < 5)
    {
        return;
    }
    size_t ip_header_len = (size_t)ihl * 4U;
    if (14 + ip_header_len > length)
    {
        return;
    }
    uint16_t total_len = read_be16(ip + 2);
    if (total_len < ip_header_len + 20U)
    {
        return;
    }
    size_t ip_available = length - 14;
    if (total_len > ip_available)
    {
        total_len = (uint16_t)ip_available;
    }
    if (ip[9] != 6)
    {
        return;
    }

    const uint8_t *tcp = ip + ip_header_len;
    size_t tcp_bytes = total_len - ip_header_len;
    if (tcp_bytes < 20)
    {
        return;
    }

    uint8_t data_offset = (uint8_t)(tcp[12] >> 4);
    size_t tcp_header_len = (size_t)data_offset * 4U;
    if (tcp_header_len < 20 || tcp_header_len > tcp_bytes)
    {
        return;
    }
    size_t payload_len = tcp_bytes - tcp_header_len;

    uint16_t src_port = read_be16(tcp + 0);
    uint16_t dst_port = read_be16(tcp + 2);
    uint32_t seq_num = read_be32(tcp + 4);
    uint32_t ack_num = read_be32(tcp + 8);
    uint8_t flags = tcp[13];
    uint16_t window = read_be16(tcp + 14);

    uint32_t src_ip = read_be32(ip + 12);
    uint32_t dst_ip = read_be32(ip + 16);

    net_tcp_socket_t *socket = tcp_find_socket(iface, dst_port, src_ip, src_port);
    if (!socket)
    {
        return;
    }

    if (socket->iface && socket->iface->ipv4_addr != 0 && dst_ip != socket->iface->ipv4_addr)
    {
        return;
    }

    /* Validate checksum */
    size_t tcp_len = tcp_header_len + payload_len;
    uint8_t tcp_copy[20 + NET_TCP_MAX_PAYLOAD];
    if (tcp_len > sizeof(tcp_copy))
    {
        return;
    }
    memcpy(tcp_copy, tcp, tcp_len);
    tcp_copy[16] = 0;
    tcp_copy[17] = 0;
    uint16_t calc = tcp_checksum(socket, tcp_copy, tcp_len);
    if (calc != read_be16(tcp + 16))
    {
        return;
    }

    socket->remote_window = window ? window : 1;
    socket->last_activity_tick = timer_ticks();

    if (flags & TCP_FLAG_RST)
    {
        tcp_mark_error(socket, "peer reset");
        return;
    }

    if ((flags & TCP_FLAG_ACK) != 0)
    {
        tcp_handle_ack(socket, ack_num);
    }

    if (socket->state == TCP_STATE_SYN_SENT &&
        (flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK))
    {
        socket->recv_next = seq_num + 1;
        socket->state = TCP_STATE_ESTABLISHED;
        socket->remote_closed = false;
        socket->awaiting_ack = false;
        socket->unacked_len = 0;
        socket->pending_payload_len = 0;
        socket->pending_flags = 0;
        tcp_send_ack(socket);
        seq_num += 1;
    }

    const uint8_t *payload = tcp + tcp_header_len;
    if (payload_len > 0)
    {
        tcp_process_payload(socket, seq_num, payload, payload_len);
    }

    if (flags & TCP_FLAG_FIN)
    {
        uint32_t fin_seq = seq_num + payload_len;
        if (fin_seq == socket->recv_next || (socket->state == TCP_STATE_SYN_SENT && socket->recv_next == 0))
        {
            socket->recv_next = fin_seq + 1;
            socket->remote_closed = true;
            if (socket->state == TCP_STATE_ESTABLISHED)
            {
                socket->state = TCP_STATE_CLOSE_WAIT;
            }
            else if (socket->state == TCP_STATE_FIN_WAIT_2)
            {
                socket->state = TCP_STATE_CLOSED;
            }
            else if (socket->state == TCP_STATE_FIN_WAIT_1)
            {
                socket->state = TCP_STATE_FIN_WAIT_2;
            }
            else if (socket->state == TCP_STATE_LAST_ACK)
            {
                socket->state = TCP_STATE_CLOSED;
            }
            tcp_send_ack(socket);
        }
    }
}

static void tcp_handle_ack(net_tcp_socket_t *socket, uint32_t ack_num)
{
    if (!socket || !socket->awaiting_ack)
    {
        return;
    }

    uint32_t expected = socket->unacked_seq + socket->unacked_len;
    if (ack_num < expected)
    {
        return;
    }

    socket->awaiting_ack = false;
    socket->unacked_len = 0;
    socket->pending_payload_len = 0;
    socket->pending_flags = 0;
    socket->retry_count = 0;

    if (socket->state == TCP_STATE_FIN_WAIT_1)
    {
        socket->state = TCP_STATE_FIN_WAIT_2;
    }
    else if (socket->state == TCP_STATE_LAST_ACK)
    {
        socket->state = TCP_STATE_CLOSED;
    }
}

static void tcp_process_payload(net_tcp_socket_t *socket, uint32_t seq_num,
                                const uint8_t *payload, size_t payload_len)
{
    if (!socket || payload_len == 0)
    {
        return;
    }

    if (socket->state != TCP_STATE_ESTABLISHED && socket->state != TCP_STATE_CLOSE_WAIT)
    {
        return;
    }

    if (seq_num != socket->recv_next)
    {
        tcp_send_ack(socket);
        return;
    }

    if (socket->rx_size + payload_len > NET_TCP_RX_CAPACITY)
    {
        tcp_mark_error(socket, "rx overflow");
        return;
    }

    memcpy(socket->rx_buffer + socket->rx_size, payload, payload_len);
    socket->rx_size += payload_len;
    socket->recv_next += (uint32_t)payload_len;

    tcp_send_ack(socket);
}

static void tcp_send_ack(net_tcp_socket_t *socket)
{
    if (!socket || !socket->have_mac)
    {
        return;
    }
    uint8_t flags = TCP_FLAG_ACK;
    tcp_send_segment(socket, socket->seq_next, flags, NULL, 0, false, false);
}

static net_tcp_socket_t *tcp_find_socket(net_interface_t *iface, uint16_t local_port,
                                         uint32_t remote_ip, uint16_t remote_port)
{
    for (size_t i = 0; i < NET_TCP_MAX_SOCKETS; ++i)
    {
        net_tcp_socket_t *socket = &g_sockets[i];
        if (socket->state == TCP_STATE_UNUSED)
        {
            continue;
        }
        if (socket->iface != iface)
        {
            continue;
        }
        if (socket->local_port != local_port)
        {
            continue;
        }
        if (socket->remote_ip != remote_ip)
        {
            continue;
        }
        if (socket->remote_port != remote_port)
        {
            continue;
        }
        return socket;
    }
    return NULL;
}

static void tcp_mark_error(net_tcp_socket_t *socket, const char *reason)
{
    if (!socket)
    {
        return;
    }
    if (reason)
    {
        serial_write_string("tcp: error ");
        serial_write_string(reason);
        serial_write_string("\r\n");
    }
    socket->error = true;
    socket->state = TCP_STATE_ERROR;
    socket->awaiting_ack = false;
    socket->pending_payload_len = 0;
}

static bool tcp_send_segment(net_tcp_socket_t *socket, uint32_t seq, uint8_t flags,
                             const uint8_t *payload, size_t payload_len, bool advance_seq,
                             bool track_retransmit)
{
    if (!socket || !socket->iface || !socket->have_mac)
    {
        return false;
    }

    uint8_t frame[14 + 20 + 20 + NET_TCP_MAX_PAYLOAD];
    memset(frame, 0, sizeof(frame));

    uint8_t *eth = frame;
    uint8_t *ip = frame + 14;
    uint8_t *tcp = ip + 20;

    memcpy(eth, socket->remote_mac, 6);
    memcpy(eth + 6, socket->iface->mac, 6);
    eth[12] = 0x08;
    eth[13] = 0x00;

    ip[0] = 0x45;
    ip[1] = 0x00;
    uint16_t ip_len = (uint16_t)(20 + 20 + payload_len);
    write_be16(ip + 2, ip_len);
    write_be16(ip + 4, 0);
    write_be16(ip + 6, 0x4000);
    ip[8] = 64;
    ip[9] = 6;
    write_be32(ip + 12, socket->iface->ipv4_addr);
    write_be32(ip + 16, socket->remote_ip);
    write_be16(ip + 10, 0);
    write_be16(ip + 10, checksum16(ip, 20));

    write_be16(tcp + 0, socket->local_port);
    write_be16(tcp + 2, socket->remote_port);
    write_be32(tcp + 4, seq);
    write_be32(tcp + 8, socket->recv_next);
    tcp[12] = (uint8_t)((5 << 4) & 0xF0);
    tcp[13] = flags;
    uint16_t window = (uint16_t)(NET_TCP_RX_CAPACITY - socket->rx_size);
    if (window == 0)
    {
        window = 1;
    }
    write_be16(tcp + 14, window);
    write_be16(tcp + 16, 0);
    write_be16(tcp + 18, 0);

    if (payload_len > 0 && payload)
    {
        memcpy(tcp + 20, payload, payload_len);
    }

    write_be16(tcp + 16, tcp_checksum(socket, tcp, 20 + payload_len));

    size_t frame_len = 14 + 20 + 20 + payload_len;
    if (frame_len < 60)
    {
        frame_len = 60;
    }

    if (!net_if_send(socket->iface, frame, frame_len))
    {
        return false;
    }

    if (advance_seq)
    {
        uint32_t advance = (uint32_t)payload_len;
        if (flags & TCP_FLAG_SYN)
        {
            advance += 1;
        }
        if (flags & TCP_FLAG_FIN)
        {
            advance += 1;
        }
        socket->seq_next = seq + advance;
    }

    if (track_retransmit)
    {
        socket->pending_flags = flags;
        socket->pending_payload_len = payload_len;
        if (payload_len > 0 && payload)
        {
            memcpy(socket->pending_payload, payload, payload_len);
        }
        socket->unacked_seq = seq;
        uint32_t needed = (uint32_t)payload_len;
        if (flags & TCP_FLAG_SYN)
        {
            needed += 1U;
        }
        if (flags & TCP_FLAG_FIN)
        {
            needed += 1U;
        }
        socket->unacked_len = needed;
        socket->awaiting_ack = true;
        socket->retry_count = 0;
        socket->last_send_tick = timer_ticks();
    }

    return true;
}

static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)
         | (uint32_t)p[3];
}

static void write_be16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)((value >> 8) & 0xFF);
    p[1] = (uint8_t)(value & 0xFF);
}

static void write_be32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)((value >> 24) & 0xFF);
    p[1] = (uint8_t)((value >> 16) & 0xFF);
    p[2] = (uint8_t)((value >> 8) & 0xFF);
    p[3] = (uint8_t)(value & 0xFF);
}

static uint16_t checksum16(const uint8_t *data, size_t len)
{
    uint32_t sum = 0;
    const uint8_t *ptr = data;
    while (len > 1)
    {
        sum += (uint32_t)((ptr[0] << 8) | ptr[1]);
        ptr += 2;
        len -= 2;
    }
    if (len)
    {
        sum += (uint32_t)(ptr[0] << 8);
    }
    while (sum >> 16)
    {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

static uint16_t tcp_checksum(const net_tcp_socket_t *socket, const uint8_t *tcp, size_t tcp_len)
{
    uint32_t sum = 0;
    uint32_t src_ip = socket->iface ? socket->iface->ipv4_addr : 0;
    uint32_t dst_ip = socket ? socket->remote_ip : 0;

    sum += (src_ip >> 16) & 0xFFFFU;
    sum += src_ip & 0xFFFFU;
    sum += (dst_ip >> 16) & 0xFFFFU;
    sum += dst_ip & 0xFFFFU;
    sum += 6U;
    sum += tcp_len;

    const uint8_t *ptr = tcp;
    size_t len = tcp_len;
    while (len > 1)
    {
        sum += (uint32_t)((ptr[0] << 8) | ptr[1]);
        ptr += 2;
        len -= 2;
    }
    if (len)
    {
        sum += (uint32_t)(ptr[0] << 8);
    }
    while (sum >> 16)
    {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}
