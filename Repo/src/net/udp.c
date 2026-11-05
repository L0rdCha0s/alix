#include "net/udp.h"
#include "net/route.h"
#include "net/arp.h"
#include "heap.h"
#include "libc.h"
#include "spinlock.h"
#include "timer.h"
#include "errno.h"
#include "io_event_service.h"
#include <stdint.h>

#define UDP_SOCKET_LIMIT 256u
#define UDP_PACKET_LIMIT 128u
#define UDP_GLOBAL_QUEUE_LIMIT (32u * 1024u * 1024u)
#define UDP_BUFFER_MAX (4u * 1024u * 1024u)
typedef struct udp_packet
{
    struct udp_packet *next;
    net_udp_packet_info_t info;
    unsigned char data[];
} udp_packet_t;
struct net_udp_socket
{
    struct net_udp_socket *next;
    uint32_t references, bound_ip, peer_ip, peer_source;
    uint16_t local_port, peer_port;
    uint32_t receive_capacity, send_capacity, queued_bytes, packet_count;
    uint8_t tos, ttl;
    bool sending;
    uint32_t arp_ip;
    uint64_t arp_next, arp_deadline, tx_retry;
    uint64_t dropped_packets;
    udp_packet_t *head, *tail;
};
static spinlock_t g_udp_lock;
static net_udp_socket_t *g_udp_sockets;
static size_t g_udp_socket_count, g_udp_queue_bytes;
static uint32_t g_udp_ip_id;

static uint16_t udp_be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t udp_be32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
static void udp_put16(uint8_t *p, uint16_t n) { p[0] = (uint8_t)(n >> 8); p[1] = (uint8_t)n; }
static void udp_put32(uint8_t *p, uint32_t n) { p[0] = (uint8_t)(n >> 24); p[1] = (uint8_t)(n >> 16); p[2] = (uint8_t)(n >> 8); p[3] = (uint8_t)n; }
static uint32_t udp_sum(uint32_t sum, const uint8_t *p, size_t size)
{
    while (size >= 2) { sum += udp_be16(p); p += 2; size -= 2; }
    if (size) sum += (uint32_t)*p << 8;
    while (sum >> 16) sum = (sum & 65535u) + (sum >> 16);
    return sum;
}
static uint16_t udp_checksum(const uint8_t *ip, const uint8_t *udp, size_t length)
{
    return (uint16_t)~udp_sum(udp_sum(17u + (uint32_t)length, ip + 12, 8), udp, length);
}
static bool udp_registered(net_udp_socket_t *socket)
{
    for (net_udp_socket_t *p = g_udp_sockets; p; p = p->next) if (p == socket) return true;
    return false;
}
static bool udp_address_valid(uint32_t address)
{
    if (!address) return true;
    bool valid = false;
    uint64_t flags = net_config_lock();
    for (size_t i = 0; i < net_if_count(); ++i)
    {
        net_interface_t *iface = net_if_at(i);
        if (iface && iface->present && iface->ipv4_addr == address) { valid = true; break; }
    }
    net_config_unlock(flags);
    return valid;
}
static int udp_bind_locked(net_udp_socket_t *socket, uint32_t ip, uint16_t port)
{
    if (socket->local_port) return -EINVAL;
    uint16_t chosen = 0;
    int result = net_udp_port_claim(socket, ip, port, &chosen);
    if (!result) { socket->bound_ip = ip; socket->local_port = chosen; }
    return result;
}

net_udp_socket_t *net_udp_socket_open_owned(void)
{
    net_udp_socket_t *socket = calloc(1, sizeof(*socket));
    if (!socket) return NULL;
    socket->references = 1; socket->receive_capacity = 262144; socket->send_capacity = 65536; socket->ttl = 64;
    uint64_t flags = spinlock_lock_irqsave(&g_udp_lock);
    if (g_udp_socket_count == UDP_SOCKET_LIMIT)
    { spinlock_unlock_irqrestore(&g_udp_lock, flags); free(socket); return NULL; }
    socket->next = g_udp_sockets; g_udp_sockets = socket; ++g_udp_socket_count;
    spinlock_unlock_irqrestore(&g_udp_lock, flags);
    return socket;
}
bool net_udp_socket_get_owned(net_udp_socket_t *socket)
{
    uint64_t flags = spinlock_lock_irqsave(&g_udp_lock);
    bool valid = udp_registered(socket) && socket->references < UINT32_MAX;
    if (valid) ++socket->references;
    spinlock_unlock_irqrestore(&g_udp_lock, flags);
    return valid;
}
int net_udp_socket_put_owned(net_udp_socket_t *socket)
{
    uint64_t flags = spinlock_lock_irqsave(&g_udp_lock);
    if (!udp_registered(socket)) { spinlock_unlock_irqrestore(&g_udp_lock, flags); return -EBADF; }
    if (--socket->references) { spinlock_unlock_irqrestore(&g_udp_lock, flags); return 0; }
    net_udp_socket_t **link = &g_udp_sockets;
    while (*link != socket) link = &(*link)->next;
    *link = socket->next; --g_udp_socket_count;
    net_udp_port_release(socket);
    udp_packet_t *packets = socket->head;
    g_udp_queue_bytes -= socket->queued_bytes + socket->packet_count * sizeof(udp_packet_t);
    spinlock_unlock_irqrestore(&g_udp_lock, flags);
    while (packets) { udp_packet_t *next = packets->next; free(packets); packets = next; }
    free(socket);
    return 0;
}
int net_udp_socket_bind_owned(net_udp_socket_t *socket, uint32_t ip, uint16_t port)
{
    if (!udp_address_valid(ip)) return -EADDRNOTAVAIL;
    uint64_t flags = spinlock_lock_irqsave(&g_udp_lock);
    int result = udp_registered(socket) ? udp_bind_locked(socket, ip, port) : -EBADF;
    spinlock_unlock_irqrestore(&g_udp_lock, flags);
    return result;
}
int net_udp_socket_connect_owned(net_udp_socket_t *socket, uint32_t ip, uint16_t port)
{
    alix_net_route_info_t *route = calloc(1, sizeof(*route));
    if (!route) return -ENOMEM;
    if ((!ip != !port) || (ip && !net_route_ipv4_snapshot(ip, route)))
    { free(route); return !ip || !port ? -EINVAL : -ENETUNREACH; }
    uint64_t flags = spinlock_lock_irqsave(&g_udp_lock);
    int result = !udp_registered(socket) ? -EBADF :
        ip && socket->bound_ip && socket->bound_ip != route->source_ipv4 ? -EADDRNOTAVAIL : 0;
    if (!result && ip && !socket->local_port) result = udp_bind_locked(socket, 0, 0);
    if (!result) { socket->peer_ip = ip; socket->peer_port = port; socket->peer_source = route->source_ipv4; }
    spinlock_unlock_irqrestore(&g_udp_lock, flags);
    free(route);
    return result;
}
int net_udp_socket_info_owned(net_udp_socket_t *socket, net_udp_socket_info_t *info)
{
    if (!info) return -EINVAL;
    uint64_t flags = spinlock_lock_irqsave(&g_udp_lock);
    int result = udp_registered(socket) ? 0 : -EBADF;
    uint32_t arp_ip = result ? 0 : socket->arp_ip;
    uint64_t deadline = result ? 0 : socket->arp_deadline;
    spinlock_unlock_irqrestore(&g_udp_lock, flags);
    /* ARP has its own gate. Never acquire it while holding the socket gate. */
    uint8_t mac[6];
    bool arp_ready = !arp_ip || timer_monotonic_millis() >= deadline || net_arp_lookup(arp_ip, mac);
    flags = spinlock_lock_irqsave(&g_udp_lock);
    if (!result)
        *info = (net_udp_socket_info_t){ .references = socket->references,
            .flags = (socket->local_port ? NET_UDP_BOUND : 0) | (socket->peer_ip ? NET_UDP_CONNECTED : 0) |
                     (socket->head ? NET_UDP_READABLE : 0) |
                     (!socket->sending && arp_ready && timer_monotonic_millis() >= socket->tx_retry ? NET_UDP_WRITABLE : 0),
            .local_ip = socket->bound_ip ? socket->bound_ip : socket->peer_source, .remote_ip = socket->peer_ip,
            .local_port = socket->local_port, .remote_port = socket->peer_port,
            .available = socket->head ? socket->head->info.length : 0,
            .receive_capacity = socket->receive_capacity, .send_capacity = socket->send_capacity,
            .queued_bytes = socket->queued_bytes, .tos = socket->tos, .ttl = socket->ttl,
            .dropped_packets = socket->dropped_packets };
    spinlock_unlock_irqrestore(&g_udp_lock, flags);
    return result;
}
int net_udp_socket_option_owned(net_udp_socket_t *socket, net_udp_option_t option, int value)
{
    uint64_t flags = spinlock_lock_irqsave(&g_udp_lock);
    int result = udp_registered(socket) ? 0 : -EBADF;
    if (!result) switch (option)
    {
        case NET_UDP_RECV_BUFFER: case NET_UDP_SEND_BUFFER:
            if (value < 256 || value > (int)UDP_BUFFER_MAX) result = -EINVAL;
            else if (option == NET_UDP_RECV_BUFFER && socket->queued_bytes > (uint32_t)value) result = -EBUSY;
            else if (option == NET_UDP_RECV_BUFFER) socket->receive_capacity = (uint32_t)value;
            else socket->send_capacity = (uint32_t)value;
            break;
        case NET_UDP_TOS:
            if (value < 0 || value > 255) result = -EINVAL; else socket->tos = (uint8_t)value;
            break;
        case NET_UDP_TTL:
            if (value < 1 || value > 255) result = -EINVAL; else socket->ttl = (uint8_t)value;
            break;
        default: result = -ENOPROTOOPT;
    }
    spinlock_unlock_irqrestore(&g_udp_lock, flags);
    return result;
}

bool net_udp_handle_frame(net_interface_t *iface, const uint8_t *frame, size_t length)
{
    if (!iface || !frame || length < 42 || udp_be16(frame + 12) != 0x0800) return false;
    const uint8_t *ip = frame + 14;
    size_t ihl = (size_t)(ip[0] & 15) * 4;
    if ((ip[0] >> 4) != 4 || ihl < 20 || length < 14 + ihl + 8 || ip[9] != 17 ||
        (udp_be16(ip + 6) & 0x3fff) || udp_sum(0, ip, ihl) != 65535) return false;
    size_t ip_length = udp_be16(ip + 2);
    if (ip_length < ihl + 8 || ip_length > length - 14) return false;
    const uint8_t *udp = ip + ihl;
    size_t udp_length = udp_be16(udp + 4);
    if (udp_length < 8 || udp_length > ip_length - ihl || udp_length - 8 > NET_UDP_MAX_PAYLOAD ||
        (udp_be16(udp + 6) && udp_checksum(ip, udp, udp_length))) return false;
    uint32_t source = udp_be32(ip + 12), destination = udp_be32(ip + 16);
    uint16_t source_port = udp_be16(udp), destination_port = udp_be16(udp + 2);
    uint32_t interface_index = 0;
    uint64_t config = net_config_lock();
    bool local = iface->present && iface->link_up && iface->ipv4_addr && iface->ipv4_addr == destination;
    for (size_t i = 0; local && i < net_if_count(); ++i) if (net_if_at(i) == iface) { interface_index = (uint32_t)i + 1; break; }
    net_config_unlock(config);
    if (!local || !source_port || !destination_port) return false;
    uint64_t flags = spinlock_lock_irqsave(&g_udp_lock);
    bool handled = false;
    bool became_readable = false;
    for (net_udp_socket_t *socket = g_udp_sockets; socket; socket = socket->next)
    {
        if (socket->local_port != destination_port || (socket->bound_ip && socket->bound_ip != destination) ||
            (socket->peer_ip && (socket->peer_ip != source || socket->peer_port != source_port))) continue;
        handled = true;
        size_t bytes = udp_length - 8, charged = sizeof(udp_packet_t) + bytes;
        udp_packet_t *packet = NULL;
        if (socket->packet_count < UDP_PACKET_LIMIT && bytes <= socket->receive_capacity - socket->queued_bytes &&
            charged <= UDP_GLOBAL_QUEUE_LIMIT - g_udp_queue_bytes) packet = malloc(charged);
        if (!packet) { ++socket->dropped_packets; break; }
        packet->next = NULL;
        packet->info = (net_udp_packet_info_t){ .source_ip = source, .destination_ip = destination,
            .length = (uint32_t)bytes, .interface_index = interface_index,
            .source_port = source_port, .tos = ip[1], .ttl = ip[8] };
        if (bytes) memcpy(packet->data, udp + 8, bytes);
        became_readable = socket->head == NULL;
        if (socket->tail) socket->tail->next = packet; else socket->head = packet;
        socket->tail = packet; ++socket->packet_count; socket->queued_bytes += (uint32_t)bytes;
        g_udp_queue_bytes += charged;
        break;
    }
    spinlock_unlock_irqrestore(&g_udp_lock, flags);
    if (became_readable) io_event_service_notify();
    return handled;
}

ssize_t net_udp_socket_recv_owned(net_udp_socket_t *socket, void *data, size_t capacity,
                                 bool peek, net_udp_packet_info_t *info)
{
    if (!info || (capacity && !data)) return -EINVAL;
    uint64_t flags = spinlock_lock_irqsave(&g_udp_lock);
    if (!udp_registered(socket)) { spinlock_unlock_irqrestore(&g_udp_lock, flags); return -EBADF; }
    udp_packet_t *packet = socket->head;
    if (!packet) { spinlock_unlock_irqrestore(&g_udp_lock, flags); return -EAGAIN; }
    size_t copied = packet->info.length < capacity ? packet->info.length : capacity;
    if (copied) memcpy(data, packet->data, copied);
    *info = packet->info;
    if (!peek)
    {
        socket->head = packet->next; if (!socket->head) socket->tail = NULL;
        --socket->packet_count; socket->queued_bytes -= packet->info.length;
        g_udp_queue_bytes -= sizeof(*packet) + packet->info.length;
    }
    spinlock_unlock_irqrestore(&g_udp_lock, flags);
    if (!peek) free(packet);
    return (ssize_t)copied;
}

ssize_t net_udp_socket_send_owned(net_udp_socket_t *socket, const void *data, size_t length,
                                 uint32_t ip, uint16_t port, int tos, uint32_t source_ip,
                                 uint64_t *next_arp_ms)
{
    if ((length && !data) || tos < -1 || tos > 255) return -EINVAL;
    uint64_t flags = spinlock_lock_irqsave(&g_udp_lock);
    if (!udp_registered(socket)) { spinlock_unlock_irqrestore(&g_udp_lock, flags); return -EBADF; }
    if (!ip && !port) { ip = socket->peer_ip; port = socket->peer_port; }
    int result = !ip || !port ? -EDESTADDRREQ : length > socket->send_capacity ? -EMSGSIZE : 0;
    uint32_t local_ip = socket->bound_ip ? socket->bound_ip : socket->peer_source;
    uint8_t ttl = socket->ttl, packet_tos = tos < 0 ? socket->tos : (uint8_t)tos;
    spinlock_unlock_irqrestore(&g_udp_lock, flags);
    if (result) return result;
    alix_net_route_info_t *route = calloc(1, sizeof(*route));
    if (!route) return -ENOMEM;
    if (!net_route_ipv4_snapshot(ip, route)) { free(route); return -ENETUNREACH; }
    if ((local_ip && route->source_ipv4 != local_ip) || (source_ip && source_ip != route->source_ipv4))
    { free(route); return -EADDRNOTAVAIL; }
    if (length > NET_UDP_MAX_PAYLOAD || route->mtu < 28 || length > route->mtu - 28)
    { free(route); return -EMSGSIZE; }
    flags = spinlock_lock_irqsave(&g_udp_lock);
    if (!socket->local_port) result = udp_bind_locked(socket, 0, 0);
    if (!result && (socket->sending || timer_monotonic_millis() < socket->tx_retry)) result = -EAGAIN;
    uint16_t local_port = socket->local_port;
    if (!result) socket->sending = true;
    spinlock_unlock_irqrestore(&g_udp_lock, flags);
    if (result) { free(route); return result; }
    size_t bytes = 42 + length;
    uint8_t *frame = calloc(1, bytes);
    net_interface_t *iface = net_if_by_name(route->interface_name);
    if (!frame) result = -ENOMEM;
    else if (!iface) result = -ENETUNREACH;
    else
    {
        bool local = ip == route->source_ipv4;
        if (!local && !net_arp_lookup(route->next_hop_ipv4, frame))
        {
            uint64_t now = timer_monotonic_millis();
            bool request = false;
            flags = spinlock_lock_irqsave(&g_udp_lock);
            if (socket->arp_ip != route->next_hop_ipv4)
            {
                socket->arp_ip = route->next_hop_ipv4;
                socket->arp_deadline = now > UINT64_MAX - 5000 ? UINT64_MAX : now + 5000;
                socket->arp_next = 0;
            }
            result = now >= socket->arp_deadline ? -EHOSTUNREACH : -EAGAIN;
            if (result == -EHOSTUNREACH) socket->arp_ip = 0;
            else if (now >= socket->arp_next)
            { socket->arp_next = now > UINT64_MAX - 250 ? UINT64_MAX : now + 250; request = true; }
            if (next_arp_ms) *next_arp_ms = socket->arp_next;
            spinlock_unlock_irqrestore(&g_udp_lock, flags);
            if (request) (void)net_arp_send_request(iface, route->next_hop_ipv4);
        }
        else
        {
            uint64_t config = net_config_lock();
            if (!iface->link_up || iface->ipv4_addr != route->source_ipv4) result = -EAGAIN;
            else { memcpy(frame + 6, iface->mac, 6); if (local) memcpy(frame, iface->mac, 6); }
            net_config_unlock(config);
            if (!result)
            {
                frame[12] = 8;
                uint8_t *header = frame + 14, *udp = header + 20;
                header[0] = 0x45; header[1] = packet_tos;
                udp_put16(header + 2, (uint16_t)(28 + length));
                udp_put16(header + 4, (uint16_t)__atomic_add_fetch(&g_udp_ip_id, 1, __ATOMIC_RELAXED));
                udp_put16(header + 6, 0x4000); header[8] = ttl; header[9] = 17;
                udp_put32(header + 12, route->source_ipv4); udp_put32(header + 16, ip);
                udp_put16(header + 10, (uint16_t)~udp_sum(0, header, 20));
                udp_put16(udp, local_port); udp_put16(udp + 2, port); udp_put16(udp + 4, (uint16_t)(8 + length));
                if (length) memcpy(udp + 8, data, length);
                uint16_t checksum = udp_checksum(header, udp, 8 + length);
                udp_put16(udp + 6, checksum ? checksum : 65535);
                if (local) (void)net_udp_handle_frame(iface, frame, bytes);
                else if (!net_if_send_copy(iface, frame, bytes)) result = -EAGAIN;
                flags = spinlock_lock_irqsave(&g_udp_lock);
                socket->arp_ip = 0;
                socket->tx_retry = result == -EAGAIN ? timer_monotonic_millis() + 10 : 0;
                spinlock_unlock_irqrestore(&g_udp_lock, flags);
            }
        }
    }
    free(frame); free(route);
    flags = spinlock_lock_irqsave(&g_udp_lock); socket->sending = false;
    spinlock_unlock_irqrestore(&g_udp_lock, flags);
    return result ? result : (ssize_t)length;
}
