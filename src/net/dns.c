#include "net/dns.h"

#include <stddef.h>

#include "libc.h"
#include "serial.h"
#include "timer.h"

#include "net/arp.h"
#include "net/interface.h"
#include "net/route.h"
#include "rtl8139.h"

#define NET_DNS_MAX_SERVERS 4
#define NET_DNS_MAX_PENDING 4
#define NET_DNS_MAX_PACKET  512

#define DNS_FLAG_QR (1U << 15)
#define DNS_FLAG_OPCODE_SHIFT 11
#define DNS_FLAG_AA (1U << 10)
#define DNS_FLAG_TC (1U << 9)
#define DNS_FLAG_RD (1U << 8)
#define DNS_FLAG_RA (1U << 7)

typedef struct
{
    bool active;
    uint16_t id;
    uint16_t qtype;
    uint16_t local_port;
    char hostname[NET_DNS_NAME_MAX + 1];
    net_interface_t *iface;
    uint32_t server_ip;
    uint32_t next_hop;
    uint8_t server_mac[6];
    bool have_mac;
    uint64_t sent_tick;
    uint32_t retries;
    uint32_t timeout_ticks;
    bool completed;
    bool success;
    net_dns_result_t result;
} dns_pending_t;

static uint32_t g_servers[NET_DNS_MAX_SERVERS];
static size_t g_server_count = 0;
static dns_pending_t g_pending[NET_DNS_MAX_PENDING];
static uint16_t g_next_id = 0x1234;
static uint32_t g_retry_count = 3;
static uint16_t g_next_port = 0xC000;

static void dns_log(const char *msg);
static uint16_t read_be16(const uint8_t *p);
static void write_be16(uint8_t *p, uint16_t value);
static void write_be32(uint8_t *p, uint32_t value);
static bool dns_encode_question(const char *hostname, uint16_t qtype,
                                uint8_t *buffer, size_t *len_in_out);
static bool dns_decode_name(const uint8_t *packet, size_t packet_len,
                            size_t *offset, char *out_name, size_t capacity);
static dns_pending_t *dns_allocate_pending(void);
static void dns_release_pending(dns_pending_t *pending);
static bool dns_send_query(dns_pending_t *pending);
static bool dns_prepare_route(dns_pending_t *pending);
static uint16_t checksum16(const uint8_t *data, size_t len);
static uint16_t dns_allocate_port(void);

void net_dns_init(void)
{
    g_server_count = 0;
    for (size_t i = 0; i < NET_DNS_MAX_PENDING; ++i)
    {
        g_pending[i].active = false;
    }
}

void net_dns_set_servers(const uint32_t *servers, size_t count)
{
    g_server_count = 0;
    if (!servers || count == 0)
    {
        return;
    }
    for (size_t i = 0; i < count && g_server_count < NET_DNS_MAX_SERVERS; ++i)
    {
        if (servers[i] != 0)
        {
            g_servers[g_server_count++] = servers[i];
        }
    }
}

size_t net_dns_server_count(void)
{
    return g_server_count;
}

static dns_pending_t *dns_allocate_pending(void)
{
    for (size_t i = 0; i < NET_DNS_MAX_PENDING; ++i)
    {
        if (!g_pending[i].active)
        {
            memset(&g_pending[i], 0, sizeof(g_pending[i]));
            g_pending[i].active = true;
            return &g_pending[i];
        }
    }
    return NULL;
}

static void dns_release_pending(dns_pending_t *pending)
{
    if (pending)
    {
        pending->active = false;
        pending->local_port = 0;
    }
}

bool net_dns_resolve(const char *hostname, uint16_t qtype,
                     net_interface_t *preferred_iface, net_dns_result_t *result)
{
    if (!hostname || !result || qtype == 0)
    {
        return false;
    }
    size_t len = strlen(hostname);
    if (len == 0 || len > NET_DNS_NAME_MAX)
    {
        return false;
    }
    if (g_server_count == 0)
    {
        dns_log("no dns servers configured");
        return false;
    }

    dns_pending_t *pending = dns_allocate_pending();
    if (!pending)
    {
        return false;
    }

    pending->local_port = dns_allocate_port();
    if (pending->local_port == 0)
    {
        dns_release_pending(pending);
        return false;
    }

    memcpy(pending->hostname, hostname, len + 1);
    pending->qtype = qtype;
    pending->id = g_next_id++;
    pending->iface = preferred_iface;
    pending->timeout_ticks = timer_frequency();
    if (pending->timeout_ticks == 0)
    {
        pending->timeout_ticks = 100;
    }

    bool sent = false;
    for (size_t i = 0; i < g_server_count; ++i)
    {
        pending->server_ip = g_servers[i];
        pending->have_mac = false;
        pending->retries = 0;
        pending->completed = false;
        pending->success = false;

        if (!dns_prepare_route(pending))
        {
            continue;
        }
        if (dns_send_query(pending))
        {
            sent = true;
            break;
        }
    }

    if (!sent)
    {
        dns_release_pending(pending);
        return false;
    }

    uint64_t start = timer_ticks();
    uint64_t deadline = start + (pending->timeout_ticks * (g_retry_count + 1));

    while (!pending->completed)
    {
        uint64_t now = timer_ticks();
        if (now >= deadline)
        {
            break;
        }
        if (pending->sent_tick != 0 &&
            now - pending->sent_tick >= pending->timeout_ticks)
        {
            if (pending->retries >= g_retry_count)
            {
                break;
            }
            if (!dns_send_query(pending))
            {
                break;
            }
        }
        rtl8139_poll();
    }

    bool success = pending->completed && pending->success;
    if (success)
    {
        *result = pending->result;
    }
    dns_release_pending(pending);
    return success;
}

bool net_dns_resolve_ipv4(const char *hostname, net_interface_t *preferred_iface,
                          uint32_t *out_addr)
{
    if (!out_addr)
    {
        return false;
    }
    net_dns_result_t result;
    if (!net_dns_resolve(hostname, NET_DNS_TYPE_A, preferred_iface, &result))
    {
        return false;
    }
    if (!result.has_a)
    {
        return false;
    }
    *out_addr = result.addr;
    return true;
}

bool net_dns_resolve_cname(const char *hostname, net_interface_t *preferred_iface,
                           char *out_buffer, size_t buffer_len)
{
    if (!out_buffer || buffer_len == 0)
    {
        return false;
    }
    net_dns_result_t result;
    if (!net_dns_resolve(hostname, NET_DNS_TYPE_CNAME, preferred_iface, &result))
    {
        return false;
    }
    if (!result.has_cname)
    {
        return false;
    }
    size_t len = strlen(result.cname);
    if (len >= buffer_len)
    {
        return false;
    }
    memcpy(out_buffer, result.cname, len + 1);
    return true;
}

static void dns_finish_pending(dns_pending_t *pending, bool success, const net_dns_result_t *result)
{
    if (!pending)
    {
        return;
    }
    pending->completed = true;
    pending->success = success;
    if (success && result)
    {
        pending->result = *result;
    }
}

static bool dns_prepare_route(dns_pending_t *pending)
{
    net_interface_t *iface = pending->iface;
    uint32_t next_hop = pending->server_ip;
    if (!net_route_next_hop(iface, pending->server_ip, &iface, &next_hop))
    {
        return false;
    }
    if (!iface || !iface->present || !iface->link_up || iface->ipv4_addr == 0)
    {
        return false;
    }
    pending->iface = iface;
    pending->next_hop = next_hop;

    uint8_t mac[6];
    if (net_arp_lookup(next_hop, mac))
    {
        memcpy(pending->server_mac, mac, 6);
        pending->have_mac = true;
    }
    else
    {
        pending->have_mac = false;
    }
    return true;
}

static bool dns_send_query(dns_pending_t *pending)
{
    net_interface_t *iface = pending->iface;
    if (!iface)
    {
        return false;
    }

    if (!pending->have_mac)
    {
        if (!net_arp_send_request(iface, pending->next_hop))
        {
            return false;
        }
        uint64_t start = timer_ticks();
        uint64_t wait_ticks = timer_frequency() / 5; /* ~200ms */
        if (wait_ticks == 0)
        {
            wait_ticks = 20;
        }
        while (timer_ticks() - start < wait_ticks)
        {
            rtl8139_poll();
            uint8_t mac[6];
            if (net_arp_lookup(pending->next_hop, mac))
            {
                memcpy(pending->server_mac, mac, 6);
                pending->have_mac = true;
                break;
            }
        }
        if (!pending->have_mac)
        {
            return false;
        }
    }

    uint8_t packet[NET_DNS_MAX_PACKET];
    memset(packet, 0, sizeof(packet));
    if (sizeof(packet) < 64)
    {
        return false;
    }

    uint8_t *eth = packet;
    uint8_t *ip = packet + 14;
    uint8_t *udp = ip + 20;
    uint8_t *dns = udp + 8;

    size_t dns_len = 12;
    write_be16(dns + 0, pending->id);
    write_be16(dns + 2, DNS_FLAG_RD);
    write_be16(dns + 4, 1); /* QDCOUNT */
    write_be16(dns + 6, 0);
    write_be16(dns + 8, 0);
    write_be16(dns + 10, 0);

    size_t question_len = NET_DNS_MAX_PACKET - (dns_len);
    size_t tmp_len = question_len;
    if (!dns_encode_question(pending->hostname, pending->qtype, dns + dns_len, &tmp_len))
    {
        return false;
    }
    dns_len += tmp_len;

    size_t udp_len = 8 + dns_len;
    size_t ip_len = 20 + udp_len;
    size_t frame_len = 14 + ip_len;
    if (frame_len < 60)
    {
        frame_len = 60;
    }

    memcpy(eth, pending->server_mac, 6);
    memcpy(eth + 6, iface->mac, 6);
    eth[12] = 0x08;
    eth[13] = 0x00;

    ip[0] = 0x45;
    ip[1] = 0x00;
    write_be16(ip + 2, (uint16_t)ip_len);
    write_be16(ip + 4, 0);
    write_be16(ip + 6, 0);
    ip[8] = 64;
    ip[9] = 17;
    write_be32(ip + 12, iface->ipv4_addr);
    write_be32(ip + 16, pending->server_ip);
    write_be16(ip + 10, 0);
    write_be16(ip + 10, checksum16(ip, 20));

    write_be16(udp + 0, pending->local_port);
    write_be16(udp + 2, 53);
    write_be16(udp + 4, (uint16_t)udp_len);
    write_be16(udp + 6, 0);

    uint32_t sum = 0;
    sum += (iface->ipv4_addr >> 16) & 0xFFFFU;
    sum += iface->ipv4_addr & 0xFFFFU;
    sum += (pending->server_ip >> 16) & 0xFFFFU;
    sum += pending->server_ip & 0xFFFFU;
    sum += 17;
    sum += (uint32_t)udp_len;
    const uint8_t *udp_ptr = udp;
    size_t udp_bytes = udp_len;
    while (udp_bytes > 1)
    {
        sum += (uint32_t)((udp_ptr[0] << 8) | udp_ptr[1]);
        udp_ptr += 2;
        udp_bytes -= 2;
    }
    if (udp_bytes)
    {
        sum += (uint32_t)(udp_ptr[0] << 8);
    }
    while (sum >> 16)
    {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }
    write_be16(udp + 6, (uint16_t)(~sum));

    if (!net_if_send(iface, packet, frame_len))
    {
        return false;
    }

    pending->sent_tick = timer_ticks();
    pending->retries++;
    return true;
}

void net_dns_handle_frame(net_interface_t *iface, const uint8_t *frame, size_t length)
{
    if (!iface || !frame || length < 14 + 20 + 8)
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
    size_t ip_header_len = (size_t)ihl * 4;
    if (length < 14 + ip_header_len + 8)
    {
        return;
    }
    if (ip[9] != 17)
    {
        return;
    }
    uint16_t dst_port = read_be16(ip + ip_header_len + 2);
    dns_pending_t *pending = NULL;
    for (size_t i = 0; i < NET_DNS_MAX_PENDING; ++i)
    {
        if (g_pending[i].active && g_pending[i].local_port == dst_port)
        {
            pending = &g_pending[i];
            break;
        }
    }
    if (!pending)
    {
        return;
    }
    uint16_t src_port = read_be16(ip + ip_header_len + 0);
    if (src_port != 53)
    {
        return;
    }
    uint16_t total_len = read_be16(ip + 2);
    size_t ip_payload_len = total_len > ip_header_len ? total_len - ip_header_len : 0;
    if (ip_payload_len < 8)
    {
        return;
    }
    const uint8_t *udp = ip + ip_header_len;
    uint16_t udp_len = read_be16(udp + 4);
    if (udp_len < 8)
    {
        return;
    }
    const uint8_t *dns = udp + 8;
    size_t dns_len = udp_len - 8;
    if (dns_len < 12)
    {
        return;
    }

    uint16_t id = read_be16(dns + 0);
    if (!pending || !pending->active || pending->iface != iface || pending->id != id)
    {
        return;
    }

    uint16_t flags = read_be16(dns + 2);
    if ((flags & DNS_FLAG_QR) == 0)
    {
        return;
    }
    uint16_t qdcount = read_be16(dns + 4);
    uint16_t ancount = read_be16(dns + 6);

    size_t offset = 12;
    for (uint16_t i = 0; i < qdcount; ++i)
    {
        char name[NET_DNS_NAME_MAX + 1];
        if (!dns_decode_name(dns, dns_len, &offset, name, sizeof(name)))
        {
            dns_finish_pending(pending, false, NULL);
            return;
        }
        if (offset + 4 > dns_len)
        {
            dns_finish_pending(pending, false, NULL);
            return;
        }
        offset += 4;
    }

    net_dns_result_t res;
    memset(&res, 0, sizeof(res));

    for (uint16_t i = 0; i < ancount; ++i)
    {
        char rr_name[NET_DNS_NAME_MAX + 1];
        if (!dns_decode_name(dns, dns_len, &offset, rr_name, sizeof(rr_name)))
        {
            dns_finish_pending(pending, false, NULL);
            return;
        }
        if (offset + 10 > dns_len)
        {
            dns_finish_pending(pending, false, NULL);
            return;
        }
        uint16_t type = read_be16(dns + offset);
        uint16_t rr_class = read_be16(dns + offset + 2);
        uint16_t rdlength = read_be16(dns + offset + 8);
        offset += 10;
        if (offset + rdlength > dns_len)
        {
            dns_finish_pending(pending, false, NULL);
            return;
        }
        if (rr_class != 1)
        {
            offset += rdlength;
            continue;
        }
        if (type == NET_DNS_TYPE_A && rdlength == 4)
        {
            res.has_a = true;
            res.addr = ((uint32_t)dns[offset] << 24)
                     | ((uint32_t)dns[offset + 1] << 16)
                     | ((uint32_t)dns[offset + 2] << 8)
                     | (uint32_t)dns[offset + 3];
            res.rr_type = NET_DNS_TYPE_A;
            dns_finish_pending(pending, true, &res);
            return;
        }
        else if (type == NET_DNS_TYPE_CNAME)
        {
            size_t cname_offset = offset;
            if (dns_decode_name(dns, dns_len, &cname_offset, res.cname, sizeof(res.cname)))
            {
                res.has_cname = true;
                res.rr_type = NET_DNS_TYPE_CNAME;
                offset += rdlength;
                dns_finish_pending(pending, true, &res);
                return;
            }
            dns_finish_pending(pending, false, NULL);
            return;
        }
        else
        {
            offset += rdlength;
        }
    }

    dns_finish_pending(pending, false, NULL);
}

static bool dns_encode_label(const char **cursor, uint8_t *buffer, size_t *offset, size_t capacity)
{
    const char *start = *cursor;
    size_t len = 0;
    while (start[len] && start[len] != '.')
    {
        ++len;
    }
    if (len > 63)
    {
        return false;
    }
    if (*offset + len + 1 >= capacity)
    {
        return false;
    }
    buffer[(*offset)++] = (uint8_t)len;
    memcpy(buffer + *offset, start, len);
    *offset += len;
    *cursor = start + len;
    if (**cursor == '.')
    {
        ++(*cursor);
    }
    return true;
}

static bool dns_encode_question(const char *hostname, uint16_t qtype,
                                uint8_t *buffer, size_t *len_in_out)
{
    size_t capacity = *len_in_out;
    size_t offset = 0;
    const char *cursor = hostname;
    if (*cursor == '\0')
    {
        return false;
    }
    while (*cursor)
    {
        if (!dns_encode_label(&cursor, buffer, &offset, capacity))
        {
            return false;
        }
    }
    if (offset + 5 > capacity)
    {
        return false;
    }
    buffer[offset++] = 0;
    write_be16(buffer + offset, qtype);
    offset += 2;
    write_be16(buffer + offset, 1);
    offset += 2;
    *len_in_out = offset;
    return true;
}

static bool dns_decode_name(const uint8_t *packet, size_t packet_len,
                            size_t *offset, char *out_name, size_t capacity)
{
    size_t pos = *offset;
    size_t out_len = 0;
    bool jumped = false;
    size_t safety = packet_len;

    if (capacity == 0)
    {
        return false;
    }

    while (safety-- > 0)
    {
        if (pos >= packet_len)
        {
            return false;
        }
        uint8_t len = packet[pos];
        if (len == 0)
        {
            pos++;
            if (!jumped)
            {
                *offset = pos;
            }
            if (out_len >= capacity)
            {
                return false;
            }
            out_name[out_len] = '\0';
            return true;
        }
        if ((len & 0xC0) == 0xC0)
        {
            if (pos + 1 >= packet_len)
            {
                return false;
            }
            uint16_t pointer = ((len & 0x3F) << 8) | packet[pos + 1];
            if (pointer >= packet_len)
            {
                return false;
            }
            if (!jumped)
            {
                *offset = pos + 2;
            }
            pos = pointer;
            jumped = true;
            continue;
        }
        if (len > 63)
        {
            return false;
        }
        pos++;
        if (pos + len > packet_len)
        {
            return false;
        }
        if (out_len != 0)
        {
            if (out_len + 1 >= capacity)
            {
                return false;
            }
            out_name[out_len++] = '.';
        }
        if (out_len + len >= capacity)
        {
            return false;
        }
        memcpy(out_name + out_len, packet + pos, len);
        out_len += len;
        pos += len;
        if (!jumped)
        {
            *offset = pos;
        }
    }
    return false;
}

static void write_be32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)((value >> 24) & 0xFF);
    p[1] = (uint8_t)((value >> 16) & 0xFF);
    p[2] = (uint8_t)((value >> 8) & 0xFF);
    p[3] = (uint8_t)(value & 0xFF);
}

static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static void write_be16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)((value >> 8) & 0xFF);
    p[1] = (uint8_t)(value & 0xFF);
}

static void dns_log(const char *msg)
{
    serial_write_string("dns: ");
    serial_write_string(msg);
    serial_write_string("\r\n");
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

static uint16_t dns_allocate_port(void)
{
    for (size_t attempt = 0; attempt < 0x8000; ++attempt)
    {
        if (g_next_port < 0xC000)
        {
            g_next_port = 0xC000;
        }
        uint16_t candidate = g_next_port++;
        if (g_next_port >= 0xFFF0)
        {
            g_next_port = 0xC000;
        }
        bool in_use = false;
        for (size_t i = 0; i < NET_DNS_MAX_PENDING; ++i)
        {
            if (g_pending[i].active && g_pending[i].local_port == candidate)
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
