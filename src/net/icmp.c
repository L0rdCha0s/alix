#include "net/icmp.h"

#include "libc.h"
#include "timer.h"

static uint16_t read_be16(const uint8_t *p);
static uint32_t read_be32(const uint8_t *p);
static void write_be16(uint8_t *p, uint16_t value);
static void write_be32(uint8_t *p, uint32_t value);
static uint16_t checksum16(const uint8_t *data, size_t len);

typedef struct
{
    bool active;
    bool received;
    uint16_t identifier;
    uint16_t sequence;
    uint64_t send_tick;
    net_icmp_reply_t reply;
} icmp_pending_t;

static icmp_pending_t g_pending;

void net_icmp_reset_pending(void)
{
    memset(&g_pending, 0, sizeof(g_pending));
}

bool net_icmp_send_echo(net_interface_t *iface, const uint8_t target_mac[6],
                        uint32_t target_ip, uint16_t identifier, uint16_t sequence,
                        size_t payload_len)
{
    if (!iface || !iface->present || iface->ipv4_addr == 0 || !target_mac)
    {
        return false;
    }

    if (payload_len > 56)
    {
        payload_len = 56;
    }

    const size_t icmp_len = 8 + payload_len;
    const size_t ip_len = 20 + icmp_len;
    const size_t frame_len = 14 + ip_len;
    uint8_t buffer[128];
    memset(buffer, 0, sizeof(buffer));

    uint8_t *eth = buffer;
    uint8_t *ip = buffer + 14;
    uint8_t *icmp = ip + 20;

    memcpy(eth, target_mac, 6);
    memcpy(eth + 6, iface->mac, 6);
    eth[12] = 0x08;
    eth[13] = 0x00;

    ip[0] = 0x45;
    ip[1] = 0x00;
    write_be16(ip + 2, (uint16_t)ip_len);
    write_be16(ip + 4, 0); /* identification */
    write_be16(ip + 6, 0); /* flags/fragment */
    ip[8] = 64;
    ip[9] = 1; /* ICMP */
    write_be32(ip + 12, iface->ipv4_addr);
    write_be32(ip + 16, target_ip);
    write_be16(ip + 10, 0);
    write_be16(ip + 10, checksum16(ip, 20));

    icmp[0] = 8;
    icmp[1] = 0;
    write_be16(icmp + 2, 0);
    write_be16(icmp + 4, identifier);
    write_be16(icmp + 6, sequence);
    for (size_t i = 0; i < payload_len; ++i)
    {
        icmp[8 + i] = (uint8_t)(i & 0xFF);
    }
    write_be16(icmp + 2, checksum16(icmp, icmp_len));

    size_t send_len = frame_len;
    if (send_len < 60)
    {
        send_len = 60;
    }

    if (!net_if_send(iface, buffer, send_len))
    {
        return false;
    }

    g_pending.active = true;
    g_pending.received = false;
    g_pending.identifier = identifier;
    g_pending.sequence = sequence;
    g_pending.send_tick = timer_ticks();
    memset(&g_pending.reply, 0, sizeof(g_pending.reply));
    return true;
}

bool net_icmp_get_reply(uint16_t identifier, uint16_t sequence, net_icmp_reply_t *out_reply)
{
    if (!out_reply || !g_pending.active)
    {
        return false;
    }
    if (!g_pending.received)
    {
        return false;
    }
    if (g_pending.identifier != identifier || g_pending.sequence != sequence)
    {
        return false;
    }

    *out_reply = g_pending.reply;
    g_pending.active = false;
    g_pending.received = false;
    return true;
}

void net_icmp_handle_frame(net_interface_t *iface, const uint8_t *frame, size_t length)
{
    if (!iface || !frame || length < 42)
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
    if (14 + ip_header_len + 8 > length)
    {
        return;
    }

    if (ip[9] != 1)
    {
        return;
    }

    uint16_t total_length = read_be16(ip + 2);
    size_t total_len = (size_t)total_length;
    if (total_len < ip_header_len + 8 || (size_t)14 + total_len > length)
    {
        return;
    }

    const uint8_t *icmp = ip + ip_header_len;
    size_t icmp_len = (size_t)total_length - ip_header_len;
    uint8_t type = icmp[0];
    uint8_t code = icmp[1];

    if (type == 0 && code == 0 && icmp_len >= 8)
    {
        uint16_t identifier = read_be16(icmp + 4);
        uint16_t sequence = read_be16(icmp + 6);
        if (g_pending.active && g_pending.identifier == identifier && g_pending.sequence == sequence)
        {
            g_pending.received = true;
            g_pending.reply.bytes = icmp_len;
            g_pending.reply.from_ip = read_be32(ip + 12);
            g_pending.reply.rtt_ticks = timer_ticks() - g_pending.send_tick;
        }
        return;
    }

    if (type == 8 && code == 0 && icmp_len >= 8)
    {
        uint32_t dest_ip = read_be32(ip + 16);
        if (iface->ipv4_addr == 0 || dest_ip != iface->ipv4_addr)
        {
            return;
        }

        uint8_t reply[128];
        if (sizeof(reply) < (size_t)14 + total_len)
        {
            return;
        }
        memcpy(reply, frame, 14 + total_length);

        uint8_t *reply_eth = reply;
        uint8_t *reply_ip = reply + 14;
        uint8_t *reply_icmp = reply_ip + ip_header_len;

        memcpy(reply_eth, eth + 6, 6);
        memcpy(reply_eth + 6, iface->mac, 6);

        write_be32(reply_ip + 12, dest_ip);
        write_be32(reply_ip + 16, read_be32(ip + 12));
        reply_ip[8] = 64;
        write_be16(reply_ip + 10, 0);
        write_be16(reply_ip + 10, checksum16(reply_ip, ip_header_len));

        reply_icmp[0] = 0;
        reply_icmp[1] = 0;
        write_be16(reply_icmp + 2, 0);
        write_be16(reply_icmp + 2, checksum16(reply_icmp, icmp_len));

        size_t reply_len = (size_t)(14 + total_length);
        if (reply_len < 60)
        {
            reply_len = 60;
        }
        net_if_send(iface, reply, reply_len);
    }
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
    for (size_t i = 0; i + 1 < len; i += 2)
    {
        sum += (uint32_t)((data[i] << 8) | data[i + 1]);
    }
    if (len & 1)
    {
        sum += (uint32_t)(data[len - 1] << 8);
    }
    while (sum >> 16)
    {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}
