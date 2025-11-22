#include "net/icmp.h"

#include "libc.h"
#include "serial.h"
#include "process.h"
#include "timer.h"
#include "heap.h"

static uint16_t read_be16(const uint8_t *p);
static uint32_t read_be32(const uint8_t *p);
#define ICMP_TRACE(label, dest, len) \
    process_debug_log_stack_write(label, __builtin_return_address(0), (dest), (len))

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
    size_t frame_len = 14 + ip_len;
    if (frame_len < 60)
    {
        frame_len = 60;
    }
    uint8_t *buffer = (uint8_t *)malloc(frame_len);
    if (!buffer)
    {
        serial_printf("%s", "icmp: alloc frame failed\r\n");
        return false;
    }
    memset(buffer, 0, frame_len);

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

    g_pending.active = true;
    g_pending.received = false;
    g_pending.identifier = identifier;
    g_pending.sequence = sequence;
    g_pending.send_tick = timer_ticks();
    memset(&g_pending.reply, 0, sizeof(g_pending.reply));

    char ipbuf[32];
    char macbuf[13];
    net_format_ipv4(target_ip, ipbuf);
    net_format_mac(target_mac, macbuf);
    serial_printf("%s", "icmp: send echo id=0x");
    serial_printf("%c", "0123456789ABCDEF"[(identifier >> 12) & 0xF]);
    serial_printf("%c", "0123456789ABCDEF"[(identifier >> 8) & 0xF]);
    serial_printf("%c", "0123456789ABCDEF"[(identifier >> 4) & 0xF]);
    serial_printf("%c", "0123456789ABCDEF"[identifier & 0xF]);
    serial_printf("%s", " seq=0x");
    serial_printf("%c", "0123456789ABCDEF"[(sequence >> 12) & 0xF]);
    serial_printf("%c", "0123456789ABCDEF"[(sequence >> 8) & 0xF]);
    serial_printf("%c", "0123456789ABCDEF"[(sequence >> 4) & 0xF]);
    serial_printf("%c", "0123456789ABCDEF"[sequence & 0xF]);
    serial_printf("%s", " target=");
    serial_printf("%s", ipbuf);
    serial_printf("%s", " mac=");
    serial_printf("%s", macbuf);
    serial_printf("%s", " len=");
    char lenbuf[12];
    size_t len_idx = 0;
    size_t send_len_copy = frame_len;
    if (send_len_copy == 0)
    {
        lenbuf[len_idx++] = '0';
    }
    else
    {
        char tmp[12];
        size_t tmp_idx = 0;
        while (send_len_copy > 0 && tmp_idx < sizeof(tmp))
        {
            tmp[tmp_idx++] = (char)('0' + (send_len_copy % 10));
            send_len_copy /= 10;
        }
        while (tmp_idx > 0)
        {
            lenbuf[len_idx++] = tmp[--tmp_idx];
        }
    }
    lenbuf[len_idx] = '\0';
    serial_printf("%s", lenbuf);
    serial_printf("%s", "\r\n");

    const size_t dump_len = frame_len < 64 ? frame_len : 64;
    {
        /* Render the dump in one line to avoid serial spam. */
        char line[256];
        size_t pos = 0;
        const char *prefix = "icmp: frame data=";
        size_t prefix_len = strlen(prefix);
        if (prefix_len < sizeof(line))
        {
            memcpy(line + pos, prefix, prefix_len);
            pos += prefix_len;
        }
        for (size_t i = 0; i < dump_len && pos + 3 < sizeof(line); ++i)
        {
            uint8_t byte = buffer[i];
            line[pos++] = ' ';
            const char hex[] = "0123456789ABCDEF";
            line[pos++] = hex[(byte >> 4) & 0xF];
            line[pos++] = hex[byte & 0xF];
        }
        line[pos] = '\0';
        serial_printf("%s", line);
    }

    bool ok = net_if_send_copy(iface, buffer, frame_len);
    if (!ok)
    {
        g_pending.active = false;
        serial_printf("%s", "icmp: send failed\r\n");
        free(buffer);
        return false;
    }

    free(buffer);
    serial_printf("%s", "icmp: send queued\r\n");
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

static uint16_t ones_sum(const uint8_t *p, size_t n) {
    uint32_t acc = 0;
    while (n > 1) { acc += (uint16_t)((p[0] << 8) | p[1]); p += 2; n -= 2; }
    if (n) acc += (uint16_t)(p[0] << 8);
    while (acc >> 16) acc = (acc & 0xFFFFu) + (acc >> 16);
    return (uint16_t)acc;
}

static bool icmp_checksum_ok(const uint8_t *icmp, size_t len) {
    if (len < 8) return false;
    return ones_sum(icmp, len) == 0xFFFFU;
}

void net_icmp_handle_frame(net_interface_t *iface, const uint8_t *frame, size_t length)
{
    if (!iface || !frame || length < 14 + 20) return;

    const uint8_t *eth = frame;
    uint16_t eth_type = (uint16_t)((eth[12] << 8) | eth[13]);
    if (eth_type != 0x0800) return; // IPv4 only

    const uint8_t *ip = frame + 14;
    uint8_t ver = ip[0] >> 4, ihl = ip[0] & 0x0F;
    size_t ip_hlen = (size_t)ihl * 4;
    if (ver != 4 || ihl < 5 || 14 + ip_hlen > length) return;

    if (ip[9] != 1) return; // not ICMP

    uint16_t ip_total = read_be16(ip + 2);
    // What the IP layer says is present after the Ethernet header:
    size_t ip_bytes_in_frame = (length >= 14) ? (length - 14) : 0;

    // Clamp the IP view to what we actually have (tolerate padding/driver quirks)
    size_t ip_effective = ip_total;
    if (ip_effective > ip_bytes_in_frame) ip_effective = ip_bytes_in_frame;
    if (ip_effective < ip_hlen + 8) return; // need at least ICMP header

    const uint8_t *icmp = ip + ip_hlen;
    size_t icmp_len = ip_effective - ip_hlen;

    // Gate on checksum so only valid ICMP proceeds
    if (!icmp_checksum_ok(icmp, icmp_len)) return;

    uint8_t type = icmp[0], code = icmp[1];

    // --- Echo Reply (type 0) -> wake the waiter ---
    if (type == 0 && code == 0 && icmp_len >= 8) {
        uint16_t identifier = read_be16(icmp + 4);
        uint16_t sequence   = read_be16(icmp + 6);

        if (g_pending.active &&
            g_pending.identifier == identifier &&
            g_pending.sequence   == sequence)
        {
            g_pending.received    = true;
            g_pending.reply.bytes = (uint32_t)icmp_len;   // you were already returning header+payload
            g_pending.reply.from_ip = read_be32(ip + 12); // source of reply
            g_pending.reply.rtt_ticks = timer_ticks() - g_pending.send_tick;

            char ipbuf[32];
            net_format_ipv4(g_pending.reply.from_ip, ipbuf);
            char nbuf[12]; size_t n=0, v=g_pending.reply.bytes;
            if (!v) nbuf[n++]='0'; else { char t[12]; size_t ti=0; while (v && ti<sizeof t){t[ti++]=(char)('0'+(v%10)); v/=10;} while(ti) nbuf[n++]=t[--ti]; }
            nbuf[n]='\0';
            serial_printf("icmp: reply from %s bytes=%s\r\n", ipbuf, nbuf);
        }
        return;
    }

    // --- Echo Request (type 8) -> optional: reply back (your existing logic) ---
    if (type == 8 && code == 0 && icmp_len >= 8) {
        uint32_t dest_ip = read_be32(ip + 16);
        if (iface->ipv4_addr == 0 || dest_ip != iface->ipv4_addr) return;

        size_t out_len = 14 + ip_effective;
        if (out_len < 60) out_len = 60;
        uint8_t *reply = (uint8_t *)malloc(out_len);
        if (!reply)
        {
            serial_printf("%s", "icmp: reply alloc failed\r\n");
            return;
        }
        memset(reply, 0, out_len);
        memcpy(reply, frame, 14 + ip_effective);
        uint8_t *rep_eth  = reply;
        uint8_t *rep_ip   = reply + 14;
        uint8_t *rep_icmp = rep_ip + ip_hlen;

        // swap MACs
        memcpy(rep_eth, eth + 6, 6);
        memcpy(rep_eth + 6, iface->mac, 6);

        // swap IPs, reset TTL & checksum
        write_be32(rep_ip + 12, dest_ip);
        write_be32(rep_ip + 16, read_be32(ip + 12));
        rep_ip[8] = 64;
        write_be16(rep_ip + 10, 0);
        write_be16(rep_ip + 10, checksum16(rep_ip, ip_hlen));

        // ICMP: request -> reply
        rep_icmp[0] = 0; // Echo Reply
        rep_icmp[1] = 0;
        write_be16(rep_icmp + 2, 0);
        write_be16(rep_icmp + 2, checksum16(rep_icmp, icmp_len));

        net_if_send_copy(iface, reply, out_len);
        free(reply);
        return;
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
    if (p)
    {
        ICMP_TRACE("icmp_write_be16", p, sizeof(uint16_t));
    }
    p[0] = (uint8_t)((value >> 8) & 0xFF);
    p[1] = (uint8_t)(value & 0xFF);
}

static void write_be32(uint8_t *p, uint32_t value)
{
    if (p)
    {
        ICMP_TRACE("icmp_write_be32", p, sizeof(uint32_t));
    }
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
