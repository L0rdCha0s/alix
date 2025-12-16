#include "net/ntp.h"

#include "libc.h"
#include "serial.h"
#include "timekeeping.h"

#define NTP_PORT 123
#define NTP_MIN_PACKET 48
#define NTP_EPOCH_OFFSET_SECONDS 2208988800ULL

typedef struct
{
    bool waiting;
    uint16_t local_port;
    uint32_t server_ip;
    uint32_t originate_seconds;
    uint32_t originate_fraction;
} ntp_pending_t;

static ntp_pending_t g_pending;
static net_ntp_result_t g_result;
static bool g_have_result = false;

static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |
           (uint32_t)p[3];
}

static int64_t ntp_to_unix_us(uint32_t seconds, uint32_t fraction)
{
    int64_t sec = (int64_t)seconds - (int64_t)NTP_EPOCH_OFFSET_SECONDS;
    uint64_t frac_us = ((uint64_t)fraction * 1000000ULL) >> 32;
    return sec * 1000000LL + (int64_t)frac_us;
}

void net_ntp_init(void)
{
    memset(&g_pending, 0, sizeof(g_pending));
    memset(&g_result, 0, sizeof(g_result));
    g_have_result = false;
}

void net_ntp_set_pending(uint32_t originate_seconds,
                         uint32_t originate_fraction,
                         uint16_t local_port,
                         uint32_t server_ip)
{
    g_pending.waiting = true;
    g_pending.local_port = local_port;
    g_pending.server_ip = server_ip;
    g_pending.originate_seconds = originate_seconds;
    g_pending.originate_fraction = originate_fraction;
    g_have_result = false;
}

void net_ntp_clear_pending(void)
{
    memset(&g_pending, 0, sizeof(g_pending));
    g_have_result = false;
}

bool net_ntp_get_result(net_ntp_result_t *out_result)
{
    if (!g_have_result || !out_result)
    {
        return false;
    }
    *out_result = g_result;
    g_have_result = false;
    return true;
}

void net_ntp_handle_frame(struct net_interface *iface, const uint8_t *frame, size_t length)
{
    (void)iface;
    if (!g_pending.waiting || !frame || length < 14 + 20 + 8 + NTP_MIN_PACKET)
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
    size_t ip_hlen = (size_t)ihl * 4;
    if (length < 14 + ip_hlen + 8 + NTP_MIN_PACKET)
    {
        return;
    }
    if (ip[9] != 17)
    {
        return;
    }

    uint16_t total_len = read_be16(ip + 2);
    if (total_len < ip_hlen + 8 + NTP_MIN_PACKET)
    {
        return;
    }

    const uint8_t *udp = ip + ip_hlen;
    uint16_t src_port = read_be16(udp + 0);
    uint16_t dst_port = read_be16(udp + 2);
    uint16_t udp_len = read_be16(udp + 4);
    if (src_port != NTP_PORT || dst_port != g_pending.local_port)
    {
        return;
    }
    if (udp_len < 8 + NTP_MIN_PACKET || (size_t)udp_len > length - 14 - ip_hlen)
    {
        return;
    }

    const uint8_t *ntp = udp + 8;
    uint32_t originate_sec = read_be32(ntp + 24);
    uint32_t originate_frac = read_be32(ntp + 28);
    if (originate_sec != g_pending.originate_seconds ||
        originate_frac != g_pending.originate_fraction)
    {
        return;
    }

    uint32_t recv_sec = read_be32(ntp + 32);
    uint32_t recv_frac = read_be32(ntp + 36);
    uint32_t transmit_sec = read_be32(ntp + 40);
    uint32_t transmit_frac = read_be32(ntp + 44);

    int64_t t1 = ntp_to_unix_us(g_pending.originate_seconds, g_pending.originate_fraction);
    int64_t t2 = ntp_to_unix_us(recv_sec, recv_frac);
    int64_t t3 = ntp_to_unix_us(transmit_sec, transmit_frac);
    int64_t t4 = (int64_t)timekeeping_now_millis() * 1000LL;

    int64_t delay = (t4 - t1) - (t3 - t2);
    int64_t offset = ((t2 - t1) + (t3 - t4)) / 2;

    g_result.offset_microseconds = offset;
    g_result.delay_microseconds = delay;
    g_result.server_time_microseconds = t3;
    g_result.destination_time_microseconds = t4;
    g_result.server_ip = read_be32(ip + 12);
    g_have_result = true;
    g_pending.waiting = false;
}
