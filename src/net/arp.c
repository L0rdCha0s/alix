#include "net/arp.h"

#include <stddef.h>

#include "libc.h"
#include "serial.h"
#include "net/dhcp.h"
#include "net/net_debug.h"
#include "timer.h"
#include "heap.h"
#include "process.h"

#define ARP_TRACE(label, dest, len) \
    process_debug_log_stack_write(label, __builtin_return_address(0), (dest), (len))

#define ARP_CACHE_SIZE 8

// replace your struct with this (adds last_tick)
typedef struct
{
    bool valid;
    uint32_t ip;
    uint8_t mac[6];
    uint64_t last_tick;
} arp_entry_t;

static arp_entry_t g_cache[ARP_CACHE_SIZE];

static uint16_t read_be16(const uint8_t *p);
static uint32_t read_be32(const uint8_t *p);
static void write_be16(uint8_t *p, uint16_t value);
static void write_be32(uint8_t *p, uint32_t value);
static void net_arp_store(uint32_t ip, const uint8_t mac[6]);
static void net_arp_send_reply(net_interface_t *iface, const uint8_t *target_mac, uint32_t target_ip, uint32_t source_ip);
static bool net_arp_send_generic(net_interface_t *iface, const uint8_t *dest_mac,
                                 const uint8_t *target_mac, uint32_t target_ip,
                                 uint32_t source_ip, uint16_t opcode);
static void arp_log_reason(const char *reason);


static void arp_log_reason(const char *reason)
{
    if (!reason)
    {
        return;
    }
    serial_printf("%s", "arp: ");
    serial_printf("%s", reason);
    serial_printf("%s", "\r\n");
}


static void arp_log_entry(const char *prefix, uint32_t ip, const uint8_t mac[6])
{
    if (!prefix)
    {
        return;
    }
    char ipbuf[32];
    char macbuf[13];
    net_format_ipv4(ip, ipbuf);
    if (mac)
    {
        net_format_mac(mac, macbuf);
    }
    else
    {
        macbuf[0] = '\0';
    }
    serial_printf("arp: %s ip=%s%s%s\r\n",
                  prefix,
                  ipbuf,
                  mac ? " mac=" : "",
                  mac ? macbuf : "");
}

void net_arp_flush(void)
{
    for (size_t i = 0; i < ARP_CACHE_SIZE; ++i)
    {
        g_cache[i].valid = false;
        g_cache[i].ip = 0;
        g_cache[i].last_tick = 0;
        memset(g_cache[i].mac, 0, sizeof(g_cache[i].mac));
    }
}

bool net_arp_lookup_fresh(uint32_t ip, uint8_t mac_out[6], uint64_t max_age_ticks)
{
    if (!mac_out || ip == 0) return false;

    uint64_t now = timer_ticks();
    for (size_t i = 0; i < ARP_CACHE_SIZE; ++i)
    {
        if (g_cache[i].valid && g_cache[i].ip == ip)
        {
            if (max_age_ticks && (now - g_cache[i].last_tick) > max_age_ticks)
            {
                // stale
                return false;
            }
            net_debug_memcpy("arp_lookup_hit", mac_out, g_cache[i].mac, 6);
            arp_log_entry("cache hit", ip, g_cache[i].mac);
            return true;
        }
    }
    return false;
}


bool net_arp_lookup(uint32_t ip, uint8_t mac_out[6])
{
    if (!mac_out || ip == 0)
    {
        return false;
    }
    for (size_t i = 0; i < ARP_CACHE_SIZE; ++i)
    {
        if (g_cache[i].valid && g_cache[i].ip == ip)
        {
            net_debug_memcpy("arp_lookup_stale", mac_out, g_cache[i].mac, 6);
            arp_log_entry("cache hit", ip, g_cache[i].mac);
            return true;
        }
    }
    // arp_log_entry("cache miss", ip, NULL);
    return false;
}

bool net_arp_send_request(net_interface_t *iface, uint32_t target_ip)
{
    if (!iface || !iface->present)
    {
        serial_printf("%s", "arp: send_request invalid iface\r\n");
        return false;
    }

    uint8_t broadcast[6];
    memset(broadcast, 0xFF, sizeof(broadcast));
    uint8_t zero_mac[6] = {0};
    uint32_t source_ip = iface->ipv4_addr;
    bool ok = net_arp_send_generic(iface, broadcast, zero_mac, target_ip, source_ip, 0x0001);
    if (ok)
    {
        char ipbuf[32];
        net_format_ipv4(target_ip, ipbuf);
        serial_printf("arp: request sent for %s\r\n", ipbuf);
    }
    else
    {
        serial_printf("%s", "arp: request send failed\r\n");
    }
    return ok;
}

void net_arp_handle_frame(net_interface_t *iface, const uint8_t *frame, size_t length)
{
    if (!iface || !frame || length < 42)
    {
        arp_log_reason("handle_frame early exit: bad iface/frame/length");
        return;
    }

    const uint8_t *eth = frame;
    uint16_t eth_type = (uint16_t)((eth[12] << 8) | eth[13]);
    if (eth_type != 0x0806)
    {
        return;
    }

    const uint8_t *arp = frame + 14;
    uint16_t hw_type = read_be16(arp + 0);
    uint16_t proto_type = read_be16(arp + 2);
    uint8_t hw_len = arp[4];
    uint8_t proto_len = arp[5];
    uint16_t opcode = read_be16(arp + 6);

    if (hw_type != 0x0001 || proto_type != 0x0800 || hw_len != 6 || proto_len != 4)
    {
        arp_log_reason("handle_frame early exit: unexpected hw/proto sizes");
        return;
    }

    const uint8_t *sender_mac = arp + 8;
    uint32_t sender_ip = read_be32(arp + 14);
    uint32_t target_ip = read_be32(arp + 24);

    if (sender_ip != 0)
    {
        net_arp_store(sender_ip, sender_mac);
    }

    if (opcode == 0x0002)
    {
        arp_log_reason("handle_frame early exit: opcode reply, no response needed");
        return;
    }

    if (opcode == 0x0001)
    {
        bool respond = false;
        uint32_t reply_ip = iface->ipv4_addr;
        if (iface->ipv4_addr != 0 && target_ip == iface->ipv4_addr)
        {
            respond = true;
        }
        else if (net_dhcp_claims_ip(iface, target_ip))
        {
            respond = true;
            reply_ip = target_ip;
        }

        if (respond)
        {
            serial_printf("%s", "arp: replying for ip ");
            char ipbuf[32];
            net_format_ipv4(reply_ip, ipbuf);
            serial_printf("%s", ipbuf);
            serial_printf("%s", "\r\n");
            net_arp_send_reply(iface, sender_mac, sender_ip, reply_ip);
        }
    }
}

static void net_arp_store(uint32_t ip, const uint8_t mac[6])
{
    if (!mac)
    {
        arp_log_reason("store: NULL mac");
        return;
    }

    char ipbuf[32];
    net_format_ipv4(ip, ipbuf);
    serial_printf("arp: store request ip=%s\r\n", ipbuf);

    if (ip == 0)
    {
        arp_log_reason("store: ip zero");
        return;
    }

    uint64_t now = timer_ticks();

    for (size_t i = 0; i < ARP_CACHE_SIZE; ++i)
    {
        if (g_cache[i].valid && g_cache[i].ip == ip)
        {
            net_debug_memcpy("arp_store_update", g_cache[i].mac, mac, 6);
            g_cache[i].last_tick = now;
            arp_log_entry("updated entry", ip, mac);
            serial_printf("arp: store updated index=%zu\r\n", i);
            return;
        }
    }

    for (size_t i = 0; i < ARP_CACHE_SIZE; ++i)
    {
        if (!g_cache[i].valid)
        {
            g_cache[i].valid = true;
            g_cache[i].ip = ip;
            net_debug_memcpy("arp_store_reuse", g_cache[i].mac, mac, 6);
            g_cache[i].last_tick = now;
            arp_log_entry("added entry", ip, mac);
            serial_printf("arp: store new index=%zu\r\n", i);
            return;
        }
    }

    /* Simple replacement: overwrite entry 0 if cache is full. */
    g_cache[0].valid = true;
    g_cache[0].ip = ip;
    net_debug_memcpy("arp_store_evicted", g_cache[0].mac, mac, 6);
    g_cache[0].last_tick = now;
    arp_log_entry("replaced entry", ip, mac);
    serial_printf("%s", "arp: store replaced index=0\r\n");
}


void net_arp_announce(net_interface_t *iface, uint32_t ip)
{
    if (!iface || ip == 0)
    {
        arp_log_reason("announce early exit: bad iface or ip zero");
        return;
    }

    /* RFC 5227: Gratuitous ARP is commonly a broadcast **request**
    with sender and target IP both set to 'ip' and target MAC zero. */
    uint8_t broadcast[6]; memset(broadcast, 0xFF, sizeof(broadcast));
    uint8_t zero_mac[6] = {0};
    net_arp_send_generic(iface, broadcast, zero_mac, ip, ip, 0x0001);
}

static void net_arp_send_reply(net_interface_t *iface, const uint8_t *target_mac, uint32_t target_ip, uint32_t source_ip)
{
    if (!iface || !target_mac)
    {
        return;
    }

    net_arp_send_generic(iface, target_mac, target_mac, target_ip, source_ip, 0x0002);
}

static bool net_arp_send_generic(net_interface_t *iface, const uint8_t *dest_mac,
                                 const uint8_t *target_mac, uint32_t target_ip,
                                 uint32_t source_ip, uint16_t opcode)
{
    if (!iface || !dest_mac)
    {
        return false;
    }

    const size_t frame_len = 60;
    uint8_t *buffer = (uint8_t *)malloc(frame_len);
    if (!buffer)
    {
        serial_printf("%s", "arp: failed to allocate tx buffer\r\n");
        return false;
    }
    memset(buffer, 0, frame_len);

    uint8_t *eth = buffer;
    uint8_t *arp = buffer + 14;

    net_debug_memcpy("arp_eth_dst", eth, dest_mac, 6);
    net_debug_memcpy("arp_eth_src", eth + 6, iface->mac, 6);
    eth[12] = 0x08;
    eth[13] = 0x06;

    write_be16(arp + 0, 0x0001);
    write_be16(arp + 2, 0x0800);
    arp[4] = 6;
    arp[5] = 4;
    write_be16(arp + 6, opcode);
    net_debug_memcpy("arp_sender_mac", arp + 8, iface->mac, 6);
    write_be32(arp + 14, source_ip);
    net_debug_memcpy("arp_target_mac", arp + 18, target_mac, 6);
    write_be32(arp + 24, target_ip);

    bool ok = net_if_send_copy(iface, buffer, frame_len);
    free(buffer);
    return ok;
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
        ARP_TRACE("arp_write_be16", p, sizeof(uint16_t));
    }
    p[0] = (uint8_t)((value >> 8) & 0xFF);
    p[1] = (uint8_t)(value & 0xFF);
}

static void write_be32(uint8_t *p, uint32_t value)
{
    if (p)
    {
        ARP_TRACE("arp_write_be32", p, sizeof(uint32_t));
    }
    p[0] = (uint8_t)((value >> 24) & 0xFF);
    p[1] = (uint8_t)((value >> 16) & 0xFF);
    p[2] = (uint8_t)((value >> 8) & 0xFF);
    p[3] = (uint8_t)(value & 0xFF);
}
