#include "net/arp.h"

#include "libc.h"

#define ARP_CACHE_SIZE 8

typedef struct
{
    bool valid;
    uint32_t ip;
    uint8_t mac[6];
} arp_entry_t;

static arp_entry_t g_cache[ARP_CACHE_SIZE];

static uint16_t read_be16(const uint8_t *p);
static uint32_t read_be32(const uint8_t *p);
static void write_be16(uint8_t *p, uint16_t value);
static void write_be32(uint8_t *p, uint32_t value);
static void net_arp_store(uint32_t ip, const uint8_t mac[6]);
static void net_arp_send_reply(net_interface_t *iface, const uint8_t *target_mac, uint32_t target_ip);

void net_arp_flush(void)
{
    for (size_t i = 0; i < ARP_CACHE_SIZE; ++i)
    {
        g_cache[i].valid = false;
        g_cache[i].ip = 0;
        memset(g_cache[i].mac, 0, sizeof(g_cache[i].mac));
    }
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
            memcpy(mac_out, g_cache[i].mac, 6);
            return true;
        }
    }
    return false;
}

bool net_arp_send_request(net_interface_t *iface, uint32_t target_ip)
{
    if (!iface || !iface->present)
    {
        return false;
    }

    uint8_t buffer[60];
    memset(buffer, 0, sizeof(buffer));

    uint8_t *eth = buffer;
    uint8_t *arp = buffer + 14;

    memset(eth, 0xFF, 6);
    memcpy(eth + 6, iface->mac, 6);
    eth[12] = 0x08;
    eth[13] = 0x06;

    write_be16(arp + 0, 0x0001); /* Ethernet */
    write_be16(arp + 2, 0x0800); /* IPv4 */
    arp[4] = 6;
    arp[5] = 4;
    write_be16(arp + 6, 0x0001); /* request */
    memcpy(arp + 8, iface->mac, 6);
    write_be32(arp + 14, iface->ipv4_addr);
    memset(arp + 18, 0x00, 6);
    write_be32(arp + 24, target_ip);

    return net_if_send(iface, buffer, sizeof(buffer));
}

void net_arp_handle_frame(net_interface_t *iface, const uint8_t *frame, size_t length)
{
    if (!iface || !frame || length < 42)
    {
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
        return;
    }

    if (opcode == 0x0001 && iface->ipv4_addr != 0 && target_ip == iface->ipv4_addr)
    {
        net_arp_send_reply(iface, sender_mac, sender_ip);
    }
}

static void net_arp_store(uint32_t ip, const uint8_t mac[6])
{
    if (ip == 0 || !mac)
    {
        return;
    }

    for (size_t i = 0; i < ARP_CACHE_SIZE; ++i)
    {
        if (g_cache[i].valid && g_cache[i].ip == ip)
        {
            memcpy(g_cache[i].mac, mac, 6);
            return;
        }
    }

    for (size_t i = 0; i < ARP_CACHE_SIZE; ++i)
    {
        if (!g_cache[i].valid)
        {
            g_cache[i].valid = true;
            g_cache[i].ip = ip;
            memcpy(g_cache[i].mac, mac, 6);
            return;
        }
    }

    /* Simple replacement: overwrite entry 0 if cache is full. */
    g_cache[0].valid = true;
    g_cache[0].ip = ip;
    memcpy(g_cache[0].mac, mac, 6);
}

static void net_arp_send_reply(net_interface_t *iface, const uint8_t *target_mac, uint32_t target_ip)
{
    if (!iface || !target_mac)
    {
        return;
    }

    uint8_t buffer[60];
    memset(buffer, 0, sizeof(buffer));

    uint8_t *eth = buffer;
    uint8_t *arp = buffer + 14;

    memcpy(eth, target_mac, 6);
    memcpy(eth + 6, iface->mac, 6);
    eth[12] = 0x08;
    eth[13] = 0x06;

    write_be16(arp + 0, 0x0001);
    write_be16(arp + 2, 0x0800);
    arp[4] = 6;
    arp[5] = 4;
    write_be16(arp + 6, 0x0002); /* reply */
    memcpy(arp + 8, iface->mac, 6);
    write_be32(arp + 14, iface->ipv4_addr);
    memcpy(arp + 18, target_mac, 6);
    write_be32(arp + 24, target_ip);

    net_if_send(iface, buffer, sizeof(buffer));
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
