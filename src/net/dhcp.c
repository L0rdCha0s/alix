#include "net/dhcp.h"

#include <stddef.h>

#include "serial.h"
#include "libc.h"
#include "net/arp.h"
#include "net/route.h"
#include "net/dns.h"
#include "net/net_debug.h"
#include "heap.h"
#include "process.h"

#define DHCP_TRACE(label, dest, len) \
    process_debug_log_stack_write(label, __builtin_return_address(0), (dest), (len))

#define DHCP_OP_REQUEST 1
#define DHCP_OP_REPLY   2

#define DHCP_HTYPE_ETHERNET 1
#define DHCP_HLEN_ETHERNET  6

#define DHCP_MAGIC_COOKIE 0x63825363U

#define DHCP_OPTION_PAD         0
#define DHCP_OPTION_SUBNET_MASK 1
#define DHCP_OPTION_ROUTER      3
#define DHCP_OPTION_REQ_IP      50
#define DHCP_OPTION_MESSAGE     53
#define DHCP_OPTION_SERVER_ID   54
#define DHCP_OPTION_PARAM_LIST  55
#define DHCP_OPTION_DNS         6
#define DHCP_OPTION_END         255

#define DHCP_MSG_DISCOVER 1
#define DHCP_MSG_OFFER    2
#define DHCP_MSG_REQUEST  3
#define DHCP_MSG_ACK      5

#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67

typedef enum
{
    DHCP_IDLE,
    DHCP_WAIT_OFFER,
    DHCP_WAIT_ACK
} dhcp_state_t;

static dhcp_state_t g_state = DHCP_IDLE;
static net_interface_t *g_active_iface = NULL;
static uint32_t g_xid = 0x12345678U;
static uint32_t g_offer_addr = 0;
static uint32_t g_server_id = 0;
static uint32_t g_prev_xid = 0;
static uint8_t g_server_mac[6];
static bool g_have_server_mac = false;

static bool dhcp_send_discover(void);
static bool dhcp_send_request(void);
static bool dhcp_send_message(uint8_t msg_type, uint32_t requested_ip, uint32_t server_id);
static uint16_t ip_checksum(const uint8_t *data, size_t len);
static uint16_t udp_checksum(const uint8_t *src_ip, const uint8_t *dst_ip,
                             const uint8_t *udp, size_t udp_len);
static uint16_t read_be16(const uint8_t *p);
static uint32_t read_be32(const uint8_t *p);
static void write_be16(uint8_t *p, uint16_t value);
static void write_be32(uint8_t *p, uint32_t value);

bool net_dhcp_acquire(net_interface_t *iface)
{
    if (!iface)
    {
        serial_printf("%s", "dhcp: no interface provided\r\n");
        return false;
    }
    serial_printf("%s", "dhcp: starting discovery on interface ");
    serial_printf("%s", iface->name);
    serial_printf("%s", "\r\n");

    g_active_iface = iface;
    g_prev_xid = g_xid;
    g_offer_addr = 0;
    g_server_id = 0;
    g_have_server_mac = false;
    memset(g_server_mac, 0, sizeof(g_server_mac));
    g_xid += 0x01020304U; /* change transaction id */
    net_if_set_ipv4(iface, 0, 0, 0);
    g_state = DHCP_WAIT_OFFER;
    if (!dhcp_send_discover())
    {
        serial_printf("%s", "dhcp: failed to send discover\r\n");
        g_state = DHCP_IDLE;
        return false;
    }
    serial_printf("%s", "dhcp: discover sent\r\n");
    return true;
}

bool net_dhcp_in_progress(void)
{
    return g_state != DHCP_IDLE;
}

bool net_dhcp_claims_ip(net_interface_t *iface, uint32_t ip)
{
    return iface && iface == g_active_iface && g_state == DHCP_WAIT_ACK && g_offer_addr == ip;
}

static bool mac_is_sane(const uint8_t mac[6])
{
    if (!mac) return false;
    // Reject multicast/broadcast, all-zeros/all-FF, or our own MAC.
    if ((mac[0] & 1) != 0) return false;
    bool all0 = true, allf = true;
    for (int i = 0; i < 6; ++i) {
        if (mac[i] != 0x00) all0 = false;
        if (mac[i] != 0xFF) allf = false;
    }
    if (all0 || allf) return false;
    if (g_active_iface && memcmp(mac, g_active_iface->mac, 6) == 0) return false;
    return true;
}

void net_dhcp_handle_frame(net_interface_t *iface, const uint8_t *frame, size_t length)
{
    if (!iface || iface != g_active_iface || length < 42)
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
    uint8_t ihl = (uint8_t)(ip[0] & 0x0F);
    uint8_t version = (uint8_t)(ip[0] >> 4);
    if (version != 4 || ihl < 5)
    {
        return;
    }
    size_t ip_header_len = (size_t)ihl * 4;
    if (14 + ip_header_len + 8 > length)
    {
        return;
    }
    if (ip[9] != 17) /* UDP */
    {
        return;
    }

    const uint8_t *udp = ip + ip_header_len;
    uint16_t src_port = read_be16(udp);
    uint16_t dst_port = read_be16(udp + 2);
    uint16_t udp_len = read_be16(udp + 4);
    if (dst_port != DHCP_CLIENT_PORT || src_port != DHCP_SERVER_PORT)
    {
        return;
    }
    if (udp_len < 8 + 240)
    {
        return;
    }

    const uint8_t *dhcp = udp + 8;
    if (read_be32(dhcp + 236) != DHCP_MAGIC_COOKIE)
    {
        return;
    }
    uint32_t xid = read_be32(dhcp + 4);
    bool xid_current = (xid == g_xid);
    bool xid_previous = (!xid_current && g_prev_xid != 0 && xid == g_prev_xid);
    if (!xid_current && !xid_previous)
    {
        serial_printf("%s", "dhcp: transaction id mismatch\r\n");
        return;
    }
    if (xid_previous)
    {
        /* Accept late response for previous transaction. */
        g_xid = xid;
        g_state = DHCP_WAIT_ACK;
    }

    uint8_t message_type = 0;
    uint32_t subnet_mask = 0;
    uint32_t router = 0;
    uint32_t server_id = 0;
    uint32_t dns_servers[NET_DNS_MAX_SERVERS];
    size_t dns_count = 0;

    const uint8_t *options = dhcp + 240;
    const uint8_t *udp_end = udp + udp_len;
    const uint8_t *opt = options;
    while (opt + 1 < udp_end)
    {
        uint8_t code = *opt++;
        if (code == DHCP_OPTION_END)
        {
            break;
        }
        if (code == DHCP_OPTION_PAD)
        {
            continue;
        }
        if (opt >= udp_end)
        {
            break;
        }
        uint8_t opt_len = *opt++;
        if (opt + opt_len > udp_end)
        {
            break;
        }
        switch (code)
        {
            case DHCP_OPTION_MESSAGE:
                if (opt_len >= 1)
                {
                    message_type = opt[0];
                }
                break;
            case DHCP_OPTION_SERVER_ID:
                if (opt_len >= 4)
                {
                    server_id = read_be32(opt);
                }
                break;
            case DHCP_OPTION_SUBNET_MASK:
                if (opt_len >= 4)
                {
                    subnet_mask = read_be32(opt);
                }
                break;
            case DHCP_OPTION_ROUTER:
                if (opt_len >= 4)
                {
                    router = read_be32(opt);
                }
                break;
            case DHCP_OPTION_DNS:
                for (size_t idx = 0; idx + 3 < opt_len && dns_count < NET_DNS_MAX_SERVERS; idx += 4)
                {
                    uint32_t dns_ip = read_be32(opt + idx);
                    if (dns_ip != 0)
                    {
                        dns_servers[dns_count++] = dns_ip;
                    }
                }
                break;
            default:
                break;
        }
        opt += opt_len;
    }

    uint32_t yiaddr = read_be32(dhcp + 16);

    char ipbuf[32];
    net_format_ipv4(yiaddr, ipbuf);
    serial_printf("dhcp: received response type=%c yiaddr=%s\r\n",
                  (char)('0' + message_type),
                  ipbuf);

    if (server_id == 0)
    {
        server_id = read_be32(ip + 12);
    }

    if (message_type == DHCP_MSG_OFFER && g_state == DHCP_WAIT_OFFER)
    {
        g_offer_addr = yiaddr;
        g_server_id = server_id;
        net_debug_memcpy("dhcp_offer_mac", g_server_mac, frame + 6, 6); /* source MAC of offer */
        g_have_server_mac = mac_is_sane(g_server_mac);
        /* Try to learn the server's L2 via ARP as well (more reliable). */
        if (g_server_id != 0) {
            net_arp_send_request(iface, g_server_id);
        }
        g_state = DHCP_WAIT_ACK;
        if (dhcp_send_request())
        {
            serial_printf("%s", "dhcp: sent request\r\n");
            net_arp_announce(iface, g_offer_addr);
        }
        else
        {
            serial_printf("%s", "dhcp: failed to send request\r\n");
            g_state = DHCP_IDLE;
        }
        return;
    }

    if (message_type == DHCP_MSG_ACK && g_state == DHCP_WAIT_ACK)
    {
        if (!subnet_mask)
        {
            subnet_mask = 0xFFFFFF00U;
        }
        bool addr_changed = (iface->ipv4_addr != yiaddr);
        if (addr_changed)
        {
            net_arp_flush();
        }
        net_if_set_ipv4(iface, yiaddr, subnet_mask, router);
        if (router != 0)
        {
            net_route_set_default(iface, router);
        }
        net_arp_announce(iface, yiaddr);
        if (router != 0)
        {
            net_arp_send_request(iface, router);
        }
        if (dns_count > 0)
        {
            net_dns_set_servers(dns_servers, dns_count);
        }
        serial_printf("%s", "dhcp: lease acquired. address=");
        net_format_ipv4(yiaddr, ipbuf);
        serial_printf("%s", ipbuf);
        serial_printf("%s", " netmask=");
        net_format_ipv4(subnet_mask, ipbuf);
        serial_printf("%s", ipbuf);
        serial_printf("%s", " gateway=");
        net_format_ipv4(router, ipbuf);
        serial_printf("%s", ipbuf);
        serial_printf("%s", "\r\n");
        g_state = DHCP_IDLE;
        g_active_iface = NULL;
        g_prev_xid = 0;
        g_offer_addr = 0;
        g_have_server_mac = false;
    }
}

static bool dhcp_send_discover(void)
{
    return dhcp_send_message(DHCP_MSG_DISCOVER, 0, 0);
}

static bool dhcp_send_request(void)
{
    bool success = dhcp_send_message(DHCP_MSG_REQUEST, g_offer_addr, g_server_id);
    if (!success)
    {
        g_state = DHCP_IDLE;
        g_active_iface = NULL;
    }
    return success;
}

static bool dhcp_send_message(uint8_t msg_type, uint32_t requested_ip, uint32_t server_id)
{
    if (!g_active_iface)
    {
        return false;
    }

    uint8_t *buffer = (uint8_t *)malloc(548);
    if (!buffer)
    {
        serial_printf("%s", "dhcp: failed to allocate tx buffer\r\n");
        return false;
    }
    memset(buffer, 0, 548);

    uint8_t *eth = buffer;
    uint8_t *ip = buffer + 14;
    uint8_t *udp = ip + 20;
    uint8_t *dhcp = udp + 8;

    bool broadcast = true;
    uint32_t dest_ip = 0xFFFFFFFFU;
    const uint8_t *dest_mac = NULL;
    uint8_t resolved_mac[6];
    if (msg_type == DHCP_MSG_REQUEST && server_id != 0)
    {
        /* Prefer an ARP-resolved L2, then fall back to the DHCP source MAC
           if (and only if) it looks sane. Otherwise, broadcast. */
        if (net_arp_lookup(server_id, resolved_mac) && mac_is_sane(resolved_mac)) {
            broadcast = false;
            dest_ip = server_id;
            dest_mac = resolved_mac;
        } else if (g_have_server_mac && mac_is_sane(g_server_mac)) {
            broadcast = false;
            dest_ip = server_id;
            dest_mac = g_server_mac;
        }
    }

    /* Ethernet header */
    if (dest_mac)
    {
        net_debug_memcpy("dhcp_eth_dst", eth, dest_mac, 6);
    }
    else
    {
        memset(eth, 0xFF, 6);
    }
    net_debug_memcpy("dhcp_eth_src", eth + 6, g_active_iface->mac, 6);
    eth[12] = 0x08;
    eth[13] = 0x00;

    /* IP header */
    memset(ip, 0, 20);
    ip[0] = 0x45;
    ip[1] = 0x00;

    /* DHCP message build */
    memset(dhcp, 0, 236);
    dhcp[0] = DHCP_OP_REQUEST;
    dhcp[1] = DHCP_HTYPE_ETHERNET;
    dhcp[2] = DHCP_HLEN_ETHERNET;
    dhcp[3] = 0;
    write_be32(dhcp + 4, g_xid);
    write_be16(dhcp + 8, 0);
    write_be16(dhcp + 10, broadcast ? 0x8000 : 0x0000); /* BOOTP flags */
    write_be32(dhcp + 12, 0);
    write_be32(dhcp + 16, 0);
    write_be32(dhcp + 20, 0);
    write_be32(dhcp + 24, 0);
    net_debug_memcpy("dhcp_hwaddr", dhcp + 28, g_active_iface->mac, 6);
    write_be32(dhcp + 236, DHCP_MAGIC_COOKIE);

    uint8_t *opt = dhcp + 240;
    *opt++ = DHCP_OPTION_MESSAGE;
    *opt++ = 1;
    *opt++ = msg_type;

    if (msg_type == DHCP_MSG_REQUEST)
    {
        *opt++ = DHCP_OPTION_REQ_IP;
        *opt++ = 4;
        write_be32(opt, requested_ip);
        opt += 4;

        *opt++ = DHCP_OPTION_SERVER_ID;
        *opt++ = 4;
        write_be32(opt, server_id);
        opt += 4;
    }

    *opt++ = DHCP_OPTION_PARAM_LIST;
    *opt++ = 3;
    *opt++ = DHCP_OPTION_SUBNET_MASK;
    *opt++ = DHCP_OPTION_ROUTER;
    *opt++ = 6; /* DNS */

    *opt++ = DHCP_OPTION_END;

    size_t dhcp_len = (size_t)(opt - dhcp);
    if (dhcp_len < 240)
    {
        dhcp_len = 240;
    }

    uint16_t udp_len = (uint16_t)(8 + dhcp_len);
    uint16_t ip_len = (uint16_t)(20 + udp_len);

    write_be16(ip + 2, ip_len);
    write_be16(ip + 4, 0);
    write_be16(ip + 6, 0);
    ip[8] = 64;
    ip[9] = 17; /* UDP */
    write_be32(ip + 12, 0);
    write_be32(ip + 16, dest_ip);
    write_be16(ip + 10, 0); /* checksum zero before calculation */
    uint16_t checksum = ip_checksum(ip, 20);
    write_be16(ip + 10, checksum);

    write_be16(udp, DHCP_CLIENT_PORT);
    write_be16(udp + 2, DHCP_SERVER_PORT);
    write_be16(udp + 4, udp_len);
    write_be16(udp + 6, 0); /* zero before checksum calculation */

    /* Compute UDP checksum with IPv4 pseudo header (some backends drop zero). */
    uint16_t udp_csum = udp_checksum(ip + 12, ip + 16, udp, udp_len);
    if (udp_csum == 0)
    {
        /* Per RFC768, a checksum value of 0 means no checksum. However, some
           emulated DHCP servers are stricter; avoid 0 by writing 0xFFFF. */
        udp_csum = 0xFFFF;
    }
    write_be16(udp + 6, udp_csum);

    size_t frame_len = 14 + ip_len;
    if (frame_len < 60)
    {
        memset(buffer + frame_len, 0, 60 - frame_len);
        frame_len = 60;
    }

    serial_printf("dhcp: transmitting message type %c\r\n", (char)('0' + msg_type));

    bool ok = net_if_send_copy(g_active_iface, buffer, frame_len);
    if (!ok)
    {
        serial_printf("%s", "dhcp: failed to transmit frame\r\n");
    }

    free(buffer);
    if (!ok)
    {
        return false;
    }

    if (!broadcast && msg_type == DHCP_MSG_REQUEST && g_offer_addr != 0)
    {
        net_arp_announce(g_active_iface, g_offer_addr);
    }

    return true;
}

static uint16_t ip_checksum(const uint8_t *data, size_t len)
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

static uint16_t udp_checksum(const uint8_t *src_ip, const uint8_t *dst_ip,
                             const uint8_t *udp, size_t udp_len)
{
    /* Pseudo header: src(4) + dst(4) + zero(1) + proto(1) + len(2) */
    uint32_t sum = 0;

    /* Source IP */
    for (int i = 0; i < 4; i += 2)
    {
        sum += (uint32_t)((src_ip[i] << 8) | src_ip[i + 1]);
    }
    /* Destination IP */
    for (int i = 0; i < 4; i += 2)
    {
        sum += (uint32_t)((dst_ip[i] << 8) | dst_ip[i + 1]);
    }
    /* Protocol (UDP=17) and UDP length */
    sum += 17; /* protocol fits in low byte of 16-bit word with preceding zero */
    sum += (uint32_t)udp_len;

    /* UDP header + payload */
    for (size_t i = 0; i + 1 < udp_len; i += 2)
    {
        sum += (uint32_t)((udp[i] << 8) | udp[i + 1]);
    }
    if (udp_len & 1)
    {
        sum += (uint32_t)(udp[udp_len - 1] << 8);
    }

    while (sum >> 16)
    {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void write_be16(uint8_t *p, uint16_t value)
{
    if (p)
    {
        DHCP_TRACE("dhcp_write_be16", p, sizeof(uint16_t));
    }
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)(value & 0xFF);
}

static void write_be32(uint8_t *p, uint32_t value)
{
    if (p)
    {
        DHCP_TRACE("dhcp_write_be32", p, sizeof(uint32_t));
    }
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)((value >> 16) & 0xFF);
    p[2] = (uint8_t)((value >> 8) & 0xFF);
    p[3] = (uint8_t)(value & 0xFF);
}
