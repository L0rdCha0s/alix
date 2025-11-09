#include "shell_commands.h"

#include "libc.h"
#include "net/arp.h"
#include "net/dns.h"
#include "net/interface.h"
#include "net/ntp.h"
#include "net/route.h"
#include "timekeeping.h"
#include "timer.h"
#include "vfs.h"

#define NTP_SERVER_PATH "/etc/ntp/server"
#define NTP_DEFAULT_SERVER "pool.ntp.org"
#define NTP_ETH_MIN_FRAME 60
#define NTP_PORT 123

static const char *ntp_skip_ws(const char *s);
static bool ntp_read_token(const char **cursor, char *out, size_t capacity);
static bool ntp_load_server(char *out, size_t capacity);
static bool ntp_write_default_server(void);
static bool ntp_resolve_mac(net_interface_t *iface, uint32_t next_hop_ip, uint8_t mac_out[6], uint64_t timeout_ticks);
static uint16_t ntp_checksum16(const uint8_t *data, size_t len);
static uint16_t ntp_udp_checksum(uint32_t src_ip, uint32_t dst_ip, const uint8_t *udp, size_t udp_len);
static void write_be16(uint8_t *p, uint16_t value);
static void write_be32(uint8_t *p, uint32_t value);
static void ntp_write_int(shell_output_t *out, int value);
static void ntp_copy_string(char *dst, size_t capacity, const char *src);

bool shell_cmd_ntpdate(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;
    const char *cursor = args ? args : "";
    char token1[64];
    char token2[128];
    bool have_iface = false;
    char iface_name[NET_IF_NAME_MAX];
    char server_name[128];

    bool has_token1 = ntp_read_token(&cursor, token1, sizeof(token1));
    bool has_token2 = ntp_read_token(&cursor, token2, sizeof(token2));
    cursor = ntp_skip_ws(cursor);
    if (*cursor != '\0')
    {
        return shell_output_error(out, "Usage: ntpdate [iface] [server]");
    }

    if (!has_token1)
    {
        if (!ntp_load_server(server_name, sizeof(server_name)))
        {
            return shell_output_error(out, "unable to load default server");
        }
    }
    else if (!has_token2)
    {
        ntp_copy_string(server_name, sizeof(server_name), token1);
    }
    else
    {
        have_iface = true;
        ntp_copy_string(iface_name, sizeof(iface_name), token1);
        ntp_copy_string(server_name, sizeof(server_name), token2);
    }

    net_interface_t *requested_iface = NULL;
    if (have_iface)
    {
        requested_iface = net_if_by_name(iface_name);
        if (!requested_iface)
        {
            return shell_output_error(out, "interface not found");
        }
        if (!requested_iface->present || !requested_iface->link_up || requested_iface->ipv4_addr == 0)
        {
            return shell_output_error(out, "interface is not ready");
        }
    }

    uint32_t server_ip = 0;
    bool resolved = false;
    if (!net_parse_ipv4(server_name, &server_ip))
    {
        shell_output_write(out, "Resolving ");
        shell_output_write(out, server_name);
        shell_output_write(out, "...\n");
        if (!net_dns_resolve_ipv4(server_name, requested_iface, &server_ip))
        {
            return shell_output_error(out, "unable to resolve server");
        }
        resolved = true;
    }

    net_interface_t *iface = requested_iface;
    uint32_t next_hop_ip = server_ip;
    if (!net_route_next_hop(iface, server_ip, &iface, &next_hop_ip))
    {
        return shell_output_error(out, "no route to server");
    }
    if (!iface || !iface->present || !iface->link_up || iface->ipv4_addr == 0)
    {
        return shell_output_error(out, "interface not ready");
    }

    char iface_ip[32];
    char server_ip_text[32];
    net_format_ipv4(iface->ipv4_addr, iface_ip);
    net_format_ipv4(server_ip, server_ip_text);

    shell_output_write(out, "NTP: using interface ");
    shell_output_write(out, iface->name);
    shell_output_write(out, " (");
    shell_output_write(out, iface_ip);
    shell_output_write(out, ") to contact ");
    if (resolved)
    {
        shell_output_write(out, server_name);
        shell_output_write(out, " (");
        shell_output_write(out, server_ip_text);
        shell_output_write(out, ")");
    }
    else
    {
        shell_output_write(out, server_ip_text);
    }
    shell_output_write(out, "\n");

    uint8_t server_mac[6];
    uint32_t freq = timer_frequency();
    if (freq == 0)
    {
        freq = 1000;
    }
    uint64_t arp_timeout = freq * 5ULL;
    if (!ntp_resolve_mac(iface, next_hop_ip, server_mac, arp_timeout))
    {
        return shell_output_error(out, "failed to resolve MAC address");
    }

    uint16_t local_port = (uint16_t)(40000 + (timer_ticks() & 0x3FFF));
    if (local_port < 1024)
    {
        local_port += 1024;
    }

    uint64_t now_ms = timekeeping_now_millis();
    uint64_t now_sec = now_ms / 1000ULL;
    uint64_t ms_remainder = now_ms % 1000ULL;
    uint32_t sec_part = (uint32_t)(now_sec + 2208988800ULL);
    uint32_t frac_part_scaled = (uint32_t)((ms_remainder * 4294967296ULL) / 1000ULL);

    uint8_t frame[128];
    memset(frame, 0, sizeof(frame));
    uint8_t *eth = frame;
    uint8_t *ip = eth + 14;
    uint8_t *udp = ip + 20;
    uint8_t *ntp = udp + 8;
    size_t ntp_len = 48;
    size_t udp_len = 8 + ntp_len;
    size_t ip_len = 20 + udp_len;
    size_t frame_len = 14 + ip_len;
    if (frame_len < NTP_ETH_MIN_FRAME)
    {
        frame_len = NTP_ETH_MIN_FRAME;
    }

    memcpy(eth, server_mac, 6);
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
    write_be32(ip + 16, server_ip);
    write_be16(ip + 10, 0);
    write_be16(ip + 10, ntp_checksum16(ip, 20));

    write_be16(udp + 0, local_port);
    write_be16(udp + 2, NTP_PORT);
    write_be16(udp + 4, (uint16_t)udp_len);
    write_be16(udp + 6, 0);

    memset(ntp, 0, ntp_len);
    ntp[0] = 0x23; /* LI=0, VN=4, Mode=3 */
    ntp[1] = 0;
    ntp[2] = 6;
    ntp[3] = 0xEC;
    write_be32(ntp + 40, sec_part);
    write_be32(ntp + 44, frac_part_scaled);

    uint16_t udp_sum = ntp_udp_checksum(iface->ipv4_addr, server_ip, udp, udp_len);
    if (udp_sum == 0)
    {
        udp_sum = 0xFFFF;
    }
    write_be16(udp + 6, udp_sum);

    net_ntp_clear_pending();
    net_ntp_set_pending(sec_part, frac_part_scaled, local_port, server_ip);

    if (!net_if_send(iface, frame, frame_len))
    {
        net_ntp_clear_pending();
        return shell_output_error(out, "failed to send request");
    }

    uint64_t start_tick = timer_ticks();
    uint64_t timeout_ticks = freq * 5ULL;
    shell_output_write(out, "Waiting for response...\n");
    while (timer_ticks() - start_tick < timeout_ticks)
    {
        net_ntp_result_t result;
        if (net_ntp_get_result(&result))
        {
            int64_t corrected_us = result.destination_time_microseconds + result.offset_microseconds;
            if (corrected_us < 0)
            {
                corrected_us = 0;
            }
            timekeeping_set_utc_seconds((uint64_t)(corrected_us / 1000000LL));
            char time_buf[32];
            timekeeping_format_time(time_buf, sizeof(time_buf));
            shell_output_write(out, "Offset: ");
            int offset_ms = (int)(result.offset_microseconds / 1000LL);
            ntp_write_int(out, offset_ms);
            shell_output_write(out, " ms\n");
            shell_output_write(out, "Delay: ");
            int delay_ms = (int)(result.delay_microseconds / 1000LL);
            ntp_write_int(out, delay_ms);
            shell_output_write(out, " ms\n");
            shell_output_write(out, "Local time updated to ");
            shell_output_write(out, time_buf);
            shell_output_write(out, "\n");
            return true;
        }
        __asm__ volatile ("pause");
    }

    net_ntp_clear_pending();
    return shell_output_error(out, "NTP timeout");
}

static const char *ntp_skip_ws(const char *s)
{
    if (!s)
    {
        return "";
    }
    while (*s == ' ' || *s == '\t')
    {
        ++s;
    }
    return s;
}

static bool ntp_read_token(const char **cursor, char *out, size_t capacity)
{
    const char *ptr = ntp_skip_ws(*cursor);
    if (*ptr == '\0')
    {
        *cursor = ptr;
        if (out && capacity)
        {
            out[0] = '\0';
        }
        return false;
    }
    size_t len = 0;
    while (*ptr && *ptr != ' ' && *ptr != '\t')
    {
        if (len + 1 < capacity)
        {
            out[len++] = *ptr;
        }
        ptr++;
    }
    if (out && capacity)
    {
        out[len] = '\0';
    }
    *cursor = ptr;
    return true;
}

static bool ntp_load_server(char *out, size_t capacity)
{
    if (!out || capacity == 0)
    {
        return false;
    }
    vfs_node_t *file = vfs_open_file(vfs_root(), NTP_SERVER_PATH, false, false);
    if (!file)
    {
        if (!ntp_write_default_server())
        {
            return false;
        }
        file = vfs_open_file(vfs_root(), NTP_SERVER_PATH, false, false);
        if (!file)
        {
            return false;
        }
    }
    size_t size = 0;
    const char *data = vfs_data(file, &size);
    if (!data || size == 0)
    {
        return false;
    }
    size_t i = 0;
    while (i < size && data[i] != '\n' && data[i] != '\r' && i + 1 < capacity)
    {
        out[i] = data[i];
        ++i;
    }
    out[i] = '\0';
    if (i > 0)
    {
        return true;
    }
    if (!ntp_write_default_server())
    {
        return false;
    }
    ntp_copy_string(out, capacity, NTP_DEFAULT_SERVER);
    return true;
}

static bool ntp_write_default_server(void)
{
    vfs_node_t *file = vfs_open_file(vfs_root(), NTP_SERVER_PATH, true, true);
    if (!file)
    {
        return false;
    }
    static const char default_line[] = NTP_DEFAULT_SERVER "\n";
    return vfs_append(file, default_line, sizeof(default_line) - 1);
}

static bool ntp_resolve_mac(net_interface_t *iface, uint32_t next_hop_ip, uint8_t mac_out[6], uint64_t timeout_ticks)
{
    if (net_arp_lookup(next_hop_ip, mac_out))
    {
        return true;
    }
    if (!net_arp_send_request(iface, next_hop_ip))
    {
        return false;
    }
    uint64_t start = timer_ticks();
    while (timer_ticks() - start < timeout_ticks)
    {
        if (net_arp_lookup(next_hop_ip, mac_out))
        {
            return true;
        }
        __asm__ volatile ("pause");
    }
    return false;
}

static uint16_t ntp_checksum16(const uint8_t *data, size_t len)
{
    uint32_t sum = 0;
    while (len > 1)
    {
        sum += (uint32_t)((data[0] << 8) | data[1]);
        data += 2;
        len -= 2;
    }
    if (len)
    {
        sum += (uint32_t)(data[0] << 8);
    }
    while (sum >> 16)
    {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

static uint16_t ntp_udp_checksum(uint32_t src_ip, uint32_t dst_ip, const uint8_t *udp, size_t udp_len)
{
    uint32_t sum = 0;
    sum += (src_ip >> 16) & 0xFFFFU;
    sum += src_ip & 0xFFFFU;
    sum += (dst_ip >> 16) & 0xFFFFU;
    sum += dst_ip & 0xFFFFU;
    sum += 17;
    sum += (uint32_t)udp_len;
    const uint8_t *ptr = udp;
    size_t bytes = udp_len;
    while (bytes > 1)
    {
        sum += (uint32_t)((ptr[0] << 8) | ptr[1]);
        ptr += 2;
        bytes -= 2;
    }
    if (bytes)
    {
        sum += (uint32_t)(ptr[0] << 8);
    }
    while (sum >> 16)
    {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }
    return (uint16_t)(~sum);
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

static void ntp_write_int(shell_output_t *out, int value)
{
    char buf[32];
    char tmp[16];
    size_t tmp_len = 0;
    bool negative = false;
    int64_t magnitude = value;
    if (magnitude < 0)
    {
        negative = true;
        magnitude = -magnitude;
    }
    uint32_t abs_value = (uint32_t)magnitude;
    do
    {
        tmp[tmp_len++] = (char)('0' + (abs_value % 10));
        abs_value /= 10;
    } while (abs_value > 0 && tmp_len < sizeof(tmp));

    size_t pos = 0;
    if (negative)
    {
        buf[pos++] = '-';
    }
    while (tmp_len > 0 && pos + 1 < sizeof(buf))
    {
        buf[pos++] = tmp[--tmp_len];
    }
    buf[pos] = '\0';
    shell_output_write(out, buf);
}

static void ntp_copy_string(char *dst, size_t capacity, const char *src)
{
    if (!dst || capacity == 0)
    {
        return;
    }
    if (!src)
    {
        dst[0] = '\0';
        return;
    }
    size_t len = strlen(src);
    if (len >= capacity)
    {
        len = capacity - 1;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
}
