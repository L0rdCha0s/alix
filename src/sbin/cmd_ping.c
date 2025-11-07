#include "shell_commands.h"

#include "net/arp.h"
#include "net/icmp.h"
#include "net/interface.h"
#include "net/route.h"
#include "net/dns.h"
#include "timer.h"
#include "process.h"
#include "libc.h"
#include <stddef.h>

static const char *skip_ws(const char *cursor);
static bool read_token(const char **cursor, char *out, size_t capacity);
static void ping_stdout_write(const char *text);
static void ping_stdout_write_uint(unsigned value);

bool shell_cmd_ping(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;
    const char *cursor = args ? args : "";

    char token1[32];
    char token2[32];
    char iface_name[NET_IF_NAME_MAX];
    char ip_token[32];
    bool have_iface = false;

    if (!read_token(&cursor, token1, sizeof(token1)))
    {
        return shell_output_error(out, "Usage: ping [iface] <host>");
    }

    if (!read_token(&cursor, token2, sizeof(token2)))
    {
        size_t ip_len = strlen(token1);
        if (ip_len == 0 || ip_len >= sizeof(ip_token))
        {
            return shell_output_error(out, "invalid host");
        }
        memcpy(ip_token, token1, ip_len + 1);
    }
    else
    {
        have_iface = true;
        size_t name_len = strlen(token1);
        if (name_len == 0 || name_len >= NET_IF_NAME_MAX)
        {
            return shell_output_error(out, "invalid interface name");
        }
        memcpy(iface_name, token1, name_len + 1);

        size_t ip_len = strlen(token2);
        if (ip_len == 0 || ip_len >= sizeof(ip_token))
        {
            return shell_output_error(out, "invalid host");
        }
        memcpy(ip_token, token2, ip_len + 1);
    }

    cursor = skip_ws(cursor);
    if (*cursor != '\0')
    {
        return shell_output_error(out, "Usage: ping [iface] <host>");
    }

    net_interface_t *requested_iface = NULL;
    if (have_iface)
    {
        requested_iface = net_if_by_name(iface_name);
        if (!requested_iface || !requested_iface->present)
        {
            return shell_output_error(out, "interface not found");
        }
        if (!requested_iface->link_up)
        {
            return shell_output_error(out, "interface is down");
        }
        if (requested_iface->ipv4_addr == 0)
        {
            return shell_output_error(out, "interface has no IPv4 address");
        }
    }

    uint32_t target_ip = 0;
    bool resolved_host = false;
    if (!net_parse_ipv4(ip_token, &target_ip))
    {
        ping_stdout_write("Resolving ");
        ping_stdout_write(ip_token);
        ping_stdout_write("...\n");
        if (!net_dns_resolve_ipv4(ip_token, requested_iface, &target_ip))
        {
            return shell_output_error(out, "unable to resolve host");
        }
        resolved_host = true;
    }

    char target_str[32];
    char source_str[32];
    net_format_ipv4(target_ip, target_str);
    net_interface_t *iface = requested_iface;
    uint32_t next_hop_ip = target_ip;
    if (!net_route_next_hop(iface, target_ip, &iface, &next_hop_ip))
    {
        return shell_output_error(out, "no route to host");
    }
    if (!iface || !iface->present || !iface->link_up || iface->ipv4_addr == 0)
    {
        return shell_output_error(out, "no route to host");
    }

    net_format_ipv4(iface->ipv4_addr, source_str);

    ping_stdout_write("PING ");
    if (resolved_host)
    {
        ping_stdout_write(ip_token);
        ping_stdout_write(" (");
        ping_stdout_write(target_str);
        ping_stdout_write(")");
    }
    else
    {
        ping_stdout_write(target_str);
    }
    ping_stdout_write(" from ");
    ping_stdout_write(source_str);
    ping_stdout_write(":\n");

    uint8_t target_mac[6];
    bool have_mac = net_arp_lookup(next_hop_ip, target_mac);
    uint32_t frequency = timer_frequency();
    if (frequency == 0)
    {
        frequency = 1000;
    }
    const uint64_t timeout_ticks = (uint64_t)frequency * 5;

    if (!have_mac)
    {
        ping_stdout_write("  Resolving ARP...\n");
        if (!net_arp_send_request(iface, next_hop_ip))
        {
            return shell_output_error(out, "failed to send ARP request");
        }

        uint64_t start = timer_ticks();
        while (timer_ticks() - start < timeout_ticks)
        {
            if (net_arp_lookup(next_hop_ip, target_mac))
            {
                have_mac = true;
                break;
            }
            __asm__ volatile ("pause");
        }

        if (!have_mac)
        {
            ping_stdout_write("  Request timed out (ARP)\n");
            return false;
        }
    }

    net_icmp_reset_pending();

    uint16_t identifier = (uint16_t)(timer_ticks() & 0xFFFF);
    if (identifier == 0)
    {
        identifier = 1;
    }
    uint16_t sequence = 1;
    const size_t payload_len = 32;
    const uint64_t interval_ticks = frequency;

    while (1)
    {
        if (!net_icmp_send_echo(iface, target_mac, target_ip, identifier, sequence, payload_len))
        {
            return shell_output_error(out, "failed to send ICMP echo request");
        }

        uint64_t send_tick = timer_ticks();
        bool got_reply = false;
        while (timer_ticks() - send_tick < timeout_ticks)
        {
            net_icmp_reply_t reply;
            if (net_icmp_get_reply(identifier, sequence, &reply))
            {
                char reply_ip[32];
                net_format_ipv4(reply.from_ip, reply_ip);
                ping_stdout_write("  Reply from ");
                ping_stdout_write(reply_ip);
                ping_stdout_write(": bytes=");
                ping_stdout_write_uint((unsigned)reply.bytes);
                ping_stdout_write(" time=");
                uint64_t ms = reply.rtt_ticks * 1000ULL / frequency;
                ping_stdout_write_uint((unsigned)ms);
                ping_stdout_write("ms\n");
                got_reply = true;
                break;
            }
            process_yield();
        }

        if (!got_reply)
        {
            ping_stdout_write("  Request timed out\n");
        }

        sequence++;
        uint64_t target_tick = send_tick + interval_ticks;
        while (timer_ticks() < target_tick)
        {
            process_yield();
        }
    }

    return true;
}

static const char *skip_ws(const char *cursor)
{
    while (*cursor == ' ' || *cursor == '\t')
    {
        ++cursor;
    }
    return cursor;
}

static bool read_token(const char **cursor, char *out, size_t capacity)
{
    const char *start = skip_ws(*cursor);
    if (*start == '\0')
    {
        *cursor = start;
        return false;
    }

    size_t len = 0;
    while (start[len] && start[len] != ' ' && start[len] != '\t')
    {
        if (len + 1 < capacity)
        {
            out[len] = start[len];
        }
        ++len;
    }

    if (len + 1 >= capacity)
    {
        *cursor = start + len;
        if (capacity > 0)
        {
            out[0] = '\0';
        }
        return false;
    }

    out[len] = '\0';
    *cursor = start + len;
    return true;
}

static void ping_stdout_write(const char *text)
{
    if (!text)
    {
        return;
    }
    process_stdout_write(text, strlen(text));
}

static void ping_stdout_write_uint(unsigned value)
{
    char buf[16];
    int pos = 0;
    if (value == 0)
    {
        buf[pos++] = '0';
    }
    else
    {
        while (value > 0 && pos < (int)(sizeof(buf) - 1))
        {
            buf[pos++] = (char)('0' + (value % 10U));
            value /= 10U;
        }
    }
    while (pos-- > 0)
    {
        process_stdout_write(&buf[pos], 1);
    }
}
