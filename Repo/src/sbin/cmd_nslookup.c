#include "shell_commands.h"

#include "net/dns.h"
#include "net/interface.h"
#include "libc.h"

#include <stddef.h>

static const char *skip_ws(const char *cursor);
static bool read_token(const char **cursor, char *out, size_t capacity);

bool shell_cmd_nslookup(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;
    const char *cursor = args ? args : "";

    char token1[NET_DNS_NAME_MAX + 1];
    char token2[NET_DNS_NAME_MAX + 1];
    char iface_name[NET_IF_NAME_MAX];
    char host[NET_DNS_NAME_MAX + 1];
    bool have_iface = false;

    if (!read_token(&cursor, token1, sizeof(token1)))
    {
        return shell_output_error(out, "Usage: nslookup [iface] <host>");
    }

    if (!read_token(&cursor, token2, sizeof(token2)))
    {
        size_t len = strlen(token1);
        if (len == 0 || len >= sizeof(host))
        {
            return shell_output_error(out, "invalid host");
        }
        memcpy(host, token1, len + 1);
    }
    else
    {
        have_iface = true;
        size_t iface_len = strlen(token1);
        if (iface_len == 0 || iface_len >= NET_IF_NAME_MAX)
        {
            return shell_output_error(out, "invalid interface name");
        }
        memcpy(iface_name, token1, iface_len + 1);

        size_t len = strlen(token2);
        if (len == 0 || len >= sizeof(host))
        {
            return shell_output_error(out, "invalid host");
        }
        memcpy(host, token2, len + 1);
    }

    cursor = skip_ws(cursor);
    if (*cursor != '\0')
    {
        return shell_output_error(out, "Usage: nslookup [iface] <host>");
    }

    net_interface_t *iface = NULL;
    if (have_iface)
    {
        iface = net_if_by_name(iface_name);
        if (!iface || !iface->present)
        {
            return shell_output_error(out, "interface not found");
        }
        if (!iface->link_up)
        {
            return shell_output_error(out, "interface is down");
        }
        if (iface->ipv4_addr == 0)
        {
            return shell_output_error(out, "interface has no IPv4 address");
        }
    }

    char current_host[NET_DNS_NAME_MAX + 1];
    memcpy(current_host, host, strlen(host) + 1);

    net_dns_result_t result;
    bool resolved = false;
    int depth = 0;

    while (depth < 5)
    {
        if (!net_dns_resolve(current_host, NET_DNS_TYPE_A, iface, &result))
        {
            break;
        }
        shell_output_write(out, "Query: ");
        shell_output_write(out, current_host);
        shell_output_write(out, "\n");

        if (result.has_a)
        {
            char ipbuf[32];
            net_format_ipv4(result.addr, ipbuf);
            shell_output_write(out, "Address: ");
            shell_output_write(out, ipbuf);
            shell_output_write(out, "\n");
            resolved = true;
            break;
        }
        if (result.has_cname)
        {
            shell_output_write(out, "CNAME: ");
            shell_output_write(out, result.cname);
            shell_output_write(out, "\n");
            size_t cname_len = strlen(result.cname);
            if (cname_len == 0 || cname_len >= sizeof(current_host))
            {
                break;
            }
            memcpy(current_host, result.cname, cname_len + 1);
            ++depth;
            continue;
        }
        break;
    }

    if (!resolved)
    {
        return shell_output_error(out, "DNS resolution failed");
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
    size_t total = 0;
    while (start[total] && start[total] != ' ' && start[total] != '\t')
    {
        if (total + 1 < capacity)
        {
            out[total] = start[total];
        }
        ++total;
    }
    size_t copy = total;
    if (copy >= capacity)
    {
        copy = capacity - 1;
    }
    out[copy] = '\0';
    *cursor = start + total;
    return true;
}
