#include <stddef.h>

#include "net/interface.h"
#include "net/route.h"

#include "libc.h"
#include "heap.h"
#include "process.h"
#include "serial.h"

static net_interface_t g_interfaces[NET_MAX_INTERFACES];
static size_t g_interface_count = 0;

void net_if_init(void)
{
    for (size_t i = 0; i < NET_MAX_INTERFACES; ++i)
    {
        memset(&g_interfaces[i], 0, sizeof(net_interface_t));
    }
    g_interface_count = 0;
    net_route_init();
}

static net_interface_t *net_if_allocate(void)
{
    if (g_interface_count >= NET_MAX_INTERFACES)
    {
        return NULL;
    }
    net_interface_t *iface = &g_interfaces[g_interface_count++];
    memset(iface, 0, sizeof(*iface));
    return iface;
}

net_interface_t *net_if_register(const char *name, const uint8_t mac[6])
{
    net_interface_t *existing = net_if_by_name(name);
    if (existing)
    {
        if (mac)
        {
            memcpy(existing->mac, mac, 6);
            existing->present = true;
        }
        return existing;
    }

    net_interface_t *iface = net_if_allocate();
    if (!iface)
    {
        return NULL;
    }

    size_t len = strlen(name);
    if (len >= NET_IF_NAME_MAX)
    {
        len = NET_IF_NAME_MAX - 1;
    }
    memcpy(iface->name, name, len);
    iface->name[len] = '\0';
    iface->present = true;
    iface->link_up = false;
    iface->ipv4_addr = 0;
    iface->ipv4_netmask = 0;
    iface->ipv4_gateway = 0;
    iface->send = NULL;
    if (mac)
    {
        memcpy(iface->mac, mac, 6);
    }
    else
    {
        memset(iface->mac, 0, 6);
    }
    return iface;
}

net_interface_t *net_if_by_name(const char *name)
{
    if (!name)
    {
        return NULL;
    }
    for (size_t i = 0; i < g_interface_count; ++i)
    {
        if (strcmp(g_interfaces[i].name, name) == 0)
        {
            return &g_interfaces[i];
        }
    }
    return NULL;
}

size_t net_if_count(void)
{
    return g_interface_count;
}

net_interface_t *net_if_at(size_t index)
{
    if (index >= g_interface_count)
    {
        return NULL;
    }
    return &g_interfaces[index];
}

void net_if_set_link_up(net_interface_t *iface, bool up)
{
    if (!iface)
    {
        return;
    }
    iface->link_up = up;
}

void net_if_set_ipv4(net_interface_t *iface, uint32_t addr, uint32_t netmask, uint32_t gateway)
{
    if (!iface)
    {
        return;
    }
    iface->ipv4_addr = addr;
    iface->ipv4_netmask = netmask;
    iface->ipv4_gateway = gateway;

    if (gateway != 0)
    {
        net_route_set_default(iface, gateway);
    }
    else
    {
        net_interface_t *default_iface = NULL;
        if (net_route_get_default(&default_iface, NULL) && default_iface == iface)
        {
            net_route_clear_default();
        }
    }
}

void net_if_set_tx_handler(net_interface_t *iface, bool (*handler)(net_interface_t *, const uint8_t *, size_t))
{
    if (!iface)
    {
        return;
    }
    iface->send = handler;
}

static bool net_pointer_on_stack(const void *ptr, size_t len, thread_t **owner_out)
{
    thread_t *owner = process_find_stack_owner(ptr, len);
    if (owner_out)
    {
        *owner_out = owner;
    }
    return owner != NULL;
}

static void net_log_stack_dma_guard(const char *tag,
                                    const thread_t *owner,
                                    const void *ptr,
                                    size_t len)
{
    serial_printf("%s", "[net-dma] tag=");
    serial_printf("%s", tag ? tag : "<none>");
    serial_printf("%s", " ptr=0x");
    serial_printf("%016llX", (unsigned long long)((uintptr_t)ptr));
    serial_printf("%s", " len=0x");
    serial_printf("%016llX", (unsigned long long)(len));
    serial_printf("%s", " owner=");
    if (owner)
    {
        const char *name = process_thread_name_const(owner);
        serial_printf("%s", name && name[0] ? name : "<unnamed>");
        serial_printf("%s", " pid=0x");
        process_t *proc = process_thread_owner(owner);
        serial_printf("%016llX", (unsigned long long)(proc ? process_get_pid(proc) : 0));
    }
    else
    {
        serial_printf("%s", "<none>");
    }
    serial_printf("%s", "\r\n");
}

static uint32_t g_net_dma_guard_budget = 16;

static bool net_if_send_inner(net_interface_t *iface, const uint8_t *payload, size_t len)
{
    if (!iface || !iface->send)
    {
        return false;
    }
    bool ok = iface->send(iface, payload, len);
    if (ok)
    {
        iface->tx_packets++;
        iface->tx_bytes += (uint64_t)len;
    }
    else
    {
        iface->tx_errors++;
    }
    return ok;
}

static bool net_if_send(net_interface_t *iface, const uint8_t *data, size_t len)
{
    if (!iface)
    {
        return false;
    }

    const uint8_t *payload = data;
    uint8_t *clone = NULL;
    thread_t *owner = NULL;
    if (len > 0 && net_pointer_on_stack(data, len, &owner))
    {
        clone = (uint8_t *)malloc(len);
        if (!clone)
        {
            iface->tx_errors++;
            return false;
        }
        memcpy(clone, data, len);
        payload = clone;
        if (owner && g_net_dma_guard_budget > 0)
        {
            net_log_stack_dma_guard("net_if_send", owner, data, len);
            g_net_dma_guard_budget--;
        }
    }

    bool ok = net_if_send_inner(iface, payload, len);

    if (clone)
    {
        free(clone);
    }
    return ok;
}

bool net_if_send_direct(net_interface_t *iface, const uint8_t *data, size_t len)
{
    bool ok = net_if_send_inner(iface, data, len);
    if (!ok)
    {
        serial_printf("%s", "[net-if] direct send failed iface=");
        serial_printf("%s", iface ? iface->name : "<null>");
        serial_printf("%s", " len=0x");
        serial_printf("%016llX", (unsigned long long)len);
        serial_printf("%s", "\r\n");
    }
    return ok;
}

bool net_if_send_copy(net_interface_t *iface, const uint8_t *data, size_t len)
{
    if (!iface || !iface->send)
    {
        return false;
    }
    if (len == 0 || !data)
    {
        return net_if_send(iface, data, 0);
    }

    uint8_t *clone = (uint8_t *)malloc(len);
    if (!clone)
    {
        iface->tx_errors++;
        return false;
    }
    memcpy(clone, data, len);
    bool ok = net_if_send(iface, clone, len);
    free(clone);
    return ok;
}

void net_if_record_rx(net_interface_t *iface, size_t bytes)
{
    if (!iface)
    {
        return;
    }
    iface->rx_packets++;
    iface->rx_bytes += (uint64_t)bytes;
}

void net_if_record_rx_error(net_interface_t *iface)
{
    if (!iface)
    {
        return;
    }
    iface->rx_errors++;
}

void net_if_record_tx_error(net_interface_t *iface)
{
    if (!iface)
    {
        return;
    }
    iface->tx_errors++;
}

size_t net_if_snapshot(net_interface_stats_t *buffer, size_t capacity)
{
    if (!buffer || capacity == 0)
    {
        return 0;
    }

    size_t count = (g_interface_count < capacity) ? g_interface_count : capacity;
    for (size_t i = 0; i < count; ++i)
    {
        net_interface_t *iface = &g_interfaces[i];
        net_interface_stats_t *stats = &buffer[i];
        stats->name = iface->name;
        stats->present = iface->present;
        stats->link_up = iface->link_up;
        memcpy(stats->mac, iface->mac, sizeof(stats->mac));
        stats->ipv4_addr = iface->ipv4_addr;
        stats->ipv4_netmask = iface->ipv4_netmask;
        stats->ipv4_gateway = iface->ipv4_gateway;
        stats->rx_bytes = iface->rx_bytes;
        stats->tx_bytes = iface->tx_bytes;
        stats->rx_packets = iface->rx_packets;
        stats->tx_packets = iface->tx_packets;
        stats->rx_errors = iface->rx_errors;
        stats->tx_errors = iface->tx_errors;
    }
    return count;
}

static void write_hex_byte(uint8_t value, char *out)
{
    static const char hex[] = "0123456789ABCDEF";
    out[0] = hex[(value >> 4) & 0xF];
    out[1] = hex[value & 0xF];
}

void net_format_mac(const uint8_t mac[6], char *out)
{
    for (int i = 0; i < 6; ++i)
    {
        write_hex_byte(mac[i], out + i * 2);
    }
    out[12] = '\0';
}

void net_format_ipv4(uint32_t addr, char *out)
{
    char *ptr = out;
    for (int i = 3; i >= 0; --i)
    {
        uint8_t byte = (uint8_t)((addr >> (i * 8)) & 0xFF);
        if (byte >= 100)
        {
            *ptr++ = (char)('0' + (byte / 100));
            byte %= 100;
        }
        if (byte >= 10 || (ptr != out && *(ptr - 1) != '.'))
        {
            *ptr++ = (char)('0' + (byte / 10));
            byte %= 10;
        }
        *ptr++ = (char)('0' + byte);
        if (i != 0)
        {
            *ptr++ = '.';
        }
    }
    *ptr = '\0';
}

bool net_parse_ipv4(const char *text, uint32_t *out_addr)
{
    if (!text || !out_addr)
    {
        return false;
    }

    uint32_t result = 0;
    uint32_t value = 0;
    int octets = 0;
    bool have_digit = false;
    const char *cursor = text;

    while (true)
    {
        char c = *cursor;
        if (c >= '0' && c <= '9')
        {
            have_digit = true;
            value = value * 10U + (uint32_t)(c - '0');
            if (value > 255U)
            {
                return false;
            }
            ++cursor;
        }
        else if (c == '.' || c == '\0')
        {
            if (!have_digit)
            {
                return false;
            }
            result = (result << 8) | value;
            ++octets;
            if (octets > 4)
            {
                return false;
            }
            if (c == '\0')
            {
                break;
            }
            value = 0;
            have_digit = false;
            ++cursor;
        }
        else
        {
            return false;
        }
    }

    if (octets != 4)
    {
        return false;
    }

    *out_addr = result;
    return true;
}
