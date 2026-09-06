#include "net/dns.h"

#include <stddef.h>

#include "libc.h"
#include "process.h"
#include "serial.h"
#include "timer.h"
#include "heap.h"
#include "process.h"

#include "net/arp.h"
#include "net/interface.h"
#include "net/route.h"
#include "spinlock.h"

#define NET_DNS_MAX_SERVERS 4
#define NET_DNS_MAX_PENDING 128
#define NET_DNS_MAX_PACKET  512
#define NET_DNS_CACHE_SIZE 128
#define NET_DNS_CACHE_TTL_DEFAULT_SEC 60
#define NET_DNS_CACHE_TTL_MAX_SEC 3600

#define DNS_FLAG_QR (1U << 15)
#define DNS_FLAG_OPCODE_SHIFT 11
#define DNS_FLAG_AA (1U << 10)
#define DNS_FLAG_TC (1U << 9)
#define DNS_FLAG_RD (1U << 8)
#define DNS_FLAG_RA (1U << 7)

#define DNS_RCODE(flags) ((flags) & 0x000F)
#define DNS_TYPE_OPT 41
#define NET_DNS_MAX_CNAME_HOPS 8

typedef struct
{
    volatile bool active;
    uint16_t id;
    uint16_t qtype;
    uint16_t local_port;
    char hostname[NET_DNS_NAME_MAX + 1];       /* original name requested */
    char qname_current[NET_DNS_NAME_MAX + 1];  /* name we are currently querying */
    uint8_t cname_hops;                        /* how many extra queries we've issued following CNAMEs */
    net_interface_t *iface;
    uint32_t server_ip;
    uint32_t next_hop;
    uint8_t server_mac[6];
    bool have_mac;
    uint64_t sent_tick;
    uint32_t retries;
    uint32_t timeout_ticks;
    volatile bool completed;
    volatile bool success;
    net_dns_result_t result;
    uint32_t server_snapshot[NET_DNS_MAX_SERVERS];
    size_t server_snapshot_count;
    char scratch_qname[NET_DNS_NAME_MAX + 1];
    char scratch_target[NET_DNS_NAME_MAX + 1];
    char scratch_rr[NET_DNS_NAME_MAX + 1];
    char scratch_tmp[NET_DNS_NAME_MAX + 1];
} dns_pending_t;

typedef struct
{
    bool valid;
    uint16_t qtype;
    uint32_t addrs[NET_DNS_MAX_ADDRS];
    size_t addr_count;
    uint64_t expires_tick;
    uint64_t last_used_tick;
    char name[NET_DNS_NAME_MAX + 1];
} dns_cache_entry_t;


static uint32_t g_servers[NET_DNS_MAX_SERVERS];
static size_t g_server_count = 0;
static dns_pending_t g_pending[NET_DNS_MAX_PENDING];
static dns_cache_entry_t g_dns_cache[NET_DNS_CACHE_SIZE];
static uint16_t g_next_id = 0x1234;
static uint32_t g_retry_count = 3;
static uint16_t g_next_port = 0xC000;
static spinlock_t g_dns_lock;
static bool g_dns_debug_enabled = false;

static inline uint64_t dns_irq_save(void)
{
    uint64_t flags;
    __asm__ volatile ("pushfq; pop %0" : "=r"(flags));
    __asm__ volatile ("cli" ::: "memory");
    return flags;
}

static inline void dns_irq_restore(uint64_t flags)
{
    __asm__ volatile ("push %0; popfq" :: "r"(flags) : "cc", "memory");
}

static inline uint64_t dns_lock(void)
{
    uint64_t flags = dns_irq_save();
    spinlock_lock(&g_dns_lock);
    return flags;
}

static inline void dns_unlock(uint64_t flags)
{
    spinlock_unlock(&g_dns_lock);
    dns_irq_restore(flags);
}

static void dns_log(const char *msg);
static void dns_debug_log(const char *msg);
static uint16_t read_be16(const uint8_t *p);
static uint32_t read_be32(const uint8_t *p);
#define DNS_TRACE(label, dest, len) \
    process_debug_log_stack_write(label, __builtin_return_address(0), (dest), (len))

static void write_be16(uint8_t *p, uint16_t value);
static void write_be32(uint8_t *p, uint32_t value);
static bool dns_encode_question(const char *hostname, uint16_t qtype,
                                uint8_t *buffer, size_t *len_in_out);
static bool dns_decode_name(const uint8_t *packet, size_t packet_len,
                            size_t *offset, char *out_name, size_t capacity);
static dns_pending_t *dns_allocate_pending(void);
static void dns_release_pending(dns_pending_t *pending);
static bool dns_send_query(dns_pending_t *pending);
static bool dns_prepare_route(dns_pending_t *pending);
static uint16_t checksum16(const uint8_t *data, size_t len);
static uint16_t dns_allocate_port(void);
static uint16_t dns_allocate_id(void);
static void dns_log_ipv4(const char *prefix, uint32_t addr);
static void dns_debug_ipv4(const char *prefix, uint32_t addr);
static uint64_t dns_cache_expiry_tick(uint32_t ttl_sec, uint64_t now);
static bool dns_cache_lookup(const char *hostname, uint16_t qtype, net_dns_result_t *result);
static void dns_cache_store_a(const char *hostname,
                              const uint32_t *addrs,
                              size_t addr_count,
                              uint32_t ttl_sec);
static bool dns_add_unique_addr(uint32_t *addrs, size_t *count, uint32_t addr);

void net_dns_init(void)
{
    spinlock_init(&g_dns_lock);
    uint64_t flags = dns_lock();
    g_server_count = 0;
    for (size_t i = 0; i < NET_DNS_MAX_PENDING; ++i)
    {
        g_pending[i].active = false;
    }
    for (size_t i = 0; i < NET_DNS_CACHE_SIZE; ++i)
    {
        g_dns_cache[i].valid = false;
    }
    dns_unlock(flags);
}

void net_dns_set_debug(bool enable)
{
    g_dns_debug_enabled = enable;
    dns_log(enable ? "debug: enabled" : "debug: disabled");
}

bool net_dns_debug_enabled(void)
{
    return g_dns_debug_enabled;
}

static bool dns_name_equal(const char *a, const char *b)
{
    if (!a || !b) return false;
    size_t la = strlen(a), lb = strlen(b);
    if (la && a[la-1] == '.') la--;
    if (lb && b[lb-1] == '.') lb--;
    if (la != lb) return false;
    for (size_t i = 0; i < la; ++i)
    {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + 32);
        if (ca != cb) return false;
    }
    return true;
}

static uint64_t dns_cache_expiry_tick(uint32_t ttl_sec, uint64_t now)
{
    uint32_t freq = timer_frequency();
    if (freq == 0)
    {
        freq = 100;
    }
    uint32_t ttl = ttl_sec;
    if (ttl == 0)
    {
        ttl = NET_DNS_CACHE_TTL_DEFAULT_SEC;
    }
    if (ttl > NET_DNS_CACHE_TTL_MAX_SEC)
    {
        ttl = NET_DNS_CACHE_TTL_MAX_SEC;
    }
    uint64_t ttl_ticks = (uint64_t)ttl * (uint64_t)freq;
    if (ttl_ticks == 0)
    {
        ttl_ticks = (uint64_t)NET_DNS_CACHE_TTL_DEFAULT_SEC * (uint64_t)freq;
    }
    return now + ttl_ticks;
}

static bool dns_cache_lookup(const char *hostname, uint16_t qtype, net_dns_result_t *result)
{
    if (!hostname || !result || qtype != NET_DNS_TYPE_A)
    {
        return false;
    }

    uint64_t now = timer_ticks();
    uint32_t addrs[NET_DNS_MAX_ADDRS];
    size_t addr_count = 0;
    bool hit = false;

    uint64_t flags = dns_lock();
    for (size_t i = 0; i < NET_DNS_CACHE_SIZE; ++i)
    {
        dns_cache_entry_t *entry = &g_dns_cache[i];
        if (!entry->valid)
        {
            continue;
        }
        if (entry->expires_tick != 0 && now >= entry->expires_tick)
        {
            entry->valid = false;
            continue;
        }
        if (entry->qtype != qtype)
        {
            continue;
        }
        if (!dns_name_equal(entry->name, hostname))
        {
            continue;
        }
        entry->last_used_tick = now;
        addr_count = entry->addr_count;
        if (addr_count > NET_DNS_MAX_ADDRS)
        {
            addr_count = NET_DNS_MAX_ADDRS;
        }
        memcpy(addrs, entry->addrs, addr_count * sizeof(addrs[0]));
        hit = true;
        break;
    }
    dns_unlock(flags);

    if (hit)
    {
        memset(result, 0, sizeof(*result));
        result->has_a = true;
        result->addr_count = addr_count;
        memcpy(result->addrs, addrs, addr_count * sizeof(addrs[0]));
        result->addr = addr_count > 0 ? addrs[0] : 0;
        result->rr_type = NET_DNS_TYPE_A;
    }
    return hit;
}

static void dns_cache_store_a(const char *hostname,
                              const uint32_t *addrs,
                              size_t addr_count,
                              uint32_t ttl_sec)
{
    if (!hostname || hostname[0] == '\0' || !addrs || addr_count == 0)
    {
        return;
    }

    uint64_t now = timer_ticks();
    uint64_t expires_tick = dns_cache_expiry_tick(ttl_sec, now);
    size_t replace = NET_DNS_CACHE_SIZE;
    uint64_t oldest_tick = 0;
    bool have_oldest = false;

    uint64_t flags = dns_lock();
    for (size_t i = 0; i < NET_DNS_CACHE_SIZE; ++i)
    {
        dns_cache_entry_t *entry = &g_dns_cache[i];
        if (entry->valid && entry->qtype == NET_DNS_TYPE_A &&
            dns_name_equal(entry->name, hostname))
        {
            entry->addr_count = addr_count > NET_DNS_MAX_ADDRS
                ? NET_DNS_MAX_ADDRS
                : addr_count;
            memcpy(entry->addrs,
                   addrs,
                   entry->addr_count * sizeof(entry->addrs[0]));
            entry->expires_tick = expires_tick;
            entry->last_used_tick = now;
            dns_unlock(flags);
            return;
        }
    }

    for (size_t i = 0; i < NET_DNS_CACHE_SIZE; ++i)
    {
        dns_cache_entry_t *entry = &g_dns_cache[i];
        if (!entry->valid)
        {
            replace = i;
            break;
        }
        if (entry->expires_tick != 0 && now >= entry->expires_tick)
        {
            replace = i;
            break;
        }
        if (!have_oldest || entry->last_used_tick < oldest_tick)
        {
            oldest_tick = entry->last_used_tick;
            have_oldest = true;
            replace = i;
        }
    }

    if (replace < NET_DNS_CACHE_SIZE)
    {
        dns_cache_entry_t *entry = &g_dns_cache[replace];
        size_t len = strlen(hostname);
        if (len > NET_DNS_NAME_MAX)
        {
            len = NET_DNS_NAME_MAX;
        }
        memcpy(entry->name, hostname, len);
        entry->name[len] = '\0';
        entry->valid = true;
        entry->qtype = NET_DNS_TYPE_A;
        entry->addr_count = addr_count > NET_DNS_MAX_ADDRS
            ? NET_DNS_MAX_ADDRS
            : addr_count;
        memcpy(entry->addrs,
               addrs,
               entry->addr_count * sizeof(entry->addrs[0]));
        entry->expires_tick = expires_tick;
        entry->last_used_tick = now;
    }
    dns_unlock(flags);
}

static bool dns_add_unique_addr(uint32_t *addrs, size_t *count, uint32_t addr)
{
    if (!addrs || !count || addr == 0)
    {
        return false;
    }
    for (size_t i = 0; i < *count; ++i)
    {
        if (addrs[i] == addr)
        {
            return true;
        }
    }
    if (*count >= NET_DNS_MAX_ADDRS)
    {
        return false;
    }
    addrs[(*count)++] = addr;
    return true;
}



void net_dns_set_servers(const uint32_t *servers, size_t count)
{
    uint64_t flags = dns_lock();
    g_server_count = 0;
    if (!servers || count == 0)
    {
        dns_unlock(flags);
        dns_log("set_servers: empty input");
        return;
    }
    for (size_t i = 0; i < count && g_server_count < NET_DNS_MAX_SERVERS; ++i)
    {
        if (servers[i] != 0)
        {
            g_servers[g_server_count++] = servers[i];
            dns_log_ipv4("set_servers: added", servers[i]);
        }
    }
    size_t total = g_server_count;
    dns_unlock(flags);
    if (total == 0)
    {
        dns_log("set_servers: no usable servers");
    }
    else
    {
        char buf[64];
        size_t len = strlen("set_servers: total=");
        memcpy(buf, "set_servers: total=", len);
        buf[len++] = (char)('0' + (int)total);
        buf[len] = '\0';
        dns_log(buf);
    }
}

size_t net_dns_server_count(void)
{
    uint64_t flags = dns_lock();
    size_t count = g_server_count;
    dns_unlock(flags);
    return count;
}

static dns_pending_t *dns_allocate_pending(void)
{
    dns_pending_t *pending = NULL;
    uint64_t flags = dns_lock();
    for (size_t i = 0; i < NET_DNS_MAX_PENDING; ++i)
    {
        if (!g_pending[i].active)
        {
            memset(&g_pending[i], 0, sizeof(g_pending[i]));
            g_pending[i].active = true;
            pending = &g_pending[i];
            break;
        }
    }
    dns_unlock(flags);
    return pending;
}

static void dns_release_pending(dns_pending_t *pending)
{
    if (pending)
    {
        uint64_t flags = dns_lock();
        pending->active = false;
        pending->local_port = 0;
        pending->server_snapshot_count = 0;
        pending->iface = NULL;
        dns_unlock(flags);
    }
}

bool net_dns_resolve(const char *hostname, uint16_t qtype,
                     net_interface_t *preferred_iface, net_dns_result_t *result)
{
    if (!hostname || !result || qtype == 0)
    {
        dns_log("resolve: invalid arguments");
        return false;
    }
    size_t len = strlen(hostname);
    if (len == 0 || len > NET_DNS_NAME_MAX)
    {
        dns_log("resolve: hostname invalid length");
        return false;
    }

    if (dns_cache_lookup(hostname, qtype, result))
    {
        return true;
    }

    uint64_t flags = dns_lock();
    size_t configured_servers = g_server_count;
    dns_unlock(flags);
    if (configured_servers == 0)
    {
        dns_log("no dns servers configured");
        return false;
    }

    dns_pending_t *pending = dns_allocate_pending();
    if (!pending)
    {
        return false;
    }

    flags = dns_lock();
    pending->server_snapshot_count = g_server_count;
    if (pending->server_snapshot_count > NET_DNS_MAX_SERVERS)
    {
        pending->server_snapshot_count = NET_DNS_MAX_SERVERS;
    }
    if (pending->server_snapshot_count > 0)
    {
        memcpy(pending->server_snapshot,
               g_servers,
               pending->server_snapshot_count * sizeof(uint32_t));
    }
    dns_unlock(flags);
    if (pending->server_snapshot_count == 0)
    {
        dns_log("no dns servers available");
        dns_release_pending(pending);
        return false;
    }

    pending->local_port = dns_allocate_port();
    if (pending->local_port == 0)
    {
        dns_release_pending(pending);
        return false;
    }

    memcpy(pending->hostname, hostname, len + 1);
    memcpy(pending->qname_current, hostname, len + 1);
    pending->cname_hops = 0;
    pending->qtype = qtype;
    pending->id = dns_allocate_id();
    pending->iface = preferred_iface;
    pending->timeout_ticks = timer_frequency();
    if (pending->timeout_ticks == 0) pending->timeout_ticks = 100;

    bool sent = false;
    for (size_t i = 0; i < pending->server_snapshot_count; ++i)
    {
        pending->server_ip = pending->server_snapshot[i];
        pending->have_mac = false;
        pending->retries = 0;
        pending->completed = false;
        pending->success = false;

        if (!dns_prepare_route(pending))
        {
            dns_log_ipv4("resolve: route unavailable for", pending->server_ip);
            continue;
        }
        if (dns_send_query(pending))
        {
            sent = true;
            break;
        }
        dns_log_ipv4("resolve: failed to send query to", pending->server_ip);
    }

    if (!sent)
    {
        dns_log("resolve: failed to send to all servers");
        dns_release_pending(pending);
        return false;
    }

    uint64_t start = timer_ticks();
    uint64_t deadline = start + (pending->timeout_ticks * (g_retry_count + 1));

    while (!pending->completed)
    {
        uint64_t now = timer_ticks();
        if (now >= deadline) break;

        if (pending->sent_tick != 0 && now - pending->sent_tick >= pending->timeout_ticks)
        {
            if (pending->retries >= g_retry_count)
            {
                break;
            }
            if (!dns_send_query(pending))
            {
                break;
            }
        }
        process_yield();
    }

    bool success = pending->completed && pending->success;
    if (success)
    {
        *result = pending->result;
    }
    dns_release_pending(pending);
    return success;
}



bool net_dns_resolve_ipv4(const char *hostname, net_interface_t *preferred_iface,
                          uint32_t *out_addr)
{
    if (!out_addr)
    {
        return false;
    }
    net_dns_result_t result;
    if (!net_dns_resolve(hostname, NET_DNS_TYPE_A, preferred_iface, &result))
    {
        return false;
    }
    if (!result.has_a)
    {
        return false;
    }
    *out_addr = result.addr;
    return true;
}

size_t net_dns_resolve_ipv4_all(const char *hostname,
                                net_interface_t *preferred_iface,
                                uint32_t *out_addrs,
                                size_t capacity)
{
    if (!out_addrs || capacity == 0)
    {
        return 0;
    }
    net_dns_result_t result;
    if (!net_dns_resolve(hostname, NET_DNS_TYPE_A, preferred_iface, &result) ||
        !result.has_a)
    {
        return 0;
    }

    size_t count = result.addr_count;
    if (count == 0 && result.addr != 0)
    {
        out_addrs[0] = result.addr;
        return 1;
    }
    if (count > capacity)
    {
        count = capacity;
    }
    memcpy(out_addrs, result.addrs, count * sizeof(out_addrs[0]));
    return count;
}

bool net_dns_resolve_cname(const char *hostname, net_interface_t *preferred_iface,
                           char *out_buffer, size_t buffer_len)
{
    if (!out_buffer || buffer_len == 0)
    {
        return false;
    }
    net_dns_result_t result;
    if (!net_dns_resolve(hostname, NET_DNS_TYPE_CNAME, preferred_iface, &result))
    {
        return false;
    }
    if (!result.has_cname)
    {
        return false;
    }
    size_t len = strlen(result.cname);
    if (len >= buffer_len)
    {
        return false;
    }
    memcpy(out_buffer, result.cname, len + 1);
    return true;
}

static void dns_finish_pending(dns_pending_t *pending, bool success, const net_dns_result_t *result)
{
    if (!pending)
    {
        return;
    }
    pending->completed = true;
    pending->success = success;
    if (success && result)
    {
        pending->result = *result;
    }
    if (g_dns_debug_enabled)
    {
        serial_printf("%s", "[dns-debug] finish: host=");
        serial_printf("%s", pending->hostname[0] ? pending->hostname : "<none>");
        serial_printf("%s", " success=0x");
        serial_printf("%016llX", (unsigned long long)(success ? 1 : 0));
        serial_printf("%s", " id=0x");
        serial_printf("%016llX", (unsigned long long)(pending->id));
        serial_printf("%s", " type=0x");
        serial_printf("%016llX", (unsigned long long)(result ? result->rr_type : 0));
        serial_printf("%s", "\r\n");
    }
}

static bool dns_prepare_route(dns_pending_t *pending)
{
    net_interface_t *iface = pending->iface;
    uint32_t next_hop = pending->server_ip;
    if (!net_route_next_hop(iface, pending->server_ip, &iface, &next_hop))
    {
        dns_log("prepare_route: next hop lookup failed");
        return false;
    }
    if (!iface || !iface->present || !iface->link_up || iface->ipv4_addr == 0)
    {
        dns_log("prepare_route: interface unusable");
        return false;
    }
    pending->iface = iface;
    pending->next_hop = next_hop;
    if (g_dns_debug_enabled)
    {
        char *tmp = pending->scratch_tmp;
        net_format_ipv4(iface->ipv4_addr, tmp);
        serial_printf("%s", "[dns-debug] prepare_route: iface=");
        serial_printf("%s", iface->name[0] ? iface->name : "<noname>");
        serial_printf("%s", " present=0x");
        serial_printf("%016llX", (unsigned long long)(iface->present ? 1 : 0));
        serial_printf("%s", " link=0x");
        serial_printf("%016llX", (unsigned long long)(iface->link_up ? 1 : 0));
        serial_printf("%s", " ip=");
        serial_printf("%s", tmp);
        serial_printf("%s", "\r\n");
        dns_debug_ipv4("prepare_route: next hop", next_hop);
    }

    if (net_arp_lookup(next_hop, pending->server_mac))
    {
        pending->have_mac = true;
    }
    else
    {
        pending->have_mac = false;
    }
    return true;
}

static bool dns_send_query(dns_pending_t *pending)
{
    net_interface_t *iface = pending->iface;
    if (!iface)
    {
        dns_log("send_query: missing iface");
        return false;
    }

    if (!pending->have_mac)
    {
        dns_log_ipv4("send_query: resolving via ARP for", pending->next_hop);
        dns_debug_log("send_query: waiting for ARP response");
        if (!net_arp_send_request(iface, pending->next_hop))
        {
            dns_log("send_query: failed to start ARP");
            dns_debug_log("send_query: net_arp_send_request failed");
            return false;
        }
        uint64_t start = timer_ticks();
        uint64_t wait_ticks = timer_frequency() / 5; /* ~200ms */
        if (wait_ticks == 0) wait_ticks = 20;
        while (timer_ticks() - start < wait_ticks)
        {
            if (net_arp_lookup(pending->next_hop, pending->server_mac))
            {
                pending->have_mac = true;
                if (g_dns_debug_enabled)
                {
                    char *macbuf = pending->scratch_tmp;
                    net_format_mac(pending->server_mac, macbuf);
                    serial_printf("%s", "[dns-debug] send_query: ARP resolved mac=");
                    serial_printf("%s", macbuf);
                    serial_printf("%s", "\r\n");
                }
                break;
            }
            process_yield();
        }
        if (!pending->have_mac)
        {
            dns_log("send_query: ARP resolution timeout");
            dns_debug_log("send_query: ARP timed out");
            return false;
        }
        dns_log("send_query: ARP resolved");
    }

    uint8_t *packet = (uint8_t *)malloc(NET_DNS_MAX_PACKET);
    if (!packet)
    {
        dns_log("send_query: alloc failed");
        return false;
    }
    memset(packet, 0, NET_DNS_MAX_PACKET);

    uint8_t *eth = packet;
    uint8_t *ip  = packet + 14;
    uint8_t *udp = ip + 20;
    uint8_t *dns = udp + 8;

    size_t dns_len = 12;
    write_be16(dns + 0, pending->id);
    write_be16(dns + 2, DNS_FLAG_RD);
    write_be16(dns + 4, 1); /* QDCOUNT */
    write_be16(dns + 6, 0);
    write_be16(dns + 8, 0);
    write_be16(dns + 10, 0);

    size_t qlen_cap = NET_DNS_MAX_PACKET - dns_len;
    size_t qlen = qlen_cap;
    if (!dns_encode_question(pending->qname_current, pending->qtype, dns + dns_len, &qlen))
    {
        dns_log("send_query: encode_question failed");
        free(packet);
        return false;
    }
    dns_len += qlen;

    size_t udp_len = 8 + dns_len;
    size_t ip_len  = 20 + udp_len;
    size_t frame_len = 14 + ip_len;
    if (frame_len < 60) frame_len = 60;

    memcpy(eth, pending->server_mac, 6);
    memcpy(eth + 6, iface->mac, 6);
    eth[12] = 0x08; eth[13] = 0x00;

    ip[0] = 0x45; ip[1] = 0x00;
    write_be16(ip + 2, (uint16_t)ip_len);
    write_be16(ip + 4, 0);
    write_be16(ip + 6, 0);
    ip[8] = 64; ip[9] = 17;
    write_be32(ip + 12, iface->ipv4_addr);
    write_be32(ip + 16, pending->server_ip);
    write_be16(ip + 10, 0);
    write_be16(ip + 10, checksum16(ip, 20));

    write_be16(udp + 0, pending->local_port);
    write_be16(udp + 2, 53);
    write_be16(udp + 4, (uint16_t)udp_len);
    write_be16(udp + 6, 0);

    uint32_t sum = 0;
    sum += (iface->ipv4_addr >> 16) & 0xFFFFU;
    sum += iface->ipv4_addr & 0xFFFFU;
    sum += (pending->server_ip >> 16) & 0xFFFFU;
    sum += pending->server_ip & 0xFFFFU;
    sum += 17;
    sum += (uint32_t)udp_len;
    const uint8_t *udp_ptr = udp;
    size_t udp_bytes = udp_len;
    while (udp_bytes > 1)
    {
        sum += (uint32_t)((udp_ptr[0] << 8) | udp_ptr[1]);
        udp_ptr += 2;
        udp_bytes -= 2;
    }
    if (udp_bytes) sum += (uint32_t)(udp_ptr[0] << 8);
    while (sum >> 16) sum = (sum & 0xFFFFU) + (sum >> 16);
    write_be16(udp + 6, (uint16_t)(~sum));

    if (g_dns_debug_enabled)
    {
        char ipbuf[32];
        char macbuf[32];
        net_format_ipv4(pending->server_ip, ipbuf);
        net_format_mac(pending->server_mac, macbuf);
        serial_printf("%s", "[dns-debug] send_query: id=0x");
        serial_printf("%016llX", (unsigned long long)(pending->id));
        serial_printf("%s", " port=0x");
        serial_printf("%016llX", (unsigned long long)(pending->local_port));
        serial_printf("%s", " iface=");
        serial_printf("%s", iface->name[0] ? iface->name : "<noname>");
        serial_printf("%s", " server=");
        serial_printf("%s", ipbuf);
        serial_printf("%s", " mac=");
        serial_printf("%s", macbuf);
        serial_printf("%s", " len=0x");
        serial_printf("%016llX", (unsigned long long)(frame_len));
        serial_printf("%s", "\r\n");
    }

    serial_printf("[dns] send_query id=0x%04X host=%s len=0x%X",
                  pending->id,
                  pending->qname_current[0] ? pending->qname_current : "<none>",
                  (unsigned)frame_len);

    if (!net_if_send_copy(iface, packet, frame_len))
    {
        dns_log("send_query: net_if_send failed");
        dns_debug_log("send_query: net_if_send_copy returned false");
        free(packet);
        return false;
    }
    serial_printf("[dns] send_query dispatched id=0x%04X", pending->id);

    pending->sent_tick = timer_ticks();
    pending->retries++;
    if (g_dns_debug_enabled)
    {
        serial_printf("%s", "[dns-debug] send_query: dispatched id=0x");
        serial_printf("%016llX", (unsigned long long)(pending->id));
        serial_printf("%s", " retries=0x");
        serial_printf("%016llX", (unsigned long long)(pending->retries));
        serial_printf("%s", "\r\n");
    }
    free(packet);
    return true;
}

static bool dns_skip_rrs(const uint8_t *dns, size_t dns_len, size_t *off,
                         uint16_t count, char *scratch, size_t scratch_cap)
{
    size_t o = *off;
    for (uint16_t i = 0; i < count; ++i)
    {
        if (!scratch || scratch_cap == 0) return false;
        if (!dns_decode_name(dns, dns_len, &o, scratch, scratch_cap)) return false;
        if (o + 10 > dns_len) return false;
        uint16_t rdlen = read_be16(dns + o + 8);
        o += 10;
        if (o + rdlen > dns_len) return false;
        o += rdlen;
    }
    *off = o;
    return true;
}



void net_dns_handle_frame(net_interface_t *iface, const uint8_t *frame, size_t length)
{
    if (!iface || !frame || length < 14 + 20 + 8) return;

    const uint8_t *eth = frame;
    uint16_t eth_type = (uint16_t)((eth[12] << 8) | eth[13]);
    if (eth_type != 0x0800) return;

    const uint8_t *ip = frame + 14;
    uint8_t version = (uint8_t)(ip[0] >> 4);
    uint8_t ihl = (uint8_t)(ip[0] & 0x0F);
    if (version != 4 || ihl < 5) return;

    size_t ip_hlen = (size_t)ihl * 4;
    if (length < 14 + ip_hlen + 8) return;
    if (ip[9] != 17) return; /* UDP */

    uint16_t ip_total_len = read_be16(ip + 2);
    if (ip_total_len < ip_hlen + 8) return;

    const uint8_t *udp = ip + ip_hlen;
    uint16_t src_port = read_be16(udp + 0);
    uint16_t dst_port = read_be16(udp + 2);
    uint16_t udp_len  = read_be16(udp + 4);
    if (udp_len < 8 || (size_t)(udp - ip) + udp_len > ip_total_len) return;

    dns_pending_t *pending = NULL;
    uint64_t lock_flags = dns_lock();
    for (size_t i = 0; i < NET_DNS_MAX_PENDING; ++i)
    {
        if (g_pending[i].active && g_pending[i].local_port == dst_port)
        {
            pending = &g_pending[i];
            break;
        }
    }
    dns_unlock(lock_flags);
    if (!pending) return;
    if (src_port != 53) return;
    if (g_dns_debug_enabled)
    {
        serial_printf("%s", "[dns-debug] handle_frame: iface=");
        serial_printf("%s", iface->name[0] ? iface->name : "<noname>");
        serial_printf("%s", " id=0x");
        serial_printf("%016llX", (unsigned long long)(pending->id));
        serial_printf("%s", " src_port=0x");
        serial_printf("%016llX", (unsigned long long)(src_port));
        serial_printf("%s", " dst_port=0x");
        serial_printf("%016llX", (unsigned long long)(dst_port));
        serial_printf("%s", " udp_len=0x");
        serial_printf("%016llX", (unsigned long long)(udp_len));
        serial_printf("%s", "\r\n");
    }

    const uint8_t *dns = udp + 8;
    size_t dns_len = udp_len - 8;
    if (dns_len < 12) return;

    uint16_t id    = read_be16(dns + 0);
    uint16_t flags = read_be16(dns + 2);
    if (!pending->active || pending->iface != iface || pending->id != id) return;
    if ((flags & DNS_FLAG_QR) == 0) { return; }             /* not a response */
    if ((flags & 0x000F) != 0)      { dns_finish_pending(pending, false, NULL); return; } /* RCODE != NOERROR */
    if (flags & DNS_FLAG_TC)        { dns_finish_pending(pending, false, NULL); return; } /* truncated over UDP */

    uint16_t qdcount = read_be16(dns + 4);
    uint16_t ancount = read_be16(dns + 6);
    uint16_t nscount = read_be16(dns + 8);
    uint16_t arcount = read_be16(dns + 10);
    if (g_dns_debug_enabled)
    {
        serial_printf("%s", "[dns-debug] handle_frame: flags=0x");
        serial_printf("%016llX", (unsigned long long)(flags));
        serial_printf("%s", " qd=0x");
        serial_printf("%016llX", (unsigned long long)(qdcount));
        serial_printf("%s", " an=0x");
        serial_printf("%016llX", (unsigned long long)(ancount));
        serial_printf("%s", " ns=0x");
        serial_printf("%016llX", (unsigned long long)(nscount));
        serial_printf("%s", " ar=0x");
        serial_printf("%016llX", (unsigned long long)(arcount));
        serial_printf("%s", "\r\n");
    }

    size_t offset = 12;

    /* Decode first question to get the owner name we asked for */
    char *qname = pending->scratch_qname;
    qname[0] = '\0';
    if (qdcount > 0)
    {
        if (!dns_decode_name(dns, dns_len, &offset, qname, sizeof(pending->scratch_qname))) { dns_finish_pending(pending, false, NULL); return; }
        if (offset + 4 > dns_len) { dns_finish_pending(pending, false, NULL); return; }
        offset += 4; /* QTYPE/QCLASS */
        /* Skip any extra questions if present */
        for (uint16_t qi = 1; qi < qdcount; ++qi)
        {
            if (!dns_decode_name(dns, dns_len, &offset, qname, sizeof(pending->scratch_qname))) { dns_finish_pending(pending, false, NULL); return; }
            if (offset + 4 > dns_len) { dns_finish_pending(pending, false, NULL); return; }
            offset += 4;
        }
    }

    /* Answers start here */
    size_t answers_start = offset;

    /* Compute section boundaries (without parsing) */
    size_t after_answers = answers_start;
    if (!dns_skip_rrs(dns, dns_len, &after_answers, ancount,
                      pending->scratch_rr, sizeof(pending->scratch_rr))) { dns_finish_pending(pending, false, NULL); return; }
    size_t after_authority = after_answers;
    if (!dns_skip_rrs(dns, dns_len, &after_authority, nscount,
                      pending->scratch_rr, sizeof(pending->scratch_rr))) { dns_finish_pending(pending, false, NULL); return; }

    /* Follow CNAME chain within this message (order-independent) */
    char *target = pending->scratch_target;
    if (pending->qname_current[0]) {
        size_t copy = strlen(pending->qname_current);
        if (copy > NET_DNS_NAME_MAX) copy = NET_DNS_NAME_MAX;
        memcpy(target, pending->qname_current, copy);
        target[copy] = '\0';
    } else {
        size_t copy = strlen(qname);
        if (copy > NET_DNS_NAME_MAX) copy = NET_DNS_NAME_MAX;
        memcpy(target, qname, copy);
        target[copy] = '\0';
    }

    for (int hop = 0; hop < NET_DNS_MAX_CNAME_HOPS; ++hop)
    {
        bool changed = false;
        size_t o = answers_start;
        for (uint16_t i = 0; i < ancount; ++i)
        {
            char *rr_name = pending->scratch_rr;
            if (!dns_decode_name(dns, dns_len, &o, rr_name, sizeof(pending->scratch_rr))) { dns_finish_pending(pending, false, NULL); return; }
            if (o + 10 > dns_len) { dns_finish_pending(pending, false, NULL); return; }
            uint16_t type   = read_be16(dns + o + 0);
            uint16_t rr_cls = read_be16(dns + o + 2);
            uint16_t rdlen  = read_be16(dns + o + 8);
            o += 10;
            if (o + rdlen > dns_len) { dns_finish_pending(pending, false, NULL); return; }

            if (rr_cls == 1 && type == NET_DNS_TYPE_CNAME)
            {
                size_t ro = o;
                char *cname_tgt = pending->scratch_tmp;
                if (dns_decode_name(dns, dns_len, &ro, cname_tgt, sizeof(pending->scratch_tmp)))
                {
                    if (dns_name_equal(rr_name, target) && !dns_name_equal(cname_tgt, target))
                    {
                        size_t cname_len = strlen(cname_tgt);
                        if (cname_len > NET_DNS_NAME_MAX) cname_len = NET_DNS_NAME_MAX;
                        memcpy(target, cname_tgt, cname_len);
                        target[cname_len] = '\0';
                        changed = true;
                    }
                }
            }
            o += rdlen;
        }
        if (!changed) break;
    }

    /* Look for A(target) in Answer section */
    bool found_a = false;
    uint32_t found_addrs[NET_DNS_MAX_ADDRS];
    size_t found_addr_count = 0;
    uint32_t found_ttl = 0;
    {
        size_t o = answers_start;
        for (uint16_t i = 0; i < ancount; ++i)
        {
            char *rr_name = pending->scratch_rr;
            if (!dns_decode_name(dns, dns_len, &o, rr_name, sizeof(pending->scratch_rr))) { dns_finish_pending(pending, false, NULL); return; }
            if (o + 10 > dns_len) { dns_finish_pending(pending, false, NULL); return; }
            uint16_t type   = read_be16(dns + o + 0);
            uint16_t rr_cls = read_be16(dns + o + 2);
            uint32_t ttl    = read_be32(dns + o + 4);
            uint16_t rdlen  = read_be16(dns + o + 8);
            o += 10;
            if (o + rdlen > dns_len) { dns_finish_pending(pending, false, NULL); return; }

            if (rr_cls == 1 && type == NET_DNS_TYPE_A && rdlen == 4 && dns_name_equal(rr_name, target))
            {
                found_a = true;
                uint32_t addr = ((uint32_t)dns[o] << 24) | ((uint32_t)dns[o+1] << 16) |
                                ((uint32_t)dns[o+2] << 8)  |  (uint32_t)dns[o+3];
                (void)dns_add_unique_addr(found_addrs, &found_addr_count, addr);
                if (found_ttl == 0 || (ttl != 0 && ttl < found_ttl))
                {
                    found_ttl = ttl;
                }
            }
            o += rdlen;
        }
    }

    /* If not found, search Additional (ignore OPT/EDNS = type 41) */
    if (!found_a)
    {
        size_t o = after_authority;
        for (uint16_t i = 0; i < arcount; ++i)
        {
            char *rr_name = pending->scratch_rr;
            if (!dns_decode_name(dns, dns_len, &o, rr_name, sizeof(pending->scratch_rr))) { dns_finish_pending(pending, false, NULL); return; }
            if (o + 10 > dns_len) { dns_finish_pending(pending, false, NULL); return; }
            uint16_t type   = read_be16(dns + o + 0);
            uint16_t rr_cls = read_be16(dns + o + 2);
            uint32_t ttl    = read_be32(dns + o + 4);
            uint16_t rdlen  = read_be16(dns + o + 8);
            o += 10;
            if (o + rdlen > dns_len) { dns_finish_pending(pending, false, NULL); return; }

            if (type != 41) /* DNS_TYPE_OPT */
            {
                if (rr_cls == 1 && type == NET_DNS_TYPE_A && rdlen == 4 && dns_name_equal(rr_name, target))
                {
                    found_a = true;
                    uint32_t addr = ((uint32_t)dns[o] << 24) | ((uint32_t)dns[o+1] << 16) |
                                    ((uint32_t)dns[o+2] << 8)  |  (uint32_t)dns[o+3];
                    (void)dns_add_unique_addr(found_addrs, &found_addr_count, addr);
                    if (found_ttl == 0 || (ttl != 0 && ttl < found_ttl))
                    {
                        found_ttl = ttl;
                    }
                }
            }
            o += rdlen;
        }
    }

    if (found_a && found_addr_count > 0)
    {
        if (pending->qtype == NET_DNS_TYPE_A)
        {
            dns_cache_store_a(pending->hostname,
                              found_addrs,
                              found_addr_count,
                              found_ttl);
            if (target[0] && !dns_name_equal(target, pending->hostname))
            {
                dns_cache_store_a(target,
                                  found_addrs,
                                  found_addr_count,
                                  found_ttl);
            }
        }
        net_dns_result_t res;
        memset(&res, 0, sizeof(res));
        res.has_a  = true;
        res.addr_count = found_addr_count;
        memcpy(res.addrs,
               found_addrs,
               found_addr_count * sizeof(found_addrs[0]));
        res.addr   = found_addrs[0];
        res.rr_type = NET_DNS_TYPE_A;
        dns_finish_pending(pending, true, &res);
        return;
    }

    /* No A yet. If target != current qname, follow CNAME by issuing a new query (bounded). */
    if (!dns_name_equal(target, pending->qname_current) &&
        pending->qtype == NET_DNS_TYPE_A &&
        pending->cname_hops < NET_DNS_MAX_CNAME_HOPS)
    {
        size_t tlen = strlen(target);
        if (tlen > NET_DNS_NAME_MAX) { dns_finish_pending(pending, false, NULL); return; }
        memcpy(pending->qname_current, target, tlen + 1);
        pending->cname_hops++;
        pending->id = dns_allocate_id();
        pending->retries = 0;
        pending->sent_tick = 0;

        if (dns_prepare_route(pending) && dns_send_query(pending))
        {
            /* wait for follow-up response */
            return;
        }
    }

    dns_finish_pending(pending, false, NULL);
}



static bool dns_encode_label(const char **cursor, uint8_t *buffer, size_t *offset, size_t capacity)
{
    const char *start = *cursor;
    size_t len = 0;
    while (start[len] && start[len] != '.')
    {
        ++len;
    }
    if (len > 63)
    {
        return false;
    }
    if (*offset + len + 1 >= capacity)
    {
        return false;
    }
    buffer[(*offset)++] = (uint8_t)len;
    memcpy(buffer + *offset, start, len);
    *offset += len;
    *cursor = start + len;
    if (**cursor == '.')
    {
        ++(*cursor);
    }
    return true;
}

static bool dns_encode_question(const char *hostname, uint16_t qtype,
                                uint8_t *buffer, size_t *len_in_out)
{
    size_t capacity = *len_in_out;
    size_t offset = 0;
    const char *cursor = hostname;
    if (*cursor == '\0')
    {
        return false;
    }
    while (*cursor)
    {
        if (!dns_encode_label(&cursor, buffer, &offset, capacity))
        {
            return false;
        }
    }
    if (offset + 5 > capacity)
    {
        return false;
    }
    buffer[offset++] = 0;
    write_be16(buffer + offset, qtype);
    offset += 2;
    write_be16(buffer + offset, 1);
    offset += 2;
    *len_in_out = offset;
    return true;
}

static bool dns_decode_name(const uint8_t *packet, size_t packet_len,
                            size_t *offset, char *out_name, size_t capacity)
{
    size_t pos = *offset;
    size_t out_len = 0;
    bool jumped = false;
    size_t safety = packet_len;

    if (capacity == 0)
    {
        return false;
    }

    while (safety-- > 0)
    {
        if (pos >= packet_len)
        {
            return false;
        }
        uint8_t len = packet[pos];
        if (len == 0)
        {
            pos++;
            if (!jumped)
            {
                *offset = pos;
            }
            if (out_len >= capacity)
            {
                return false;
            }
            out_name[out_len] = '\0';
            return true;
        }
        if ((len & 0xC0) == 0xC0)
        {
            if (pos + 1 >= packet_len)
            {
                return false;
            }
            uint16_t pointer = ((len & 0x3F) << 8) | packet[pos + 1];
            if (pointer >= packet_len)
            {
                return false;
            }
            if (!jumped)
            {
                *offset = pos + 2;
            }
            pos = pointer;
            jumped = true;
            continue;
        }
        if (len > 63)
        {
            return false;
        }
        pos++;
        if (pos + len > packet_len)
        {
            return false;
        }
        if (out_len != 0)
        {
            if (out_len + 1 >= capacity)
            {
                return false;
            }
            out_name[out_len++] = '.';
        }
        if (out_len + len >= capacity)
        {
            return false;
        }
        memcpy(out_name + out_len, packet + pos, len);
        out_len += len;
        pos += len;
        if (!jumped)
        {
            *offset = pos;
        }
    }
    return false;
}

static void write_be32(uint8_t *p, uint32_t value)
{
    if (p)
    {
        DNS_TRACE("dns_write_be32", p, sizeof(uint32_t));
    }
    p[0] = (uint8_t)((value >> 24) & 0xFF);
    p[1] = (uint8_t)((value >> 16) & 0xFF);
    p[2] = (uint8_t)((value >> 8) & 0xFF);
    p[3] = (uint8_t)(value & 0xFF);
}

static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | ((uint32_t)p[3]);
}

static void write_be16(uint8_t *p, uint16_t value)
{
    if (p)
    {
        DNS_TRACE("dns_write_be16", p, sizeof(uint16_t));
    }
    p[0] = (uint8_t)((value >> 8) & 0xFF);
    p[1] = (uint8_t)(value & 0xFF);
}

static void dns_log(const char *msg)
{
    serial_printf("%s", "dns: ");
    serial_printf("%s", msg);
    serial_printf("%s", "\r\n");
}

static void dns_debug_log(const char *msg)
{
    if (!g_dns_debug_enabled || !msg)
    {
        return;
    }
    serial_printf("%s", "[dns-debug] ");
    serial_printf("%s", msg);
    serial_printf("%s", "\r\n");
}

static void dns_log_ipv4(const char *prefix, uint32_t addr)
{
    char buf[64];
    char ip[32];
    net_format_ipv4(addr, ip);

    const size_t capacity = sizeof(buf);
    size_t len = 0;

    if (prefix)
    {
        for (size_t i = 0; prefix[i] && len < capacity - 1; ++i)
        {
            buf[len++] = prefix[i];
        }
    }

    const char sep[] = " = ";
    const size_t sep_len = sizeof(sep) - 1;
    if (len + sep_len < capacity)
    {
        memcpy(buf + len, sep, sep_len);
        len += sep_len;
    }

    size_t remaining = (len < capacity) ? (capacity - len - 1) : 0;
    if (remaining > 0)
    {
        size_t ip_len = strlen(ip);
        if (ip_len > remaining)
        {
            ip_len = remaining;
        }
        memcpy(buf + len, ip, ip_len);
        len += ip_len;
    }

    if (len >= capacity)
    {
        len = capacity - 1;
    }
    buf[len] = '\0';
    dns_log(buf);
}

static void dns_debug_ipv4(const char *prefix, uint32_t addr)
{
    if (!g_dns_debug_enabled)
    {
        return;
    }
    char buf[64];
    char ip[32];
    net_format_ipv4(addr, ip);

    const size_t capacity = sizeof(buf);
    size_t len = 0;

    if (prefix)
    {
        for (size_t i = 0; prefix[i] && len < capacity - 1; ++i)
        {
            buf[len++] = prefix[i];
        }
    }

    const char sep[] = " = ";
    const size_t sep_len = sizeof(sep) - 1;
    if (len + sep_len < capacity)
    {
        memcpy(buf + len, sep, sep_len);
        len += sep_len;
    }

    size_t remaining = (len < capacity) ? (capacity - len - 1) : 0;
    if (remaining > 0)
    {
        size_t ip_len = strlen(ip);
        if (ip_len > remaining)
        {
            ip_len = remaining;
        }
        memcpy(buf + len, ip, ip_len);
        len += ip_len;
    }

    if (len >= capacity)
    {
        len = capacity - 1;
    }
    buf[len] = '\0';
    dns_debug_log(buf);
}

static uint16_t checksum16(const uint8_t *data, size_t len)
{
    uint32_t sum = 0;
    const uint8_t *ptr = data;
    while (len > 1)
    {
        sum += (uint32_t)((ptr[0] << 8) | ptr[1]);
        ptr += 2;
        len -= 2;
    }
    if (len)
    {
        sum += (uint32_t)(ptr[0] << 8);
    }
    while (sum >> 16)
    {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

static uint16_t dns_allocate_port(void)
{
    uint64_t flags = dns_lock();
    uint16_t result = 0;
    for (size_t attempt = 0; attempt < 0x8000; ++attempt)
    {
        if (g_next_port < 0xC000)
        {
            g_next_port = 0xC000;
        }
        uint16_t candidate = g_next_port++;
        if (g_next_port >= 0xFFF0)
        {
            g_next_port = 0xC000;
        }
        bool in_use = false;
        for (size_t i = 0; i < NET_DNS_MAX_PENDING; ++i)
        {
            if (g_pending[i].active && g_pending[i].local_port == candidate)
            {
                in_use = true;
                break;
            }
        }
        if (!in_use)
        {
            result = candidate;
            break;
        }
    }
    dns_unlock(flags);
    return result;
}

static uint16_t dns_allocate_id(void)
{
    uint64_t flags = dns_lock();
    uint16_t id = g_next_id++;
    if (g_next_id == 0)
    {
        g_next_id = 0x1234;
    }
    dns_unlock(flags);
    return id;
}
