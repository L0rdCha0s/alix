#include "netdb.h"
#include "netdb_internal.h"
#include "arpa/inet.h"
#include "stdlib.h"
#include "string.h"
#include "stdio.h"
#include "errno.h"
#include "usyscall.h"

static __thread int resolver_error;
int *__h_errno_location(void) { return &resolver_error; }

typedef struct { const char *name, *protocol; uint16_t port; } service_record_t;
static const service_record_t services[] = {
    {"http","tcp",80},{"https","tcp",443},{"ssh","tcp",22},{"ftp","tcp",21},
    {"smtp","tcp",25},{"imap","tcp",143},{"imaps","tcp",993},
    {"pop3","tcp",110},{"pop3s","tcp",995},{"ldap","tcp",389},{"ldaps","tcp",636},
    {"domain","tcp",53},{"domain","udp",53},{"ntp","udp",123}
};
typedef struct { const char *name; int number; } protocol_record_t;
static const protocol_record_t protocols[] = {
    {"ip",0},{"icmp",1},{"tcp",6},{"udp",17},{"ipv6",41},{"ipv6-icmp",58},{"raw",255}
};
static const service_record_t *service_find(const char *name, int port, const char *protocol)
{
    for (size_t index = 0; index < sizeof(services)/sizeof(*services); ++index)
    {
        const service_record_t *record = &services[index];
        if (protocol && strcmp(protocol, record->protocol)) continue;
        if (name ? !strcmp(name, record->name) : (uint16_t)port == htons(record->port)) return record;
    }
    return NULL;
}
static int service_port(const char *service, int flags, uint16_t *port)
{
    *port = 0;
    if (!service) return 0;
    if (!*service) return EAI_SERVICE;
    unsigned value = 0;
    const char *cursor = service;
    while (*cursor >= '0' && *cursor <= '9')
    {
        value = value * 10u + (unsigned)(*cursor++ - '0');
        if (value > 65535u) return EAI_SERVICE;
    }
    if (!*cursor) { *port = (uint16_t)value; return 0; }
    if (flags & AI_NUMERICSERV) return EAI_NONAME;
    const service_record_t *record = service_find(service, 0, "tcp");
    if (!record) return EAI_SERVICE;
    *port = record->port;
    return 0;
}
static int configured_ipv4(void)
{
    syscall_net_stats_t *interfaces = calloc(8, sizeof(*interfaces));
    if (!interfaces) { errno = ENOMEM; return -1; }
    ssize_t count = sys_net_snapshot(interfaces, 8);
    if (count < 0) { free(interfaces); errno = (int)-count; return -1; }
    if (count > 8) { free(interfaces); errno = EIO; return -1; }
    int found = 0;
    for (ssize_t index = 0; index < count; ++index)
        if (interfaces[index].present && interfaces[index].ipv4_addr && (interfaces[index].ipv4_addr >> 24) != 127) found = 1;
    free(interfaces);
    return found;
}
void freeaddrinfo(struct addrinfo *result)
{
    while (result) { struct addrinfo *next = result->ai_next; free(result); result = next; }
}
typedef struct { struct addrinfo info; struct sockaddr_in address; char canonical[]; } address_node_t;
int __alix_getaddrinfo_at(const char *node, const char *service, const struct addrinfo *hints,
                          uint32_t server_ip, uint16_t server_port, struct addrinfo **result)
{
    if (!result) { errno = EINVAL; return EAI_SYSTEM; }
    *result = NULL;
    if (!node && !service) return EAI_NONAME;
    int flags = hints ? hints->ai_flags : 0;
    const int known = AI_PASSIVE | AI_CANONNAME | AI_NUMERICHOST | AI_V4MAPPED | AI_ALL | AI_ADDRCONFIG | AI_NUMERICSERV;
    if ((flags & ~known) || (!node && (flags & AI_CANONNAME))) return EAI_BADFLAGS;
    int family = hints ? hints->ai_family : AF_UNSPEC;
    if (family != AF_UNSPEC && family != AF_INET) return EAI_FAMILY;
    if (hints && hints->ai_socktype && hints->ai_socktype != SOCK_STREAM) return EAI_SOCKTYPE;
    if (hints && hints->ai_protocol && hints->ai_protocol != IPPROTO_TCP) return EAI_SOCKTYPE;
    if (flags & AI_ADDRCONFIG)
    {
        int configured = configured_ipv4();
        if (configured < 0) return errno == ENOMEM ? EAI_MEMORY : EAI_SYSTEM;
        if (!configured) return EAI_NONAME;
    }
    uint16_t port;
    int error = service_port(service, flags, &port);
    if (error) return error;
    syscall_dns_reply_t *reply = calloc(1, sizeof(*reply));
    if (!reply) return EAI_MEMORY;
    const char *canonical = node;
    uint32_t network_address;
    if (!node || (!(flags & AI_NUMERICHOST) && (!strcasecmp(node, "localhost") || !strcasecmp(node, "localhost."))))
    {
        reply->address_count = 1;
        reply->addresses[0] = !node && (flags & AI_PASSIVE) ? INADDR_ANY : INADDR_LOOPBACK;
        canonical = "localhost";
    }
    else if (!*node || strnlen(node, SYSCALL_DNS_NAME_MAX + 1u) > SYSCALL_DNS_NAME_MAX) error = EAI_NONAME;
    else if (inet_pton(AF_INET, node, &network_address) == 1)
    {
        reply->address_count = 1; reply->addresses[0] = ntohl(network_address);
    }
    else if (flags & AI_NUMERICHOST) error = EAI_NONAME;
    else if (__alix_dns_query4(node, server_ip, server_port, reply)) error = errno == ENOMEM ? EAI_MEMORY : EAI_SYSTEM;
    else if (reply->status != SYSCALL_DNS_OK || !reply->address_count)
        error = reply->status == SYSCALL_DNS_AGAIN ? EAI_AGAIN :
                reply->status == SYSCALL_DNS_FAILURE ? EAI_FAIL : EAI_NONAME;
    else canonical = reply->canonical[0] ? reply->canonical : node;
    struct addrinfo **tail = result;
    for (uint32_t index = 0; !error && index < reply->address_count; ++index)
    {
        size_t length = index == 0 && (flags & AI_CANONNAME) ? strlen(canonical) + 1 : 0;
        address_node_t *address = calloc(1, sizeof(*address) + length);
        if (!address) { error = EAI_MEMORY; break; }
        address->address.sin_family = AF_INET;
        address->address.sin_port = htons(port);
        address->address.sin_addr.s_addr = htonl(reply->addresses[index]);
        address->info = (struct addrinfo){ .ai_flags = flags, .ai_family = AF_INET, .ai_socktype = SOCK_STREAM,
            .ai_protocol = IPPROTO_TCP, .ai_addrlen = sizeof(address->address), .ai_addr = (struct sockaddr *)&address->address };
        if (length) { memcpy(address->canonical, canonical, length); address->info.ai_canonname = address->canonical; }
        *tail = &address->info; tail = &address->info.ai_next;
    }
    free(reply);
    if (error) { freeaddrinfo(*result); *result = NULL; }
    return error;
}
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **result)
{
    return __alix_getaddrinfo_at(node, service, hints, 0, 0, result);
}
const char *gai_strerror(int error)
{
    switch (error)
    {
        case 0: return "Success";
        case EAI_BADFLAGS: return "Invalid address lookup flags";
        case EAI_NONAME: return "Name or service not known";
        case EAI_AGAIN: return "Temporary name lookup failure";
        case EAI_FAIL: return "Permanent name lookup failure";
        case EAI_NODATA: return "Name has no address data";
        case EAI_FAMILY: return "Address family not supported";
        case EAI_SOCKTYPE: return "Socket type or protocol not supported";
        case EAI_SERVICE: return "Service not supported";
        case EAI_MEMORY: return "Out of memory";
        case EAI_SYSTEM: return "System error";
        case EAI_OVERFLOW: return "Address output buffer too small";
        default: return "Unknown address lookup error";
    }
}
int getnameinfo(const struct sockaddr *address, socklen_t length, char *host, socklen_t host_capacity,
                char *service, socklen_t service_capacity, int flags)
{
    if (flags & ~(NI_NUMERICHOST | NI_NUMERICSERV | NI_NOFQDN | NI_NAMEREQD | NI_DGRAM)) return EAI_BADFLAGS;
    if (!address || length < sizeof(struct sockaddr_in) || address->sa_family != AF_INET) return EAI_FAMILY;
    if (!host && !service) return EAI_NONAME;
    const struct sockaddr_in *endpoint = (const struct sockaddr_in *)address;
    char numeric[INET_ADDRSTRLEN], number[6];
    const char *hostname = numeric;
    if (!(flags & NI_NUMERICHOST) && ntohl(endpoint->sin_addr.s_addr) == INADDR_LOOPBACK) hostname = "localhost";
    else
    {
        if (host && (flags & NI_NAMEREQD) && !(flags & NI_NUMERICHOST)) return EAI_NONAME;
        if (!inet_ntop(AF_INET, &endpoint->sin_addr, numeric, sizeof(numeric))) return EAI_SYSTEM;
    }
    const service_record_t *record = !(flags & NI_NUMERICSERV) ?
        service_find(NULL, endpoint->sin_port, flags & NI_DGRAM ? "udp" : "tcp") : NULL;
    snprintf(number, sizeof(number), "%u", (unsigned)ntohs(endpoint->sin_port));
    const char *service_name = record ? record->name : number;
    if ((host && strlen(hostname) >= host_capacity) || (service && strlen(service_name) >= service_capacity)) return EAI_OVERFLOW;
    if (host) memcpy(host, hostname, strlen(hostname) + 1);
    if (service) memcpy(service, service_name, strlen(service_name) + 1);
    return 0;
}

static int host_pack(const char *canonical, const struct addrinfo *addresses,
                      struct hostent *entry, char *buffer, size_t capacity)
{
    size_t count = 0;
    for (const struct addrinfo *item = addresses; item; item = item->ai_next) ++count;
    if (!count || count > SYSCALL_DNS_ADDR_MAX) return EIO;
    uintptr_t base = (uintptr_t)buffer;
    uintptr_t aligned = (base + sizeof(void *) - 1u) & ~(uintptr_t)(sizeof(void *) - 1u);
    if (aligned < base) return ERANGE;
    size_t prefix = aligned - base;
    size_t name_length = strlen(canonical) + 1;
    size_t needed = (count + 2) * sizeof(char *) + count * 4 + name_length;
    if (prefix > capacity || needed > capacity - prefix) return ERANGE;
    char **aliases = (char **)aligned;
    char **list = aliases + 1;
    char *bytes = (char *)(list + count + 1);
    char *name = bytes + count * 4;
    aliases[0] = NULL;
    size_t index = 0;
    for (const struct addrinfo *item = addresses; item; item = item->ai_next, ++index)
    {
        const struct sockaddr_in *endpoint = (const struct sockaddr_in *)item->ai_addr;
        list[index] = bytes + index * 4;
        memcpy(list[index], &endpoint->sin_addr, 4);
    }
    list[count] = NULL;
    memcpy(name, canonical, name_length);
    *entry = (struct hostent){ .h_name = name, .h_aliases = aliases, .h_addrtype = AF_INET,
                               .h_length = 4, .h_addr_list = list };
    return 0;
}
int gethostbyname2_r(const char *name, int family, struct hostent *entry, char *buffer, size_t capacity,
                     struct hostent **result, int *error)
{
    if (result) *result = NULL;
    if (error) *error = NO_RECOVERY;
    if (!result || !error || !entry || !buffer || !name) return EINVAL;
    *error = NO_RECOVERY;
    if (family != AF_INET) return EAFNOSUPPORT;
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM, .ai_flags = AI_CANONNAME };
    struct addrinfo *addresses = NULL;
    int status = getaddrinfo(name, NULL, &hints, &addresses);
    if (status)
    {
        *error = status == EAI_AGAIN ? TRY_AGAIN : status == EAI_NONAME ? HOST_NOT_FOUND : NO_RECOVERY;
        if (status == EAI_MEMORY || status == EAI_SYSTEM) { *error = NETDB_INTERNAL; return status == EAI_MEMORY ? ENOMEM : errno; }
        return 0;
    }
    int packed = host_pack(addresses->ai_canonname ? addresses->ai_canonname : name, addresses, entry, buffer, capacity);
    freeaddrinfo(addresses);
    if (packed) { *error = NETDB_INTERNAL; return packed; }
    *error = NETDB_SUCCESS; *result = entry;
    return 0;
}
int gethostbyname_r(const char *name, struct hostent *entry, char *buffer, size_t capacity,
                    struct hostent **result, int *error)
{
    return gethostbyname2_r(name, AF_INET, entry, buffer, capacity, result, error);
}
int gethostbyaddr_r(const void *address, socklen_t length, int family, struct hostent *entry, char *buffer,
                    size_t capacity, struct hostent **result, int *error)
{
    if (result) *result = NULL;
    if (error) *error = NO_RECOVERY;
    if (!result || !error || !entry || !buffer || !address) return EINVAL;
    if (family != AF_INET) { *error = NO_RECOVERY; return EAFNOSUPPORT; }
    if (length != 4) return EINVAL;
    uint32_t value; memcpy(&value, address, 4);
    if (ntohl(value) != INADDR_LOOPBACK) { *error = HOST_NOT_FOUND; return 0; }
    return gethostbyname_r("localhost", entry, buffer, capacity, result, error);
}
static __thread struct hostent host_entry;
static __thread char host_buffer[512] __attribute__((aligned(sizeof(void *))));
struct hostent *gethostbyname2(const char *name, int family)
{
    struct hostent *result = NULL;
    int status = gethostbyname2_r(name, family, &host_entry, host_buffer, sizeof(host_buffer), &result, &resolver_error);
    if (status) errno = status;
    return result;
}
struct hostent *gethostbyname(const char *name) { return gethostbyname2(name, AF_INET); }
struct hostent *gethostbyaddr(const void *address, socklen_t length, int family)
{
    struct hostent *result = NULL;
    int status = gethostbyaddr_r(address, length, family, &host_entry, host_buffer, sizeof(host_buffer), &result, &resolver_error);
    if (status) errno = status;
    return result;
}

static const protocol_record_t *protocol_find(const char *name, int number)
{
    for (size_t index = 0; index < sizeof(protocols)/sizeof(*protocols); ++index)
        if (name ? !strcmp(name, protocols[index].name) : number == protocols[index].number) return &protocols[index];
    return NULL;
}
static int protocol_pack(const protocol_record_t *record, struct protoent *entry, char *buffer, size_t capacity)
{
    uintptr_t base = (uintptr_t)buffer, aligned = (base + sizeof(void *) - 1u) & ~(uintptr_t)(sizeof(void *) - 1u);
    size_t bytes = sizeof(char *) + strlen(record->name) + 1;
    if (aligned < base || aligned - base > capacity || bytes > capacity - (aligned - base)) return ERANGE;
    char **aliases = (char **)aligned; aliases[0] = NULL;
    char *name = (char *)(aliases + 1); memcpy(name, record->name, strlen(record->name) + 1);
    *entry = (struct protoent){ .p_name = name, .p_aliases = aliases, .p_proto = record->number };
    return 0;
}
static int protocol_lookup(const char *name, int number, struct protoent *entry, char *buffer, size_t capacity, struct protoent **result)
{
    if (result) *result = NULL;
    if (!entry || !buffer || !result) return EINVAL;
    const protocol_record_t *record = protocol_find(name, number);
    if (!record) return ENOENT;
    int status = protocol_pack(record, entry, buffer, capacity);
    if (!status) *result = entry;
    return status;
}
int getprotobyname_r(const char *name, struct protoent *entry, char *buffer, size_t capacity, struct protoent **result)
{
    if (!name) { if (result) *result = NULL; return EINVAL; }
    return protocol_lookup(name, 0, entry, buffer, capacity, result);
}
int getprotobynumber_r(int number, struct protoent *entry, char *buffer, size_t capacity, struct protoent **result)
{
    return protocol_lookup(NULL, number, entry, buffer, capacity, result);
}
static __thread struct protoent protocol_entry;
static __thread char protocol_buffer[64] __attribute__((aligned(sizeof(void *))));
struct protoent *getprotobyname(const char *name)
{
    struct protoent *result = NULL;
    int status = getprotobyname_r(name, &protocol_entry, protocol_buffer, sizeof(protocol_buffer), &result);
    if (status) errno = status;
    return result;
}
struct protoent *getprotobynumber(int number)
{
    struct protoent *result = NULL;
    int status = getprotobynumber_r(number, &protocol_entry, protocol_buffer, sizeof(protocol_buffer), &result);
    if (status) errno = status;
    return result;
}
static int service_lookup(const char *name, int port, const char *protocol, struct servent *entry,
                           char *buffer, size_t capacity, struct servent **result)
{
    if (result) *result = NULL;
    if (!entry || !buffer || !result) return EINVAL;
    const service_record_t *record = service_find(name, port, protocol);
    if (!record) return ENOENT;
    uintptr_t base = (uintptr_t)buffer, aligned = (base + sizeof(void *) - 1u) & ~(uintptr_t)(sizeof(void *) - 1u);
    size_t name_bytes = strlen(record->name) + 1, protocol_bytes = strlen(record->protocol) + 1;
    size_t needed = sizeof(char *) + name_bytes + protocol_bytes;
    if (aligned < base || aligned - base > capacity || needed > capacity - (aligned - base)) return ERANGE;
    char **aliases = (char **)aligned; aliases[0] = NULL;
    char *stored_name = (char *)(aliases + 1), *stored_protocol = stored_name + name_bytes;
    memcpy(stored_name, record->name, name_bytes); memcpy(stored_protocol, record->protocol, protocol_bytes);
    *entry = (struct servent){ .s_name = stored_name, .s_aliases = aliases, .s_port = htons(record->port), .s_proto = stored_protocol };
    *result = entry; return 0;
}
int getservbyname_r(const char *name, const char *protocol, struct servent *entry, char *buffer, size_t capacity, struct servent **result)
{
    if (!name) { if (result) *result = NULL; return EINVAL; }
    return service_lookup(name, 0, protocol, entry, buffer, capacity, result);
}
int getservbyport_r(int port, const char *protocol, struct servent *entry, char *buffer, size_t capacity, struct servent **result)
{
    return service_lookup(NULL, port, protocol, entry, buffer, capacity, result);
}
static __thread struct servent service_entry;
static __thread char service_buffer[128] __attribute__((aligned(sizeof(void *))));
struct servent *getservbyname(const char *name, const char *protocol)
{
    struct servent *result = NULL;
    int status = getservbyname_r(name, protocol, &service_entry, service_buffer, sizeof(service_buffer), &result);
    if (status) errno = status;
    return result;
}
struct servent *getservbyport(int port, const char *protocol)
{
    struct servent *result = NULL;
    int status = getservbyport_r(port, protocol, &service_entry, service_buffer, sizeof(service_buffer), &result);
    if (status) errno = status;
    return result;
}
void endhostent(void) { memset(&host_entry, 0, sizeof(host_entry)); memset(host_buffer, 0, sizeof(host_buffer)); }
void sethostent(int stay_open) { (void)stay_open; endhostent(); }
void endprotoent(void) { memset(&protocol_entry, 0, sizeof(protocol_entry)); memset(protocol_buffer, 0, sizeof(protocol_buffer)); }
void setprotoent(int stay_open) { (void)stay_open; endprotoent(); }
void endservent(void) { memset(&service_entry, 0, sizeof(service_entry)); memset(service_buffer, 0, sizeof(service_buffer)); }
void setservent(int stay_open) { (void)stay_open; endservent(); }
