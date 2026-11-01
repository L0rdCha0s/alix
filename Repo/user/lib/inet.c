#include "arpa/inet.h"
#include "endian.h"
#include "errno.h"
#include "stdio.h"
#include "string.h"

const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;
const struct in6_addr in6addr_loopback = IN6ADDR_LOOPBACK_INIT;
uint16_t htons(uint16_t value) { return htobe16(value); }
uint16_t ntohs(uint16_t value) { return be16toh(value); }
uint32_t htonl(uint32_t value) { return htobe32(value); }
uint32_t ntohl(uint32_t value) { return be32toh(value); }

int inet_pton(int family, const char *text, void *address)
{
    if (family != AF_INET) { errno = EAFNOSUPPORT; return -1; }
    if (!text || !address) { errno = EFAULT; return -1; }
    uint32_t result = 0;
    for (unsigned part = 0; part < 4; ++part)
    {
        unsigned value = 0, digits = 0;
        const char *beginning = text;
        while (*text >= '0' && *text <= '9')
        {
            if (++digits > 3) return 0;
            value = value * 10 + (unsigned)(*text++ - '0');
        }
        if (!digits || value > 255 || (digits > 1 && *beginning == '0')) return 0;
        if (part < 3 ? *text++ != '.' : *text != '\0') return 0;
        result = (result << 8) | value;
    }
    result = htonl(result);
    memcpy(address, &result, sizeof(result));
    return 1;
}

const char *inet_ntop(int family, const void *address, char *text, socklen_t capacity)
{
    if (family != AF_INET) { errno = EAFNOSUPPORT; return NULL; }
    if (!address || !text) { errno = EFAULT; return NULL; }
    const unsigned char *bytes = address;
    char formatted[INET_ADDRSTRLEN];
    int length = snprintf(formatted, sizeof(formatted), "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
    if (length < 0 || (unsigned)length >= sizeof(formatted)) { errno = EIO; return NULL; }
    if ((unsigned)length >= capacity) { errno = ENOSPC; return NULL; }
    memcpy(text, formatted, (size_t)length + 1);
    return text;
}
