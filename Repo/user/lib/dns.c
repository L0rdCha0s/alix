#include "netdb_internal.h"
#include "usyscall.h"
#include "errno.h"
int __alix_dns_query4(const char *name, uint32_t server_ip, uint16_t server_port, syscall_dns_reply_t *reply)
{
    uint64_t endpoint = ((uint64_t)server_ip << 32) | server_port;
    int64_t result = sys_file_io(SYSCALL_FILE_DNS_RESOLVE, (uintptr_t)name, (uintptr_t)reply, sizeof(*reply), endpoint);
    if (result < 0) { errno = (int)-result; return -1; }
    if (reply->version != SYSCALL_DNS_VERSION || reply->size != sizeof(*reply) || reply->reserved ||
        reply->status > SYSCALL_DNS_FAILURE || reply->address_count > SYSCALL_DNS_ADDR_MAX ||
        reply->canonical_length > SYSCALL_DNS_NAME_MAX || reply->canonical[reply->canonical_length])
    { errno = EIO; return -1; }
    return 0;
}
