#ifndef ALIX_NETDB_INTERNAL_H
#define ALIX_NETDB_INTERNAL_H
#include "netdb.h"
#include "syscall_defs.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Native resolver dependency boundary. Zero server/port uses DHCP/defaults;
 * a per-call endpoint enables explicit resolvers without global mutation. */
int __alix_dns_query4(const char *name, uint32_t server_ip, uint16_t server_port, syscall_dns_reply_t *reply);
int __alix_getaddrinfo_at(const char *node, const char *service, const struct addrinfo *hints,
                          uint32_t server_ip, uint16_t server_port, struct addrinfo **result);
#ifdef __cplusplus
}
#endif
#endif
