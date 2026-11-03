#ifndef ALIX_NETINET_IN_H
#define ALIX_NETINET_IN_H
#ifdef TTF_HOST_BUILD
#include_next <netinet/in.h>
#else
#include "sys/socket.h"
typedef uint16_t in_port_t;
typedef uint32_t in_addr_t;
struct in_addr { in_addr_t s_addr; };
/* Request layout only; native multicast membership is not implemented. */
struct ip_mreq { struct in_addr imr_multiaddr, imr_interface; };
struct in6_addr { union { uint8_t bytes[16]; uint16_t words[8]; uint32_t dwords[4]; } __data; };
struct ipv6_mreq { struct in6_addr ipv6mr_multiaddr; uint32_t ipv6mr_interface; };
struct ip_mreqn { struct in_addr imr_multiaddr, imr_address; int imr_ifindex; };
struct ip_mreq_source { struct in_addr imr_multiaddr, imr_interface, imr_sourceaddr; };
#define s6_addr __data.bytes
#define s6_addr16 __data.words
#define s6_addr32 __data.dwords
struct sockaddr_in { sa_family_t sin_family; in_port_t sin_port; struct in_addr sin_addr; uint8_t sin_zero[8]; };
struct sockaddr_in6 { sa_family_t sin6_family; in_port_t sin6_port; uint32_t sin6_flowinfo; struct in6_addr sin6_addr; uint32_t sin6_scope_id; };
#define INADDR_ANY UINT32_C(0)
#define INADDR_BROADCAST UINT32_C(0xffffffff)
#define INADDR_NONE UINT32_C(0xffffffff)
#define INADDR_LOOPBACK UINT32_C(0x7f000001)
#define INET_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46
#define IPPROTO_IP 0
#define IPPROTO_ICMP 1
#define IPPROTO_TCP SYSCALL_IPPROTO_TCP
#define IPPROTO_UDP 17
#define IPPROTO_IPV6 41
#define IPPROTO_ICMPV6 58
#define IPPROTO_RAW 255
#define IP_TOS 1
#define IP_TTL 2
#define IP_HDRINCL 3
#define IP_RECVTOS 13
#define IP_MULTICAST_IF 32
#define IP_MULTICAST_TTL 33
#define IP_MULTICAST_LOOP 34
#define IP_ADD_MEMBERSHIP 35
#define IP_DROP_MEMBERSHIP 36
#define IP_ADD_SOURCE_MEMBERSHIP 39
#define IP_DROP_SOURCE_MEMBERSHIP 40
#define IPV6_UNICAST_HOPS 16
#define IPV6_MULTICAST_IF 17
#define IPV6_MULTICAST_HOPS 18
#define IPV6_MULTICAST_LOOP 19
#define IPV6_ADD_MEMBERSHIP 20
#define IPV6_DROP_MEMBERSHIP 21
#define IPV6_RECVHOPLIMIT 51
#define IPV6_RECVTCLASS 66
#define IPV6_V6ONLY 26
#define IN6ADDR_ANY_INIT {{{0}}}
#define IN6ADDR_LOOPBACK_INIT {{{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}}}
#ifdef __cplusplus
extern "C" {
#endif
extern const struct in6_addr in6addr_any;
extern const struct in6_addr in6addr_loopback;
uint16_t htons(uint16_t value);
uint16_t ntohs(uint16_t value);
uint32_t htonl(uint32_t value);
uint32_t ntohl(uint32_t value);
#ifdef __cplusplus
}
#endif
#endif
#endif
