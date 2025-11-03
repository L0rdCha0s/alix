#ifndef NET_INTERFACE_H
#define NET_INTERFACE_H

#include "types.h"

#define NET_IF_NAME_MAX 8

typedef struct net_interface
{
    char name[NET_IF_NAME_MAX];
    bool present;
    bool link_up;
    uint8_t mac[6];
    uint32_t ipv4_addr;
    uint32_t ipv4_netmask;
    uint32_t ipv4_gateway;
    bool (*send)(struct net_interface *, const uint8_t *, size_t);
} net_interface_t;

void net_if_init(void);
net_interface_t *net_if_register(const char *name, const uint8_t mac[6]);
net_interface_t *net_if_by_name(const char *name);
size_t net_if_count(void);
net_interface_t *net_if_at(size_t index);
void net_if_set_link_up(net_interface_t *iface, bool up);
void net_if_set_ipv4(net_interface_t *iface, uint32_t addr, uint32_t netmask, uint32_t gateway);
void net_if_set_tx_handler(net_interface_t *iface, bool (*handler)(net_interface_t *, const uint8_t *, size_t));
bool net_if_send(net_interface_t *iface, const uint8_t *data, size_t len);

void net_format_mac(const uint8_t mac[6], char *out);
void net_format_ipv4(uint32_t addr, char *out);
bool net_parse_ipv4(const char *text, uint32_t *out_addr);

#endif
