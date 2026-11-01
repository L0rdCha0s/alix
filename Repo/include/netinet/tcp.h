#ifndef ALIX_NETINET_TCP_H
#define ALIX_NETINET_TCP_H
#ifdef TTF_HOST_BUILD
#include_next <netinet/tcp.h>
#else
#include "netinet/in.h"
#define TCP_NODELAY SYSCALL_TCP_NODELAY
#define TCP_MAXSEG SYSCALL_TCP_MAXSEG
#define TCP_CORK 3
#define TCP_KEEPIDLE 4
#define TCP_KEEPINTVL 5
#define TCP_KEEPCNT 6
#endif
#endif
