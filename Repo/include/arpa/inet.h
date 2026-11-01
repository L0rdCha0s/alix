#ifndef ALIX_ARPA_INET_H
#define ALIX_ARPA_INET_H
#ifdef TTF_HOST_BUILD
#include_next <arpa/inet.h>
#else
#include "netinet/in.h"
#ifdef __cplusplus
extern "C" {
#endif
int inet_pton(int family, const char *text, void *address);
const char *inet_ntop(int family, const void *address, char *text, socklen_t capacity);
#ifdef __cplusplus
}
#endif
#endif
#endif
