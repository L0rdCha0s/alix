#ifndef ALIX_NETDB_H
#define ALIX_NETDB_H
#ifdef TTF_HOST_BUILD
#include_next <netdb.h>
#else
#include "sys/socket.h"
#define AI_PASSIVE 1
#define AI_CANONNAME 2
#define AI_NUMERICHOST 4
#define AI_V4MAPPED 8
#define AI_ALL 16
#define AI_ADDRCONFIG 32
#define AI_NUMERICSERV 1024
#define EAI_BADFLAGS -1
#define EAI_NONAME -2
#define EAI_AGAIN -3
#define EAI_FAIL -4
#define EAI_NODATA -5
#define EAI_FAMILY -6
#define EAI_SOCKTYPE -7
#define EAI_SERVICE -8
#define EAI_MEMORY -10
#define EAI_SYSTEM -11
#define EAI_OVERFLOW -12
#define NI_NUMERICHOST 1
#define NI_NUMERICSERV 2
#define NI_NOFQDN 4
#define NI_NAMEREQD 8
#define NI_DGRAM 16
#define NI_MAXHOST 1025
#define NI_MAXSERV 32
#define HOST_NOT_FOUND 1
#define TRY_AGAIN 2
#define NO_RECOVERY 3
#define NO_DATA 4
#define NO_ADDRESS NO_DATA
#define NETDB_INTERNAL -1
#define NETDB_SUCCESS 0
struct addrinfo {
    int ai_flags, ai_family, ai_socktype, ai_protocol;
    socklen_t ai_addrlen;
    struct sockaddr *ai_addr;
    char *ai_canonname;
    struct addrinfo *ai_next;
};
struct hostent { char *h_name; char **h_aliases; int h_addrtype, h_length; char **h_addr_list; };
#define h_addr h_addr_list[0]
struct protoent { char *p_name; char **p_aliases; int p_proto; };
struct servent { char *s_name; char **s_aliases; int s_port; char *s_proto; };
#ifdef __cplusplus
extern "C" {
#endif
int *__h_errno_location(void);
#define h_errno (*__h_errno_location())
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **result);
void freeaddrinfo(struct addrinfo *result);
const char *gai_strerror(int error);
int getnameinfo(const struct sockaddr *address, socklen_t length, char *host, socklen_t host_capacity,
                char *service, socklen_t service_capacity, int flags);
struct hostent *gethostbyname(const char *name);
struct hostent *gethostbyname2(const char *name, int family);
struct hostent *gethostbyaddr(const void *address, socklen_t length, int family);
int gethostbyname_r(const char *name, struct hostent *entry, char *buffer, size_t capacity, struct hostent **result, int *error);
int gethostbyname2_r(const char *name, int family, struct hostent *entry, char *buffer, size_t capacity, struct hostent **result, int *error);
int gethostbyaddr_r(const void *address, socklen_t length, int family, struct hostent *entry, char *buffer, size_t capacity, struct hostent **result, int *error);
struct protoent *getprotobyname(const char *name);
struct protoent *getprotobynumber(int number);
struct servent *getservbyname(const char *name, const char *protocol);
struct servent *getservbyport(int port, const char *protocol);
int getprotobyname_r(const char *name, struct protoent *entry, char *buffer, size_t capacity, struct protoent **result);
int getprotobynumber_r(int number, struct protoent *entry, char *buffer, size_t capacity, struct protoent **result);
int getservbyname_r(const char *name, const char *protocol, struct servent *entry, char *buffer, size_t capacity, struct servent **result);
int getservbyport_r(int port, const char *protocol, struct servent *entry, char *buffer, size_t capacity, struct servent **result);
void sethostent(int stay_open);
void endhostent(void);
void setprotoent(int stay_open);
void endprotoent(void);
void setservent(int stay_open);
void endservent(void);
#ifdef __cplusplus
}
#endif
#endif
#endif
