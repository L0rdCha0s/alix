#ifndef ALIX_NET_IF_H
#define ALIX_NET_IF_H

#define IF_NAMESIZE 16
#define IFNAMSIZ IF_NAMESIZE

#ifdef __cplusplus
extern "C" {
#endif
unsigned int if_nametoindex(const char *name);
char *if_indextoname(unsigned int index, char *name);
#ifdef __cplusplus
}
#endif
#endif
