#ifndef ALIX_SYS_UTSNAME_H
#define ALIX_SYS_UTSNAME_H
#ifdef TTF_HOST_BUILD
#include_next <sys/utsname.h>
#else
#include "../syscall_defs.h"
#define _UTSNAME_LENGTH SYSCALL_UTS_FIELD_LENGTH
struct utsname {
    char sysname[_UTSNAME_LENGTH], nodename[_UTSNAME_LENGTH];
    char release[_UTSNAME_LENGTH], version[_UTSNAME_LENGTH];
    char machine[_UTSNAME_LENGTH];
};
#ifdef __cplusplus
extern "C" {
#endif
int uname(struct utsname *info);
#ifdef __cplusplus
}
#endif
#endif
#endif
