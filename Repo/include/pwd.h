#ifndef ALIX_PWD_H
#define ALIX_PWD_H
#ifdef TTF_HOST_BUILD
#include_next <pwd.h>
#else
#include <stddef.h>
#include <sys/types.h>

struct passwd {
    char *pw_name;
    char *pw_passwd;
    uid_t pw_uid;
    gid_t pw_gid;
    char *pw_gecos;
    char *pw_dir;
    char *pw_shell;
};
#ifdef __cplusplus
extern "C" {
#endif
int getpwuid_r(uid_t uid, struct passwd *entry, char *buffer, size_t capacity,
               struct passwd **result);
int getpwnam_r(const char *name, struct passwd *entry, char *buffer, size_t capacity,
               struct passwd **result);
#ifdef __cplusplus
}
#endif
#endif
#endif
