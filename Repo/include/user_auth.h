#ifndef USER_AUTH_H
#define USER_AUTH_H

#include "types.h"

typedef struct
{
    uint32_t uid;
    uint32_t gid;
    char *name;
    char *home;
} user_record_t;

bool user_auth_lookup(const char *username, user_record_t *out);
bool user_auth_check_password(const char *username, const char *password);
void user_auth_free_record(user_record_t *record);
char *user_auth_username_for_uid(uint32_t uid);

#endif
