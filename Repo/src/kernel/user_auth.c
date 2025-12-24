#include "user_auth.h"

#include "heap.h"
#include "libc.h"
#include "vfs.h"

typedef struct
{
    const char *data;
    size_t size;
} auth_file_view_t;

static bool auth_load_file(const char *path, auth_file_view_t *out)
{
    if (!path || !out)
    {
        return false;
    }
    vfs_node_t *node = vfs_resolve(vfs_root(), path);
    if (!node || !vfs_is_file(node))
    {
        return false;
    }
    size_t size = 0;
    char *data = vfs_data(node, &size);
    if (!data)
    {
        return false;
    }
    out->data = data;
    out->size = size;
    return true;
}

static const char *auth_find_char_range(const char *start, const char *end, char ch)
{
    for (const char *cur = start; cur < end; ++cur)
    {
        if (*cur == ch)
        {
            return cur;
        }
    }
    return NULL;
}

static bool auth_field_match(const char *start, const char *end, const char *value)
{
    if (!start || !end || !value)
    {
        return false;
    }
    size_t len = (size_t)(end - start);
    size_t value_len = strlen(value);
    if (len != value_len)
    {
        return false;
    }
    return strncmp(start, value, len) == 0;
}

static bool auth_parse_u32(const char *start, const char *end, uint32_t *out)
{
    if (!start || !end || !out || start >= end)
    {
        return false;
    }
    uint32_t value = 0;
    for (const char *cur = start; cur < end; ++cur)
    {
        if (*cur < '0' || *cur > '9')
        {
            return false;
        }
        uint32_t digit = (uint32_t)(*cur - '0');
        uint32_t next = value * 10u + digit;
        if (next < value)
        {
            return false;
        }
        value = next;
    }
    *out = value;
    return true;
}

static char *auth_copy_field(const char *start, const char *end)
{
    if (!start || !end || end < start)
    {
        return NULL;
    }
    size_t len = (size_t)(end - start);
    char *copy = (char *)malloc(len + 1);
    if (!copy)
    {
        return NULL;
    }
    if (len > 0)
    {
        memcpy(copy, start, len);
    }
    copy[len] = '\0';
    return copy;
}

void user_auth_free_record(user_record_t *record)
{
    if (!record)
    {
        return;
    }
    if (record->name)
    {
        free(record->name);
        record->name = NULL;
    }
    if (record->home)
    {
        free(record->home);
        record->home = NULL;
    }
    record->uid = 0;
    record->gid = 0;
}

static bool auth_parse_passwd_line(const char *line,
                                   const char *end,
                                   const char *username,
                                   user_record_t *out)
{
    const char *colon1 = auth_find_char_range(line, end, ':');
    if (!colon1)
    {
        return false;
    }
    if (!auth_field_match(line, colon1, username))
    {
        return false;
    }
    const char *colon2 = auth_find_char_range(colon1 + 1, end, ':');
    const char *colon3 = colon2 ? auth_find_char_range(colon2 + 1, end, ':') : NULL;
    const char *colon4 = colon3 ? auth_find_char_range(colon3 + 1, end, ':') : NULL;
    if (!colon2 || !colon3 || !colon4)
    {
        return false;
    }

    uint32_t uid = 0;
    uint32_t gid = 0;
    if (!auth_parse_u32(colon1 + 1, colon2, &uid))
    {
        return false;
    }
    if (!auth_parse_u32(colon2 + 1, colon3, &gid))
    {
        return false;
    }

    char *name = auth_copy_field(colon3 + 1, colon4);
    char *home = auth_copy_field(colon4 + 1, end);
    if (!home)
    {
        if (name)
        {
            free(name);
        }
        return false;
    }

    out->uid = uid;
    out->gid = gid;
    out->name = name;
    out->home = home;
    return true;
}

static bool auth_parse_passwd_line_uid(const char *line,
                                       const char *end,
                                       uint32_t uid,
                                       char **username_out)
{
    const char *colon1 = auth_find_char_range(line, end, ':');
    if (!colon1)
    {
        return false;
    }
    const char *colon2 = auth_find_char_range(colon1 + 1, end, ':');
    if (!colon2)
    {
        return false;
    }
    uint32_t parsed_uid = 0;
    if (!auth_parse_u32(colon1 + 1, colon2, &parsed_uid))
    {
        return false;
    }
    if (parsed_uid != uid)
    {
        return false;
    }
    if (!username_out)
    {
        return true;
    }
    *username_out = auth_copy_field(line, colon1);
    return *username_out != NULL;
}

bool user_auth_lookup(const char *username, user_record_t *out)
{
    if (!username || !out)
    {
        return false;
    }
    memset(out, 0, sizeof(*out));

    auth_file_view_t view = { 0 };
    if (!auth_load_file("/etc/passwd", &view))
    {
        return false;
    }

    size_t pos = 0;
    while (pos < view.size)
    {
        size_t line_end = pos;
        while (line_end < view.size && view.data[line_end] != '\n' && view.data[line_end] != '\r')
        {
            ++line_end;
        }
        if (line_end > pos)
        {
            const char *line = view.data + pos;
            const char *end = view.data + line_end;
            if (auth_parse_passwd_line(line, end, username, out))
            {
                return true;
            }
        }
        while (line_end < view.size && (view.data[line_end] == '\n' || view.data[line_end] == '\r'))
        {
            ++line_end;
        }
        pos = line_end;
    }

    return false;
}

char *user_auth_username_for_uid(uint32_t uid)
{
    auth_file_view_t view = { 0 };
    if (!auth_load_file("/etc/passwd", &view))
    {
        return NULL;
    }

    size_t pos = 0;
    while (pos < view.size)
    {
        size_t line_end = pos;
        while (line_end < view.size && view.data[line_end] != '\n' && view.data[line_end] != '\r')
        {
            ++line_end;
        }
        if (line_end > pos)
        {
            const char *line = view.data + pos;
            const char *end = view.data + line_end;
            char *username = NULL;
            if (auth_parse_passwd_line_uid(line, end, uid, &username))
            {
                return username;
            }
        }
        while (line_end < view.size && (view.data[line_end] == '\n' || view.data[line_end] == '\r'))
        {
            ++line_end;
        }
        pos = line_end;
    }

    return NULL;
}

bool user_auth_check_password(const char *username, const char *password)
{
    if (!username || !password)
    {
        return false;
    }
    auth_file_view_t view = { 0 };
    if (!auth_load_file("/etc/shadow", &view))
    {
        return false;
    }

    size_t pos = 0;
    while (pos < view.size)
    {
        size_t line_end = pos;
        while (line_end < view.size && view.data[line_end] != '\n' && view.data[line_end] != '\r')
        {
            ++line_end;
        }
        if (line_end > pos)
        {
            const char *line = view.data + pos;
            const char *end = view.data + line_end;
            const char *colon = auth_find_char_range(line, end, ':');
            if (colon && auth_field_match(line, colon, username))
            {
                size_t stored_len = (size_t)(end - (colon + 1));
                size_t password_len = strlen(password);
                if (stored_len == password_len &&
                    strncmp(colon + 1, password, stored_len) == 0)
                {
                    return true;
                }
                return false;
            }
        }
        while (line_end < view.size && (view.data[line_end] == '\n' || view.data[line_end] == '\r'))
        {
            ++line_end;
        }
        pos = line_end;
    }

    return false;
}
