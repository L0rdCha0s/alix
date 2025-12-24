#include "shell_prompt.h"

#include "heap.h"
#include "libc.h"
#include "process.h"
#include "user_auth.h"
#include "vfs.h"

#define SHELL_PROMPT_DEFAULT_HOST "alix"
#define SHELL_PROMPT_DEFAULT_USER "unknown"

static bool shell_prompt_is_space(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r';
}

static char *shell_prompt_dup(const char *text)
{
    const char *source = text ? text : "";
    size_t len = strlen(source);
    char *copy = (char *)malloc(len + 1);
    if (!copy)
    {
        return NULL;
    }
    memcpy(copy, source, len);
    copy[len] = '\0';
    return copy;
}

static char *shell_prompt_copy_trimmed(const char *data, size_t len)
{
    if (!data || len == 0)
    {
        return NULL;
    }
    size_t start = 0;
    while (start < len && shell_prompt_is_space(data[start]))
    {
        ++start;
    }
    size_t end = len;
    while (end > start && shell_prompt_is_space(data[end - 1]))
    {
        --end;
    }
    if (end <= start)
    {
        return NULL;
    }
    size_t out_len = end - start;
    char *copy = (char *)malloc(out_len + 1);
    if (!copy)
    {
        return NULL;
    }
    memcpy(copy, data + start, out_len);
    copy[out_len] = '\0';
    return copy;
}

static char *shell_prompt_load_hostname(void)
{
    vfs_node_t *node = vfs_resolve(vfs_root(), "/etc/hostname");
    if (!node || !vfs_is_file(node))
    {
        return shell_prompt_dup(SHELL_PROMPT_DEFAULT_HOST);
    }

    size_t size = 0;
    char *data = vfs_data(node, &size);
    char *trimmed = shell_prompt_copy_trimmed(data, size);
    if (!trimmed || trimmed[0] == '\0')
    {
        if (trimmed)
        {
            free(trimmed);
        }
        return shell_prompt_dup(SHELL_PROMPT_DEFAULT_HOST);
    }
    return trimmed;
}

char *shell_prompt_build(struct process *owner)
{
    char *user = NULL;
    if (owner)
    {
        uint32_t uid = process_get_uid(owner);
        if (uid != PROCESS_UID_INVALID)
        {
            user = user_auth_username_for_uid(uid);
        }
    }
    if (!user || user[0] == '\0')
    {
        if (user)
        {
            free(user);
        }
        user = shell_prompt_dup(SHELL_PROMPT_DEFAULT_USER);
    }

    char *host = shell_prompt_load_hostname();
    if (!host)
    {
        host = shell_prompt_dup(SHELL_PROMPT_DEFAULT_HOST);
    }

    if (!user || !host)
    {
        if (user)
        {
            free(user);
        }
        if (host)
        {
            free(host);
        }
        return NULL;
    }

    size_t user_len = strlen(user);
    size_t host_len = strlen(host);
    size_t total = user_len + host_len + 4;
    char *prompt = (char *)malloc(total);
    if (!prompt)
    {
        free(user);
        free(host);
        return NULL;
    }

    char *cursor = prompt;
    if (user_len > 0)
    {
        memcpy(cursor, user, user_len);
        cursor += user_len;
    }
    *cursor++ = '@';
    if (host_len > 0)
    {
        memcpy(cursor, host, host_len);
        cursor += host_len;
    }
    *cursor++ = '$';
    *cursor++ = ' ';
    *cursor = '\0';

    free(user);
    free(host);
    return prompt;
}
