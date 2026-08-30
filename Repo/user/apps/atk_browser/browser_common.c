#include "browser_internal.h"

#include "stdio.h"
#include "string.h"

char *browser_strdup(const char *src)
{
    if (!src)
    {
        src = "";
    }
    size_t len = strlen(src);
    char *dst = (char *)malloc(len + 1);
    if (!dst)
    {
        return NULL;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
    return dst;
}

char *browser_strdup_len(const char *src, size_t len)
{
    if (!src)
    {
        return NULL;
    }
    char *out = (char *)malloc(len + 1);
    if (!out)
    {
        return NULL;
    }
    memcpy(out, src, len);
    out[len] = '\0';
    return out;
}

bool browser_main_document_error(int status,
                                 const char *body,
                                 char *message,
                                 size_t message_cap)
{
    if (!message || message_cap == 0u)
    {
        return false;
    }
    message[0] = '\0';

    if (status >= 400)
    {
        const char *reason = NULL;
        switch (status)
        {
            case 400: reason = "Bad Request"; break;
            case 401: reason = "Unauthorized"; break;
            case 403: reason = "Forbidden"; break;
            case 404: reason = "Not Found"; break;
            case 408: reason = "Request Timeout"; break;
            case 429: reason = "Too Many Requests"; break;
            case 500: reason = "Internal Server Error"; break;
            case 502: reason = "Bad Gateway"; break;
            case 503: reason = "Service Unavailable"; break;
            case 504: reason = "Gateway Timeout"; break;
            default: reason = "Request Failed"; break;
        }
        snprintf(message, message_cap, "HTTP %d %s", status, reason);
        return true;
    }

    if (body && strncmp(body, "Error:\n", 7) == 0)
    {
        const char *detail = body + 7;
        size_t len = 0u;
        while (detail[len] != '\0' && detail[len] != '\r' && detail[len] != '\n')
        {
            len++;
        }
        if (len >= message_cap)
        {
            len = message_cap - 1u;
        }
        memcpy(message, detail, len);
        message[len] = '\0';
        if (len == 0u)
        {
            snprintf(message, message_cap, "network error");
        }
        return true;
    }
    return false;
}

bool browser_write_all(int fd, const uint8_t *data, size_t len)
{
    if (fd < 0 || (!data && len > 0))
    {
        return false;
    }
    size_t offset = 0;
    while (offset < len)
    {
        ssize_t wrote = write(fd, data + offset, len - offset);
        if (wrote <= 0)
        {
            return false;
        }
        offset += (size_t)wrote;
    }
    return true;
}

bool browser_buf_append(char **buf, size_t *len, size_t *cap, const uint8_t *data, size_t data_len)
{
    if (!buf || !len || !cap)
    {
        return false;
    }
    if (data_len == 0)
    {
        return true;
    }
    if (!data)
    {
        return false;
    }

    size_t needed = *len + data_len + 1;
    if (needed > BROWSER_MAX_BYTES)
    {
        return false;
    }
    if (needed > *cap)
    {
        size_t new_cap = (*cap == 0) ? 4096 : *cap;
        while (new_cap < needed)
        {
            new_cap *= 2;
        }
        if (new_cap > BROWSER_MAX_BYTES)
        {
            new_cap = BROWSER_MAX_BYTES;
        }
        char *new_buf = (char *)realloc(*buf, new_cap);
        if (!new_buf)
        {
            return false;
        }
        *buf = new_buf;
        *cap = new_cap;
    }
    memcpy(*buf + *len, data, data_len);
    *len += data_len;
    (*buf)[*len] = '\0';
    return true;
}

bool browser_has_token_ci(const char *value, size_t value_len, const char *token)
{
    if (!value || value_len == 0 || !token || token[0] == '\0')
    {
        return false;
    }

    size_t token_len = strlen(token);
    if (token_len == 0)
    {
        return false;
    }

    size_t i = 0;
    while (i < value_len)
    {
        while (i < value_len &&
               (value[i] == ' ' || value[i] == '\t' || value[i] == '\r' || value[i] == '\n' ||
                value[i] == ',' || value[i] == ';'))
        {
            ++i;
        }
        size_t start = i;
        while (i < value_len &&
               value[i] != ' ' && value[i] != '\t' && value[i] != '\r' && value[i] != '\n' &&
               value[i] != ',' && value[i] != ';')
        {
            ++i;
        }
        size_t seg_len = i - start;
        if (seg_len == token_len && strncasecmp(value + start, token, token_len) == 0)
        {
            return true;
        }
    }

    return false;
}
