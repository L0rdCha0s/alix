#include "web/js/internal.h"

#include "libc.h"

void js_parse_error_set(js_parse_error_t *err, size_t offset, const char *message)
{
    if (!err || err->message)
    {
        return;
    }
    err->offset = offset;
    err->message = message;
}

char *js_strdup_len(const char *src, size_t len)
{
    char *out = (char *)malloc(len + 1);
    if (!out)
    {
        return NULL;
    }
    if (len)
    {
        memcpy(out, src, len);
    }
    out[len] = '\0';
    return out;
}

char *js_strdup(const char *src)
{
    if (!src)
    {
        return NULL;
    }
    return js_strdup_len(src, strlen(src));
}

int js_hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}
