#include "web/url.h"

#include "ctype.h"
#include "libc.h"

bool web_url_has_extension(const char *url, const char *ext)
{
    if (!url || !ext || ext[0] == '\0')
    {
        return false;
    }

    const char *end = url;
    while (*end && *end != '?' && *end != '#')
    {
        ++end;
    }

    size_t url_len = (size_t)(end - url);
    size_t ext_len = strlen(ext);
    if (url_len < ext_len)
    {
        return false;
    }

    const char *tail = url + url_len - ext_len;
    return strncasecmp(tail, ext, ext_len) == 0;
}

bool web_url_is_svg(const char *url)
{
    return web_url_has_extension(url, ".svg");
}
