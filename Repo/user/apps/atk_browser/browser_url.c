#include "browser_internal.h"

#include "stdio.h"
#include "string.h"

bool browser_parse_url(const char *input, browser_url_t *out)
{
    if (!out)
    {
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->use_tls = true;
    out->port = 443;

    if (!input)
    {
        return false;
    }

    const char *s = input;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
    {
        ++s;
    }
    if (strncmp(s, "https://", 8) == 0)
    {
        out->use_tls = true;
        out->port = 443;
        s += 8;
    }
    else if (strncmp(s, "http://", 7) == 0)
    {
        out->use_tls = false;
        out->port = 80;
        s += 7;
    }

    const char *host_start = s;
    const char *path_start = strchr(s, '/');
    const char *host_end = path_start ? path_start : (s + strlen(s));
    while (host_end > host_start && (host_end[-1] == ' ' || host_end[-1] == '\t'))
    {
        host_end--;
    }

    const char *colon = NULL;
    for (const char *p = host_start; p < host_end; ++p)
    {
        if (*p == ':')
        {
            colon = p;
        }
    }

    size_t host_len = (size_t)(host_end - host_start);
    if (colon && colon > host_start && colon + 1 < host_end)
    {
        int port_val = 0;
        bool ok = true;
        for (const char *p = colon + 1; p < host_end; ++p)
        {
            if (*p < '0' || *p > '9')
            {
                ok = false;
                break;
            }
            port_val = port_val * 10 + (*p - '0');
            if (port_val > 65535)
            {
                ok = false;
                break;
            }
        }
        if (ok && port_val > 0)
        {
            out->port = (uint16_t)port_val;
            host_len = (size_t)(colon - host_start);
        }
    }

    if (host_len == 0)
    {
        return false;
    }

    out->host = (char *)malloc(host_len + 1);
    if (!out->host)
    {
        return false;
    }
    memcpy(out->host, host_start, host_len);
    out->host[host_len] = '\0';

    const char *path = (path_start && path_start[0] != '\0') ? path_start : "/";
    out->path = browser_strdup(path);
    if (!out->path)
    {
        free(out->host);
        out->host = NULL;
        return false;
    }
    return true;
}

void browser_url_destroy(browser_url_t *url)
{
    if (!url)
    {
        return;
    }
    if (url->host)
    {
        free(url->host);
        url->host = NULL;
    }
    if (url->path)
    {
        free(url->path);
        url->path = NULL;
    }
    url->port = 0;
    url->use_tls = false;
}

bool browser_url_clone(const browser_url_t *src, browser_url_t *dst)
{
    if (!src || !dst)
    {
        return false;
    }

    if (dst->host || dst->path)
    {
        browser_url_destroy(dst);
    }
    memset(dst, 0, sizeof(*dst));

    dst->use_tls = src->use_tls;
    dst->port = src->port;
    dst->host = browser_strdup(src->host);
    dst->path = browser_strdup(src->path);
    if (!dst->host || !dst->path)
    {
        browser_url_destroy(dst);
        return false;
    }
    return true;
}

char *browser_url_to_string(const browser_url_t *url)
{
    if (!url || !url->host || !url->path)
    {
        return NULL;
    }

    const char *scheme = url->use_tls ? "https" : "http";
    uint16_t default_port = url->use_tls ? 443u : 80u;

    char port_buf[16];
    port_buf[0] = '\0';
    if (url->port != 0 && url->port != default_port)
    {
        snprintf(port_buf, sizeof(port_buf), ":%u", (unsigned)url->port);
    }

    size_t scheme_len = strlen(scheme);
    size_t host_len = strlen(url->host);
    size_t port_len = strlen(port_buf);
    size_t path_len = strlen(url->path);

    size_t total = scheme_len + 3 + host_len + port_len + path_len;
    char *out = (char *)malloc(total + 1);
    if (!out)
    {
        return NULL;
    }

    size_t pos = 0;
    memcpy(out + pos, scheme, scheme_len);
    pos += scheme_len;
    memcpy(out + pos, "://", 3);
    pos += 3;
    memcpy(out + pos, url->host, host_len);
    pos += host_len;
    if (port_len > 0)
    {
        memcpy(out + pos, port_buf, port_len);
        pos += port_len;
    }
    memcpy(out + pos, url->path, path_len);
    pos += path_len;
    out[pos] = '\0';
    return out;
}

static size_t browser_path_dir_len(const char *path)
{
    if (!path || path[0] == '\0')
    {
        return 1;
    }
    size_t len = strlen(path);
    if (len == 0)
    {
        return 1;
    }
    if (path[len - 1] == '/')
    {
        return len;
    }
    const char *last = strrchr(path, '/');
    if (!last)
    {
        return 1;
    }
    size_t dir_len = (size_t)(last - path) + 1;
    if (dir_len == 0)
    {
        dir_len = 1;
    }
    return dir_len;
}

char *browser_build_absolute_url(const browser_url_t *base, const char *location, size_t location_len)
{
    if (!base || !base->host || !location)
    {
        return NULL;
    }

    while (location_len > 0 &&
           (location[0] == ' ' || location[0] == '\t' || location[0] == '\r' || location[0] == '\n'))
    {
        location++;
        location_len--;
    }
    while (location_len > 0)
    {
        char tail = location[location_len - 1];
        if (tail == ' ' || tail == '\t' || tail == '\r' || tail == '\n')
        {
            location_len--;
            continue;
        }
        break;
    }

    if (location_len == 0)
    {
        return NULL;
    }

    if (location_len >= 7 && strncasecmp(location, "http://", 7) == 0)
    {
        char *out = browser_strdup_len(location, location_len);
        if (out)
        {
            memcpy(out, "http://", 7);
        }
        return out;
    }
    if (location_len >= 8 && strncasecmp(location, "https://", 8) == 0)
    {
        char *out = browser_strdup_len(location, location_len);
        if (out)
        {
            memcpy(out, "https://", 8);
        }
        return out;
    }

    const char *scheme = base->use_tls ? "https" : "http";
    uint16_t default_port = base->use_tls ? 443u : 80u;

    char port_buf[16];
    port_buf[0] = '\0';
    if (base->port != 0 && base->port != default_port)
    {
        snprintf(port_buf, sizeof(port_buf), ":%u", (unsigned)base->port);
    }

    if (location_len >= 2 && location[0] == '/' && location[1] == '/')
    {
        size_t scheme_len = strlen(scheme);
        size_t need = scheme_len + 1 + location_len;
        char *out = (char *)malloc(need + 1);
        if (!out)
        {
            return NULL;
        }
        memcpy(out, scheme, scheme_len);
        out[scheme_len] = ':';
        memcpy(out + scheme_len + 1, location, location_len);
        out[need] = '\0';
        return out;
    }

    if (location[0] == '#')
    {
        return NULL;
    }

    size_t scheme_len = strlen(scheme);
    size_t host_len = strlen(base->host);
    size_t port_len = strlen(port_buf);
    size_t authority_len = scheme_len + 3 + host_len + port_len;

    const char *path_part = NULL;
    size_t path_len = 0;
    char *relative_path = NULL;

    if (location[0] == '/')
    {
        path_part = location;
        path_len = location_len;
    }
    else if (location[0] == '?')
    {
        const char *base_path = base->path ? base->path : "/";
        size_t base_len = strlen(base_path);
        size_t core_len = base_len;
        for (size_t i = 0; i < base_len; ++i)
        {
            if (base_path[i] == '?' || base_path[i] == '#')
            {
                core_len = i;
                break;
            }
        }
        if (core_len == 0)
        {
            core_len = 1;
        }
        relative_path = (char *)malloc(core_len + location_len + 1);
        if (!relative_path)
        {
            return NULL;
        }
        memcpy(relative_path, base_path, core_len);
        memcpy(relative_path + core_len, location, location_len);
        relative_path[core_len + location_len] = '\0';
        path_part = relative_path;
        path_len = core_len + location_len;
    }
    else
    {
        const char *base_path = base->path ? base->path : "/";
        size_t dir_len = browser_path_dir_len(base_path);
        relative_path = (char *)malloc(dir_len + location_len + 2);
        if (!relative_path)
        {
            return NULL;
        }
        memcpy(relative_path, base_path, dir_len);
        size_t pos = dir_len;
        if (pos == 0 || relative_path[pos - 1] != '/')
        {
            relative_path[pos++] = '/';
        }
        memcpy(relative_path + pos, location, location_len);
        pos += location_len;
        relative_path[pos] = '\0';
        path_part = relative_path;
        path_len = pos;
    }

    size_t total_len = authority_len + path_len;
    char *out = (char *)malloc(total_len + 1);
    if (!out)
    {
        free(relative_path);
        return NULL;
    }

    size_t pos = 0;
    memcpy(out + pos, scheme, scheme_len);
    pos += scheme_len;
    memcpy(out + pos, "://", 3);
    pos += 3;
    memcpy(out + pos, base->host, host_len);
    pos += host_len;
    if (port_len > 0)
    {
        memcpy(out + pos, port_buf, port_len);
        pos += port_len;
    }
    memcpy(out + pos, path_part, path_len);
    pos += path_len;
    out[pos] = '\0';

    free(relative_path);
    return out;
}

