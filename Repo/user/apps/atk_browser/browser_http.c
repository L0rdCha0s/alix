#include "browser_internal.h"

#include "crypto/sha1.h"
#include "net/tls.h"
#include "usyscall.h"

#include "stdio.h"
#include "string.h"

#define BROWSER_MAX_PASSWD_BYTES (64u * 1024u)

static bool browser_parse_u32_range(const char *start, const char *end, uint32_t *out)
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

static char *browser_read_file_all(const char *path, size_t *len_out, size_t max_bytes)
{
    if (len_out)
    {
        *len_out = 0;
    }
    if (!path || path[0] == '\0')
    {
        return NULL;
    }

    int fd = open(path, SYSCALL_OPEN_READ);
    if (fd < 0)
    {
        return NULL;
    }

    struct stat st;
    if (fstat(fd, &st) != 0)
    {
        close(fd);
        return NULL;
    }

    if (st.st_size == 0)
    {
        close(fd);
        return NULL;
    }
    if (st.st_size > (uint64_t)max_bytes)
    {
        close(fd);
        return NULL;
    }

    size_t size = (size_t)st.st_size;
    char *buf = (char *)malloc(size + 1);
    if (!buf)
    {
        close(fd);
        return NULL;
    }

    size_t offset = 0;
    while (offset < size)
    {
        ssize_t got = read(fd, buf + offset, size - offset);
        if (got <= 0)
        {
            free(buf);
            close(fd);
            return NULL;
        }
        offset += (size_t)got;
    }
    buf[size] = '\0';
    close(fd);

    if (len_out)
    {
        *len_out = size;
    }
    return buf;
}

static bool browser_passwd_line_home(const char *line,
                                     const char *end,
                                     uint32_t *uid_out,
                                     const char **home_start_out,
                                     size_t *home_len_out)
{
    if (!line || !end || line >= end || !uid_out || !home_start_out || !home_len_out)
    {
        return false;
    }

    const char *colon1 = NULL;
    const char *colon2 = NULL;
    const char *colon3 = NULL;
    const char *colon4 = NULL;
    for (const char *cur = line; cur < end; ++cur)
    {
        if (*cur == ':')
        {
            if (!colon1)
            {
                colon1 = cur;
            }
            else if (!colon2)
            {
                colon2 = cur;
            }
            else if (!colon3)
            {
                colon3 = cur;
            }
            else
            {
                colon4 = cur;
                break;
            }
        }
    }

    if (!colon1 || !colon2 || !colon3 || !colon4)
    {
        return false;
    }

    uint32_t uid = 0;
    if (!browser_parse_u32_range(colon1 + 1, colon2, &uid))
    {
        return false;
    }

    const char *home_start = colon4 + 1;
    if (home_start > end)
    {
        return false;
    }
    size_t home_len = (size_t)(end - home_start);
    if (home_len == 0)
    {
        return false;
    }

    *uid_out = uid;
    *home_start_out = home_start;
    *home_len_out = home_len;
    return true;
}

static char *browser_home_from_passwd(uint32_t uid)
{
    size_t data_len = 0;
    char *data = browser_read_file_all("/etc/passwd", &data_len, BROWSER_MAX_PASSWD_BYTES);
    if (!data || data_len == 0)
    {
        free(data);
        return NULL;
    }

    char *home = NULL;
    char *root_home = NULL;
    size_t pos = 0;
    while (pos < data_len)
    {
        size_t line_end = pos;
        while (line_end < data_len && data[line_end] != '\n' && data[line_end] != '\r')
        {
            ++line_end;
        }

        if (line_end > pos)
        {
            const char *line = data + pos;
            const char *end = data + line_end;
            uint32_t line_uid = 0;
            const char *home_start = NULL;
            size_t home_len = 0;
            if (browser_passwd_line_home(line, end, &line_uid, &home_start, &home_len))
            {
                if (!home && line_uid == uid)
                {
                    home = browser_strdup_len(home_start, home_len);
                }
                if (!root_home && line_uid == 0)
                {
                    root_home = browser_strdup_len(home_start, home_len);
                }
            }
        }

        while (line_end < data_len && (data[line_end] == '\n' || data[line_end] == '\r'))
        {
            ++line_end;
        }
        pos = line_end;
    }

    free(data);
    if (home)
    {
        free(root_home);
        return home;
    }
    return root_home;
}

static bool browser_dir_exists(const char *path)
{
    if (!path || path[0] == '\0')
    {
        return false;
    }
    syscall_dirent_t *scratch = (syscall_dirent_t *)malloc(sizeof(*scratch));
    if (!scratch)
    {
        return false;
    }
    ssize_t count = sys_list_dir(path, scratch, 1);
    free(scratch);
    return count >= 0;
}

static bool browser_ensure_dir_path(const char *path)
{
    if (!path || path[0] == '\0')
    {
        return false;
    }

    char *copy = browser_strdup(path);
    if (!copy)
    {
        return false;
    }

    size_t len = strlen(copy);
    if (len == 0)
    {
        free(copy);
        return false;
    }

    size_t pos = 0;
    if (copy[0] == '/')
    {
        pos = 1;
        while (copy[pos] == '/')
        {
            pos++;
        }
    }

    for (; pos <= len; ++pos)
    {
        if (copy[pos] == '/' || copy[pos] == '\0')
        {
            char saved = copy[pos];
            copy[pos] = '\0';
            if (copy[0] != '\0' && !(copy[0] == '/' && copy[1] == '\0'))
            {
                if (mkdir(copy, 0) != 0)
                {
                    if (!browser_dir_exists(copy))
                    {
                        free(copy);
                        return false;
                    }
                }
            }
            copy[pos] = saved;
            while (copy[pos] == '/')
            {
                pos++;
            }
        }
    }

    free(copy);
    return true;
}

static const char *browser_cache_dir(browser_app_t *app)
{
    if (!app)
    {
        return NULL;
    }

    browser_lock_enter(app, &app->lock, "app_lock");
    if (app->cache_ready)
    {
        const char *dir = app->cache_dir;
        browser_lock_exit(app, &app->lock, "app_lock");
        return dir;
    }
    if (app->cache_attempted)
    {
        browser_lock_exit(app, &app->lock, "app_lock");
        return NULL;
    }
    app->cache_attempted = true;
    browser_lock_exit(app, &app->lock, "app_lock");

    char *home = browser_home_from_passwd(getuid());
    if (!home || home[0] == '\0')
    {
        free(home);
        return NULL;
    }

    size_t home_len = strlen(home);
    while (home_len > 1 && home[home_len - 1] == '/')
    {
        home_len--;
    }
    home[home_len] = '\0';

    if (!browser_ensure_dir_path(home))
    {
        free(home);
        return NULL;
    }

    const char suffix[] = "/.browser/cache";
    size_t suffix_len = sizeof(suffix) - 1;
    size_t cache_len = home_len + suffix_len;
    char *cache_dir = (char *)malloc(cache_len + 1);
    if (!cache_dir)
    {
        free(home);
        return NULL;
    }

    memcpy(cache_dir, home, home_len);
    memcpy(cache_dir + home_len, suffix, suffix_len);
    cache_dir[cache_len] = '\0';
    free(home);

    if (!browser_ensure_dir_path(cache_dir))
    {
        free(cache_dir);
        return NULL;
    }

    browser_lock_enter(app, &app->lock, "app_lock");
    if (!app->cache_ready)
    {
        app->cache_dir = cache_dir;
        app->cache_ready = true;
    }
    const char *dir = app->cache_dir;
    browser_lock_exit(app, &app->lock, "app_lock");

    if (dir != cache_dir)
    {
        free(cache_dir);
    }
    return dir;
}

static bool browser_cache_hash_uri(const char *uri, char out[41])
{
    if (!uri || !out)
    {
        return false;
    }

    uint8_t digest[20];
    sha1_ctx_t ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, uri, strlen(uri));
    sha1_final(&ctx, digest);

    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(digest); ++i)
    {
        out[i * 2] = hex[(digest[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex[digest[i] & 0x0F];
    }
    out[40] = '\0';
    return true;
}

static char *browser_cache_path_for_uri(const char *cache_dir, const char *uri)
{
    if (!cache_dir || !uri)
    {
        return NULL;
    }

    char hash[41];
    if (!browser_cache_hash_uri(uri, hash))
    {
        return NULL;
    }

    size_t dir_len = strlen(cache_dir);
    size_t path_len = dir_len + 1 + sizeof(hash) - 1;
    char *path = (char *)malloc(path_len + 1);
    if (!path)
    {
        return NULL;
    }

    memcpy(path, cache_dir, dir_len);
    path[dir_len] = '/';
    memcpy(path + dir_len + 1, hash, sizeof(hash));
    path[path_len] = '\0';
    return path;
}

static char *browser_cache_read(browser_app_t *app, const char *uri, size_t *body_len_out)
{
    if (body_len_out)
    {
        *body_len_out = 0;
    }
    if (!app || !uri || uri[0] == '\0')
    {
        return NULL;
    }

    const char *cache_dir = browser_cache_dir(app);
    if (!cache_dir)
    {
        return NULL;
    }

    char *path = browser_cache_path_for_uri(cache_dir, uri);
    if (!path)
    {
        return NULL;
    }

    char *data = browser_read_file_all(path, body_len_out, BROWSER_MAX_BYTES);
    if (data)
    {
        browser_debug_logf(app, "[cache] hit url=%s", uri);
    }
    free(path);
    return data;
}

static void browser_cache_write(browser_app_t *app, const char *uri, const uint8_t *data, size_t len)
{
    if (!app || !uri || uri[0] == '\0' || !data || len == 0 || len > BROWSER_MAX_BYTES)
    {
        return;
    }

    const char *cache_dir = browser_cache_dir(app);
    if (!cache_dir)
    {
        return;
    }

    char *path = browser_cache_path_for_uri(cache_dir, uri);
    if (!path)
    {
        return;
    }

    int fd = open(path, SYSCALL_OPEN_WRITE | SYSCALL_OPEN_CREATE | SYSCALL_OPEN_TRUNCATE);
    if (fd >= 0)
    {
        if (browser_write_all(fd, data, len))
        {
            browser_debug_logf(app, "[cache] store url=%s bytes=%u", uri, (unsigned)len);
        }
        close(fd);
    }
    free(path);
}

static bool browser_http_find_header_end(const char *data,
                                        size_t len,
                                        size_t *header_len_out,
                                        size_t *body_offset_out)
{
    if (!data || len == 0)
    {
        return false;
    }

    for (size_t i = 0; i + 3 < len; ++i)
    {
        if (data[i] == '\r' &&
            data[i + 1] == '\n' &&
            data[i + 2] == '\r' &&
            data[i + 3] == '\n')
        {
            if (header_len_out)
            {
                *header_len_out = i;
            }
            if (body_offset_out)
            {
                *body_offset_out = i + 4;
            }
            return true;
        }
    }

    for (size_t i = 0; i + 1 < len; ++i)
    {
        if (data[i] == '\n' && data[i + 1] == '\n')
        {
            if (header_len_out)
            {
                *header_len_out = i;
            }
            if (body_offset_out)
            {
                *body_offset_out = i + 2;
            }
            return true;
        }
    }

    return false;
}

static bool browser_http_find_header_value(const char *headers,
                                          size_t headers_len,
                                          const char *name,
                                          const char **value_out,
                                          size_t *value_len_out)
{
    if (!headers || headers_len == 0 || !name || !value_out || !value_len_out)
    {
        return false;
    }

    const size_t name_len = strlen(name);
    const char *p = headers;
    const char *end = headers + headers_len;

    while (p < end)
    {
        const char *line = p;
        const char *line_end = NULL;
        for (const char *it = p; it < end; ++it)
        {
            if (*it == '\n')
            {
                line_end = it;
                break;
            }
        }
        if (!line_end)
        {
            line_end = end;
            p = end;
        }
        else
        {
            p = line_end + 1;
        }

        size_t line_len = (size_t)(line_end - line);
        if (line_len > 0 && line[line_len - 1] == '\r')
        {
            line_len--;
        }
        if (line_len == 0)
        {
            continue;
        }

        const char *colon = NULL;
        for (size_t i = 0; i < line_len; ++i)
        {
            if (line[i] == ':')
            {
                colon = line + i;
                break;
            }
        }
        if (!colon)
        {
            continue;
        }

        size_t key_len = (size_t)(colon - line);
        if (key_len != name_len)
        {
            continue;
        }
        if (strncasecmp(line, name, name_len) != 0)
        {
            continue;
        }

        const char *value = colon + 1;
        const char *line_data_end = line + line_len;
        while (value < line_data_end && (*value == ' ' || *value == '\t'))
        {
            value++;
        }
        const char *value_end = line_data_end;
        while (value_end > value && (value_end[-1] == ' ' || value_end[-1] == '\t'))
        {
            value_end--;
        }

        *value_out = value;
        *value_len_out = (size_t)(value_end - value);
        return true;
    }

    return false;
}

static bool browser_parse_decimal_size(const char *value, size_t value_len, size_t *out)
{
    if (!value || value_len == 0 || !out)
    {
        return false;
    }

    size_t parsed = 0;
    bool saw_digit = false;
    for (size_t i = 0; i < value_len; ++i)
    {
        char c = value[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
        {
            continue;
        }
        if (c < '0' || c > '9')
        {
            return false;
        }
        saw_digit = true;
        size_t digit = (size_t)(c - '0');
        if (parsed > (BROWSER_MAX_BYTES - digit) / 10u)
        {
            return false;
        }
        parsed = parsed * 10u + digit;
    }
    if (!saw_digit)
    {
        return false;
    }
    *out = parsed;
    return true;
}

static void browser_http_copy_status_line(const char *headers,
                                         size_t headers_len,
                                         char *out,
                                         size_t out_cap)
{
    if (!out || out_cap == 0)
    {
        return;
    }
    out[0] = '\0';
    if (!headers || headers_len == 0)
    {
        return;
    }

    size_t max = headers_len;
    for (size_t i = 0; i < max; ++i)
    {
        char c = headers[i];
        if (c == '\r' || c == '\n')
        {
            max = i;
            break;
        }
    }
    if (max >= out_cap)
    {
        max = out_cap - 1;
    }
    memcpy(out, headers, max);
    out[max] = '\0';
}

static int browser_http_parse_status_code(const char *headers, size_t headers_len)
{
    if (!headers || headers_len == 0)
    {
        return -1;
    }

    size_t i = 0;
    while (i < headers_len && (headers[i] == ' ' || headers[i] == '\t'))
    {
        ++i;
    }

    while (i < headers_len && headers[i] != ' ' && headers[i] != '\t' && headers[i] != '\r' && headers[i] != '\n')
    {
        ++i;
    }
    while (i < headers_len && (headers[i] == ' ' || headers[i] == '\t'))
    {
        ++i;
    }

    if (i + 3 > headers_len)
    {
        return -1;
    }
    int code = 0;
    for (int d = 0; d < 3; ++d)
    {
        char c = headers[i + (size_t)d];
        if (c < '0' || c > '9')
        {
            return -1;
        }
        code = code * 10 + (c - '0');
    }
    return code;
}

typedef enum
{
    BROWSER_CHUNK_READ_SIZE = 0,
    BROWSER_CHUNK_READ_DATA,
    BROWSER_CHUNK_READ_DATA_CR,
    BROWSER_CHUNK_READ_DATA_LF,
    BROWSER_CHUNK_READ_TRAILERS,
    BROWSER_CHUNK_DONE
} browser_chunk_state_t;

typedef struct
{
    browser_chunk_state_t state;
    size_t current_size;
    size_t remaining;
    char linebuf[64];
    size_t line_len;
    int trailer_stage;
} browser_chunked_t;

static void browser_chunked_init(browser_chunked_t *st)
{
    if (!st)
    {
        return;
    }
    st->state = BROWSER_CHUNK_READ_SIZE;
    st->current_size = 0;
    st->remaining = 0;
    st->line_len = 0;
    st->trailer_stage = 0;
}

static bool browser_parse_chunk_size_line(const char *line, size_t len, size_t *out)
{
    if (!line || len == 0 || !out)
    {
        return false;
    }

    size_t val = 0;
    bool saw_digit = false;
    for (size_t i = 0; i < len; ++i)
    {
        char c = line[i];
        if (c == ';' || c == ' ' || c == '\t')
        {
            break;
        }

        unsigned d = 0;
        if (c >= '0' && c <= '9')
        {
            d = (unsigned)(c - '0');
        }
        else if (c >= 'a' && c <= 'f')
        {
            d = 10u + (unsigned)(c - 'a');
        }
        else if (c >= 'A' && c <= 'F')
        {
            d = 10u + (unsigned)(c - 'A');
        }
        else
        {
            return false;
        }

        saw_digit = true;
        if (val > (BROWSER_MAX_BYTES - (size_t)d) / 16u)
        {
            return false;
        }
        val = (val << 4) | (size_t)d;
    }

    if (!saw_digit)
    {
        return false;
    }

    *out = val;
    return true;
}

static bool browser_chunked_consume(browser_chunked_t *st,
                                   char **out_body,
                                   size_t *out_len,
                                   size_t *out_cap,
                                   const uint8_t *data,
                                   size_t len,
                                   bool *done)
{
    if (!st || !out_body || !out_len || !out_cap || (!data && len > 0) || !done)
    {
        return false;
    }

    size_t pos = 0;
    *done = false;

    while (pos < len && st->state != BROWSER_CHUNK_DONE)
    {
        switch (st->state)
        {
            case BROWSER_CHUNK_READ_SIZE:
            {
                char b = (char)data[pos++];
                if (st->line_len >= sizeof(st->linebuf))
                {
                    return false;
                }
                st->linebuf[st->line_len++] = b;
                if (st->line_len >= 2 &&
                    st->linebuf[st->line_len - 2] == '\r' &&
                    st->linebuf[st->line_len - 1] == '\n')
                {
                    size_t linelen = st->line_len - 2;
                    if (!browser_parse_chunk_size_line(st->linebuf, linelen, &st->current_size))
                    {
                        return false;
                    }
                    st->line_len = 0;
                    st->remaining = st->current_size;
                    if (st->current_size == 0)
                    {
                        st->state = BROWSER_CHUNK_READ_TRAILERS;
                        st->trailer_stage = 2;
                    }
                    else
                    {
                        st->state = BROWSER_CHUNK_READ_DATA;
                    }
                }
                break;
            }

            case BROWSER_CHUNK_READ_DATA:
            {
                size_t avail = len - pos;
                size_t take = (st->remaining < avail) ? st->remaining : avail;
                if (take > 0)
                {
                    if (!browser_buf_append(out_body, out_len, out_cap, data + pos, take))
                    {
                        return false;
                    }
                    pos += take;
                    st->remaining -= take;
                }
                if (st->remaining == 0)
                {
                    st->state = BROWSER_CHUNK_READ_DATA_CR;
                }
                break;
            }

            case BROWSER_CHUNK_READ_DATA_CR:
                if (pos >= len)
                {
                    return true;
                }
                if (data[pos++] != '\r')
                {
                    return false;
                }
                st->state = BROWSER_CHUNK_READ_DATA_LF;
                break;

            case BROWSER_CHUNK_READ_DATA_LF:
                if (pos >= len)
                {
                    return true;
                }
                if (data[pos++] != '\n')
                {
                    return false;
                }
                st->state = BROWSER_CHUNK_READ_SIZE;
                break;

            case BROWSER_CHUNK_READ_TRAILERS:
            {
                char c = (char)data[pos++];
                switch (st->trailer_stage)
                {
                    case 0: st->trailer_stage = (c == '\r') ? 1 : 0; break;
                    case 1: st->trailer_stage = (c == '\n') ? 2 : (c == '\r' ? 1 : 0); break;
                    case 2: st->trailer_stage = (c == '\r') ? 3 : 0; break;
                    case 3:
                        if (c == '\n')
                        {
                            st->state = BROWSER_CHUNK_DONE;
                            *done = true;
                        }
                        else
                        {
                            st->trailer_stage = 0;
                        }
                        break;
                }
                break;
            }

            case BROWSER_CHUNK_DONE:
                *done = true;
                break;
        }
    }

    return true;
}

static char *browser_format_error(const char *message)
{
    if (!message)
    {
        message = "unknown error";
    }
    const char *prefix = "Error:\n";
    size_t plen = strlen(prefix);
    size_t mlen = strlen(message);
    char *out = (char *)malloc(plen + mlen + 2);
    if (!out)
    {
        return NULL;
    }
    memcpy(out, prefix, plen);
    memcpy(out + plen, message, mlen);
    out[plen + mlen] = '\n';
    out[plen + mlen + 1] = '\0';
    return out;
}

static char *browser_build_request(const char *host, const char *path)
{
    if (!host || host[0] == '\0')
    {
        host = "unknown";
    }
    if (!path || path[0] == '\0')
    {
        path = "/";
    }
    const char *fmt =
        "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\nUser-Agent: atk_browser/0.1\r\n\r\n";
    size_t cap = strlen(fmt) + strlen(host) + strlen(path) + 32;
    char *req = (char *)malloc(cap);
    if (!req)
    {
        return NULL;
    }
    snprintf(req, cap, fmt, path, host);
    return req;
}

static char *browser_fetch_http_internal(browser_app_t *app,
                                         const browser_url_t *url,
                                         int redirect_depth,
                                         size_t *body_len_out,
                                         browser_url_t *final_url_out)
{
    if (body_len_out)
    {
        *body_len_out = 0;
    }

    if (!url || !url->host || !url->path)
    {
        browser_debug_logf(app, "[fetch] invalid url (missing host/path)");
        return browser_format_error("invalid url");
    }

    if (redirect_depth < 0)
    {
        redirect_depth = 0;
    }
    if (redirect_depth > BROWSER_MAX_REDIRECTS)
    {
        browser_debug_logf(app, "[http] too many redirects");
        return browser_format_error("too many redirects");
    }

    browser_debug_logf(app,
                       "[fetch] connect tls=%d host=%s port=%u path=%s",
                       url->use_tls ? 1 : 0,
                       url->host ? url->host : "(null)",
                       (unsigned)url->port,
                       url->path ? url->path : "(null)");

    int fd = socket_open(NULL);
    if (fd < 0)
    {
        browser_debug_logf(app, "[net] socket_open failed");
        return browser_format_error("socket_open failed");
    }

    if (socket_connect(fd, url->host, url->port) != 0)
    {
        browser_debug_logf(app, "[net] socket_connect failed");
        close(fd);
        return browser_format_error("socket_connect failed");
    }
    browser_debug_logf(app, "[net] connected");

    char *request = browser_build_request(url->host, url->path);
    if (!request)
    {
        browser_debug_logf(app, "[http] alloc request failed");
        close(fd);
        return browser_format_error("alloc request failed");
    }
    browser_debug_logf(app,
                       "[http] request GET %s Host: %s",
                       url->path ? url->path : "/",
                       url->host ? url->host : "(null)");

    char *header_buf = NULL;
    size_t header_len = 0;
    size_t header_cap = 0;
    bool header_done = false;

    char *body_buf = NULL;
    size_t body_len = 0;
    size_t body_cap = 0;

    bool have_content_length = false;
    size_t content_length = 0;
    bool is_chunked = false;
    browser_chunked_t chunked;
    browser_chunked_init(&chunked);

    char *redirect_target = NULL;
    int redirect_status = 0;

    uint8_t *chunk = (uint8_t *)malloc(2048);
    if (!chunk)
    {
        browser_debug_logf(app, "[http] alloc recv buffer failed");
        free(request);
        close(fd);
        return browser_format_error("alloc recv buffer failed");
    }

    if (url->use_tls)
    {
        browser_debug_logf(app, "[tls] handshake start");
        tls_session_t *tls = tls_session_create_fd(fd);
        if (!tls)
        {
            browser_debug_logf(app, "[tls] alloc tls session failed");
            free(chunk);
            free(request);
            close(fd);
            return browser_format_error("alloc tls session failed");
        }

        if (!tls_session_handshake(tls, url->host))
        {
            browser_debug_logf(app, "[tls] handshake failed (see serial log)");
            tls_session_destroy(tls);
            free(chunk);
            free(request);
            close(fd);
            return browser_format_error("tls handshake failed");
        }
        browser_debug_logf(app, "[tls] handshake ok");

        if (!tls_session_send(tls, (const uint8_t *)request, strlen(request)))
        {
            browser_debug_logf(app, "[tls] send failed");
            tls_session_destroy(tls);
            free(chunk);
            free(request);
            close(fd);
            return browser_format_error("tls send failed");
        }

        while (1)
        {
            size_t got = tls_session_recv(tls, chunk, 2048);
            if (got == 0)
            {
                break;
            }

            if (!header_done)
            {
                if (!browser_buf_append(&header_buf, &header_len, &header_cap, chunk, got))
                {
                    tls_session_destroy(tls);
                    free(request);
                    close(fd);
                    free(header_buf);
                    free(body_buf);
                    free(chunk);
                    return browser_format_error("response too large");
                }

                size_t header_block_len = 0;
                size_t body_offset = 0;
                if (!browser_http_find_header_end(header_buf, header_len, &header_block_len, &body_offset))
                {
                    continue;
                }

                header_done = true;

                char status_line[128];
                browser_http_copy_status_line(header_buf, header_block_len, status_line, sizeof(status_line));
                int status = browser_http_parse_status_code(header_buf, header_block_len);
                browser_debug_logf(app, "[http] status %s (code=%d)", status_line, status);

                const char *value = NULL;
                size_t value_len = 0;
                const char *location_value = NULL;
                size_t location_len = 0;
                if (browser_http_find_header_value(header_buf, header_block_len,
                                                   "transfer-encoding",
                                                   &value, &value_len) &&
                    browser_has_token_ci(value, value_len, "chunked"))
                {
                    is_chunked = true;
                    have_content_length = false;
                }

                if (!is_chunked &&
                    browser_http_find_header_value(header_buf, header_block_len,
                                                   "content-length",
                                                   &value, &value_len))
                {
                    size_t parsed_len = 0;
                    if (browser_parse_decimal_size(value, value_len, &parsed_len) &&
                        parsed_len <= BROWSER_MAX_BYTES)
                    {
                        have_content_length = true;
                        content_length = parsed_len;
                    }
                }

                if (browser_http_find_header_value(header_buf, header_block_len,
                                                   "content-type",
                                                   &value, &value_len))
                {
                    char type_buf[96];
                    size_t copy = value_len;
                    if (copy >= sizeof(type_buf))
                    {
                        copy = sizeof(type_buf) - 1;
                    }
                    memcpy(type_buf, value, copy);
                    type_buf[copy] = '\0';
                    browser_debug_logf(app, "[http] content-type %s", type_buf);
                }

                if (browser_http_find_header_value(header_buf, header_block_len,
                                                   "location",
                                                   &value, &value_len))
                {
                    location_value = value;
                    location_len = value_len;
                    char loc_buf[160];
                    size_t copy = value_len;
                    if (copy >= sizeof(loc_buf))
                    {
                        copy = sizeof(loc_buf) - 1;
                    }
                    memcpy(loc_buf, value, copy);
                    loc_buf[copy] = '\0';
                    browser_debug_logf(app, "[http] location %s", loc_buf);
                }

                if (!redirect_target &&
                    (status == 301 || status == 302 || status == 303 || status == 307 || status == 308) &&
                    location_value && location_len > 0 && location_value[0] != '#')
                {
                    if (redirect_depth >= BROWSER_MAX_REDIRECTS)
                    {
                        tls_session_destroy(tls);
                        free(request);
                        close(fd);
                        free(header_buf);
                        free(body_buf);
                        free(chunk);
                        return browser_format_error("too many redirects");
                    }
                    redirect_target = browser_build_absolute_url(url, location_value, location_len);
                    if (!redirect_target)
                    {
                        tls_session_destroy(tls);
                        free(request);
                        close(fd);
                        free(header_buf);
                        free(body_buf);
                        free(chunk);
                        return browser_format_error("redirect allocation failed");
                    }
                    redirect_status = status;
                    browser_debug_logf(app, "[http] redirect %d -> %s", status, redirect_target);

                    free(header_buf);
                    header_buf = NULL;
                    header_len = 0;
                    header_cap = 0;
                    break;
                }

                browser_debug_logf(app,
                                   "[http] transfer=%s content-length=%u",
                                   is_chunked ? "chunked" : "identity",
                                   have_content_length ? (unsigned)content_length : 0u);

                if (header_len > body_offset)
                {
                    size_t body_bytes = header_len - body_offset;
                    if (is_chunked)
                    {
                        bool done = false;
                        if (!browser_chunked_consume(&chunked, &body_buf, &body_len, &body_cap,
                                                     (const uint8_t *)header_buf + body_offset,
                                                     body_bytes,
                                                     &done))
                        {
                            tls_session_destroy(tls);
                            free(request);
                            close(fd);
                            free(header_buf);
                            free(body_buf);
                            free(chunk);
                            return browser_format_error("invalid chunked body");
                        }
                        if (done)
                        {
                            break;
                        }
                    }
                    else
                    {
                        size_t take = body_bytes;
                        if (have_content_length && body_len < content_length)
                        {
                            size_t remaining = content_length - body_len;
                            if (take > remaining)
                            {
                                take = remaining;
                            }
                        }
                        if (take > 0 &&
                            !browser_buf_append(&body_buf, &body_len, &body_cap,
                                                (const uint8_t *)header_buf + body_offset,
                                                take))
                        {
                            tls_session_destroy(tls);
                            free(request);
                            close(fd);
                            free(header_buf);
                            free(body_buf);
                            free(chunk);
                            return browser_format_error("response too large");
                        }
                    }
                }

                free(header_buf);
                header_buf = NULL;
                header_len = 0;
                header_cap = 0;
            }
            else
            {
                if (is_chunked)
                {
                    bool done = false;
                    if (!browser_chunked_consume(&chunked, &body_buf, &body_len, &body_cap,
                                                 chunk, got, &done))
                    {
                        tls_session_destroy(tls);
                        free(request);
                        close(fd);
                        free(body_buf);
                        free(chunk);
                        return browser_format_error("invalid chunked body");
                    }
                    if (done)
                    {
                        break;
                    }
                }
                else
                {
                    size_t take = got;
                    if (have_content_length && body_len < content_length)
                    {
                        size_t remaining = content_length - body_len;
                        if (take > remaining)
                        {
                            take = remaining;
                        }
                    }
                    if (take > 0 &&
                        !browser_buf_append(&body_buf, &body_len, &body_cap, chunk, take))
                    {
                        tls_session_destroy(tls);
                        free(request);
                        close(fd);
                        free(body_buf);
                        free(chunk);
                        return browser_format_error("response too large");
                    }
                }
            }

            if (!is_chunked &&
                have_content_length &&
                body_len >= content_length)
            {
                break;
            }
        }

        tls_session_destroy(tls);
    }
    else
    {
        if (!browser_write_all(fd, (const uint8_t *)request, strlen(request)))
        {
            browser_debug_logf(app, "[http] write failed");
            free(chunk);
            free(request);
            close(fd);
            return browser_format_error("write failed");
        }

        while (1)
        {
            ssize_t got_raw = read(fd, chunk, 2048);
            if (got_raw < 0)
            {
                continue;
            }
            if (got_raw == 0)
            {
                break;
            }

            size_t got = (size_t)got_raw;
            if (!header_done)
            {
                if (!browser_buf_append(&header_buf, &header_len, &header_cap, chunk, got))
                {
                    browser_debug_logf(app, "[http] header too large");
                    free(request);
                    close(fd);
                    free(header_buf);
                    free(body_buf);
                    free(chunk);
                    return browser_format_error("response too large");
                }

                size_t header_block_len = 0;
                size_t body_offset = 0;
                if (!browser_http_find_header_end(header_buf, header_len, &header_block_len, &body_offset))
                {
                    continue;
                }

                header_done = true;

                char status_line[128];
                browser_http_copy_status_line(header_buf, header_block_len, status_line, sizeof(status_line));
                int status = browser_http_parse_status_code(header_buf, header_block_len);
                browser_debug_logf(app, "[http] status %s (code=%d)", status_line, status);

                const char *value = NULL;
                size_t value_len = 0;
                const char *location_value = NULL;
                size_t location_len = 0;
                if (browser_http_find_header_value(header_buf, header_block_len,
                                                   "transfer-encoding",
                                                   &value, &value_len) &&
                    browser_has_token_ci(value, value_len, "chunked"))
                {
                    is_chunked = true;
                    have_content_length = false;
                }

                if (!is_chunked &&
                    browser_http_find_header_value(header_buf, header_block_len,
                                                   "content-length",
                                                   &value, &value_len))
                {
                    size_t parsed_len = 0;
                    if (browser_parse_decimal_size(value, value_len, &parsed_len) &&
                        parsed_len <= BROWSER_MAX_BYTES)
                    {
                        have_content_length = true;
                        content_length = parsed_len;
                    }
                }

                if (browser_http_find_header_value(header_buf, header_block_len,
                                                   "content-type",
                                                   &value, &value_len))
                {
                    char type_buf[96];
                    size_t copy = value_len;
                    if (copy >= sizeof(type_buf))
                    {
                        copy = sizeof(type_buf) - 1;
                    }
                    memcpy(type_buf, value, copy);
                    type_buf[copy] = '\0';
                    browser_debug_logf(app, "[http] content-type %s", type_buf);
                }

                if (browser_http_find_header_value(header_buf, header_block_len,
                                                   "location",
                                                   &value, &value_len))
                {
                    location_value = value;
                    location_len = value_len;
                    char loc_buf[160];
                    size_t copy = value_len;
                    if (copy >= sizeof(loc_buf))
                    {
                        copy = sizeof(loc_buf) - 1;
                    }
                    memcpy(loc_buf, value, copy);
                    loc_buf[copy] = '\0';
                    browser_debug_logf(app, "[http] location %s", loc_buf);
                }

                if (!redirect_target &&
                    (status == 301 || status == 302 || status == 303 || status == 307 || status == 308) &&
                    location_value && location_len > 0 && location_value[0] != '#')
                {
                    if (redirect_depth >= BROWSER_MAX_REDIRECTS)
                    {
                        free(request);
                        close(fd);
                        free(header_buf);
                        free(body_buf);
                        free(chunk);
                        return browser_format_error("too many redirects");
                    }
                    redirect_target = browser_build_absolute_url(url, location_value, location_len);
                    if (!redirect_target)
                    {
                        free(request);
                        close(fd);
                        free(header_buf);
                        free(body_buf);
                        free(chunk);
                        return browser_format_error("redirect allocation failed");
                    }
                    redirect_status = status;
                    browser_debug_logf(app, "[http] redirect %d -> %s", status, redirect_target);

                    free(header_buf);
                    header_buf = NULL;
                    header_len = 0;
                    header_cap = 0;
                    break;
                }

                browser_debug_logf(app,
                                   "[http] transfer=%s content-length=%u",
                                   is_chunked ? "chunked" : "identity",
                                   have_content_length ? (unsigned)content_length : 0u);

                if (header_len > body_offset)
                {
                    size_t body_bytes = header_len - body_offset;
                    if (is_chunked)
                    {
                        bool done = false;
                        if (!browser_chunked_consume(&chunked, &body_buf, &body_len, &body_cap,
                                                     (const uint8_t *)header_buf + body_offset,
                                                     body_bytes,
                                                     &done))
                        {
                            browser_debug_logf(app, "[http] response too large");
                            free(request);
                            close(fd);
                            free(header_buf);
                            free(body_buf);
                            free(chunk);
                            return browser_format_error("invalid chunked body");
                        }
                        if (done)
                        {
                            break;
                        }
                    }
                    else
                    {
                        size_t take = body_bytes;
                        if (have_content_length && body_len < content_length)
                        {
                            size_t remaining = content_length - body_len;
                            if (take > remaining)
                            {
                                take = remaining;
                            }
                        }
                        if (take > 0 &&
                            !browser_buf_append(&body_buf, &body_len, &body_cap,
                                                (const uint8_t *)header_buf + body_offset,
                                                take))
                        {
                            free(request);
                            close(fd);
                            free(header_buf);
                            free(body_buf);
                            free(chunk);
                            return browser_format_error("response too large");
                        }
                    }
                }

                free(header_buf);
                header_buf = NULL;
                header_len = 0;
                header_cap = 0;
            }
            else
            {
                if (is_chunked)
                {
                    bool done = false;
                    if (!browser_chunked_consume(&chunked, &body_buf, &body_len, &body_cap,
                                                 chunk, got, &done))
                    {
                        free(request);
                        close(fd);
                        free(body_buf);
                        free(chunk);
                        return browser_format_error("invalid chunked body");
                    }
                    if (done)
                    {
                        break;
                    }
                }
                else
                {
                    size_t take = got;
                    if (have_content_length && body_len < content_length)
                    {
                        size_t remaining = content_length - body_len;
                        if (take > remaining)
                        {
                            take = remaining;
                        }
                    }
                    if (take > 0 &&
                        !browser_buf_append(&body_buf, &body_len, &body_cap, chunk, take))
                    {
                        browser_debug_logf(app, "[http] response too large");
                        free(request);
                        close(fd);
                        free(body_buf);
                        free(chunk);
                        return browser_format_error("response too large");
                    }
                }
            }

            if (!is_chunked &&
                have_content_length &&
                body_len >= content_length)
            {
                break;
            }
        }
    }

    free(request);
    close(fd);
    free(chunk);

    if (header_buf)
    {
        free(header_buf);
        header_buf = NULL;
    }

    if (redirect_target)
    {
        if (body_buf)
        {
            free(body_buf);
            body_buf = NULL;
        }

        browser_url_t next = {0};
        if (!browser_parse_url(redirect_target, &next))
        {
            browser_debug_logf(app, "[http] redirect parse failed");
            free(redirect_target);
            return browser_format_error("invalid redirect url");
        }
        browser_debug_logf(app, "[http] follow redirect %d depth=%d url=%s",
                           redirect_status,
                           redirect_depth + 1,
                           redirect_target);
        free(redirect_target);
        char *res = browser_fetch_http_internal(app, &next, redirect_depth + 1, body_len_out, final_url_out);
        browser_url_destroy(&next);
        return res;
    }

    if (have_content_length && body_len < content_length)
    {
        browser_debug_logf(app, "[http] incomplete body got=%u expected=%u",
                           (unsigned)body_len, (unsigned)content_length);
        free(body_buf);
        return browser_format_error("incomplete response body");
    }

    if (!body_buf)
    {
        browser_debug_logf(app, "[http] empty response body");
        return browser_format_error("empty response");
    }

    browser_debug_logf(app, "[http] body bytes=%u", (unsigned)body_len);
    if (body_len_out)
    {
        *body_len_out = body_len;
    }
    if (final_url_out)
    {
        (void)browser_url_clone(url, final_url_out);
    }
    return body_buf;
}

char *browser_fetch_http(browser_app_t *app,
                         const browser_url_t *url,
                         size_t *body_len_out,
                         browser_url_t *final_url_out)
{
    char *url_text = browser_url_to_string(url);
    if (url_text)
    {
        char *cached = browser_cache_read(app, url_text, body_len_out);
        if (cached)
        {
            if (final_url_out)
            {
                (void)browser_url_clone(url, final_url_out);
            }
            free(url_text);
            return cached;
        }
    }

    char *body = browser_fetch_http_internal(app, url, 0, body_len_out, final_url_out);
    if (body && url_text && body_len_out && *body_len_out > 0 &&
        strncmp(body, "Error:\n", 6) != 0)
    {
        browser_cache_write(app, url_text, (const uint8_t *)body, *body_len_out);
    }
    free(url_text);
    return body;
}
