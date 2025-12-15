#include "atk_user.h"

#include "atk.h"
#include "atk_app.h"
#include "atk_internal.h"
#include "atk_menu_bar.h"
#include "atk_window.h"
#include "atk/layout.h"
#include "atk/atk_rich_text.h"
#include "atk/atk_text_input.h"
#include "libc.h"
#include "net/tls.h"
#include "serial.h"
#include "stdio.h"
#include "video.h"

#define BROWSER_WIDTH  1000
#define BROWSER_HEIGHT 720
#define BROWSER_MARGIN 14
#define BROWSER_GAP    10
#define BROWSER_MAX_BYTES (2u * 1024u * 1024u)

typedef struct
{
    bool use_tls;
    uint16_t port;
    char *host;
    char *path;
} browser_url_t;

typedef struct
{
    atk_user_window_t remote;
    atk_widget_t *window;
    atk_widget_t *url_input;
    atk_widget_t *viewer;

    alix_mutex_t lock;
    bool fetch_running;
    alix_thread_t fetch_thread;
    char *pending_text;
    bool pending_ready;
} browser_app_t;

static void apply_theme(atk_state_t *state)
{
    if (!state)
    {
        return;
    }
    state->theme.background = video_make_color(0x12, 0x16, 0x1F);
    state->theme.window_border = video_make_color(0x2F, 0x38, 0x46);
    state->theme.window_title = video_make_color(0x28, 0x6A, 0xA8);
    state->theme.window_title_text = video_make_color(0xF3, 0xF5, 0xF7);
    state->theme.window_body = video_make_color(0x1B, 0x22, 0x2F);
    state->theme.button_face = video_make_color(0x28, 0x36, 0x48);
    state->theme.button_border = video_make_color(0x14, 0x1B, 0x26);
    state->theme.button_text = video_make_color(0xE4, 0xE9, 0xEF);
    state->theme.desktop_icon_face = video_make_color(0x3A, 0x78, 0xB0);
    state->theme.desktop_icon_text = state->theme.window_title_text;
    atk_state_theme_commit(state);
}

static char *browser_strdup(const char *src)
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

static bool browser_parse_url(const char *input, browser_url_t *out)
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

static void browser_url_destroy(browser_url_t *url)
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

static bool browser_write_all(int fd, const uint8_t *data, size_t len)
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

static bool browser_buf_append(char **buf, size_t *len, size_t *cap, const uint8_t *data, size_t data_len)
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

static bool browser_has_token_ci(const char *value, size_t value_len, const char *token)
{
    if (!value || value_len == 0 || !token || token[0] == '\0')
    {
        return false;
    }
    size_t token_len = strlen(token);
    if (token_len == 0 || token_len > value_len)
    {
        return false;
    }
    for (size_t i = 0; i + token_len <= value_len; ++i)
    {
        if (strncasecmp(value + i, token, token_len) == 0)
        {
            return true;
        }
    }
    return false;
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
        if (c >= '0' && c <= '9') d = (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') d = 10u + (unsigned)(c - 'a');
        else if (c >= 'A' && c <= 'F') d = 10u + (unsigned)(c - 'A');
        else return false;

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
    const char *fmt = "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\nUser-Agent: atk_browser/0.1\r\n\r\n";
    size_t cap = strlen(fmt) + strlen(host) + strlen(path) + 32;
    char *req = (char *)malloc(cap);
    if (!req)
    {
        return NULL;
    }
    snprintf(req, cap, fmt, path, host);
    return req;
}

static char *browser_fetch_http(const browser_url_t *url)
{
    if (!url || !url->host || !url->path)
    {
        return browser_format_error("invalid url");
    }

    int fd = socket_open(NULL);
    if (fd < 0)
    {
        return browser_format_error("socket_open failed");
    }

    if (socket_connect(fd, url->host, url->port) != 0)
    {
        close(fd);
        return browser_format_error("socket_connect failed");
    }

    char *request = browser_build_request(url->host, url->path);
    if (!request)
    {
        close(fd);
        return browser_format_error("alloc request failed");
    }

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

    uint8_t *chunk = (uint8_t *)malloc(2048);
    if (!chunk)
    {
        free(request);
        close(fd);
        return browser_format_error("alloc recv buffer failed");
    }

    if (url->use_tls)
    {
        tls_session_t *tls = (tls_session_t *)malloc(sizeof(*tls));
        if (!tls)
        {
            free(chunk);
            free(request);
            close(fd);
            return browser_format_error("alloc tls session failed");
        }

        if (!tls_session_init_fd(tls, fd))
        {
            free(tls);
            free(chunk);
            free(request);
            close(fd);
            return browser_format_error("tls_session_init_fd failed");
        }

        if (!tls_session_handshake(tls, url->host))
        {
            tls_session_close(tls);
            free(tls);
            free(chunk);
            free(request);
            close(fd);
            return browser_format_error("tls handshake failed");
        }

        if (!tls_session_send(tls, (const uint8_t *)request, strlen(request)))
        {
            tls_session_close(tls);
            free(tls);
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
                    tls_session_close(tls);
                    free(tls);
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

                const char *value = NULL;
                size_t value_len = 0;
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
                            tls_session_close(tls);
                            free(tls);
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
                            tls_session_close(tls);
                            free(tls);
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
                        tls_session_close(tls);
                        free(tls);
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
                        tls_session_close(tls);
                        free(tls);
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

        tls_session_close(tls);
        free(tls);
    }
    else
    {
        if (!browser_write_all(fd, (const uint8_t *)request, strlen(request)))
        {
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

                const char *value = NULL;
                size_t value_len = 0;
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

    if (have_content_length && body_len < content_length)
    {
        free(body_buf);
        return browser_format_error("incomplete response body");
    }

    if (!body_buf)
    {
        return browser_format_error("empty response");
    }

    return body_buf;
}

static void browser_fetch_thread(void *arg)
{
    browser_app_t *app = (browser_app_t *)arg;
    if (!app)
    {
        return;
    }

    char *url_text = NULL;
    alix_mutex_lock(&app->lock);
    url_text = app->pending_text;
    app->pending_text = NULL;
    alix_mutex_unlock(&app->lock);

    if (!url_text)
    {
        alix_mutex_lock(&app->lock);
        app->pending_text = browser_format_error("missing url");
        app->pending_ready = true;
        app->fetch_running = false;
        alix_mutex_unlock(&app->lock);
        return;
    }

    browser_url_t url;
    char *result = NULL;
    if (!browser_parse_url(url_text, &url))
    {
        result = browser_format_error("invalid url");
    }
    else
    {
        result = browser_fetch_http(&url);
    }
    browser_url_destroy(&url);
    free(url_text);

    if (!result)
    {
        result = browser_format_error("allocation failed");
    }

    alix_mutex_lock(&app->lock);
    if (app->pending_text)
    {
        free(app->pending_text);
    }
    app->pending_text = result;
    app->pending_ready = true;
    app->fetch_running = false;
    alix_mutex_unlock(&app->lock);
}

static void on_url_submit(atk_widget_t *input, void *context)
{
    browser_app_t *app = (browser_app_t *)context;
    if (!app || !input)
    {
        return;
    }
    const char *text = atk_text_input_text(input);
    if (!text || text[0] == '\0')
    {
        return;
    }

    alix_mutex_lock(&app->lock);
    bool busy = app->fetch_running;
    alix_mutex_unlock(&app->lock);
    if (busy)
    {
        atk_rich_text_set_text(app->viewer, "Already loading...\n");
        atk_window_mark_dirty(app->window);
        return;
    }

    char *url_copy = browser_strdup(text);
    if (!url_copy)
    {
        atk_rich_text_set_text(app->viewer, "Allocation failed.\n");
        atk_window_mark_dirty(app->window);
        return;
    }

    alix_mutex_lock(&app->lock);
    if (app->pending_text)
    {
        free(app->pending_text);
    }
    app->pending_text = url_copy;
    app->pending_ready = false;
    app->fetch_running = true;
    alix_mutex_unlock(&app->lock);

    atk_rich_text_set_text(app->viewer, "Loading...\n");
    atk_window_mark_dirty(app->window);

    if (alix_thread_create(&app->fetch_thread, "atk_browser_fetch", browser_fetch_thread, app) != 0)
    {
        alix_mutex_lock(&app->lock);
        app->fetch_running = false;
        if (app->pending_text)
        {
            free(app->pending_text);
            app->pending_text = NULL;
        }
        alix_mutex_unlock(&app->lock);
        atk_rich_text_set_text(app->viewer, "Failed to start fetch thread.\n");
        atk_window_mark_dirty(app->window);
    }
}

static bool browser_tick(void *context)
{
    browser_app_t *app = (browser_app_t *)context;
    if (!app)
    {
        return false;
    }

    char *text = NULL;
    bool ready = false;
    alix_thread_t join_thread = 0;

    alix_mutex_lock(&app->lock);
    if (app->pending_ready)
    {
        ready = true;
        text = app->pending_text;
        app->pending_text = NULL;
        app->pending_ready = false;
        join_thread = app->fetch_thread;
        app->fetch_thread = 0;
    }
    alix_mutex_unlock(&app->lock);

    if (!ready)
    {
        return false;
    }

    if (join_thread != 0)
    {
        (void)alix_thread_join(join_thread, NULL);
    }

    if (!text)
    {
        return false;
    }

    atk_rich_text_set_text(app->viewer, text);
    free(text);
    atk_window_mark_dirty(app->window);
    return true;
}

static bool build_ui(browser_app_t *app)
{
    if (!app)
    {
        return false;
    }

    atk_init();
    atk_state_t *state = atk_state_get();
    atk_menu_bar_set_enabled(state, false);
    apply_theme(state);

    app->window = atk_window_create_at(state, BROWSER_WIDTH / 2, BROWSER_HEIGHT / 2);
    if (!app->window)
    {
        return false;
    }

    atk_window_set_chrome_visible(app->window, false);
    atk_window_set_title_text(app->window, "atk_browser");
    app->window->x = 0;
    app->window->y = 0;
    app->window->width = BROWSER_WIDTH;
    app->window->height = BROWSER_HEIGHT;
    atk_window_ensure_inside(app->window);

    int chrome_top = atk_window_is_chrome_visible(app->window) ? ATK_WINDOW_TITLE_HEIGHT : 0;
    int content_x = BROWSER_MARGIN;
    int content_y = chrome_top + BROWSER_MARGIN;
    int content_w = app->window->width - BROWSER_MARGIN * 2;
    int content_h = app->window->height - content_y - BROWSER_MARGIN;

    app->url_input = atk_window_add_text_input(app->window, content_x, content_y, content_w);
    if (!app->url_input)
    {
        return false;
    }
    atk_text_input_set_text(app->url_input, "https://example.com/");
    atk_text_input_set_submit_handler(app->url_input, on_url_submit, app);
    atk_text_input_focus(state, app->url_input);

    int url_h = app->url_input->height;
    int viewer_y = content_y + url_h + BROWSER_GAP;
    int viewer_h = (content_y + content_h) - viewer_y;
    if (viewer_h < 16)
    {
        viewer_h = 16;
    }

    app->viewer = atk_window_add_rich_text(app->window,
                                           content_x,
                                           viewer_y,
                                           content_w,
                                           viewer_h);
    if (!app->viewer)
    {
        return false;
    }
    atk_widget_set_layout(app->viewer,
                          ATK_WIDGET_ANCHOR_LEFT | ATK_WIDGET_ANCHOR_RIGHT |
                          ATK_WIDGET_ANCHOR_TOP | ATK_WIDGET_ANCHOR_BOTTOM);
    atk_rich_text_set_pagination_enabled(app->viewer, false);
    atk_rich_text_set_read_only(app->viewer, true);
    atk_rich_text_set_text(app->viewer, "Enter a URL above and press Enter.\n");
    return true;
}

int main(void)
{
    browser_app_t app = {0};
    alix_mutex_init(&app.lock);

    if (!atk_user_window_open(&app.remote, "atk_browser", BROWSER_WIDTH, BROWSER_HEIGHT))
    {
        printf("atk_browser: failed to open window\n");
        return 1;
    }
    atk_user_enable_dirty_tracking(&app.remote, true);

    if (!build_ui(&app))
    {
        printf("atk_browser: failed to init UI\n");
        atk_user_close(&app.remote);
        return 1;
    }

    atk_render();
    atk_user_present_force(&app.remote);

    atk_main_config_t main_cfg = {
        .window = &app.remote,
        .tick = browser_tick,
        .tick_context = &app,
        .present_on_idle = false,
        .legacy_input = false
    };
    atk_main(&main_cfg);

    atk_user_close(&app.remote);
    return 0;
}
