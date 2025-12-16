#include "atk_user.h"

#include "atk.h"
#include "atk_app.h"
#include "atk_internal.h"
#include "atk_menu_bar.h"
#include "atk_window.h"
#include "atk/layout.h"
#include "atk/atk_html_view.h"
#include "atk/atk_font.h"
#include "atk/atk_menu.h"
#include "atk/atk_rich_text.h"
#include "atk/atk_text_input.h"
#include "libc.h"
#include "net/tls.h"
#include "serial.h"
#include "stdarg.h"
#include "stdio.h"
#include "video.h"
#include "web/html.h"

#define BROWSER_WIDTH  1000
#define BROWSER_HEIGHT 720
#define BROWSER_MARGIN 14
#define BROWSER_GAP    10
#define BROWSER_MAX_BYTES (2u * 1024u * 1024u)
#define BROWSER_DEBUG_LOG_MAX_BYTES (256u * 1024u)
#define BROWSER_DEBUG_WINDOW_WIDTH  860
#define BROWSER_DEBUG_WINDOW_HEIGHT 420

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
    atk_widget_t *menu_button;
    atk_widget_t *menu_browser;
    atk_widget_t *menu_open;
    atk_widget_t *url_input;
    atk_widget_t *viewer;

    alix_mutex_t lock;
    bool fetch_running;
    alix_thread_t fetch_thread;
    char *pending_text;
    bool pending_ready;

    atk_modal_session_t debug_modal;
    atk_widget_t *debug_window;
    atk_widget_t *debug_text;
    char *debug_log;
    size_t debug_log_len;
    size_t debug_log_cap;
    size_t debug_log_flush_offset;
    bool debug_log_resync;
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

static const html_node_t *browser_dom_find_first_element(const html_node_t *root, const char *tag)
{
    if (!root || !tag || tag[0] == '\0')
    {
        return NULL;
    }

    const html_node_t *stack[64];
    size_t sp = 0;
    stack[sp++] = root;

    while (sp > 0)
    {
        const html_node_t *node = stack[--sp];
        if (node->type == HTML_NODE_ELEMENT && node->name && strcmp(node->name, tag) == 0)
        {
            return node;
        }
        for (const html_node_t *child = node->last_child; child; child = child->prev_sibling)
        {
            if (sp < sizeof(stack) / sizeof(stack[0]))
            {
                stack[sp++] = child;
            }
        }
    }
    return NULL;
}

static const char *browser_dom_first_text_child(const html_node_t *node)
{
    if (!node)
    {
        return NULL;
    }
    for (const html_node_t *child = node->first_child; child; child = child->next_sibling)
    {
        if (child->type == HTML_NODE_TEXT && child->text && child->text[0] != '\0')
        {
            return child->text;
        }
    }
    return NULL;
}

static size_t browser_dom_count_nodes(const html_node_t *root, size_t limit)
{
    if (!root)
    {
        return 0;
    }
    if (limit == 0)
    {
        limit = 1;
    }

    const html_node_t *stack[128];
    size_t sp = 0;
    stack[sp++] = root;
    size_t count = 0;

    while (sp > 0 && count < limit)
    {
        const html_node_t *node = stack[--sp];
        count++;
        for (const html_node_t *child = node->last_child; child; child = child->prev_sibling)
        {
            if (sp < sizeof(stack) / sizeof(stack[0]))
            {
                stack[sp++] = child;
            }
        }
    }
    return count;
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

static void browser_debug_log_trim_locked(browser_app_t *app)
{
    if (!app || !app->debug_log)
    {
        return;
    }

    if (app->debug_log_len <= BROWSER_DEBUG_LOG_MAX_BYTES)
    {
        return;
    }

    size_t excess = app->debug_log_len - BROWSER_DEBUG_LOG_MAX_BYTES;
    size_t drop = excess;
    while (drop < app->debug_log_len && app->debug_log[drop] != '\n')
    {
        drop++;
    }
    if (drop < app->debug_log_len)
    {
        drop++;
    }
    if (drop == 0 || drop > app->debug_log_len)
    {
        return;
    }

    memmove(app->debug_log, app->debug_log + drop, app->debug_log_len - drop + 1);
    app->debug_log_len -= drop;
    app->debug_log_flush_offset = 0;
    app->debug_log_resync = true;
}

static void browser_debug_log_append_locked(browser_app_t *app, const char *data, size_t len)
{
    if (!app || !data || len == 0)
    {
        return;
    }

    size_t needed = app->debug_log_len + len + 1;
    if (needed > app->debug_log_cap)
    {
        size_t new_cap = app->debug_log_cap ? app->debug_log_cap : 1024;
        while (new_cap < needed)
        {
            new_cap *= 2;
        }
        char *next = (char *)realloc(app->debug_log, new_cap);
        if (!next)
        {
            return;
        }
        app->debug_log = next;
        app->debug_log_cap = new_cap;
    }

    memcpy(app->debug_log + app->debug_log_len, data, len);
    app->debug_log_len += len;
    app->debug_log[app->debug_log_len] = '\0';

    browser_debug_log_trim_locked(app);
}

static void browser_debug_log_line(browser_app_t *app, const char *line)
{
    if (!app || !line)
    {
        return;
    }
    size_t len = strlen(line);

    alix_mutex_lock(&app->lock);
    browser_debug_log_append_locked(app, line, len);
    if (len == 0 || line[len - 1] != '\n')
    {
        browser_debug_log_append_locked(app, "\n", 1);
    }
    alix_mutex_unlock(&app->lock);
}

static bool browser_debug_flush(browser_app_t *app);
static void browser_debug_open_window(browser_app_t *app);
static void browser_debug_clear(browser_app_t *app);

static void browser_debug_logf(browser_app_t *app, const char *fmt, ...)
{
    if (!app || !fmt)
    {
        return;
    }

    char stack_buf[256];
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(stack_buf, sizeof(stack_buf), fmt, args);
    va_end(args);

    if (n < 0)
    {
        return;
    }

    if ((size_t)n < sizeof(stack_buf))
    {
        browser_debug_log_line(app, stack_buf);
        return;
    }

    size_t len = (size_t)n;
    char *heap_buf = (char *)malloc(len + 1);
    if (!heap_buf)
    {
        browser_debug_log_line(app, "<debug log alloc failed>");
        return;
    }

    va_start(args, fmt);
    (void)vsnprintf(heap_buf, len + 1, fmt, args);
    va_end(args);

    browser_debug_log_line(app, heap_buf);
    free(heap_buf);
}

static void browser_menu_open_debug(void *context)
{
    browser_app_t *app = (browser_app_t *)context;
    if (app)
    {
        if (app->menu_browser)
        {
            atk_menu_hide(app->menu_browser);
        }
        app->menu_open = NULL;
    }
    browser_debug_open_window(app);
}

static void browser_menu_clear_debug(void *context)
{
    browser_app_t *app = (browser_app_t *)context;
    if (app)
    {
        if (app->menu_browser)
        {
            atk_menu_hide(app->menu_browser);
        }
        app->menu_open = NULL;
    }
    browser_debug_clear(app);
}

static void browser_debug_window_on_destroy(void *context)
{
    browser_app_t *app = (browser_app_t *)context;
    if (!app)
    {
        return;
    }

    alix_mutex_lock(&app->lock);
    app->debug_window = NULL;
    app->debug_text = NULL;
    app->debug_log_flush_offset = 0;
    app->debug_log_resync = true;
    alix_mutex_unlock(&app->lock);
}

static void browser_debug_close_window(browser_app_t *app)
{
    if (!app)
    {
        return;
    }

    atk_state_t *state = atk_state_get();
    if (state && app->debug_window && app->debug_window->used)
    {
        atk_window_close(state, app->debug_window);
    }
    app->debug_window = NULL;
    app->debug_text = NULL;

    if (app->debug_modal.active)
    {
        atk_modal_end(&app->debug_modal);
    }
}

static void browser_on_close_event(void *context)
{
    browser_app_t *app = (browser_app_t *)context;
    if (!app)
    {
        atk_main_request_exit();
        return;
    }

    if (app->debug_modal.active)
    {
        browser_debug_close_window(app);
        return;
    }

    atk_main_request_exit();
}

static void browser_debug_open_window(browser_app_t *app)
{
    if (!app)
    {
        return;
    }

    atk_state_t *state = atk_state_get();
    if (!state)
    {
        return;
    }

    if (app->debug_modal.active)
    {
        (void)browser_debug_flush(app);
        return;
    }

    alix_mutex_lock(&app->lock);
    atk_widget_t *existing = app->debug_window;
    atk_widget_t *existing_text = app->debug_text;
    alix_mutex_unlock(&app->lock);

    if (existing && existing->used)
    {
        if (existing_text && existing_text->used)
        {
            atk_rich_text_scroll_to_bottom(existing_text);
        }
        atk_window_mark_dirty(existing);
        return;
    }

    if (!atk_modal_begin(&app->debug_modal,
                         "Browser Debug",
                         BROWSER_DEBUG_WINDOW_WIDTH,
                         BROWSER_DEBUG_WINDOW_HEIGHT,
                         0,
                         app->window))
    {
        return;
    }

    int screen_w = video_screen_width();
    int screen_h = video_screen_height();
    if (screen_w <= 0)
    {
        screen_w = (int)BROWSER_DEBUG_WINDOW_WIDTH;
    }
    if (screen_h <= 0)
    {
        screen_h = (int)BROWSER_DEBUG_WINDOW_HEIGHT;
    }

    atk_widget_t *window = atk_window_create_at(state, screen_w / 2, screen_h / 2);
    if (!window)
    {
        atk_modal_end(&app->debug_modal);
        return;
    }

    atk_window_set_chrome_visible(window, false);
    atk_window_set_title_text(window, "Browser Debug");
    window->x = 0;
    window->y = 0;
    window->width = screen_w;
    window->height = screen_h;
    atk_window_ensure_inside(window);
    atk_window_set_context(window, app, browser_debug_window_on_destroy);
    atk_window_bring_to_front(state, window);

    int chrome_top = atk_window_is_chrome_visible(window) ? ATK_WINDOW_TITLE_HEIGHT : 0;
    int margin = 10;
    int content_x = margin;
    int content_y = chrome_top + margin;
    int content_w = window->width - margin * 2;
    int content_h = window->height - content_y - margin;
    if (content_w < 16) content_w = 16;
    if (content_h < 16) content_h = 16;

    atk_widget_t *editor = atk_window_add_rich_text(window, content_x, content_y, content_w, content_h);
    if (!editor)
    {
        atk_window_close(state, window);
        return;
    }
    atk_widget_set_layout(editor,
                          ATK_WIDGET_ANCHOR_LEFT | ATK_WIDGET_ANCHOR_RIGHT |
                          ATK_WIDGET_ANCHOR_TOP | ATK_WIDGET_ANCHOR_BOTTOM);
    atk_rich_text_set_read_only(editor, true);

    alix_mutex_lock(&app->lock);
    app->debug_window = window;
    app->debug_text = editor;
    app->debug_log_flush_offset = 0;
    app->debug_log_resync = true;
    alix_mutex_unlock(&app->lock);
    (void)browser_debug_flush(app);
    atk_window_mark_dirty(window);
}

static bool browser_menu_button_hit_test(const atk_widget_t *button, int px, int py)
{
    if (!button || !button->used)
    {
        return false;
    }

    int origin_x = 0;
    int origin_y = 0;
    if (button->parent)
    {
        atk_widget_absolute_position(button->parent, &origin_x, &origin_y);
    }
    return atk_button_hit_test(button, origin_x, origin_y, px, py);
}

static void browser_menus_close(browser_app_t *app)
{
    if (!app)
    {
        return;
    }

    if (app->menu_browser)
    {
        atk_menu_hide(app->menu_browser);
    }
    app->menu_open = NULL;
    if (app->window)
    {
        atk_window_mark_dirty(app->window);
    }
}

static void browser_menu_toggle(browser_app_t *app, atk_widget_t *menu, atk_widget_t *button)
{
    if (!app || !app->window || !menu || !button)
    {
        return;
    }

    bool already_open = (app->menu_open == menu) && atk_menu_is_visible(menu);
    browser_menus_close(app);
    if (already_open)
    {
        return;
    }

    atk_window_priv_t *wpriv = (atk_window_priv_t *)atk_widget_priv(app->window, &ATK_WINDOW_CLASS);
    if (wpriv)
    {
        atk_list_node_t *node = atk_list_find(&wpriv->children, menu);
        if (node)
        {
            atk_list_move_to_back(&wpriv->children, node);
        }
    }

    int menu_x = button->x;
    int menu_y = button->y + button->height;
    atk_menu_show(menu, menu_x, menu_y);
    if (menu->width < button->width)
    {
        menu->width = button->width;
    }
    if (menu->width > app->window->width)
    {
        menu->width = app->window->width;
    }
    if (menu->x + menu->width > app->window->width - 2)
    {
        menu->x = app->window->width - menu->width - 2;
    }
    if (menu->x < 0)
    {
        menu->x = 0;
    }

    app->menu_open = menu;
    atk_window_mark_dirty(app->window);
}

static void on_menu_button(atk_widget_t *button, void *context)
{
    browser_app_t *app = (browser_app_t *)context;
    if (!app || !button)
    {
        return;
    }

    if (button == app->menu_button)
    {
        browser_menu_toggle(app, app->menu_browser, app->menu_button);
    }
}

static bool browser_on_mouse_event(const user_atk_event_t *event, void *context)
{
    browser_app_t *app = (browser_app_t *)context;
    if (!app || !event)
    {
        return false;
    }

    bool left = (event->flags & USER_ATK_MOUSE_FLAG_LEFT) != 0;
    bool press = (event->flags & USER_ATK_MOUSE_FLAG_PRESS) != 0;
    if (left && press && app->menu_open && atk_menu_is_visible(app->menu_open))
    {
        int px = event->x;
        int py = event->y;
        bool inside_menu = atk_menu_contains(app->menu_open, px, py);
        bool inside_button = browser_menu_button_hit_test(app->menu_button, px, py);
        if (!inside_menu && !inside_button)
        {
            browser_menus_close(app);
        }
    }

    return false;
}

static void browser_debug_clear(browser_app_t *app)
{
    if (!app)
    {
        return;
    }

    atk_widget_t *editor = NULL;
    alix_mutex_lock(&app->lock);
    if (app->debug_log)
    {
        app->debug_log[0] = '\0';
    }
    app->debug_log_len = 0;
    app->debug_log_flush_offset = 0;
    app->debug_log_resync = false;
    editor = app->debug_text;
    alix_mutex_unlock(&app->lock);

    if (editor && editor->used)
    {
        atk_rich_text_set_text(editor, "");
        atk_rich_text_scroll_to_top(editor);
    }
}

static bool browser_debug_flush(browser_app_t *app)
{
    if (!app)
    {
        return false;
    }

    atk_widget_t *editor = NULL;
    atk_widget_t *window = NULL;
    bool resync = false;
    char *chunk = NULL;

    alix_mutex_lock(&app->lock);
    editor = app->debug_text;
    window = app->debug_window;

    if (!editor || !editor->used)
    {
        alix_mutex_unlock(&app->lock);
        return false;
    }

    if (app->debug_log_resync)
    {
        resync = true;
        size_t log_len = app->debug_log ? app->debug_log_len : 0;
        chunk = (char *)malloc(log_len + 1);
        if (!chunk)
        {
            alix_mutex_unlock(&app->lock);
            return false;
        }
        if (log_len > 0 && app->debug_log)
        {
            memcpy(chunk, app->debug_log, log_len);
        }
        chunk[log_len] = '\0';
        app->debug_log_flush_offset = log_len;
        app->debug_log_resync = false;
    }
    else if (app->debug_log && app->debug_log_flush_offset < app->debug_log_len)
    {
        size_t start = app->debug_log_flush_offset;
        size_t len = app->debug_log_len - start;
        chunk = (char *)malloc(len + 1);
        if (!chunk)
        {
            alix_mutex_unlock(&app->lock);
            return false;
        }
        memcpy(chunk, app->debug_log + start, len);
        chunk[len] = '\0';
        app->debug_log_flush_offset = app->debug_log_len;
    }
    alix_mutex_unlock(&app->lock);

    if (!chunk)
    {
        return false;
    }

    if (resync)
    {
        atk_rich_text_set_text(editor, chunk);
    }
    else
    {
        atk_rich_text_append(editor, chunk);
    }
    atk_rich_text_scroll_to_bottom(editor);
    free(chunk);

    if (window && window->used)
    {
        atk_window_mark_dirty(window);
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

static char *browser_fetch_http(browser_app_t *app, const browser_url_t *url)
{
    if (!url || !url->host || !url->path)
    {
        browser_debug_logf(app, "[fetch] invalid url (missing host/path)");
        return browser_format_error("invalid url");
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
        tls_session_t *tls = (tls_session_t *)malloc(sizeof(*tls));
        if (!tls)
        {
            browser_debug_logf(app, "[tls] alloc tls session failed");
            free(chunk);
            free(request);
            close(fd);
            return browser_format_error("alloc tls session failed");
        }

        if (!tls_session_init_fd(tls, fd))
        {
            browser_debug_logf(app, "[tls] tls_session_init_fd failed");
            free(tls);
            free(chunk);
            free(request);
            close(fd);
            return browser_format_error("tls_session_init_fd failed");
        }

        if (!tls_session_handshake(tls, url->host))
        {
            browser_debug_logf(app, "[tls] handshake failed (see serial log)");
            tls_session_close(tls);
            free(tls);
            free(chunk);
            free(request);
            close(fd);
            return browser_format_error("tls handshake failed");
        }
        browser_debug_logf(app, "[tls] handshake ok");

        if (!tls_session_send(tls, (const uint8_t *)request, strlen(request)))
        {
            browser_debug_logf(app, "[tls] send failed");
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

                char status_line[128];
                browser_http_copy_status_line(header_buf, header_block_len, status_line, sizeof(status_line));
                int status = browser_http_parse_status_code(header_buf, header_block_len);
                browser_debug_logf(app, "[http] status %s (code=%d)", status_line, status);

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

    browser_debug_logf(app, "[fetch] thread start url=%s", url_text ? url_text : "(null)");

    if (!url_text)
    {
        alix_mutex_lock(&app->lock);
        app->pending_text = browser_format_error("missing url");
        app->pending_ready = true;
        app->fetch_running = false;
        alix_mutex_unlock(&app->lock);
        browser_debug_logf(app, "[fetch] missing url");
        return;
    }

    browser_url_t url;
    char *result = NULL;
    if (!browser_parse_url(url_text, &url))
    {
        browser_debug_logf(app, "[fetch] invalid url");
        result = browser_format_error("invalid url");
    }
    else
    {
        browser_debug_logf(app,
                           "[fetch] parsed tls=%d host=%s port=%u path=%s",
                           url.use_tls ? 1 : 0,
                           url.host ? url.host : "(null)",
                           (unsigned)url.port,
                           url.path ? url.path : "(null)");
        result = browser_fetch_http(app, &url);
    }
    browser_url_destroy(&url);
    free(url_text);

    if (!result)
    {
        browser_debug_logf(app, "[fetch] result null (allocation failed)");
        result = browser_format_error("allocation failed");
    }
    else if (strncmp(result, "Error:\n", 6) == 0)
    {
        const char *msg = result + 6;
        char preview[96];
        size_t mlen = strlen(msg);
        size_t copy = mlen;
        if (copy >= sizeof(preview))
        {
            copy = sizeof(preview) - 1;
        }
        memcpy(preview, msg, copy);
        preview[copy] = '\0';
        browser_debug_logf(app, "[fetch] error %s", preview);
    }
    else
    {
        browser_debug_logf(app, "[fetch] success bytes=%u", (unsigned)strlen(result));
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
    browser_debug_logf(app, "[ui] submit url=%s", text);

    alix_mutex_lock(&app->lock);
    bool busy = app->fetch_running;
    alix_mutex_unlock(&app->lock);
    if (busy)
    {
        browser_debug_logf(app, "[ui] already loading");
        (void)atk_html_view_set_html(app->viewer,
                                     "<!doctype html><html><body><p>Already loading...</p></body></html>",
                                     NULL);
        atk_window_mark_dirty(app->window);
        return;
    }

    char *url_copy = browser_strdup(text);
    if (!url_copy)
    {
        browser_debug_logf(app, "[ui] allocation failed (url_copy)");
        (void)atk_html_view_set_html(app->viewer,
                                     "<!doctype html><html><body><p>Allocation failed.</p></body></html>",
                                     NULL);
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

    (void)atk_html_view_set_html(app->viewer,
                                 "<!doctype html><html><body><p>Loading...</p></body></html>",
                                 NULL);
    atk_window_mark_dirty(app->window);

    if (alix_thread_create(&app->fetch_thread, "atk_browser_fetch", browser_fetch_thread, app) != 0)
    {
        browser_debug_logf(app, "[ui] failed to start fetch thread");
        alix_mutex_lock(&app->lock);
        app->fetch_running = false;
        if (app->pending_text)
        {
            free(app->pending_text);
            app->pending_text = NULL;
        }
        alix_mutex_unlock(&app->lock);
        (void)atk_html_view_set_html(app->viewer,
                                     "<!doctype html><html><body><p>Failed to start fetch thread.</p></body></html>",
                                     NULL);
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

    bool redraw = false;
    if (browser_debug_flush(app))
    {
        redraw = true;
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
        return redraw;
    }

    if (join_thread != 0)
    {
        (void)alix_thread_join(join_thread, NULL);
    }

    if (!text)
    {
        return false;
    }

    browser_debug_logf(app, "[ui] document ready bytes=%u", (unsigned)strlen(text));

    if (strncmp(text, "Error:\n", 6) == 0)
    {
        const char *msg = text + 6;
        char page[512];
        snprintf(page,
                 sizeof(page),
                 "<!doctype html><html><body><p>Fetch error:</p><p>%s</p></body></html>",
                 msg ? msg : "unknown");
        (void)atk_html_view_set_html(app->viewer, page, NULL);
        browser_debug_logf(app, "[render] showing fetch error page");
        free(text);
        atk_window_mark_dirty(app->window);
        return true;
    }

    html_parse_error_t parse_err = {0};
    html_document_t *doc = html_parse(text, &parse_err);
    if (doc)
    {
        size_t node_count = browser_dom_count_nodes(doc->root, 50000);
        const html_node_t *body = browser_dom_find_first_element(doc->root, "body");
        const html_node_t *title = browser_dom_find_first_element(doc->root, "title");
        const char *title_text = browser_dom_first_text_child(title);
        if (title_text && title_text[0] != '\0')
        {
            char title_preview[96];
            size_t tlen = strlen(title_text);
            size_t copy = tlen;
            if (copy >= sizeof(title_preview))
            {
                copy = sizeof(title_preview) - 1;
            }
            memcpy(title_preview, title_text, copy);
            title_preview[copy] = '\0';
            browser_debug_logf(app, "[parse] title %s", title_preview);
        }
        browser_debug_logf(app, "[parse] nodes=%u body=%s",
                           (unsigned)node_count,
                           body ? "yes" : "no");

        atk_html_view_set_document(app->viewer, doc);
        browser_debug_logf(app, "[render] set document ok");
    }
    else
    {
        char msg[256];
        const char *detail = parse_err.message ? parse_err.message : "unknown error";
        snprintf(msg,
                 sizeof(msg),
                 "<!doctype html><html><body><p>Failed to parse HTML: %s</p></body></html>",
                 detail);
        (void)atk_html_view_set_html(app->viewer, msg, NULL);
        browser_debug_logf(app, "[parse] failed: %s", detail);
    }
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
    int menu_w = atk_font_text_width("Menu") + 32;
    if (menu_w < 72)
    {
        menu_w = 72;
    }
    app->menu_button = atk_window_add_button(app->window,
                                             "Menu",
                                             content_x,
                                             content_y,
                                             menu_w,
                                             url_h,
                                             ATK_BUTTON_STYLE_TITLE_INSIDE,
                                             false,
                                             on_menu_button,
                                             app);
    if (!app->menu_button)
    {
        return false;
    }
    atk_widget_set_layout(app->menu_button, ATK_WIDGET_ANCHOR_TOP | ATK_WIDGET_ANCHOR_LEFT);

    int url_x = content_x + menu_w + BROWSER_GAP;
    int url_w = content_w - menu_w - BROWSER_GAP;
    if (url_w < 16)
    {
        url_w = 16;
    }
    app->url_input->x = url_x;
    app->url_input->width = url_w;
    atk_widget_set_layout(app->url_input,
                          ATK_WIDGET_ANCHOR_TOP | ATK_WIDGET_ANCHOR_LEFT | ATK_WIDGET_ANCHOR_RIGHT);

    atk_window_priv_t *wpriv = (atk_window_priv_t *)atk_widget_priv(app->window, &ATK_WINDOW_CLASS);
    if (!wpriv)
    {
        return false;
    }
    app->menu_browser = atk_menu_create();
    if (!app->menu_browser)
    {
        return false;
    }
    app->menu_browser->parent = app->window;
    if (!atk_list_push_back(&wpriv->children, app->menu_browser))
    {
        atk_menu_destroy(app->menu_browser);
        app->menu_browser = NULL;
        return false;
    }
    if (!atk_menu_add_item(app->menu_browser, "Open Debug Window", browser_menu_open_debug, app) ||
        !atk_menu_add_item(app->menu_browser, "Clear Debug Log", browser_menu_clear_debug, app))
    {
        return false;
    }
    app->menu_open = NULL;

    int viewer_y = content_y + url_h + BROWSER_GAP;
    int viewer_h = (content_y + content_h) - viewer_y;
    if (viewer_h < 16)
    {
        viewer_h = 16;
    }

    app->viewer = atk_window_add_html_view(app->window,
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
    (void)atk_html_view_set_html(app->viewer,
                                 "<!doctype html><html><body><p>Enter a URL above and press Enter.</p></body></html>",
                                 NULL);
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
    atk_main_register_mouse_handler(browser_on_mouse_event, &app);
    atk_main_register_close_handler(browser_on_close_event, &app);
    atk_main(&main_cfg);

    atk_user_close(&app.remote);
    return 0;
}
