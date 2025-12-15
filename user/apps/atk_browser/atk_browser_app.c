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

static const char *browser_find_http_body(const char *response)
{
    if (!response)
    {
        return NULL;
    }
    const char *p = strstr(response, "\r\n\r\n");
    if (p)
    {
        return p + 4;
    }
    p = strstr(response, "\n\n");
    if (p)
    {
        return p + 2;
    }
    return response;
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

    char *response = NULL;
    size_t response_len = 0;
    size_t response_cap = 0;

    if (url->use_tls)
    {
        tls_session_t *tls = (tls_session_t *)malloc(sizeof(*tls));
        if (!tls)
        {
            free(request);
            close(fd);
            return browser_format_error("alloc tls session failed");
        }

        if (!tls_session_init_fd(tls, fd))
        {
            free(tls);
            free(request);
            close(fd);
            return browser_format_error("tls_session_init_fd failed");
        }

        if (!tls_session_handshake(tls, url->host))
        {
            tls_session_close(tls);
            free(tls);
            free(request);
            close(fd);
            return browser_format_error("tls handshake failed");
        }

        if (!tls_session_send(tls, (const uint8_t *)request, strlen(request)))
        {
            tls_session_close(tls);
            free(tls);
            free(request);
            close(fd);
            return browser_format_error("tls send failed");
        }

        uint8_t chunk[2048];
        while (1)
        {
            size_t got = tls_session_recv(tls, chunk, sizeof(chunk));
            if (got == 0)
            {
                break;
            }
            if (!browser_buf_append(&response, &response_len, &response_cap, chunk, got))
            {
                tls_session_close(tls);
                free(tls);
                free(request);
                close(fd);
                free(response);
                return browser_format_error("response too large");
            }
        }

        tls_session_close(tls);
        free(tls);
    }
    else
    {
        if (!browser_write_all(fd, (const uint8_t *)request, strlen(request)))
        {
            free(request);
            close(fd);
            return browser_format_error("write failed");
        }

        uint8_t chunk[2048];
        while (1)
        {
            ssize_t got = read(fd, chunk, sizeof(chunk));
            if (got < 0)
            {
                free(request);
                close(fd);
                free(response);
                return browser_format_error("read failed");
            }
            if (got == 0)
            {
                break;
            }
            if (!browser_buf_append(&response, &response_len, &response_cap, chunk, (size_t)got))
            {
                free(request);
                close(fd);
                free(response);
                return browser_format_error("response too large");
            }
        }
    }

    free(request);
    close(fd);

    if (!response)
    {
        return browser_format_error("empty response");
    }

    const char *body = browser_find_http_body(response);
    char *out = browser_strdup(body);
    free(response);
    return out ? out : browser_format_error("alloc body failed");
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
