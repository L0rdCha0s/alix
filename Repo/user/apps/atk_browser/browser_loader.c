#include "browser_internal.h"

#include "atk/util/gif.h"
#include "atk/util/png.h"
#include "ctype.h"
#include "string.h"

static void browser_loader_emit_event(browser_app_t *app, browser_ui_event_t *ev);


static bool browser_span_equals_ci(const char *a, size_t a_len, const char *b)
{
    if (!a || !b)
    {
        return false;
    }
    size_t b_len = strlen(b);
    if (a_len != b_len)
    {
        return false;
    }
    return strncasecmp(a, b, a_len) == 0;
}

static void browser_trim_span(const char **start, size_t *len)
{
    if (!start || !*start || !len)
    {
        return;
    }
    const char *s = *start;
    size_t n = *len;
    while (n > 0 && isspace((unsigned char)*s))
    {
        s++;
        n--;
    }
    while (n > 0 && isspace((unsigned char)s[n - 1]))
    {
        n--;
    }
    *start = s;
    *len = n;
}

static const char *browser_find_char(const char *start, size_t len, char needle)
{
    if (!start)
    {
        return NULL;
    }
    for (size_t i = 0; i < len; ++i)
    {
        if (start[i] == needle)
        {
            return start + i;
        }
    }
    return NULL;
}

static bool browser_data_url_parse_base64(const char *url,
                                          const char **out_payload,
                                          size_t *out_payload_len,
                                          bool *out_has_type,
                                          bool *out_is_png)
{
    if (!url || strncasecmp(url, "data:", 5) != 0)
    {
        return false;
    }

    const char *meta = url + 5;
    const char *comma = strchr(meta, ',');
    if (!comma)
    {
        return false;
    }

    size_t meta_len = (size_t)(comma - meta);
    const char *payload = comma + 1;
    if (!payload || payload[0] == '\0')
    {
        return false;
    }

    bool base64 = false;
    bool has_type = false;
    bool is_png = false;

    const char *cursor = meta;
    size_t remaining = meta_len;
    const char *semi = browser_find_char(cursor, remaining, ';');
    size_t token_len = semi ? (size_t)(semi - cursor) : remaining;
    const char *token = cursor;
    browser_trim_span(&token, &token_len);
    if (token_len > 0)
    {
        has_type = true;
        if (browser_span_equals_ci(token, token_len, "image/png"))
        {
            is_png = true;
        }
    }

    if (semi)
    {
        cursor = semi + 1;
        while (cursor < meta + meta_len)
        {
            const char *next = browser_find_char(cursor, (size_t)((meta + meta_len) - cursor), ';');
            size_t len = next ? (size_t)(next - cursor) : (size_t)((meta + meta_len) - cursor);
            const char *tok = cursor;
            browser_trim_span(&tok, &len);
            if (len > 0 && browser_span_equals_ci(tok, len, "base64"))
            {
                base64 = true;
            }
            if (!next)
            {
                break;
            }
            cursor = next + 1;
        }
    }

    if (!base64)
    {
        return false;
    }

    if (out_payload)
    {
        *out_payload = payload;
    }
    if (out_payload_len)
    {
        *out_payload_len = strlen(payload);
    }
    if (out_has_type)
    {
        *out_has_type = has_type;
    }
    if (out_is_png)
    {
        *out_is_png = is_png;
    }
    return true;
}

static int browser_base64_value(char ch)
{
    if (ch >= 'A' && ch <= 'Z')
    {
        return ch - 'A';
    }
    if (ch >= 'a' && ch <= 'z')
    {
        return ch - 'a' + 26;
    }
    if (ch >= '0' && ch <= '9')
    {
        return ch - '0' + 52;
    }
    if (ch == '+')
    {
        return 62;
    }
    if (ch == '/')
    {
        return 63;
    }
    return -1;
}

static uint8_t *browser_decode_base64(const char *input, size_t len, size_t *out_len)
{
    if (!input || len == 0 || !out_len)
    {
        return NULL;
    }
    *out_len = 0;

    size_t valid = 0;
    size_t padding = 0;
    bool seen_pad = false;
    for (size_t i = 0; i < len; ++i)
    {
        unsigned char ch = (unsigned char)input[i];
        if (isspace(ch))
        {
            continue;
        }
        if (ch == '=')
        {
            padding++;
            seen_pad = true;
            continue;
        }
        if (seen_pad)
        {
            return NULL;
        }
        if (browser_base64_value((char)ch) < 0)
        {
            return NULL;
        }
        valid++;
    }

    size_t total = valid + padding;
    if (total == 0 || (total % 4) != 0 || padding > 2)
    {
        return NULL;
    }

    size_t decoded_len = (total / 4) * 3;
    if (padding > 0)
    {
        decoded_len -= padding;
    }
    if (decoded_len == 0 || decoded_len > BROWSER_MAX_BYTES)
    {
        return NULL;
    }

    uint8_t *out = (uint8_t *)malloc(decoded_len);
    if (!out)
    {
        return NULL;
    }

    size_t out_pos = 0;
    int quartet[4] = {0, 0, 0, 0};
    int q = 0;

    for (size_t i = 0; i < len; ++i)
    {
        unsigned char ch = (unsigned char)input[i];
        if (isspace(ch))
        {
            continue;
        }

        int val = 0;
        if (ch == '=')
        {
            val = 64;
        }
        else
        {
            val = browser_base64_value((char)ch);
            if (val < 0)
            {
                free(out);
                return NULL;
            }
        }
        quartet[q++] = val;
        if (q != 4)
        {
            continue;
        }

        if (quartet[0] == 64 || quartet[1] == 64)
        {
            free(out);
            return NULL;
        }
        out[out_pos++] = (uint8_t)((quartet[0] << 2) | (quartet[1] >> 4));
        if (quartet[2] != 64)
        {
            out[out_pos++] = (uint8_t)(((quartet[1] & 0x0Fu) << 4) | (quartet[2] >> 2));
            if (quartet[3] != 64)
            {
                out[out_pos++] = (uint8_t)(((quartet[2] & 0x03u) << 6) | quartet[3]);
            }
        }
        else if (quartet[3] != 64)
        {
            free(out);
            return NULL;
        }

        q = 0;
    }

    if (q != 0 || out_pos != decoded_len)
    {
        free(out);
        return NULL;
    }

    *out_len = decoded_len;
    return out;
}

static bool browser_handle_data_url_image(browser_app_t *app, uint64_t load_id, const char *url)
{
    if (!app || !url)
    {
        return false;
    }
    if (strncasecmp(url, "data:", 5) != 0)
    {
        return false;
    }

    const char *payload = NULL;
    size_t payload_len = 0;
    bool has_type = false;
    bool is_png = false;
    if (!browser_data_url_parse_base64(url, &payload, &payload_len, &has_type, &is_png))
    {
        browser_debug_logf(app, "[img] data url unsupported");
        return true;
    }
    if (has_type && !is_png)
    {
        browser_debug_logf(app, "[img] data url skipped (type not png)");
        return true;
    }

    size_t decoded_len = 0;
    uint8_t *decoded = browser_decode_base64(payload, payload_len, &decoded_len);
    if (!decoded)
    {
        browser_debug_logf(app, "[img] data url base64 decode failed len=%u", (unsigned)payload_len);
        return true;
    }
    if (!browser_is_png_bytes(decoded, decoded_len))
    {
        browser_debug_logf(app, "[img] data url skipped (not png)");
        free(decoded);
        return true;
    }
    if (!browser_load_is_active(app, load_id))
    {
        free(decoded);
        return true;
    }

    video_color_t *pixels = NULL;
    int w = 0;
    int h = 0;
    int stride_bytes = 0;
    int rc = -1;
    browser_lock_enter(app, &app->decode_lock, "decode_lock");
    rc = png_decode_rgba32(decoded, decoded_len, &pixels, &w, &h, &stride_bytes);
    browser_lock_exit(app, &app->decode_lock, "decode_lock");
    free(decoded);

    if (rc != 0 || !pixels || w <= 0 || h <= 0 || stride_bytes <= 0)
    {
        const char *err = png_last_error();
        browser_debug_logf(app,
                           "[img] data url decode failed err=%s",
                           err ? err : "(unknown)");
        free(pixels);
        return true;
    }

    if (!browser_load_is_active(app, load_id))
    {
        free(pixels);
        return true;
    }

    browser_ui_event_t img_ev = {0};
    img_ev.type = BROWSER_UI_EVENT_IMAGE_RGBA;
    img_ev.load_id = load_id;
    img_ev.u.image_rgba.src = browser_strdup(url);
    img_ev.u.image_rgba.pixels = pixels;
    img_ev.u.image_rgba.width = w;
    img_ev.u.image_rgba.height = h;
    img_ev.u.image_rgba.stride_bytes = stride_bytes;
    if (!img_ev.u.image_rgba.src)
    {
        browser_ui_event_free_payload(&img_ev);
        browser_debug_logf(app, "[img] data url out of memory");
        return true;
    }

    browser_loader_emit_event(app, &img_ev);
    browser_debug_logf(app, "[img] data url ok bytes=%u", (unsigned)decoded_len);
    return true;
}

bool browser_load_is_active(browser_app_t *app, uint64_t load_id)
{
    if (!app || load_id == 0)
    {
        return false;
    }

    bool active = false;
    browser_lock_enter(app, &app->lock, "app_lock");
    active = (app->active_load_id == load_id);
    browser_lock_exit(app, &app->lock, "app_lock");
    return active;
}

void browser_track_load_thread(browser_app_t *app, alix_thread_t thread)
{
    if (!app || thread == 0)
    {
        return;
    }

    browser_lock_enter(app, &app->lock, "app_lock");
    if (app->load_thread_count < BROWSER_MAX_LOAD_THREADS)
    {
        app->load_threads[app->load_thread_count++] = thread;
    }
    browser_lock_exit(app, &app->lock, "app_lock");
}

void browser_untrack_load_thread(browser_app_t *app, alix_thread_t thread)
{
    if (!app || thread == 0)
    {
        return;
    }

    browser_lock_enter(app, &app->lock, "app_lock");
    for (size_t i = 0; i < app->load_thread_count; ++i)
    {
        if (app->load_threads[i] == thread)
        {
            app->load_threads[i] = app->load_threads[app->load_thread_count - 1];
            app->load_thread_count--;
            break;
        }
    }
    browser_lock_exit(app, &app->lock, "app_lock");
}

void browser_app_css_reset(browser_app_t *app)
{
    if (!app)
    {
        return;
    }
    free(app->external_css);
    app->external_css = NULL;
    app->external_css_len = 0;
    app->external_css_cap = 0;
    app->css_dirty = false;
    app->css_dirty_since_ms = 0;
}

bool browser_app_css_append(browser_app_t *app, const char *data, size_t len)
{
    if (!app)
    {
        return false;
    }
    if (!data || len == 0)
    {
        return true;
    }
    return browser_buf_append(&app->external_css,
                              &app->external_css_len,
                              &app->external_css_cap,
                              (const uint8_t *)data,
                              len);
}

typedef struct
{
    browser_app_t *app;
    uint64_t load_id;
    char *url_text;
    browser_resource_set_t requested;
} browser_load_job_t;

typedef struct
{
    browser_app_t *app;
    uint64_t load_id;
    browser_resource_kind_t kind;
    char *url;
} browser_resource_job_t;

static bool browser_can_spawn_load_thread(browser_app_t *app)
{
    if (!app)
    {
        return false;
    }
    bool ok = false;
    browser_lock_enter(app, &app->lock, "app_lock");
    ok = app->load_thread_count < BROWSER_MAX_LOAD_THREADS;
    browser_lock_exit(app, &app->lock, "app_lock");
    return ok;
}

static void browser_resource_fetch(browser_app_t *app,
                                   uint64_t load_id,
                                   browser_resource_kind_t kind,
                                   char *abs)
{
    if (!abs)
    {
        return;
    }
    if (!app)
    {
        free(abs);
        return;
    }
    if (!browser_load_is_active(app, load_id))
    {
        free(abs);
        return;
    }

    if (kind == BROWSER_RESOURCE_IMAGE)
    {
        if (browser_handle_data_url_image(app, load_id, abs))
        {
            free(abs);
            return;
        }
    }

    if (kind == BROWSER_RESOURCE_CSS)
    {
        browser_debug_logf(app, "[css] fetch %s", abs);
    }
    else if (kind == BROWSER_RESOURCE_SCRIPT)
    {
        browser_debug_logf(app, "[js] fetch %s", abs);
    }
    else if (kind == BROWSER_RESOURCE_IMAGE)
    {
        browser_debug_logf(app, "[img] fetch %s", abs);
    }

    browser_url_t res_url = {0};
    browser_url_t res_final = {0};
    size_t res_len = 0;
    char *res_body = NULL;
    if (browser_parse_url(abs, &res_url))
    {
        res_body = browser_fetch_http(app, &res_url, &res_len, &res_final);
    }

    if (!browser_load_is_active(app, load_id))
    {
        free(res_body);
        browser_url_destroy(&res_url);
        browser_url_destroy(&res_final);
        free(abs);
        return;
    }

    if (res_body && strncmp(res_body, "Error:\n", 6) != 0)
    {
        if (kind == BROWSER_RESOURCE_CSS)
        {
            browser_ui_event_t css_ev = {0};
            css_ev.type = BROWSER_UI_EVENT_CSS_APPEND;
            css_ev.load_id = load_id;
            css_ev.u.css_append.css = res_body;
            css_ev.u.css_append.len = res_len;
            res_body = NULL;
            browser_loader_emit_event(app, &css_ev);
            browser_debug_logf(app, "[css] ok bytes=%u url=%s", (unsigned)res_len, abs);
        }
        else if (kind == BROWSER_RESOURCE_SCRIPT)
        {
            browser_ui_event_t js_ev = {0};
            if (browser_script_event_init(&js_ev, load_id, abs, res_body, res_len))
            {
                browser_debug_logf(app, "[js] ok bytes=%u url=%s", (unsigned)res_len, abs);
                res_body = NULL;
                browser_loader_emit_event(app, &js_ev);
            }
            else
            {
                browser_debug_logf(app, "[js] failed to queue url=%s", abs ? abs : "(null)");
            }
        }
        else if (kind == BROWSER_RESOURCE_IMAGE)
        {
            bool is_gif = browser_is_gif_bytes((const uint8_t *)res_body, res_len);
            bool is_png = (!is_gif && browser_is_png_bytes((const uint8_t *)res_body, res_len));
            if (is_gif || is_png)
            {
                video_color_t *pixels = NULL;
                int w = 0;
                int h = 0;
                int stride_bytes = 0;
                int rc = -1;

                browser_lock_enter(app, &app->decode_lock, "decode_lock");
                if (is_gif)
                {
                    rc = gif_decode_rgba32((const uint8_t *)res_body,
                                           res_len,
                                           &pixels,
                                           &w,
                                           &h,
                                           &stride_bytes);
                }
                else
                {
                    rc = png_decode_rgba32((const uint8_t *)res_body,
                                           res_len,
                                           &pixels,
                                           &w,
                                           &h,
                                           &stride_bytes);
                }
                browser_lock_exit(app, &app->decode_lock, "decode_lock");

                if (rc == 0 && pixels && w > 0 && h > 0 && stride_bytes > 0)
                {
                    browser_ui_event_t img_ev = {0};
                    img_ev.type = BROWSER_UI_EVENT_IMAGE_RGBA;
                    img_ev.load_id = load_id;
                    img_ev.u.image_rgba.src = browser_strdup(abs);
                    img_ev.u.image_rgba.pixels = pixels;
                    img_ev.u.image_rgba.width = w;
                    img_ev.u.image_rgba.height = h;
                    img_ev.u.image_rgba.stride_bytes = stride_bytes;
                    if (!img_ev.u.image_rgba.src)
                    {
                        browser_ui_event_free_payload(&img_ev);
                    }
                    else
                    {
                        pixels = NULL;
                        browser_loader_emit_event(app, &img_ev);
                        browser_debug_logf(app, "[img] ok bytes=%u url=%s", (unsigned)res_len, abs);
                    }
                }
                else
                {
                    const char *err = is_gif ? gif_last_error() : png_last_error();
                    browser_debug_logf(app,
                                       "[img] decode failed url=%s err=%s",
                                       abs ? abs : "(null)",
                                       err ? err : "(unknown)");
                    free(pixels);
                }
            }
            else
            {
                browser_debug_logf(app, "[img] skipped (not png/gif) url=%s", abs);
            }
        }
    }
    else
    {
        const char *msg = res_body ? (res_body + 6) : "allocation failed";
        if (kind == BROWSER_RESOURCE_CSS)
        {
            browser_debug_logf(app, "[css] failed url=%s err=%s", abs, msg);
        }
        else if (kind == BROWSER_RESOURCE_SCRIPT)
        {
            browser_debug_logf(app, "[js] failed url=%s err=%s", abs ? abs : "(null)", msg);
        }
        else if (kind == BROWSER_RESOURCE_IMAGE)
        {
            browser_debug_logf(app, "[img] failed url=%s err=%s", abs, msg);
        }
    }

    free(res_body);
    browser_url_destroy(&res_url);
    browser_url_destroy(&res_final);
    free(abs);
}

static void browser_resource_thread(void *arg)
{
    browser_resource_job_t *job = (browser_resource_job_t *)arg;
    if (!job)
    {
        return;
    }

    browser_app_t *app = job->app;
    uint64_t load_id = job->load_id;
    browser_resource_kind_t kind = job->kind;
    char *url = job->url;
    job->app = NULL;
    job->url = NULL;
    free(job);

    browser_resource_fetch(app, load_id, kind, url);

    if (app)
    {
        browser_ui_event_t done_ev = {0};
        done_ev.type = BROWSER_UI_EVENT_THREAD_DONE;
        done_ev.load_id = load_id;
        done_ev.u.thread_done.thread = alix_thread_self();
        browser_loader_emit_event(app, &done_ev);
    }
}

static bool browser_spawn_resource_thread(browser_app_t *app,
                                          uint64_t load_id,
                                          browser_resource_kind_t kind,
                                          char *url)
{
    if (!app || !url)
    {
        return false;
    }
    if (!browser_can_spawn_load_thread(app))
    {
        return false;
    }

    browser_resource_job_t *job = (browser_resource_job_t *)calloc(1, sizeof(*job));
    if (!job)
    {
        return false;
    }
    job->app = app;
    job->load_id = load_id;
    job->kind = kind;
    job->url = url;

    alix_thread_t thread;
    if (alix_thread_create(&thread, "atk_browser_res", browser_resource_thread, job) != 0)
    {
        free(job);
        return false;
    }
    browser_track_load_thread(app, thread);
    return true;
}

static void browser_loader_emit_event(browser_app_t *app, browser_ui_event_t *ev)
{
    if (!app || !ev)
    {
        return;
    }
    if (!browser_ui_event_enqueue(app, ev))
    {
        browser_debug_logf(app, "[load] event queue full (drop type=%u)", (unsigned)ev->type);
        browser_ui_event_free_payload(ev);
    }
}

static void browser_loader_emit_error(browser_app_t *app, uint64_t load_id, const char *message)
{
    browser_ui_event_t ev = {0};
    ev.type = BROWSER_UI_EVENT_ERROR;
    ev.load_id = load_id;
    ev.u.error.message = browser_strdup(message ? message : "unknown error");
    if (!ev.u.error.message)
    {
        browser_debug_logf(app, "[load] error alloc failed");
        return;
    }
    browser_loader_emit_event(app, &ev);
}

static void browser_load_thread(void *arg)
{
    browser_load_job_t *job = (browser_load_job_t *)arg;
    if (!job)
    {
        return;
    }
    (void)browser_resource_set_init(&job->requested);
    browser_app_t *app = job->app;
    uint64_t load_id = job->load_id;
    char *url_text = job->url_text;
    job->app = NULL;
    job->url_text = NULL;

    if (!app)
    {
        free(url_text);
        browser_resource_set_destroy(&job->requested);
        free(job);
        return;
    }

    browser_debug_logf(app, "[load] start id=%llu url=%s",
                       (unsigned long long)load_id,
                       url_text ? url_text : "(null)");

    if (!url_text || url_text[0] == '\0')
    {
        browser_loader_emit_error(app, load_id, "missing url");
        goto done;
    }

    browser_url_t url = {0};
    browser_url_t final_url = {0};
    char *html = NULL;
    size_t html_len = 0;

    if (!browser_parse_url(url_text, &url))
    {
        browser_loader_emit_error(app, load_id, "invalid url");
        goto done_fetch;
    }

    browser_debug_logf(app,
                       "[load] parsed tls=%d host=%s port=%u path=%s",
                       url.use_tls ? 1 : 0,
                       url.host ? url.host : "(null)",
                       (unsigned)url.port,
                       url.path ? url.path : "(null)");

    html = browser_fetch_http(app, &url, &html_len, &final_url);
    if (!html)
    {
        browser_loader_emit_error(app, load_id, "allocation failed");
        goto done_fetch;
    }
    if (strncmp(html, "Error:\n", 6) == 0)
    {
        browser_loader_emit_error(app, load_id, html + 6);
        goto done_fetch;
    }

    if (!browser_load_is_active(app, load_id))
    {
        browser_debug_logf(app, "[load] canceled before parse id=%llu", (unsigned long long)load_id);
        goto done_fetch;
    }

    browser_debug_logf(app, "[load] html bytes=%u", (unsigned)html_len);
    html_parse_error_t parse_err = {0};
    html_document_t *doc = html_parse(html, &parse_err);
    if (!doc)
    {
        const char *detail = parse_err.message ? parse_err.message : "parse failed";
        browser_loader_emit_error(app, load_id, detail);
        goto done_fetch;
    }

    char *css_urls[BROWSER_MAX_STYLESHEETS] = {0};
    size_t css_count = 0;
    char *img_urls[BROWSER_MAX_IMAGES] = {0};
    size_t img_count = 0;
    char *script_urls[BROWSER_MAX_SCRIPTS] = {0};
    size_t script_count = 0;
    if (doc->root)
    {
        browser_collect_resource_urls(app,
                                      doc->root,
                                      &final_url,
                                      css_urls,
                                      &css_count,
                                      img_urls,
                                      &img_count,
                                      script_urls,
                                      &script_count);
    }

    if (!browser_load_is_active(app, load_id))
    {
        browser_debug_logf(app, "[load] canceled after parse id=%llu", (unsigned long long)load_id);
        html_document_destroy(doc);
        doc = NULL;
        goto done_resources;
    }

    browser_ui_event_t doc_ev = {0};
    doc_ev.type = BROWSER_UI_EVENT_DOC_READY;
    doc_ev.load_id = load_id;
    doc_ev.u.doc_ready.doc = doc;
    doc_ev.u.doc_ready.final_url = browser_url_to_string(&final_url);
    browser_loader_emit_event(app, &doc_ev);
    doc = NULL;

    for (size_t i = 0; i < css_count; ++i)
    {
        if (!browser_load_is_active(app, load_id))
        {
            break;
        }
        char *abs = css_urls[i];
        css_urls[i] = NULL;
        if (!abs)
        {
            continue;
        }
        browser_resource_track_t track = browser_resource_set_track(&job->requested, BROWSER_RESOURCE_CSS, abs);
        if (track == BROWSER_RESOURCE_TRACK_DUP)
        {
            browser_debug_logf(app, "[css] skip duplicate url=%s", abs);
            free(abs);
            continue;
        }
        if (track == BROWSER_RESOURCE_TRACK_ERROR)
        {
            browser_debug_logf(app, "[css] track failed url=%s", abs);
        }
        if (browser_spawn_resource_thread(app, load_id, BROWSER_RESOURCE_CSS, abs))
        {
            abs = NULL;
        }
        if (abs)
        {
            browser_resource_fetch(app, load_id, BROWSER_RESOURCE_CSS, abs);
        }
    }

    for (size_t i = 0; i < script_count; ++i)
    {
        if (!browser_load_is_active(app, load_id))
        {
            break;
        }
        char *abs = script_urls[i];
        script_urls[i] = NULL;
        if (!abs)
        {
            continue;
        }
        browser_resource_track_t track = browser_resource_set_track(&job->requested, BROWSER_RESOURCE_SCRIPT, abs);
        if (track == BROWSER_RESOURCE_TRACK_DUP)
        {
            browser_debug_logf(app, "[js] skip duplicate url=%s", abs);
            free(abs);
            continue;
        }
        if (track == BROWSER_RESOURCE_TRACK_ERROR)
        {
            browser_debug_logf(app, "[js] track failed url=%s", abs);
        }
        if (browser_spawn_resource_thread(app, load_id, BROWSER_RESOURCE_SCRIPT, abs))
        {
            abs = NULL;
        }
        if (abs)
        {
            browser_resource_fetch(app, load_id, BROWSER_RESOURCE_SCRIPT, abs);
        }
    }

    for (size_t i = 0; i < img_count; ++i)
    {
        if (!browser_load_is_active(app, load_id))
        {
            break;
        }
        char *abs = img_urls[i];
        img_urls[i] = NULL;
        if (!abs)
        {
            continue;
        }
        browser_resource_track_t track = browser_resource_set_track(&job->requested, BROWSER_RESOURCE_IMAGE, abs);
        if (track == BROWSER_RESOURCE_TRACK_DUP)
        {
            browser_debug_logf(app, "[img] skip duplicate url=%s", abs);
            free(abs);
            continue;
        }
        if (track == BROWSER_RESOURCE_TRACK_ERROR)
        {
            browser_debug_logf(app, "[img] track failed url=%s", abs);
        }
        if (browser_spawn_resource_thread(app, load_id, BROWSER_RESOURCE_IMAGE, abs))
        {
            abs = NULL;
        }
        if (abs)
        {
            browser_resource_fetch(app, load_id, BROWSER_RESOURCE_IMAGE, abs);
        }
    }

done_resources:
    for (size_t i = 0; i < css_count; ++i)
    {
        free(css_urls[i]);
        css_urls[i] = NULL;
    }
    for (size_t i = 0; i < img_count; ++i)
    {
        free(img_urls[i]);
        img_urls[i] = NULL;
    }
    for (size_t i = 0; i < script_count; ++i)
    {
        free(script_urls[i]);
        script_urls[i] = NULL;
    }

done_fetch:
    free(html);
    browser_url_destroy(&url);
    browser_url_destroy(&final_url);

done:
    free(url_text);
    browser_resource_set_destroy(&job->requested);
    free(job);
    browser_ui_event_t done_ev = {0};
    done_ev.type = BROWSER_UI_EVENT_THREAD_DONE;
    done_ev.load_id = load_id;
    done_ev.u.thread_done.thread = alix_thread_self();
    browser_loader_emit_event(app, &done_ev);
}

bool browser_loader_start(browser_app_t *app, const char *url_text)
{
    if (!app || !url_text || url_text[0] == '\0' || !app->viewer || !app->window)
    {
        return false;
    }

    char *url_copy = browser_strdup(url_text);
    if (!url_copy)
    {
        browser_debug_logf(app, "[ui] allocation failed (url_copy)");
        (void)atk_html_view_set_html(app->viewer,
                                     "<!doctype html><html><body><p>Allocation failed.</p></body></html>",
                                     NULL);
        atk_window_mark_dirty(app->window);
        return false;
    }

    uint64_t load_id = 0;
    browser_lock_enter(app, &app->lock, "app_lock");
    load_id = ++app->next_load_id;
    app->active_load_id = load_id;
    browser_lock_exit(app, &app->lock, "app_lock");
    browser_app_css_reset(app);

    (void)atk_html_view_set_html(app->viewer,
                                 "<!doctype html><html><head><style>"
                                 "body{margin:0;padding:0;}"
                                 "p{margin-top:40vh;text-align:center;font-size:16px;color:#444;}"
                                 "</style></head><body><p>Loading...</p></body></html>",
                                 NULL);
    atk_window_mark_dirty(app->window);

    browser_load_job_t *job = (browser_load_job_t *)calloc(1, sizeof(*job));
    if (!job)
    {
        (void)atk_html_view_set_html(app->viewer,
                                     "<!doctype html><html><body><p>Allocation failed.</p></body></html>",
                                     NULL);
        atk_window_mark_dirty(app->window);
        free(url_copy);
        return false;
    }
    job->app = app;
    job->load_id = load_id;
    job->url_text = url_copy;

    alix_thread_t thread = 0;
    if (alix_thread_create(&thread, "atk_browser_load", browser_load_thread, job) != 0)
    {
        browser_debug_logf(app, "[ui] failed to start load thread");
        browser_loader_emit_error(app, load_id, "failed to start load thread");
        free(job->url_text);
        free(job);
        return false;
    }
    browser_track_load_thread(app, thread);
    return true;
}
