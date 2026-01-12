#include "browser_internal.h"

#include "atk/util/gif.h"
#include "atk/util/png.h"
#include "atk/util/svg.h"
#include "ctype.h"
#include "stdio.h"
#include "string.h"
#include "web/html/html_internal.h"

static void browser_loader_emit_event(browser_app_t *app, browser_ui_event_t *ev);
static void browser_load_thread(void *arg);

#define BROWSER_RESOURCE_LOG_URL_MAX 160u

static const char *browser_resource_kind_label(browser_resource_kind_t kind)
{
    switch (kind)
    {
        case BROWSER_RESOURCE_CSS:
            return "css";
        case BROWSER_RESOURCE_SCRIPT:
            return "js";
        case BROWSER_RESOURCE_IMAGE:
            return "img";
        default:
            return "unknown";
    }
}

static void browser_resource_log_start(browser_app_t *app,
                                       uint64_t load_id,
                                       browser_resource_kind_t kind,
                                       const char *url)
{
    if (!app)
    {
        return;
    }
    const char *kind_label = browser_resource_kind_label(kind);
    const char *safe_url = url ? url : "(null)";
    size_t url_len = strlen(safe_url);
    size_t show = url_len;
    if (show > BROWSER_RESOURCE_LOG_URL_MAX)
    {
        show = BROWSER_RESOURCE_LOG_URL_MAX;
    }
    char url_buf[BROWSER_RESOURCE_LOG_URL_MAX + 4];
    const char *serial_url = safe_url;
    if (url_len > BROWSER_RESOURCE_LOG_URL_MAX)
    {
        memcpy(url_buf, safe_url, BROWSER_RESOURCE_LOG_URL_MAX);
        memcpy(url_buf + BROWSER_RESOURCE_LOG_URL_MAX, "...", 3);
        url_buf[BROWSER_RESOURCE_LOG_URL_MAX + 3] = '\0';
        serial_url = url_buf;
    }
    browser_debug_logf(app,
                       "[res] start id=%llu kind=%s url=%.*s%s",
                       (unsigned long long)load_id,
                       kind_label,
                       (int)show,
                       safe_url,
                       url_len > show ? "..." : "");
    serial_printf("[res] start id=%llu kind=%s url=%s",
                  (unsigned long long)load_id,
                  kind_label,
                  serial_url);
}

static void browser_resource_log_done(browser_app_t *app,
                                      uint64_t load_id,
                                      browser_resource_kind_t kind,
                                      const char *url,
                                      const char *status,
                                      uint64_t elapsed_ms,
                                      size_t bytes,
                                      const char *detail)
{
    if (!app)
    {
        return;
    }
    const char *kind_label = browser_resource_kind_label(kind);
    const char *safe_url = url ? url : "(null)";
    const char *safe_status = status ? status : "unknown";
    size_t url_len = strlen(safe_url);
    size_t show = url_len;
    if (show > BROWSER_RESOURCE_LOG_URL_MAX)
    {
        show = BROWSER_RESOURCE_LOG_URL_MAX;
    }
    char url_buf[BROWSER_RESOURCE_LOG_URL_MAX + 4];
    const char *serial_url = safe_url;
    if (url_len > BROWSER_RESOURCE_LOG_URL_MAX)
    {
        memcpy(url_buf, safe_url, BROWSER_RESOURCE_LOG_URL_MAX);
        memcpy(url_buf + BROWSER_RESOURCE_LOG_URL_MAX, "...", 3);
        url_buf[BROWSER_RESOURCE_LOG_URL_MAX + 3] = '\0';
        serial_url = url_buf;
    }
    if (detail && detail[0] != '\0')
    {
        browser_debug_logf(app,
                           "[res] done id=%llu kind=%s status=%s ms=%llu bytes=%u url=%.*s%s err=%s",
                           (unsigned long long)load_id,
                           kind_label,
                           safe_status,
                           (unsigned long long)elapsed_ms,
                           (unsigned)bytes,
                           (int)show,
                           safe_url,
                           url_len > show ? "..." : "",
                           detail);
        serial_printf("[res] done id=%llu kind=%s status=%s ms=%llu bytes=%u url=%s err=%s",
                      (unsigned long long)load_id,
                      kind_label,
                      safe_status,
                      (unsigned long long)elapsed_ms,
                      (unsigned)bytes,
                      serial_url,
                      detail);
    }
    else
    {
        browser_debug_logf(app,
                           "[res] done id=%llu kind=%s status=%s ms=%llu bytes=%u url=%.*s%s",
                           (unsigned long long)load_id,
                           kind_label,
                           safe_status,
                           (unsigned long long)elapsed_ms,
                           (unsigned)bytes,
                           (int)show,
                           safe_url,
                           url_len > show ? "..." : "");
        serial_printf("[res] done id=%llu kind=%s status=%s ms=%llu bytes=%u url=%s",
                      (unsigned long long)load_id,
                      kind_label,
                      safe_status,
                      (unsigned long long)elapsed_ms,
                      (unsigned)bytes,
                      serial_url);
    }
}

static void browser_css_log_sniff(browser_app_t *app, const char *url, const uint8_t *data, size_t len)
{
    if (!app || !data || len == 0)
    {
        return;
    }

    size_t nul_count = 0;
    size_t ctrl_count = 0;
    size_t high_count = 0;
    size_t sample_len = len < 48 ? len : 48;
    char sample[49];
    size_t sample_idx = 0;

    for (size_t i = 0; i < len; ++i)
    {
        unsigned char c = data[i];
        if (c == 0)
        {
            ++nul_count;
        }
        if (c >= 0x80)
        {
            ++high_count;
        }
        if ((c < 0x20 && c != '\n' && c != '\r' && c != '\t') || c == 0x7f)
        {
            ++ctrl_count;
        }
        if (i < sample_len)
        {
            sample[sample_idx++] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
        }
    }
    sample[sample_idx] = '\0';

    size_t scan_idx = 0;
    while (scan_idx < len)
    {
        unsigned char c = data[scan_idx];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
        {
            break;
        }
        ++scan_idx;
    }
    bool looks_html = (scan_idx < len && data[scan_idx] == '<');
    const char *magic = "";
    if (len >= 2 && data[0] == 0x1f && data[1] == 0x8b)
    {
        magic = "gzip";
    }

    bool high_ratio = (high_count * 100u) / (len ? len : 1) > 20u;
    bool ctrl_ratio = (ctrl_count * 100u) / (len ? len : 1) > 2u;
    if (!looks_html && magic[0] == '\0' && nul_count == 0 && !ctrl_ratio && !high_ratio)
    {
        return;
    }

    const char *safe_url = url ? url : "(null)";
    size_t url_len = strlen(safe_url);
    size_t show = url_len;
    if (show > BROWSER_RESOURCE_LOG_URL_MAX)
    {
        show = BROWSER_RESOURCE_LOG_URL_MAX;
    }
    browser_debug_logf(app,
                       "[css] sniff bytes=%u nul=%u ctrl=%u high=%u html=%u magic=%s sample=%s url=%.*s%s",
                       (unsigned)len,
                       (unsigned)nul_count,
                       (unsigned)ctrl_count,
                       (unsigned)high_count,
                       looks_html ? 1u : 0u,
                       magic[0] ? magic : "none",
                       sample,
                       (int)show,
                       safe_url,
                       url_len > show ? "..." : "");
}

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

static bool browser_svg_append(char **buf, size_t *len, size_t *cap, const char *text)
{
    if (!text)
    {
        return true;
    }
    return browser_buf_append(buf, len, cap, (const uint8_t *)text, strlen(text));
}

typedef struct
{
    const html_node_t *node;
    bool closing;
} browser_svg_stack_entry_t;

static char *browser_svg_serialize_node(const html_node_t *root, size_t *out_len)
{
    if (out_len)
    {
        *out_len = 0;
    }
    if (!root || !out_len)
    {
        return NULL;
    }

    size_t stack_cap = 32;
    size_t stack_len = 0;
    browser_svg_stack_entry_t *stack = (browser_svg_stack_entry_t *)malloc(stack_cap * sizeof(*stack));
    if (!stack)
    {
        return NULL;
    }
    stack[stack_len++] = (browser_svg_stack_entry_t){ .node = root, .closing = false };

    char *buf = NULL;
    size_t len = 0;
    size_t cap = 0;
    bool ok = true;

    while (stack_len > 0 && ok)
    {
        browser_svg_stack_entry_t entry = stack[--stack_len];
        const html_node_t *node = entry.node;
        if (!node)
        {
            continue;
        }

        if (entry.closing)
        {
            if (node->type == HTML_NODE_ELEMENT && node->name)
            {
                ok = browser_svg_append(&buf, &len, &cap, "</") &&
                     browser_svg_append(&buf, &len, &cap, node->name) &&
                     browser_svg_append(&buf, &len, &cap, ">");
            }
            continue;
        }

        if (node->type == HTML_NODE_TEXT)
        {
            if (node->text && node->text[0] != '\0')
            {
                ok = browser_svg_append(&buf, &len, &cap, node->text);
            }
            continue;
        }

        if (node->type != HTML_NODE_ELEMENT || !node->name)
        {
            continue;
        }

        ok = browser_svg_append(&buf, &len, &cap, "<") &&
             browser_svg_append(&buf, &len, &cap, node->name);

        if (ok)
        {
            for (const html_attr_t *attr = node->attrs; attr; attr = attr->next)
            {
                if (!attr->name)
                {
                    continue;
                }
                ok = browser_svg_append(&buf, &len, &cap, " ") &&
                     browser_svg_append(&buf, &len, &cap, attr->name) &&
                     browser_svg_append(&buf, &len, &cap, "=\"") &&
                     browser_svg_append(&buf, &len, &cap, attr->value ? attr->value : "") &&
                     browser_svg_append(&buf, &len, &cap, "\"");
                if (!ok)
                {
                    break;
                }
            }
        }
        if (ok)
        {
            ok = browser_svg_append(&buf, &len, &cap, ">");
        }
        if (!ok)
        {
            break;
        }

        if (stack_len + 1 >= stack_cap)
        {
            size_t new_cap = stack_cap * 2u;
            browser_svg_stack_entry_t *next = (browser_svg_stack_entry_t *)realloc(stack, new_cap * sizeof(*next));
            if (!next)
            {
                ok = false;
                break;
            }
            stack = next;
            stack_cap = new_cap;
        }
        stack[stack_len++] = (browser_svg_stack_entry_t){ .node = node, .closing = true };

        for (const html_node_t *child = node->last_child; child; child = child->prev_sibling)
        {
            if (stack_len + 1 >= stack_cap)
            {
                size_t new_cap = stack_cap * 2u;
                browser_svg_stack_entry_t *next = (browser_svg_stack_entry_t *)realloc(stack, new_cap * sizeof(*next));
                if (!next)
                {
                    ok = false;
                    break;
                }
                stack = next;
                stack_cap = new_cap;
            }
            stack[stack_len++] = (browser_svg_stack_entry_t){ .node = child, .closing = false };
        }
    }

    free(stack);

    if (!ok)
    {
        free(buf);
        return NULL;
    }

    *out_len = len;
    return buf;
}

static void browser_inline_svg_process(browser_app_t *app, uint64_t load_id, html_node_t *root)
{
    if (!app || !root)
    {
        return;
    }

    size_t stack_cap = 64;
    size_t stack_len = 0;
    html_node_t **stack = (html_node_t **)malloc(stack_cap * sizeof(*stack));
    if (!stack)
    {
        return;
    }
    stack[stack_len++] = root;

    unsigned svg_index = 0;

    while (stack_len > 0)
    {
        html_node_t *node = stack[--stack_len];
        if (!node)
        {
            continue;
        }

        if (node->type == HTML_NODE_ELEMENT && node->name && strcasecmp(node->name, "svg") == 0)
        {
            if (!browser_load_is_active(app, load_id))
            {
                break;
            }

            size_t svg_len = 0;
            char *svg_text = browser_svg_serialize_node(node, &svg_len);
            if (!svg_text || svg_len == 0)
            {
                free(svg_text);
                continue;
            }

            video_color_t *pixels = NULL;
            int w = 0;
            int h = 0;
            int stride_bytes = 0;
            int rc = -1;

            browser_lock_enter(app, &app->decode_lock, "decode_lock");
            rc = svg_decode_rgba32((const uint8_t *)svg_text, svg_len, &pixels, &w, &h, &stride_bytes);
            browser_lock_exit(app, &app->decode_lock, "decode_lock");

            free(svg_text);

            if (rc != 0 || !pixels || w <= 0 || h <= 0 || stride_bytes <= 0)
            {
                free(pixels);
                continue;
            }

            if (!browser_load_is_active(app, load_id))
            {
                free(pixels);
                break;
            }

            char src_buf[64];
            int written = snprintf(src_buf, sizeof(src_buf), "inline-svg:%llu:%u",
                                   (unsigned long long)load_id,
                                   svg_index++);
            if (written < 0 || written >= (int)sizeof(src_buf))
            {
                free(pixels);
                continue;
            }

            char *img_name = browser_strdup("img");
            if (!img_name)
            {
                free(pixels);
                continue;
            }

            browser_dom_set_attr(node, "src", src_buf);
            free(node->name);
            node->name = img_name;

            browser_ui_event_t img_ev = {0};
            img_ev.type = BROWSER_UI_EVENT_IMAGE_RGBA;
            img_ev.load_id = load_id;
            img_ev.u.image_rgba.src = browser_strdup(src_buf);
            img_ev.u.image_rgba.pixels = pixels;
            img_ev.u.image_rgba.width = w;
            img_ev.u.image_rgba.height = h;
            img_ev.u.image_rgba.stride_bytes = stride_bytes;
            if (!img_ev.u.image_rgba.src)
            {
                browser_ui_event_free_payload(&img_ev);
                continue;
            }
            browser_loader_emit_event(app, &img_ev);
            continue;
        }

        for (html_node_t *child = node->last_child; child; child = child->prev_sibling)
        {
            if (stack_len + 1 >= stack_cap)
            {
                size_t new_cap = stack_cap * 2u;
                html_node_t **next = (html_node_t **)realloc(stack, new_cap * sizeof(*next));
                if (!next)
                {
                    stack_len = 0;
                    break;
                }
                stack = next;
                stack_cap = new_cap;
            }
            stack[stack_len++] = child;
        }
    }

    free(stack);
}

static bool browser_data_url_parse_base64(const char *url,
                                          const char **out_payload,
                                          size_t *out_payload_len,
                                          bool *out_has_type,
                                          bool *out_is_png,
                                          bool *out_is_svg)
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
    bool is_svg = false;

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
        else if (browser_span_equals_ci(token, token_len, "image/svg+xml") ||
                 browser_span_equals_ci(token, token_len, "image/svg"))
        {
            is_svg = true;
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
    if (out_is_svg)
    {
        *out_is_svg = is_svg;
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

static int browser_hex_value(char ch)
{
    if (ch >= '0' && ch <= '9')
    {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f')
    {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F')
    {
        return ch - 'A' + 10;
    }
    return -1;
}

static char *browser_decode_percent(const char *input, size_t len, size_t *out_len)
{
    if (!input || len == 0 || !out_len)
    {
        return NULL;
    }
    if (len > BROWSER_MAX_BYTES)
    {
        return NULL;
    }

    char *out = (char *)malloc(len + 1);
    if (!out)
    {
        return NULL;
    }

    size_t w = 0;
    for (size_t i = 0; i < len; ++i)
    {
        char ch = input[i];
        if (ch == '%' && (i + 2) < len)
        {
            int hi = browser_hex_value(input[i + 1]);
            int lo = browser_hex_value(input[i + 2]);
            if (hi >= 0 && lo >= 0)
            {
                out[w++] = (char)((hi << 4) | lo);
                i += 2;
                continue;
            }
        }
        out[w++] = ch;
    }

    out[w] = '\0';
    *out_len = w;
    return out;
}

static bool browser_handle_data_url_image(browser_app_t *app, uint64_t load_id, const char *url, atk_widget_t *view)
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
    bool is_svg = false;
    if (!browser_data_url_parse_base64(url, &payload, &payload_len, &has_type, &is_png, &is_svg))
    {
        browser_debug_logf(app, "[img] data url unsupported");
        return true;
    }
    if (has_type && !is_png && !is_svg)
    {
        browser_debug_logf(app, "[img] data url skipped (type not png/svg)");
        return true;
    }

    size_t decoded_payload_len = 0;
    char *decoded_payload = browser_decode_percent(payload, payload_len, &decoded_payload_len);
    if (!decoded_payload)
    {
        browser_debug_logf(app, "[img] data url decode failed len=%u", (unsigned)payload_len);
        return true;
    }

    size_t decoded_len = 0;
    uint8_t *decoded = browser_decode_base64(decoded_payload, decoded_payload_len, &decoded_len);
    free(decoded_payload);
    if (!decoded)
    {
        browser_debug_logf(app, "[img] data url base64 decode failed len=%u", (unsigned)payload_len);
        return true;
    }
    bool is_png_bytes = browser_is_png_bytes(decoded, decoded_len);
    bool is_svg_bytes = browser_is_svg_bytes(decoded, decoded_len);
    if (has_type)
    {
        if (is_png && !is_png_bytes)
        {
            browser_debug_logf(app, "[img] data url skipped (not png)");
            free(decoded);
            return true;
        }
        if (is_svg && !is_svg_bytes)
        {
            browser_debug_logf(app, "[img] data url skipped (not svg)");
            free(decoded);
            return true;
        }
    }
    else
    {
        is_png = is_png_bytes;
        is_svg = is_svg_bytes;
    }
    if (!is_png && !is_svg)
    {
        browser_debug_logf(app, "[img] data url skipped (not png/svg)");
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
    if (is_svg)
    {
        rc = svg_decode_rgba32(decoded, decoded_len, &pixels, &w, &h, &stride_bytes);
    }
    else
    {
        rc = png_decode_rgba32(decoded, decoded_len, &pixels, &w, &h, &stride_bytes);
    }
    browser_lock_exit(app, &app->decode_lock, "decode_lock");
    free(decoded);

    if (rc != 0 || !pixels || w <= 0 || h <= 0 || stride_bytes <= 0)
    {
        const char *err = is_svg ? svg_last_error() : png_last_error();
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

    if (view)
    {
        bool ok = atk_html_view_add_image_rgba(view, url, pixels, w, h, stride_bytes);
        if (!ok)
        {
            free(pixels);
            browser_debug_logf(app, "[img] data url apply failed");
        }
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

static bool browser_handle_data_url_css(browser_app_t *app,
                                        uint64_t load_id,
                                        const char *url,
                                        char **out_css,
                                        size_t *out_len)
{
    if (out_css)
    {
        *out_css = NULL;
    }
    if (out_len)
    {
        *out_len = 0;
    }
    if (!app || !url)
    {
        return false;
    }
    if (strncasecmp(url, "data:", 5) != 0)
    {
        return false;
    }

    const char *meta = url + 5;
    const char *comma = strchr(meta, ',');
    if (!comma)
    {
        browser_debug_logf(app, "[css] data url missing comma");
        return true;
    }

    size_t meta_len = (size_t)(comma - meta);
    const char *payload = comma + 1;
    size_t payload_len = payload ? strlen(payload) : 0;

    bool base64 = false;
    bool is_css = false;

    if (meta_len == 0)
    {
        is_css = true;
    }
    else
    {
        const char *cursor = meta;
        const char *semi = browser_find_char(cursor, meta_len, ';');
        size_t type_len = semi ? (size_t)(semi - cursor) : meta_len;
        const char *type_start = cursor;
        browser_trim_span(&type_start, &type_len);
        if (type_len == 0 || browser_span_equals_ci(type_start, type_len, "text/css"))
        {
            is_css = true;
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
    }

    if (!is_css)
    {
        browser_debug_logf(app, "[css] data url skipped (not text/css)");
        return true;
    }

    if (!browser_load_is_active(app, load_id))
    {
        return true;
    }

    char *decoded = NULL;
    size_t decoded_len = 0;
    if (base64)
    {
        uint8_t *bytes = browser_decode_base64(payload, payload_len, &decoded_len);
        if (!bytes)
        {
            browser_debug_logf(app, "[css] data url base64 decode failed len=%u", (unsigned)payload_len);
            return true;
        }
        if (decoded_len > BROWSER_MAX_BYTES)
        {
            free(bytes);
            browser_debug_logf(app, "[css] data url skipped (too large)");
            return true;
        }
        decoded = (char *)malloc(decoded_len + 1);
        if (!decoded)
        {
            free(bytes);
            browser_debug_logf(app, "[css] data url out of memory");
            return true;
        }
        memcpy(decoded, bytes, decoded_len);
        decoded[decoded_len] = '\0';
        free(bytes);
    }
    else
    {
        decoded = browser_decode_percent(payload, payload_len, &decoded_len);
        if (!decoded)
        {
            browser_debug_logf(app, "[css] data url decode failed len=%u", (unsigned)payload_len);
            return true;
        }
    }

    if (!browser_load_is_active(app, load_id))
    {
        free(decoded);
        return true;
    }

    if (out_css)
    {
        *out_css = decoded;
        if (out_len)
        {
            *out_len = decoded_len;
        }
        browser_debug_logf(app, "[css] data url ok bytes=%u", (unsigned)decoded_len);
        return true;
    }

    browser_ui_event_t css_ev = {0};
    css_ev.type = BROWSER_UI_EVENT_CSS_APPEND;
    css_ev.load_id = load_id;
    css_ev.u.css_append.css = decoded;
    css_ev.u.css_append.len = decoded_len;
    browser_loader_emit_event(app, &css_ev);
    browser_debug_logf(app, "[css] data url ok bytes=%u", (unsigned)decoded_len);
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

    uint64_t start_ms = sys_time_millis();
    browser_resource_log_start(app, load_id, kind, abs);

    if (kind == BROWSER_RESOURCE_SCRIPT && !browser_js_enabled(app))
    {
        uint64_t elapsed_ms = sys_time_millis() - start_ms;
        browser_resource_log_done(app, load_id, kind, abs, "disabled", elapsed_ms, 0, "js disabled");
        free(abs);
        return;
    }

    if (kind == BROWSER_RESOURCE_IMAGE)
    {
        if (browser_handle_data_url_image(app, load_id, abs, NULL))
        {
            uint64_t elapsed_ms = sys_time_millis() - start_ms;
            browser_resource_log_done(app, load_id, kind, abs, "data", elapsed_ms, 0, NULL);
            free(abs);
            return;
        }
    }
    if (kind == BROWSER_RESOURCE_CSS)
    {
        if (browser_handle_data_url_css(app, load_id, abs, NULL, NULL))
        {
            uint64_t elapsed_ms = sys_time_millis() - start_ms;
            browser_resource_log_done(app, load_id, kind, abs, "data", elapsed_ms, 0, NULL);
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
    const char *log_status = NULL;
    const char *log_detail = NULL;
    size_t log_bytes = 0;
    int status_code = 0;
    char *status_detail = NULL;
    bool parsed = browser_parse_url(abs, &res_url);
    if (parsed)
    {
        res_body = browser_fetch_http_with_status(app, &res_url, &res_len, &res_final, &status_code);
        if (status_code >= 400)
        {
            log_status = "fail";
            status_detail = (char *)malloc(32);
            if (status_detail)
            {
                snprintf(status_detail, 32, "http %d", status_code);
                log_detail = status_detail;
            }
            else
            {
                log_detail = "http error";
            }
        }
    }
    else
    {
        log_status = "fail";
        log_detail = "invalid url";
    }

    if (!browser_load_is_active(app, load_id))
    {
        free(res_body);
        browser_url_destroy(&res_url);
        browser_url_destroy(&res_final);
        free(abs);
        return;
    }

    if (!log_status)
    {
        if (res_body && strncmp(res_body, "Error:\n", 6) != 0)
        {
            log_status = "ok";
            log_bytes = res_len;
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
                browser_css_log_sniff(app,
                                      abs,
                                      (const uint8_t *)css_ev.u.css_append.css,
                                      css_ev.u.css_append.len);
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
                    log_status = "fail";
                    log_detail = "queue failed";
                }
            }
            else if (kind == BROWSER_RESOURCE_IMAGE)
            {
                bool is_gif = browser_is_gif_bytes((const uint8_t *)res_body, res_len);
                bool is_png = (!is_gif && browser_is_png_bytes((const uint8_t *)res_body, res_len));
                bool is_svg = (!is_gif && !is_png && browser_is_svg_bytes((const uint8_t *)res_body, res_len));
                if (is_gif || is_png || is_svg)
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
                    else if (is_png)
                    {
                        rc = png_decode_rgba32((const uint8_t *)res_body,
                                               res_len,
                                               &pixels,
                                               &w,
                                               &h,
                                               &stride_bytes);
                    }
                    else
                    {
                        rc = svg_decode_rgba32((const uint8_t *)res_body,
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
                        const char *err = is_gif ? gif_last_error() : (is_png ? png_last_error() : svg_last_error());
                        browser_debug_logf(app,
                                           "[img] decode failed url=%s err=%s",
                                           abs ? abs : "(null)",
                                           err ? err : "(unknown)");
                        log_status = "fail";
                        log_detail = err ? err : "decode failed";
                        free(pixels);
                    }
                }
                else
                {
                    browser_debug_logf(app, "[img] skipped (not png/gif/svg) url=%s", abs);
                    log_status = "skip";
                    log_detail = "unsupported type";
                }
            }
        }
        else
        {
            const char *msg = res_body ? (res_body + 6) : "allocation failed";
            log_status = "fail";
            log_detail = msg;
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
    }

    {
        uint64_t elapsed_ms = sys_time_millis() - start_ms;
        browser_resource_log_done(app, load_id, kind, abs, log_status, elapsed_ms, log_bytes, log_detail);
    }

    free(res_body);
    browser_url_destroy(&res_url);
    browser_url_destroy(&res_final);
    free(abs);
    free(status_detail);
}

static void browser_resource_worker_thread(void *arg)
{
    browser_app_t *app = (browser_app_t *)arg;
    if (!app)
    {
        return;
    }

    while (__atomic_load_n(&app->resource_thread_stop, __ATOMIC_ACQUIRE) == 0u)
    {
        browser_resource_job_t *job = browser_resource_queue_pop(app);
        if (!job)
        {
            (void)sys_sleep_ms(1);
            continue;
        }
        browser_resource_fetch(app, job->load_id, job->kind, job->url);
        free(job);
    }
}

bool browser_resource_worker_start(browser_app_t *app)
{
    if (!app)
    {
        return false;
    }

    browser_lock_enter(app, &app->resource_lock, "resource_lock");
    if (app->resource_thread != 0)
    {
        browser_lock_exit(app, &app->resource_lock, "resource_lock");
        return true;
    }
    __atomic_store_n(&app->resource_thread_stop, 0u, __ATOMIC_RELEASE);
    browser_lock_exit(app, &app->resource_lock, "resource_lock");

    alix_thread_t thread = 0;
    if (alix_thread_create(&thread, "atk_browser_res", browser_resource_worker_thread, app) != 0)
    {
        return false;
    }

    browser_lock_enter(app, &app->resource_lock, "resource_lock");
    app->resource_thread = thread;
    browser_lock_exit(app, &app->resource_lock, "resource_lock");
    return true;
}

void browser_resource_worker_stop(browser_app_t *app)
{
    if (!app)
    {
        return;
    }

    alix_thread_t thread = 0;
    browser_lock_enter(app, &app->resource_lock, "resource_lock");
    thread = app->resource_thread;
    __atomic_store_n(&app->resource_thread_stop, 1u, __ATOMIC_RELEASE);
    browser_lock_exit(app, &app->resource_lock, "resource_lock");

    if (thread != 0)
    {
        (void)alix_thread_join(thread, NULL);
    }

    browser_lock_enter(app, &app->resource_lock, "resource_lock");
    app->resource_thread = 0;
    browser_lock_exit(app, &app->resource_lock, "resource_lock");
    browser_resource_queue_clear(app);
}

static void browser_html_worker_thread(void *arg)
{
    browser_app_t *app = (browser_app_t *)arg;
    if (!app)
    {
        return;
    }

    while (__atomic_load_n(&app->html_thread_stop, __ATOMIC_ACQUIRE) == 0u)
    {
        browser_load_request_t *req = browser_load_queue_pop(app);
        if (!req)
        {
            if (app->viewer)
            {
                (void)atk_html_view_rebuild_cache_if_pending(app->viewer);
            }
            (void)sys_sleep_ms(1);
            continue;
        }

        if (req->kind == BROWSER_LOAD_JOB_REBUILD)
        {
            if (app->viewer && browser_load_is_active(app, req->load_id))
            {
                (void)atk_html_view_rebuild_cache(app->viewer);
            }
            free(req);
            continue;
        }

        browser_load_job_t *job = (browser_load_job_t *)calloc(1, sizeof(*job));
        if (!job)
        {
            free(req->url_text);
            free(req);
            continue;
        }
        job->app = app;
        job->load_id = req->load_id;
        job->url_text = req->url_text;
        req->url_text = NULL;
        browser_load_thread(job);

        free(req);
    }
}

bool browser_html_worker_start(browser_app_t *app)
{
    if (!app)
    {
        return false;
    }

    browser_lock_enter(app, &app->load_lock, "load_lock");
    if (app->html_thread != 0)
    {
        browser_lock_exit(app, &app->load_lock, "load_lock");
        return true;
    }
    __atomic_store_n(&app->html_thread_stop, 0u, __ATOMIC_RELEASE);
    browser_lock_exit(app, &app->load_lock, "load_lock");

    alix_thread_t thread = 0;
    if (alix_thread_create(&thread, "atk_browser_html", browser_html_worker_thread, app) != 0)
    {
        return false;
    }

    browser_lock_enter(app, &app->load_lock, "load_lock");
    app->html_thread = thread;
    browser_lock_exit(app, &app->load_lock, "load_lock");
    return true;
}

void browser_html_worker_stop(browser_app_t *app)
{
    if (!app)
    {
        return;
    }

    alix_thread_t thread = 0;
    browser_lock_enter(app, &app->load_lock, "load_lock");
    thread = app->html_thread;
    __atomic_store_n(&app->html_thread_stop, 1u, __ATOMIC_RELEASE);
    browser_lock_exit(app, &app->load_lock, "load_lock");

    if (thread != 0)
    {
        (void)alix_thread_join(thread, NULL);
    }

    browser_lock_enter(app, &app->load_lock, "load_lock");
    app->html_thread = 0;
    browser_lock_exit(app, &app->load_lock, "load_lock");
    browser_load_queue_clear(app);
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

static void browser_resource_queue_release(browser_resource_queue_t *queue)
{
    if (!queue)
    {
        return;
    }

    browser_resource_job_t *job = queue->head;
    while (job)
    {
        browser_resource_job_t *next = job->next;
        free(job->url);
        free(job);
        job = next;
    }
    queue->head = NULL;
    queue->tail = NULL;
    queue->count = 0;
}

static void browser_resource_queue_process_inline(browser_app_t *app, browser_resource_queue_t *queue)
{
    if (!app || !queue)
    {
        return;
    }

    browser_resource_job_t *job = queue->head;
    while (job)
    {
        browser_resource_job_t *next = job->next;
        browser_resource_fetch(app, job->load_id, job->kind, job->url);
        free(job);
        job = next;
    }
    queue->head = NULL;
    queue->tail = NULL;
    queue->count = 0;
}

static bool browser_resource_fetch_image_inline(browser_app_t *app, uint64_t load_id, char *abs)
{
    if (!abs)
    {
        return false;
    }
    if (!app)
    {
        free(abs);
        return false;
    }
    if (!browser_load_is_active(app, load_id))
    {
        free(abs);
        return false;
    }

    uint64_t start_ms = sys_time_millis();
    browser_resource_log_start(app, load_id, BROWSER_RESOURCE_IMAGE, abs);

    if (browser_handle_data_url_image(app, load_id, abs, app->viewer))
    {
        uint64_t elapsed_ms = sys_time_millis() - start_ms;
        browser_resource_log_done(app, load_id, BROWSER_RESOURCE_IMAGE, abs, "data", elapsed_ms, 0, NULL);
        free(abs);
        return true;
    }

    browser_debug_logf(app, "[img] fetch %s", abs);

    browser_url_t res_url = {0};
    browser_url_t res_final = {0};
    size_t res_len = 0;
    char *res_body = NULL;
    const char *log_status = NULL;
    const char *log_detail = NULL;
    size_t log_bytes = 0;
    int status_code = 0;
    char *status_detail = NULL;
    bool parsed = browser_parse_url(abs, &res_url);
    if (parsed)
    {
        res_body = browser_fetch_http_with_status(app, &res_url, &res_len, &res_final, &status_code);
        if (status_code >= 400)
        {
            log_status = "fail";
            status_detail = (char *)malloc(32);
            if (status_detail)
            {
                snprintf(status_detail, 32, "http %d", status_code);
                log_detail = status_detail;
            }
            else
            {
                log_detail = "http error";
            }
        }
    }
    else
    {
        log_status = "fail";
        log_detail = "invalid url";
    }

    if (!browser_load_is_active(app, load_id))
    {
        free(res_body);
        browser_url_destroy(&res_url);
        browser_url_destroy(&res_final);
        free(abs);
        free(status_detail);
        return false;
    }

    bool added = false;
    if (!log_status)
    {
        if (res_body && strncmp(res_body, "Error:\n", 6) != 0)
        {
            bool is_gif = browser_is_gif_bytes((const uint8_t *)res_body, res_len);
            bool is_png = (!is_gif && browser_is_png_bytes((const uint8_t *)res_body, res_len));
            bool is_svg = (!is_gif && !is_png && browser_is_svg_bytes((const uint8_t *)res_body, res_len));
            if (is_gif || is_png || is_svg)
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
                else if (is_png)
                {
                    rc = png_decode_rgba32((const uint8_t *)res_body,
                                           res_len,
                                           &pixels,
                                           &w,
                                           &h,
                                           &stride_bytes);
                }
                else
                {
                    rc = svg_decode_rgba32((const uint8_t *)res_body,
                                           res_len,
                                           &pixels,
                                           &w,
                                           &h,
                                           &stride_bytes);
                }
                browser_lock_exit(app, &app->decode_lock, "decode_lock");

                if (rc == 0 && pixels && w > 0 && h > 0 && stride_bytes > 0)
                {
                    if (!browser_load_is_active(app, load_id))
                    {
                        free(pixels);
                        free(status_detail);
                        free(res_body);
                        browser_url_destroy(&res_url);
                        browser_url_destroy(&res_final);
                        free(abs);
                        return false;
                    }
                    bool ok = app->viewer &&
                              atk_html_view_add_image_rgba(app->viewer, abs, pixels, w, h, stride_bytes);
                    if (ok)
                    {
                        added = true;
                        log_status = "ok";
                        log_bytes = res_len;
                        browser_debug_logf(app, "[img] ok bytes=%u url=%s", (unsigned)res_len, abs);
                    }
                    else
                    {
                        free(pixels);
                        log_status = "fail";
                        log_detail = "apply failed";
                    }
                }
                else
                {
                    const char *err = is_gif ? gif_last_error() : (is_png ? png_last_error() : svg_last_error());
                    browser_debug_logf(app,
                                       "[img] decode failed url=%s err=%s",
                                       abs ? abs : "(null)",
                                       err ? err : "(unknown)");
                    log_status = "fail";
                    log_detail = err ? err : "decode failed";
                    free(pixels);
                }
            }
            else
            {
                browser_debug_logf(app, "[img] skipped (not png/gif/svg) url=%s", abs);
                log_status = "skip";
                log_detail = "unsupported type";
            }
        }
        else
        {
            const char *msg = res_body ? (res_body + 6) : "allocation failed";
            log_status = "fail";
            log_detail = msg;
            browser_debug_logf(app, "[img] failed url=%s err=%s", abs ? abs : "(null)", msg);
        }
    }

    {
        uint64_t elapsed_ms = sys_time_millis() - start_ms;
        browser_resource_log_done(app, load_id, BROWSER_RESOURCE_IMAGE, abs, log_status, elapsed_ms, log_bytes, log_detail);
    }

    free(res_body);
    browser_url_destroy(&res_url);
    browser_url_destroy(&res_final);
    free(abs);
    free(status_detail);
    return added;
}

static void browser_resource_queue_process_images_inline(browser_app_t *app,
                                                         uint64_t load_id,
                                                         browser_resource_queue_t *queue)
{
    if (!app || !queue)
    {
        return;
    }

    browser_resource_job_t *job = queue->head;
    queue->head = NULL;
    queue->tail = NULL;
    queue->count = 0;

    while (job)
    {
        browser_resource_job_t *next = job->next;
        char *abs = job->url;
        job->url = NULL;
        free(job);
        job = next;

        if (!abs)
        {
            continue;
        }
        if (!browser_load_is_active(app, load_id))
        {
            free(abs);
            while (job)
            {
                browser_resource_job_t *drop = job;
                job = job->next;
                free(drop->url);
                free(drop);
            }
            break;
        }

        bool added = browser_resource_fetch_image_inline(app, load_id, abs);
        if (added)
        {
            (void)atk_html_view_rebuild_cache_if_pending(app->viewer);
        }
    }
}

static char *browser_resource_queue_fetch_css(browser_app_t *app,
                                              uint64_t load_id,
                                              browser_resource_queue_t *queue,
                                              size_t *out_len)
{
    if (out_len)
    {
        *out_len = 0;
    }
    if (!app || !queue || !queue->head)
    {
        return NULL;
    }

    size_t css_jobs = queue->count;
    serial_printf("[css] queue start id=%llu count=%u",
                  (unsigned long long)load_id,
                  (unsigned)css_jobs);

    char *css_buf = NULL;
    size_t css_len = 0;
    size_t css_cap = 0;

    browser_resource_job_t *job = queue->head;
    queue->head = NULL;
    queue->tail = NULL;
    queue->count = 0;

    while (job)
    {
        browser_resource_job_t *next = job->next;
        char *abs = job->url;
        job->url = NULL;
        free(job);
        job = next;

        if (!abs)
        {
            continue;
        }
        if (!browser_load_is_active(app, load_id))
        {
            free(abs);
            while (job)
            {
                browser_resource_job_t *drop = job;
                job = job->next;
                free(drop->url);
                free(drop);
            }
            break;
        }

        uint64_t start_ms = sys_time_millis();
        browser_resource_log_start(app, load_id, BROWSER_RESOURCE_CSS, abs);

        if (abs && strncasecmp(abs, "data:", 5) == 0)
        {
            char *decoded = NULL;
            size_t decoded_len = 0;
            (void)browser_handle_data_url_css(app, load_id, abs, &decoded, &decoded_len);
            const char *log_status = "data";
            const char *log_detail = NULL;
            size_t log_bytes = decoded_len;
            if (decoded && decoded_len > 0)
            {
                if (!browser_buf_append(&css_buf, &css_len, &css_cap, (const uint8_t *)decoded, decoded_len) ||
                    !browser_buf_append(&css_buf, &css_len, &css_cap, (const uint8_t *)"\n", 1))
                {
                    log_status = "fail";
                    log_detail = "css append failed";
                }
            }
            uint64_t elapsed_ms = sys_time_millis() - start_ms;
            browser_resource_log_done(app, load_id, BROWSER_RESOURCE_CSS, abs, log_status, elapsed_ms, log_bytes, log_detail);
            free(decoded);
            free(abs);
            continue;
        }

        browser_url_t res_url = {0};
        browser_url_t res_final = {0};
        size_t res_len = 0;
        char *res_body = NULL;
        const char *log_status = NULL;
        const char *log_detail = NULL;
        size_t log_bytes = 0;
        int status_code = 0;
        char *status_detail = NULL;
        bool parsed = browser_parse_url(abs, &res_url);
        if (parsed)
        {
            res_body = browser_fetch_http_with_status(app, &res_url, &res_len, &res_final, &status_code);
            if (status_code >= 400)
            {
                log_status = "fail";
                status_detail = (char *)malloc(32);
                if (status_detail)
                {
                    snprintf(status_detail, 32, "http %d", status_code);
                    log_detail = status_detail;
                }
                else
                {
                    log_detail = "http error";
                }
            }
        }
        else
        {
            log_status = "fail";
            log_detail = "invalid url";
        }

        if (!log_status)
        {
            if (res_body && strncmp(res_body, "Error:\n", 6) != 0)
            {
                if (browser_buf_append(&css_buf, &css_len, &css_cap, (const uint8_t *)res_body, res_len))
                {
                    (void)browser_buf_append(&css_buf, &css_len, &css_cap, (const uint8_t *)"\n", 1);
                    log_status = "ok";
                    log_bytes = res_len;
                    browser_css_log_sniff(app, abs, (const uint8_t *)res_body, res_len);
                }
                else
                {
                    log_status = "fail";
                    log_detail = "css append failed";
                }
            }
        }

        if (!log_status)
        {
            log_status = "fail";
            log_detail = "fetch failed";
        }

        uint64_t elapsed_ms = sys_time_millis() - start_ms;
        browser_resource_log_done(app, load_id, BROWSER_RESOURCE_CSS, abs, log_status, elapsed_ms, log_bytes, log_detail);

        free(status_detail);
        free(res_body);
        browser_url_destroy(&res_url);
        browser_url_destroy(&res_final);
        free(abs);
    }

    if (css_buf && css_len > 0 && browser_load_is_active(app, load_id))
    {
        if (out_len)
        {
            *out_len = css_len;
        }
        serial_printf("[css] queue done id=%llu bytes=%u",
                      (unsigned long long)load_id,
                      (unsigned)css_len);
        return css_buf;
    }

    free(css_buf);
    serial_printf("[css] queue done id=%llu bytes=0",
                  (unsigned long long)load_id);
    return NULL;
}

static void browser_emit_nav_update(browser_app_t *app, uint64_t load_id, const browser_url_t *final_url)
{
    if (!app || !final_url)
    {
        return;
    }

    char *final_text = browser_url_to_string(final_url);
    if (!final_text)
    {
        return;
    }

    browser_ui_event_t ev = {0};
    ev.type = BROWSER_UI_EVENT_NAV_UPDATE;
    ev.load_id = load_id;
    ev.u.nav_update.final_url = final_text;
    browser_loader_emit_event(app, &ev);
}

static void browser_apply_error_page(browser_app_t *app, uint64_t load_id, const char *message)
{
    if (!app || !app->viewer)
    {
        return;
    }
    if (!browser_load_is_active(app, load_id))
    {
        return;
    }

    const char *msg = message ? message : "unknown error";
    serial_printf("[load] error id=%llu msg=%s",
                  (unsigned long long)load_id,
                  msg);
    char page_buf[512];
    snprintf(page_buf,
             sizeof(page_buf),
             "<!doctype html><html><body><p>Fetch error:</p><p>%s</p></body></html>",
             msg);
    (void)atk_html_view_set_html(app->viewer, page_buf, NULL);
    (void)atk_html_view_rebuild_cache(app->viewer);
}

static void browser_apply_loading_page(browser_app_t *app, uint64_t load_id)
{
    if (!app || !app->viewer)
    {
        return;
    }
    if (!browser_load_is_active(app, load_id))
    {
        return;
    }

    serial_printf("[load] loading id=%llu", (unsigned long long)load_id);
    (void)atk_html_view_set_html(app->viewer,
                                 "<!doctype html><html><head><style>"
                                 "body{margin:0;padding:0;}"
                                 "p{margin-top:40vh;text-align:center;font-size:16px;color:#444;}"
                                 "</style></head><body><p>Loading...</p></body></html>",
                                 NULL);
    (void)atk_html_view_rebuild_cache(app->viewer);
}

static void browser_apply_document(browser_app_t *app,
                                   uint64_t load_id,
                                   html_document_t *doc,
                                   const browser_url_t *final_url)
{
    if (!app || !doc || !app->viewer)
    {
        if (doc)
        {
            html_document_destroy(doc);
        }
        return;
    }
    if (!browser_load_is_active(app, load_id))
    {
        html_document_destroy(doc);
        return;
    }

    atk_html_view_set_document(app->viewer, doc);
    (void)atk_html_view_rebuild_cache(app->viewer);
    browser_debug_logf(app, "[render] set document ok");
    serial_printf("[render] set document id=%llu doc=%p",
                  (unsigned long long)load_id,
                  (void *)doc);
    browser_emit_nav_update(app, load_id, final_url);
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
    serial_printf("[load] start id=%llu url=%s",
                  (unsigned long long)load_id,
                  url_text ? url_text : "(null)");

    if (!url_text || url_text[0] == '\0')
    {
        browser_apply_error_page(app, load_id, "missing url");
        goto done;
    }

    browser_apply_loading_page(app, load_id);

    browser_url_t url = {0};
    browser_url_t final_url = {0};
    char *html = NULL;
    size_t html_len = 0;

    if (!browser_parse_url(url_text, &url))
    {
        browser_apply_error_page(app, load_id, "invalid url");
        goto done_fetch;
    }

    browser_debug_logf(app,
                       "[load] parsed tls=%d host=%s port=%u path=%s",
                       url.use_tls ? 1 : 0,
                       url.host ? url.host : "(null)",
                       (unsigned)url.port,
                       url.path ? url.path : "(null)");
    serial_printf("[load] parsed id=%llu tls=%u host=%s port=%u path=%s",
                  (unsigned long long)load_id,
                  url.use_tls ? 1u : 0u,
                  url.host ? url.host : "(null)",
                  (unsigned)url.port,
                  url.path ? url.path : "(null)");

    html = browser_fetch_http(app, &url, &html_len, &final_url);
    if (!html)
    {
        browser_apply_error_page(app, load_id, "allocation failed");
        goto done_fetch;
    }
    if (strncmp(html, "Error:\n", 6) == 0)
    {
        browser_apply_error_page(app, load_id, html + 6);
        goto done_fetch;
    }

    if (!browser_load_is_active(app, load_id))
    {
        browser_debug_logf(app, "[load] canceled before parse id=%llu", (unsigned long long)load_id);
        serial_printf("[load] canceled id=%llu stage=before-parse",
                      (unsigned long long)load_id);
        goto done_fetch;
    }

    browser_debug_logf(app, "[load] html bytes=%u", (unsigned)html_len);
    serial_printf("[load] html id=%llu bytes=%u",
                  (unsigned long long)load_id,
                  (unsigned)html_len);
    html_parse_error_t parse_err = {0};
    html_document_t *doc = html_parse(html, &parse_err);
    if (!doc)
    {
        const char *detail = parse_err.message ? parse_err.message : "parse failed";
        browser_apply_error_page(app, load_id, detail);
        goto done_fetch;
    }
    if (doc->root)
    {
        browser_inline_svg_process(app, load_id, doc->root);
    }

    size_t css_count = 0;
    size_t img_count = 0;
    size_t script_count = 0;
    browser_resource_queue_t css_queue = {0};
    browser_resource_queue_t img_queue = {0};
    browser_resource_queue_t script_queue = {0};
    bool use_css = true;
    bool js_enabled = browser_js_enabled(app);
    if (doc->root)
    {
        if (use_css)
        {
            css_count = browser_collect_resource_urls(app,
                                                      doc->root,
                                                      &final_url,
                                                      &job->requested,
                                                      BROWSER_RESOURCE_CSS,
                                                      load_id,
                                                      &css_queue);
        }
        script_count = browser_collect_resource_urls(app,
                                                     doc->root,
                                                     &final_url,
                                                     &job->requested,
                                                     BROWSER_RESOURCE_SCRIPT,
                                                     load_id,
                                                     js_enabled ? &script_queue : NULL);
        img_count = browser_collect_resource_urls(app,
                                                  doc->root,
                                                  &final_url,
                                                  &job->requested,
                                                  BROWSER_RESOURCE_IMAGE,
                                                  load_id,
                                                  &img_queue);
    }

    if (!browser_load_is_active(app, load_id))
    {
        browser_debug_logf(app, "[load] canceled after parse id=%llu", (unsigned long long)load_id);
        serial_printf("[load] canceled id=%llu stage=after-parse",
                      (unsigned long long)load_id);
        html_document_destroy(doc);
        doc = NULL;
        goto done_resources;
    }

    if (css_count > 0)
    {
        browser_debug_logf(app, "[css] total stylesheets=%u", (unsigned)css_count);
        serial_printf("[css] total id=%llu count=%u",
                      (unsigned long long)load_id,
                      (unsigned)css_count);
    }
    if (script_count > 0)
    {
        browser_debug_logf(app, "[js] total scripts=%u", (unsigned)script_count);
        serial_printf("[js] total id=%llu count=%u",
                      (unsigned long long)load_id,
                      (unsigned)script_count);
    }
    if (!js_enabled && script_count > 0)
    {
        browser_debug_logf(app, "[js] disabled (skip %u scripts)", (unsigned)script_count);
        serial_printf("[js] disabled id=%llu skip=%u",
                      (unsigned long long)load_id,
                      (unsigned)script_count);
    }
    if (img_count > 0)
    {
        browser_debug_logf(app, "[img] total images=%u", (unsigned)img_count);
        serial_printf("[img] total id=%llu count=%u",
                      (unsigned long long)load_id,
                      (unsigned)img_count);
    }

    if (!browser_load_is_active(app, load_id))
    {
        goto done_resources;
    }

    if (doc && doc->root)
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
            serial_printf("[parse] title id=%llu %s",
                          (unsigned long long)load_id,
                          title_preview);
        }
        browser_debug_logf(app, "[parse] nodes=%u body=%s",
                           (unsigned)node_count,
                           body ? "yes" : "no");
        serial_printf("[parse] nodes id=%llu count=%u body=%u",
                      (unsigned long long)load_id,
                      (unsigned)node_count,
                      body ? 1u : 0u);
    }

    bool wait_for_css = (use_css && css_count > 0);
    atk_html_view_set_wait_for_css(app->viewer, wait_for_css);
    serial_printf("[css] wait id=%llu enabled=%u",
                  (unsigned long long)load_id,
                  wait_for_css ? 1u : 0u);
    browser_apply_document(app, load_id, doc, &final_url);
    doc = NULL;

    if (wait_for_css)
    {
        size_t css_len = 0;
        char *css_buf = browser_resource_queue_fetch_css(app, load_id, &css_queue, &css_len);
        if (browser_load_is_active(app, load_id))
        {
            atk_html_view_set_wait_for_css(app->viewer, false);
            if (css_buf && css_len > 0)
            {
                bool ok = atk_html_view_try_set_external_stylesheet(app->viewer, css_buf);
                if (!ok)
                {
                    atk_html_view_set_external_stylesheet(app->viewer, css_buf);
                }
                browser_debug_logf(app, "[css] external bytes=%u", (unsigned)css_len);
                serial_printf("[css] external id=%llu bytes=%u ok=%u",
                              (unsigned long long)load_id,
                              (unsigned)css_len,
                              ok ? 1u : 0u);
            }
            else
            {
                serial_printf("[css] external id=%llu bytes=0",
                              (unsigned long long)load_id);
            }
        }
        free(css_buf);
    }

    bool resource_stop = (__atomic_load_n(&app->resource_thread_stop, __ATOMIC_ACQUIRE) != 0u);
    if (!browser_resource_queue_append(app, &script_queue))
    {
        if (resource_stop)
        {
            browser_resource_queue_release(&script_queue);
        }
        else
        {
            browser_resource_queue_process_inline(app, &script_queue);
        }
    }
    browser_resource_queue_process_images_inline(app, load_id, &img_queue);

done_resources:
    browser_resource_queue_release(&css_queue);
    browser_resource_queue_release(&script_queue);
    browser_resource_queue_release(&img_queue);
    serial_printf("[load] done id=%llu", (unsigned long long)load_id);

done_fetch:
    free(html);
    browser_url_destroy(&url);
    browser_url_destroy(&final_url);

done:
    free(url_text);
    browser_resource_set_destroy(&job->requested);
    free(job);
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
    serial_printf("[load] queue id=%llu url=%s",
                  (unsigned long long)load_id,
                  url_text);
    browser_app_css_reset(app);
    browser_resource_queue_clear(app);
    browser_load_queue_clear(app);

    if (!browser_html_worker_start(app))
    {
        browser_debug_logf(app, "[ui] failed to start html worker");
        browser_lock_enter(app, &app->lock, "app_lock");
        if (app->active_load_id == load_id)
        {
            app->active_load_id = 0;
        }
        browser_lock_exit(app, &app->lock, "app_lock");
        free(url_copy);
        return false;
    }

    if (!browser_load_queue_push(app, BROWSER_LOAD_JOB_URL, load_id, url_copy))
    {
        browser_debug_logf(app, "[ui] failed to queue load job");
        browser_lock_enter(app, &app->lock, "app_lock");
        if (app->active_load_id == load_id)
        {
            app->active_load_id = 0;
        }
        browser_lock_exit(app, &app->lock, "app_lock");
        return false;
    }
    return true;
}
