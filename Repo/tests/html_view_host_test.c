#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>

#include "atk/html_view/html_view_internal.h"
#include "atk/html_view/render/render_internal.h"
#include "atk/util/png.h"
#include "libc.h"
#include "video.h"
#include "web/css.h"
#include "web/html.h"

char *html_view_strdup(const char *src)
{
    if (!src)
    {
        return NULL;
    }
    size_t len = strlen(src);
    char *copy = (char *)malloc(len + 1);
    if (!copy)
    {
        return NULL;
    }
    memcpy(copy, src, len + 1);
    return copy;
}

video_color_t video_make_color(uint8_t r, uint8_t g, uint8_t b)
{
    return 0xFF000000U | ((video_color_t)r << 16) | ((video_color_t)g << 8) | (video_color_t)b;
}

static video_color_t *g_surface = NULL;
static int g_surface_width = 0;
static int g_surface_height = 0;

static bool surface_init(int width, int height, video_color_t bg)
{
    if (width <= 0 || height <= 0)
    {
        return false;
    }
    size_t count = (size_t)width * (size_t)height;
    if (count == 0 || count > (SIZE_MAX / sizeof(video_color_t)))
    {
        return false;
    }

    g_surface = (video_color_t *)malloc(count * sizeof(video_color_t));
    if (!g_surface)
    {
        return false;
    }
    g_surface_width = width;
    g_surface_height = height;
    for (size_t i = 0; i < count; ++i)
    {
        g_surface[i] = bg;
    }
    return true;
}

static void surface_destroy(void)
{
    free(g_surface);
    g_surface = NULL;
    g_surface_width = 0;
    g_surface_height = 0;
}

static void surface_clear(video_color_t color)
{
    if (!g_surface || g_surface_width <= 0 || g_surface_height <= 0)
    {
        return;
    }
    size_t count = (size_t)g_surface_width * (size_t)g_surface_height;
    for (size_t i = 0; i < count; ++i)
    {
        g_surface[i] = color;
    }
}

int serial_printf(const char *format, ...)
{
    (void)format;
    return 0;
}

ssize_t sys_font_cache(void *buffer, size_t capacity)
{
    const char *path = "PublicSans.ttf";
    FILE *fp = fopen(path, "rb");
    if (!fp)
    {
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0)
    {
        fclose(fp);
        return -1;
    }
    long size = ftell(fp);
    if (size < 0)
    {
        fclose(fp);
        return -1;
    }
    if (!buffer || capacity == 0)
    {
        fclose(fp);
        return (ssize_t)size;
    }
    if ((size_t)size > capacity)
    {
        fclose(fp);
        return -1;
    }
    rewind(fp);

    size_t read_len = fread(buffer, 1, (size_t)size, fp);
    fclose(fp);
    return (ssize_t)read_len;
}

int video_screen_width(void)
{
    return g_surface_width;
}

int video_screen_height(void)
{
    return g_surface_height;
}

void video_draw_rect(int x, int y, int width, int height, video_color_t color)
{
    if (!g_surface || width <= 0 || height <= 0)
    {
        return;
    }

    int x0 = x;
    int y0 = y;
    int x1 = x + width;
    int y1 = y + height;

    if (x1 <= 0 || y1 <= 0 || x0 >= g_surface_width || y0 >= g_surface_height)
    {
        return;
    }

    if (x0 < 0) x0 = 0;
    if (y0 < 0) y0 = 0;
    if (x1 > g_surface_width) x1 = g_surface_width;
    if (y1 > g_surface_height) y1 = g_surface_height;

    for (int row = y0; row < y1; ++row)
    {
        video_color_t *dst = &g_surface[(size_t)row * (size_t)g_surface_width + (size_t)x0];
        for (int col = x0; col < x1; ++col)
        {
            *dst++ = color;
        }
    }
}

void video_draw_text(int x, int y, const char *text, video_color_t fg, video_color_t bg)
{
    (void)x;
    (void)y;
    (void)text;
    (void)fg;
    (void)bg;
}

void video_blit_rgba32_untracked(int dst_x,
                                 int dst_y,
                                 int width,
                                 int height,
                                 const video_color_t *pixels,
                                 int stride_bytes,
                                 bool use_alpha)
{
    if (!g_surface || !pixels || width <= 0 || height <= 0)
    {
        return;
    }

    if (stride_bytes <= 0)
    {
        stride_bytes = width * (int)sizeof(video_color_t);
    }

    int x0 = dst_x;
    int y0 = dst_y;
    int x1 = dst_x + width;
    int y1 = dst_y + height;
    int src_x = 0;
    int src_y = 0;

    if (x0 < 0) { src_x = -x0; x0 = 0; }
    if (y0 < 0) { src_y = -y0; y0 = 0; }
    if (x1 > g_surface_width) x1 = g_surface_width;
    if (y1 > g_surface_height) y1 = g_surface_height;

    int copy_w = x1 - x0;
    int copy_h = y1 - y0;
    if (copy_w <= 0 || copy_h <= 0)
    {
        return;
    }

    const uint8_t *row = (const uint8_t *)pixels +
                         (size_t)src_y * (size_t)stride_bytes +
                         (size_t)src_x * sizeof(video_color_t);
    for (int row_idx = 0; row_idx < copy_h; ++row_idx)
    {
        const video_color_t *src_row = (const video_color_t *)row;
        video_color_t *dst = &g_surface[(size_t)(y0 + row_idx) * (size_t)g_surface_width + (size_t)x0];
        if (!use_alpha)
        {
            memcpy(dst, src_row, (size_t)copy_w * sizeof(video_color_t));
        }
        else
        {
            for (int col = 0; col < copy_w; ++col)
            {
                video_color_t src_px = src_row[col];
                uint8_t a = (uint8_t)(src_px >> 24);
                if (a == 0)
                {
                    continue;
                }
                if (a == 255)
                {
                    dst[col] = src_px;
                    continue;
                }

                uint8_t sr = (uint8_t)(src_px >> 16);
                uint8_t sg = (uint8_t)(src_px >> 8);
                uint8_t sb = (uint8_t)src_px;

                video_color_t dst_px = dst[col];
                uint8_t dr = (uint8_t)(dst_px >> 16);
                uint8_t dg = (uint8_t)(dst_px >> 8);
                uint8_t db = (uint8_t)dst_px;

                uint8_t ia = (uint8_t)(255 - a);
                uint8_t rr = (uint8_t)((sr * a + dr * ia) / 255);
                uint8_t rg = (uint8_t)((sg * a + dg * ia) / 255);
                uint8_t rb = (uint8_t)((sb * a + db * ia) / 255);

                dst[col] = 0xFF000000U | ((video_color_t)rr << 16) |
                           ((video_color_t)rg << 8) | (video_color_t)rb;
            }
        }
        row += stride_bytes;
    }
}

bool html_view_buf_append(char **buf, size_t *len, size_t *cap, const char *data, size_t data_len)
{
    if (!buf || !len || !cap)
    {
        return false;
    }
    if (!data || data_len == 0)
    {
        return true;
    }

    size_t needed = *len + data_len + 1;
    if (needed > *cap)
    {
        size_t new_cap = *cap > 0 ? *cap : 1024;
        while (new_cap < needed)
        {
            new_cap *= 2;
        }
        char *next = (char *)realloc(*buf, new_cap);
        if (!next)
        {
            return false;
        }
        *buf = next;
        *cap = new_cap;
    }

    memcpy(*buf + *len, data, data_len);
    *len += data_len;
    (*buf)[*len] = '\0';
    return true;
}

void html_view_render_cache_clear(html_view_render_cache_t *cache)
{
    if (!cache)
    {
        return;
    }
    if (cache->owned_text)
    {
        for (size_t i = 0; i < cache->owned_text_count; ++i)
        {
            free(cache->owned_text[i]);
        }
        free(cache->owned_text);
    }
    free(cache->ops);
    free(cache->fixed_ops);
    free(cache->anchors);
    free(cache->tiles);
    cache->owned_text = NULL;
    cache->owned_text_count = 0;
    cache->owned_text_cap = 0;
    cache->ops = NULL;
    cache->op_count = 0;
    cache->op_cap = 0;
    cache->fixed_ops = NULL;
    cache->fixed_count = 0;
    cache->fixed_cap = 0;
    cache->anchors = NULL;
    cache->anchor_count = 0;
    cache->anchor_cap = 0;
    cache->tiles = NULL;
    cache->tile_count = 0;
    cache->tile_used = 0;
    cache->valid = false;
}

char *html_view_render_cache_strdup(html_view_render_cache_t *cache, const char *text)
{
    if (!cache || !text)
    {
        return NULL;
    }

    char *copy = html_view_strdup(text);
    if (!copy)
    {
        return NULL;
    }

    if (cache->owned_text_count == cache->owned_text_cap)
    {
        size_t new_cap = cache->owned_text_cap > 0 ? cache->owned_text_cap * 2 : 16;
        char **next = (char **)realloc(cache->owned_text, new_cap * sizeof(*next));
        if (!next)
        {
            free(copy);
            return NULL;
        }
        cache->owned_text = next;
        cache->owned_text_cap = new_cap;
    }
    cache->owned_text[cache->owned_text_count++] = copy;
    return copy;
}

bool html_view_render_cache_add_anchor(html_view_render_cache_t *cache, const char *id, int y)
{
    if (!cache || !id || id[0] == '\0')
    {
        return false;
    }

    for (size_t i = 0; i < cache->anchor_count; ++i)
    {
        html_view_anchor_t *anchor = &cache->anchors[i];
        if (anchor->id && strcmp(anchor->id, id) == 0)
        {
            if (y < 0)
            {
                y = 0;
            }
            anchor->y = y;
            return true;
        }
    }

    if (cache->anchor_count == cache->anchor_cap)
    {
        size_t new_cap = cache->anchor_cap ? (cache->anchor_cap * 2) : 32;
        html_view_anchor_t *new_anchors = (html_view_anchor_t *)realloc(cache->anchors, new_cap * sizeof(*new_anchors));
        if (!new_anchors)
        {
            return false;
        }
        cache->anchors = new_anchors;
        cache->anchor_cap = new_cap;
    }

    const char *owned = html_view_render_cache_strdup(cache, id);
    if (!owned)
    {
        return false;
    }

    if (y < 0)
    {
        y = 0;
    }
    cache->anchors[cache->anchor_count++] = (html_view_anchor_t){
        .id = owned,
        .y = y,
    };
    return true;
}

bool html_view_render_cache_push_op(html_view_render_cache_t *cache, const html_view_op_t *op, int tile_h)
{
    (void)tile_h;
    if (!cache || !op)
    {
        return false;
    }
    if (cache->op_count == cache->op_cap)
    {
        size_t new_cap = cache->op_cap > 0 ? cache->op_cap * 2 : 256;
        html_view_op_t *next = (html_view_op_t *)realloc(cache->ops, new_cap * sizeof(*next));
        if (!next)
        {
            return false;
        }
        cache->ops = next;
        cache->op_cap = new_cap;
    }
    cache->ops[cache->op_count++] = *op;
    return true;
}

static bool host_intersect_rect(const atk_rect_t *a, const atk_rect_t *b, atk_rect_t *out)
{
    if (!a || !b || !out)
    {
        return false;
    }
    int x0 = a->x > b->x ? a->x : b->x;
    int y0 = a->y > b->y ? a->y : b->y;
    int x1 = (a->x + a->width) < (b->x + b->width) ? (a->x + a->width) : (b->x + b->width);
    int y1 = (a->y + a->height) < (b->y + b->height) ? (a->y + a->height) : (b->y + b->height);
    int w = x1 - x0;
    int h = y1 - y0;
    if (w <= 0 || h <= 0)
    {
        return false;
    }
    out->x = x0;
    out->y = y0;
    out->width = w;
    out->height = h;
    return true;
}

static void host_render_cache_draw_text_span(html_view_ctx_t *ctx,
                                             int x,
                                             int baseline_y,
                                             const char *text,
                                             uint32_t len,
                                             video_color_t color,
                                             const atk_rect_t *clip)
{
    if (!ctx || !text || len == 0)
    {
        return;
    }

    char scratch[128];
    const char *tmp = NULL;
    char *heap = NULL;
    if (len < sizeof(scratch))
    {
        memcpy(scratch, text, len);
        scratch[len] = '\0';
        tmp = scratch;
    }
    else
    {
        heap = (char *)malloc((size_t)len + 1);
        if (!heap)
        {
            return;
        }
        memcpy(heap, text, len);
        heap[len] = '\0';
        tmp = heap;
    }

    html_view_draw_string_clipped(ctx, x, baseline_y, tmp, color, clip ? clip : &ctx->clip);
    free(heap);
}

void html_view_render_cache_draw_visible(html_view_ctx_t *ctx)
{
    if (!ctx || !ctx->priv)
    {
        return;
    }

    const html_view_render_cache_t *cache = &ctx->priv->render_cache;
    if (!cache->ops || cache->op_count == 0)
    {
        return;
    }

    typedef struct
    {
        size_t op_index;
        int32_t z_index;
    } host_draw_item_t;

    host_draw_item_t stack_items[256];
    host_draw_item_t *items = stack_items;
    size_t count = cache->op_count;
    bool has_z = false;

    if (count > (sizeof(stack_items) / sizeof(stack_items[0])))
    {
        items = (host_draw_item_t *)malloc(count * sizeof(*items));
        if (!items)
        {
            return;
        }
    }

    for (size_t i = 0; i < count; ++i)
    {
        items[i].op_index = i;
        items[i].z_index = cache->ops[i].z_index;
        if (cache->ops[i].z_index != 0)
        {
            has_z = true;
        }
    }

    if (count > 1 && has_z)
    {
        for (size_t i = 1; i < count; ++i)
        {
            host_draw_item_t key = items[i];
            size_t j = i;
            while (j > 0)
            {
                host_draw_item_t *prev = &items[j - 1];
                if (prev->z_index < key.z_index ||
                    (prev->z_index == key.z_index && prev->op_index <= key.op_index))
                {
                    break;
                }
                items[j] = *prev;
                --j;
            }
            items[j] = key;
        }
    }

    for (size_t i = 0; i < count; ++i)
    {
        size_t op_index = items[i].op_index;
        if (op_index >= cache->op_count)
        {
            continue;
        }
        const html_view_op_t *op = &cache->ops[op_index];
        bool fixed = op->fixed;

        int abs_x = fixed ? (int)op->x : (ctx->doc_origin_x + (int)op->x);
        int abs_y = fixed ? (int)op->y : (ctx->doc_origin_y + (int)op->y - ctx->scroll_y);

        atk_rect_t draw_clip = ctx->clip;
        if (op->has_clip)
        {
            atk_rect_t op_clip = {
                .x = fixed ? (int)op->clip_x : (ctx->doc_origin_x + (int)op->clip_x),
                .y = fixed ? (int)op->clip_y : (ctx->doc_origin_y + (int)op->clip_y - ctx->scroll_y),
                .width = (int)op->clip_w,
                .height = (int)op->clip_h,
            };
            if (!host_intersect_rect(&draw_clip, &op_clip, &draw_clip))
            {
                continue;
            }
        }

        switch (op->kind)
        {
            case HTML_VIEW_OP_RECT:
                html_view_draw_rect_clipped(ctx, abs_x, abs_y, (int)op->w, (int)op->h, op->color, &draw_clip);
                break;
            case HTML_VIEW_OP_TEXT:
            {
                int baseline_y = abs_y + (int)op->baseline_off;
                int saved_font_px = ctx->actual_font_px;
                if (op->font_px > 0)
                {
                    ctx->actual_font_px = op->font_px;
                }
                host_render_cache_draw_text_span(ctx,
                                                 abs_x,
                                                 baseline_y,
                                                 op->text,
                                                 op->text_len,
                                                 op->color,
                                                 &draw_clip);
                ctx->actual_font_px = saved_font_px;
                break;
            }
            case HTML_VIEW_OP_IMAGE:
                html_view_blit_rgba32_clipped(ctx,
                                              abs_x,
                                              abs_y,
                                              (int)op->w,
                                              (int)op->h,
                                              op->pixels,
                                              op->stride_bytes,
                                              &draw_clip);
                break;
            case HTML_VIEW_OP_CONTROL:
            default:
                break;
        }
    }

    if (items != stack_items)
    {
        free(items);
    }
}

html_view_control_t *html_view_control_find(atk_html_view_priv_t *priv, const html_node_t *node)
{
    (void)priv;
    (void)node;
    return NULL;
}

void html_view_collect_text(const html_node_t *node, char **buf, size_t *len, size_t *cap)
{
    if (!node)
    {
        return;
    }
    if (node->type == HTML_NODE_TEXT && node->text)
    {
        (void)html_view_buf_append(buf, len, cap, node->text, strlen(node->text));
    }
    for (const html_node_t *child = node->first_child; child; child = child->next_sibling)
    {
        html_view_collect_text(child, buf, len, cap);
    }
}

void html_view_trim_collapse_ws(char *text)
{
    if (!text)
    {
        return;
    }

    char *src = text;
    char *dst = text;
    bool in_ws = true;
    while (*src)
    {
        if (isspace((unsigned char)*src))
        {
            if (!in_ws)
            {
                *dst++ = ' ';
                in_ws = true;
            }
        }
        else
        {
            *dst++ = *src;
            in_ws = false;
        }
        src++;
    }
    if (dst > text && dst[-1] == ' ')
    {
        dst--;
    }
    *dst = '\0';
}

static const char *host_find_char(const char *start, size_t len, char ch)
{
    if (!start || len == 0)
    {
        return NULL;
    }
    for (size_t i = 0; i < len; ++i)
    {
        if (start[i] == ch)
        {
            return start + i;
        }
    }
    return NULL;
}

static bool host_data_url_parse_base64(const char *url,
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
    const char *semi = host_find_char(cursor, meta_len, ';');
    size_t token_len = semi ? (size_t)(semi - cursor) : meta_len;
    if (token_len > 0)
    {
        has_type = true;
        if (token_len == 9 && strncasecmp(cursor, "image/png", 9) == 0)
        {
            is_png = true;
        }
    }

    if (semi)
    {
        cursor = semi + 1;
        while (cursor < meta + meta_len)
        {
            const char *next = host_find_char(cursor, (size_t)((meta + meta_len) - cursor), ';');
            size_t len = next ? (size_t)(next - cursor) : (size_t)((meta + meta_len) - cursor);
            const char *tok = cursor;
            while (len > 0 && isspace((unsigned char)*tok))
            {
                tok++;
                len--;
            }
            while (len > 0 && isspace((unsigned char)tok[len - 1]))
            {
                len--;
            }
            if (len == 6 && strncasecmp(tok, "base64", 6) == 0)
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

static int host_hex_value(char ch)
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

static char *host_decode_percent(const char *input, size_t len, size_t *out_len)
{
    if (!input || len == 0 || !out_len)
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
        if (ch == '%' && i + 2 < len)
        {
            int h = host_hex_value(input[i + 1]);
            int l = host_hex_value(input[i + 2]);
            if (h >= 0 && l >= 0)
            {
                out[w++] = (char)((h << 4) | l);
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

static int host_base64_value(char ch)
{
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '+') return 62;
    if (ch == '/') return 63;
    return -1;
}

static uint8_t *host_decode_base64(const char *input, size_t len, size_t *out_len)
{
    if (!input || len == 0 || !out_len)
    {
        return NULL;
    }

    size_t max_out = (len / 4 + 1) * 3;
    uint8_t *out = (uint8_t *)malloc(max_out);
    if (!out)
    {
        return NULL;
    }

    size_t out_pos = 0;
    int vals[4];
    size_t i = 0;
    while (i < len)
    {
        size_t got = 0;
        while (i < len && got < 4)
        {
            unsigned char ch = (unsigned char)input[i++];
            if (ch == '=')
            {
                vals[got++] = -2;
            }
            else
            {
                int v = host_base64_value((char)ch);
                if (v < 0)
                {
                    continue;
                }
                vals[got++] = v;
            }
        }
        if (got < 2)
        {
            break;
        }
        if (vals[0] < 0 || vals[1] < 0)
        {
            break;
        }
        out[out_pos++] = (uint8_t)((vals[0] << 2) | (vals[1] >> 4));
        if (got > 2 && vals[2] >= 0)
        {
            out[out_pos++] = (uint8_t)((vals[1] << 4) | (vals[2] >> 2));
            if (got > 3 && vals[3] >= 0)
            {
                out[out_pos++] = (uint8_t)((vals[2] << 6) | vals[3]);
            }
        }
    }

    *out_len = out_pos;
    return out;
}

static bool host_is_png_bytes(const uint8_t *data, size_t len)
{
    static const uint8_t signature[8] = {0x89u, 0x50u, 0x4Eu, 0x47u, 0x0Du, 0x0Au, 0x1Au, 0x0Au};
    if (!data || len < sizeof(signature))
    {
        return false;
    }
    return memcmp(data, signature, sizeof(signature)) == 0;
}

html_view_image_t *html_view_image_find(atk_html_view_priv_t *priv, const char *src)
{
    if (!priv || !src)
    {
        return NULL;
    }
    for (html_view_image_t *img = priv->images; img; img = img->next)
    {
        if (img->src && strcmp(img->src, src) == 0)
        {
            return img;
        }
    }
    return NULL;
}

bool html_view_try_load_data_image_locked(atk_html_view_priv_t *priv, const char *src)
{
    if (!priv || !src)
    {
        return false;
    }
    if (strncasecmp(src, "data:", 5) != 0)
    {
        return false;
    }
    if (html_view_image_find(priv, src))
    {
        return true;
    }

    const char *payload = NULL;
    size_t payload_len = 0;
    bool has_type = false;
    bool is_png = false;
    if (!host_data_url_parse_base64(src, &payload, &payload_len, &has_type, &is_png))
    {
        return false;
    }
    if (has_type && !is_png)
    {
        return false;
    }

    size_t decoded_len = 0;
    char *decoded_payload = host_decode_percent(payload, payload_len, &decoded_len);
    if (!decoded_payload)
    {
        return false;
    }

    size_t png_len = 0;
    uint8_t *png_bytes = host_decode_base64(decoded_payload, decoded_len, &png_len);
    free(decoded_payload);
    if (!png_bytes)
    {
        return false;
    }
    if (!host_is_png_bytes(png_bytes, png_len))
    {
        free(png_bytes);
        return false;
    }

    video_color_t *pixels = NULL;
    int w = 0;
    int h = 0;
    int stride_bytes = 0;
    int rc = png_decode_rgba32(png_bytes, png_len, &pixels, &w, &h, &stride_bytes);
    free(png_bytes);
    if (rc != 0 || !pixels || w <= 0 || h <= 0 || stride_bytes <= 0)
    {
        free(pixels);
        return false;
    }

    html_view_image_t *img = (html_view_image_t *)calloc(1, sizeof(*img));
    if (!img)
    {
        free(pixels);
        return false;
    }
    img->src = html_view_strdup(src);
    if (!img->src)
    {
        free(pixels);
        free(img);
        return false;
    }
    img->pixels = pixels;
    img->width = w;
    img->height = h;
    img->stride_bytes = stride_bytes;
    img->next = priv->images;
    priv->images = img;
    return true;
}

void html_view_images_clear(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    html_view_image_t *img = priv->images;
    while (img)
    {
        html_view_image_t *next = img->next;
        free(img->src);
        free(img->pixels);
        free(img);
        img = next;
    }
    priv->images = NULL;
}

static bool css_length_is(const css_length_t *len, int32_t milli, css_unit_t unit)
{
    if (!len)
    {
        return false;
    }
    return len->valid && !len->is_auto && len->value_milli == milli && len->unit == unit;
}

static const html_node_t *find_first_tag(const html_node_t *root, const char *tag)
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

static const html_node_t *find_node_by_id(const html_node_t *root, const char *id)
{
    if (!root || !id || id[0] == '\0')
    {
        return NULL;
    }

    const html_node_t *stack[64];
    size_t sp = 0;
    stack[sp++] = root;

    while (sp > 0)
    {
        const html_node_t *node = stack[--sp];
        if (node->type == HTML_NODE_ELEMENT)
        {
            const char *node_id = html_attr_get(node, "id");
            if (node_id && strcmp(node_id, id) == 0)
            {
                return node;
            }
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

static char *read_file(const char *path, size_t *out_len)
{
    if (out_len)
    {
        *out_len = 0;
    }
    if (!path || path[0] == '\0')
    {
        return NULL;
    }

    FILE *fp = fopen(path, "rb");
    if (!fp)
    {
        return NULL;
    }

    if (fseek(fp, 0, SEEK_END) != 0)
    {
        fclose(fp);
        return NULL;
    }
    long len = ftell(fp);
    if (len < 0)
    {
        fclose(fp);
        return NULL;
    }
    rewind(fp);

    char *buf = (char *)malloc((size_t)len + 1);
    if (!buf)
    {
        fclose(fp);
        return NULL;
    }
    size_t read_len = fread(buf, 1, (size_t)len, fp);
    fclose(fp);

    buf[read_len] = '\0';
    if (out_len)
    {
        *out_len = read_len;
    }
    return buf;
}

static bool attr_has_token(const char *value, const char *token)
{
    if (!value || !token || token[0] == '\0')
    {
        return false;
    }
    size_t token_len = strlen(token);
    const char *p = value;
    while (*p)
    {
        while (*p && isspace((unsigned char)*p))
        {
            ++p;
        }
        if (!*p)
        {
            break;
        }
        const char *start = p;
        while (*p && !isspace((unsigned char)*p))
        {
            ++p;
        }
        size_t len = (size_t)(p - start);
        if (len == token_len && strncasecmp(start, token, len) == 0)
        {
            return true;
        }
    }
    return false;
}

static char *decode_data_css(const char *href)
{
    if (!href)
    {
        return NULL;
    }
    const char *prefix = "data:text/css";
    size_t prefix_len = strlen(prefix);
    if (strncasecmp(href, prefix, prefix_len) != 0)
    {
        return NULL;
    }
    const char *comma = strchr(href, ',');
    if (!comma || comma[1] == '\0')
    {
        return NULL;
    }

    const char *data = comma + 1;
    size_t cap = strlen(data) + 1;
    char *out = (char *)malloc(cap);
    if (!out)
    {
        return NULL;
    }

    size_t len = 0;
    for (const char *p = data; *p; ++p)
    {
        if (*p == '%' && p[1] && p[2])
        {
            char hi = p[1];
            char lo = p[2];
            int vhi = isdigit((unsigned char)hi) ? hi - '0' :
                      isxdigit((unsigned char)hi) ? 10 + (tolower((unsigned char)hi) - 'a') : -1;
            int vlo = isdigit((unsigned char)lo) ? lo - '0' :
                      isxdigit((unsigned char)lo) ? 10 + (tolower((unsigned char)lo) - 'a') : -1;
            if (vhi >= 0 && vlo >= 0)
            {
                out[len++] = (char)((vhi << 4) | vlo);
                p += 2;
                continue;
            }
        }
        out[len++] = (*p == '+') ? ' ' : *p;
    }
    out[len] = '\0';
    return out;
}

static void collect_style_text(const html_node_t *node, char **css, size_t *len, size_t *cap)
{
    if (!node)
    {
        return;
    }

    if (node->type == HTML_NODE_ELEMENT && node->name)
    {
        if (strcmp(node->name, "style") == 0)
        {
            char *text = NULL;
            size_t text_len = 0;
            size_t text_cap = 0;
            html_view_collect_text(node, &text, &text_len, &text_cap);
            if (text && text_len > 0)
            {
                (void)html_view_buf_append(css, len, cap, text, text_len);
                (void)html_view_buf_append(css, len, cap, "\n", 1);
            }
            free(text);
        }
        else if (strcmp(node->name, "link") == 0)
        {
            const char *rel = html_attr_get(node, "rel");
            if (attr_has_token(rel, "stylesheet"))
            {
                const char *href = html_attr_get(node, "href");
                char *decoded = decode_data_css(href);
                if (decoded)
                {
                    (void)html_view_buf_append(css, len, cap, decoded, strlen(decoded));
                    (void)html_view_buf_append(css, len, cap, "\n", 1);
                    free(decoded);
                }
            }
        }
    }

    for (const html_node_t *child = node->first_child; child; child = child->next_sibling)
    {
        collect_style_text(child, css, len, cap);
    }
}

void html_view_rebuild_stylesheet(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    if (priv->sheet)
    {
        css_stylesheet_destroy(priv->sheet);
        priv->sheet = NULL;
    }

    if (!priv->doc || !priv->doc->root)
    {
        return;
    }

    char *css = NULL;
    size_t css_len = 0;
    size_t css_cap = 0;
    collect_style_text(priv->doc->root, &css, &css_len, &css_cap);

    priv->sheet = css_parse(css ? css : "");
    free(css);
}

static void hash_bytes(uint64_t *hash, const void *data, size_t len)
{
    if (!hash || !data)
    {
        return;
    }
    const uint8_t *bytes = (const uint8_t *)data;
    for (size_t i = 0; i < len; ++i)
    {
        *hash ^= (uint64_t)bytes[i];
        *hash *= 1099511628211ULL;
    }
}

static void hash_u32(uint64_t *hash, uint32_t value)
{
    uint8_t bytes[4];
    bytes[0] = (uint8_t)(value & 0xFF);
    bytes[1] = (uint8_t)((value >> 8) & 0xFF);
    bytes[2] = (uint8_t)((value >> 16) & 0xFF);
    bytes[3] = (uint8_t)((value >> 24) & 0xFF);
    hash_bytes(hash, bytes, sizeof(bytes));
}

static void hash_u64(uint64_t *hash, uint64_t value)
{
    uint8_t bytes[8];
    bytes[0] = (uint8_t)(value & 0xFF);
    bytes[1] = (uint8_t)((value >> 8) & 0xFF);
    bytes[2] = (uint8_t)((value >> 16) & 0xFF);
    bytes[3] = (uint8_t)((value >> 24) & 0xFF);
    bytes[4] = (uint8_t)((value >> 32) & 0xFF);
    bytes[5] = (uint8_t)((value >> 40) & 0xFF);
    bytes[6] = (uint8_t)((value >> 48) & 0xFF);
    bytes[7] = (uint8_t)((value >> 56) & 0xFF);
    hash_bytes(hash, bytes, sizeof(bytes));
}

static uint64_t hash_render_ops(const html_view_render_cache_t *cache)
{
    uint64_t hash = 14695981039346656037ULL;
    if (!cache)
    {
        return hash;
    }

    hash_u64(&hash, (uint64_t)cache->op_count);
    for (size_t i = 0; i < cache->op_count; ++i)
    {
        const html_view_op_t *op = &cache->ops[i];
        hash_u32(&hash, (uint32_t)op->kind);
        hash_u32(&hash, (uint32_t)op->x);
        hash_u32(&hash, (uint32_t)op->y);
        hash_u32(&hash, (uint32_t)op->w);
        hash_u32(&hash, (uint32_t)op->h);
        hash_u32(&hash, (uint32_t)op->color);
        hash_u32(&hash, (uint32_t)op->text_len);
        hash_u32(&hash, (uint32_t)op->baseline_off);
        hash_u32(&hash, (uint32_t)op->font_px);
        hash_u32(&hash, (uint32_t)op->z_index);
        hash_u32(&hash, op->fixed ? 1u : 0u);
        hash_u32(&hash, op->has_clip ? 1u : 0u);
        if (op->has_clip)
        {
            hash_u32(&hash, (uint32_t)op->clip_x);
            hash_u32(&hash, (uint32_t)op->clip_y);
            hash_u32(&hash, (uint32_t)op->clip_w);
            hash_u32(&hash, (uint32_t)op->clip_h);
        }
        if (op->kind == HTML_VIEW_OP_TEXT && op->text && op->text_len > 0)
        {
            hash_bytes(&hash, op->text, op->text_len);
        }
    }

    return hash;
}

static bool find_anchor_y(const html_view_render_cache_t *cache, const char *id, int *out_y)
{
    if (out_y)
    {
        *out_y = 0;
    }
    if (!cache || !id || !out_y)
    {
        return false;
    }
    for (size_t i = 0; i < cache->anchor_count; ++i)
    {
        const html_view_anchor_t *anchor = &cache->anchors[i];
        if (anchor->id && strcmp(anchor->id, id) == 0)
        {
            *out_y = anchor->y;
            return true;
        }
    }
    return false;
}

static bool ensure_test_out_dir(void)
{
    if (mkdir("test-out", 0755) == 0)
    {
        return true;
    }
    return errno == EEXIST;
}

static uint32_t host_crc32_table[256];
static bool host_crc32_ready = false;

static void host_crc32_init_table(void)
{
    for (uint32_t i = 0; i < 256; ++i)
    {
        uint32_t c = i;
        for (int j = 0; j < 8; ++j)
        {
            if (c & 1u)
            {
                c = 0xEDB88320u ^ (c >> 1);
            }
            else
            {
                c >>= 1;
            }
        }
        host_crc32_table[i] = c;
    }
    host_crc32_ready = true;
}

static uint32_t host_crc32_update(uint32_t crc, const uint8_t *data, size_t len)
{
    if (!host_crc32_ready)
    {
        host_crc32_init_table();
    }
    for (size_t i = 0; i < len; ++i)
    {
        crc = host_crc32_table[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    }
    return crc;
}

static uint32_t host_crc32_chunk(const char type[4], const uint8_t *data, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    crc = host_crc32_update(crc, (const uint8_t *)type, 4);
    if (data && len > 0)
    {
        crc = host_crc32_update(crc, data, len);
    }
    return crc ^ 0xFFFFFFFFu;
}

static uint32_t host_adler32(const uint8_t *data, size_t len)
{
    const uint32_t mod = 65521u;
    uint32_t a = 1;
    uint32_t b = 0;
    for (size_t i = 0; i < len; ++i)
    {
        a += data[i];
        if (a >= mod)
        {
            a -= mod;
        }
        b += a;
        if (b >= mod)
        {
            b %= mod;
        }
    }
    return (b << 16) | a;
}

static bool host_write_be32(FILE *fp, uint32_t v)
{
    uint8_t bytes[4];
    bytes[0] = (uint8_t)((v >> 24) & 0xFF);
    bytes[1] = (uint8_t)((v >> 16) & 0xFF);
    bytes[2] = (uint8_t)((v >> 8) & 0xFF);
    bytes[3] = (uint8_t)(v & 0xFF);
    return fwrite(bytes, 1, sizeof(bytes), fp) == sizeof(bytes);
}

static bool host_write_png_chunk(FILE *fp, const char type[4], const uint8_t *data, size_t len)
{
    if (!fp || !type)
    {
        return false;
    }
    if (len > 0xFFFFFFFFu)
    {
        return false;
    }
    if (!host_write_be32(fp, (uint32_t)len))
    {
        return false;
    }
    if (fwrite(type, 1, 4, fp) != 4)
    {
        return false;
    }
    if (len > 0 && data)
    {
        if (fwrite(data, 1, len, fp) != len)
        {
            return false;
        }
    }
    uint32_t crc = host_crc32_chunk(type, data, len);
    return host_write_be32(fp, crc);
}

static bool host_write_png_rgba32(const char *path,
                                  const video_color_t *pixels,
                                  int width,
                                  int height,
                                  int stride_bytes)
{
    if (!path || !pixels || width <= 0 || height <= 0)
    {
        return false;
    }
    if (stride_bytes <= 0)
    {
        stride_bytes = width * (int)sizeof(video_color_t);
    }

    size_t row_bytes = (size_t)width * 4 + 1;
    if (row_bytes <= (size_t)width * 4)
    {
        return false;
    }
    if (row_bytes > (SIZE_MAX / (size_t)height))
    {
        return false;
    }
    size_t raw_size = row_bytes * (size_t)height;

    uint8_t *raw = (uint8_t *)malloc(raw_size);
    if (!raw)
    {
        return false;
    }

    for (int y = 0; y < height; ++y)
    {
        uint8_t *dst = raw + (size_t)y * row_bytes;
        dst[0] = 0;
        const video_color_t *src = (const video_color_t *)((const uint8_t *)pixels + (size_t)y * (size_t)stride_bytes);
        for (int x = 0; x < width; ++x)
        {
            video_color_t px = src[x];
            size_t off = 1 + (size_t)x * 4;
            dst[off + 0] = (uint8_t)(px >> 16);
            dst[off + 1] = (uint8_t)(px >> 8);
            dst[off + 2] = (uint8_t)(px);
            dst[off + 3] = (uint8_t)(px >> 24);
        }
    }

    size_t blocks = (raw_size + 65534) / 65535;
    size_t zlib_size = 2 + raw_size + blocks * 5 + 4;
    if (zlib_size < raw_size || zlib_size > SIZE_MAX)
    {
        free(raw);
        return false;
    }
    uint8_t *zlib = (uint8_t *)malloc(zlib_size);
    if (!zlib)
    {
        free(raw);
        return false;
    }

    size_t zpos = 0;
    zlib[zpos++] = 0x78;
    zlib[zpos++] = 0x01;

    size_t remaining = raw_size;
    size_t offset = 0;
    while (remaining > 0)
    {
        size_t chunk = remaining > 65535 ? 65535 : remaining;
        bool final = (remaining <= 65535);
        zlib[zpos++] = final ? 0x01 : 0x00;
        zlib[zpos++] = (uint8_t)(chunk & 0xFF);
        zlib[zpos++] = (uint8_t)((chunk >> 8) & 0xFF);
        uint16_t nlen = (uint16_t)(~chunk);
        zlib[zpos++] = (uint8_t)(nlen & 0xFF);
        zlib[zpos++] = (uint8_t)((nlen >> 8) & 0xFF);
        memcpy(&zlib[zpos], raw + offset, chunk);
        zpos += chunk;
        offset += chunk;
        remaining -= chunk;
    }

    uint32_t adler = host_adler32(raw, raw_size);
    zlib[zpos++] = (uint8_t)((adler >> 24) & 0xFF);
    zlib[zpos++] = (uint8_t)((adler >> 16) & 0xFF);
    zlib[zpos++] = (uint8_t)((adler >> 8) & 0xFF);
    zlib[zpos++] = (uint8_t)(adler & 0xFF);

    bool ok = false;
    FILE *fp = fopen(path, "wb");
    if (fp)
    {
        static const uint8_t signature[8] = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
        uint8_t ihdr[13];
        ihdr[0] = (uint8_t)((width >> 24) & 0xFF);
        ihdr[1] = (uint8_t)((width >> 16) & 0xFF);
        ihdr[2] = (uint8_t)((width >> 8) & 0xFF);
        ihdr[3] = (uint8_t)(width & 0xFF);
        ihdr[4] = (uint8_t)((height >> 24) & 0xFF);
        ihdr[5] = (uint8_t)((height >> 16) & 0xFF);
        ihdr[6] = (uint8_t)((height >> 8) & 0xFF);
        ihdr[7] = (uint8_t)(height & 0xFF);
        ihdr[8] = 8;
        ihdr[9] = 6;
        ihdr[10] = 0;
        ihdr[11] = 0;
        ihdr[12] = 0;

        if (fwrite(signature, 1, sizeof(signature), fp) == sizeof(signature) &&
            host_write_png_chunk(fp, "IHDR", ihdr, sizeof(ihdr)) &&
            host_write_png_chunk(fp, "IDAT", zlib, zpos) &&
            host_write_png_chunk(fp, "IEND", NULL, 0))
        {
            ok = true;
        }
        fclose(fp);
    }

    free(zlib);
    free(raw);
    return ok;
}

static bool test_table_cell_alignment(void)
{
    html_parse_error_t err = {0};
    html_document_t *doc = html_parse("<center><table><tr><td>Hi</td></tr></table></center>", &err);
    if (!doc)
    {
        return false;
    }

    const html_node_t *td = find_first_tag(doc->root, "td");
    if (!td)
    {
        html_document_destroy(doc);
        return false;
    }

    css_style_t parent = {0};
    parent.has_text_align = true;
    parent.text_align = CSS_TEXT_ALIGN_CENTER;

    css_style_t out = {0};
    html_view_style_for_node(&out, NULL, &parent, td);

    html_document_destroy(doc);
    return out.has_text_align && out.text_align == CSS_TEXT_ALIGN_LEFT;
}

static bool test_table_header_alignment(void)
{
    html_parse_error_t err = {0};
    html_document_t *doc = html_parse("<table><tr><th>Head</th></tr></table>", &err);
    if (!doc)
    {
        return false;
    }

    const html_node_t *th = find_first_tag(doc->root, "th");
    if (!th)
    {
        html_document_destroy(doc);
        return false;
    }

    css_style_t parent = {0};
    parent.has_text_align = true;
    parent.text_align = CSS_TEXT_ALIGN_LEFT;

    css_style_t out = {0};
    html_view_style_for_node(&out, NULL, &parent, th);

    html_document_destroy(doc);
    return out.has_text_align && out.text_align == CSS_TEXT_ALIGN_CENTER;
}

static bool test_line_height_length_px(void)
{
    html_view_ctx_t ctx = {0};
    ctx.actual_font_px = 12;
    ctx.base_font_px = 12;
    ctx.viewport_w = 800;
    ctx.viewport_h = 600;

    css_style_t style = {0};
    style.has_line_height = true;
    style.line_height_is_length = true;
    style.line_height.valid = true;
    style.line_height.is_auto = false;
    style.line_height.value_milli = 18000;
    style.line_height.unit = CSS_UNIT_PX;

    int lh = html_view_line_height_for_style(&ctx, &style);
    return lh == 18;
}

static bool test_border_style_none_zeroes_width(void)
{
    html_view_ctx_t ctx = {0};
    ctx.viewport_w = 800;
    ctx.viewport_h = 600;
    ctx.body_w = 800;
    ctx.base_font_px = 16;

    css_style_t style = {0};
    style.has_border = true;
    style.has_border_style = true;
    style.border_style_none[CSS_BORDER_SIDE_TOP] = true;
    style.border_style_none[CSS_BORDER_SIDE_BOTTOM] = true;
    style.border_style_none[CSS_BORDER_SIDE_LEFT] = false;
    style.border_style_none[CSS_BORDER_SIDE_RIGHT] = false;
    style.border_width.top = (css_length_t){ .valid = true, .is_auto = false, .value_milli = 2000, .unit = CSS_UNIT_PX };
    style.border_width.right = (css_length_t){ .valid = true, .is_auto = false, .value_milli = 2000, .unit = CSS_UNIT_PX };
    style.border_width.bottom = (css_length_t){ .valid = true, .is_auto = false, .value_milli = 2000, .unit = CSS_UNIT_PX };
    style.border_width.left = (css_length_t){ .valid = true, .is_auto = false, .value_milli = 2000, .unit = CSS_UNIT_PX };

    int top = html_view_length_to_px(&style.border_width.top,
                                     ctx.viewport_w,
                                     ctx.viewport_h,
                                     ctx.body_w,
                                     ctx.viewport_h,
                                     ctx.base_font_px,
                                     false);
    int right = html_view_length_to_px(&style.border_width.right,
                                       ctx.viewport_w,
                                       ctx.viewport_h,
                                       ctx.body_w,
                                       ctx.viewport_h,
                                       ctx.base_font_px,
                                       true);
    int bottom = html_view_length_to_px(&style.border_width.bottom,
                                        ctx.viewport_w,
                                        ctx.viewport_h,
                                        ctx.body_w,
                                        ctx.viewport_h,
                                        ctx.base_font_px,
                                        false);
    int left = html_view_length_to_px(&style.border_width.left,
                                      ctx.viewport_w,
                                      ctx.viewport_h,
                                      ctx.body_w,
                                      ctx.viewport_h,
                                      ctx.base_font_px,
                                      true);

    html_view_apply_border_style_none(&style, &top, &right, &bottom, &left);

    return top == 0 && bottom == 0 && right == 2 && left == 2;
}

static bool test_height_percent_requires_basis(void)
{
    html_view_ctx_t ctx = {0};
    ctx.viewport_w = 800;
    ctx.viewport_h = 600;
    ctx.body_w = 800;
    ctx.base_font_px = 16;

    css_length_t len = {
        .valid = true,
        .is_auto = false,
        .value_milli = 50000,
        .unit = CSS_UNIT_PERCENT,
    };
    int px = 123;
    bool ok = !html_view_length_to_px_height(&ctx, &len, &px);
    return ok && px == 0;
}

static bool test_height_percent_with_basis(void)
{
    html_view_ctx_t ctx = {0};
    ctx.viewport_w = 800;
    ctx.viewport_h = 600;
    ctx.body_w = 800;
    ctx.base_font_px = 16;
    ctx.height_basis_valid = true;
    ctx.height_basis_explicit = true;
    ctx.height_basis = 200;

    css_length_t len = {
        .valid = true,
        .is_auto = false,
        .value_milli = 50000,
        .unit = CSS_UNIT_PERCENT,
    };
    int px = 0;
    bool ok = html_view_length_to_px_height(&ctx, &len, &px);
    return ok && px == 100;
}

static bool test_height_px_without_basis(void)
{
    html_view_ctx_t ctx = {0};
    ctx.viewport_w = 800;
    ctx.viewport_h = 600;
    ctx.body_w = 800;
    ctx.base_font_px = 16;

    css_length_t len = {
        .valid = true,
        .is_auto = false,
        .value_milli = 24000,
        .unit = CSS_UNIT_PX,
    };
    int px = 0;
    bool ok = html_view_length_to_px_height(&ctx, &len, &px);
    return ok && px == 24;
}

static bool test_margin_collapse_siblings(void)
{
    html_view_ctx_t ctx = {0};
    ctx.viewport_w = 200;
    ctx.viewport_h = 200;
    ctx.body_w = 200;
    ctx.max_x = 200;
    ctx.base_font_px = 16;
    ctx.base_line_height = 16;
    ctx.line_height = 16;
    ctx.paint_layer = HTML_VIEW_PAINT_LAYER_BLOCK;
    ctx.body_x = 0;
    ctx.x = 0;
    ctx.y = 0;

    html_node_t node1 = {0};
    node1.type = HTML_NODE_ELEMENT;
    node1.name = (char *)"div";

    css_style_t style1 = {0};
    style1.has_margin = true;
    style1.margin.bottom.valid = true;
    style1.margin.bottom.value_milli = 20000;
    style1.margin.bottom.unit = CSS_UNIT_PX;
    style1.margin.bottom.is_auto = false;
    style1.has_height = true;
    style1.height.valid = true;
    style1.height.is_auto = false;
    style1.height.value_milli = 10000;
    style1.height.unit = CSS_UNIT_PX;

    html_node_t node2 = {0};
    node2.type = HTML_NODE_ELEMENT;
    node2.name = (char *)"div";

    css_style_t style2 = {0};
    style2.has_margin = true;
    style2.margin.top.valid = true;
    style2.margin.top.value_milli = 10000;
    style2.margin.top.unit = CSS_UNIT_PX;
    style2.margin.top.is_auto = false;
    style2.has_height = true;
    style2.height.valid = true;
    style2.height.is_auto = false;
    style2.height.value_milli = 10000;
    style2.height.unit = CSS_UNIT_PX;

    bool ok1 = html_view_render_block_element(&ctx, &node1, &style1);
    int after_first = ctx.y;
    bool ok2 = html_view_render_block_element(&ctx, &node2, &style2);

    return ok1 && ok2 && after_first == 10 && ctx.y == 40;
}

static bool test_margin_collapse_empty_block(void)
{
    html_view_ctx_t ctx = {0};
    ctx.viewport_w = 200;
    ctx.viewport_h = 200;
    ctx.body_w = 200;
    ctx.max_x = 200;
    ctx.base_font_px = 16;
    ctx.base_line_height = 16;
    ctx.line_height = 16;
    ctx.paint_layer = HTML_VIEW_PAINT_LAYER_BLOCK;
    ctx.body_x = 0;
    ctx.x = 0;
    ctx.y = 0;

    html_node_t node = {0};
    node.type = HTML_NODE_ELEMENT;
    node.name = (char *)"div";

    css_style_t style = {0};
    style.has_margin = true;
    style.margin.top.valid = true;
    style.margin.top.value_milli = 10000;
    style.margin.top.unit = CSS_UNIT_PX;
    style.margin.top.is_auto = false;
    style.margin.bottom.valid = true;
    style.margin.bottom.value_milli = 20000;
    style.margin.bottom.unit = CSS_UNIT_PX;
    style.margin.bottom.is_auto = false;

    bool ok = html_view_render_block_element(&ctx, &node, &style);
    return ok && ctx.y == 0 && ctx.pending_margin.valid && html_view_margin_state_value(&ctx.pending_margin) == 20;
}

static bool test_attribute_selectors_with_escapes(void)
{
    html_parse_error_t err = {0};
    html_document_t *doc = html_parse("<div class=\"first one\"><span class=\"second two\"></span></div>", &err);
    if (!doc)
    {
        return false;
    }

    const html_node_t *div = find_first_tag(doc->root, "div");
    const html_node_t *span = find_first_tag(doc->root, "span");
    if (!div || !span)
    {
        html_document_destroy(doc);
        return false;
    }

    const char *css =
        "[class~=one].first.one { position: absolute; }\n"
        "[class=second\\ two][class=\"second two\"] { float: right; }\n";
    css_stylesheet_t *sheet = css_parse(css);
    if (!sheet)
    {
        html_document_destroy(doc);
        return false;
    }

    css_style_t parent = {0};
    css_style_t out_div = {0};
    html_view_style_for_node(&out_div, sheet, &parent, div);
    bool ok_div = out_div.has_position && out_div.position == CSS_POSITION_ABSOLUTE;

    css_style_t out_span = {0};
    html_view_style_for_node(&out_span, sheet, &parent, span);
    bool ok_span = out_span.has_float && out_span.float_mode == CSS_FLOAT_RIGHT;

    css_stylesheet_destroy(sheet);
    html_document_destroy(doc);
    return ok_div && ok_span;
}

static bool test_adjacent_sibling_selector(void)
{
    html_parse_error_t err = {0};
    html_document_t *doc = html_parse("<div class=\"picture\"><p id=\"first\"></p><table></table><p id=\"second\"></p></div>", &err);
    if (!doc)
    {
        return false;
    }

    const html_node_t *first = find_node_by_id(doc->root, "first");
    const html_node_t *second = find_node_by_id(doc->root, "second");
    if (!first || !second)
    {
        html_document_destroy(doc);
        return false;
    }

    const char *css = ".picture p + table + p { background: yellow; }";
    css_stylesheet_t *sheet = css_parse(css);
    if (!sheet)
    {
        html_document_destroy(doc);
        return false;
    }

    css_style_t parent = {0};
    css_style_t out_first = {0};
    html_view_style_for_node(&out_first, sheet, &parent, first);
    css_style_t out_second = {0};
    html_view_style_for_node(&out_second, sheet, &parent, second);

    css_stylesheet_destroy(sheet);
    html_document_destroy(doc);

    return !out_first.has_background && out_second.has_background;
}

static bool test_child_and_descendant_selectors(void)
{
    html_parse_error_t err = {0};
    html_document_t *doc = html_parse("<div class=\"nose\"><div id=\"child\"><div id=\"grand\"></div></div></div>", &err);
    if (!doc)
    {
        return false;
    }

    const html_node_t *nose = find_first_tag(doc->root, "div");
    const html_node_t *child = find_node_by_id(doc->root, "child");
    const html_node_t *grand = find_node_by_id(doc->root, "grand");
    if (!nose || !child || !grand)
    {
        html_document_destroy(doc);
        return false;
    }

    const char *css =
        ".nose > div { background: yellow; }\n"
        ".nose div div { background: red; }\n";
    css_stylesheet_t *sheet = css_parse(css);
    if (!sheet)
    {
        html_document_destroy(doc);
        return false;
    }

    css_style_t parent = {0};
    css_style_t out_nose = {0};
    css_style_t out_child = {0};
    css_style_t out_grand = {0};
    html_view_style_for_node(&out_nose, sheet, &parent, nose);
    html_view_style_for_node(&out_child, sheet, &parent, child);
    html_view_style_for_node(&out_grand, sheet, &parent, grand);

    css_stylesheet_destroy(sheet);
    html_document_destroy(doc);

    bool nose_ok = !out_nose.has_background;
    bool child_ok = out_child.has_background && out_child.background == video_make_color(0xFF, 0xFF, 0x00);
    bool grand_ok = out_grand.has_background && out_grand.background == video_make_color(0xFF, 0x00, 0x00);
    return nose_ok && child_ok && grand_ok;
}

static bool test_link_pseudo_class(void)
{
    html_parse_error_t err = {0};
    html_document_t *doc = html_parse("<a href=\"x\" id=\"link\">link</a>", &err);
    if (!doc)
    {
        return false;
    }

    const html_node_t *link = find_node_by_id(doc->root, "link");
    if (!link)
    {
        html_document_destroy(doc);
        return false;
    }

    const char *css =
        "a:link { color: blue; }\n"
        "a:visited { color: purple; }\n";
    css_stylesheet_t *sheet = css_parse(css);
    if (!sheet)
    {
        html_document_destroy(doc);
        return false;
    }

    css_style_t parent = {0};
    css_style_t out = {0};
    html_view_style_for_node(&out, sheet, &parent, link);

    css_stylesheet_destroy(sheet);
    html_document_destroy(doc);

    return out.has_color && out.color == video_make_color(0x00, 0x00, 0xFF);
}

static bool test_pseudo_element_style(void)
{
    html_parse_error_t err = {0};
    html_document_t *doc = html_parse("<div class=\"nose\"><div id=\"child\"></div></div>", &err);
    if (!doc)
    {
        return false;
    }

    const html_node_t *child = find_node_by_id(doc->root, "child");
    if (!child)
    {
        html_document_destroy(doc);
        return false;
    }

    const char *css = ".nose div:before { background: yellow; content: ''; border-top: 1px solid red; }";
    css_stylesheet_t *sheet = css_parse(css);
    if (!sheet)
    {
        html_document_destroy(doc);
        return false;
    }

    css_style_t parent = {0};
    css_style_t base = {0};
    html_view_style_for_node(&base, sheet, &parent, child);

    css_style_t out = {0};
    bool has_pseudo = html_view_style_for_pseudo(&out, sheet, &base, child, HTML_VIEW_PSEUDO_BEFORE);

    css_stylesheet_destroy(sheet);
    html_document_destroy(doc);
    bool ok = has_pseudo &&
              out.has_background &&
              out.background == video_make_color(0xFF, 0xFF, 0x00) &&
              out.has_content &&
              out.border_color_side_set[CSS_BORDER_SIDE_TOP] &&
              out.border_color_side[CSS_BORDER_SIDE_TOP] == video_make_color(0xFF, 0x00, 0x00);
    return ok;
}

static bool test_inline_background_style(void)
{
    html_parse_error_t err = {0};
    html_document_t *doc = html_parse("<div id=\"box\" style=\"background: red url(foo.png) no-repeat fixed 1px 2px;\"></div>", &err);
    if (!doc)
    {
        return false;
    }

    const html_node_t *node = find_node_by_id(doc->root, "box");
    if (!node)
    {
        html_document_destroy(doc);
        return false;
    }

    css_style_t parent = {0};
    css_style_t out = {0};
    html_view_style_for_node(&out, NULL, &parent, node);

    bool ok = out.has_background &&
              !out.background_transparent &&
              out.background == video_make_color(0xFF, 0x00, 0x00);
    ok = ok && out.has_background_image &&
         out.background_image &&
         strcmp(out.background_image, "foo.png") == 0;
    ok = ok && out.has_background_repeat &&
         out.background_repeat == CSS_BACKGROUND_REPEAT_NO_REPEAT;
    ok = ok && out.has_background_attachment &&
         out.background_attachment == CSS_BACKGROUND_ATTACHMENT_FIXED;
    ok = ok && out.has_background_position &&
         css_length_is(&out.background_pos_x, 1000, CSS_UNIT_PX) &&
         css_length_is(&out.background_pos_y, 2000, CSS_UNIT_PX);

    if (out.background_image_owned && out.background_image)
    {
        free((void *)out.background_image);
    }
    html_document_destroy(doc);
    return ok;
}

static bool test_link_stylesheet_data_url(void)
{
    html_parse_error_t err = {0};
    const char *html =
        "<html><head>"
        "<style>div{background:red;}</style>"
        "<link rel=\"appendix stylesheet\" href=\"data:text/css,div%7Bbackground%3Ablue%3B%7D\">"
        "</head><body><div id=\"box\"></div></body></html>";
    html_document_t *doc = html_parse(html, &err);
    if (!doc)
    {
        return false;
    }

    const html_node_t *box = find_node_by_id(doc->root, "box");
    if (!box)
    {
        html_document_destroy(doc);
        return false;
    }

    atk_html_view_priv_t priv = {0};
    priv.doc = doc;
    html_view_rebuild_stylesheet(&priv);
    if (!priv.sheet)
    {
        html_document_destroy(doc);
        return false;
    }

    css_style_t parent = {0};
    css_style_t out = {0};
    html_view_style_for_node(&out, priv.sheet, &parent, box);

    bool ok = out.has_background &&
              !out.background_transparent &&
              out.background == video_make_color(0x00, 0x00, 0xFF);

    css_stylesheet_destroy(priv.sheet);
    priv.sheet = NULL;
    html_document_destroy(doc);
    return ok;
}

static bool test_object_fallback_text(void)
{
    html_parse_error_t err = {0};
    html_document_t *doc = html_parse("<object data=\"data:application/x-unknown,ERROR\">OK</object>", &err);
    if (!doc)
    {
        return false;
    }

    const html_node_t *obj = find_first_tag(doc->root, "object");
    if (!obj)
    {
        html_document_destroy(doc);
        return false;
    }

    atk_html_view_priv_t priv = {0};
    html_view_ctx_t ctx = {0};
    ctx.priv = &priv;
    ctx.viewport_w = 200;
    ctx.viewport_h = 200;
    ctx.body_w = 200;
    ctx.max_x = 200;
    ctx.actual_font_px = 16;
    ctx.base_font_px = 16;
    ctx.base_line_height = 16;
    ctx.line_height = 16;
    ctx.space_w = html_view_text_width(&ctx, " ");
    ctx.paint_layer = HTML_VIEW_PAINT_LAYER_BLOCK;

    css_style_t parent = {0};
    css_style_t style = {0};
    html_view_style_for_node(&style, NULL, &parent, obj);

    bool rendered = html_view_render_inline_element(&ctx, obj, &style);
    int expected = html_view_text_width(&ctx, "OK");
    html_view_font_state_reset(&priv.font);
    html_document_destroy(doc);
    return rendered && ctx.x == expected;
}

static bool test_float_inherit(void)
{
    html_parse_error_t err = {0};
    html_document_t *doc = html_parse("<span id=\"parent\"><em id=\"child\"></em></span>", &err);
    if (!doc)
    {
        return false;
    }

    const html_node_t *parent_node = find_node_by_id(doc->root, "parent");
    const html_node_t *child_node = find_node_by_id(doc->root, "child");
    if (!parent_node || !child_node)
    {
        html_document_destroy(doc);
        return false;
    }

    const char *css = "span { float: right; } em { float: inherit; }";
    css_stylesheet_t *sheet = css_parse(css);
    if (!sheet)
    {
        html_document_destroy(doc);
        return false;
    }

    css_style_t root = {0};
    css_style_t parent_style = {0};
    html_view_style_for_node(&parent_style, sheet, &root, parent_node);

    css_style_t child_style = {0};
    html_view_style_for_node(&child_style, sheet, &parent_style, child_node);

    bool ok = parent_style.has_float && parent_style.float_mode == CSS_FLOAT_RIGHT;
    ok = ok && child_style.has_float && child_style.float_mode == CSS_FLOAT_RIGHT;
    ok = ok && !child_style.float_inherit;

    css_stylesheet_destroy(sheet);
    html_document_destroy(doc);
    return ok;
}

static bool test_float_measure_width(void)
{
    html_view_ctx_t ctx = {0};
    ctx.viewport_w = 200;
    ctx.viewport_h = 200;
    ctx.body_w = 200;
    ctx.max_x = 200;
    ctx.actual_font_px = 16;
    ctx.base_font_px = 16;
    ctx.base_line_height = 16;
    ctx.line_height = 16;
    ctx.paint_layer = HTML_VIEW_PAINT_LAYER_BLOCK;

    css_style_t style = {0};
    style.has_float = true;
    style.float_mode = CSS_FLOAT_RIGHT;
    style.has_width = true;
    style.width.valid = true;
    style.width.is_auto = false;
    style.width.value_milli = 40000;
    style.width.unit = CSS_UNIT_PX;

    html_node_t node = {0};
    node.type = HTML_NODE_ELEMENT;
    node.name = (char *)"div";

    html_view_render_float_box(&ctx, &node, &style, CSS_FLOAT_RIGHT);

    return ctx.measure_max_x >= 40;
}

#define ACID2_SNAPSHOT_HASH 0x62F2DE48A86F2400ULL

static bool test_acid2_render_snapshot(void)
{
    size_t html_len = 0;
    char *html = read_file("tests/acid2.html", &html_len);
    if (!html)
    {
        printf("html_view_host_test: acid2 snapshot failed to read tests/acid2.html\n");
        return false;
    }

    html_parse_error_t err = {0};
    html_document_t *doc = html_parse(html, &err);
    if (!doc)
    {
        printf("html_view_host_test: acid2 snapshot parse failed at %zu: %s\n",
               err.offset,
               err.message ? err.message : "unknown");
        free(html);
        return false;
    }

    char *css = NULL;
    size_t css_len = 0;
    size_t css_cap = 0;
    collect_style_text(doc->root, &css, &css_len, &css_cap);
    css_stylesheet_t *sheet = css_parse(css ? css : "");
    if (!sheet)
    {
        printf("html_view_host_test: acid2 snapshot css parse failed\n");
        html_document_destroy(doc);
        free(html);
        free(css);
        return false;
    }

    atk_html_view_priv_t priv = {0};
    priv.doc = doc;
    priv.sheet = sheet;
    html_view_render_cache_clear(&priv.render_cache);
    priv.render_cache.tile_h = ATK_HTML_VIEW_RENDER_TILE_H;

    const html_node_t *html_node = find_first_tag(doc->root, "html");
    const html_node_t *body_node = find_first_tag(doc->root, "body");

    const int viewport_x = 0;
    const int viewport_y = 0;
    const int viewport_w = 1000;
    const int viewport_h = 800;

    video_color_t default_page_bg = video_make_color(0xFF, 0xFF, 0xFF);
    video_color_t default_text = video_make_color(0x00, 0x00, 0x00);

    css_style_t base_style = {0};
    base_style.has_color = true;
    base_style.color = default_text;
    base_style.has_font_size = true;
    base_style.font_size = (css_length_t){
        .valid = true,
        .is_auto = false,
        .value_milli = atk_font_line_height() * 1000,
        .unit = CSS_UNIT_PX,
    };
    base_style.has_line_height = true;
    base_style.line_height_milli = 1000;

    css_style_t html_style = {0};
    if (html_node)
    {
        html_view_style_for_node(&html_style, sheet, &base_style, html_node);
    }
    else
    {
        html_style = base_style;
    }

    css_style_t body_style = {0};
    if (body_node)
    {
        html_view_style_for_node(&body_style, sheet, &html_style, body_node);
    }
    else
    {
        body_style = html_style;
    }

    bool body_has_bg = body_style.has_background && !body_style.background_transparent;
    video_color_t body_bg = body_has_bg ? body_style.background : default_page_bg;

    int actual_font_px = atk_font_line_height();
    int css_font_px = actual_font_px;
    const css_style_t *font_src = &html_style;
    if (!(html_style.has_font_size && html_style.font_size.valid && !html_style.font_size.is_auto) &&
        (body_style.has_font_size && body_style.font_size.valid && !body_style.font_size.is_auto))
    {
        font_src = &body_style;
    }
    if (font_src->has_font_size && font_src->font_size.valid && !font_src->font_size.is_auto)
    {
        int computed = html_view_length_to_px(&font_src->font_size,
                                              viewport_w,
                                              viewport_h,
                                              viewport_w,
                                              viewport_h,
                                              actual_font_px,
                                              true);
        if (computed > 0)
        {
            css_font_px = computed;
        }
    }
    if (css_font_px > HTML_VIEW_FONT_MAX_PX)
    {
        css_font_px = HTML_VIEW_FONT_MAX_PX;
    }

    int base_font_px = css_font_px;
    int base_line_height = base_font_px + 4;
    if (base_line_height < 8)
    {
        base_line_height = 8;
    }

    int border_px = 0;
    if (body_style.has_border)
    {
        border_px = html_view_length_to_px(&body_style.border_width.left,
                                           viewport_w,
                                           viewport_h,
                                           viewport_w,
                                           viewport_h,
                                           base_font_px,
                                           true);
        if (border_px < 0)
        {
            border_px = 0;
        }
    }

    int pad_top = 0;
    int pad_right = 0;
    int pad_bottom = 0;
    int pad_left = 0;
    if (body_style.has_padding)
    {
        pad_top = html_view_length_to_px(&body_style.padding.top,
                                         viewport_w,
                                         viewport_h,
                                         viewport_w,
                                         viewport_h,
                                         base_font_px,
                                         false);
        pad_right = html_view_length_to_px(&body_style.padding.right,
                                           viewport_w,
                                           viewport_h,
                                           viewport_w,
                                           viewport_h,
                                           base_font_px,
                                           true);
        pad_bottom = html_view_length_to_px(&body_style.padding.bottom,
                                            viewport_w,
                                            viewport_h,
                                            viewport_w,
                                            viewport_h,
                                            base_font_px,
                                            false);
        pad_left = html_view_length_to_px(&body_style.padding.left,
                                          viewport_w,
                                          viewport_h,
                                          viewport_w,
                                          viewport_h,
                                          base_font_px,
                                          true);
        if (pad_top < 0) pad_top = 0;
        if (pad_right < 0) pad_right = 0;
        if (pad_bottom < 0) pad_bottom = 0;
        if (pad_left < 0) pad_left = 0;
    }

    int body_content_w = viewport_w;
    if (body_style.has_width)
    {
        int computed = html_view_length_to_px(&body_style.width,
                                              viewport_w,
                                              viewport_h,
                                              viewport_w,
                                              viewport_h,
                                              base_font_px,
                                              true);
        if (computed > 0)
        {
            body_content_w = computed;
        }
    }
    if (body_content_w < 0)
    {
        body_content_w = 0;
    }

    int body_box_w = body_content_w + pad_left + pad_right + border_px * 2;
    if (body_box_w > viewport_w)
    {
        int max_content = viewport_w - pad_left - pad_right - border_px * 2;
        if (max_content < 0)
        {
            max_content = 0;
        }
        body_content_w = max_content;
        body_box_w = body_content_w + pad_left + pad_right + border_px * 2;
    }

    int body_box_x = viewport_x;
    if (body_style.has_margin)
    {
        bool auto_left = body_style.margin.left.valid && body_style.margin.left.is_auto;
        bool auto_right = body_style.margin.right.valid && body_style.margin.right.is_auto;
        if (auto_left && auto_right)
        {
            body_box_x = viewport_x + (viewport_w - body_box_w) / 2;
        }
        else if (body_style.margin.left.valid && !body_style.margin.left.is_auto)
        {
            body_box_x = viewport_x + html_view_length_to_px_signed(&body_style.margin.left,
                                                                    viewport_w,
                                                                    viewport_h,
                                                                    viewport_w,
                                                                    viewport_h,
                                                                    base_font_px,
                                                                    true);
        }
    }

    int margin_top = 0;
    if (body_style.has_margin && body_style.margin.top.valid && !body_style.margin.top.is_auto)
    {
        margin_top = html_view_length_to_px_signed(&body_style.margin.top,
                                                   viewport_w,
                                                   viewport_h,
                                                   viewport_w,
                                                   viewport_h,
                                                   base_font_px,
                                                   false);
    }

    int body_box_y0 = viewport_y + margin_top;
    int body_content_x = body_box_x + border_px + pad_left;
    int body_content_y0 = body_box_y0 + border_px + pad_top;

    int body_height_basis = 0;
    bool body_height_valid = false;
    if (body_style.has_height && body_style.height.valid && !body_style.height.is_auto)
    {
        body_height_basis = html_view_length_to_px(&body_style.height,
                                                   viewport_w,
                                                   viewport_h,
                                                   viewport_w,
                                                   viewport_h,
                                                   base_font_px,
                                                   false);
        if (body_height_basis < 0)
        {
            body_height_basis = 0;
        }
        body_height_valid = true;
    }

    priv.render_cache.doc = doc;
    priv.render_cache.sheet = sheet;
    priv.render_cache.viewport_w = viewport_w;
    priv.render_cache.viewport_h = viewport_h;
    priv.render_cache.doc_origin_local_x = body_content_x - viewport_x;
    priv.render_cache.doc_origin_local_y = body_content_y0 - viewport_y;
    priv.render_cache.body_w = body_content_w;
    priv.render_cache.base_font_px = base_font_px;
    priv.render_cache.base_line_height = base_line_height;

    const int clip_pad = 10000000;
    atk_rect_t record_clip = {
        .x = viewport_x - clip_pad,
        .y = viewport_y - clip_pad,
        .width = viewport_w + clip_pad * 2,
        .height = viewport_h + clip_pad * 2
    };

    html_view_float_ctx_t floats_record = {0};
    html_view_ctx_t record = {
        .state = NULL,
        .widget = NULL,
        .priv = &priv,
        .sheet = sheet,
        .bg = body_bg,
        .clip = record_clip,
        .viewport_x = viewport_x,
        .viewport_y = viewport_y,
        .viewport_w = viewport_w,
        .viewport_h = viewport_h,
        .scroll_y = 0,
        .window_x = 0,
        .window_y = 0,
        .body_x = body_content_x,
        .body_w = body_content_w,
        .pos_x = viewport_x,
        .pos_y = viewport_y,
        .pos_w = viewport_w,
        .pos_h = viewport_h,
        .height_basis = body_height_basis,
        .height_basis_valid = body_height_valid,
        .height_basis_explicit = body_height_valid,
        .floats = &floats_record,
        .actual_font_px = base_font_px,
        .base_font_px = base_font_px,
        .base_line_height = base_line_height,
        .line_height = base_line_height,
        .space_w = 0,
        .x = body_content_x,
        .y = body_content_y0,
        .max_x = body_content_x + body_content_w,
        .measure_max_x = body_content_x,
        .content_bottom = body_content_y0,
        .pending_margin = {0},
        .list_level = 0,
        .text_align_mode = body_style.has_text_align ? body_style.text_align : CSS_TEXT_ALIGN_LEFT,
        .line_op_start = 0,
        .line_start_x = body_content_x,
        .line_start_y = body_content_y0,
        .pending_space = false,
        .z_index = 0,
        .paint_layer = HTML_VIEW_PAINT_LAYER_BLOCK,
        .draw = false,
        .record = true,
        .record_failed = false,
        .fixed_mode = false,
        .table_mode = false,
        .doc_origin_x = body_content_x,
        .doc_origin_y = body_content_y0
    };

    record.space_w = html_view_text_width(&record, " ");
    if (body_node)
    {
        html_view_render_children(&record, body_node, &body_style);
    }
    else if (doc->root)
    {
        html_view_render_children(&record, doc->root, &body_style);
    }
    html_view_align_current_line(&record);
    html_view_style_stack_destroy(&record);

    if (surface_init(viewport_w, viewport_h, body_bg))
    {
        surface_clear(body_bg);
        html_view_ctx_t draw_ctx = record;
        draw_ctx.draw = true;
        draw_ctx.record = false;
        draw_ctx.clip = (atk_rect_t){ viewport_x, viewport_y, viewport_w, viewport_h };
        int anchor_y = 0;
        if (find_anchor_y(&priv.render_cache, "top", &anchor_y))
        {
            if (anchor_y < 0)
            {
                anchor_y = 0;
            }
            draw_ctx.scroll_y = anchor_y;
        }
        else
        {
            draw_ctx.scroll_y = 0;
        }

        html_view_render_cache_draw_visible(&draw_ctx);

        if (ensure_test_out_dir())
        {
            time_t now = time(NULL);
            char path[128];
            snprintf(path, sizeof(path), "test-out/acid2-run-%lld.png", (long long)now);
            if (!host_write_png_rgba32(path,
                                       g_surface,
                                       g_surface_width,
                                       g_surface_height,
                                       g_surface_width * (int)sizeof(video_color_t)))
            {
                printf("html_view_host_test: acid2 snapshot failed to write %s\n", path);
            }
            else
            {
                printf("html_view_host_test: acid2 snapshot wrote %s\n", path);
            }
        }
        else
        {
            printf("html_view_host_test: acid2 snapshot failed to create test-out\n");
        }

        surface_destroy();
    }
    else
    {
        printf("html_view_host_test: acid2 snapshot failed to allocate surface\n");
    }

    uint64_t hash = hash_render_ops(&priv.render_cache);
    bool ok = (hash == ACID2_SNAPSHOT_HASH);
    if (!ok)
    {
        printf("html_view_host_test: acid2 snapshot mismatch got=0x%016llX expected=0x%016llX\n",
               (unsigned long long)hash,
               (unsigned long long)ACID2_SNAPSHOT_HASH);
    }

    html_view_images_clear(&priv);
    html_view_render_cache_clear(&priv.render_cache);
    css_stylesheet_destroy(sheet);
    html_document_destroy(doc);
    free(css);
    free(html);
    return ok;
}

typedef struct
{
    const char *name;
    bool (*fn)(void);
} hv_case_t;

int main(void)
{
    hv_case_t cases[] = {
        { "table-cell-align-left", test_table_cell_alignment },
        { "table-header-align-center", test_table_header_alignment },
        { "line-height-length-px", test_line_height_length_px },
        { "border-style-none-zeroes", test_border_style_none_zeroes_width },
        { "height-percent-requires-basis", test_height_percent_requires_basis },
        { "height-percent-with-basis", test_height_percent_with_basis },
        { "height-px-without-basis", test_height_px_without_basis },
        { "margin-collapse-siblings", test_margin_collapse_siblings },
        { "margin-collapse-empty-block", test_margin_collapse_empty_block },
        { "attribute-selectors-escapes", test_attribute_selectors_with_escapes },
        { "adjacent-sibling-selector", test_adjacent_sibling_selector },
        { "child-descendant-selector", test_child_and_descendant_selectors },
        { "link-pseudo-class", test_link_pseudo_class },
        { "pseudo-element-style", test_pseudo_element_style },
        { "inline-background-style", test_inline_background_style },
        { "link-stylesheet-data-url", test_link_stylesheet_data_url },
        { "object-fallback-text", test_object_fallback_text },
        { "float-inherit", test_float_inherit },
        { "float-measure-width", test_float_measure_width },
        { "acid2-snapshot", test_acid2_render_snapshot },
    };

    size_t pass = 0;
    size_t fail = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    {
        bool ok = cases[i].fn();
        if (ok)
        {
            pass++;
        }
        else
        {
            fail++;
            printf("html_view_host_test: case %s failed\n", cases[i].name);
        }
    }

    printf("html_view_host_test: total=%zu pass=%zu fail=%zu\n", pass + fail, pass, fail);
    return fail == 0 ? 0 : 1;
}
