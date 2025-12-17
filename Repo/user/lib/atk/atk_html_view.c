#include "atk/atk_html_view.h"

#include "atk/atk_checkbox.h"
#include "atk/atk_font.h"
#include "atk/atk_radio.h"
#include "atk/atk_scrollbar.h"
#include "atk/atk_text_input.h"
#include "atk/util/png.h"
#include "atk_internal.h"
#include "atk_window.h"
#include "ctype.h"
#include "libc.h"
#include "ttf.h"
#include "usyscall.h"
#include "utf8.h"
#include "video.h"
#include "web/css.h"
#include "web/html.h"

#define ATK_HTML_VIEW_PADDING 8
#define ATK_HTML_VIEW_SCROLLBAR_WIDTH 14
#define ATK_HTML_VIEW_RENDER_TILE_H 256

#define HTML_VIEW_FONT_CACHE_FIRST 32
#define HTML_VIEW_FONT_CACHE_LAST  126
#define HTML_VIEW_FONT_CACHE_COUNT (HTML_VIEW_FONT_CACHE_LAST - HTML_VIEW_FONT_CACHE_FIRST + 1)
#define HTML_VIEW_FONT_EXTRA_CACHE_SLOTS 256
#define HTML_VIEW_FONT_SIZE_CACHE_SLOTS 8
#define HTML_VIEW_FONT_MAX_ROW_PIXELS 256
#define HTML_VIEW_FONT_TEXT_GUARD 2048

typedef struct html_view_image
{
    char *src;
    video_color_t *pixels;
    int width;
    int height;
    int stride_bytes;
    struct html_view_image *next;
} html_view_image_t;

typedef enum
{
    HTML_VIEW_CONTROL_INPUT_TEXT = 0,
    HTML_VIEW_CONTROL_TEXTAREA,
    HTML_VIEW_CONTROL_BUTTON,
    HTML_VIEW_CONTROL_CHECKBOX,
    HTML_VIEW_CONTROL_RADIO
} html_view_control_kind_t;

typedef struct html_view_control
{
    const html_node_t *node;
    atk_widget_t *widget;
    html_view_control_kind_t kind;
    struct html_view_control *next;
} html_view_control_t;

typedef struct
{
    bool ready;
    uint8_t *alpha;
    int width;
    int height;
    int stride;
    int advance;
    int bearing_x;
    int bearing_y;
} html_view_font_glyph_t;

typedef struct
{
    uint32_t codepoint;
    uint32_t last_used;
    html_view_font_glyph_t glyph;
} html_view_font_glyph_entry_t;

typedef struct
{
    bool used;
    int pixel_height;
    ttf_font_metrics_t metrics;
    html_view_font_glyph_t glyphs[HTML_VIEW_FONT_CACHE_COUNT];
    html_view_font_glyph_entry_t extra_glyphs[HTML_VIEW_FONT_EXTRA_CACHE_SLOTS];
    uint32_t glyph_use_counter;
    uint32_t last_used;
} html_view_font_size_cache_t;

typedef struct
{
    bool ready;
    ttf_font_t font;
    uint8_t *font_blob;
    size_t font_blob_size;
    uint32_t cache_use_counter;
    html_view_font_size_cache_t size_caches[HTML_VIEW_FONT_SIZE_CACHE_SLOTS];
} html_view_font_state_t;

typedef enum
{
    HTML_VIEW_OP_RECT = 0,
    HTML_VIEW_OP_TEXT,
    HTML_VIEW_OP_IMAGE,
    HTML_VIEW_OP_CONTROL
} html_view_op_kind_t;

typedef struct
{
    html_view_op_kind_t kind;
    int32_t x;
    int32_t y;
    int32_t w;
    int32_t h;
    video_color_t color;
    const char *text;
    uint32_t text_len;
    bool text_owned;
    int16_t baseline_off;
    int16_t font_px;
    const video_color_t *pixels;
    int stride_bytes;
    atk_widget_t *widget;
} html_view_op_t;

typedef struct
{
    size_t *ops;
    size_t count;
    size_t cap;
} html_view_tile_t;

typedef struct
{
    bool valid;
    const html_document_t *doc;
    const css_stylesheet_t *sheet;
    int viewport_w;
    int viewport_h;
    int body_w;
    int base_font_px;
    int base_line_height;
    int body_box_h;
    int content_height;
    int tile_h;
    char **owned_text;
    size_t owned_text_count;
    size_t owned_text_cap;
    html_view_op_t *ops;
    size_t op_count;
    size_t op_cap;
    html_view_tile_t *tiles;
    size_t tile_count;
    size_t tile_used;
} html_view_render_cache_t;

typedef struct
{
    atk_list_node_t *child_node;
    atk_widget_t *scrollbar;
    int scrollbar_width;
    int scroll_y;
    int content_height;
    int last_width;
    int last_height;
    html_document_t *doc;
    css_stylesheet_t *sheet;
    char *external_css;
    size_t external_css_len;
    html_view_image_t *images;
    html_view_control_t *controls;
    html_view_font_state_t font;
    html_view_render_cache_t render_cache;
} atk_html_view_priv_t;

typedef struct
{
    int x;
    int y;
    int w;
    int h;
    css_float_t side;
} html_view_float_t;

typedef struct
{
    html_view_float_t items[128];
    size_t count;
} html_view_float_ctx_t;

typedef struct html_view_style_block
{
    css_style_t styles[64];
    size_t used;
    struct html_view_style_block *prev;
} html_view_style_block_t;

typedef struct
{
    const atk_state_t *state;
    const atk_widget_t *widget;
    atk_html_view_priv_t *priv;
    const css_stylesheet_t *sheet;
    video_color_t bg;
    atk_rect_t clip;
    int viewport_x;
    int viewport_y;
    int viewport_w;
    int viewport_h;
    int window_x;
    int window_y;
    int body_x;
    int body_w;
    html_view_float_ctx_t *floats;
    int actual_font_px;
    int base_font_px;
    int base_line_height;
    int line_height;
    int space_w;
    int x;
    int y;
    int max_x;
    int content_bottom;
    int list_level;
    bool text_underline;
    bool text_bold;
    bool pending_space;
    bool draw;
    bool record;
    bool record_failed;
    int doc_origin_x;
    int doc_origin_y;
    html_view_style_block_t *style_block;
    size_t style_depth;
} html_view_ctx_t;

static void html_view_draw_rect_clipped(html_view_ctx_t *ctx,
                                        int x,
                                        int y,
                                        int w,
                                        int h,
                                        video_color_t color,
                                        const atk_rect_t *clip);
static void html_view_blit_rgba32_clipped(html_view_ctx_t *ctx,
                                         int dst_x,
                                         int dst_y,
                                         int w,
                                         int h,
                                         const video_color_t *src,
                                         int src_stride_bytes,
                                         const atk_rect_t *clip);
static void html_view_draw_string_clipped(const html_view_ctx_t *ctx,
                                          int x,
                                          int baseline_y,
                                          const char *text,
                                          video_color_t fg,
                                          const atk_rect_t *clip);
static void html_view_place_control_widget(html_view_ctx_t *ctx,
                                           atk_widget_t *child,
                                           int abs_x,
                                           int abs_y,
                                           int width,
                                           int height);

static atk_html_view_priv_t *html_view_priv_mut(atk_widget_t *view)
{
    return (atk_html_view_priv_t *)atk_widget_priv(view, &ATK_HTML_VIEW_CLASS);
}

static void html_view_invalidate(const atk_widget_t *view)
{
    if (!view || !view->parent)
    {
        return;
    }
    int origin_x = view->parent->x + view->x;
    int origin_y = view->parent->y + view->y;
    atk_dirty_mark_rect(origin_x, origin_y, view->width, view->height);
    video_request_refresh_window(view->parent);
}

static bool html_view_hit_test_cb(const atk_widget_t *widget,
                                  int origin_x,
                                  int origin_y,
                                  int px,
                                  int py,
                                  void *context)
{
    (void)context;
    if (!widget)
    {
        return false;
    }
    int x0 = origin_x + widget->x;
    int y0 = origin_y + widget->y;
    int x1 = x0 + widget->width;
    int y1 = y0 + widget->height;
    return (px >= x0 && px < x1 && py >= y0 && py < y1);
}

static atk_mouse_response_t html_view_mouse_cb(atk_widget_t *widget,
                                               const atk_mouse_event_t *event,
                                               void *context)
{
    (void)widget;
    (void)event;
    (void)context;
    return ATK_MOUSE_RESPONSE_NONE;
}

static atk_key_response_t html_view_key_cb(atk_widget_t *widget,
                                           int key,
                                           int modifiers,
                                           int action,
                                           void *context)
{
    (void)widget;
    (void)key;
    (void)modifiers;
    (void)action;
    (void)context;
    return ATK_KEY_RESPONSE_NONE;
}

static bool html_view_buf_append(char **buf, size_t *len, size_t *cap, const char *data, size_t data_len)
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
    if (needed > *cap)
    {
        size_t new_cap = (*cap == 0) ? 1024 : *cap;
        while (new_cap < needed)
        {
            new_cap *= 2;
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

static char *html_view_strdup(const char *src)
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

static void html_view_render_cache_clear(html_view_render_cache_t *cache)
{
    if (!cache)
    {
        return;
    }

    for (size_t i = 0; i < cache->owned_text_count; ++i)
    {
        free(cache->owned_text[i]);
    }
    free(cache->owned_text);
    cache->owned_text = NULL;
    cache->owned_text_count = 0;
    cache->owned_text_cap = 0;

    if (cache->ops)
    {
        for (size_t i = 0; i < cache->op_count; ++i)
        {
            html_view_op_t *op = &cache->ops[i];
            if (op->kind == HTML_VIEW_OP_TEXT && op->text_owned)
            {
                free((void *)op->text);
            }
        }
    }

    for (size_t i = 0; i < cache->tile_count; ++i)
    {
        free(cache->tiles[i].ops);
        cache->tiles[i].ops = NULL;
        cache->tiles[i].count = 0;
        cache->tiles[i].cap = 0;
    }

    free(cache->tiles);
    free(cache->ops);
    memset(cache, 0, sizeof(*cache));
}

static bool html_view_render_cache_ensure_tiles(html_view_render_cache_t *cache, size_t needed)
{
    if (!cache)
    {
        return false;
    }
    if (needed <= cache->tile_count)
    {
        return true;
    }

    size_t new_count = cache->tile_count ? cache->tile_count : 8;
    while (new_count < needed)
    {
        new_count *= 2;
    }

    html_view_tile_t *new_tiles = (html_view_tile_t *)realloc(cache->tiles, new_count * sizeof(*new_tiles));
    if (!new_tiles)
    {
        return false;
    }
    memset(new_tiles + cache->tile_count, 0, (new_count - cache->tile_count) * sizeof(*new_tiles));
    cache->tiles = new_tiles;
    cache->tile_count = new_count;
    return true;
}

static bool html_view_render_cache_add_op_to_tile(html_view_render_cache_t *cache, size_t tile_index, size_t op_index)
{
    if (!cache)
    {
        return false;
    }
    if (!html_view_render_cache_ensure_tiles(cache, tile_index + 1))
    {
        return false;
    }
    if (tile_index + 1 > cache->tile_used)
    {
        cache->tile_used = tile_index + 1;
    }

    html_view_tile_t *tile = &cache->tiles[tile_index];
    if (tile->count == tile->cap)
    {
        size_t new_cap = tile->cap ? (tile->cap * 2) : 64;
        size_t *new_ops = (size_t *)realloc(tile->ops, new_cap * sizeof(*new_ops));
        if (!new_ops)
        {
            return false;
        }
        tile->ops = new_ops;
        tile->cap = new_cap;
    }
    tile->ops[tile->count++] = op_index;
    return true;
}

static char *html_view_render_cache_strdup(html_view_render_cache_t *cache, const char *text)
{
    if (!cache || !text)
    {
        return NULL;
    }

    char *dup = html_view_strdup(text);
    if (!dup)
    {
        return NULL;
    }

    if (cache->owned_text_count == cache->owned_text_cap)
    {
        size_t new_cap = cache->owned_text_cap ? (cache->owned_text_cap * 2) : 64;
        char **new_list = (char **)realloc(cache->owned_text, new_cap * sizeof(*new_list));
        if (!new_list)
        {
            free(dup);
            return NULL;
        }
        cache->owned_text = new_list;
        cache->owned_text_cap = new_cap;
    }

    cache->owned_text[cache->owned_text_count++] = dup;
    return dup;
}

static bool html_view_render_cache_push_op(html_view_render_cache_t *cache, const html_view_op_t *op, int tile_h)
{
    if (!cache || !op || tile_h <= 0)
    {
        return false;
    }

    if (cache->op_count == cache->op_cap)
    {
        size_t new_cap = cache->op_cap ? (cache->op_cap * 2) : 1024;
        html_view_op_t *new_ops = (html_view_op_t *)realloc(cache->ops, new_cap * sizeof(*new_ops));
        if (!new_ops)
        {
            return false;
        }
        cache->ops = new_ops;
        cache->op_cap = new_cap;
    }

    size_t index = cache->op_count++;
    cache->ops[index] = *op;

    int32_t y0 = op->y;
    int32_t y1 = op->y;
    if (op->kind == HTML_VIEW_OP_TEXT)
    {
        y1 = y0 + op->h;
    }
    else if (op->kind == HTML_VIEW_OP_RECT || op->kind == HTML_VIEW_OP_IMAGE || op->kind == HTML_VIEW_OP_CONTROL)
    {
        y1 = y0 + op->h;
    }

    if (y0 < 0)
    {
        y0 = 0;
    }
    if (y1 < y0)
    {
        y1 = y0;
    }

    size_t tile0 = (size_t)((uint32_t)y0 / (uint32_t)tile_h);
    size_t tile1 = (y1 > 0) ? (size_t)((uint32_t)(y1 - 1) / (uint32_t)tile_h) : tile0;
    for (size_t t = tile0; t <= tile1; ++t)
    {
        if (!html_view_render_cache_add_op_to_tile(cache, t, index))
        {
            return false;
        }
    }

    return true;
}

static void html_view_render_cache_draw_text_span(html_view_ctx_t *ctx,
                                                  int x,
                                                  int baseline_y,
                                                  const char *text,
                                                  uint32_t len,
                                                  video_color_t color)
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

    html_view_draw_string_clipped(ctx, x, baseline_y, tmp, color, &ctx->clip);
    free(heap);
}

static void html_view_render_cache_draw_visible(html_view_ctx_t *ctx)
{
    if (!ctx || !ctx->priv)
    {
        return;
    }

    const html_view_render_cache_t *cache = &ctx->priv->render_cache;
    if (!cache->valid || !cache->tiles || cache->tile_used == 0)
    {
        return;
    }

    int tile_h = cache->tile_h > 0 ? cache->tile_h : ATK_HTML_VIEW_RENDER_TILE_H;
    if (tile_h <= 0)
    {
        return;
    }

    int scroll_y = ctx->priv->scroll_y;
    int visible_y0 = scroll_y - tile_h;
    int visible_y1 = scroll_y + ctx->viewport_h + tile_h;
    if (visible_y0 < 0) visible_y0 = 0;

    int start_tile = scroll_y / tile_h;
    int end_tile = (scroll_y + ctx->viewport_h) / tile_h;
    if (start_tile > 0) start_tile -= 1;
    end_tile += 1;
    if (start_tile < 0) start_tile = 0;
    if (cache->tile_used > 0 && (size_t)end_tile >= cache->tile_used)
    {
        end_tile = (int)cache->tile_used - 1;
    }

    int tile_count = (end_tile - start_tile) + 1;
    if (tile_count <= 0)
    {
        return;
    }

    size_t tile_pos_stack[32];
    size_t *tile_pos = tile_pos_stack;
    if (tile_count > (int)(sizeof(tile_pos_stack) / sizeof(tile_pos_stack[0])))
    {
        tile_pos = (size_t *)calloc((size_t)tile_count, sizeof(*tile_pos));
        if (!tile_pos)
        {
            return;
        }
    }
    else
    {
        memset(tile_pos, 0, (size_t)tile_count * sizeof(*tile_pos));
    }

    size_t last_op_index = (size_t)-1;
    for (;;)
    {
        size_t min_op_index = (size_t)-1;
        int min_tile_slot = -1;

        for (int i = 0; i < tile_count; ++i)
        {
            int t = start_tile + i;
            if (t < 0 || (size_t)t >= cache->tile_count)
            {
                continue;
            }

            const html_view_tile_t *tile = &cache->tiles[t];
            size_t pos = tile_pos[i];
            if (pos >= tile->count)
            {
                continue;
            }

            size_t op_index = tile->ops[pos];
            if (op_index < min_op_index)
            {
                min_op_index = op_index;
                min_tile_slot = i;
            }
        }

        if (min_tile_slot < 0)
        {
            break;
        }

        tile_pos[min_tile_slot] += 1;
        if (min_op_index == last_op_index)
        {
            continue;
        }
        last_op_index = min_op_index;

        if (min_op_index >= cache->op_count)
        {
            continue;
        }
        const html_view_op_t *op = &cache->ops[min_op_index];

        int op_y0 = (int)op->y;
        int op_y1 = (int)op->y + (int)op->h;
        if (op_y1 <= visible_y0 || op_y0 >= visible_y1)
        {
            continue;
        }

        int abs_x = ctx->doc_origin_x + (int)op->x;
        int abs_y = ctx->doc_origin_y + (int)op->y - scroll_y;

        switch (op->kind)
        {
            case HTML_VIEW_OP_RECT:
                html_view_draw_rect_clipped(ctx, abs_x, abs_y, (int)op->w, (int)op->h, op->color, &ctx->clip);
                break;
            case HTML_VIEW_OP_TEXT:
            {
                int baseline_y = abs_y + (int)op->baseline_off;
                int saved_font_px = ctx->actual_font_px;
                if (op->font_px > 0)
                {
                    ctx->actual_font_px = op->font_px;
                }
                html_view_render_cache_draw_text_span(ctx, abs_x, baseline_y, op->text, op->text_len, op->color);
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
                                             &ctx->clip);
                break;
            case HTML_VIEW_OP_CONTROL:
                html_view_place_control_widget(ctx, op->widget, abs_x, abs_y, (int)op->w, (int)op->h);
                break;
            default:
                break;
        }
    }

    if (tile_pos != tile_pos_stack)
    {
        free(tile_pos);
    }
}

static void html_view_images_clear(atk_html_view_priv_t *priv)
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

static void html_view_window_remove_widget(atk_widget_t *window, atk_widget_t *child)
{
    if (!window || !child)
    {
        return;
    }

    atk_window_priv_t *wpriv = (atk_window_priv_t *)atk_widget_priv(window, &ATK_WINDOW_CLASS);
    if (!wpriv)
    {
        return;
    }

    atk_list_node_t *node = atk_list_find(&wpriv->children, child);
    if (node)
    {
        atk_list_remove(&wpriv->children, node);
    }

    node = atk_list_find(&wpriv->buttons, child);
    if (node)
    {
        atk_list_remove(&wpriv->buttons, node);
    }

    node = atk_list_find(&wpriv->text_inputs, child);
    if (node)
    {
        atk_list_remove(&wpriv->text_inputs, node);
    }

    node = atk_list_find(&wpriv->scrollbars, child);
    if (node)
    {
        atk_list_remove(&wpriv->scrollbars, node);
    }

    atk_state_t *state = atk_state_get();
    if (state && atk_state_focus_widget(state) == child)
    {
        if (atk_widget_is_a(child, &ATK_TEXT_INPUT_CLASS))
        {
            atk_text_input_focus(state, NULL);
        }
        else
        {
            atk_state_set_focus_widget(state, NULL);
        }
    }

    atk_widget_destroy_any(child);
}

static void html_view_controls_clear(atk_widget_t *view, atk_html_view_priv_t *priv)
{
    if (!view || !priv)
    {
        return;
    }

    atk_widget_t *window = view->parent;
    html_view_control_t *ctrl = priv->controls;
    while (ctrl)
    {
        html_view_control_t *next = ctrl->next;
        if (window && ctrl->widget)
        {
            html_view_window_remove_widget(window, ctrl->widget);
        }
        free(ctrl);
        ctrl = next;
    }
    priv->controls = NULL;
}

static void html_view_controls_hide_all(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    for (html_view_control_t *ctrl = priv->controls; ctrl; ctrl = ctrl->next)
    {
        if (ctrl->widget)
        {
            ctrl->widget->used = false;
        }
    }
}

static html_view_control_t *html_view_control_find(atk_html_view_priv_t *priv, const html_node_t *node)
{
    if (!priv || !node)
    {
        return NULL;
    }
    for (html_view_control_t *ctrl = priv->controls; ctrl; ctrl = ctrl->next)
    {
        if (ctrl->node == node)
        {
            return ctrl;
        }
    }
    return NULL;
}

static void html_view_collect_text(const html_node_t *node, char **buf, size_t *len, size_t *cap)
{
    if (!node || !buf || !len || !cap)
    {
        return;
    }

    const html_node_t **stack = NULL;
    size_t stack_cap = 0;
    size_t sp = 0;

    const html_node_t *cur = node->first_child;
    while (cur)
    {
        if (cur->type == HTML_NODE_TEXT && cur->text)
        {
            (void)html_view_buf_append(buf, len, cap, cur->text, strlen(cur->text));
        }

        if (cur->type == HTML_NODE_ELEMENT && cur->first_child)
        {
            if (cur->next_sibling)
            {
                if (sp == stack_cap)
                {
                    size_t new_cap = stack_cap ? (stack_cap * 2) : 32;
                    const html_node_t **new_stack = (const html_node_t **)realloc(stack, new_cap * sizeof(*new_stack));
                    if (!new_stack)
                    {
                        break;
                    }
                    stack = new_stack;
                    stack_cap = new_cap;
                }
                stack[sp++] = cur->next_sibling;
            }
            cur = cur->first_child;
            continue;
        }

        if (cur->next_sibling)
        {
            cur = cur->next_sibling;
            continue;
        }
        if (sp > 0)
        {
            cur = stack[--sp];
            continue;
        }
        break;
    }

    free(stack);
}

static void html_view_trim_collapse_ws(char *text)
{
    if (!text)
    {
        return;
    }

    size_t len = strlen(text);
    size_t start = 0;
    while (start < len && isspace((unsigned char)text[start]))
    {
        start++;
    }
    size_t end = len;
    while (end > start && isspace((unsigned char)text[end - 1]))
    {
        end--;
    }

    size_t out = 0;
    bool pending_space = false;
    for (size_t i = start; i < end; ++i)
    {
        unsigned char c = (unsigned char)text[i];
        if (isspace(c))
        {
            pending_space = true;
            continue;
        }
        if (pending_space && out > 0)
        {
            text[out++] = ' ';
            pending_space = false;
        }
        text[out++] = (char)c;
    }
    text[out] = '\0';
}

static void html_view_font_glyph_free(html_view_font_glyph_t *glyph)
{
    if (!glyph)
    {
        return;
    }
    free(glyph->alpha);
    memset(glyph, 0, sizeof(*glyph));
}

static void html_view_font_cache_clear_glyphs(html_view_font_size_cache_t *cache)
{
    if (!cache)
    {
        return;
    }

    for (size_t i = 0; i < HTML_VIEW_FONT_CACHE_COUNT; ++i)
    {
        html_view_font_glyph_free(&cache->glyphs[i]);
    }

    for (size_t i = 0; i < HTML_VIEW_FONT_EXTRA_CACHE_SLOTS; ++i)
    {
        html_view_font_glyph_free(&cache->extra_glyphs[i].glyph);
        cache->extra_glyphs[i].codepoint = 0;
        cache->extra_glyphs[i].last_used = 0;
    }

    cache->glyph_use_counter = 0;
}

static void html_view_font_state_reset(html_view_font_state_t *state)
{
    if (!state)
    {
        return;
    }

    for (size_t i = 0; i < HTML_VIEW_FONT_SIZE_CACHE_SLOTS; ++i)
    {
        html_view_font_size_cache_t *cache = &state->size_caches[i];
        if (cache->used)
        {
            html_view_font_cache_clear_glyphs(cache);
        }
    }
    if (state->font.impl)
    {
        ttf_font_unload(&state->font);
    }
    free(state->font_blob);
    memset(state, 0, sizeof(*state));
}

static bool html_view_font_state_load(html_view_font_state_t *state)
{
    if (!state)
    {
        return false;
    }
    if (state->ready)
    {
        return true;
    }

    ssize_t size = sys_font_cache(NULL, 0);
    if (size <= 0)
    {
        return false;
    }

    uint8_t *buffer = (uint8_t *)malloc((size_t)size);
    if (!buffer)
    {
        return false;
    }

    ssize_t got = sys_font_cache(buffer, (size_t)size);
    if (got <= 0)
    {
        free(buffer);
        return false;
    }

    if (!ttf_font_load(&state->font, buffer, (size_t)got))
    {
        free(buffer);
        return false;
    }

    state->font_blob = buffer;
    state->font_blob_size = (size_t)got;
    state->ready = true;
    return true;
}

static html_view_font_size_cache_t *html_view_font_state_get_cache(html_view_font_state_t *state, int pixel_height)
{
    if (!state)
    {
        return NULL;
    }
    if (pixel_height < 6)
    {
        pixel_height = 6;
    }
    if (!html_view_font_state_load(state))
    {
        return NULL;
    }

    for (size_t i = 0; i < HTML_VIEW_FONT_SIZE_CACHE_SLOTS; ++i)
    {
        html_view_font_size_cache_t *cache = &state->size_caches[i];
        if (cache->used && cache->pixel_height == pixel_height)
        {
            cache->last_used = ++state->cache_use_counter;
            return cache;
        }
    }

    size_t slot = (size_t)-1;
    for (size_t i = 0; i < HTML_VIEW_FONT_SIZE_CACHE_SLOTS; ++i)
    {
        if (!state->size_caches[i].used)
        {
            slot = i;
            break;
        }
    }

    if (slot == (size_t)-1)
    {
        slot = 0;
        uint32_t best = state->size_caches[0].last_used;
        for (size_t i = 1; i < HTML_VIEW_FONT_SIZE_CACHE_SLOTS; ++i)
        {
            if (state->size_caches[i].last_used < best)
            {
                best = state->size_caches[i].last_used;
                slot = i;
            }
        }
    }

    html_view_font_size_cache_t *cache = &state->size_caches[slot];
    if (cache->used)
    {
        html_view_font_cache_clear_glyphs(cache);
    }

    memset(cache, 0, sizeof(*cache));
    cache->used = true;
    cache->pixel_height = pixel_height;
    cache->last_used = ++state->cache_use_counter;
    if (!ttf_font_metrics(&state->font, pixel_height, &cache->metrics))
    {
        cache->metrics.ascent = pixel_height;
        cache->metrics.descent = pixel_height / 4;
        cache->metrics.line_gap = 0;
    }
    return cache;
}

static bool html_view_font_render_glyph(html_view_font_state_t *state,
                                        const html_view_font_size_cache_t *cache,
                                        uint32_t codepoint,
                                        html_view_font_glyph_t *out)
{
    if (!state || !cache || !out || cache->pixel_height <= 0)
    {
        return false;
    }

    ttf_bitmap_t bitmap = {0};
    ttf_glyph_metrics_t metrics = {0};
    if (!ttf_font_render_glyph_bitmap(&state->font, codepoint, cache->pixel_height, &bitmap, &metrics))
    {
        return false;
    }

    size_t alpha_bytes = (size_t)bitmap.stride * (size_t)bitmap.height;
    uint8_t *alpha = NULL;
    if (alpha_bytes > 0)
    {
        alpha = (uint8_t *)malloc(alpha_bytes);
        if (!alpha)
        {
            ttf_bitmap_destroy(&bitmap);
            return false;
        }
        for (int row = 0; row < bitmap.height; ++row)
        {
            memcpy(alpha + (size_t)row * (size_t)bitmap.stride,
                   bitmap.pixels + (size_t)row * (size_t)bitmap.stride,
                   (size_t)bitmap.stride);
        }
    }

    out->alpha = alpha;
    out->width = bitmap.width;
    out->height = bitmap.height;
    out->stride = bitmap.stride;
    out->advance = metrics.advance;
    out->bearing_x = metrics.bearing_x;
    out->bearing_y = metrics.bearing_y;
    out->ready = true;

    ttf_bitmap_destroy(&bitmap);
    return true;
}

static html_view_font_glyph_t *html_view_font_cache_get_glyph(html_view_font_state_t *state,
                                                              html_view_font_size_cache_t *cache,
                                                              uint32_t codepoint)
{
    if (!state || !cache || !state->ready || cache->pixel_height <= 0)
    {
        return NULL;
    }

    if (codepoint < 0x20u || codepoint == 0x7Fu)
    {
        codepoint = (uint32_t)'?';
    }

    if (codepoint >= HTML_VIEW_FONT_CACHE_FIRST && codepoint <= HTML_VIEW_FONT_CACHE_LAST)
    {
        size_t idx = (size_t)(codepoint - HTML_VIEW_FONT_CACHE_FIRST);
        html_view_font_glyph_t *glyph = &cache->glyphs[idx];
        if (!glyph->ready)
        {
            (void)html_view_font_render_glyph(state, cache, codepoint, glyph);
        }
        return glyph;
    }

    uint32_t tick = ++cache->glyph_use_counter;
    html_view_font_glyph_entry_t *slot = NULL;
    html_view_font_glyph_entry_t *oldest = NULL;

    for (size_t i = 0; i < HTML_VIEW_FONT_EXTRA_CACHE_SLOTS; ++i)
    {
        html_view_font_glyph_entry_t *entry = &cache->extra_glyphs[i];
        if (entry->codepoint == codepoint)
        {
            entry->last_used = tick;
            if (!entry->glyph.ready)
            {
                (void)html_view_font_render_glyph(state, cache, codepoint, &entry->glyph);
            }
            return &entry->glyph;
        }
        if (!entry->glyph.ready)
        {
            slot = entry;
        }
        if (!oldest || entry->last_used < oldest->last_used)
        {
            oldest = entry;
        }
    }

    if (!slot)
    {
        slot = oldest;
    }
    if (!slot)
    {
        return NULL;
    }

    html_view_font_glyph_free(&slot->glyph);
    slot->codepoint = codepoint;
    slot->last_used = tick;
    (void)html_view_font_render_glyph(state, cache, codepoint, &slot->glyph);
    return &slot->glyph;
}

static html_view_font_size_cache_t *html_view_font_cache_for_ctx(const html_view_ctx_t *ctx)
{
    if (!ctx || !ctx->priv)
    {
        return NULL;
    }
    if (ctx->actual_font_px <= 0)
    {
        return NULL;
    }
    return html_view_font_state_get_cache(&ctx->priv->font, ctx->actual_font_px);
}

static int html_view_text_width(const html_view_ctx_t *ctx, const char *text)
{
    if (!ctx || !text || *text == '\0')
    {
        return 0;
    }

    html_view_font_size_cache_t *cache = html_view_font_cache_for_ctx(ctx);
    if (!cache)
    {
        return atk_font_text_width(text);
    }

    html_view_font_state_t *font_state = &ctx->priv->font;
    int width = 0;
    size_t guard = 0;
    const char *cursor = text;
    while (*cursor && guard < HTML_VIEW_FONT_TEXT_GUARD)
    {
        utf8_decode_result_t dec = utf8_decode_one(cursor);
        if (dec.consumed == 0)
        {
            break;
        }
        guard += (size_t)dec.consumed;
        cursor += dec.consumed;

        html_view_font_glyph_t *glyph = html_view_font_cache_get_glyph(font_state, cache, dec.codepoint);
        if (!glyph || !glyph->ready)
        {
            width += ctx->actual_font_px / 2;
            continue;
        }
        width += glyph->advance;
    }
    return width;
}

static int html_view_baseline_for_rect(const html_view_ctx_t *ctx, int top, int height)
{
    if (!ctx)
    {
        return atk_font_baseline_for_rect(top, height);
    }

    html_view_font_size_cache_t *cache = html_view_font_cache_for_ctx(ctx);
    if (!cache)
    {
        return atk_font_baseline_for_rect(top, height);
    }

    int ascent = cache->metrics.ascent;
    int descent = cache->metrics.descent;
    if (descent < 0)
    {
        descent = -descent;
    }
    int total = ascent + descent;
    if (total <= 0)
    {
        total = ctx->base_font_px;
    }
    int offset = (height - total) / 2 + ascent;
    return top + offset;
}

static void html_view_draw_string_clipped(const html_view_ctx_t *ctx,
                                         int x,
                                         int baseline_y,
                                         const char *text,
                                         video_color_t fg,
                                         const atk_rect_t *clip)
{
    if (!ctx || !text || *text == '\0')
    {
        return;
    }

    html_view_font_size_cache_t *cache = html_view_font_cache_for_ctx(ctx);
    if (!cache)
    {
        atk_font_draw_string_clipped(x, baseline_y, text, fg, ctx->bg, clip);
        return;
    }

    html_view_font_state_t *font_state = &ctx->priv->font;

    int clip_x0 = clip ? clip->x : 0;
    int clip_y0 = clip ? clip->y : 0;
    int clip_x1 = clip ? (clip->x + clip->width) : video_screen_width();
    int clip_y1 = clip ? (clip->y + clip->height) : video_screen_height();
    if (clip && (clip_x1 <= clip_x0 || clip_y1 <= clip_y0))
    {
        return;
    }

    video_color_t row_pixels[HTML_VIEW_FONT_MAX_ROW_PIXELS];
    int pen_x = x;

    size_t guard = 0;
    const char *cursor = text;
    while (*cursor && guard < HTML_VIEW_FONT_TEXT_GUARD)
    {
        utf8_decode_result_t dec = utf8_decode_one(cursor);
        if (dec.consumed == 0)
        {
            break;
        }
        guard += (size_t)dec.consumed;
        cursor += dec.consumed;

        html_view_font_glyph_t *glyph = html_view_font_cache_get_glyph(font_state, cache, dec.codepoint);
        if (!glyph || !glyph->ready)
        {
            pen_x += ctx->actual_font_px / 2;
            continue;
        }

        const uint8_t *glyph_alpha = glyph->alpha;
        int glyph_width = glyph->width;
        int glyph_height = glyph->height;
        int glyph_stride = glyph->stride;
        int glyph_advance = glyph->advance;
        int glyph_bearing_x = glyph->bearing_x;
        int glyph_bearing_y = glyph->bearing_y;

        if (glyph_width <= 0 || glyph_height <= 0 || !glyph_alpha || glyph_stride <= 0)
        {
            pen_x += glyph_advance;
            continue;
        }

        if (glyph_width > HTML_VIEW_FONT_MAX_ROW_PIXELS)
        {
            pen_x += glyph_advance;
            continue;
        }

        int dst_x = pen_x + glyph_bearing_x;
        int dst_y = baseline_y - glyph_bearing_y;

        int glyph_x0 = dst_x;
        int glyph_y0 = dst_y;
        int glyph_x1 = glyph_x0 + glyph_width;
        int glyph_y1 = glyph_y0 + glyph_height;

        if (glyph_x1 <= clip_x0 || glyph_x0 >= clip_x1 ||
            glyph_y1 <= clip_y0 || glyph_y0 >= clip_y1)
        {
            pen_x += glyph_advance;
            continue;
        }

        int visible_x0 = (glyph_x0 < clip_x0) ? clip_x0 : glyph_x0;
        int visible_x1 = (glyph_x1 > clip_x1) ? clip_x1 : glyph_x1;
        int visible_y0 = (glyph_y0 < clip_y0) ? clip_y0 : glyph_y0;
        int visible_y1 = (glyph_y1 > clip_y1) ? clip_y1 : glyph_y1;

        int start_col = visible_x0 - glyph_x0;
        int width = visible_x1 - visible_x0;
        int start_row = visible_y0 - glyph_y0;
        int rows = visible_y1 - visible_y0;

        if (width <= 0 || rows <= 0)
        {
            pen_x += glyph_advance;
            continue;
        }

        if (start_col >= glyph_stride)
        {
            pen_x += glyph_advance;
            continue;
        }
        if (width > glyph_stride - start_col)
        {
            width = glyph_stride - start_col;
            if (width <= 0)
            {
                pen_x += glyph_advance;
                continue;
            }
        }

        if (start_row >= glyph_height)
        {
            pen_x += glyph_advance;
            continue;
        }
        if (rows > glyph_height - start_row)
        {
            rows = glyph_height - start_row;
        }

        for (int row = 0; row < rows; ++row)
        {
            const uint8_t *src = glyph_alpha + (start_row + row) * glyph_stride + start_col;
            for (int col = 0; col < width; ++col)
            {
                uint8_t alpha = src[col];
                row_pixels[col] = ((video_color_t)alpha << 24) | (fg & 0x00FFFFFFU);
            }
            video_blit_rgba32_untracked(visible_x0,
                                        visible_y0 + row,
                                        width,
                                        1,
                                        row_pixels,
                                        width * (int)sizeof(video_color_t),
                                        true);
        }

        pen_x += glyph_advance;
    }
}

typedef struct html_view_radio_group
{
    char *name;
    atk_radio_group_t *group;
    struct html_view_radio_group *next;
} html_view_radio_group_t;

static atk_radio_group_t *html_view_radio_group_get(html_view_radio_group_t **head, const char *name)
{
    if (!head)
    {
        return NULL;
    }
    const char *key = (name && name[0] != '\0') ? name : NULL;
    if (!key)
    {
        return NULL;
    }
    for (html_view_radio_group_t *g = *head; g; g = g->next)
    {
        if (g->name && key && strcmp(g->name, key) == 0)
        {
            return g->group;
        }
    }

    atk_radio_group_t *group = atk_radio_group_create();
    if (!group)
    {
        return NULL;
    }

    html_view_radio_group_t *entry = (html_view_radio_group_t *)calloc(1, sizeof(*entry));
    if (!entry)
    {
        atk_radio_group_destroy(group);
        return NULL;
    }
    entry->group = group;
    entry->name = key ? html_view_strdup(key) : NULL;
    entry->next = *head;
    *head = entry;
    return group;
}

static void html_view_radio_groups_free(html_view_radio_group_t *head)
{
    html_view_radio_group_t *g = head;
    while (g)
    {
        html_view_radio_group_t *next = g->next;
        free(g->name);
        /* group lifetime is managed by radio widgets; do not destroy here */
        free(g);
        g = next;
    }
}

static bool html_view_controls_add(atk_html_view_priv_t *priv,
                                  const html_node_t *node,
                                  atk_widget_t *widget,
                                  html_view_control_kind_t kind)
{
    if (!priv || !node || !widget)
    {
        return false;
    }

    html_view_control_t *ctrl = (html_view_control_t *)calloc(1, sizeof(*ctrl));
    if (!ctrl)
    {
        return false;
    }
    ctrl->node = node;
    ctrl->widget = widget;
    ctrl->kind = kind;
    ctrl->next = priv->controls;
    priv->controls = ctrl;
    return true;
}

static void html_view_controls_build_node(atk_widget_t *view,
                                         atk_html_view_priv_t *priv,
                                         const html_node_t *node,
                                         html_view_radio_group_t **radio_groups)
{
    if (!view || !priv || !node)
    {
        return;
    }

    const html_node_t **stack = NULL;
    size_t stack_cap = 0;
    size_t sp = 0;

    const html_node_t *cur = node;
    while (cur)
    {
        if (cur->type == HTML_NODE_ELEMENT && cur->name)
        {
            if (strcmp(cur->name, "input") == 0)
            {
                const char *type = html_attr_get(cur, "type");
                if (!type || type[0] == '\0')
                {
                    type = "text";
                }

                atk_widget_t *w = NULL;
                if (strcmp(type, "checkbox") == 0)
                {
                    w = atk_window_add_checkbox(view->parent, "", 0, 0, 24);
                    if (w)
                    {
                        w->used = false;
                        if (html_attr_get(cur, "checked"))
                        {
                            atk_checkbox_set_checked(w, true);
                        }
                        if (!html_view_controls_add(priv, cur, w, HTML_VIEW_CONTROL_CHECKBOX))
                        {
                            html_view_window_remove_widget(view->parent, w);
                        }
                    }
                }
                else if (strcmp(type, "radio") == 0)
                {
                    const char *name = html_attr_get(cur, "name");
                    bool ephemeral_group = !(name && name[0] != '\0');
                    atk_radio_group_t *group = ephemeral_group ? atk_radio_group_create()
                                                               : html_view_radio_group_get(radio_groups, name);
                    if (group)
                    {
                        w = atk_window_add_radio_button(view->parent, group, "", 0, 0, 24);
                        if (w)
                        {
                            w->used = false;
                            if (html_attr_get(cur, "checked"))
                            {
                                atk_radio_button_set_selected(w, true);
                            }
                            if (!html_view_controls_add(priv, cur, w, HTML_VIEW_CONTROL_RADIO))
                            {
                                html_view_window_remove_widget(view->parent, w);
                            }
                        }
                        else if (ephemeral_group)
                        {
                            atk_radio_group_destroy(group);
                        }
                    }
                }
                else
                {
                    w = atk_window_add_text_input(view->parent, 0, 0, 200);
                    if (w)
                    {
                        w->used = false;
                        const char *value = html_attr_get(cur, "value");
                        if (value && value[0] != '\0')
                        {
                            atk_text_input_set_text(w, value);
                        }
                        if (!html_view_controls_add(priv, cur, w, HTML_VIEW_CONTROL_INPUT_TEXT))
                        {
                            html_view_window_remove_widget(view->parent, w);
                        }
                    }
                }
            }
            else if (strcmp(cur->name, "textarea") == 0)
            {
                atk_widget_t *w = atk_window_add_text_input(view->parent, 0, 0, 280);
                if (w)
                {
                    w->used = false;
                    atk_text_input_set_multiline(w, true);
                    char *text = NULL;
                    size_t text_len = 0;
                    size_t text_cap = 0;
                    html_view_collect_text(cur, &text, &text_len, &text_cap);
                    if (text)
                    {
                        atk_text_input_set_text(w, text);
                    }
                    free(text);
                    if (!html_view_controls_add(priv, cur, w, HTML_VIEW_CONTROL_TEXTAREA))
                    {
                        html_view_window_remove_widget(view->parent, w);
                    }
                }
            }
            else if (strcmp(cur->name, "button") == 0)
            {
                char *label = NULL;
                size_t label_len = 0;
                size_t label_cap = 0;
                html_view_collect_text(cur, &label, &label_len, &label_cap);
                if (!label)
                {
                    label = html_view_strdup("Button");
                }
                if (label)
                {
                    html_view_trim_collapse_ws(label);
                }

                int btn_w = 100;
                if (label && label[0] != '\0')
                {
                    btn_w = atk_font_text_width(label) + 20;
                    if (btn_w < 80) btn_w = 80;
                }
                int btn_h = atk_font_line_height() + 8;

                atk_widget_t *w = atk_window_add_button(view->parent,
                                                        (label && label[0] != '\0') ? label : "Button",
                                                        0,
                                                        0,
                                                        btn_w,
                                                        btn_h,
                                                        ATK_BUTTON_STYLE_TITLE_INSIDE,
                                                        false,
                                                        NULL,
                                                        NULL);
                free(label);
                if (w)
                {
                    w->used = false;
                    if (!html_view_controls_add(priv, cur, w, HTML_VIEW_CONTROL_BUTTON))
                    {
                        html_view_window_remove_widget(view->parent, w);
                    }
                }
            }
        }

        if (cur->first_child)
        {
            if (cur->next_sibling)
            {
                if (sp == stack_cap)
                {
                    size_t new_cap = stack_cap ? (stack_cap * 2) : 64;
                    const html_node_t **new_stack = (const html_node_t **)realloc(stack, new_cap * sizeof(*new_stack));
                    if (!new_stack)
                    {
                        break;
                    }
                    stack = new_stack;
                    stack_cap = new_cap;
                }
                stack[sp++] = cur->next_sibling;
            }
            cur = cur->first_child;
            continue;
        }

        if (cur->next_sibling)
        {
            cur = cur->next_sibling;
            continue;
        }
        if (sp > 0)
        {
            cur = stack[--sp];
            continue;
        }
        break;
    }

    free(stack);
}

static void html_view_controls_build(atk_widget_t *view, atk_html_view_priv_t *priv)
{
    if (!view || !priv || !priv->doc || !priv->doc->root)
    {
        return;
    }

    html_view_radio_group_t *radio_groups = NULL;
    html_view_controls_build_node(view, priv, priv->doc->root, &radio_groups);
    html_view_radio_groups_free(radio_groups);
}

static html_view_image_t *html_view_image_find(atk_html_view_priv_t *priv, const char *src)
{
    if (!priv || !src || src[0] == '\0')
    {
        return NULL;
    }
    for (html_view_image_t *img = priv->images; img; img = img->next)
    {
        if (!img->src)
        {
            continue;
        }
        if (strcmp(img->src, src) == 0)
        {
            return img;
        }
    }
    return NULL;
}

static void html_view_collect_style_text(const html_node_t *node, char **buf, size_t *len, size_t *cap)
{
    if (!node || !buf || !len || !cap)
    {
        return;
    }

    const html_node_t **stack = NULL;
    size_t stack_cap = 0;
    size_t sp = 0;

    const html_node_t *cur = node->first_child;
    while (cur)
    {
        bool descend = cur->first_child != NULL;
        if (cur->type == HTML_NODE_ELEMENT && cur->name && strcmp(cur->name, "style") == 0)
        {
            for (const html_node_t *txt = cur->first_child; txt; txt = txt->next_sibling)
            {
                if (txt->type == HTML_NODE_TEXT && txt->text)
                {
                    (void)html_view_buf_append(buf, len, cap, txt->text, strlen(txt->text));
                    (void)html_view_buf_append(buf, len, cap, "\n", 1);
                }
            }
            descend = false;
        }

        if (descend)
        {
            if (cur->next_sibling)
            {
                if (sp == stack_cap)
                {
                    size_t new_cap = stack_cap ? (stack_cap * 2) : 64;
                    const html_node_t **new_stack = (const html_node_t **)realloc(stack, new_cap * sizeof(*new_stack));
                    if (!new_stack)
                    {
                        break;
                    }
                    stack = new_stack;
                    stack_cap = new_cap;
                }
                stack[sp++] = cur->next_sibling;
            }
            cur = cur->first_child;
            continue;
        }

        if (cur->next_sibling)
        {
            cur = cur->next_sibling;
            continue;
        }
        if (sp > 0)
        {
            cur = stack[--sp];
            continue;
        }
        break;
    }

    free(stack);
}

static void html_view_rebuild_stylesheet(atk_html_view_priv_t *priv)
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

    char *css_text = NULL;
    size_t css_len = 0;
    size_t css_cap = 0;
    html_view_collect_style_text(priv->doc->root, &css_text, &css_len, &css_cap);

    if (priv->external_css && priv->external_css_len > 0)
    {
        if (css_len > 0)
        {
            (void)html_view_buf_append(&css_text, &css_len, &css_cap, "\n", 1);
        }
        (void)html_view_buf_append(&css_text,
                                   &css_len,
                                   &css_cap,
                                   priv->external_css,
                                   priv->external_css_len);
    }

    if (!css_text || css_len == 0)
    {
        free(css_text);
        return;
    }

    priv->sheet = css_parse(css_text);
    free(css_text);
}

static const html_node_t *html_view_find_first_element(const html_node_t *root, const char *tag)
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

        for (const html_node_t *child = node->first_child; child; child = child->next_sibling)
        {
            if (sp < (sizeof(stack) / sizeof(stack[0])))
            {
                stack[sp++] = child;
            }
        }
    }

    return NULL;
}

static void html_view_trim_range(const char **start, const char **end)
{
    if (!start || !end || !*start || !*end)
    {
        return;
    }
    while (*start < *end && isspace((unsigned char)**start))
    {
        (*start)++;
    }
    while (*end > *start && isspace((unsigned char)(*end)[-1]))
    {
        (*end)--;
    }
}

static bool html_view_node_has_class(const html_node_t *node, const char *cls_start, size_t cls_len)
{
    if (!node || node->type != HTML_NODE_ELEMENT || !cls_start || cls_len == 0)
    {
        return false;
    }
    const char *classes = html_attr_get(node, "class");
    if (!classes || classes[0] == '\0')
    {
        return false;
    }

    const char *p = classes;
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
        if (len == cls_len && strncasecmp(start, cls_start, cls_len) == 0)
        {
            return true;
        }
    }

    return false;
}

static bool html_view_simple_selector_matches_range(const char *sel_start,
                                                    const char *sel_end,
                                                    const html_node_t *node)
{
    if (!sel_start || !sel_end || sel_end <= sel_start || !node || node->type != HTML_NODE_ELEMENT || !node->name)
    {
        return false;
    }

    html_view_trim_range(&sel_start, &sel_end);
    if (sel_end <= sel_start)
    {
        return false;
    }

    const char *p = sel_start;
    bool have_tag = false;
    bool match = true;

    if (*p == '*')
    {
        ++p;
    }
    else if (*p != '#' && *p != '.')
    {
        const char *tag_end = p;
        while (tag_end < sel_end && *tag_end != ':' && *tag_end != '.' && *tag_end != '#' && *tag_end != '[' && !isspace((unsigned char)*tag_end))
        {
            tag_end++;
        }
        size_t tag_len = (size_t)(tag_end - p);
        if (tag_len == 0 || strlen(node->name) != tag_len || strncasecmp(node->name, p, tag_len) != 0)
        {
            match = false;
        }
        have_tag = true;
        p = tag_end;
    }

    (void)have_tag;

    while (match && p < sel_end)
    {
        if (*p == '.')
        {
            ++p;
            const char *cls_end = p;
            while (cls_end < sel_end && *cls_end != ':' && *cls_end != '.' && *cls_end != '#' && *cls_end != '[' && !isspace((unsigned char)*cls_end))
            {
                cls_end++;
            }
            size_t cls_len = (size_t)(cls_end - p);
            if (cls_len == 0 || !html_view_node_has_class(node, p, cls_len))
            {
                match = false;
                break;
            }
            p = cls_end;
            continue;
        }

        if (*p == '#')
        {
            ++p;
            const char *id_end = p;
            while (id_end < sel_end && *id_end != ':' && *id_end != '.' && *id_end != '#' && *id_end != '[' && !isspace((unsigned char)*id_end))
            {
                id_end++;
            }
            size_t id_len = (size_t)(id_end - p);
            const char *id = (id_len > 0) ? html_attr_get(node, "id") : NULL;
            if (!id || strlen(id) != id_len || strncasecmp(id, p, id_len) != 0)
            {
                match = false;
                break;
            }
            p = id_end;
            continue;
        }

        if (*p == ':' || *p == '[' || isspace((unsigned char)*p))
        {
            break;
        }

        ++p;
    }

    return match;
}

static bool html_view_selector_matches(const char *selector, const html_node_t *node)
{
    if (!selector || !node || node->type != HTML_NODE_ELEMENT)
    {
        return false;
    }

    const char *start = selector;
    const char *end = selector + strlen(selector);
    html_view_trim_range(&start, &end);
    if (end <= start)
    {
        return false;
    }

    /* Very small selector subset: tag, .class, #id, tag.class, tag#id, and a single descendant "A B". */
    const char *last_space = NULL;
    for (const char *p = start; p < end; ++p)
    {
        if (isspace((unsigned char)*p))
        {
            last_space = p;
        }
    }

    if (!last_space)
    {
        return html_view_simple_selector_matches_range(start, end, node);
    }

    const char *target_start = last_space;
    while (target_start < end && isspace((unsigned char)*target_start))
    {
        target_start++;
    }
    if (!html_view_simple_selector_matches_range(target_start, end, node))
    {
        return false;
    }

    const char *ancestor_end = last_space;
    html_view_trim_range(&start, &ancestor_end);
    if (ancestor_end <= start)
    {
        return false;
    }

    const char *ancestor_start = ancestor_end;
    while (ancestor_start > start && !isspace((unsigned char)ancestor_start[-1]))
    {
        ancestor_start--;
    }

    for (const html_node_t *p = node->parent; p; p = p->parent)
    {
        if (html_view_simple_selector_matches_range(ancestor_start, ancestor_end, p))
        {
            return true;
        }
    }
    return false;
}

static bool html_view_parse_hex_color(const char *s, video_color_t *out)
{
    if (!s || !out || s[0] == '\0')
    {
        return false;
    }

    while (*s && isspace((unsigned char)*s))
    {
        ++s;
    }
    if (*s != '#')
    {
        return false;
    }
    ++s;

    uint32_t value = 0;
    size_t digits = 0;
    while (*s)
    {
        unsigned char c = (unsigned char)*s;
        if (isspace(c))
        {
            break;
        }
        uint32_t d = 0;
        if (c >= '0' && c <= '9')
        {
            d = (uint32_t)(c - '0');
        }
        else if (c >= 'a' && c <= 'f')
        {
            d = 10u + (uint32_t)(c - 'a');
        }
        else if (c >= 'A' && c <= 'F')
        {
            d = 10u + (uint32_t)(c - 'A');
        }
        else
        {
            break;
        }
        value = (value << 4) | d;
        ++digits;
        ++s;
        if (digits > 6)
        {
            break;
        }
    }

    if (digits == 3)
    {
        uint8_t r = (uint8_t)(((value >> 8) & 0xFu) * 17u);
        uint8_t g = (uint8_t)(((value >> 4) & 0xFu) * 17u);
        uint8_t b = (uint8_t)(((value >> 0) & 0xFu) * 17u);
        *out = video_make_color(r, g, b);
        return true;
    }
    if (digits == 6)
    {
        uint8_t r = (uint8_t)((value >> 16) & 0xFFu);
        uint8_t g = (uint8_t)((value >> 8) & 0xFFu);
        uint8_t b = (uint8_t)((value >> 0) & 0xFFu);
        *out = video_make_color(r, g, b);
        return true;
    }
    return false;
}

static bool html_view_parse_html_length_attr(const char *value, css_length_t *out)
{
    if (!value || !out)
    {
        return false;
    }
    while (*value && isspace((unsigned char)*value))
    {
        ++value;
    }
    if (*value == '\0')
    {
        return false;
    }

    bool percent = false;
    int32_t number = 0;
    bool have_digit = false;
    const char *p = value;
    while (*p && isdigit((unsigned char)*p))
    {
        have_digit = true;
        number = number * 10 + (*p - '0');
        ++p;
        if (number > 1000000)
        {
            break;
        }
    }
    while (*p && isspace((unsigned char)*p))
    {
        ++p;
    }
    if (*p == '%')
    {
        percent = true;
    }

    if (!have_digit)
    {
        return false;
    }

    out->valid = true;
    out->is_auto = false;
    out->value_milli = number * 1000;
    out->unit = percent ? CSS_UNIT_PERCENT : CSS_UNIT_PX;
    return true;
}

static void html_view_apply_presentational_attrs(css_style_t *style, const css_style_t *parent, const html_node_t *node)
{
    (void)parent;
    if (!style || !node || node->type != HTML_NODE_ELEMENT || !node->name)
    {
        return;
    }

    const char *bgcolor = html_attr_get(node, "bgcolor");
    if (bgcolor && bgcolor[0] != '\0' && !style->has_background)
    {
        video_color_t c;
        if (html_view_parse_hex_color(bgcolor, &c))
        {
            style->has_background = true;
            style->background = c;
        }
    }

    const char *w = html_attr_get(node, "width");
    if (w && w[0] != '\0' && !style->has_width)
    {
        css_length_t len = {0};
        if (html_view_parse_html_length_attr(w, &len))
        {
            style->has_width = true;
            style->width = len;
        }
    }

    const char *h = html_attr_get(node, "height");
    if (h && h[0] != '\0' && !style->has_height)
    {
        css_length_t len = {0};
        if (html_view_parse_html_length_attr(h, &len))
        {
            style->has_height = true;
            style->height = len;
        }
    }

    const char *align = html_attr_get(node, "align");
    if (align && align[0] != '\0' && !style->has_text_align)
    {
        if (strcasecmp(align, "center") == 0)
        {
            style->has_text_align = true;
            style->text_align = CSS_TEXT_ALIGN_CENTER;
        }
        else if (strcasecmp(align, "right") == 0)
        {
            style->has_text_align = true;
            style->text_align = CSS_TEXT_ALIGN_RIGHT;
        }
        else if (strcasecmp(align, "left") == 0)
        {
            style->has_text_align = true;
            style->text_align = CSS_TEXT_ALIGN_LEFT;
        }
    }

    if (strcmp(node->name, "table") == 0)
    {
        const char *border = html_attr_get(node, "border");
        if (border && border[0] != '\0' && !style->has_border)
        {
            int b = atoi(border);
            if (b > 0)
            {
                css_length_t px = {
                    .valid = true,
                    .is_auto = false,
                    .value_milli = b * 1000,
                    .unit = CSS_UNIT_PX,
                };
                style->has_border = true;
                style->border_width.top = px;
                style->border_width.right = px;
                style->border_width.bottom = px;
                style->border_width.left = px;
            }
        }

        const char *table_align = html_attr_get(node, "align");
        if (table_align && table_align[0] != '\0' && strcasecmp(table_align, "center") == 0)
        {
            style->has_margin = true;
            style->margin.left.valid = true;
            style->margin.left.is_auto = true;
            style->margin.right.valid = true;
            style->margin.right.is_auto = true;
        }
    }

    if (strcmp(node->name, "center") == 0 && !style->has_text_align)
    {
        style->has_text_align = true;
        style->text_align = CSS_TEXT_ALIGN_CENTER;
    }
}

static void html_view_apply_inline_style(css_style_t *style, const char *inline_style)
{
    if (!style || !inline_style || inline_style[0] == '\0')
    {
        return;
    }
    size_t len = strlen(inline_style);
    char *buf = (char *)malloc(len + 4);
    if (!buf)
    {
        return;
    }
    memcpy(buf, "x{", 2);
    memcpy(buf + 2, inline_style, len);
    buf[2 + len] = '}';
    buf[3 + len] = '\0';

    css_stylesheet_t *sheet = css_parse(buf);
    free(buf);
    if (!sheet)
    {
        return;
    }
    if (sheet->rules)
    {
        css_style_merge(style, &sheet->rules->style);
    }
    css_stylesheet_destroy(sheet);
}

static void html_view_style_for_node(css_style_t *out,
                                     const css_stylesheet_t *sheet,
                                     const css_style_t *parent,
                                     const html_node_t *node)
{
    if (!out)
    {
        return;
    }
    memset(out, 0, sizeof(*out));

    bool is_table_cell = false;
    bool is_table_header = false;
    if (node && node->type == HTML_NODE_ELEMENT && node->name)
    {
        is_table_cell = (strcmp(node->name, "td") == 0 || strcmp(node->name, "th") == 0);
        is_table_header = (strcmp(node->name, "th") == 0);
    }

    if (parent)
    {
        if (parent->has_color)
        {
            out->has_color = true;
            out->color = parent->color;
        }
        if (parent->has_font_size)
        {
            out->has_font_size = true;
            out->font_size = parent->font_size;
        }
        if (parent->has_line_height)
        {
            out->has_line_height = true;
            out->line_height_milli = parent->line_height_milli;
        }
        if (parent->has_text_align && !is_table_cell)
        {
            out->has_text_align = true;
            out->text_align = parent->text_align;
        }
        if (parent->has_letter_spacing)
        {
            out->has_letter_spacing = true;
            out->letter_spacing = parent->letter_spacing;
        }
    }

    if (sheet && node && node->type == HTML_NODE_ELEMENT)
    {
        for (const css_rule_t *rule = sheet->rules; rule; rule = rule->next)
        {
            if (rule->selector && html_view_selector_matches(rule->selector, node))
            {
                css_style_merge(out, &rule->style);
            }
        }
    }

    html_view_apply_presentational_attrs(out, parent, node);

    const char *inline_style = html_attr_get(node, "style");
    if (inline_style && inline_style[0] != '\0')
    {
        html_view_apply_inline_style(out, inline_style);
    }

    if (is_table_header && !out->has_text_align)
    {
        out->has_text_align = true;
        out->text_align = CSS_TEXT_ALIGN_CENTER;
    }
}

static void html_view_style_stack_destroy(html_view_ctx_t *ctx)
{
    if (!ctx)
    {
        return;
    }

    html_view_style_block_t *blk = ctx->style_block;
    while (blk)
    {
        html_view_style_block_t *prev = blk->prev;
        free(blk);
        blk = prev;
    }
    ctx->style_block = NULL;
    ctx->style_depth = 0;
}

static const css_style_t *html_view_style_push(html_view_ctx_t *ctx, const css_style_t *parent, const html_node_t *node)
{
    if (!ctx)
    {
        return NULL;
    }

    if (!ctx->style_block || ctx->style_block->used >= (sizeof(ctx->style_block->styles) / sizeof(ctx->style_block->styles[0])))
    {
        html_view_style_block_t *blk = (html_view_style_block_t *)calloc(1, sizeof(*blk));
        if (!blk)
        {
            return NULL;
        }
        blk->prev = ctx->style_block;
        ctx->style_block = blk;
    }

    css_style_t *slot = &ctx->style_block->styles[ctx->style_block->used++];
    ctx->style_depth++;
    html_view_style_for_node(slot, ctx->sheet, parent, node);
    return slot;
}

static void html_view_style_pop(html_view_ctx_t *ctx)
{
    if (!ctx || ctx->style_depth == 0)
    {
        return;
    }

    ctx->style_depth--;

    html_view_style_block_t *blk = ctx->style_block;
    if (!blk)
    {
        return;
    }
    if (blk->used > 0)
    {
        blk->used--;
    }
    if (blk->used == 0 && blk->prev)
    {
        ctx->style_block = blk->prev;
        free(blk);
    }
}

static int html_view_length_to_px(const css_length_t *len,
                                  int viewport_w,
                                  int viewport_h,
                                  int ref_w,
                                  int ref_h,
                                  int font_px,
                                  bool horizontal)
{
    if (!len || !len->valid || len->is_auto)
    {
        return 0;
    }
    int32_t v = len->value_milli;
    if (v <= 0)
    {
        return 0;
    }

    switch (len->unit)
    {
        case CSS_UNIT_VW:
            return (int)(((int64_t)viewport_w * (int64_t)v + 50000LL) / 100000LL);
        case CSS_UNIT_VH:
            return (int)(((int64_t)viewport_h * (int64_t)v + 50000LL) / 100000LL);
        case CSS_UNIT_PERCENT:
        {
            int ref = horizontal ? ref_w : ref_h;
            return (int)(((int64_t)ref * (int64_t)v + 50000LL) / 100000LL);
        }
        case CSS_UNIT_EM:
            return (int)(((int64_t)font_px * (int64_t)v + 500LL) / 1000LL);
        case CSS_UNIT_PX:
        case CSS_UNIT_NONE:
        default:
            return (int)((v + 500) / 1000);
    }
}

static int html_view_line_height_for_style(const html_view_ctx_t *ctx, const css_style_t *style)
{
    if (!ctx)
    {
        return atk_font_line_height() + 4;
    }

    int actual_font_px = ctx->actual_font_px > 0 ? ctx->actual_font_px : atk_font_line_height();
    int base_font_px = ctx->base_font_px > 0 ? ctx->base_font_px : actual_font_px;
    int line_height = ctx->base_line_height > 0 ? ctx->base_line_height : (base_font_px + 4);

    if (style && style->has_line_height && style->line_height_milli > 0)
    {
        line_height = (int)(((int64_t)base_font_px * (int64_t)style->line_height_milli + 500LL) / 1000LL);
        if (line_height < base_font_px)
        {
            line_height = base_font_px;
        }
    }

    if (line_height < actual_font_px)
    {
        line_height = actual_font_px;
    }

    if (line_height < 8)
    {
        line_height = 8;
    }
    return line_height;
}

typedef struct
{
    int actual_font_px;
    int base_font_px;
    int line_height;
    int space_w;
} html_view_font_scope_t;

static int html_view_font_px_for_style(const html_view_ctx_t *ctx, const css_style_t *style, int parent_font_px)
{
    if (!ctx || !style || !style->has_font_size || !style->font_size.valid || style->font_size.is_auto)
    {
        return parent_font_px;
    }

    if (style->font_size.unit == CSS_UNIT_PERCENT)
    {
        int64_t scaled = (int64_t)parent_font_px * (int64_t)style->font_size.value_milli;
        int px = (int)((scaled + 50000LL) / 100000LL);
        return px > 0 ? px : parent_font_px;
    }

    int px = html_view_length_to_px(&style->font_size,
                                    ctx->viewport_w,
                                    ctx->viewport_h,
                                    ctx->viewport_w,
                                    ctx->viewport_h,
                                    parent_font_px,
                                    true);
    return px > 0 ? px : parent_font_px;
}

static void html_view_font_scope_push(html_view_ctx_t *ctx, const css_style_t *style, bool block, html_view_font_scope_t *saved)
{
    if (!ctx || !saved)
    {
        return;
    }

    saved->actual_font_px = ctx->actual_font_px;
    saved->base_font_px = ctx->base_font_px;
    saved->line_height = ctx->line_height;
    saved->space_w = ctx->space_w;

    int parent_font_px = ctx->base_font_px > 0 ? ctx->base_font_px : ctx->actual_font_px;
    if (parent_font_px <= 0)
    {
        parent_font_px = atk_font_line_height();
    }

    int font_px = html_view_font_px_for_style(ctx, style, parent_font_px);
    if (font_px <= 0)
    {
        font_px = parent_font_px;
    }

    ctx->base_font_px = font_px;
    ctx->actual_font_px = font_px;
    ctx->space_w = html_view_text_width(ctx, " ");

    int candidate_line_height = html_view_line_height_for_style(ctx, style);
    if (block)
    {
        ctx->line_height = candidate_line_height;
    }
    else if (candidate_line_height > ctx->line_height)
    {
        ctx->line_height = candidate_line_height;
    }
}

static void html_view_font_scope_pop(html_view_ctx_t *ctx, const html_view_font_scope_t *saved)
{
    if (!ctx || !saved)
    {
        return;
    }

    ctx->actual_font_px = saved->actual_font_px;
    ctx->base_font_px = saved->base_font_px;
    ctx->line_height = saved->line_height;
    ctx->space_w = saved->space_w;
}

static void html_view_draw_rect_clipped(html_view_ctx_t *ctx,
                                        int x,
                                        int y,
                                        int w,
                                        int h,
                                        video_color_t color,
                                        const atk_rect_t *clip)
{
    if (!ctx || w <= 0 || h <= 0)
    {
        return;
    }

    if (ctx->record)
    {
        if (!ctx->record_failed && ctx->priv)
        {
            html_view_render_cache_t *cache = &ctx->priv->render_cache;
            html_view_op_t op = {0};
            op.kind = HTML_VIEW_OP_RECT;
            op.x = x - ctx->doc_origin_x;
            op.y = (y + ctx->priv->scroll_y) - ctx->doc_origin_y;
            op.w = w;
            op.h = h;
            op.color = color;
            if (!html_view_render_cache_push_op(cache, &op, cache->tile_h))
            {
                ctx->record_failed = true;
            }
        }
        return;
    }
    if (!ctx->draw)
    {
        return;
    }

    int x0 = x;
    int y0 = y;
    int x1 = x + w;
    int y1 = y + h;

    if (clip)
    {
        int cx0 = clip->x;
        int cy0 = clip->y;
        int cx1 = clip->x + clip->width;
        int cy1 = clip->y + clip->height;
        if (x0 < cx0) x0 = cx0;
        if (y0 < cy0) y0 = cy0;
        if (x1 > cx1) x1 = cx1;
        if (y1 > cy1) y1 = cy1;
    }

    if (x1 <= x0 || y1 <= y0)
    {
        return;
    }
    video_draw_rect(x0, y0, x1 - x0, y1 - y0, color);
}

static void html_view_draw_border_clipped(html_view_ctx_t *ctx,
                                         int x,
                                         int y,
                                         int w,
                                         int h,
                                         int thickness,
                                         video_color_t color,
                                         const atk_rect_t *clip)
{
    if (w <= 0 || h <= 0 || thickness <= 0)
    {
        return;
    }

    if (thickness * 2 > w)
    {
        thickness = w / 2;
    }
    if (thickness * 2 > h)
    {
        thickness = h / 2;
    }
    if (thickness <= 0)
    {
        return;
    }

    html_view_draw_rect_clipped(ctx, x, y, w, thickness, color, clip);                    /* top */
    html_view_draw_rect_clipped(ctx, x, y + h - thickness, w, thickness, color, clip);   /* bottom */
    html_view_draw_rect_clipped(ctx, x, y + thickness, thickness, h - thickness * 2, color, clip); /* left */
    html_view_draw_rect_clipped(ctx, x + w - thickness, y + thickness, thickness, h - thickness * 2, color, clip); /* right */
}

static void html_view_blit_rgba32_clipped(html_view_ctx_t *ctx,
                                         int dst_x,
                                         int dst_y,
                                         int width,
                                         int height,
                                         const video_color_t *pixels,
                                         int stride_bytes,
                                         const atk_rect_t *clip)
{
    if (!ctx || !pixels || width <= 0 || height <= 0 || stride_bytes <= 0)
    {
        return;
    }

    if (ctx->record)
    {
        if (!ctx->record_failed && ctx->priv)
        {
            html_view_render_cache_t *cache = &ctx->priv->render_cache;
            html_view_op_t op = {0};
            op.kind = HTML_VIEW_OP_IMAGE;
            op.x = dst_x - ctx->doc_origin_x;
            op.y = (dst_y + ctx->priv->scroll_y) - ctx->doc_origin_y;
            op.w = width;
            op.h = height;
            op.pixels = pixels;
            op.stride_bytes = stride_bytes;
            if (!html_view_render_cache_push_op(cache, &op, cache->tile_h))
            {
                ctx->record_failed = true;
            }
        }
        return;
    }
    if (!ctx->draw)
    {
        return;
    }

    int x0 = dst_x;
    int y0 = dst_y;
    int x1 = dst_x + width;
    int y1 = dst_y + height;

    int clip_x0 = clip ? clip->x : 0;
    int clip_y0 = clip ? clip->y : 0;
    int clip_x1 = clip ? (clip->x + clip->width) : video_screen_width();
    int clip_y1 = clip ? (clip->y + clip->height) : video_screen_height();

    if (x0 < clip_x0) x0 = clip_x0;
    if (y0 < clip_y0) y0 = clip_y0;
    if (x1 > clip_x1) x1 = clip_x1;
    if (y1 > clip_y1) y1 = clip_y1;

    int draw_w = x1 - x0;
    int draw_h = y1 - y0;
    if (draw_w <= 0 || draw_h <= 0)
    {
        return;
    }

    int offset_x = x0 - dst_x;
    int offset_y = y0 - dst_y;
    int stride_px = stride_bytes / (int)sizeof(video_color_t);
    const video_color_t *src = pixels + offset_y * stride_px + offset_x;

    video_blit_rgba32_untracked(x0, y0, draw_w, draw_h, src, stride_bytes, true);
}

static void html_view_new_line(html_view_ctx_t *ctx)
{
    if (!ctx)
    {
        return;
    }
    ctx->x = ctx->body_x;
    ctx->y += ctx->line_height;
    ctx->pending_space = false;
    int bottom = ctx->y + ctx->line_height;
    if (bottom > ctx->content_bottom)
    {
        ctx->content_bottom = bottom;
    }
}

static void html_view_ensure_line_visible(html_view_ctx_t *ctx)
{
    if (!ctx)
    {
        return;
    }
    int bottom = ctx->y + ctx->line_height;
    if (bottom > ctx->content_bottom)
    {
        ctx->content_bottom = bottom;
    }
}

static bool html_view_line_visible(const html_view_ctx_t *ctx)
{
    if (!ctx)
    {
        return false;
    }
    int draw_top = ctx->y - ctx->priv->scroll_y;
    int draw_bottom = draw_top + ctx->line_height;
    int clip_y0 = ctx->clip.y;
    int clip_y1 = ctx->clip.y + ctx->clip.height;
    return !(draw_bottom <= clip_y0 || draw_top >= clip_y1);
}

static void html_view_float_bounds_at_y(const html_view_float_ctx_t *floats,
                                       int y,
                                       int container_x,
                                       int container_w,
                                       int *out_left,
                                       int *out_right)
{
    if (!out_left || !out_right)
    {
        return;
    }
    int left = container_x;
    int right = container_x + container_w;
    if (floats)
    {
        for (size_t i = 0; i < floats->count; ++i)
        {
            const html_view_float_t *f = &floats->items[i];
            if (!f)
            {
                continue;
            }
            if (y < f->y || y >= f->y + f->h)
            {
                continue;
            }
            if (f->side == CSS_FLOAT_LEFT)
            {
                int edge = f->x + f->w;
                if (edge > left)
                {
                    left = edge;
                }
            }
            else if (f->side == CSS_FLOAT_RIGHT)
            {
                int edge = f->x;
                if (edge < right)
                {
                    right = edge;
                }
            }
        }
    }
    *out_left = left;
    *out_right = right;
}

static int html_view_float_next_y(const html_view_float_ctx_t *floats, int y)
{
    if (!floats)
    {
        return y + 1;
    }
    int next = -1;
    for (size_t i = 0; i < floats->count; ++i)
    {
        const html_view_float_t *f = &floats->items[i];
        if (!f)
        {
            continue;
        }
        if (y < f->y || y >= f->y + f->h)
        {
            continue;
        }
        int bottom = f->y + f->h;
        if (bottom > y && (next < 0 || bottom < next))
        {
            next = bottom;
        }
    }
    return (next > y) ? next : (y + 1);
}

static int html_view_float_max_bottom(const html_view_float_ctx_t *floats, css_clear_t clear_mode)
{
    if (!floats || clear_mode == CSS_CLEAR_NONE)
    {
        return 0;
    }
    int max_bottom = 0;
    for (size_t i = 0; i < floats->count; ++i)
    {
        const html_view_float_t *f = &floats->items[i];
        if (!f)
        {
            continue;
        }
        if (clear_mode == CSS_CLEAR_LEFT && f->side != CSS_FLOAT_LEFT)
        {
            continue;
        }
        if (clear_mode == CSS_CLEAR_RIGHT && f->side != CSS_FLOAT_RIGHT)
        {
            continue;
        }
        int bottom = f->y + f->h;
        if (bottom > max_bottom)
        {
            max_bottom = bottom;
        }
    }
    return max_bottom;
}

static void html_view_draw_border_sides_clipped(html_view_ctx_t *ctx,
                                                int x,
                                                int y,
                                                int w,
                                                int h,
                                                int top,
                                                int right,
                                                int bottom,
                                                int left,
                                                video_color_t color,
                                                const atk_rect_t *clip)
{
    if (w <= 0 || h <= 0)
    {
        return;
    }

    if (top > 0)
    {
        html_view_draw_rect_clipped(ctx, x, y, w, top, color, clip);
    }
    if (bottom > 0)
    {
        html_view_draw_rect_clipped(ctx, x, y + h - bottom, w, bottom, color, clip);
    }

    int inner_y = y + top;
    int inner_h = h - top - bottom;
    if (inner_h <= 0)
    {
        return;
    }
    if (left > 0)
    {
        html_view_draw_rect_clipped(ctx, x, inner_y, left, inner_h, color, clip);
    }
    if (right > 0)
    {
        html_view_draw_rect_clipped(ctx, x + w - right, inner_y, right, inner_h, color, clip);
    }
}

static void html_view_draw_word(html_view_ctx_t *ctx,
                                const char *word,
                                size_t len,
                                video_color_t color,
                                bool underline,
                                bool bold)
{
    if (!ctx || !word || len == 0)
    {
        return;
    }

    char scratch[128];
    const char *text = NULL;
    char *heap = NULL;
    if (len < sizeof(scratch))
    {
        memcpy(scratch, word, len);
        scratch[len] = '\0';
        text = scratch;
    }
    else
    {
        heap = (char *)malloc(len + 1);
        if (!heap)
        {
            return;
        }
        memcpy(heap, word, len);
        heap[len] = '\0';
        text = heap;
    }

    int w = html_view_text_width(ctx, text);

    if (ctx->pending_space && ctx->x != ctx->body_x)
    {
        if (ctx->x + ctx->space_w + w > ctx->max_x)
        {
            html_view_new_line(ctx);
        }
        else
        {
            ctx->x += ctx->space_w;
        }
    }
    else if (ctx->x != ctx->body_x && ctx->x + w > ctx->max_x)
    {
        html_view_new_line(ctx);
    }

    int draw_x = ctx->x;
    int draw_top = ctx->y - ctx->priv->scroll_y;
    int baseline = html_view_baseline_for_rect(ctx, draw_top, ctx->line_height);

    if (ctx->record)
    {
        if (!ctx->record_failed && ctx->priv)
        {
            html_view_render_cache_t *cache = &ctx->priv->render_cache;
            html_view_op_t op = {0};
            op.kind = HTML_VIEW_OP_TEXT;
            op.x = draw_x - ctx->doc_origin_x;
            op.y = (draw_top + ctx->priv->scroll_y) - ctx->doc_origin_y;
            op.h = ctx->line_height;
            op.baseline_off = (int16_t)(baseline - draw_top);
            op.font_px = (int16_t)ctx->actual_font_px;
            op.color = color;
            op.text = word;
            op.text_len = (uint32_t)len;
            op.text_owned = false;
            if (!html_view_render_cache_push_op(cache, &op, cache->tile_h))
            {
                ctx->record_failed = true;
            }
            if (bold && !ctx->record_failed)
            {
                html_view_op_t bold_op = op;
                bold_op.x += 1;
                (void)html_view_render_cache_push_op(cache, &bold_op, cache->tile_h);
            }
        }
        if (underline)
        {
            int underline_y = draw_top + ctx->line_height - 3;
            html_view_draw_rect_clipped(ctx, draw_x, underline_y, w, 1, color, &ctx->clip);
        }
    }
    else if (ctx->draw && html_view_line_visible(ctx))
    {
        html_view_draw_string_clipped(ctx, draw_x, baseline, text, color, &ctx->clip);
        if (bold)
        {
            html_view_draw_string_clipped(ctx, draw_x + 1, baseline, text, color, &ctx->clip);
        }
        if (underline)
        {
            int underline_y = draw_top + ctx->line_height - 3;
            int clip_y0 = ctx->clip.y;
            int clip_y1 = ctx->clip.y + ctx->clip.height;
            if (underline_y >= clip_y0 && underline_y < clip_y1)
            {
                html_view_draw_rect_clipped(ctx, draw_x, underline_y, w, 1, color, &ctx->clip);
            }
        }
    }

    ctx->x += w;
    ctx->pending_space = true;
    html_view_ensure_line_visible(ctx);

    free(heap);
}

static void html_view_draw_text(html_view_ctx_t *ctx,
                                const char *text,
                                video_color_t color,
                                bool underline,
                                bool bold)
{
    if (!ctx || !text)
    {
        return;
    }

    const char *p = text;
    while (*p)
    {
        while (*p && isspace((unsigned char)*p))
        {
            ctx->pending_space = true;
            p++;
        }
        if (!*p)
        {
            break;
        }

        const char *wstart = p;
        while (*p && !isspace((unsigned char)*p))
        {
            p++;
        }
        size_t wlen = (size_t)(p - wstart);
        html_view_draw_word(ctx, wstart, wlen, color, underline, bold);
    }
}

static void html_view_place_control_widget(html_view_ctx_t *ctx,
                                           atk_widget_t *child,
                                           int abs_x,
                                           int abs_y,
                                           int width,
                                           int height)
{
    if (!ctx || !child || width <= 0 || height <= 0)
    {
        return;
    }

    child->x = abs_x - ctx->window_x;
    child->y = abs_y - ctx->window_y;
    child->width = width;
    child->height = height;

    int vx0 = ctx->viewport_x;
    int vy0 = ctx->viewport_y;
    int vx1 = vx0 + ctx->viewport_w;
    int vy1 = vy0 + ctx->viewport_h;
    int wx1 = abs_x + width;
    int wy1 = abs_y + height;

    bool visible = abs_x >= vx0 && abs_y >= vy0 && wx1 <= vx1 && wy1 <= vy1;
    child->used = visible;
}

static void html_view_place_inline_control(html_view_ctx_t *ctx,
                                           atk_widget_t *child,
                                           int width,
                                           int height)
{
    if (!ctx || width <= 0 || height <= 0)
    {
        return;
    }

    int max_width = ctx->max_x - ctx->body_x;
    if (max_width < 0)
    {
        max_width = 0;
    }
    if (width > max_width)
    {
        width = max_width;
    }

    if (ctx->pending_space && ctx->x != ctx->body_x)
    {
        if (ctx->x + ctx->space_w + width > ctx->max_x)
        {
            html_view_new_line(ctx);
        }
        else
        {
            ctx->x += ctx->space_w;
        }
    }
    else if (ctx->x != ctx->body_x && ctx->x + width > ctx->max_x)
    {
        html_view_new_line(ctx);
    }

    int abs_x = ctx->x;
    int abs_y = ctx->y - ctx->priv->scroll_y;
    if (child)
    {
        if (ctx->record)
        {
            if (!ctx->record_failed && ctx->priv)
            {
                html_view_render_cache_t *cache = &ctx->priv->render_cache;
                html_view_op_t op = {0};
                op.kind = HTML_VIEW_OP_CONTROL;
                op.x = abs_x - ctx->doc_origin_x;
                op.y = (abs_y + ctx->priv->scroll_y) - ctx->doc_origin_y;
                op.w = width;
                op.h = height;
                op.widget = child;
                if (!html_view_render_cache_push_op(cache, &op, cache->tile_h))
                {
                    ctx->record_failed = true;
                }
            }
        }
        else if (ctx->draw)
        {
            html_view_place_control_widget(ctx, child, abs_x, abs_y, width, height);
        }
    }

    ctx->x += width;
    ctx->pending_space = true;
    html_view_ensure_line_visible(ctx);
}

static void html_view_place_block_control(html_view_ctx_t *ctx,
                                          atk_widget_t *child,
                                          int width,
                                          int height)
{
    if (!ctx || width <= 0 || height <= 0)
    {
        return;
    }

    if (ctx->x != ctx->body_x)
    {
        html_view_new_line(ctx);
    }

    int max_width = ctx->max_x - ctx->body_x;
    if (max_width < 0)
    {
        max_width = 0;
    }
    if (width > max_width)
    {
        width = max_width;
    }

    int abs_x = ctx->body_x;
    int abs_y = ctx->y - ctx->priv->scroll_y;
    if (child)
    {
        if (ctx->record)
        {
            if (!ctx->record_failed && ctx->priv)
            {
                html_view_render_cache_t *cache = &ctx->priv->render_cache;
                html_view_op_t op = {0};
                op.kind = HTML_VIEW_OP_CONTROL;
                op.x = abs_x - ctx->doc_origin_x;
                op.y = (abs_y + ctx->priv->scroll_y) - ctx->doc_origin_y;
                op.w = width;
                op.h = height;
                op.widget = child;
                if (!html_view_render_cache_push_op(cache, &op, cache->tile_h))
                {
                    ctx->record_failed = true;
                }
            }
        }
        else if (ctx->draw)
        {
            html_view_place_control_widget(ctx, child, abs_x, abs_y, width, height);
        }
    }

    ctx->y += height;
    ctx->x = ctx->body_x;
    ctx->pending_space = false;
    html_view_ensure_line_visible(ctx);
}

static bool html_view_is_block_tag(const char *tag)
{
    if (!tag)
    {
        return false;
    }
    return strcmp(tag, "html") == 0 ||
           strcmp(tag, "body") == 0 ||
           strcmp(tag, "div") == 0 ||
           strcmp(tag, "center") == 0 ||
           strcmp(tag, "form") == 0 ||
           strcmp(tag, "p") == 0 ||
           strcmp(tag, "h1") == 0 ||
           strcmp(tag, "h2") == 0 ||
           strcmp(tag, "h3") == 0 ||
           strcmp(tag, "h4") == 0 ||
           strcmp(tag, "h5") == 0 ||
           strcmp(tag, "h6") == 0 ||
           strcmp(tag, "ul") == 0 ||
           strcmp(tag, "dl") == 0 ||
           strcmp(tag, "dt") == 0 ||
           strcmp(tag, "dd") == 0 ||
           strcmp(tag, "blockquote") == 0 ||
           strcmp(tag, "address") == 0 ||
           strcmp(tag, "li") == 0 ||
           strcmp(tag, "fieldset") == 0 ||
           strcmp(tag, "legend") == 0 ||
           strcmp(tag, "table") == 0 ||
           strcmp(tag, "tbody") == 0 ||
           strcmp(tag, "thead") == 0 ||
           strcmp(tag, "tfoot") == 0 ||
           strcmp(tag, "tr") == 0 ||
           strcmp(tag, "td") == 0 ||
           strcmp(tag, "th") == 0 ||
           strcmp(tag, "img") == 0;
}

static bool html_view_is_form_control_tag(const char *tag)
{
    if (!tag)
    {
        return false;
    }
    return strcmp(tag, "input") == 0 ||
           strcmp(tag, "textarea") == 0 ||
           strcmp(tag, "button") == 0;
}

typedef struct
{
    const html_node_t *node;
    css_style_t style;
    int colspan;
    int x;
    int y;
    int w;
    int h;
    int content_x;
    int content_y;
    int content_w;
    int pad_top;
    int pad_right;
    int pad_bottom;
    int pad_left;
    int border_top;
    int border_right;
    int border_bottom;
    int border_left;
} html_view_table_cell_layout_t;

typedef struct
{
    const html_node_t *node;
    css_style_t style;
    html_view_table_cell_layout_t *cells;
    size_t cell_count;
    size_t cell_cap;
    int y;
    int h;
    int min_h;
} html_view_table_row_layout_t;

typedef struct
{
    html_view_table_row_layout_t *rows;
    size_t row_count;
    size_t row_cap;
    int col_count;
    int *col_w;
    int cellpadding;
    int cellspacing;
    int table_x;
    int table_y;
    int content_w;
    int pad_top;
    int pad_right;
    int pad_bottom;
    int pad_left;
    int border_top;
    int border_right;
    int border_bottom;
    int border_left;
    int margin_top;
    int margin_right;
    int margin_bottom;
    int margin_left;
    int table_h;
} html_view_table_layout_t;

static void html_view_table_layout_destroy(html_view_table_layout_t *layout)
{
    if (!layout)
    {
        return;
    }
    for (size_t i = 0; i < layout->row_count; ++i)
    {
        free(layout->rows[i].cells);
        layout->rows[i].cells = NULL;
        layout->rows[i].cell_count = 0;
        layout->rows[i].cell_cap = 0;
    }
    free(layout->rows);
    layout->rows = NULL;
    layout->row_count = 0;
    layout->row_cap = 0;
    free(layout->col_w);
    layout->col_w = NULL;
    layout->col_count = 0;
}

static int html_view_attr_to_int(const html_node_t *node, const char *name, int fallback)
{
    const char *v = html_attr_get(node, name);
    if (!v || v[0] == '\0')
    {
        return fallback;
    }
    int n = atoi(v);
    return n >= 0 ? n : fallback;
}

static int html_view_measure_text_width(html_view_ctx_t *ctx, const html_node_t *node)
{
    if (!ctx || !node)
    {
        return 0;
    }
    char *buf = NULL;
    size_t len = 0;
    size_t cap = 0;
    html_view_collect_text(node, &buf, &len, &cap);
    int w = buf ? html_view_text_width(ctx, buf) : 0;
    free(buf);
    return w;
}

static bool html_view_table_row_add_cell(html_view_table_row_layout_t *row, const html_view_table_cell_layout_t *cell)
{
    if (!row || !cell)
    {
        return false;
    }
    if (row->cell_count == row->cell_cap)
    {
        size_t new_cap = row->cell_cap ? (row->cell_cap * 2) : 8;
        html_view_table_cell_layout_t *new_cells = (html_view_table_cell_layout_t *)realloc(row->cells, new_cap * sizeof(*new_cells));
        if (!new_cells)
        {
            return false;
        }
        row->cells = new_cells;
        row->cell_cap = new_cap;
    }
    row->cells[row->cell_count++] = *cell;
    return true;
}

static bool html_view_table_layout_add_row(html_view_table_layout_t *layout, const html_node_t *tr, const css_style_t *parent_style, html_view_ctx_t *ctx)
{
    if (!layout || !tr || !parent_style || !ctx)
    {
        return false;
    }
    if (layout->row_count == layout->row_cap)
    {
        size_t new_cap = layout->row_cap ? (layout->row_cap * 2) : 8;
        html_view_table_row_layout_t *new_rows = (html_view_table_row_layout_t *)realloc(layout->rows, new_cap * sizeof(*new_rows));
        if (!new_rows)
        {
            return false;
        }
        layout->rows = new_rows;
        layout->row_cap = new_cap;
    }

    html_view_table_row_layout_t *row = &layout->rows[layout->row_count++];
    memset(row, 0, sizeof(*row));
    row->node = tr;
    html_view_style_for_node(&row->style, ctx->sheet, parent_style, tr);

    if (row->style.has_height && row->style.height.valid && !row->style.height.is_auto)
    {
        row->min_h = html_view_length_to_px(&row->style.height,
                                            ctx->viewport_w,
                                            ctx->viewport_h,
                                            layout->content_w,
                                            ctx->viewport_h,
                                            ctx->base_font_px,
                                            false);
        if (row->min_h < 0)
        {
            row->min_h = 0;
        }
    }

    for (const html_node_t *child = tr->first_child; child; child = child->next_sibling)
    {
        if (child->type != HTML_NODE_ELEMENT || !child->name)
        {
            continue;
        }
        if (strcmp(child->name, "td") != 0 && strcmp(child->name, "th") != 0)
        {
            continue;
        }

        html_view_table_cell_layout_t cell = {0};
        cell.node = child;
        html_view_style_for_node(&cell.style, ctx->sheet, &row->style, child);
        cell.colspan = html_view_attr_to_int(child, "colspan", 1);
        if (cell.colspan < 1)
        {
            cell.colspan = 1;
        }
        if (!html_view_table_row_add_cell(row, &cell))
        {
            return false;
        }
    }

    return true;
}

static bool html_view_subtree_has_form_control(const html_node_t *root)
{
    if (!root)
    {
        return false;
    }

    const html_node_t *stack[64];
    size_t sp = 0;
    stack[sp++] = root;

    while (sp > 0)
    {
        const html_node_t *node = stack[--sp];
        if (node->type == HTML_NODE_ELEMENT && node->name && html_view_is_form_control_tag(node->name))
        {
            return true;
        }
        for (const html_node_t *child = node->first_child; child; child = child->next_sibling)
        {
            if (sp < (sizeof(stack) / sizeof(stack[0])))
            {
                stack[sp++] = child;
            }
        }
    }

    return false;
}

static void html_view_render_children(html_view_ctx_t *ctx, const html_node_t *node, const css_style_t *style);

static void html_view_render_table(html_view_ctx_t *ctx,
                                   const html_node_t *node,
                                   const css_style_t *style,
                                   const css_style_t *parent_style);

static void html_view_render_float_box(html_view_ctx_t *ctx,
                                       const html_node_t *node,
                                       const css_style_t *style,
                                       css_float_t side)
{
    if (!ctx || !node || !style || side == CSS_FLOAT_NONE)
    {
        return;
    }

    if (ctx->x != ctx->body_x)
    {
        html_view_new_line(ctx);
    }

    int saved_line_height = ctx->line_height;
    ctx->line_height = html_view_line_height_for_style(ctx, style);

    int margin_top = 0;
    int margin_right = 0;
    int margin_bottom = 0;
    int margin_left = 0;
    if (style->has_margin)
    {
        if (style->margin.top.valid && !style->margin.top.is_auto)
        {
            margin_top = html_view_length_to_px(&style->margin.top,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                ctx->body_w,
                                                ctx->viewport_h,
                                                ctx->base_font_px,
                                                false);
        }
        if (style->margin.right.valid && !style->margin.right.is_auto)
        {
            margin_right = html_view_length_to_px(&style->margin.right,
                                                  ctx->viewport_w,
                                                  ctx->viewport_h,
                                                  ctx->body_w,
                                                  ctx->viewport_h,
                                                  ctx->base_font_px,
                                                  true);
        }
        if (style->margin.bottom.valid && !style->margin.bottom.is_auto)
        {
            margin_bottom = html_view_length_to_px(&style->margin.bottom,
                                                   ctx->viewport_w,
                                                   ctx->viewport_h,
                                                   ctx->body_w,
                                                   ctx->viewport_h,
                                                   ctx->base_font_px,
                                                   false);
        }
        if (style->margin.left.valid && !style->margin.left.is_auto)
        {
            margin_left = html_view_length_to_px(&style->margin.left,
                                                 ctx->viewport_w,
                                                 ctx->viewport_h,
                                                 ctx->body_w,
                                                 ctx->viewport_h,
                                                 ctx->base_font_px,
                                                 true);
        }
    }

    int pad_top = 0;
    int pad_right = 0;
    int pad_bottom = 0;
    int pad_left = 0;
    if (style->has_padding)
    {
        pad_top = html_view_length_to_px(&style->padding.top,
                                         ctx->viewport_w,
                                         ctx->viewport_h,
                                         ctx->body_w,
                                         ctx->viewport_h,
                                         ctx->base_font_px,
                                         false);
        pad_right = html_view_length_to_px(&style->padding.right,
                                           ctx->viewport_w,
                                           ctx->viewport_h,
                                           ctx->body_w,
                                           ctx->viewport_h,
                                           ctx->base_font_px,
                                           true);
        pad_bottom = html_view_length_to_px(&style->padding.bottom,
                                            ctx->viewport_w,
                                            ctx->viewport_h,
                                            ctx->body_w,
                                            ctx->viewport_h,
                                            ctx->base_font_px,
                                            false);
        pad_left = html_view_length_to_px(&style->padding.left,
                                          ctx->viewport_w,
                                          ctx->viewport_h,
                                          ctx->body_w,
                                          ctx->viewport_h,
                                          ctx->base_font_px,
                                          true);
    }

    int border_top = 0;
    int border_right = 0;
    int border_bottom = 0;
    int border_left = 0;
    if (style->has_border)
    {
        border_top = html_view_length_to_px(&style->border_width.top,
                                            ctx->viewport_w,
                                            ctx->viewport_h,
                                            ctx->body_w,
                                            ctx->viewport_h,
                                            ctx->base_font_px,
                                            false);
        border_right = html_view_length_to_px(&style->border_width.right,
                                              ctx->viewport_w,
                                              ctx->viewport_h,
                                              ctx->body_w,
                                              ctx->viewport_h,
                                              ctx->base_font_px,
                                              true);
        border_bottom = html_view_length_to_px(&style->border_width.bottom,
                                               ctx->viewport_w,
                                               ctx->viewport_h,
                                               ctx->body_w,
                                               ctx->viewport_h,
                                               ctx->base_font_px,
                                               false);
        border_left = html_view_length_to_px(&style->border_width.left,
                                             ctx->viewport_w,
                                             ctx->viewport_h,
                                             ctx->body_w,
                                             ctx->viewport_h,
                                             ctx->base_font_px,
                                             true);
    }

    if (margin_top < 0) margin_top = 0;
    if (margin_right < 0) margin_right = 0;
    if (margin_bottom < 0) margin_bottom = 0;
    if (margin_left < 0) margin_left = 0;
    if (pad_top < 0) pad_top = 0;
    if (pad_right < 0) pad_right = 0;
    if (pad_bottom < 0) pad_bottom = 0;
    if (pad_left < 0) pad_left = 0;
    if (border_top < 0) border_top = 0;
    if (border_right < 0) border_right = 0;
    if (border_bottom < 0) border_bottom = 0;
    if (border_left < 0) border_left = 0;

    int content_w = 0;
    if (style->has_width && style->width.valid && !style->width.is_auto)
    {
        content_w = html_view_length_to_px(&style->width,
                                           ctx->viewport_w,
                                           ctx->viewport_h,
                                           ctx->body_w,
                                           ctx->viewport_h,
                                           ctx->base_font_px,
                                           true);
    }
    else
    {
        content_w = ctx->body_w;
    }
    if (content_w < 0)
    {
        content_w = 0;
    }

    int content_h = 0;
    if (style->has_height && style->height.valid && !style->height.is_auto)
    {
        content_h = html_view_length_to_px(&style->height,
                                           ctx->viewport_w,
                                           ctx->viewport_h,
                                           ctx->viewport_w,
                                           ctx->viewport_h,
                                           ctx->base_font_px,
                                           false);
    }
    else
    {
        content_h = ctx->line_height;
    }
    if (content_h < 0)
    {
        content_h = 0;
    }

    int border_box_w = content_w + pad_left + pad_right + border_left + border_right;
    int border_box_h = content_h + pad_top + pad_bottom + border_top + border_bottom;
    int outer_w = border_box_w + margin_left + margin_right;
    int outer_h = border_box_h + margin_top + margin_bottom;

    int place_y = ctx->y;
    int place_x = ctx->body_x;
    int container_w = ctx->body_w;
    if (container_w < 0) container_w = 0;

    for (int it = 0; it < 256; ++it)
    {
        int left = ctx->body_x;
        int right = ctx->body_x + container_w;
        html_view_float_bounds_at_y(ctx->floats, place_y, ctx->body_x, container_w, &left, &right);
        int avail = right - left;
        if (outer_w <= avail)
        {
            if (side == CSS_FLOAT_RIGHT)
            {
                place_x = right - outer_w;
            }
            else
            {
                place_x = left;
            }
            break;
        }
        place_y = html_view_float_next_y(ctx->floats, place_y);
    }

    if (ctx->floats && ctx->floats->count < (sizeof(ctx->floats->items) / sizeof(ctx->floats->items[0])))
    {
        ctx->floats->items[ctx->floats->count++] = (html_view_float_t){
            .x = place_x,
            .y = place_y,
            .w = outer_w,
            .h = outer_h,
            .side = side,
        };
    }

    int outer_bottom = place_y + outer_h;
    if (outer_bottom > ctx->content_bottom)
    {
        ctx->content_bottom = outer_bottom;
    }

    int border_box_x = place_x + margin_left;
    int border_box_y = place_y + margin_top;
    int draw_y = border_box_y - ctx->priv->scroll_y;

    if (ctx->draw)
    {
        if (style->has_background)
        {
            html_view_draw_rect_clipped(ctx, border_box_x, draw_y, border_box_w, border_box_h, style->background, &ctx->clip);
        }

        if (style->has_border && (border_top > 0 || border_right > 0 || border_bottom > 0 || border_left > 0))
        {
            video_color_t border_color = style->has_border_color ? style->border_color : video_make_color(0x00, 0x00, 0x00);
            html_view_draw_border_sides_clipped(ctx,
                                                border_box_x,
                                                draw_y,
                                                border_box_w,
                                                border_box_h,
                                                border_top,
                                                border_right,
                                                border_bottom,
                                                border_left,
                                                border_color,
                                                &ctx->clip);
        }
    }

    int saved_body_x = ctx->body_x;
    int saved_body_w = ctx->body_w;
    int saved_max_x = ctx->max_x;
    int saved_x = ctx->x;
    int saved_y = ctx->y;
    bool saved_pending = ctx->pending_space;
    video_color_t saved_bg = ctx->bg;
    html_view_float_ctx_t *saved_floats = ctx->floats;

    html_view_float_ctx_t *inner_floats = (html_view_float_ctx_t *)calloc(1, sizeof(*inner_floats));
    ctx->floats = inner_floats ? inner_floats : saved_floats;

    ctx->body_x = border_box_x + border_left + pad_left;
    ctx->body_w = content_w;
    ctx->max_x = ctx->body_x + content_w;
    ctx->x = ctx->body_x;
    ctx->y = border_box_y + border_top + pad_top;
    ctx->pending_space = false;
    if (style->has_background)
    {
        ctx->bg = style->background;
    }

    html_view_render_children(ctx, node, style);

    ctx->floats = saved_floats;
    free(inner_floats);
    ctx->bg = saved_bg;
    ctx->body_x = saved_body_x;
    ctx->body_w = saved_body_w;
    ctx->max_x = saved_max_x;
    ctx->x = saved_x;
    ctx->y = saved_y;
    ctx->pending_space = saved_pending;
    ctx->line_height = saved_line_height;
}

static void html_view_render_table(html_view_ctx_t *ctx,
                                   const html_node_t *node,
                                   const css_style_t *style,
                                   const css_style_t *parent_style)
{
    if (!ctx || !node || !style)
    {
        return;
    }

    if (ctx->x != ctx->body_x)
    {
        html_view_new_line(ctx);
    }

    html_view_table_layout_t layout = {0};
    layout.cellpadding = html_view_attr_to_int(node, "cellpadding", 0);
    layout.cellspacing = html_view_attr_to_int(node, "cellspacing", 0);
    if (layout.cellpadding < 0) layout.cellpadding = 0;
    if (layout.cellspacing < 0) layout.cellspacing = 0;

    layout.margin_top = 0;
    layout.margin_right = 0;
    layout.margin_bottom = 0;
    layout.margin_left = 0;
    if (style->has_margin)
    {
        if (style->margin.top.valid && !style->margin.top.is_auto)
        {
            layout.margin_top = html_view_length_to_px(&style->margin.top,
                                                       ctx->viewport_w,
                                                       ctx->viewport_h,
                                                       ctx->body_w,
                                                       ctx->viewport_h,
                                                       ctx->base_font_px,
                                                       false);
        }
        if (style->margin.right.valid && !style->margin.right.is_auto)
        {
            layout.margin_right = html_view_length_to_px(&style->margin.right,
                                                         ctx->viewport_w,
                                                         ctx->viewport_h,
                                                         ctx->body_w,
                                                         ctx->viewport_h,
                                                         ctx->base_font_px,
                                                         true);
        }
        if (style->margin.bottom.valid && !style->margin.bottom.is_auto)
        {
            layout.margin_bottom = html_view_length_to_px(&style->margin.bottom,
                                                          ctx->viewport_w,
                                                          ctx->viewport_h,
                                                          ctx->body_w,
                                                          ctx->viewport_h,
                                                          ctx->base_font_px,
                                                          false);
        }
        if (style->margin.left.valid && !style->margin.left.is_auto)
        {
            layout.margin_left = html_view_length_to_px(&style->margin.left,
                                                        ctx->viewport_w,
                                                        ctx->viewport_h,
                                                        ctx->body_w,
                                                        ctx->viewport_h,
                                                        ctx->base_font_px,
                                                        true);
        }
    }
    if (layout.margin_top < 0) layout.margin_top = 0;
    if (layout.margin_right < 0) layout.margin_right = 0;
    if (layout.margin_bottom < 0) layout.margin_bottom = 0;
    if (layout.margin_left < 0) layout.margin_left = 0;

    layout.pad_top = 0;
    layout.pad_right = 0;
    layout.pad_bottom = 0;
    layout.pad_left = 0;
    if (style->has_padding)
    {
        layout.pad_top = html_view_length_to_px(&style->padding.top,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                ctx->body_w,
                                                ctx->viewport_h,
                                                ctx->base_font_px,
                                                false);
        layout.pad_right = html_view_length_to_px(&style->padding.right,
                                                  ctx->viewport_w,
                                                  ctx->viewport_h,
                                                  ctx->body_w,
                                                  ctx->viewport_h,
                                                  ctx->base_font_px,
                                                  true);
        layout.pad_bottom = html_view_length_to_px(&style->padding.bottom,
                                                   ctx->viewport_w,
                                                   ctx->viewport_h,
                                                   ctx->body_w,
                                                   ctx->viewport_h,
                                                   ctx->base_font_px,
                                                   false);
        layout.pad_left = html_view_length_to_px(&style->padding.left,
                                                 ctx->viewport_w,
                                                 ctx->viewport_h,
                                                 ctx->body_w,
                                                 ctx->viewport_h,
                                                 ctx->base_font_px,
                                                 true);
    }
    if (layout.pad_top < 0) layout.pad_top = 0;
    if (layout.pad_right < 0) layout.pad_right = 0;
    if (layout.pad_bottom < 0) layout.pad_bottom = 0;
    if (layout.pad_left < 0) layout.pad_left = 0;

    layout.border_top = 0;
    layout.border_right = 0;
    layout.border_bottom = 0;
    layout.border_left = 0;
    if (style->has_border)
    {
        layout.border_top = html_view_length_to_px(&style->border_width.top,
                                                   ctx->viewport_w,
                                                   ctx->viewport_h,
                                                   ctx->body_w,
                                                   ctx->viewport_h,
                                                   ctx->base_font_px,
                                                   false);
        layout.border_right = html_view_length_to_px(&style->border_width.right,
                                                     ctx->viewport_w,
                                                     ctx->viewport_h,
                                                     ctx->body_w,
                                                     ctx->viewport_h,
                                                     ctx->base_font_px,
                                                     true);
        layout.border_bottom = html_view_length_to_px(&style->border_width.bottom,
                                                      ctx->viewport_w,
                                                      ctx->viewport_h,
                                                      ctx->body_w,
                                                      ctx->viewport_h,
                                                      ctx->base_font_px,
                                                      false);
        layout.border_left = html_view_length_to_px(&style->border_width.left,
                                                    ctx->viewport_w,
                                                    ctx->viewport_h,
                                                    ctx->body_w,
                                                    ctx->viewport_h,
                                                    ctx->base_font_px,
                                                    true);
    }
    if (layout.border_top < 0) layout.border_top = 0;
    if (layout.border_right < 0) layout.border_right = 0;
    if (layout.border_bottom < 0) layout.border_bottom = 0;
    if (layout.border_left < 0) layout.border_left = 0;

    layout.content_w = ctx->body_w;
    if (style->has_width && style->width.valid && !style->width.is_auto)
    {
        int w = html_view_length_to_px(&style->width,
                                       ctx->viewport_w,
                                       ctx->viewport_h,
                                       ctx->body_w,
                                       ctx->viewport_h,
                                       ctx->base_font_px,
                                       true);
        if (w > 0)
        {
            layout.content_w = w;
        }
    }
    if (layout.content_w < 0)
    {
        layout.content_w = 0;
    }
    if (layout.content_w > ctx->body_w)
    {
        layout.content_w = ctx->body_w;
    }

    int table_box_w = layout.content_w + layout.pad_left + layout.pad_right + layout.border_left + layout.border_right;

    int base_x = ctx->body_x + layout.margin_left;
    bool centered = false;
    if (style->has_margin)
    {
        bool auto_left = style->margin.left.valid && style->margin.left.is_auto;
        bool auto_right = style->margin.right.valid && style->margin.right.is_auto;
        if (auto_left && auto_right)
        {
            centered = true;
        }
    }
    if (!centered && parent_style && parent_style->has_text_align && parent_style->text_align == CSS_TEXT_ALIGN_CENTER)
    {
        centered = true;
    }
    if (centered && table_box_w < ctx->body_w)
    {
        base_x = ctx->body_x + (ctx->body_w - table_box_w) / 2;
    }

    layout.table_x = base_x;
    layout.table_y = ctx->y + layout.margin_top;

    const html_node_t *child = node->first_child;
    while (child)
    {
        if (child->type == HTML_NODE_ELEMENT && child->name)
        {
            if (strcmp(child->name, "tr") == 0)
            {
                if (!html_view_table_layout_add_row(&layout, child, style, ctx))
                {
                    html_view_table_layout_destroy(&layout);
                    return;
                }
            }
            else if (strcmp(child->name, "tbody") == 0 || strcmp(child->name, "thead") == 0 || strcmp(child->name, "tfoot") == 0)
            {
                for (const html_node_t *row = child->first_child; row; row = row->next_sibling)
                {
                    if (row->type == HTML_NODE_ELEMENT && row->name && strcmp(row->name, "tr") == 0)
                    {
                        if (!html_view_table_layout_add_row(&layout, row, style, ctx))
                        {
                            html_view_table_layout_destroy(&layout);
                            return;
                        }
                    }
                }
            }
        }
        child = child->next_sibling;
    }

    int col_count = 0;
    for (size_t r = 0; r < layout.row_count; ++r)
    {
        int cols = 0;
        for (size_t c = 0; c < layout.rows[r].cell_count; ++c)
        {
            cols += layout.rows[r].cells[c].colspan > 0 ? layout.rows[r].cells[c].colspan : 1;
        }
        if (cols > col_count)
        {
            col_count = cols;
        }
    }
    layout.col_count = col_count;
    if (layout.col_count <= 0)
    {
        if (ctx->draw || ctx->record)
        {
            html_view_render_children(ctx, node, style);
        }
        html_view_table_layout_destroy(&layout);
        return;
    }

    layout.col_w = (int *)calloc((size_t)layout.col_count, sizeof(*layout.col_w));
    if (!layout.col_w)
    {
        html_view_table_layout_destroy(&layout);
        return;
    }

    for (size_t r = 0; r < layout.row_count; ++r)
    {
        int col = 0;
        for (size_t c = 0; c < layout.rows[r].cell_count; ++c)
        {
            html_view_table_cell_layout_t *cell = &layout.rows[r].cells[c];
            int colspan = cell->colspan > 0 ? cell->colspan : 1;
            int cell_font_px = html_view_font_px_for_style(ctx, &cell->style, ctx->base_font_px);
            if (cell_font_px <= 0)
            {
                cell_font_px = ctx->base_font_px;
            }

            int desired_content_w = 0;
            if (cell->style.has_width && cell->style.width.valid && !cell->style.width.is_auto)
            {
                desired_content_w = html_view_length_to_px(&cell->style.width,
                                                          ctx->viewport_w,
                                                          ctx->viewport_h,
                                                          layout.content_w,
                                                          ctx->viewport_h,
                                                          cell_font_px,
                                                          true);
            }
            else
            {
                html_view_ctx_t measure_cell_ctx = *ctx;
                measure_cell_ctx.base_font_px = cell_font_px;
                measure_cell_ctx.actual_font_px = cell_font_px;
                desired_content_w = html_view_measure_text_width(&measure_cell_ctx, cell->node);
            }
            if (desired_content_w < 0) desired_content_w = 0;

            int pad_l = layout.cellpadding;
            int pad_r = layout.cellpadding;
            if (cell->style.has_padding)
            {
                pad_l += html_view_length_to_px(&cell->style.padding.left,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                layout.content_w,
                                                ctx->viewport_h,
                                                cell_font_px,
                                                true);
                pad_r += html_view_length_to_px(&cell->style.padding.right,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                layout.content_w,
                                                ctx->viewport_h,
                                                cell_font_px,
                                                true);
            }
            if (pad_l < 0) pad_l = 0;
            if (pad_r < 0) pad_r = 0;

            int border_l = 0;
            int border_r = 0;
            if (cell->style.has_border)
            {
                border_l = html_view_length_to_px(&cell->style.border_width.left,
                                                  ctx->viewport_w,
                                                  ctx->viewport_h,
                                                  layout.content_w,
                                                  ctx->viewport_h,
                                                  cell_font_px,
                                                  true);
                border_r = html_view_length_to_px(&cell->style.border_width.right,
                                                  ctx->viewport_w,
                                                  ctx->viewport_h,
                                                  layout.content_w,
                                                  ctx->viewport_h,
                                                  cell_font_px,
                                                  true);
                if (border_l < 0) border_l = 0;
                if (border_r < 0) border_r = 0;
            }

            int desired_total_w = desired_content_w + pad_l + pad_r + border_l + border_r;
            if (desired_total_w < 0) desired_total_w = 0;

            if (colspan == 1 && col < layout.col_count)
            {
                if (desired_total_w > layout.col_w[col])
                {
                    layout.col_w[col] = desired_total_w;
                }
            }
            col += colspan;
        }
    }

    int total_cols = 0;
    for (int i = 0; i < layout.col_count; ++i)
    {
        if (layout.col_w[i] < 0) layout.col_w[i] = 0;
        total_cols += layout.col_w[i];
    }
    int gaps = layout.cellspacing * (layout.col_count > 0 ? (layout.col_count - 1) : 0);
    int total_w = total_cols + gaps;
    if (total_w < layout.content_w)
    {
        layout.col_w[layout.col_count - 1] += layout.content_w - total_w;
    }
    else if (total_w > layout.content_w)
    {
        int over = total_w - layout.content_w;
        if (layout.col_w[layout.col_count - 1] > over)
        {
            layout.col_w[layout.col_count - 1] -= over;
        }
    }

    int rows_y0 = layout.table_y + layout.border_top + layout.pad_top + layout.cellspacing;
    int y_cursor = rows_y0;
    for (size_t r = 0; r < layout.row_count; ++r)
    {
        html_view_table_row_layout_t *row = &layout.rows[r];
        row->y = y_cursor;
        int row_h = row->min_h;

        int x_cursor = layout.table_x + layout.border_left + layout.pad_left + layout.cellspacing;
        int col = 0;
        for (size_t c = 0; c < row->cell_count; ++c)
        {
            html_view_table_cell_layout_t *cell = &row->cells[c];
            int colspan = cell->colspan > 0 ? cell->colspan : 1;

            int cell_w = 0;
            for (int k = 0; k < colspan && (col + k) < layout.col_count; ++k)
            {
                cell_w += layout.col_w[col + k];
            }
            if (cell_w < 0) cell_w = 0;

            cell->x = x_cursor;
            cell->y = row->y;
            cell->w = cell_w;

            int cell_font_px = html_view_font_px_for_style(ctx, &cell->style, ctx->base_font_px);
            if (cell_font_px <= 0)
            {
                cell_font_px = ctx->base_font_px;
            }

            cell->pad_top = layout.cellpadding;
            cell->pad_right = layout.cellpadding;
            cell->pad_bottom = layout.cellpadding;
            cell->pad_left = layout.cellpadding;
            if (cell->style.has_padding)
            {
                cell->pad_top += html_view_length_to_px(&cell->style.padding.top,
                                                        ctx->viewport_w,
                                                        ctx->viewport_h,
                                                        cell_w,
                                                        ctx->viewport_h,
                                                        cell_font_px,
                                                        false);
                cell->pad_right += html_view_length_to_px(&cell->style.padding.right,
                                                          ctx->viewport_w,
                                                          ctx->viewport_h,
                                                          cell_w,
                                                          ctx->viewport_h,
                                                          cell_font_px,
                                                          true);
                cell->pad_bottom += html_view_length_to_px(&cell->style.padding.bottom,
                                                           ctx->viewport_w,
                                                           ctx->viewport_h,
                                                           cell_w,
                                                           ctx->viewport_h,
                                                           cell_font_px,
                                                           false);
                cell->pad_left += html_view_length_to_px(&cell->style.padding.left,
                                                         ctx->viewport_w,
                                                         ctx->viewport_h,
                                                         cell_w,
                                                         ctx->viewport_h,
                                                         cell_font_px,
                                                         true);
            }
            if (cell->pad_top < 0) cell->pad_top = 0;
            if (cell->pad_right < 0) cell->pad_right = 0;
            if (cell->pad_bottom < 0) cell->pad_bottom = 0;
            if (cell->pad_left < 0) cell->pad_left = 0;

            cell->border_top = 0;
            cell->border_right = 0;
            cell->border_bottom = 0;
            cell->border_left = 0;
            if (cell->style.has_border)
            {
                cell->border_top = html_view_length_to_px(&cell->style.border_width.top,
                                                          ctx->viewport_w,
                                                          ctx->viewport_h,
                                                          cell_w,
                                                          ctx->viewport_h,
                                                          cell_font_px,
                                                          false);
                cell->border_right = html_view_length_to_px(&cell->style.border_width.right,
                                                            ctx->viewport_w,
                                                            ctx->viewport_h,
                                                            cell_w,
                                                            ctx->viewport_h,
                                                            cell_font_px,
                                                            true);
                cell->border_bottom = html_view_length_to_px(&cell->style.border_width.bottom,
                                                             ctx->viewport_w,
                                                             ctx->viewport_h,
                                                             cell_w,
                                                             ctx->viewport_h,
                                                             cell_font_px,
                                                             false);
                cell->border_left = html_view_length_to_px(&cell->style.border_width.left,
                                                           ctx->viewport_w,
                                                           ctx->viewport_h,
                                                           cell_w,
                                                           ctx->viewport_h,
                                                           cell_font_px,
                                                           true);
                if (cell->border_top < 0) cell->border_top = 0;
                if (cell->border_right < 0) cell->border_right = 0;
                if (cell->border_bottom < 0) cell->border_bottom = 0;
                if (cell->border_left < 0) cell->border_left = 0;
            }

            cell->content_x = cell->x + cell->border_left + cell->pad_left;
            cell->content_y = cell->y + cell->border_top + cell->pad_top;
            cell->content_w = cell->w - (cell->border_left + cell->border_right + cell->pad_left + cell->pad_right);
            if (cell->content_w < 0) cell->content_w = 0;

            html_view_ctx_t measure = *ctx;
            measure.draw = false;
            measure.record = false;
            measure.record_failed = false;
            measure.floats = NULL;
            measure.style_block = NULL;
            measure.style_depth = 0;
            measure.body_x = cell->content_x;
            measure.body_w = cell->content_w;
            measure.max_x = measure.body_x + measure.body_w;
            measure.x = measure.body_x;
            measure.y = cell->content_y;
            measure.content_bottom = measure.y;
            measure.pending_space = false;
            measure.list_level = 0;
            measure.base_font_px = cell_font_px;
            measure.actual_font_px = cell_font_px;
            measure.line_height = html_view_line_height_for_style(&measure, &cell->style);
            measure.space_w = html_view_text_width(&measure, " ");
            html_view_render_children(&measure, cell->node, &cell->style);
            html_view_style_stack_destroy(&measure);

            int content_h = measure.content_bottom - cell->content_y;
            if (content_h < 0) content_h = 0;
            if (cell->style.has_height && cell->style.height.valid && !cell->style.height.is_auto)
            {
                int h = html_view_length_to_px(&cell->style.height,
                                               ctx->viewport_w,
                                               ctx->viewport_h,
                                               cell->w,
                                               ctx->viewport_h,
                                               cell_font_px,
                                               false);
                if (h > content_h)
                {
                    content_h = h;
                }
            }

            int cell_h = content_h + cell->pad_top + cell->pad_bottom + cell->border_top + cell->border_bottom;
            if (cell_h > row_h)
            {
                row_h = cell_h;
            }

            col += colspan;
            x_cursor += cell->w;
            if (c + 1 < row->cell_count)
            {
                x_cursor += layout.cellspacing;
            }
        }

        row->h = row_h;
        for (size_t c = 0; c < row->cell_count; ++c)
        {
            row->cells[c].h = row_h;
        }

        y_cursor += row_h + layout.cellspacing;
    }

    int y_end = y_cursor;
    layout.table_h = (y_end - layout.table_y) + layout.pad_bottom + layout.border_bottom;

    if (ctx->draw || ctx->record)
    {
        if (style->has_background && table_box_w > 0 && layout.table_h > 0)
        {
            int draw_y = layout.table_y - ctx->priv->scroll_y;
            html_view_draw_rect_clipped(ctx, layout.table_x, draw_y, table_box_w, layout.table_h, style->background, &ctx->clip);
        }

        if (style->has_border && (layout.border_top > 0 || layout.border_right > 0 || layout.border_bottom > 0 || layout.border_left > 0))
        {
            video_color_t border_color = style->has_border_color ? style->border_color : video_make_color(0x00, 0x00, 0x00);
            int draw_y = layout.table_y - ctx->priv->scroll_y;
            html_view_draw_border_sides_clipped(ctx,
                                                layout.table_x,
                                                draw_y,
                                                table_box_w,
                                                layout.table_h,
                                                layout.border_top,
                                                layout.border_right,
                                                layout.border_bottom,
                                                layout.border_left,
                                                border_color,
                                                &ctx->clip);
        }

        for (size_t r = 0; r < layout.row_count; ++r)
        {
            html_view_table_row_layout_t *row = &layout.rows[r];
            for (size_t c = 0; c < row->cell_count; ++c)
            {
                html_view_table_cell_layout_t *cell = &row->cells[c];
                if (cell->w <= 0 || cell->h <= 0)
                {
                    continue;
                }

                int cell_draw_y = cell->y - ctx->priv->scroll_y;
                if (cell->style.has_background)
                {
                    html_view_draw_rect_clipped(ctx, cell->x, cell_draw_y, cell->w, cell->h, cell->style.background, &ctx->clip);
                }
                if (cell->style.has_border && (cell->border_top > 0 || cell->border_right > 0 || cell->border_bottom > 0 || cell->border_left > 0))
                {
                    video_color_t border_color = cell->style.has_border_color ? cell->style.border_color : video_make_color(0x00, 0x00, 0x00);
                    html_view_draw_border_sides_clipped(ctx,
                                                        cell->x,
                                                        cell_draw_y,
                                                        cell->w,
                                                        cell->h,
                                                        cell->border_top,
                                                        cell->border_right,
                                                        cell->border_bottom,
                                                        cell->border_left,
                                                        border_color,
                                                        &ctx->clip);
                }

                html_view_ctx_t inner = *ctx;
                inner.floats = NULL;
                inner.style_block = NULL;
                inner.style_depth = 0;
                inner.body_x = cell->content_x;
                inner.body_w = cell->content_w;
                inner.max_x = inner.body_x + inner.body_w;
                inner.x = inner.body_x;
                inner.y = cell->content_y;
                inner.content_bottom = inner.y;
                inner.pending_space = false;
                inner.list_level = 0;
                inner.bg = cell->style.has_background ? cell->style.background : ctx->bg;
                int cell_font_px = html_view_font_px_for_style(&inner, &cell->style, inner.base_font_px);
                if (cell_font_px > 0)
                {
                    inner.base_font_px = cell_font_px;
                    inner.actual_font_px = cell_font_px;
                }
                inner.line_height = html_view_line_height_for_style(&inner, &cell->style);
                inner.space_w = html_view_text_width(&inner, " ");

                if (cell->style.has_text_align &&
                    (cell->style.text_align == CSS_TEXT_ALIGN_CENTER || cell->style.text_align == CSS_TEXT_ALIGN_RIGHT))
                {
                    html_view_ctx_t measure_align = inner;
                    measure_align.draw = false;
                    measure_align.record = false;
                    measure_align.record_failed = false;
                    measure_align.floats = NULL;
                    measure_align.style_block = NULL;
                    measure_align.style_depth = 0;
                    measure_align.x = measure_align.body_x;
                    measure_align.y = inner.y;
                    measure_align.content_bottom = measure_align.y;
                    measure_align.pending_space = false;
                    measure_align.list_level = 0;
                    measure_align.space_w = inner.space_w;

                    html_view_render_children(&measure_align, cell->node, &cell->style);

                    bool single_line = (measure_align.y == inner.y);
                    int line_w = measure_align.x - measure_align.body_x;
                    html_view_style_stack_destroy(&measure_align);

                    if (single_line && inner.body_w > 0 && line_w > 0 && line_w < inner.body_w)
                    {
                        if (cell->style.text_align == CSS_TEXT_ALIGN_CENTER)
                        {
                            inner.x = inner.body_x + (inner.body_w - line_w) / 2;
                        }
                        else
                        {
                            inner.x = inner.body_x + (inner.body_w - line_w);
                        }
                        if (inner.x < inner.body_x)
                        {
                            inner.x = inner.body_x;
                        }
                    }
                }

                html_view_render_children(&inner, cell->node, &cell->style);
                if (inner.record_failed)
                {
                    ctx->record_failed = true;
                }
                html_view_style_stack_destroy(&inner);
                if (ctx->record_failed)
                {
                    break;
                }
            }
            if (ctx->record_failed)
            {
                break;
            }
        }
    }

    int bottom = layout.table_y + layout.table_h + layout.margin_bottom;
    if (bottom > ctx->y)
    {
        ctx->y = bottom;
    }
    ctx->x = ctx->body_x;
    ctx->pending_space = false;
    html_view_ensure_line_visible(ctx);

    html_view_table_layout_destroy(&layout);
}

static void html_view_render_node(html_view_ctx_t *ctx, const html_node_t *node, const css_style_t *parent_style);

static void html_view_render_children(html_view_ctx_t *ctx, const html_node_t *node, const css_style_t *style)
{
    if (!ctx || !node)
    {
        return;
    }
    for (const html_node_t *child = node->first_child; child; child = child->next_sibling)
    {
        html_view_render_node(ctx, child, style);
    }
}

static void html_view_render_node(html_view_ctx_t *ctx, const html_node_t *node, const css_style_t *parent_style)
{
    if (!ctx || !node)
    {
        return;
    }

    if (node->type == HTML_NODE_TEXT)
    {
        if (!node->text || !parent_style)
        {
            return;
        }
        video_color_t color = parent_style->has_color ? parent_style->color : video_make_color(0x00, 0x00, 0x00);
        html_view_draw_text(ctx, node->text, color, ctx->text_underline, ctx->text_bold);
        return;
    }

    if (node->type != HTML_NODE_ELEMENT || !node->name)
    {
        return;
    }

    const char *tag = node->name;
    if (strcmp(tag, "head") == 0 ||
        strcmp(tag, "style") == 0 ||
        strcmp(tag, "meta") == 0 ||
        strcmp(tag, "title") == 0 ||
        strcmp(tag, "link") == 0 ||
        strcmp(tag, "script") == 0)
    {
        return;
    }

    const css_style_t *style = html_view_style_push(ctx, parent_style, node);
    if (!style)
    {
        return;
    }
    bool block = html_view_is_block_tag(tag);
    if (style->has_display)
    {
        if (style->display == CSS_DISPLAY_INLINE)
        {
            block = false;
        }
        else if (style->display == CSS_DISPLAY_BLOCK || style->display == CSS_DISPLAY_LIST_ITEM)
        {
            block = true;
        }
    }

    html_view_font_scope_t font_scope = {0};
    bool font_pushed = false;

    if (style->has_display && style->display == CSS_DISPLAY_NONE)
    {
        goto out;
    }

    html_view_font_scope_push(ctx, style, block, &font_scope);
    font_pushed = true;

    if (style->has_float && style->float_mode != CSS_FLOAT_NONE &&
        !html_view_is_form_control_tag(tag) &&
        strcmp(tag, "img") != 0)
    {
        html_view_render_float_box(ctx, node, style, style->float_mode);
        goto out;
    }

    if (strcmp(tag, "br") == 0)
    {
        html_view_new_line(ctx);
        goto out;
    }

    if (strcmp(tag, "table") == 0)
    {
        html_view_render_table(ctx, node, style, parent_style);
        goto out;
    }

    if (strcmp(tag, "input") == 0)
    {
        html_view_control_t *ctrl = html_view_control_find(ctx->priv, node);
        if (ctrl && ctrl->widget)
        {
            int height = ctx->line_height;
            int width = 24;
            if (ctrl->kind == HTML_VIEW_CONTROL_INPUT_TEXT)
            {
                width = 240;
            }
            else if (ctrl->kind == HTML_VIEW_CONTROL_CHECKBOX || ctrl->kind == HTML_VIEW_CONTROL_RADIO)
            {
                width = ctx->line_height;
            }
            html_view_place_inline_control(ctx, ctrl->widget, width, height);
        }
        else
        {
            video_color_t color = style->has_color ? style->color : video_make_color(0x00, 0x00, 0x00);
            html_view_draw_text(ctx, "[input]", color, false, false);
        }
        goto out;
    }

    if (strcmp(tag, "textarea") == 0)
    {
        html_view_control_t *ctrl = html_view_control_find(ctx->priv, node);
        if (ctrl && ctrl->widget)
        {
            int width = 360;
            int height = ctx->line_height * 4;
            if (height < 32)
            {
                height = 32;
            }
            html_view_place_block_control(ctx, ctrl->widget, width, height);
        }
        goto out;
    }

    if (strcmp(tag, "button") == 0)
    {
        html_view_control_t *ctrl = html_view_control_find(ctx->priv, node);
        if (ctrl && ctrl->widget)
        {
            int height = ctx->line_height;
            int width = ctrl->widget->width > 0 ? ctrl->widget->width : 100;
            html_view_place_inline_control(ctx, ctrl->widget, width, height);
        }
        else
        {
            html_view_render_children(ctx, node, style);
        }
        goto out;
    }

    if (strcmp(tag, "h1") == 0)
    {
        if (ctx->x != ctx->body_x)
        {
            html_view_new_line(ctx);
        }

        int pad_top = 0;
        int pad_bottom = 0;
        if (style->has_padding)
        {
            pad_top = html_view_length_to_px(&style->padding.top,
                                             ctx->viewport_w,
                                             ctx->viewport_h,
                                             ctx->viewport_w,
                                             ctx->viewport_h,
                                             ctx->base_font_px,
                                             false);
            pad_bottom = html_view_length_to_px(&style->padding.bottom,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                ctx->base_font_px,
                                                false);
        }

        ctx->y += pad_top;
        ctx->pending_space = false;

        video_color_t color = style->has_color ? style->color : video_make_color(0x00, 0x00, 0x00);

        char *text = NULL;
        size_t text_len = 0;
        size_t text_cap = 0;
        for (const html_node_t *child = node->first_child; child; child = child->next_sibling)
        {
            if (child->type == HTML_NODE_TEXT && child->text)
            {
                (void)html_view_buf_append(&text, &text_len, &text_cap, child->text, strlen(child->text));
            }
        }
        if (text && text_len > 0)
        {
            int text_w = html_view_text_width(ctx, text);
            int draw_x = ctx->body_x;
            if (style->has_text_align)
            {
                if (style->text_align == CSS_TEXT_ALIGN_CENTER)
                {
                    draw_x = ctx->body_x + (ctx->body_w - text_w) / 2;
                }
                else if (style->text_align == CSS_TEXT_ALIGN_RIGHT)
                {
                    draw_x = ctx->body_x + (ctx->body_w - text_w);
                }
            }
            if (draw_x < ctx->body_x)
            {
                draw_x = ctx->body_x;
            }

            int draw_top = ctx->y - ctx->priv->scroll_y;
            int baseline = html_view_baseline_for_rect(ctx, draw_top, ctx->line_height);

            if (ctx->record)
            {
                if (!ctx->record_failed && ctx->priv && text)
                {
                    html_view_render_cache_t *cache = &ctx->priv->render_cache;
                    char *owned = html_view_render_cache_strdup(cache, text);
                    if (!owned)
                    {
                        ctx->record_failed = true;
                    }
                    else
                    {
                        int baseline_off = baseline - draw_top;
                        size_t owned_len = strlen(owned);

                        if (style->has_text_shadow)
                        {
                            int dx = html_view_length_to_px(&style->text_shadow_x,
                                                            ctx->viewport_w,
                                                            ctx->viewport_h,
                                                            ctx->viewport_w,
                                                            ctx->viewport_h,
                                                            ctx->base_font_px,
                                                            true);
                            int dy = html_view_length_to_px(&style->text_shadow_y,
                                                            ctx->viewport_w,
                                                            ctx->viewport_h,
                                                            ctx->viewport_w,
                                                            ctx->viewport_h,
                                                            ctx->base_font_px,
                                                            false);
                            video_color_t shadow = style->has_text_shadow_color ? style->text_shadow_color : video_make_color(0x00, 0x00, 0x00);

                            html_view_op_t shadow_op = {0};
                            shadow_op.kind = HTML_VIEW_OP_TEXT;
                            shadow_op.x = (draw_x + dx) - ctx->doc_origin_x;
                            shadow_op.y = (draw_top + ctx->priv->scroll_y) - ctx->doc_origin_y;
                            shadow_op.h = ctx->line_height;
                            shadow_op.baseline_off = (int16_t)(baseline_off + dy);
                            shadow_op.font_px = (int16_t)ctx->actual_font_px;
                            shadow_op.color = shadow;
                            shadow_op.text = owned;
                            shadow_op.text_len = (uint32_t)owned_len;
                            shadow_op.text_owned = false;
                            if (!html_view_render_cache_push_op(cache, &shadow_op, cache->tile_h))
                            {
                                ctx->record_failed = true;
                            }

                            if (!ctx->record_failed)
                            {
                                html_view_op_t shadow_op2 = shadow_op;
                                shadow_op2.x += 1;
                                (void)html_view_render_cache_push_op(cache, &shadow_op2, cache->tile_h);
                            }
                        }

                        if (!ctx->record_failed)
                        {
                            html_view_op_t main_op = {0};
                            main_op.kind = HTML_VIEW_OP_TEXT;
                            main_op.x = draw_x - ctx->doc_origin_x;
                            main_op.y = (draw_top + ctx->priv->scroll_y) - ctx->doc_origin_y;
                            main_op.h = ctx->line_height;
                            main_op.baseline_off = (int16_t)baseline_off;
                            main_op.font_px = (int16_t)ctx->actual_font_px;
                            main_op.color = color;
                            main_op.text = owned;
                            main_op.text_len = (uint32_t)owned_len;
                            main_op.text_owned = false;
                            if (!html_view_render_cache_push_op(cache, &main_op, cache->tile_h))
                            {
                                ctx->record_failed = true;
                            }

                            if (!ctx->record_failed)
                            {
                                html_view_op_t main_op2 = main_op;
                                main_op2.x += 1;
                                (void)html_view_render_cache_push_op(cache, &main_op2, cache->tile_h);
                            }
                        }
                    }
                }
            }
            else if (ctx->draw && html_view_line_visible(ctx))
            {
                if (style->has_text_shadow)
                {
                    int dx = html_view_length_to_px(&style->text_shadow_x,
                                                    ctx->viewport_w,
                                                    ctx->viewport_h,
                                                    ctx->viewport_w,
                                                    ctx->viewport_h,
                                                    ctx->base_font_px,
                                                    true);
                    int dy = html_view_length_to_px(&style->text_shadow_y,
                                                    ctx->viewport_w,
                                                    ctx->viewport_h,
                                                    ctx->viewport_w,
                                                    ctx->viewport_h,
                                                    ctx->base_font_px,
                                                    false);
                    video_color_t shadow = style->has_text_shadow_color ? style->text_shadow_color : video_make_color(0x00, 0x00, 0x00);
                    html_view_draw_string_clipped(ctx, draw_x + dx, baseline + dy, text, shadow, &ctx->clip);
                    html_view_draw_string_clipped(ctx, draw_x + dx + 1, baseline + dy, text, shadow, &ctx->clip);
                }

                html_view_draw_string_clipped(ctx, draw_x, baseline, text, color, &ctx->clip);
                html_view_draw_string_clipped(ctx, draw_x + 1, baseline, text, color, &ctx->clip);
            }

            ctx->x = ctx->body_x;
            ctx->pending_space = false;
            html_view_ensure_line_visible(ctx);
        }
        free(text);

        html_view_new_line(ctx);
        ctx->y += pad_bottom;
        ctx->pending_space = false;
        goto out;
    }

    if (strcmp(tag, "p") == 0)
    {
        if (ctx->x != ctx->body_x)
        {
            html_view_new_line(ctx);
        }

        if (style->has_clear && style->clear_mode != CSS_CLEAR_NONE)
        {
            int clear_y = html_view_float_max_bottom(ctx->floats, style->clear_mode);
            if (clear_y > ctx->y)
            {
                ctx->y = clear_y;
                ctx->x = ctx->body_x;
                ctx->pending_space = false;
            }
        }

        int saved_line_height = ctx->line_height;
        ctx->line_height = html_view_line_height_for_style(ctx, style);
        if (html_view_subtree_has_form_control(node) && ctx->line_height < atk_font_line_height() + 8)
        {
            ctx->line_height = atk_font_line_height() + 8;
        }

        int margin_top = 0;
        int margin_bottom = 0;
        if (style->has_margin)
        {
            if (style->margin.top.valid && !style->margin.top.is_auto)
            {
                margin_top = html_view_length_to_px(&style->margin.top,
                                                    ctx->viewport_w,
                                                    ctx->viewport_h,
                                                    ctx->body_w,
                                                    ctx->viewport_h,
                                                    ctx->base_font_px,
                                                    false);
            }
            if (style->margin.bottom.valid && !style->margin.bottom.is_auto)
            {
                margin_bottom = html_view_length_to_px(&style->margin.bottom,
                                                       ctx->viewport_w,
                                                       ctx->viewport_h,
                                                       ctx->body_w,
                                                       ctx->viewport_h,
                                                       ctx->base_font_px,
                                                       false);
            }
        }
        else
        {
            if (ctx->y > ctx->viewport_y)
            {
                margin_top = ctx->line_height / 3;
            }
            margin_bottom = ctx->line_height / 3;
        }
        if (margin_top < 0) margin_top = 0;
        if (margin_bottom < 0) margin_bottom = 0;

        ctx->y += margin_top;
        ctx->pending_space = false;
        html_view_render_children(ctx, node, style);
        html_view_new_line(ctx);
        ctx->y += margin_bottom;
        html_view_ensure_line_visible(ctx);
        ctx->line_height = saved_line_height;
        ctx->pending_space = false;
        goto out;
    }

    if (strcmp(tag, "ul") == 0)
    {
        bool styled = style->has_margin ||
                      style->has_padding ||
                      style->has_border ||
                      style->has_background ||
                      style->has_width ||
                      style->has_height ||
                      style->has_float ||
                      (style->has_display && style->display != CSS_DISPLAY_INLINE);

        if (styled)
        {
            if (ctx->x != ctx->body_x)
            {
                html_view_new_line(ctx);
            }
            ctx->pending_space = false;
            html_view_render_children(ctx, node, style);
            if (ctx->x != ctx->body_x)
            {
                html_view_new_line(ctx);
            }
            ctx->pending_space = false;
            goto out;
        }

        if (ctx->x != ctx->body_x)
        {
            html_view_new_line(ctx);
        }
        if (ctx->y > ctx->viewport_y)
        {
            ctx->y += ctx->line_height / 3;
        }
        ctx->pending_space = false;
        ctx->list_level += 1;
        html_view_render_children(ctx, node, style);
        if (ctx->list_level > 0)
        {
            ctx->list_level -= 1;
        }
        if (ctx->x != ctx->body_x)
        {
            html_view_new_line(ctx);
        }
        ctx->pending_space = false;
        goto out;
    }

    if (strcmp(tag, "dl") == 0)
    {
        if (ctx->x != ctx->body_x)
        {
            html_view_new_line(ctx);
        }

        int pad_top = 0;
        int pad_right = 0;
        int pad_bottom = 0;
        int pad_left = 0;
        if (style->has_padding)
        {
            pad_top = html_view_length_to_px(&style->padding.top,
                                             ctx->viewport_w,
                                             ctx->viewport_h,
                                             ctx->body_w,
                                             ctx->viewport_h,
                                             ctx->base_font_px,
                                             false);
            pad_right = html_view_length_to_px(&style->padding.right,
                                               ctx->viewport_w,
                                               ctx->viewport_h,
                                               ctx->body_w,
                                               ctx->viewport_h,
                                               ctx->base_font_px,
                                               true);
            pad_bottom = html_view_length_to_px(&style->padding.bottom,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                ctx->body_w,
                                                ctx->viewport_h,
                                                ctx->base_font_px,
                                                false);
            pad_left = html_view_length_to_px(&style->padding.left,
                                              ctx->viewport_w,
                                              ctx->viewport_h,
                                              ctx->body_w,
                                              ctx->viewport_h,
                                              ctx->base_font_px,
                                              true);
        }
        if (pad_top < 0) pad_top = 0;
        if (pad_right < 0) pad_right = 0;
        if (pad_bottom < 0) pad_bottom = 0;
        if (pad_left < 0) pad_left = 0;

        int saved_body_x = ctx->body_x;
        int saved_body_w = ctx->body_w;
        int saved_max_x = ctx->max_x;
        int saved_y = ctx->y;

        ctx->body_x = saved_body_x + pad_left;
        ctx->body_w = saved_body_w - pad_left - pad_right;
        if (ctx->body_w < 0) ctx->body_w = 0;
        ctx->max_x = ctx->body_x + ctx->body_w;
        ctx->x = ctx->body_x;
        ctx->y = saved_y + pad_top;
        ctx->pending_space = false;

        html_view_render_children(ctx, node, style);

        int new_y = ctx->y + pad_bottom;

        ctx->body_x = saved_body_x;
        ctx->body_w = saved_body_w;
        ctx->max_x = saved_max_x;
        ctx->x = saved_body_x;
        ctx->y = new_y;
        ctx->pending_space = false;
        html_view_ensure_line_visible(ctx);
        goto out;
    }

    if (strcmp(tag, "li") == 0)
    {
        css_display_t display = style->has_display ? style->display : CSS_DISPLAY_LIST_ITEM;
        if (display != CSS_DISPLAY_LIST_ITEM)
        {
            if (ctx->x != ctx->body_x)
            {
                html_view_new_line(ctx);
            }
            ctx->pending_space = false;
            html_view_render_children(ctx, node, style);
            if (ctx->x != ctx->body_x)
            {
                html_view_new_line(ctx);
            }
            ctx->pending_space = false;
            goto out;
        }

        if (ctx->x != ctx->body_x)
        {
            html_view_new_line(ctx);
        }

        int saved_body_x = ctx->body_x;
        int saved_max_x = ctx->max_x;
        int saved_line_height = ctx->line_height;
        ctx->line_height = html_view_line_height_for_style(ctx, style);

        int level = ctx->list_level > 0 ? ctx->list_level : 1;
        int indent = level * 32;
        int bullet_size = 4;
        int bullet_x = saved_body_x + indent - 16;
        int bullet_draw_y = (ctx->y - ctx->priv->scroll_y) + ctx->line_height / 2 - bullet_size / 2;
        video_color_t bullet_color = style->has_color ? style->color : video_make_color(0x00, 0x00, 0x00);

        if (ctx->record || (ctx->draw && html_view_line_visible(ctx)))
        {
            html_view_draw_rect_clipped(ctx, bullet_x, bullet_draw_y, bullet_size, bullet_size, bullet_color, &ctx->clip);
        }

        ctx->body_x = saved_body_x + indent;
        ctx->x = ctx->body_x;
        ctx->max_x = saved_max_x;
        ctx->pending_space = false;

        html_view_render_children(ctx, node, style);
        html_view_new_line(ctx);

        ctx->body_x = saved_body_x;
        ctx->x = ctx->body_x;
        ctx->max_x = saved_max_x;
        ctx->line_height = saved_line_height;
        ctx->pending_space = false;
        goto out;
    }

    if (strcmp(tag, "img") == 0)
    {
        if (ctx->x != ctx->body_x)
        {
            html_view_new_line(ctx);
        }

        int margin_top = 0;
        int margin_bottom = 0;
        if (style->has_margin)
        {
            if (style->margin.top.valid && !style->margin.top.is_auto)
            {
                margin_top = html_view_length_to_px(&style->margin.top,
                                                    ctx->viewport_w,
                                                    ctx->viewport_h,
                                                    ctx->viewport_w,
                                                    ctx->viewport_h,
                                                    ctx->base_font_px,
                                                    false);
            }
            if (style->margin.bottom.valid && !style->margin.bottom.is_auto)
            {
                margin_bottom = html_view_length_to_px(&style->margin.bottom,
                                                      ctx->viewport_w,
                                                      ctx->viewport_h,
                                                      ctx->viewport_w,
                                                      ctx->viewport_h,
                                                      ctx->base_font_px,
                                                      false);
            }
        }
        ctx->y += margin_top;
        ctx->pending_space = false;

        const char *src = html_attr_get(node, "src");
        html_view_image_t *img = src ? html_view_image_find(ctx->priv, src) : NULL;
        int img_w = img ? img->width : 0;
        int img_h = img ? img->height : 0;

        bool have_dimensions = (img_w > 0 || img_h > 0);
        if (!have_dimensions)
        {
            if (style->has_width && style->width.valid && !style->width.is_auto)
            {
                img_w = html_view_length_to_px(&style->width,
                                               ctx->viewport_w,
                                               ctx->viewport_h,
                                               ctx->body_w,
                                               ctx->viewport_h,
                                               ctx->base_font_px,
                                               true);
            }
            if (style->has_height && style->height.valid && !style->height.is_auto)
            {
                img_h = html_view_length_to_px(&style->height,
                                               ctx->viewport_w,
                                               ctx->viewport_h,
                                               ctx->viewport_w,
                                               ctx->viewport_h,
                                               ctx->base_font_px,
                                               false);
            }
            if (img_w < 0) img_w = 0;
            if (img_h < 0) img_h = 0;
            have_dimensions = (img_w > 0 || img_h > 0);
        }

        if (have_dimensions)
        {
            bool is_spacer_gif = false;
            if (src)
            {
                size_t slen = strlen(src);
                if (slen >= 5 && strcasecmp(src + slen - 5, "s.gif") == 0)
                {
                    is_spacer_gif = true;
                }
            }

            int draw_x = ctx->body_x;
            if (style->has_margin)
            {
                bool auto_left = style->margin.left.valid && style->margin.left.is_auto;
                bool auto_right = style->margin.right.valid && style->margin.right.is_auto;
                if (auto_left && auto_right)
                {
                    draw_x = ctx->body_x + (ctx->body_w - img_w) / 2;
                }
                else if (style->margin.left.valid && !style->margin.left.is_auto)
                {
                    draw_x = ctx->body_x + html_view_length_to_px(&style->margin.left,
                                                                  ctx->viewport_w,
                                                                  ctx->viewport_h,
                                                                  ctx->viewport_w,
                                                                  ctx->viewport_h,
                                                                  ctx->base_font_px,
                                                                  true);
                }
            }
            if (draw_x < ctx->body_x)
            {
                draw_x = ctx->body_x;
            }
            int draw_y = ctx->y - ctx->priv->scroll_y;
            if (img && img->pixels && img_w > 0 && img_h > 0)
            {
                if (ctx->draw)
                {
                    html_view_blit_rgba32_clipped(ctx, draw_x, draw_y, img_w, img_h, img->pixels, img->stride_bytes, &ctx->clip);
                }
                else if (ctx->record)
                {
                    html_view_blit_rgba32_clipped(ctx, draw_x, draw_y, img_w, img_h, img->pixels, img->stride_bytes, &ctx->clip);
                }
            }
            else
            {
                if (!is_spacer_gif && img_w > 0 && img_h > 0)
                {
                    video_color_t ph = video_make_color(0xDD, 0xDD, 0xDD);
                    html_view_draw_rect_clipped(ctx, draw_x, draw_y, img_w, img_h, ph, &ctx->clip);
                }
            }

            if (style->has_border && img_w > 0 && img_h > 0)
            {
                int bt = html_view_length_to_px(&style->border_width.top,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                img_w,
                                                ctx->viewport_h,
                                                ctx->base_font_px,
                                                false);
                int br = html_view_length_to_px(&style->border_width.right,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                img_w,
                                                ctx->viewport_h,
                                                ctx->base_font_px,
                                                true);
                int bb = html_view_length_to_px(&style->border_width.bottom,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                img_w,
                                                ctx->viewport_h,
                                                ctx->base_font_px,
                                                false);
                int bl = html_view_length_to_px(&style->border_width.left,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                img_w,
                                                ctx->viewport_h,
                                                ctx->base_font_px,
                                                true);
                if (bt < 0) bt = 0;
                if (br < 0) br = 0;
                if (bb < 0) bb = 0;
                if (bl < 0) bl = 0;
                if (bt > 0 || br > 0 || bb > 0 || bl > 0)
                {
                    video_color_t border_color = style->has_border_color ? style->border_color : video_make_color(0x00, 0x00, 0x00);
                    html_view_draw_border_sides_clipped(ctx,
                                                        draw_x,
                                                        draw_y,
                                                        img_w,
                                                        img_h,
                                                        bt,
                                                        br,
                                                        bb,
                                                        bl,
                                                        border_color,
                                                        &ctx->clip);
                }
            }

            ctx->y += img_h;
        }
        else
        {
            const char *alt = html_attr_get(node, "alt");
            if (!alt || alt[0] == '\0')
            {
                alt = "[image]";
            }
            video_color_t color = style->has_color ? style->color : video_make_color(0x00, 0x00, 0x00);
            html_view_draw_text(ctx, alt, color, false, false);
            html_view_new_line(ctx);
        }

        ctx->y += margin_bottom;
        ctx->x = ctx->body_x;
        ctx->pending_space = false;
        html_view_ensure_line_visible(ctx);
        goto out;
    }

    if (strcmp(tag, "b") == 0 || strcmp(tag, "strong") == 0)
    {
        bool saved_bold = ctx->text_bold;
        ctx->text_bold = true;
        html_view_render_children(ctx, node, style);
        ctx->text_bold = saved_bold;
        goto out;
    }

    if (strcmp(tag, "a") == 0)
    {
        bool saved_underline = ctx->text_underline;
        bool underline = true;
        if (style->has_text_decoration)
        {
            underline = (style->text_decoration == CSS_TEXT_DECORATION_UNDERLINE);
        }
        ctx->text_underline = underline;
        html_view_render_children(ctx, node, style);
        ctx->text_underline = saved_underline;
        goto out;
    }

    if (block && ctx->x != ctx->body_x)
    {
        html_view_new_line(ctx);
    }
    html_view_render_children(ctx, node, style);
    if (block && ctx->x != ctx->body_x)
    {
        html_view_new_line(ctx);
    }

out:
    if (font_pushed)
    {
        html_view_font_scope_pop(ctx, &font_scope);
    }
    html_view_style_pop(ctx);
}

static void html_view_position_scrollbar(atk_widget_t *view, atk_html_view_priv_t *priv)
{
    if (!view || !priv || !priv->scrollbar)
    {
        return;
    }
    int sb_w = priv->scrollbar_width;
    if (sb_w < 4)
    {
        sb_w = 4;
    }
    int sb_x = view->x + view->width - sb_w;
    if (sb_x < view->x)
    {
        sb_x = view->x;
    }
    priv->scrollbar->x = sb_x;
    priv->scrollbar->y = view->y;
    priv->scrollbar->width = sb_w;
    priv->scrollbar->height = view->height;
}

static void html_view_scrollbar_changed(atk_widget_t *scrollbar, void *context, int value)
{
    (void)scrollbar;
    atk_widget_t *view = (atk_widget_t *)context;
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        return;
    }
    priv->scroll_y = value;
    html_view_invalidate(view);
}

static void html_view_update_scrollbar(atk_widget_t *view, atk_html_view_priv_t *priv)
{
    if (!view || !priv || !priv->scrollbar)
    {
        return;
    }
    int viewport_h = view->height - ATK_HTML_VIEW_PADDING * 2;
    if (viewport_h < 0)
    {
        viewport_h = 0;
    }
    int max_scroll = priv->content_height - viewport_h;
    if (max_scroll < 0)
    {
        max_scroll = 0;
    }
    if (priv->scroll_y < 0) priv->scroll_y = 0;
    if (priv->scroll_y > max_scroll) priv->scroll_y = max_scroll;
    atk_scrollbar_set_range(priv->scrollbar, 0, max_scroll, viewport_h);
    atk_scrollbar_set_value(priv->scrollbar, priv->scroll_y);
}

static void html_view_draw_cb(const atk_state_t *state,
                              const atk_widget_t *widget,
                              int origin_x,
                              int origin_y,
                              void *context)
{
    (void)context;
    if (!state || !widget)
    {
        return;
    }

    atk_html_view_priv_t *priv = html_view_priv_mut((atk_widget_t *)widget);
    if (!priv)
    {
        return;
    }

    html_view_controls_hide_all(priv);

    int abs_x = origin_x + widget->x;
    int abs_y = origin_y + widget->y;

    html_view_position_scrollbar((atk_widget_t *)widget, priv);

    int sb_w = priv->scrollbar ? priv->scrollbar_width : 0;
    int viewport_x = abs_x + ATK_HTML_VIEW_PADDING;
    int viewport_y = abs_y + ATK_HTML_VIEW_PADDING;
    int viewport_w = widget->width - ATK_HTML_VIEW_PADDING * 2 - sb_w;
    int viewport_h = widget->height - ATK_HTML_VIEW_PADDING * 2;
    if (viewport_w < 0) viewport_w = 0;
    if (viewport_h < 0) viewport_h = 0;

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

    const html_node_t *html_node = NULL;
    const html_node_t *body_node = NULL;
    if (priv->doc && priv->doc->root)
    {
        html_node = html_view_find_first_element(priv->doc->root, "html");
        body_node = html_view_find_first_element(priv->doc->root, "body");
    }

    css_style_t html_style = {0};
    if (html_node)
    {
        html_view_style_for_node(&html_style, priv->sheet, &base_style, html_node);
    }
    else
    {
        html_style = base_style;
    }

    css_style_t body_style = {0};
    if (body_node)
    {
        html_view_style_for_node(&body_style, priv->sheet, &html_style, body_node);
    }
    else
    {
        body_style = html_style;
    }
    video_color_t page_bg = html_style.has_background ? html_style.background : default_page_bg;
    video_color_t body_bg = body_style.has_background ? body_style.background : default_page_bg;

    video_draw_rect(abs_x, abs_y, widget->width, widget->height, page_bg);
    video_draw_rect_outline(abs_x, abs_y, widget->width, widget->height, state->theme.window_border);

    atk_rect_t clip = { viewport_x, viewport_y, viewport_w, viewport_h };

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
    if (body_content_w < 0) body_content_w = 0;

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
            body_box_x = viewport_x + html_view_length_to_px(&body_style.margin.left,
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
        margin_top = html_view_length_to_px(&body_style.margin.top,
                                            viewport_w,
                                            viewport_h,
                                            viewport_w,
                                            viewport_h,
                                            base_font_px,
                                            false);
    }

    const html_node_t *body = body_node;

    int body_box_y0 = viewport_y + margin_top;
    int body_content_x = body_box_x + border_px + pad_left;
    int body_content_y0 = body_box_y0 + border_px + pad_top;

    int effective_font_px = base_font_px;
    if (effective_font_px <= 0)
    {
        effective_font_px = atk_font_line_height();
    }

    if (!html_view_font_state_get_cache(&priv->font, effective_font_px))
    {
        effective_font_px = atk_font_line_height();
        base_font_px = effective_font_px;
        base_line_height = base_font_px + 4;
        if (base_line_height < 8)
        {
            base_line_height = 8;
        }
    }

    html_view_render_cache_t *cache = &priv->render_cache;
    bool cache_matches = cache->valid &&
                         cache->doc == priv->doc &&
                         cache->sheet == priv->sheet &&
                         cache->viewport_w == viewport_w &&
                         cache->viewport_h == viewport_h &&
                         cache->body_w == body_content_w &&
                         cache->base_font_px == base_font_px &&
                         cache->base_line_height == base_line_height;

    if (!cache_matches)
    {
        html_view_render_cache_clear(cache);
        cache->tile_h = ATK_HTML_VIEW_RENDER_TILE_H;
        cache->doc = priv->doc;
        cache->sheet = priv->sheet;
        cache->viewport_w = viewport_w;
        cache->viewport_h = viewport_h;
        cache->body_w = body_content_w;
        cache->base_font_px = base_font_px;
        cache->base_line_height = base_line_height;

        html_view_float_ctx_t floats_record = {0};
        html_view_ctx_t record = {
            .state = state,
            .widget = widget,
            .priv = priv,
            .sheet = priv->sheet,
            .bg = body_bg,
            .clip = clip,
            .viewport_x = viewport_x,
            .viewport_y = viewport_y,
            .viewport_w = viewport_w,
            .viewport_h = viewport_h,
            .window_x = origin_x,
            .window_y = origin_y,
            .body_x = body_content_x,
            .body_w = body_content_w,
            .floats = &floats_record,
            .actual_font_px = effective_font_px,
            .base_font_px = base_font_px,
            .base_line_height = base_line_height,
            .line_height = base_line_height,
            .space_w = 0,
            .x = body_content_x,
            .y = body_content_y0,
            .max_x = body_content_x + body_content_w,
            .content_bottom = body_content_y0,
            .list_level = 0,
            .pending_space = false,
            .draw = true,
            .record = true,
            .record_failed = false,
            .doc_origin_x = body_content_x,
            .doc_origin_y = body_content_y0
        };

        record.space_w = html_view_text_width(&record, " ");
        if (body)
        {
            html_view_render_children(&record, body, &body_style);
        }
        else
        {
            html_view_draw_text(&record, "No document.\n", default_text, false, false);
        }
        html_view_style_stack_destroy(&record);

        if (!record.record_failed)
        {
            int body_box_h = (record.content_bottom - body_box_y0) + pad_bottom + border_px;
            int min_h = border_px * 2 + pad_top + pad_bottom;
            if (body_box_h < min_h)
            {
                body_box_h = min_h;
            }
            cache->body_box_h = body_box_h;

            int final_bottom = record.content_bottom;
            int body_bottom = body_box_y0 + body_box_h;
            if (body_bottom > final_bottom)
            {
                final_bottom = body_bottom;
            }

            cache->content_height = final_bottom - viewport_y;
            if (cache->content_height < 0)
            {
                cache->content_height = 0;
            }

            cache->valid = true;
        }
        else
        {
            html_view_render_cache_clear(cache);
        }
    }

    html_view_ctx_t ctx = {
        .state = state,
        .widget = widget,
        .priv = priv,
        .sheet = priv->sheet,
        .bg = body_bg,
        .clip = clip,
        .viewport_x = viewport_x,
        .viewport_y = viewport_y,
        .viewport_w = viewport_w,
        .viewport_h = viewport_h,
        .window_x = origin_x,
        .window_y = origin_y,
        .body_x = body_content_x,
        .body_w = body_content_w,
        .floats = NULL,
        .actual_font_px = effective_font_px,
        .base_font_px = base_font_px,
        .base_line_height = base_line_height,
        .line_height = base_line_height,
        .space_w = 0,
        .x = body_content_x,
        .y = body_content_y0,
        .max_x = body_content_x + body_content_w,
        .content_bottom = body_content_y0,
        .list_level = 0,
        .pending_space = false,
        .draw = true,
        .record = false,
        .record_failed = false,
        .doc_origin_x = body_content_x,
        .doc_origin_y = body_content_y0
    };

    ctx.space_w = html_view_text_width(&ctx, " ");

    if (!cache->valid)
    {
        html_view_draw_text(&ctx, "Render cache unavailable.\n", default_text, false, false);
        return;
    }

    priv->content_height = cache->content_height;
    if (priv->content_height < 0) priv->content_height = 0;
    if (priv->scrollbar)
    {
        html_view_update_scrollbar((atk_widget_t *)widget, priv);
    }

    int body_draw_y = body_box_y0 - priv->scroll_y;
    html_view_draw_rect_clipped(&ctx, body_box_x, body_draw_y, body_box_w, cache->body_box_h, body_bg, &clip);
    if (border_px > 0)
    {
        video_color_t border_color = body_style.has_border_color ? body_style.border_color : video_make_color(0x00, 0x00, 0x00);
        html_view_draw_border_clipped(&ctx, body_box_x, body_draw_y, body_box_w, cache->body_box_h, border_px, border_color, &clip);
    }

    html_view_render_cache_draw_visible(&ctx);
}

static void html_view_destroy_cb(atk_widget_t *widget, void *context)
{
    (void)context;
    atk_html_view_priv_t *priv = html_view_priv_mut(widget);
    if (priv)
    {
        html_view_render_cache_clear(&priv->render_cache);
        html_view_control_t *ctrl = priv->controls;
        while (ctrl)
        {
            html_view_control_t *next = ctrl->next;
            free(ctrl);
            ctrl = next;
        }
        priv->controls = NULL;
        html_view_images_clear(priv);
        if (priv->external_css)
        {
            free(priv->external_css);
            priv->external_css = NULL;
            priv->external_css_len = 0;
        }
        if (priv->doc)
        {
            html_document_destroy(priv->doc);
            priv->doc = NULL;
        }
        if (priv->sheet)
        {
            css_stylesheet_destroy(priv->sheet);
            priv->sheet = NULL;
        }
        html_view_font_state_reset(&priv->font);
        priv->scrollbar = NULL;
        priv->child_node = NULL;
    }
    atk_widget_destroy(widget);
}

static const atk_widget_vtable_t html_view_vtable = { 0 };
static const atk_widget_ops_t g_html_view_ops = {
    .destroy = html_view_destroy_cb,
    .draw = html_view_draw_cb,
    .hit_test = html_view_hit_test_cb,
    .on_mouse = html_view_mouse_cb,
    .on_key = html_view_key_cb
};

const atk_class_t ATK_HTML_VIEW_CLASS = { "HtmlView", &ATK_WIDGET_CLASS, &html_view_vtable, sizeof(atk_html_view_priv_t) };

atk_widget_t *atk_window_add_html_view(atk_widget_t *window, int x, int y, int width, int height)
{
    if (!window || width <= 0 || height <= 0)
    {
        return NULL;
    }

    atk_window_priv_t *wpriv = (atk_window_priv_t *)atk_widget_priv(window, &ATK_WINDOW_CLASS);
    if (!wpriv)
    {
        return NULL;
    }

    atk_widget_t *view = atk_widget_create(&ATK_HTML_VIEW_CLASS);
    if (!view)
    {
        return NULL;
    }

    view->x = x;
    view->y = y;
    view->width = width;
    view->height = height;
    view->parent = window;
    view->used = true;
    atk_widget_set_ops(view, &g_html_view_ops, NULL);

    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        atk_widget_destroy(view);
        return NULL;
    }
    priv->child_node = NULL;
    priv->scrollbar = NULL;
    priv->scrollbar_width = ATK_HTML_VIEW_SCROLLBAR_WIDTH;
    priv->scroll_y = 0;
    priv->content_height = 0;
    priv->last_width = width;
    priv->last_height = height;
    priv->doc = NULL;
    priv->sheet = NULL;
    priv->external_css = NULL;
    priv->external_css_len = 0;
    priv->images = NULL;
    priv->controls = NULL;
    priv->render_cache.tile_h = ATK_HTML_VIEW_RENDER_TILE_H;

    atk_list_node_t *child_node = atk_list_push_back(&wpriv->children, view);
    if (!child_node)
    {
        atk_widget_destroy(view);
        return NULL;
    }
    priv->child_node = child_node;

    int sb_x = x + width - priv->scrollbar_width;
    if (sb_x < x)
    {
        sb_x = x;
    }
    atk_widget_t *scrollbar = atk_window_add_scrollbar(window,
                                                       sb_x,
                                                       y,
                                                       priv->scrollbar_width,
                                                       height,
                                                       ATK_SCROLLBAR_VERTICAL);
    if (scrollbar)
    {
        priv->scrollbar = scrollbar;
        atk_scrollbar_set_change_handler(scrollbar, html_view_scrollbar_changed, view);
        html_view_update_scrollbar(view, priv);
    }

    return view;
}

void atk_html_view_set_document(atk_widget_t *view, html_document_t *doc)
{
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        if (doc)
        {
            html_document_destroy(doc);
        }
        return;
    }

    html_view_render_cache_clear(&priv->render_cache);

    if (priv->doc)
    {
        html_document_destroy(priv->doc);
    }
    html_view_controls_clear(view, priv);
    html_view_images_clear(priv);
    if (priv->external_css)
    {
        free(priv->external_css);
        priv->external_css = NULL;
        priv->external_css_len = 0;
    }
    priv->doc = doc;
    priv->scroll_y = 0;
    html_view_rebuild_stylesheet(priv);
    html_view_controls_build(view, priv);
    html_view_invalidate(view);
}

bool atk_html_view_set_html(atk_widget_t *view, const char *html, html_parse_error_t *error_out)
{
    html_parse_error_t tmp = {0};
    if (!error_out)
    {
        error_out = &tmp;
    }
    html_document_t *doc = html_parse(html, error_out);
    if (!doc)
    {
        return false;
    }
    atk_html_view_set_document(view, doc);
    return true;
}

void atk_html_view_set_external_stylesheet(atk_widget_t *view, const char *css_text)
{
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        return;
    }

    html_view_render_cache_clear(&priv->render_cache);

    if (priv->external_css)
    {
        free(priv->external_css);
        priv->external_css = NULL;
        priv->external_css_len = 0;
    }

    if (css_text && css_text[0] != '\0')
    {
        priv->external_css = html_view_strdup(css_text);
        if (priv->external_css)
        {
            priv->external_css_len = strlen(priv->external_css);
        }
    }

    html_view_rebuild_stylesheet(priv);
    html_view_invalidate(view);
}

bool atk_html_view_add_image_png(atk_widget_t *view, const char *src, const uint8_t *data, size_t size)
{
    if (!view || !src || src[0] == '\0' || !data || size == 0)
    {
        return false;
    }

    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        return false;
    }

    if (html_view_image_find(priv, src))
    {
        return true;
    }

    video_color_t *pixels = NULL;
    int w = 0;
    int h = 0;
    int stride_bytes = 0;
    int rc = png_decode_rgba32(data, size, &pixels, &w, &h, &stride_bytes);
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

    html_view_render_cache_clear(&priv->render_cache);
    html_view_invalidate(view);
    return true;
}
