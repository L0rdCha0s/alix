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

#define HTML_VIEW_FONT_CACHE_FIRST 32
#define HTML_VIEW_FONT_CACHE_LAST  126
#define HTML_VIEW_FONT_CACHE_COUNT (HTML_VIEW_FONT_CACHE_LAST - HTML_VIEW_FONT_CACHE_FIRST + 1)
#define HTML_VIEW_FONT_EXTRA_CACHE_SLOTS 256
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
    bool ready;
    ttf_font_t font;
    ttf_font_metrics_t metrics;
    int pixel_height;
    html_view_font_glyph_t glyphs[HTML_VIEW_FONT_CACHE_COUNT];
    html_view_font_glyph_entry_t extra_glyphs[HTML_VIEW_FONT_EXTRA_CACHE_SLOTS];
    uint32_t use_counter;
    uint8_t *font_blob;
    size_t font_blob_size;
} html_view_font_state_t;

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
    bool pending_space;
    bool draw;
    html_view_style_block_t *style_block;
    size_t style_depth;
} html_view_ctx_t;

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

static void html_view_font_state_clear_glyphs(html_view_font_state_t *state)
{
    if (!state)
    {
        return;
    }

    for (size_t i = 0; i < HTML_VIEW_FONT_CACHE_COUNT; ++i)
    {
        html_view_font_glyph_free(&state->glyphs[i]);
    }

    for (size_t i = 0; i < HTML_VIEW_FONT_EXTRA_CACHE_SLOTS; ++i)
    {
        html_view_font_glyph_free(&state->extra_glyphs[i].glyph);
        state->extra_glyphs[i].codepoint = 0;
        state->extra_glyphs[i].last_used = 0;
    }

    state->use_counter = 0;
}

static void html_view_font_state_reset(html_view_font_state_t *state)
{
    if (!state)
    {
        return;
    }

    html_view_font_state_clear_glyphs(state);
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

static bool html_view_font_state_set_size(html_view_font_state_t *state, int pixel_height)
{
    if (!state)
    {
        return false;
    }
    if (pixel_height < 6)
    {
        pixel_height = 6;
    }
    if (!html_view_font_state_load(state))
    {
        return false;
    }
    if (state->pixel_height == pixel_height)
    {
        return true;
    }

    html_view_font_state_clear_glyphs(state);
    state->pixel_height = pixel_height;
    if (!ttf_font_metrics(&state->font, pixel_height, &state->metrics))
    {
        state->metrics.ascent = pixel_height;
        state->metrics.descent = pixel_height / 4;
        state->metrics.line_gap = 0;
    }
    return true;
}

static bool html_view_font_render_glyph(html_view_font_state_t *state, uint32_t codepoint, html_view_font_glyph_t *out)
{
    if (!state || !out)
    {
        return false;
    }

    ttf_bitmap_t bitmap = {0};
    ttf_glyph_metrics_t metrics = {0};
    if (!ttf_font_render_glyph_bitmap(&state->font, codepoint, state->pixel_height, &bitmap, &metrics))
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

static html_view_font_glyph_t *html_view_font_state_get_glyph(html_view_font_state_t *state, uint32_t codepoint)
{
    if (!state || !state->ready || state->pixel_height <= 0)
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
        html_view_font_glyph_t *glyph = &state->glyphs[idx];
        if (!glyph->ready)
        {
            (void)html_view_font_render_glyph(state, codepoint, glyph);
        }
        return glyph;
    }

    uint32_t tick = ++state->use_counter;
    html_view_font_glyph_entry_t *slot = NULL;
    html_view_font_glyph_entry_t *oldest = NULL;

    for (size_t i = 0; i < HTML_VIEW_FONT_EXTRA_CACHE_SLOTS; ++i)
    {
        html_view_font_glyph_entry_t *entry = &state->extra_glyphs[i];
        if (entry->codepoint == codepoint)
        {
            entry->last_used = tick;
            if (!entry->glyph.ready)
            {
                (void)html_view_font_render_glyph(state, codepoint, &entry->glyph);
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
    (void)html_view_font_render_glyph(state, codepoint, &slot->glyph);
    return &slot->glyph;
}

static bool html_view_use_view_font(const html_view_ctx_t *ctx)
{
    if (!ctx || !ctx->priv)
    {
        return false;
    }
    if (ctx->actual_font_px <= 0)
    {
        return false;
    }
    if (!ctx->priv->font.ready)
    {
        return false;
    }
    return ctx->priv->font.pixel_height == ctx->actual_font_px;
}

static int html_view_text_width(const html_view_ctx_t *ctx, const char *text)
{
    if (!ctx || !text || *text == '\0')
    {
        return 0;
    }

    if (!html_view_use_view_font(ctx))
    {
        return atk_font_text_width(text);
    }

    html_view_font_state_t *font = &ctx->priv->font;
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

        html_view_font_glyph_t *glyph = html_view_font_state_get_glyph(font, dec.codepoint);
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

    if (!html_view_use_view_font(ctx))
    {
        return atk_font_baseline_for_rect(top, height);
    }

    html_view_font_state_t *font = &ctx->priv->font;
    int ascent = font->metrics.ascent;
    int descent = font->metrics.descent;
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

    if (!html_view_use_view_font(ctx))
    {
        atk_font_draw_string_clipped(x, baseline_y, text, fg, ctx->bg, clip);
        return;
    }

    html_view_font_state_t *font = &ctx->priv->font;

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

        html_view_font_glyph_t *glyph = html_view_font_state_get_glyph(font, dec.codepoint);
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

static bool html_view_selector_matches_range(const char *sel_start,
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

    if (*sel_start == '#')
    {
        const char *id = html_attr_get(node, "id");
        if (!id || id[0] == '\0')
        {
            return false;
        }
        sel_start++;
        html_view_trim_range(&sel_start, &sel_end);
        if (sel_end <= sel_start)
        {
            return false;
        }
        size_t len = (size_t)(sel_end - sel_start);
        if (strlen(id) != len)
        {
            return false;
        }
        return strncasecmp(id, sel_start, len) == 0;
    }

    const char *end = sel_start;
    while (end < sel_end && *end != ':' && *end != '.' && *end != '#' && *end != '[' && !isspace((unsigned char)*end))
    {
        end++;
    }
    size_t len = (size_t)(end - sel_start);
    if (len == 0)
    {
        return false;
    }
    if (strlen(node->name) != len)
    {
        return false;
    }
    return strncasecmp(node->name, sel_start, len) == 0;
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

    /* Very small selector subset: tag, #id, and a single descendant "A B". */
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
        return html_view_selector_matches_range(start, end, node);
    }

    const char *target_start = last_space;
    while (target_start < end && isspace((unsigned char)*target_start))
    {
        target_start++;
    }
    if (!html_view_selector_matches_range(target_start, end, node))
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
        if (html_view_selector_matches_range(ancestor_start, ancestor_end, p))
        {
            return true;
        }
    }
    return false;
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

static css_style_t html_view_style_for_node(const css_stylesheet_t *sheet, const css_style_t *parent, const html_node_t *node)
{
    css_style_t out = {0};
    if (parent)
    {
        if (parent->has_color)
        {
            out.has_color = true;
            out.color = parent->color;
        }
        if (parent->has_font_size)
        {
            out.has_font_size = true;
            out.font_size = parent->font_size;
        }
        if (parent->has_line_height)
        {
            out.has_line_height = true;
            out.line_height_milli = parent->line_height_milli;
        }
        if (parent->has_text_align)
        {
            out.has_text_align = true;
            out.text_align = parent->text_align;
        }
        if (parent->has_letter_spacing)
        {
            out.has_letter_spacing = true;
            out.letter_spacing = parent->letter_spacing;
        }
    }

    if (sheet && node && node->type == HTML_NODE_ELEMENT)
    {
        for (const css_rule_t *rule = sheet->rules; rule; rule = rule->next)
        {
            if (rule->selector && html_view_selector_matches(rule->selector, node))
            {
                css_style_merge(&out, &rule->style);
            }
        }
    }

    const char *inline_style = html_attr_get(node, "style");
    if (inline_style && inline_style[0] != '\0')
    {
        html_view_apply_inline_style(&out, inline_style);
    }

    return out;
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
    *slot = html_view_style_for_node(ctx->sheet, parent, node);
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

static void html_view_draw_rect_clipped(int x, int y, int w, int h, video_color_t color, const atk_rect_t *clip)
{
    if (w <= 0 || h <= 0)
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

static void html_view_draw_border_clipped(int x,
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

    html_view_draw_rect_clipped(x, y, w, thickness, color, clip);                    /* top */
    html_view_draw_rect_clipped(x, y + h - thickness, w, thickness, color, clip);   /* bottom */
    html_view_draw_rect_clipped(x, y + thickness, thickness, h - thickness * 2, color, clip); /* left */
    html_view_draw_rect_clipped(x + w - thickness, y + thickness, thickness, h - thickness * 2, color, clip); /* right */
}

static void html_view_blit_rgba32_clipped(int dst_x,
                                         int dst_y,
                                         int width,
                                         int height,
                                         const video_color_t *pixels,
                                         int stride_bytes,
                                         const atk_rect_t *clip)
{
    if (!pixels || width <= 0 || height <= 0 || stride_bytes <= 0)
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

static void html_view_draw_border_sides_clipped(int x,
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
        html_view_draw_rect_clipped(x, y, w, top, color, clip);
    }
    if (bottom > 0)
    {
        html_view_draw_rect_clipped(x, y + h - bottom, w, bottom, color, clip);
    }

    int inner_y = y + top;
    int inner_h = h - top - bottom;
    if (inner_h <= 0)
    {
        return;
    }
    if (left > 0)
    {
        html_view_draw_rect_clipped(x, inner_y, left, inner_h, color, clip);
    }
    if (right > 0)
    {
        html_view_draw_rect_clipped(x + w - right, inner_y, right, inner_h, color, clip);
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

    if (ctx->draw && html_view_line_visible(ctx))
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
                video_draw_rect(draw_x, underline_y, w, 1, color);
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
    if (ctx->draw && child)
    {
        html_view_place_control_widget(ctx, child, abs_x, abs_y, width, height);
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
    if (ctx->draw && child)
    {
        html_view_place_control_widget(ctx, child, abs_x, abs_y, width, height);
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
            html_view_draw_rect_clipped(border_box_x, draw_y, border_box_w, border_box_h, style->background, &ctx->clip);
        }

        if (style->has_border && (border_top > 0 || border_right > 0 || border_bottom > 0 || border_left > 0))
        {
            video_color_t border_color = style->has_border_color ? style->border_color : video_make_color(0x00, 0x00, 0x00);
            html_view_draw_border_sides_clipped(border_box_x,
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
        html_view_draw_text(ctx, node->text, color, false, false);
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

    if (style->has_display && style->display == CSS_DISPLAY_NONE)
    {
        goto out;
    }

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

            if (ctx->draw && html_view_line_visible(ctx))
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

        if (ctx->draw && html_view_line_visible(ctx))
        {
            html_view_draw_rect_clipped(bullet_x, bullet_draw_y, bullet_size, bullet_size, bullet_color, &ctx->clip);
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

        if (img && img_w > 0 && img_h > 0)
        {
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
            if (ctx->draw)
            {
                html_view_blit_rgba32_clipped(draw_x, draw_y, img_w, img_h, img->pixels, img->stride_bytes, &ctx->clip);
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

    if (strcmp(tag, "a") == 0)
    {
        video_color_t color = style->has_color ? style->color : video_make_color(0x00, 0x33, 0x88);
        for (const html_node_t *child = node->first_child; child; child = child->next_sibling)
        {
            if (child->type == HTML_NODE_TEXT && child->text)
            {
                html_view_draw_text(ctx, child->text, color, true, false);
            }
            else
            {
                html_view_render_node(ctx, child, style);
            }
        }
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

    css_style_t html_style = html_node ? html_view_style_for_node(priv->sheet, &base_style, html_node) : base_style;
    css_style_t body_style = body_node ? html_view_style_for_node(priv->sheet, &html_style, body_node) : html_style;
    video_color_t page_bg = html_style.has_background ? html_style.background : default_page_bg;
    video_color_t body_bg = body_style.has_background ? body_style.background : default_page_bg;

    video_draw_rect(abs_x, abs_y, widget->width, widget->height, page_bg);
    video_draw_rect_outline(abs_x, abs_y, widget->width, widget->height, state->theme.window_border);

    atk_rect_t clip = { viewport_x, viewport_y, viewport_w, viewport_h };

    int actual_font_px = atk_font_line_height();
    int css_font_px = actual_font_px;
    if (html_style.has_font_size && html_style.font_size.valid && !html_style.font_size.is_auto)
    {
        int computed = html_view_length_to_px(&html_style.font_size,
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

    html_view_float_ctx_t floats_layout = {0};

    int render_font_px = base_font_px;
    if (render_font_px > 0 && render_font_px < 12)
    {
        render_font_px += 2;
    }

    (void)html_view_font_state_set_size(&priv->font, render_font_px);
    int effective_font_px = (priv->font.ready && priv->font.pixel_height == render_font_px) ? render_font_px
                                                                                           : atk_font_line_height();

    html_view_ctx_t layout = {
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
        .floats = &floats_layout,
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
        .draw = false
    };

    layout.space_w = html_view_text_width(&layout, " ");

    if (body)
    {
        html_view_render_children(&layout, body, &body_style);
    }
    else
    {
        html_view_draw_text(&layout, "No document.\n", default_text, false, false);
    }

    html_view_style_stack_destroy(&layout);

    int body_box_h = (layout.content_bottom - body_box_y0) + pad_bottom + border_px;
    int min_h = border_px * 2 + pad_top + pad_bottom;
    if (body_box_h < min_h)
    {
        body_box_h = min_h;
    }

    int body_draw_y = body_box_y0 - priv->scroll_y;
    html_view_draw_rect_clipped(body_box_x, body_draw_y, body_box_w, body_box_h, body_bg, &clip);
    if (border_px > 0)
    {
        video_color_t border_color = body_style.has_border_color ? body_style.border_color : video_make_color(0x00, 0x00, 0x00);
        html_view_draw_border_clipped(body_box_x, body_draw_y, body_box_w, body_box_h, border_px, border_color, &clip);
    }

    html_view_float_ctx_t floats_draw = {0};
    html_view_ctx_t ctx = layout;
    ctx.floats = &floats_draw;
    ctx.draw = true;
    ctx.x = body_content_x;
    ctx.y = body_content_y0;
    ctx.content_bottom = body_content_y0;
    ctx.list_level = 0;
    ctx.line_height = base_line_height;
    ctx.pending_space = false;

    if (body)
    {
        html_view_render_children(&ctx, body, &body_style);
    }
    else
    {
        html_view_draw_text(&ctx, "No document.\n", default_text, false, false);
    }

    html_view_style_stack_destroy(&ctx);

    int final_bottom = ctx.content_bottom;
    int body_bottom = body_box_y0 + body_box_h;
    if (body_bottom > final_bottom)
    {
        final_bottom = body_bottom;
    }

    priv->content_height = final_bottom - viewport_y;
    if (priv->content_height < 0)
    {
        priv->content_height = 0;
    }

    if (priv->scrollbar)
    {
        html_view_update_scrollbar((atk_widget_t *)widget, priv);
    }
}

static void html_view_destroy_cb(atk_widget_t *widget, void *context)
{
    (void)context;
    atk_html_view_priv_t *priv = html_view_priv_mut(widget);
    if (priv)
    {
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

    html_view_invalidate(view);
    return true;
}
