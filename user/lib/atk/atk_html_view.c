#include "atk/atk_html_view.h"

#include "atk/atk_font.h"
#include "atk/atk_scrollbar.h"
#include "atk/util/png.h"
#include "atk_internal.h"
#include "ctype.h"
#include "libc.h"
#include "video.h"
#include "web/css.h"
#include "web/html.h"

#define ATK_HTML_VIEW_PADDING 8
#define ATK_HTML_VIEW_SCROLLBAR_WIDTH 14

typedef struct html_view_image
{
    char *src;
    video_color_t *pixels;
    int width;
    int height;
    int stride_bytes;
    struct html_view_image *next;
} html_view_image_t;

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
} atk_html_view_priv_t;

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
    int body_x;
    int body_w;
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

    for (const html_node_t *child = node->first_child; child; child = child->next_sibling)
    {
        if (child->type == HTML_NODE_ELEMENT && child->name && strcmp(child->name, "style") == 0)
        {
            for (const html_node_t *txt = child->first_child; txt; txt = txt->next_sibling)
            {
                if (txt->type == HTML_NODE_TEXT && txt->text)
                {
                    (void)html_view_buf_append(buf, len, cap, txt->text, strlen(txt->text));
                    (void)html_view_buf_append(buf, len, cap, "\n", 1);
                }
            }
            continue;
        }

        html_view_collect_style_text(child, buf, len, cap);
    }
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

static css_style_t html_view_style_for_tag(const css_stylesheet_t *sheet, const css_style_t *parent, const char *tag)
{
    css_style_t out = parent ? *parent : (css_style_t){0};
    if (!sheet || !tag || tag[0] == '\0')
    {
        return out;
    }
    for (const css_rule_t *rule = sheet->rules; rule; rule = rule->next)
    {
        if (css_rule_matches_tag(rule, tag))
        {
            css_style_merge(&out, &rule->style);
        }
    }
    return out;
}

static int html_view_length_to_px(const css_length_t *len, int viewport_w, int viewport_h, int base_font_px, bool horizontal)
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
            return (int)(((int64_t)viewport_w * (int64_t)v) / 100000LL);
        case CSS_UNIT_VH:
            return (int)(((int64_t)viewport_h * (int64_t)v) / 100000LL);
        case CSS_UNIT_PERCENT:
        {
            int ref = horizontal ? viewport_w : viewport_h;
            return (int)(((int64_t)ref * (int64_t)v) / 100000LL);
        }
        case CSS_UNIT_EM:
            return (int)(((int64_t)base_font_px * (int64_t)v) / 1000LL);
        case CSS_UNIT_PX:
        case CSS_UNIT_NONE:
        default:
            return (int)(v / 1000);
    }
}

static int html_view_line_height_for_style(const html_view_ctx_t *ctx, const css_style_t *style)
{
    if (!ctx)
    {
        return atk_font_line_height() + 4;
    }

    int base_font_px = ctx->base_font_px > 0 ? ctx->base_font_px : atk_font_line_height();
    int line_height = ctx->base_line_height > 0 ? ctx->base_line_height : (base_font_px + 4);

    if (style && style->has_line_height && style->line_height_milli > 0)
    {
        line_height = (int)(((int64_t)base_font_px * (int64_t)style->line_height_milli) / 1000LL);
        if (line_height < base_font_px)
        {
            line_height = base_font_px;
        }
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

    int w = atk_font_text_width(text);

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
    int baseline = atk_font_baseline_for_rect(draw_top, ctx->line_height);

    if (ctx->draw && html_view_line_visible(ctx))
    {
        atk_font_draw_string_clipped(draw_x, baseline, text, color, ctx->bg, &ctx->clip);
        if (bold)
        {
            atk_font_draw_string_clipped(draw_x + 1, baseline, text, color, ctx->bg, &ctx->clip);
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

static bool html_view_is_block_tag(const char *tag)
{
    if (!tag)
    {
        return false;
    }
    return strcmp(tag, "body") == 0 ||
           strcmp(tag, "div") == 0 ||
           strcmp(tag, "p") == 0 ||
           strcmp(tag, "h1") == 0 ||
           strcmp(tag, "ul") == 0 ||
           strcmp(tag, "li") == 0 ||
           strcmp(tag, "img") == 0;
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

    css_style_t style = html_view_style_for_tag(ctx->sheet, parent_style, tag);
    bool block = html_view_is_block_tag(tag);

    if (strcmp(tag, "br") == 0)
    {
        html_view_new_line(ctx);
        return;
    }

    if (strcmp(tag, "h1") == 0)
    {
        if (ctx->x != ctx->body_x)
        {
            html_view_new_line(ctx);
        }

        int pad_top = 0;
        int pad_bottom = 0;
        if (style.has_padding)
        {
            pad_top = html_view_length_to_px(&style.padding.top,
                                             ctx->viewport_w,
                                             ctx->viewport_h,
                                             ctx->base_font_px,
                                             false);
            pad_bottom = html_view_length_to_px(&style.padding.bottom,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                ctx->base_font_px,
                                                false);
        }

        ctx->y += pad_top;
        ctx->pending_space = false;

        video_color_t color = style.has_color ? style.color : video_make_color(0x00, 0x00, 0x00);

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
            int text_w = atk_font_text_width(text);
            int draw_x = ctx->body_x;
            if (style.has_text_align)
            {
                if (style.text_align == CSS_TEXT_ALIGN_CENTER)
                {
                    draw_x = ctx->body_x + (ctx->body_w - text_w) / 2;
                }
                else if (style.text_align == CSS_TEXT_ALIGN_RIGHT)
                {
                    draw_x = ctx->body_x + (ctx->body_w - text_w);
                }
            }
            if (draw_x < ctx->body_x)
            {
                draw_x = ctx->body_x;
            }

            int draw_top = ctx->y - ctx->priv->scroll_y;
            int baseline = atk_font_baseline_for_rect(draw_top, ctx->line_height);

            if (ctx->draw && html_view_line_visible(ctx))
            {
                if (style.has_text_shadow)
                {
                    int dx = html_view_length_to_px(&style.text_shadow_x,
                                                    ctx->viewport_w,
                                                    ctx->viewport_h,
                                                    ctx->base_font_px,
                                                    true);
                    int dy = html_view_length_to_px(&style.text_shadow_y,
                                                    ctx->viewport_w,
                                                    ctx->viewport_h,
                                                    ctx->base_font_px,
                                                    false);
                    video_color_t shadow = style.has_text_shadow_color ? style.text_shadow_color : video_make_color(0x00, 0x00, 0x00);
                    atk_font_draw_string_clipped(draw_x + dx, baseline + dy, text, shadow, ctx->bg, &ctx->clip);
                    atk_font_draw_string_clipped(draw_x + dx + 1, baseline + dy, text, shadow, ctx->bg, &ctx->clip);
                }

                atk_font_draw_string_clipped(draw_x, baseline, text, color, ctx->bg, &ctx->clip);
                atk_font_draw_string_clipped(draw_x + 1, baseline, text, color, ctx->bg, &ctx->clip);
            }

            ctx->x = ctx->body_x;
            ctx->pending_space = false;
            html_view_ensure_line_visible(ctx);
        }
        free(text);

        html_view_new_line(ctx);
        ctx->y += pad_bottom;
        ctx->pending_space = false;
        return;
    }

    if (strcmp(tag, "p") == 0)
    {
        if (ctx->x != ctx->body_x)
        {
            html_view_new_line(ctx);
        }
        int saved_line_height = ctx->line_height;
        ctx->line_height = html_view_line_height_for_style(ctx, &style);
        if (ctx->y > ctx->viewport_y)
        {
            ctx->y += ctx->line_height / 3;
        }
        ctx->pending_space = false;
        html_view_render_children(ctx, node, &style);
        html_view_new_line(ctx);
        ctx->line_height = saved_line_height;
        ctx->pending_space = false;
        return;
    }

    if (strcmp(tag, "ul") == 0)
    {
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
        html_view_render_children(ctx, node, &style);
        if (ctx->list_level > 0)
        {
            ctx->list_level -= 1;
        }
        if (ctx->x != ctx->body_x)
        {
            html_view_new_line(ctx);
        }
        ctx->pending_space = false;
        return;
    }

    if (strcmp(tag, "li") == 0)
    {
        if (ctx->x != ctx->body_x)
        {
            html_view_new_line(ctx);
        }

        int saved_body_x = ctx->body_x;
        int saved_max_x = ctx->max_x;
        int saved_line_height = ctx->line_height;
        ctx->line_height = html_view_line_height_for_style(ctx, &style);

        int level = ctx->list_level > 0 ? ctx->list_level : 1;
        int indent = level * 32;
        int bullet_size = 4;
        int bullet_x = saved_body_x + indent - 16;
        int bullet_draw_y = (ctx->y - ctx->priv->scroll_y) + ctx->line_height / 2 - bullet_size / 2;
        video_color_t bullet_color = style.has_color ? style.color : video_make_color(0x00, 0x00, 0x00);

        if (ctx->draw && html_view_line_visible(ctx))
        {
            html_view_draw_rect_clipped(bullet_x, bullet_draw_y, bullet_size, bullet_size, bullet_color, &ctx->clip);
        }

        ctx->body_x = saved_body_x + indent;
        ctx->x = ctx->body_x;
        ctx->max_x = saved_max_x;
        ctx->pending_space = false;

        html_view_render_children(ctx, node, &style);
        html_view_new_line(ctx);

        ctx->body_x = saved_body_x;
        ctx->x = ctx->body_x;
        ctx->max_x = saved_max_x;
        ctx->line_height = saved_line_height;
        ctx->pending_space = false;
        return;
    }

    if (strcmp(tag, "img") == 0)
    {
        if (ctx->x != ctx->body_x)
        {
            html_view_new_line(ctx);
        }

        int margin_top = 0;
        int margin_bottom = 0;
        if (style.has_margin)
        {
            if (style.margin.top.valid && !style.margin.top.is_auto)
            {
                margin_top = html_view_length_to_px(&style.margin.top,
                                                    ctx->viewport_w,
                                                    ctx->viewport_h,
                                                    ctx->base_font_px,
                                                    false);
            }
            if (style.margin.bottom.valid && !style.margin.bottom.is_auto)
            {
                margin_bottom = html_view_length_to_px(&style.margin.bottom,
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
            if (style.has_margin)
            {
                bool auto_left = style.margin.left.valid && style.margin.left.is_auto;
                bool auto_right = style.margin.right.valid && style.margin.right.is_auto;
                if (auto_left && auto_right)
                {
                    draw_x = ctx->body_x + (ctx->body_w - img_w) / 2;
                }
                else if (style.margin.left.valid && !style.margin.left.is_auto)
                {
                    draw_x = ctx->body_x + html_view_length_to_px(&style.margin.left,
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
            video_color_t color = style.has_color ? style.color : video_make_color(0x00, 0x00, 0x00);
            html_view_draw_text(ctx, alt, color, false, false);
            html_view_new_line(ctx);
        }

        ctx->y += margin_bottom;
        ctx->x = ctx->body_x;
        ctx->pending_space = false;
        html_view_ensure_line_visible(ctx);
        return;
    }

    if (strcmp(tag, "a") == 0)
    {
        video_color_t color = style.has_color ? style.color : video_make_color(0x00, 0x33, 0x88);
        for (const html_node_t *child = node->first_child; child; child = child->next_sibling)
        {
            if (child->type == HTML_NODE_TEXT && child->text)
            {
                html_view_draw_text(ctx, child->text, color, true, false);
            }
            else
            {
                html_view_render_node(ctx, child, &style);
            }
        }
        return;
    }

    if (block && ctx->x != ctx->body_x)
    {
        html_view_new_line(ctx);
    }
    html_view_render_children(ctx, node, &style);
    if (block && ctx->x != ctx->body_x)
    {
        html_view_new_line(ctx);
    }
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

    css_style_t html_style = html_view_style_for_tag(priv->sheet, &base_style, "html");
    css_style_t body_style = html_view_style_for_tag(priv->sheet, &base_style, "body");
    video_color_t page_bg = html_style.has_background ? html_style.background : default_page_bg;
    video_color_t body_bg = body_style.has_background ? body_style.background : default_page_bg;

    video_draw_rect(abs_x, abs_y, widget->width, widget->height, page_bg);
    video_draw_rect_outline(abs_x, abs_y, widget->width, widget->height, state->theme.window_border);

    atk_rect_t clip = { viewport_x, viewport_y, viewport_w, viewport_h };

    int base_font_px = atk_font_line_height();
    int base_line_height = base_font_px + 4;
    if (base_line_height < 8)
    {
        base_line_height = 8;
    }

    int border_px = 0;
    if (body_style.has_border)
    {
        border_px = html_view_length_to_px(&body_style.border_width, viewport_w, viewport_h, base_font_px, true);
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
        pad_top = html_view_length_to_px(&body_style.padding.top, viewport_w, viewport_h, base_font_px, false);
        pad_right = html_view_length_to_px(&body_style.padding.right, viewport_w, viewport_h, base_font_px, true);
        pad_bottom = html_view_length_to_px(&body_style.padding.bottom, viewport_w, viewport_h, base_font_px, false);
        pad_left = html_view_length_to_px(&body_style.padding.left, viewport_w, viewport_h, base_font_px, true);
        if (pad_top < 0) pad_top = 0;
        if (pad_right < 0) pad_right = 0;
        if (pad_bottom < 0) pad_bottom = 0;
        if (pad_left < 0) pad_left = 0;
    }

    int body_content_w = viewport_w;
    if (body_style.has_width)
    {
        int computed = html_view_length_to_px(&body_style.width, viewport_w, viewport_h, base_font_px, true);
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
            body_box_x = viewport_x + html_view_length_to_px(&body_style.margin.left, viewport_w, viewport_h, base_font_px, true);
        }
    }

    int margin_top = 0;
    if (body_style.has_margin && body_style.margin.top.valid && !body_style.margin.top.is_auto)
    {
        margin_top = html_view_length_to_px(&body_style.margin.top, viewport_w, viewport_h, base_font_px, false);
    }

    const html_node_t *body = NULL;
    if (priv->doc && priv->doc->root)
    {
        body = html_view_find_first_element(priv->doc->root, "body");
    }

    int body_box_y0 = viewport_y + margin_top;
    int body_content_x = body_box_x + border_px + pad_left;
    int body_content_y0 = body_box_y0 + border_px + pad_top;

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
        .body_x = body_content_x,
        .body_w = body_content_w,
        .base_font_px = base_font_px,
        .base_line_height = base_line_height,
        .line_height = base_line_height,
        .space_w = atk_font_text_width(" "),
        .x = body_content_x,
        .y = body_content_y0,
        .max_x = body_content_x + body_content_w,
        .content_bottom = body_content_y0,
        .list_level = 0,
        .pending_space = false,
        .draw = false
    };

    if (body)
    {
        html_view_render_children(&layout, body, &body_style);
    }
    else
    {
        html_view_draw_text(&layout, "No document.\n", default_text, false, false);
    }

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

    html_view_ctx_t ctx = layout;
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
