#include "atk/atk_html_view.h"

#include "atk/atk_font.h"
#include "atk/atk_scrollbar.h"
#include "atk_internal.h"
#include "ctype.h"
#include "libc.h"
#include "video.h"
#include "web/css.h"
#include "web/html.h"

#define ATK_HTML_VIEW_PADDING 8
#define ATK_HTML_VIEW_SCROLLBAR_WIDTH 14

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
    int line_height;
    int space_w;
    int x;
    int y;
    int max_x;
    int content_bottom;
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
           strcmp(tag, "h1") == 0;
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
        video_color_t color = parent_style->has_color ? parent_style->color : video_make_color(0x10, 0x10, 0x10);
        html_view_draw_text(ctx, node->text, color, false, false);
        return;
    }

    if (node->type != HTML_NODE_ELEMENT || !node->name)
    {
        return;
    }

    const char *tag = node->name;
    if (strcmp(tag, "head") == 0 || strcmp(tag, "style") == 0 || strcmp(tag, "meta") == 0 || strcmp(tag, "title") == 0)
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
        ctx->y += ctx->line_height / 2;
        ctx->pending_space = false;

        video_color_t color = style.has_color ? style.color : video_make_color(0x10, 0x10, 0x10);
        for (const html_node_t *child = node->first_child; child; child = child->next_sibling)
        {
            if (child->type == HTML_NODE_TEXT && child->text)
            {
                html_view_draw_text(ctx, child->text, color, false, true);
            }
        }
        html_view_new_line(ctx);
        ctx->y += ctx->line_height / 4;
        ctx->pending_space = false;
        return;
    }

    if (strcmp(tag, "p") == 0)
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
        html_view_render_children(ctx, node, &style);
        html_view_new_line(ctx);
        ctx->pending_space = false;
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

    video_color_t default_bg = state->theme.window_body;
    video_color_t default_text = video_make_color(0x10, 0x10, 0x10);

    css_style_t base_style = {0};
    base_style.has_color = true;
    base_style.color = default_text;

    css_style_t body_style = html_view_style_for_tag(priv->sheet, &base_style, "body");
    video_color_t bg = body_style.has_background ? body_style.background : default_bg;

    video_draw_rect(abs_x, abs_y, widget->width, widget->height, bg);
    video_draw_rect_outline(abs_x, abs_y, widget->width, widget->height, state->theme.window_border);

    atk_rect_t clip = { viewport_x, viewport_y, viewport_w, viewport_h };

    int body_w = viewport_w;
    if (body_style.has_width)
    {
        int computed = html_view_length_to_px(&body_style.width, viewport_w, viewport_h, atk_font_line_height(), true);
        if (computed > 0 && computed < body_w)
        {
            body_w = computed;
        }
    }
    if (body_w < 0) body_w = 0;
    if (body_w > viewport_w) body_w = viewport_w;

    int body_x = viewport_x;
    if (body_style.has_margin)
    {
        bool auto_left = body_style.margin.left.valid && body_style.margin.left.is_auto;
        bool auto_right = body_style.margin.right.valid && body_style.margin.right.is_auto;
        if (auto_left && auto_right)
        {
            body_x = viewport_x + (viewport_w - body_w) / 2;
        }
        else if (body_style.margin.left.valid && !body_style.margin.left.is_auto)
        {
            body_x = viewport_x + html_view_length_to_px(&body_style.margin.left, viewport_w, viewport_h, atk_font_line_height(), true);
        }
    }

    int margin_top = 0;
    if (body_style.has_margin && body_style.margin.top.valid && !body_style.margin.top.is_auto)
    {
        margin_top = html_view_length_to_px(&body_style.margin.top, viewport_w, viewport_h, atk_font_line_height(), false);
    }

    const html_node_t *body = NULL;
    if (priv->doc && priv->doc->root)
    {
        body = html_view_find_first_element(priv->doc->root, "body");
    }

    html_view_ctx_t ctx = {
        .state = state,
        .widget = widget,
        .priv = priv,
        .sheet = priv->sheet,
        .bg = bg,
        .clip = clip,
        .viewport_x = viewport_x,
        .viewport_y = viewport_y,
        .viewport_w = viewport_w,
        .viewport_h = viewport_h,
        .body_x = body_x,
        .body_w = body_w,
        .line_height = atk_font_line_height() + 4,
        .space_w = atk_font_text_width(" "),
        .x = body_x,
        .y = viewport_y + margin_top,
        .max_x = body_x + body_w,
        .content_bottom = viewport_y + margin_top,
        .pending_space = false
    };

    if (ctx.line_height < 8)
    {
        ctx.line_height = 8;
    }

    if (body)
    {
        ctx.draw = true;
        html_view_render_children(&ctx, body, &body_style);
    }
    else
    {
        ctx.draw = true;
        html_view_draw_text(&ctx, "No document.\n", default_text, false, false);
    }

    priv->content_height = ctx.content_bottom - viewport_y;
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
