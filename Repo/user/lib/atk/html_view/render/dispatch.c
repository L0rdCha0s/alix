#include "atk/html_view/render/render_internal.h"
#include "serial.h"

#include <ctype.h>
#include "stdio.h"
#include <string.h>

void html_view_render_children(html_view_ctx_t *ctx, const html_node_t *node, const css_style_t *style);

#define HTML_VIEW_LARGE_FONT_PX 64
#define HTML_VIEW_LARGE_TEXT_SNIPPET 80

static bool html_view_text_has_non_ws_local(const char *text)
{
    if (!text)
    {
        return false;
    }
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p)
    {
        if (*p >= 0x80u || !isspace(*p))
        {
            return true;
        }
    }
    return false;
}

static void html_view_sanitize_text(const char *src, char *dst, size_t cap, size_t max_len)
{
    if (!dst || cap == 0)
    {
        return;
    }
    if (!src)
    {
        dst[0] = '\0';
        return;
    }

    size_t out = 0;
    size_t seen = 0;
    bool last_space = false;
    while (*src && out + 1 < cap && seen < max_len)
    {
        unsigned char ch = (unsigned char)*src++;
        seen++;
        if (ch < 0x20 || ch == 0x7F)
        {
            if (!last_space)
            {
                dst[out++] = ' ';
                last_space = true;
            }
            continue;
        }
        if (ch >= 0x80)
        {
            ch = '?';
        }
        if (isspace(ch))
        {
            if (!last_space)
            {
                dst[out++] = ' ';
                last_space = true;
            }
            continue;
        }
        dst[out++] = (char)ch;
        last_space = false;
    }
    if ((*src || seen >= max_len) && out + 4 < cap)
    {
        dst[out++] = '.';
        dst[out++] = '.';
        dst[out++] = '.';
    }
    dst[out] = '\0';
}

static const char *html_view_css_unit_name(css_unit_t unit)
{
    switch (unit)
    {
        case CSS_UNIT_PX: return "px";
        case CSS_UNIT_EM: return "em";
        case CSS_UNIT_VW: return "vw";
        case CSS_UNIT_VH: return "vh";
        case CSS_UNIT_PERCENT: return "%";
        case CSS_UNIT_NONE: default: return "";
    }
}

static void html_view_format_length(const css_length_t *len, char *buf, size_t cap)
{
    if (!buf || cap == 0)
    {
        return;
    }
    if (!len || !len->valid)
    {
        (void)snprintf(buf, cap, "unset");
        return;
    }
    if (len->is_auto)
    {
        (void)snprintf(buf, cap, "auto");
        return;
    }
    int32_t v = len->value_milli;
    int32_t whole = v / 1000;
    int32_t frac = v % 1000;
    if (frac < 0)
    {
        frac = -frac;
    }
    const char *unit = html_view_css_unit_name(len->unit);
    if (frac == 0)
    {
        (void)snprintf(buf, cap, "%d%s", whole, unit);
    }
    else
    {
        (void)snprintf(buf, cap, "%d.%03d%s", whole, frac, unit);
    }
}

static void html_view_format_line_height(const css_style_t *style, char *buf, size_t cap)
{
    if (!buf || cap == 0)
    {
        return;
    }
    if (!style || !style->has_line_height)
    {
        (void)snprintf(buf, cap, "inherit");
        return;
    }
    if (style->line_height_is_length)
    {
        html_view_format_length(&style->line_height, buf, cap);
        return;
    }
    int32_t v = style->line_height_milli;
    int32_t whole = v / 1000;
    int32_t frac = v % 1000;
    if (frac < 0)
    {
        frac = -frac;
    }
    if (frac == 0)
    {
        (void)snprintf(buf, cap, "%d", whole);
    }
    else
    {
        (void)snprintf(buf, cap, "%d.%03d", whole, frac);
    }
}

static void html_view_log_large_text(const html_view_ctx_t *ctx,
                                     const html_node_t *node,
                                     const css_style_t *style)
{
    if (!ctx || !node || !node->text || !style)
    {
        return;
    }
    if (ctx->actual_font_px < HTML_VIEW_LARGE_FONT_PX)
    {
        return;
    }
    if (!html_view_text_has_non_ws_local(node->text))
    {
        return;
    }

    char text_buf[96];
    char font_buf[32];
    char line_buf[32];
    char id_buf[48];
    char class_buf[96];
    const html_node_t *parent = node->parent;
    const char *tag = parent && parent->name ? parent->name : "?";
    const char *id = parent ? html_attr_get(parent, "id") : NULL;
    const char *class_name = parent ? html_attr_get(parent, "class") : NULL;

    html_view_sanitize_text(node->text, text_buf, sizeof(text_buf), HTML_VIEW_LARGE_TEXT_SNIPPET);
    if (style->has_font_size)
    {
        html_view_format_length(&style->font_size, font_buf, sizeof(font_buf));
    }
    else
    {
        (void)snprintf(font_buf, sizeof(font_buf), "inherit");
    }
    html_view_format_line_height(style, line_buf, sizeof(line_buf));
    html_view_sanitize_text(id, id_buf, sizeof(id_buf), 40);
    html_view_sanitize_text(class_name, class_buf, sizeof(class_buf), 72);

    serial_printf("[html_view] large_text tag=%s id=%s class=%s font_px=%d line_h=%d css_font=%s css_line=%s viewport=%dx%d text=\"%s\"",
                  tag,
                  id_buf[0] ? id_buf : "-",
                  class_buf[0] ? class_buf : "-",
                  ctx->actual_font_px,
                  ctx->line_height,
                  font_buf,
                  line_buf,
                  ctx->viewport_w,
                  ctx->viewport_h,
                  text_buf);
}

static bool html_view_attr_has_class_local(const html_node_t *node, const char *token)
{
    if (!node || !token || !*token)
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
        if (len == strlen(token) && strncasecmp(start, token, len) == 0)
        {
            return true;
        }
    }
    return false;
}

static bool html_view_node_has_ancestor_class_local(const html_node_t *node, const char *token)
{
    for (const html_node_t *cur = node; cur; cur = cur->parent)
    {
        if (html_view_attr_has_class_local(cur, token))
        {
            return true;
        }
    }
    return false;
}

void html_view_record_anchor(html_view_ctx_t *ctx, const html_node_t *node)
{
    if (!ctx || !ctx->record || !ctx->priv || !node || node->type != HTML_NODE_ELEMENT)
    {
        return;
    }

    const char *id = html_attr_get(node, "id");
    if (id && id[0] != '\0')
    {
        int doc_y = ctx->y - ctx->doc_origin_y;
        (void)html_view_render_cache_add_anchor(&ctx->priv->render_cache, id, doc_y);
    }

    const char *name = html_attr_get(node, "name");
    if (name && name[0] != '\0' && (!id || strcmp(id, name) != 0))
    {
        int doc_y = ctx->y - ctx->doc_origin_y;
        (void)html_view_render_cache_add_anchor(&ctx->priv->render_cache, name, doc_y);
    }
}

static void html_view_render_node_with_style(html_view_ctx_t *ctx,
                                             const html_node_t *node,
                                             const css_style_t *style,
                                             const css_style_t *parent_style)
{
    if (!ctx || !node || !style)
    {
        return;
    }

    int32_t saved_z = ctx->z_index;
    if (style->has_position && style->position != CSS_POSITION_STATIC && style->has_z_index)
    {
        ctx->z_index = style->z_index;
    }

    bool block = false;
    if (style->has_display)
    {
        if (style->display == CSS_DISPLAY_BLOCK ||
            style->display == CSS_DISPLAY_LIST_ITEM ||
            style->display == CSS_DISPLAY_TABLE ||
            style->display == CSS_DISPLAY_FLEX ||
            style->display == CSS_DISPLAY_GRID)
        {
            block = true;
        }
    }

    html_view_font_scope_t font_scope = {0};
    bool font_pushed = false;
    css_text_align_t saved_align = ctx->text_align_mode;
    if (style->has_text_align)
    {
        ctx->text_align_mode = style->text_align;
    }

    bool saved_draw = ctx->draw;
    bool saved_record = ctx->record;

    if (style->has_display && style->display == CSS_DISPLAY_NONE)
    {
        goto out;
    }

    if (style->has_opacity && style->opacity_milli <= 0)
    {
        ctx->draw = false;
        ctx->record = false;
    }

    html_view_font_scope_push(ctx, style, block, &font_scope);
    font_pushed = true;

    if (html_view_render_positioned_element(ctx, node, style, parent_style))
    {
        goto out;
    }

    if (style->has_display &&
        (style->display == CSS_DISPLAY_FLEX || style->display == CSS_DISPLAY_INLINE_FLEX))
    {
        html_view_render_flex_container(ctx, node, style, style->display == CSS_DISPLAY_INLINE_FLEX);
        goto out;
    }
    if (style->has_display &&
        (style->display == CSS_DISPLAY_GRID || style->display == CSS_DISPLAY_INLINE_GRID))
    {
        html_view_render_grid_container(ctx, node, style, style->display == CSS_DISPLAY_INLINE_GRID);
        goto out;
    }

    if (style->has_float && style->float_mode != CSS_FLOAT_NONE)
    {
        html_view_render_float_box(ctx, node, style, style->float_mode);
        goto out;
    }

    if (html_view_render_block_element(ctx, node, style))
    {
        goto out;
    }

    if (html_view_render_inline_element(ctx, node, style))
    {
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
    ctx->z_index = saved_z;
    ctx->text_align_mode = saved_align;
    ctx->draw = saved_draw;
    ctx->record = saved_record;
    if (font_pushed)
    {
        html_view_font_scope_pop(ctx, &font_scope);
    }
}

static void html_view_render_pseudo_element(html_view_ctx_t *ctx,
                                            const html_node_t *node,
                                            const css_style_t *parent_style,
                                            html_view_pseudo_t pseudo)
{
    const char *pseudo_name = (pseudo == HTML_VIEW_PSEUDO_BEFORE) ? "before" : "after";

    if (!ctx || !node || !parent_style || !ctx->priv)
    {
        return;
    }

    bool trace_acid2 = html_view_node_has_ancestor_class_local(node, "nose") ||
                       html_view_node_has_ancestor_class_local(node, "smile") ||
                       html_view_node_has_ancestor_class_local(node, "eyes");

    css_style_t style = {0};
    if (!html_view_style_for_pseudo(&style, ctx->priv->sheet, parent_style, node, ctx->priv, pseudo))
    {
        if (ctx->record && trace_acid2)
        {
            const char *cls = html_attr_get(node, "class");
            serial_printf("[html_view][acid2] pseudo=%s tag=%s class=%s has_content=0",
                          pseudo_name,
                          node->name ? node->name : "(null)",
                          cls ? cls : "(null)");
        }
        return;
    }

    if (style.has_display && style.display == CSS_DISPLAY_NONE)
    {
        return;
    }

    if (ctx->record && trace_acid2)
    {
        const char *cls = html_attr_get(node, "class");
        int display = style.has_display ? (int)style.display : -1;
        serial_printf("[html_view][acid2] pseudo=%s tag=%s class=%s has_content=%d display=%d border=%d,%d,%d,%d border_none=%d,%d,%d,%d bg=%08X font_px=%d base_font=%d",
                      pseudo_name,
                      node->name ? node->name : "(null)",
                      cls ? cls : "(null)",
                      style.has_content ? 1 : 0,
                      display,
                      style.has_border ? (int)style.border_width.top.value_milli / 1000 : 0,
                      style.has_border ? (int)style.border_width.right.value_milli / 1000 : 0,
                      style.has_border ? (int)style.border_width.bottom.value_milli / 1000 : 0,
                      style.has_border ? (int)style.border_width.left.value_milli / 1000 : 0,
                      style.border_style_none[CSS_BORDER_SIDE_TOP] ? 1 : 0,
                      style.border_style_none[CSS_BORDER_SIDE_RIGHT] ? 1 : 0,
                      style.border_style_none[CSS_BORDER_SIDE_BOTTOM] ? 1 : 0,
                      style.border_style_none[CSS_BORDER_SIDE_LEFT] ? 1 : 0,
                      style.has_background ? style.background : 0,
                      ctx->actual_font_px,
                      ctx->base_font_px);
    }

    html_node_t *pseudo_node = (html_node_t *)calloc(1, sizeof(*pseudo_node));
    if (!pseudo_node)
    {
        return;
    }
    pseudo_node->type = HTML_NODE_ELEMENT;
    pseudo_node->name = (char *)"span";

    html_node_t *text_node = NULL;
    if (style.has_content && style.content && style.content[0] != '\0')
    {
        text_node = (html_node_t *)calloc(1, sizeof(*text_node));
        if (text_node)
        {
            text_node->type = HTML_NODE_TEXT;
            text_node->text = (char *)style.content;
            text_node->parent = pseudo_node;
            pseudo_node->first_child = text_node;
            pseudo_node->last_child = text_node;
        }
    }

    html_view_render_node_with_style(ctx, pseudo_node, &style, parent_style);

    free(text_node);
    free(pseudo_node);
}

void html_view_render_children(html_view_ctx_t *ctx, const html_node_t *node, const css_style_t *style)
{
    if (!ctx || !node)
    {
        return;
    }
    if (style && node->type == HTML_NODE_ELEMENT)
    {
        html_view_render_pseudo_element(ctx, node, style, HTML_VIEW_PSEUDO_BEFORE);
    }
    for (const html_node_t *child = node->first_child; child; child = child->next_sibling)
    {
        html_view_render_node_internal(ctx, child, style);
    }
    if (style && node->type == HTML_NODE_ELEMENT)
    {
        html_view_render_pseudo_element(ctx, node, style, HTML_VIEW_PSEUDO_AFTER);
    }
}

void html_view_render_node_internal(html_view_ctx_t *ctx, const html_node_t *node, const css_style_t *parent_style)
{
    if (!ctx || !node)
    {
        return;
    }
#ifdef HTML_VIEW_HOST_TRACE
    html_view_trace_note_node(node, "render");
#endif

    if (node->type == HTML_NODE_TEXT)
    {
        if (!node->text || !parent_style)
        {
            return;
        }
        video_color_t color = parent_style->has_color ? parent_style->color : video_make_color(0x00, 0x00, 0x00);
        html_view_paint_layer_t saved_layer = ctx->paint_layer;
        if (ctx->paint_layer == HTML_VIEW_PAINT_LAYER_BLOCK)
        {
            ctx->paint_layer = HTML_VIEW_PAINT_LAYER_INLINE;
        }
        html_view_log_large_text(ctx, node, parent_style);
        html_view_draw_text(ctx, node->text, color, ctx->text_underline, ctx->text_bold);
        ctx->paint_layer = saved_layer;
        return;
    }

    if (node->type != HTML_NODE_ELEMENT || !node->name)
    {
        return;
    }

    const char *tag = node->name;
    if (strcmp(tag, "noscript") == 0)
    {
        if (ctx->priv && ctx->priv->js_enabled)
        {
            return;
        }
    }
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
    html_view_record_anchor(ctx, node);
    int32_t saved_z = ctx->z_index;
    if (style->has_position && style->position != CSS_POSITION_STATIC && style->has_z_index)
    {
        ctx->z_index = style->z_index;
    }
    bool block = html_view_is_block_tag(tag);
    if (style->has_display)
    {
        if (style->display == CSS_DISPLAY_INLINE ||
            style->display == CSS_DISPLAY_INLINE_BLOCK ||
            style->display == CSS_DISPLAY_INLINE_FLEX)
        {
            block = false;
        }
        else if (style->display == CSS_DISPLAY_INLINE_GRID)
        {
            block = false;
        }
        else if (style->display == CSS_DISPLAY_TABLE_CELL)
        {
            block = false;
        }
        else if (style->display == CSS_DISPLAY_BLOCK ||
                 style->display == CSS_DISPLAY_LIST_ITEM ||
                 style->display == CSS_DISPLAY_TABLE ||
                 style->display == CSS_DISPLAY_FLEX ||
                 style->display == CSS_DISPLAY_GRID)
        {
            block = true;
        }
    }

    html_view_font_scope_t font_scope = {0};
    bool font_pushed = false;
    css_text_align_t saved_align = ctx->text_align_mode;
    if (style->has_text_align)
    {
        ctx->text_align_mode = style->text_align;
    }

    bool saved_draw = ctx->draw;
    bool saved_record = ctx->record;

    if (style->has_display && style->display == CSS_DISPLAY_NONE)
    {
        goto out;
    }

    if (style->has_opacity && style->opacity_milli <= 0)
    {
        ctx->draw = false;
        ctx->record = false;
    }

    html_view_font_scope_push(ctx, style, block, &font_scope);
    font_pushed = true;

    if (html_view_render_positioned_element(ctx, node, style, parent_style))
    {
        goto out;
    }

    if (style->has_display &&
        (style->display == CSS_DISPLAY_FLEX || style->display == CSS_DISPLAY_INLINE_FLEX))
    {
        html_view_render_flex_container(ctx, node, style, style->display == CSS_DISPLAY_INLINE_FLEX);
        goto out;
    }
    if (style->has_display &&
        (style->display == CSS_DISPLAY_GRID || style->display == CSS_DISPLAY_INLINE_GRID))
    {
        html_view_render_grid_container(ctx, node, style, style->display == CSS_DISPLAY_INLINE_GRID);
        goto out;
    }

    if (ctx->table_mode &&
        parent_style &&
        parent_style->has_display &&
        parent_style->display == CSS_DISPLAY_TABLE)
    {
        bool as_cell = false;
        if (style->has_display)
        {
            if (style->display == CSS_DISPLAY_TABLE_CELL ||
                style->display == CSS_DISPLAY_TABLE ||
                style->display == CSS_DISPLAY_LIST_ITEM)
            {
                as_cell = true;
            }
        }
        else if (strcmp(tag, "li") == 0)
        {
            as_cell = true;
        }
        if (as_cell)
        {
            html_view_render_float_box(ctx, node, style, CSS_FLOAT_LEFT);
            goto out;
        }
    }

    if (style->has_float && style->float_mode != CSS_FLOAT_NONE &&
        !html_view_is_form_control_tag(tag) &&
        strcmp(tag, "img") != 0)
    {
        html_view_render_float_box(ctx, node, style, style->float_mode);
        goto out;
    }

    if (html_view_render_break_element(ctx, node))
    {
        goto out;
    }

    if (html_view_render_table_element(ctx, node, style, parent_style))
    {
        goto out;
    }

    if (html_view_render_form_element(ctx, node, style))
    {
        goto out;
    }

    if (html_view_render_block_element(ctx, node, style))
    {
        goto out;
    }

    if (html_view_render_inline_element(ctx, node, style))
    {
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
    ctx->z_index = saved_z;
    ctx->text_align_mode = saved_align;
    ctx->draw = saved_draw;
    ctx->record = saved_record;
    if (font_pushed)
    {
        html_view_font_scope_pop(ctx, &font_scope);
    }
    html_view_style_pop(ctx);
}
