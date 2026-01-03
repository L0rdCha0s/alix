#include "atk/html_view/render/render_internal.h"
#include "serial.h"

#include <ctype.h>
#include <string.h>

void html_view_render_children(html_view_ctx_t *ctx, const html_node_t *node, const css_style_t *style);

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
            style->display == CSS_DISPLAY_FLEX)
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

    if (style->has_display && style->display == CSS_DISPLAY_NONE)
    {
        goto out;
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
    if (!html_view_style_for_pseudo(&style, ctx->priv->sheet, parent_style, node, pseudo))
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
        if (style->display == CSS_DISPLAY_INLINE || style->display == CSS_DISPLAY_INLINE_FLEX)
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
                 style->display == CSS_DISPLAY_FLEX)
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

    if (style->has_display && style->display == CSS_DISPLAY_NONE)
    {
        goto out;
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
    if (font_pushed)
    {
        html_view_font_scope_pop(ctx, &font_scope);
    }
    html_view_style_pop(ctx);
}
