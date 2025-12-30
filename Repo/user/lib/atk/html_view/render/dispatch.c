#include "atk/html_view/render/render_internal.h"

void html_view_render_children(html_view_ctx_t *ctx, const html_node_t *node, const css_style_t *style);

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
    if (!ctx || !node || !parent_style || !ctx->priv)
    {
        return;
    }

    css_style_t style = {0};
    if (!html_view_style_for_pseudo(&style, ctx->priv->sheet, parent_style, node, pseudo))
    {
        return;
    }

    if (style.has_display && style.display == CSS_DISPLAY_NONE)
    {
        return;
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

    if (ctx->table_mode && style->has_display && style->display == CSS_DISPLAY_TABLE_CELL)
    {
        html_view_render_float_box(ctx, node, style, CSS_FLOAT_LEFT);
        goto out;
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
