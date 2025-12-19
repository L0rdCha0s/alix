#include "atk/html_view/render/render_internal.h"

void html_view_render_children(html_view_ctx_t *ctx, const html_node_t *node, const css_style_t *style)
{
    if (!ctx || !node)
    {
        return;
    }
    for (const html_node_t *child = node->first_child; child; child = child->next_sibling)
    {
        html_view_render_node_internal(ctx, child, style);
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
        html_view_draw_text(ctx, node->text, color, ctx->text_underline, ctx->text_bold);
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
    bool block = html_view_is_block_tag(tag);
    if (style->has_display)
    {
        if (style->display == CSS_DISPLAY_INLINE || style->display == CSS_DISPLAY_INLINE_FLEX)
        {
            block = false;
        }
        else if (style->display == CSS_DISPLAY_BLOCK ||
                 style->display == CSS_DISPLAY_LIST_ITEM ||
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

    if (style->has_display &&
        (style->display == CSS_DISPLAY_FLEX || style->display == CSS_DISPLAY_INLINE_FLEX))
    {
        html_view_render_flex_container(ctx, node, style, style->display == CSS_DISPLAY_INLINE_FLEX);
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
    ctx->text_align_mode = saved_align;
    if (font_pushed)
    {
        html_view_font_scope_pop(ctx, &font_scope);
    }
    html_view_style_pop(ctx);
}
