#include "atk/html_view/render/render_internal.h"

bool html_view_render_break_element(html_view_ctx_t *ctx, const html_node_t *node)
{
    if (!ctx || !node || node->type != HTML_NODE_ELEMENT || !node->name)
    {
        return false;
    }

    if (strcmp(node->name, "br") != 0)
    {
        return false;
    }

    const char *clear = html_attr_get(node, "clear");
    if (clear && clear[0] != '\0' && ctx->floats)
    {
        css_clear_t clear_mode = CSS_CLEAR_NONE;
        if (strcasecmp(clear, "all") == 0 || strcasecmp(clear, "both") == 0)
        {
            clear_mode = CSS_CLEAR_BOTH;
        }
        else if (strcasecmp(clear, "left") == 0)
        {
            clear_mode = CSS_CLEAR_LEFT;
        }
        else if (strcasecmp(clear, "right") == 0)
        {
            clear_mode = CSS_CLEAR_RIGHT;
        }

        if (clear_mode != CSS_CLEAR_NONE)
        {
            int clear_y = html_view_float_max_bottom(ctx->floats, clear_mode);
            if (clear_y > ctx->y)
            {
                ctx->y = clear_y;
                ctx->x = ctx->body_x;
                ctx->pending_space = false;
            }
        }
    }
    html_view_new_line(ctx);
    return true;
}

bool html_view_render_inline_element(html_view_ctx_t *ctx, const html_node_t *node, const css_style_t *style)
{
    if (!ctx || !node || !style || node->type != HTML_NODE_ELEMENT || !node->name)
    {
        return false;
    }

    const char *tag = node->name;
    if (strcmp(tag, "b") == 0 || strcmp(tag, "strong") == 0)
    {
        bool saved_bold = ctx->text_bold;
        ctx->text_bold = true;
        html_view_render_children(ctx, node, style);
        ctx->text_bold = saved_bold;
        return true;
    }

    if (strcmp(tag, "a") == 0)
    {
        bool saved_underline = ctx->text_underline;
        const char *saved_href = ctx->active_href;
        const char *href = html_attr_get(node, "href");
        if (!href || href[0] == '\0')
        {
            href = NULL;
        }

        bool underline = true;
        if (style->has_text_decoration)
        {
            underline = (style->text_decoration == CSS_TEXT_DECORATION_UNDERLINE);
        }
        ctx->text_underline = underline;
        ctx->active_href = href;
        html_view_render_children(ctx, node, style);
        if (underline && !saved_underline)
        {
            html_view_flush_underline_run(ctx);
        }
        ctx->text_underline = saved_underline;
        ctx->active_href = saved_href;
        return true;
    }

    return false;
}
