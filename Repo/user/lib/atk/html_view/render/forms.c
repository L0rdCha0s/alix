#include "atk/html_view/render/render_internal.h"

bool html_view_render_form_element(html_view_ctx_t *ctx, const html_node_t *node, const css_style_t *style)
{
    if (!ctx || !node || !style || node->type != HTML_NODE_ELEMENT || !node->name)
    {
        return false;
    }

    const char *tag = node->name;
    if (strcmp(tag, "input") == 0)
    {
        const char *type = html_attr_get(node, "type");
        if (!type || type[0] == '\0')
        {
            type = "text";
        }
        if (strcasecmp(type, "hidden") == 0)
        {
            return true;
        }

        html_view_control_t *ctrl = html_view_control_find(ctx->priv, node);
        if (ctrl && ctrl->widget)
        {
            int height = ctx->line_height;
            int width = 24;
            if (ctrl->kind == HTML_VIEW_CONTROL_INPUT_TEXT)
            {
                width = 240;
                if (style->has_width && style->width.valid && !style->width.is_auto)
                {
                    int wpx = html_view_length_to_px(&style->width,
                                                    ctx->viewport_w,
                                                    ctx->viewport_h,
                                                    ctx->body_w,
                                                    ctx->viewport_h,
                                                    ctx->base_font_px,
                                                    true);
                    if (wpx > 0)
                    {
                        width = wpx;
                    }
                }
                else
                {
                    const char *size_attr = html_attr_get(node, "size");
                    int size = (size_attr && size_attr[0] != '\0') ? atoi(size_attr) : 0;
                    if (size > 0)
                    {
                        int ch_w = html_view_text_width(ctx, "0");
                        if (ch_w <= 0)
                        {
                            ch_w = ctx->space_w > 0 ? ctx->space_w : 8;
                        }
                        int wpx = (size * ch_w) + 16;
                        if (wpx > 0)
                        {
                            width = wpx;
                        }
                    }
                }
            }
            else if (ctrl->kind == HTML_VIEW_CONTROL_BUTTON)
            {
                width = ctrl->widget->width > 0 ? ctrl->widget->width : 80;
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
        return true;
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
        return true;
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
        return true;
    }

    return false;
}
