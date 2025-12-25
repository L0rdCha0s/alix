#include "atk/html_view/render/render_internal.h"

static int html_view_select_option_width(html_view_ctx_t *ctx, const html_node_t *node)
{
    if (!ctx || !node)
    {
        return 0;
    }

    int max_w = 0;
    for (const html_node_t *opt = node->first_child; opt; opt = opt->next_sibling)
    {
        if (opt->type != HTML_NODE_ELEMENT || !opt->name || strcmp(opt->name, "option") != 0)
        {
            continue;
        }
        char *label = NULL;
        size_t label_len = 0;
        size_t label_cap = 0;
        html_view_collect_text(opt, &label, &label_len, &label_cap);
        if (label)
        {
            html_view_trim_collapse_ws(label);
        }

        const char *value = html_attr_get(opt, "value");
        const char *title = (label && label[0] != '\0') ? label :
                            (value && value[0] != '\0') ? value : NULL;
        if (title && title[0] != '\0')
        {
            int w = html_view_text_width(ctx, title);
            if (w > max_w)
            {
                max_w = w;
            }
        }
        free(label);
    }

    return max_w;
}

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

    if (strcmp(tag, "select") == 0)
    {
        html_view_control_t *ctrl = html_view_control_find(ctx->priv, node);
        if (ctrl && ctrl->widget)
        {
            int height = ctx->line_height;
            int width = 140;
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
                int content_w = html_view_select_option_width(ctx, node);
                if (content_w > 0)
                {
                    width = content_w + 32;
                }
            }
            if (width < 80)
            {
                width = 80;
            }
            html_view_place_inline_control(ctx, ctrl->widget, width, height);
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
