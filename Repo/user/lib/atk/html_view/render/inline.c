#include "atk/html_view/render/render_internal.h"

static bool html_view_object_type_is_image(const char *type)
{
    if (!type || type[0] == '\0')
    {
        return false;
    }
    return strncasecmp(type, "image/", 6) == 0;
}

static bool html_view_object_data_is_image(const char *data)
{
    if (!data || data[0] == '\0')
    {
        return false;
    }
    return strncasecmp(data, "data:image/", 11) == 0;
}

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
        html_view_paint_layer_t saved_layer = ctx->paint_layer;
        if (ctx->paint_layer == HTML_VIEW_PAINT_LAYER_BLOCK)
        {
            ctx->paint_layer = HTML_VIEW_PAINT_LAYER_INLINE;
        }
        bool saved_bold = ctx->text_bold;
        ctx->text_bold = true;
        html_view_render_children(ctx, node, style);
        ctx->text_bold = saved_bold;
        ctx->paint_layer = saved_layer;
        return true;
    }

    if (strcmp(tag, "a") == 0)
    {
        html_view_paint_layer_t saved_layer = ctx->paint_layer;
        if (ctx->paint_layer == HTML_VIEW_PAINT_LAYER_BLOCK)
        {
            ctx->paint_layer = HTML_VIEW_PAINT_LAYER_INLINE;
        }
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
        ctx->paint_layer = saved_layer;
        return true;
    }

    if (strcmp(tag, "object") == 0)
    {
        const char *data = html_attr_get(node, "data");
        const char *type = html_attr_get(node, "type");
        bool allow_image = false;
        if (type && type[0] != '\0')
        {
            allow_image = html_view_object_type_is_image(type);
        }
        else
        {
            allow_image = html_view_object_data_is_image(data);
        }

        if (allow_image && data && ctx->priv)
        {
            html_view_image_t *img = html_view_image_find(ctx->priv, data);
            if (!img && ctx->record)
            {
                (void)html_view_try_load_data_image_locked(ctx->priv, data);
                img = html_view_image_find(ctx->priv, data);
            }
            if (img && img->pixels && img->width > 0 && img->height > 0 && img->stride_bytes > 0)
            {
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
                if (border_top < 0) border_top = 0;
                if (border_right < 0) border_right = 0;
                if (border_bottom < 0) border_bottom = 0;
                if (border_left < 0) border_left = 0;
                html_view_apply_border_style_none(style, &border_top, &border_right, &border_bottom, &border_left);

                int content_w = img->width;
                int content_h = img->height;
                int box_w = content_w + pad_left + pad_right + border_left + border_right;
                int box_h = content_h + pad_top + pad_bottom + border_top + border_bottom;
                if (box_w > 0 && box_h > 0)
                {
                    if (box_h > ctx->line_height)
                    {
                        ctx->line_height = box_h;
                    }

                    int max_width = ctx->max_x - ctx->body_x;
                    if (max_width < 0)
                    {
                        max_width = 0;
                    }
                    if (box_w > max_width)
                    {
                        box_w = max_width;
                    }

                    if (ctx->pending_space && ctx->x != ctx->body_x)
                    {
                        if (ctx->x + ctx->space_w + box_w > ctx->max_x)
                        {
                            html_view_new_line(ctx);
                        }
                        else
                        {
                            ctx->x += ctx->space_w;
                        }
                    }
                    else if (ctx->x != ctx->body_x && ctx->x + box_w > ctx->max_x)
                    {
                        html_view_new_line(ctx);
                    }

                    html_view_paint_layer_t saved_layer = ctx->paint_layer;
                    if (ctx->paint_layer == HTML_VIEW_PAINT_LAYER_BLOCK)
                    {
                        ctx->paint_layer = HTML_VIEW_PAINT_LAYER_INLINE;
                    }

                    int draw_x = ctx->x;
                    int doc_y = ctx->y + ctx->line_height - box_h;
                    int draw_y = html_view_draw_y(ctx, doc_y);

                    if (style->has_background && !style->background_transparent)
                    {
                        html_view_draw_rect_clipped(ctx, draw_x, draw_y, box_w, box_h, style->background, &ctx->clip);
                    }
                    html_view_draw_background_image(ctx, style, draw_x, doc_y, box_w, box_h);

                    if (style->has_border && (border_top > 0 || border_right > 0 || border_bottom > 0 || border_left > 0))
                    {
                        html_view_draw_border_sides_clipped(ctx,
                                                            draw_x,
                                                            draw_y,
                                                            box_w,
                                                            box_h,
                                                            border_top,
                                                            border_right,
                                                            border_bottom,
                                                            border_left,
                                                            style,
                                                            &ctx->clip);
                    }

                    int content_x = draw_x + border_left + pad_left;
                    int content_y = draw_y + border_top + pad_top;
                    html_view_blit_rgba32_clipped(ctx,
                                                  content_x,
                                                  content_y,
                                                  content_w,
                                                  content_h,
                                                  img->pixels,
                                                  img->stride_bytes,
                                                  &ctx->clip);

                    ctx->x += box_w;
                    if (ctx->x > ctx->measure_max_x)
                    {
                        ctx->measure_max_x = ctx->x;
                    }
                    ctx->pending_space = true;
                    html_view_ensure_line_visible(ctx);
                    ctx->paint_layer = saved_layer;
                    return true;
                }
            }
        }

        html_view_paint_layer_t saved_layer = ctx->paint_layer;
        if (ctx->paint_layer == HTML_VIEW_PAINT_LAYER_BLOCK)
        {
            ctx->paint_layer = HTML_VIEW_PAINT_LAYER_INLINE;
        }
        html_view_render_children(ctx, node, style);
        ctx->paint_layer = saved_layer;
        return true;
    }

    return false;
}
