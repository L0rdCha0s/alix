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

static bool html_view_measure_inline_children(const html_view_ctx_t *ctx,
                                              const html_node_t *node,
                                              const css_style_t *style,
                                              int *out_w,
                                              int *out_h,
                                              bool *out_wrapped)
{
    if (out_w)
    {
        *out_w = 0;
    }
    if (out_h)
    {
        *out_h = 0;
    }
    if (out_wrapped)
    {
        *out_wrapped = false;
    }
    if (!ctx || !node || !style)
    {
        return false;
    }

    html_view_ctx_t measure = *ctx;
    html_view_float_ctx_t floats = {0};
    if (ctx->floats)
    {
        floats = *ctx->floats;
        measure.floats = &floats;
    }
    else
    {
        measure.floats = NULL;
    }
    measure.draw = false;
    measure.record = false;
    measure.record_failed = false;
    measure.style_block = NULL;
    measure.style_depth = 0;
    measure.measure_max_x = measure.x;
    measure.content_bottom = measure.y;

    int start_x = measure.x;
    int start_y = measure.y;
    int start_line_y = measure.line_start_y;

    html_view_render_children(&measure, node, style);
    if (measure.x != measure.body_x)
    {
        html_view_ensure_line_visible(&measure);
    }

    int width = measure.x - start_x;
    int height = measure.content_bottom - start_y;
    if (height <= 0)
    {
        height = measure.line_height;
    }
    bool wrapped = (measure.y != start_y) || (measure.line_start_y != start_line_y);

    html_view_style_stack_destroy(&measure);

    if (out_wrapped)
    {
        *out_wrapped = wrapped;
    }
    if (width <= 0 || height <= 0)
    {
        return false;
    }

    if (out_w)
    {
        *out_w = width;
    }
    if (out_h)
    {
        *out_h = height;
    }
    return true;
}

static bool html_view_render_inline_background_box(html_view_ctx_t *ctx,
                                                   const html_node_t *node,
                                                   const css_style_t *style)
{
    int content_w = 0;
    int content_h = 0;
    bool wrapped = false;
    if (!html_view_measure_inline_children(ctx, node, style, &content_w, &content_h, &wrapped))
    {
        return false;
    }
    if (wrapped)
    {
        return false;
    }

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
                                         true);
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
                                            true);
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

    int box_w = content_w + pad_left + pad_right + border_left + border_right;
    int box_h = content_h + pad_top + pad_bottom + border_top + border_bottom;
    if (box_w <= 0 || box_h <= 0)
    {
        return false;
    }

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
    if (box_w < 0)
    {
        box_w = 0;
    }
    content_w = box_w - pad_left - pad_right - border_left - border_right;
    if (content_w < 0)
    {
        content_w = 0;
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

    html_view_ctx_t inner = *ctx;
    html_view_float_ctx_t inner_floats = {0};
    if (ctx->floats)
    {
        inner_floats = *ctx->floats;
        inner.floats = &inner_floats;
    }
    else
    {
        inner.floats = NULL;
    }
    inner.style_block = NULL;
    inner.style_depth = 0;
    inner.body_x = draw_x + border_left + pad_left;
    inner.body_w = content_w;
    if (inner.body_w < 0) inner.body_w = 0;
    inner.max_x = inner.body_x + inner.body_w;
    inner.x = inner.body_x;
    inner.y = doc_y + border_top + pad_top;
    inner.line_start_x = inner.x;
    inner.line_start_y = inner.y;
    inner.pending_space = false;
    inner.pending_margin = 0;
    inner.pending_margin_valid = false;
    inner.measure_max_x = inner.x;
    inner.content_bottom = inner.y;
    inner.line_height = html_view_line_height_for_style(&inner, style);
    if (html_view_subtree_has_form_control(node) && inner.line_height < atk_font_line_height() + 8)
    {
        inner.line_height = atk_font_line_height() + 8;
    }

    html_view_render_children(&inner, node, style);
    if (inner.x != inner.body_x)
    {
        html_view_new_line(&inner);
    }
    html_view_style_stack_destroy(&inner);
    if (inner.record_failed)
    {
        ctx->record_failed = true;
    }

    ctx->x = draw_x + box_w;
    if (ctx->x > ctx->measure_max_x)
    {
        ctx->measure_max_x = ctx->x;
    }
    ctx->pending_space = true;
    html_view_ensure_line_visible(ctx);
    ctx->paint_layer = saved_layer;
    return true;
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
    if (ctx->pending_margin_valid && ctx->x == ctx->body_x)
    {
        ctx->y += ctx->pending_margin;
        ctx->pending_margin = 0;
        ctx->pending_margin_valid = false;
        ctx->pending_space = false;
        ctx->line_start_x = ctx->x;
        ctx->line_start_y = ctx->y;
        if (ctx->record && ctx->priv)
        {
            ctx->line_op_start = ctx->priv->render_cache.op_count;
        }
        else
        {
            ctx->line_op_start = 0;
        }
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

    if (strcmp(tag, "img") == 0)
    {
        const char *src = html_attr_get(node, "src");
        html_view_image_t *img = src ? html_view_image_find(ctx->priv, src) : NULL;
        if (!img && ctx->record && ctx->priv && src)
        {
            (void)html_view_try_load_data_image_locked(ctx->priv, src);
            img = html_view_image_find(ctx->priv, src);
        }

        int content_w = (img && img->pixels && img->width > 0) ? img->width : 0;
        int content_h = (img && img->pixels && img->height > 0) ? img->height : 0;
        if (style->has_width && style->width.valid && !style->width.is_auto)
        {
            content_w = html_view_length_to_px(&style->width,
                                               ctx->viewport_w,
                                               ctx->viewport_h,
                                               ctx->body_w,
                                               ctx->viewport_h,
                                               ctx->base_font_px,
                                               true);
        }
        if (style->has_height && style->height.valid && !style->height.is_auto)
        {
            content_h = html_view_length_to_px(&style->height,
                                               ctx->viewport_w,
                                               ctx->viewport_h,
                                               ctx->body_w,
                                               ctx->viewport_h,
                                               ctx->base_font_px,
                                               false);
        }

        if (content_w <= 0 || content_h <= 0)
        {
            const char *alt = html_attr_get(node, "alt");
            if (!alt || alt[0] == '\0')
            {
                alt = "[image]";
            }
            video_color_t color = style->has_color ? style->color : video_make_color(0x00, 0x00, 0x00);
            html_view_draw_text(ctx, alt, color, false, false);
            return true;
        }

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
                                             true);
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
                                                true);
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

        int box_w = content_w + pad_left + pad_right + border_left + border_right;
        int box_h = content_h + pad_top + pad_bottom + border_top + border_bottom;
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
        if (img && img->pixels)
        {
            html_view_blit_rgba32_clipped(ctx,
                                          content_x,
                                          content_y,
                                          content_w,
                                          content_h,
                                          img->pixels,
                                          img->stride_bytes,
                                          &ctx->clip);
        }

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
                                                     true);
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
                                                        true);
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

    if ((style->has_background_image && style->background_image) ||
        (style->has_background && !style->background_transparent) ||
        style->has_border)
    {
        if (html_view_render_inline_background_box(ctx, node, style))
        {
            return true;
        }
    }

    return false;
}
