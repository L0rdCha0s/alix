#include "atk/html_view/render/render_internal.h"

static bool html_view_form_uses_border_box(const css_style_t *style)
{
    return style && style->has_box_sizing && style->box_sizing == CSS_BOX_SIZING_BORDER_BOX;
}

static void html_view_form_box_edges(const html_view_ctx_t *ctx,
                                     const css_style_t *style,
                                     int *pad_top,
                                     int *pad_right,
                                     int *pad_bottom,
                                     int *pad_left,
                                     int *border_top,
                                     int *border_right,
                                     int *border_bottom,
                                     int *border_left)
{
    if (pad_top) *pad_top = 0;
    if (pad_right) *pad_right = 0;
    if (pad_bottom) *pad_bottom = 0;
    if (pad_left) *pad_left = 0;
    if (border_top) *border_top = 0;
    if (border_right) *border_right = 0;
    if (border_bottom) *border_bottom = 0;
    if (border_left) *border_left = 0;

    if (!ctx || !style)
    {
        return;
    }

    if (style->has_padding)
    {
        if (pad_top)
        {
            *pad_top = html_view_length_to_px(&style->padding.top,
                                              ctx->viewport_w,
                                              ctx->viewport_h,
                                              ctx->body_w,
                                              ctx->viewport_h,
                                              ctx->base_font_px,
                                              false);
        }
        if (pad_right)
        {
            *pad_right = html_view_length_to_px(&style->padding.right,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                ctx->body_w,
                                                ctx->viewport_h,
                                                ctx->base_font_px,
                                                true);
        }
        if (pad_bottom)
        {
            *pad_bottom = html_view_length_to_px(&style->padding.bottom,
                                                 ctx->viewport_w,
                                                 ctx->viewport_h,
                                                 ctx->body_w,
                                                 ctx->viewport_h,
                                                 ctx->base_font_px,
                                                 false);
        }
        if (pad_left)
        {
            *pad_left = html_view_length_to_px(&style->padding.left,
                                               ctx->viewport_w,
                                               ctx->viewport_h,
                                               ctx->body_w,
                                               ctx->viewport_h,
                                               ctx->base_font_px,
                                               true);
        }
    }

    if (style->has_border)
    {
        if (border_top)
        {
            *border_top = html_view_length_to_px(&style->border_width.top,
                                                 ctx->viewport_w,
                                                 ctx->viewport_h,
                                                 ctx->body_w,
                                                 ctx->viewport_h,
                                                 ctx->base_font_px,
                                                 false);
        }
        if (border_right)
        {
            *border_right = html_view_length_to_px(&style->border_width.right,
                                                   ctx->viewport_w,
                                                   ctx->viewport_h,
                                                   ctx->body_w,
                                                   ctx->viewport_h,
                                                   ctx->base_font_px,
                                                   true);
        }
        if (border_bottom)
        {
            *border_bottom = html_view_length_to_px(&style->border_width.bottom,
                                                    ctx->viewport_w,
                                                    ctx->viewport_h,
                                                    ctx->body_w,
                                                    ctx->viewport_h,
                                                    ctx->base_font_px,
                                                    false);
        }
        if (border_left)
        {
            *border_left = html_view_length_to_px(&style->border_width.left,
                                                  ctx->viewport_w,
                                                  ctx->viewport_h,
                                                  ctx->body_w,
                                                  ctx->viewport_h,
                                                  ctx->base_font_px,
                                                  true);
        }
    }

    if (pad_top && *pad_top < 0) *pad_top = 0;
    if (pad_right && *pad_right < 0) *pad_right = 0;
    if (pad_bottom && *pad_bottom < 0) *pad_bottom = 0;
    if (pad_left && *pad_left < 0) *pad_left = 0;
    if (border_top && *border_top < 0) *border_top = 0;
    if (border_right && *border_right < 0) *border_right = 0;
    if (border_bottom && *border_bottom < 0) *border_bottom = 0;
    if (border_left && *border_left < 0) *border_left = 0;

    if (border_top && border_right && border_bottom && border_left)
    {
        html_view_apply_border_style_none(style, border_top, border_right, border_bottom, border_left);
    }
}

static void html_view_form_draw_label(html_view_ctx_t *ctx,
                                      int draw_x,
                                      int draw_y,
                                      int box_w,
                                      int box_h,
                                      const char *text,
                                      video_color_t color)
{
    if (!ctx || !text || text[0] == '\0' || box_w <= 0 || box_h <= 0)
    {
        return;
    }

    int baseline = html_view_baseline_for_rect(ctx, draw_y, box_h > 0 ? box_h : ctx->line_height);
    atk_rect_t clip = { draw_x, draw_y, box_w, box_h };

    if (ctx->record)
    {
        if (!ctx->record_failed && ctx->priv)
        {
            html_view_render_cache_t *cache = &ctx->priv->render_cache;
            html_view_op_t op = {0};
            op.kind = HTML_VIEW_OP_TEXT;
            op.x = html_view_record_x(ctx, draw_x);
            op.y = html_view_record_y(ctx, draw_y);
            op.w = html_view_text_width(ctx, text);
            op.h = box_h;
            op.baseline_off = (int16_t)(baseline - draw_y);
            op.font_px = (int16_t)ctx->actual_font_px;
            op.color = color;
            op.text = text;
            op.text_len = (uint32_t)strlen(text);
            op.text_owned = false;
            op.href = ctx->active_href;
            op.z_index = html_view_effective_z_index(ctx);
            op.fixed = ctx->fixed_mode;
            op.has_clip = true;
            op.clip_scroll = ctx->clip_scroll;
            op.clip_x = html_view_record_x(ctx, clip.x);
            op.clip_y = html_view_record_y(ctx, clip.y);
            op.clip_w = clip.width;
            op.clip_h = clip.height;
            if (!html_view_render_cache_push_op(cache, &op, cache->tile_h))
            {
                ctx->record_failed = true;
            }
            if (ctx->text_bold && !ctx->record_failed)
            {
                html_view_op_t op2 = op;
                op2.x += 1;
                (void)html_view_render_cache_push_op(cache, &op2, cache->tile_h);
            }
        }
        return;
    }

    if (!ctx->draw || !html_view_line_visible(ctx))
    {
        return;
    }
    html_view_draw_string_clipped(ctx, draw_x, baseline, text, color, &clip);
    if (ctx->text_bold)
    {
        html_view_draw_string_clipped(ctx, draw_x + 1, baseline, text, color, &clip);
    }
}

static bool html_view_form_display_block(const css_style_t *style)
{
    if (!style || !style->has_display)
    {
        return false;
    }
    return style->display == CSS_DISPLAY_BLOCK ||
           style->display == CSS_DISPLAY_LIST_ITEM ||
           style->display == CSS_DISPLAY_TABLE ||
           style->display == CSS_DISPLAY_FLEX ||
           style->display == CSS_DISPLAY_GRID;
}

static void html_view_form_draw_box(html_view_ctx_t *ctx,
                                    const css_style_t *style,
                                    int draw_x,
                                    int draw_y,
                                    int doc_y,
                                    int box_w,
                                    int box_h,
                                    int border_top,
                                    int border_right,
                                    int border_bottom,
                                    int border_left)
{
    if (!ctx || !style || box_w <= 0 || box_h <= 0)
    {
        return;
    }

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
}

static void html_view_form_render_inline_box(html_view_ctx_t *ctx,
                                             const css_style_t *style,
                                             int box_w,
                                             int box_h,
                                             int pad_top,
                                             int pad_right,
                                             int pad_bottom,
                                             int pad_left,
                                             int border_top,
                                             int border_right,
                                             int border_bottom,
                                             int border_left,
                                             const char *label,
                                             video_color_t label_color)
{
    if (!ctx || box_w <= 0 || box_h <= 0)
    {
        return;
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
    if (style && (!style->has_width || !style->width.valid || style->width.is_auto))
    {
        if (box_w < max_width)
        {
            box_w = max_width;
        }
    }
    if (box_w > max_width)
    {
        box_w = max_width;
    }
    if (box_w < 0)
    {
        box_w = 0;
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

    int draw_x = ctx->x;
    int doc_y = ctx->y + ctx->line_height - box_h;
    int draw_y = html_view_draw_y(ctx, doc_y);

    html_view_form_draw_box(ctx,
                            style,
                            draw_x,
                            draw_y,
                            doc_y,
                            box_w,
                            box_h,
                            border_top,
                            border_right,
                            border_bottom,
                            border_left);

    int content_x = draw_x + border_left + pad_left;
    int content_y = draw_y + border_top + pad_top;
    int content_w = box_w - border_left - border_right - pad_left - pad_right;
    int content_h = box_h - border_top - border_bottom - pad_top - pad_bottom;
    if (content_w < 0)
    {
        content_w = 0;
    }
    if (content_h < 0)
    {
        content_h = 0;
    }
    html_view_form_draw_label(ctx, content_x, content_y, content_w, content_h, label, label_color);

    ctx->x += box_w;
    if (ctx->x > ctx->measure_max_x)
    {
        ctx->measure_max_x = ctx->x;
    }
    ctx->pending_space = true;
    html_view_ensure_line_visible(ctx);
}

static void html_view_form_render_block_box(html_view_ctx_t *ctx,
                                            const css_style_t *style,
                                            int box_w,
                                            int box_h,
                                            int pad_top,
                                            int pad_right,
                                            int pad_bottom,
                                            int pad_left,
                                            int border_top,
                                            int border_right,
                                            int border_bottom,
                                            int border_left,
                                            const char *label,
                                            video_color_t label_color)
{
    if (!ctx || box_w <= 0 || box_h <= 0)
    {
        return;
    }

    if (ctx->x != ctx->body_x)
    {
        html_view_new_line(ctx);
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

    int draw_x = ctx->body_x;
    int draw_y = html_view_draw_y(ctx, ctx->y);

    html_view_form_draw_box(ctx,
                            style,
                            draw_x,
                            draw_y,
                            ctx->y,
                            box_w,
                            box_h,
                            border_top,
                            border_right,
                            border_bottom,
                            border_left);

    int content_x = draw_x + border_left + pad_left;
    int content_y = draw_y + border_top + pad_top;
    int content_w = box_w - border_left - border_right - pad_left - pad_right;
    int content_h = box_h - border_top - border_bottom - pad_top - pad_bottom;
    if (content_w < 0)
    {
        content_w = 0;
    }
    if (content_h < 0)
    {
        content_h = 0;
    }
    html_view_form_draw_label(ctx, content_x, content_y, content_w, content_h, label, label_color);

    int right_edge = draw_x + box_w;
    if (right_edge > ctx->measure_max_x)
    {
        ctx->measure_max_x = right_edge;
    }

    ctx->y += box_h;
    ctx->x = ctx->body_x;
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
    html_view_ensure_line_visible(ctx);
}

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
            int pad_top = 0;
            int pad_right = 0;
            int pad_bottom = 0;
            int pad_left = 0;
            int border_top = 0;
            int border_right = 0;
            int border_bottom = 0;
            int border_left = 0;
            html_view_form_box_edges(ctx, style,
                                     &pad_top, &pad_right, &pad_bottom, &pad_left,
                                     &border_top, &border_right, &border_bottom, &border_left);

            bool border_box = html_view_form_uses_border_box(style);
            int content_w = 0;
            int content_h = 0;
            int box_w = 0;
            int box_h = 0;

            if (strcasecmp(type, "checkbox") == 0 || strcasecmp(type, "radio") == 0)
            {
                content_w = ctx->line_height;
                content_h = ctx->line_height;
            }
            else
            {
                content_w = 240;
                content_h = ctx->line_height;
            }

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
                    if (border_box)
                    {
                        box_w = wpx;
                        content_w = box_w - pad_left - pad_right - border_left - border_right;
                    }
                    else
                    {
                        content_w = wpx;
                    }
                }
            }
            if (style->has_height && style->height.valid && !style->height.is_auto)
            {
                int hpx = html_view_length_to_px(&style->height,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                ctx->body_w,
                                                ctx->viewport_h,
                                                ctx->base_font_px,
                                                false);
                if (hpx > 0)
                {
                    if (border_box)
                    {
                        box_h = hpx;
                        content_h = box_h - pad_top - pad_bottom - border_top - border_bottom;
                    }
                    else
                    {
                        content_h = hpx;
                    }
                }
            }

            if (content_w < 0)
            {
                content_w = 0;
            }
            if (content_h < 0)
            {
                content_h = 0;
            }
            if (box_w <= 0)
            {
                box_w = content_w + pad_left + pad_right + border_left + border_right;
            }
            if (box_h <= 0)
            {
                box_h = content_h + pad_top + pad_bottom + border_top + border_bottom;
            }

            const char *value = html_attr_get(node, "value");
            const char *placeholder = html_attr_get(node, "placeholder");
            const char *label = NULL;
            video_color_t label_color = style->has_color ? style->color : video_make_color(0x00, 0x00, 0x00);
            if (value && value[0] != '\0')
            {
                label = value;
            }
            else if (placeholder && placeholder[0] != '\0')
            {
                label = placeholder;
                label_color = video_make_color(0x80, 0x80, 0x80);
            }

            bool block = html_view_form_display_block(style);
            if (block)
            {
                html_view_form_render_block_box(ctx,
                                                style,
                                                box_w,
                                                box_h,
                                                pad_top,
                                                pad_right,
                                                pad_bottom,
                                                pad_left,
                                                border_top,
                                                border_right,
                                                border_bottom,
                                                border_left,
                                                label,
                                                label_color);
            }
            else
            {
                html_view_form_render_inline_box(ctx,
                                                 style,
                                                 box_w,
                                                 box_h,
                                                 pad_top,
                                                 pad_right,
                                                 pad_bottom,
                                                 pad_left,
                                                 border_top,
                                                 border_right,
                                                 border_bottom,
                                                 border_left,
                                                 label,
                                                 label_color);
            }
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
        else
        {
            int pad_top = 0;
            int pad_right = 0;
            int pad_bottom = 0;
            int pad_left = 0;
            int border_top = 0;
            int border_right = 0;
            int border_bottom = 0;
            int border_left = 0;
            html_view_form_box_edges(ctx, style,
                                     &pad_top, &pad_right, &pad_bottom, &pad_left,
                                     &border_top, &border_right, &border_bottom, &border_left);

            int content_w = html_view_select_option_width(ctx, node);
            if (content_w <= 0)
            {
                content_w = 80;
            }
            int content_h = ctx->line_height;
            int box_w = content_w + pad_left + pad_right + border_left + border_right + 32;
            int box_h = content_h + pad_top + pad_bottom + border_top + border_bottom;

            char *label = NULL;
            size_t label_len = 0;
            size_t label_cap = 0;
            html_view_collect_text(node, &label, &label_len, &label_cap);
            if (label)
            {
                html_view_trim_collapse_ws(label);
            }
            video_color_t label_color = style->has_color ? style->color : video_make_color(0x00, 0x00, 0x00);
            html_view_form_render_inline_box(ctx,
                                             style,
                                             box_w,
                                             box_h,
                                             pad_top,
                                             pad_right,
                                             pad_bottom,
                                             pad_left,
                                             border_top,
                                             border_right,
                                             border_bottom,
                                             border_left,
                                             label,
                                             label_color);
            free(label);
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
        else
        {
            int pad_top = 0;
            int pad_right = 0;
            int pad_bottom = 0;
            int pad_left = 0;
            int border_top = 0;
            int border_right = 0;
            int border_bottom = 0;
            int border_left = 0;
            html_view_form_box_edges(ctx, style,
                                     &pad_top, &pad_right, &pad_bottom, &pad_left,
                                     &border_top, &border_right, &border_bottom, &border_left);

            int rows = 4;
            const char *rows_attr = html_attr_get(node, "rows");
            if (rows_attr && rows_attr[0] != '\0')
            {
                int parsed = atoi(rows_attr);
                if (parsed > 0)
                {
                    rows = parsed;
                }
            }

            int content_h = ctx->line_height * rows;
            if (content_h < ctx->line_height)
            {
                content_h = ctx->line_height;
            }
            int content_w = 360;
            bool border_box = html_view_form_uses_border_box(style);
            int box_w = content_w + pad_left + pad_right + border_left + border_right;
            int box_h = content_h + pad_top + pad_bottom + border_top + border_bottom;

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
                    if (border_box)
                    {
                        box_w = wpx;
                    }
                    else
                    {
                        content_w = wpx;
                        box_w = content_w + pad_left + pad_right + border_left + border_right;
                    }
                }
            }
            if (style->has_height && style->height.valid && !style->height.is_auto)
            {
                int hpx = html_view_length_to_px(&style->height,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                ctx->body_w,
                                                ctx->viewport_h,
                                                ctx->base_font_px,
                                                false);
                if (hpx > 0)
                {
                    if (border_box)
                    {
                        box_h = hpx;
                    }
                    else
                    {
                        content_h = hpx;
                        box_h = content_h + pad_top + pad_bottom + border_top + border_bottom;
                    }
                }
            }

            const char *placeholder = html_attr_get(node, "placeholder");
            char *label = NULL;
            size_t label_len = 0;
            size_t label_cap = 0;
            html_view_collect_text(node, &label, &label_len, &label_cap);
            if (label)
            {
                html_view_trim_collapse_ws(label);
            }
            const char *label_text = (label && label[0] != '\0') ? label : placeholder;
            video_color_t label_color = style->has_color ? style->color : video_make_color(0x00, 0x00, 0x00);
            if ((!label || label[0] == '\0') && placeholder && placeholder[0] != '\0')
            {
                label_color = video_make_color(0x80, 0x80, 0x80);
            }
            html_view_form_render_block_box(ctx,
                                            style,
                                            box_w,
                                            box_h,
                                            pad_top,
                                            pad_right,
                                            pad_bottom,
                                            pad_left,
                                            border_top,
                                            border_right,
                                            border_bottom,
                                            border_left,
                                            label_text,
                                            label_color);
            free(label);
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
            int pad_top = 0;
            int pad_right = 0;
            int pad_bottom = 0;
            int pad_left = 0;
            int border_top = 0;
            int border_right = 0;
            int border_bottom = 0;
            int border_left = 0;
            html_view_form_box_edges(ctx, style,
                                     &pad_top, &pad_right, &pad_bottom, &pad_left,
                                     &border_top, &border_right, &border_bottom, &border_left);

            char *label = NULL;
            size_t label_len = 0;
            size_t label_cap = 0;
            html_view_collect_text(node, &label, &label_len, &label_cap);
            if (label)
            {
                html_view_trim_collapse_ws(label);
            }
            const char *label_text = (label && label[0] != '\0') ? label : NULL;
            video_color_t label_color = style->has_color ? style->color : video_make_color(0x00, 0x00, 0x00);

            int content_w = 80;
            if (label_text)
            {
                int text_w = html_view_text_width(ctx, label_text);
                if (text_w > 0)
                {
                    content_w = text_w + 16;
                }
            }
            int content_h = ctx->line_height;
            int box_w = content_w + pad_left + pad_right + border_left + border_right;
            int box_h = content_h + pad_top + pad_bottom + border_top + border_bottom;

            bool block = html_view_form_display_block(style);
            if (block)
            {
                html_view_form_render_block_box(ctx,
                                                style,
                                                box_w,
                                                box_h,
                                                pad_top,
                                                pad_right,
                                                pad_bottom,
                                                pad_left,
                                                border_top,
                                                border_right,
                                                border_bottom,
                                                border_left,
                                                label_text,
                                                label_color);
            }
            else
            {
                html_view_form_render_inline_box(ctx,
                                                 style,
                                                 box_w,
                                                 box_h,
                                                 pad_top,
                                                 pad_right,
                                                 pad_bottom,
                                                 pad_left,
                                                 border_top,
                                                 border_right,
                                                 border_bottom,
                                                 border_left,
                                                 label_text,
                                                 label_color);
            }
            free(label);
        }
        return true;
    }

    return false;
}
