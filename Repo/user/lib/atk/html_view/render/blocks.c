#include "atk/html_view/render/render_internal.h"

static int html_view_measure_block_children_height(const html_view_ctx_t *ctx,
                                                   const html_node_t *node,
                                                   const css_style_t *style,
                                                   int content_w)
{
    if (!ctx || !node || !style)
    {
        return 0;
    }

    html_view_ctx_t measure = *ctx;
    html_view_float_ctx_t floats = {0};
    measure.draw = false;
    measure.record = false;
    measure.record_failed = false;
    measure.floats = &floats;
    measure.style_block = NULL;
    measure.style_depth = 0;
    measure.body_x = 0;
    measure.body_w = content_w;
    if (measure.body_w < 0) measure.body_w = 0;
    measure.max_x = measure.body_x + measure.body_w;
    measure.x = measure.body_x;
    measure.y = 0;
    measure.content_bottom = 0;
    measure.pending_space = false;
    measure.list_level = 0;
    measure.measure_max_x = measure.x;
    measure.space_w = html_view_text_width(&measure, " ");
    measure.line_height = html_view_line_height_for_style(&measure, style);
    if (html_view_subtree_has_form_control(node) && measure.line_height < atk_font_line_height() + 8)
    {
        measure.line_height = atk_font_line_height() + 8;
    }

    html_view_render_children(&measure, node, style);
    if (measure.x != measure.body_x)
    {
        html_view_new_line(&measure);
    }
    html_view_style_stack_destroy(&measure);

    int used_h = measure.content_bottom;
    if (used_h < 0) used_h = 0;
    return used_h;
}

bool html_view_render_table_element(html_view_ctx_t *ctx,
                                    const html_node_t *node,
                                    const css_style_t *style,
                                    const css_style_t *parent_style)
{
    if (!ctx || !node || !style || node->type != HTML_NODE_ELEMENT || !node->name)
    {
        return false;
    }

    if (strcmp(node->name, "table") != 0)
    {
        return false;
    }

    html_view_render_table(ctx, node, style, parent_style);
    return true;
}

bool html_view_render_block_element(html_view_ctx_t *ctx, const html_node_t *node, const css_style_t *style)
{
    if (!ctx || !node || !style || node->type != HTML_NODE_ELEMENT || !node->name)
    {
        return false;
    }

    const char *tag = node->name;
    if (strcmp(tag, "h1") == 0)
    {
        if (ctx->x != ctx->body_x)
        {
            html_view_new_line(ctx);
        }

        int pad_top = 0;
        int pad_bottom = 0;
        if (style->has_padding)
        {
            pad_top = html_view_length_to_px(&style->padding.top,
                                             ctx->viewport_w,
                                             ctx->viewport_h,
                                             ctx->viewport_w,
                                             ctx->viewport_h,
                                             ctx->base_font_px,
                                             false);
            pad_bottom = html_view_length_to_px(&style->padding.bottom,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                ctx->base_font_px,
                                                false);
        }

        ctx->y += pad_top;
        ctx->pending_space = false;

        video_color_t color = style->has_color ? style->color : video_make_color(0x00, 0x00, 0x00);

        char *text = NULL;
        size_t text_len = 0;
        size_t text_cap = 0;
        for (const html_node_t *child = node->first_child; child; child = child->next_sibling)
        {
            if (child->type == HTML_NODE_TEXT && child->text)
            {
                (void)html_view_buf_append(&text, &text_len, &text_cap, child->text, strlen(child->text));
            }
        }
        if (text && text_len > 0)
        {
            int text_w = html_view_text_width(ctx, text);
            int draw_x = ctx->body_x;
            if (style->has_text_align)
            {
                if (style->text_align == CSS_TEXT_ALIGN_CENTER)
                {
                    draw_x = ctx->body_x + (ctx->body_w - text_w) / 2;
                }
                else if (style->text_align == CSS_TEXT_ALIGN_RIGHT)
                {
                    draw_x = ctx->body_x + (ctx->body_w - text_w);
                }
            }
            if (draw_x < ctx->body_x)
            {
                draw_x = ctx->body_x;
            }

            int draw_top = ctx->y - ctx->priv->scroll_y;
            int baseline = html_view_baseline_for_rect(ctx, draw_top, ctx->line_height);

            if (ctx->record)
            {
                if (!ctx->record_failed && ctx->priv && text)
                {
                    html_view_render_cache_t *cache = &ctx->priv->render_cache;
                    char *owned = html_view_render_cache_strdup(cache, text);
                    if (!owned)
                    {
                        ctx->record_failed = true;
                    }
                    else
                    {
                        int baseline_off = baseline - draw_top;
                        size_t owned_len = strlen(owned);

                        if (style->has_text_shadow)
                        {
                            int dx = html_view_length_to_px(&style->text_shadow_x,
                                                            ctx->viewport_w,
                                                            ctx->viewport_h,
                                                            ctx->viewport_w,
                                                            ctx->viewport_h,
                                                            ctx->base_font_px,
                                                            true);
                            int dy = html_view_length_to_px(&style->text_shadow_y,
                                                            ctx->viewport_w,
                                                            ctx->viewport_h,
                                                            ctx->viewport_w,
                                                            ctx->viewport_h,
                                                            ctx->base_font_px,
                                                            false);
                            video_color_t shadow = style->has_text_shadow_color ? style->text_shadow_color : video_make_color(0x00, 0x00, 0x00);

                            html_view_op_t shadow_op = {0};
                            shadow_op.kind = HTML_VIEW_OP_TEXT;
                            shadow_op.x = (draw_x + dx) - ctx->doc_origin_x;
                            shadow_op.y = (draw_top + ctx->priv->scroll_y) - ctx->doc_origin_y;
                            shadow_op.h = ctx->line_height;
                            shadow_op.baseline_off = (int16_t)(baseline_off + dy);
                            shadow_op.font_px = (int16_t)ctx->actual_font_px;
                            shadow_op.color = shadow;
                            shadow_op.text = owned;
                            shadow_op.text_len = (uint32_t)owned_len;
                            shadow_op.text_owned = false;
                            if (!html_view_render_cache_push_op(cache, &shadow_op, cache->tile_h))
                            {
                                ctx->record_failed = true;
                            }

                            if (!ctx->record_failed)
                            {
                                html_view_op_t shadow_op2 = shadow_op;
                                shadow_op2.x += 1;
                                (void)html_view_render_cache_push_op(cache, &shadow_op2, cache->tile_h);
                            }
                        }

                        if (!ctx->record_failed)
                        {
                            html_view_op_t main_op = {0};
                            main_op.kind = HTML_VIEW_OP_TEXT;
                            main_op.x = draw_x - ctx->doc_origin_x;
                            main_op.y = (draw_top + ctx->priv->scroll_y) - ctx->doc_origin_y;
                            main_op.h = ctx->line_height;
                            main_op.baseline_off = (int16_t)baseline_off;
                            main_op.font_px = (int16_t)ctx->actual_font_px;
                            main_op.color = color;
                            main_op.text = owned;
                            main_op.text_len = (uint32_t)owned_len;
                            main_op.text_owned = false;
                            if (!html_view_render_cache_push_op(cache, &main_op, cache->tile_h))
                            {
                                ctx->record_failed = true;
                            }

                            if (!ctx->record_failed)
                            {
                                html_view_op_t main_op2 = main_op;
                                main_op2.x += 1;
                                (void)html_view_render_cache_push_op(cache, &main_op2, cache->tile_h);
                            }
                        }
                    }
                }
            }
            else if (ctx->draw && html_view_line_visible(ctx))
            {
                if (style->has_text_shadow)
                {
                    int dx = html_view_length_to_px(&style->text_shadow_x,
                                                    ctx->viewport_w,
                                                    ctx->viewport_h,
                                                    ctx->viewport_w,
                                                    ctx->viewport_h,
                                                    ctx->base_font_px,
                                                    true);
                    int dy = html_view_length_to_px(&style->text_shadow_y,
                                                    ctx->viewport_w,
                                                    ctx->viewport_h,
                                                    ctx->viewport_w,
                                                    ctx->viewport_h,
                                                    ctx->base_font_px,
                                                    false);
                    video_color_t shadow = style->has_text_shadow_color ? style->text_shadow_color : video_make_color(0x00, 0x00, 0x00);
                    html_view_draw_string_clipped(ctx, draw_x + dx, baseline + dy, text, shadow, &ctx->clip);
                    html_view_draw_string_clipped(ctx, draw_x + dx + 1, baseline + dy, text, shadow, &ctx->clip);
                }

                html_view_draw_string_clipped(ctx, draw_x, baseline, text, color, &ctx->clip);
                html_view_draw_string_clipped(ctx, draw_x + 1, baseline, text, color, &ctx->clip);
            }

            ctx->x = ctx->body_x;
            ctx->pending_space = false;
            html_view_ensure_line_visible(ctx);
        }
        free(text);

        html_view_new_line(ctx);
        ctx->y += pad_bottom;
        ctx->pending_space = false;
        return true;
    }

    if (strcmp(tag, "p") == 0)
    {
        if (ctx->x != ctx->body_x)
        {
            html_view_new_line(ctx);
        }

        if (style->has_clear && style->clear_mode != CSS_CLEAR_NONE)
        {
            int clear_y = html_view_float_max_bottom(ctx->floats, style->clear_mode);
            if (clear_y > ctx->y)
            {
                ctx->y = clear_y;
                ctx->x = ctx->body_x;
                ctx->pending_space = false;
            }
        }

        int saved_line_height = ctx->line_height;
        ctx->line_height = html_view_line_height_for_style(ctx, style);
        if (html_view_subtree_has_form_control(node) && ctx->line_height < atk_font_line_height() + 8)
        {
            ctx->line_height = atk_font_line_height() + 8;
        }

        int margin_top = 0;
        int margin_bottom = 0;
        if (style->has_margin)
        {
            if (style->margin.top.valid && !style->margin.top.is_auto)
            {
                margin_top = html_view_length_to_px(&style->margin.top,
                                                    ctx->viewport_w,
                                                    ctx->viewport_h,
                                                    ctx->body_w,
                                                    ctx->viewport_h,
                                                    ctx->base_font_px,
                                                    false);
            }
            if (style->margin.bottom.valid && !style->margin.bottom.is_auto)
            {
                margin_bottom = html_view_length_to_px(&style->margin.bottom,
                                                       ctx->viewport_w,
                                                       ctx->viewport_h,
                                                       ctx->body_w,
                                                       ctx->viewport_h,
                                                       ctx->base_font_px,
                                                       false);
            }
        }
        else
        {
            if (ctx->y > ctx->viewport_y)
            {
                margin_top = ctx->line_height / 3;
            }
            margin_bottom = ctx->line_height / 3;
        }
        if (margin_top < 0) margin_top = 0;
        if (margin_bottom < 0) margin_bottom = 0;

        ctx->y += margin_top;
        ctx->pending_space = false;
        html_view_render_children(ctx, node, style);
        html_view_new_line(ctx);
        ctx->y += margin_bottom;
        html_view_ensure_line_visible(ctx);
        ctx->line_height = saved_line_height;
        ctx->pending_space = false;
        return true;
    }

    if (strcmp(tag, "ul") == 0)
    {
        bool styled = style->has_margin ||
                      style->has_padding ||
                      style->has_border ||
                      style->has_background ||
                      style->has_width ||
                      style->has_height ||
                      style->has_float ||
                      (style->has_display && style->display != CSS_DISPLAY_INLINE);

        if (styled)
        {
            if (ctx->x != ctx->body_x)
            {
                html_view_new_line(ctx);
            }
            ctx->pending_space = false;
            html_view_render_children(ctx, node, style);
            if (ctx->x != ctx->body_x)
            {
                html_view_new_line(ctx);
            }
            ctx->pending_space = false;
            return true;
        }

        if (ctx->x != ctx->body_x)
        {
            html_view_new_line(ctx);
        }
        if (ctx->y > ctx->viewport_y)
        {
            ctx->y += ctx->line_height / 3;
        }
        ctx->pending_space = false;
        ctx->list_level += 1;
        html_view_render_children(ctx, node, style);
        if (ctx->list_level > 0)
        {
            ctx->list_level -= 1;
        }
        if (ctx->x != ctx->body_x)
        {
            html_view_new_line(ctx);
        }
        ctx->pending_space = false;
        return true;
    }

    if (strcmp(tag, "dl") == 0)
    {
        if (ctx->x != ctx->body_x)
        {
            html_view_new_line(ctx);
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

        int saved_body_x = ctx->body_x;
        int saved_body_w = ctx->body_w;
        int saved_max_x = ctx->max_x;
        int saved_y = ctx->y;

        ctx->body_x = saved_body_x + pad_left;
        ctx->body_w = saved_body_w - pad_left - pad_right;
        if (ctx->body_w < 0) ctx->body_w = 0;
        ctx->max_x = ctx->body_x + ctx->body_w;
        ctx->x = ctx->body_x;
        ctx->y = saved_y + pad_top;
        ctx->pending_space = false;

        html_view_render_children(ctx, node, style);

        int new_y = ctx->y + pad_bottom;

        ctx->body_x = saved_body_x;
        ctx->body_w = saved_body_w;
        ctx->max_x = saved_max_x;
        ctx->x = saved_body_x;
        ctx->y = new_y;
        ctx->pending_space = false;
        html_view_ensure_line_visible(ctx);
        return true;
    }

    if (strcmp(tag, "li") == 0)
    {
        css_display_t display = style->has_display ? style->display : CSS_DISPLAY_LIST_ITEM;
        if (display != CSS_DISPLAY_LIST_ITEM)
        {
            if (ctx->x != ctx->body_x)
            {
                html_view_new_line(ctx);
            }
            ctx->pending_space = false;
            html_view_render_children(ctx, node, style);
            if (ctx->x != ctx->body_x)
            {
                html_view_new_line(ctx);
            }
            ctx->pending_space = false;
            return true;
        }

        if (ctx->x != ctx->body_x)
        {
            html_view_new_line(ctx);
        }

        int saved_body_x = ctx->body_x;
        int saved_max_x = ctx->max_x;
        int saved_line_height = ctx->line_height;
        ctx->line_height = html_view_line_height_for_style(ctx, style);

        int level = ctx->list_level > 0 ? ctx->list_level : 1;
        int indent = level * 32;
        int bullet_size = 4;
        int bullet_x = saved_body_x + indent - 16;
        int bullet_draw_y = (ctx->y - ctx->priv->scroll_y) + ctx->line_height / 2 - bullet_size / 2;
        video_color_t bullet_color = style->has_color ? style->color : video_make_color(0x00, 0x00, 0x00);

        if (ctx->record || (ctx->draw && html_view_line_visible(ctx)))
        {
            html_view_draw_rect_clipped(ctx, bullet_x, bullet_draw_y, bullet_size, bullet_size, bullet_color, &ctx->clip);
        }

        ctx->body_x = saved_body_x + indent;
        ctx->x = ctx->body_x;
        ctx->max_x = saved_max_x;
        ctx->pending_space = false;

        html_view_render_children(ctx, node, style);
        html_view_new_line(ctx);

        ctx->body_x = saved_body_x;
        ctx->x = ctx->body_x;
        ctx->max_x = saved_max_x;
        ctx->line_height = saved_line_height;
        ctx->pending_space = false;
        return true;
    }

    if (strcmp(tag, "img") == 0)
    {
        if (ctx->x != ctx->body_x)
        {
            html_view_new_line(ctx);
        }

        int margin_top = 0;
        int margin_bottom = 0;
        if (style->has_margin)
        {
            if (style->margin.top.valid && !style->margin.top.is_auto)
            {
                margin_top = html_view_length_to_px(&style->margin.top,
                                                    ctx->viewport_w,
                                                    ctx->viewport_h,
                                                    ctx->viewport_w,
                                                    ctx->viewport_h,
                                                    ctx->base_font_px,
                                                    false);
            }
            if (style->margin.bottom.valid && !style->margin.bottom.is_auto)
            {
                margin_bottom = html_view_length_to_px(&style->margin.bottom,
                                                      ctx->viewport_w,
                                                      ctx->viewport_h,
                                                      ctx->viewport_w,
                                                      ctx->viewport_h,
                                                      ctx->base_font_px,
                                                      false);
            }
        }
        ctx->y += margin_top;
        ctx->pending_space = false;

        const char *src = html_attr_get(node, "src");
        html_view_image_t *img = src ? html_view_image_find(ctx->priv, src) : NULL;
        int img_w = img ? img->width : 0;
        int img_h = img ? img->height : 0;

        bool have_dimensions = (img_w > 0 || img_h > 0);
        if (!have_dimensions)
        {
            if (style->has_width && style->width.valid && !style->width.is_auto)
            {
                img_w = html_view_length_to_px(&style->width,
                                               ctx->viewport_w,
                                               ctx->viewport_h,
                                               ctx->body_w,
                                               ctx->viewport_h,
                                               ctx->base_font_px,
                                               true);
            }
            if (style->has_height && style->height.valid && !style->height.is_auto)
            {
                img_h = html_view_length_to_px(&style->height,
                                               ctx->viewport_w,
                                               ctx->viewport_h,
                                               ctx->viewport_w,
                                               ctx->viewport_h,
                                               ctx->base_font_px,
                                               false);
            }
            if (img_w < 0) img_w = 0;
            if (img_h < 0) img_h = 0;
            have_dimensions = (img_w > 0 || img_h > 0);
        }

        if (have_dimensions)
        {
            bool is_spacer_gif = false;
            if (src)
            {
                size_t slen = strlen(src);
                if (slen >= 5 && strcasecmp(src + slen - 5, "s.gif") == 0)
                {
                    is_spacer_gif = true;
                }
            }
            bool skip_placeholder = is_spacer_gif || web_url_is_svg(src);

            int draw_x = ctx->body_x;
            bool positioned = false;
            if (style->has_margin)
            {
                bool auto_left = style->margin.left.valid && style->margin.left.is_auto;
                bool auto_right = style->margin.right.valid && style->margin.right.is_auto;
                if (auto_left && auto_right)
                {
                    draw_x = ctx->body_x + (ctx->body_w - img_w) / 2;
                    positioned = true;
                }
                else if (style->margin.left.valid && !style->margin.left.is_auto)
                {
                    draw_x = ctx->body_x + html_view_length_to_px(&style->margin.left,
                                                                  ctx->viewport_w,
                                                                  ctx->viewport_h,
                                                                  ctx->viewport_w,
                                                                  ctx->viewport_h,
                                                                  ctx->base_font_px,
                                                                  true);
                    positioned = true;
                }
            }
            if (!positioned && style->has_text_align)
            {
                if (style->text_align == CSS_TEXT_ALIGN_CENTER)
                {
                    draw_x = ctx->body_x + (ctx->body_w - img_w) / 2;
                }
                else if (style->text_align == CSS_TEXT_ALIGN_RIGHT)
                {
                    draw_x = ctx->body_x + (ctx->body_w - img_w);
                }
            }
            if (draw_x < ctx->body_x)
            {
                draw_x = ctx->body_x;
            }
            int draw_y = ctx->y - ctx->priv->scroll_y;
            if (img && img->pixels && img_w > 0 && img_h > 0)
            {
                if (ctx->draw)
                {
                    html_view_blit_rgba32_clipped(ctx, draw_x, draw_y, img_w, img_h, img->pixels, img->stride_bytes, &ctx->clip);
                }
                else if (ctx->record)
                {
                    html_view_blit_rgba32_clipped(ctx, draw_x, draw_y, img_w, img_h, img->pixels, img->stride_bytes, &ctx->clip);
                }
            }
            else
            {
                if (!skip_placeholder && img_w > 0 && img_h > 0)
                {
                    video_color_t ph = video_make_color(0xDD, 0xDD, 0xDD);
                    html_view_draw_rect_clipped(ctx, draw_x, draw_y, img_w, img_h, ph, &ctx->clip);
                }
            }

            if (style->has_border && img_w > 0 && img_h > 0 && (img || !skip_placeholder))
            {
                int bt = html_view_length_to_px(&style->border_width.top,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                img_w,
                                                ctx->viewport_h,
                                                ctx->base_font_px,
                                                false);
                int br = html_view_length_to_px(&style->border_width.right,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                img_w,
                                                ctx->viewport_h,
                                                ctx->base_font_px,
                                                true);
                int bb = html_view_length_to_px(&style->border_width.bottom,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                img_w,
                                                ctx->viewport_h,
                                                ctx->base_font_px,
                                                false);
                int bl = html_view_length_to_px(&style->border_width.left,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                img_w,
                                                ctx->viewport_h,
                                                ctx->base_font_px,
                                                true);
                if (bt < 0) bt = 0;
                if (br < 0) br = 0;
                if (bb < 0) bb = 0;
                if (bl < 0) bl = 0;
                if (bt > 0 || br > 0 || bb > 0 || bl > 0)
                {
                    video_color_t border_color = style->has_border_color ? style->border_color : video_make_color(0x00, 0x00, 0x00);
                    html_view_draw_border_sides_clipped(ctx,
                                                        draw_x,
                                                        draw_y,
                                                        img_w,
                                                        img_h,
                                                        bt,
                                                        br,
                                                        bb,
                                                        bl,
                                                        border_color,
                                                        &ctx->clip);
                }
            }

            ctx->y += img_h;
        }
        else
        {
            const char *alt = html_attr_get(node, "alt");
            if (!alt || alt[0] == '\0')
            {
                alt = "[image]";
            }
            video_color_t color = style->has_color ? style->color : video_make_color(0x00, 0x00, 0x00);
            html_view_draw_text(ctx, alt, color, false, false);
            html_view_new_line(ctx);
        }

        ctx->y += margin_bottom;
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
        return true;
    }

    bool styled = style->has_margin ||
                  style->has_padding ||
                  style->has_border ||
                  style->has_background ||
                  style->has_width ||
                  style->has_height;
    if (!styled)
    {
        return false;
    }

    if (!html_view_is_block_tag(tag))
    {
        return false;
    }

    if (ctx->x != ctx->body_x)
    {
        html_view_new_line(ctx);
    }

    if (style->has_clear && style->clear_mode != CSS_CLEAR_NONE)
    {
        int clear_y = html_view_float_max_bottom(ctx->floats, style->clear_mode);
        if (clear_y > ctx->y)
        {
            ctx->y = clear_y;
            ctx->x = ctx->body_x;
            ctx->pending_space = false;
        }
    }

    int saved_line_height = ctx->line_height;
    ctx->line_height = html_view_line_height_for_style(ctx, style);
    if (html_view_subtree_has_form_control(node) && ctx->line_height < atk_font_line_height() + 8)
    {
        ctx->line_height = atk_font_line_height() + 8;
    }

    int margin_top = 0;
    int margin_right = 0;
    int margin_bottom = 0;
    int margin_left = 0;
    bool auto_left = false;
    bool auto_right = false;
    if (style->has_margin)
    {
        if (style->margin.top.valid && !style->margin.top.is_auto)
        {
            margin_top = html_view_length_to_px(&style->margin.top,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                ctx->body_w,
                                                ctx->viewport_h,
                                                ctx->base_font_px,
                                                false);
        }
        if (style->margin.right.valid && !style->margin.right.is_auto)
        {
            margin_right = html_view_length_to_px(&style->margin.right,
                                                  ctx->viewport_w,
                                                  ctx->viewport_h,
                                                  ctx->body_w,
                                                  ctx->viewport_h,
                                                  ctx->base_font_px,
                                                  true);
        }
        if (style->margin.bottom.valid && !style->margin.bottom.is_auto)
        {
            margin_bottom = html_view_length_to_px(&style->margin.bottom,
                                                   ctx->viewport_w,
                                                   ctx->viewport_h,
                                                   ctx->body_w,
                                                   ctx->viewport_h,
                                                   ctx->base_font_px,
                                                   false);
        }
        if (style->margin.left.valid && !style->margin.left.is_auto)
        {
            margin_left = html_view_length_to_px(&style->margin.left,
                                                 ctx->viewport_w,
                                                 ctx->viewport_h,
                                                 ctx->body_w,
                                                 ctx->viewport_h,
                                                 ctx->base_font_px,
                                                 true);
        }
        auto_left = style->margin.left.valid && style->margin.left.is_auto;
        auto_right = style->margin.right.valid && style->margin.right.is_auto;
    }
    if (margin_top < 0) margin_top = 0;
    if (margin_right < 0) margin_right = 0;
    if (margin_bottom < 0) margin_bottom = 0;
    if (margin_left < 0) margin_left = 0;

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

    int available_w = ctx->body_w;
    if (available_w < 0) available_w = 0;
    int content_w = available_w - margin_left - margin_right - pad_left - pad_right - border_left - border_right;
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
    if (content_w < 0) content_w = 0;

    if (auto_left || auto_right)
    {
        int total_box_w = content_w + pad_left + pad_right + border_left + border_right;
        int free_w = available_w - total_box_w;
        if (free_w < 0) free_w = 0;
        if (auto_left && auto_right)
        {
            margin_left = free_w / 2;
            margin_right = free_w - margin_left;
        }
        else if (auto_left)
        {
            margin_left = free_w;
        }
        else if (auto_right)
        {
            margin_right = free_w;
        }
    }

    int border_box_w = content_w + pad_left + pad_right + border_left + border_right;
    if (border_box_w < 0) border_box_w = 0;

    int border_doc_x = ctx->body_x + margin_left;
    int content_doc_x = border_doc_x + border_left + pad_left;

    ctx->y += margin_top;
    int border_doc_y = ctx->y;
    int content_doc_y = border_doc_y + border_top + pad_top;

    int specified_h = 0;
    if (style->has_height && style->height.valid && !style->height.is_auto)
    {
        specified_h = html_view_length_to_px(&style->height,
                                             ctx->viewport_w,
                                             ctx->viewport_h,
                                             ctx->body_w,
                                             ctx->viewport_h,
                                             ctx->base_font_px,
                                             false);
        if (specified_h < 0) specified_h = 0;
    }

    if (style->has_background || style->has_border)
    {
        int content_h = html_view_measure_block_children_height(ctx, node, style, content_w);
        if (content_h < specified_h)
        {
            content_h = specified_h;
        }

        int border_box_h = content_h + pad_top + pad_bottom + border_top + border_bottom;
        if (border_box_h < 0) border_box_h = 0;
        int draw_y = border_doc_y - ctx->priv->scroll_y;
        if (style->has_background && border_box_w > 0 && border_box_h > 0)
        {
            html_view_draw_rect_clipped(ctx, border_doc_x, draw_y, border_box_w, border_box_h, style->background, &ctx->clip);
        }
        if (style->has_border && border_box_w > 0 && border_box_h > 0)
        {
            if (border_top > 0 || border_right > 0 || border_bottom > 0 || border_left > 0)
            {
                video_color_t border_color = style->has_border_color ? style->border_color : video_make_color(0x00, 0x00, 0x00);
                html_view_draw_border_sides_clipped(ctx,
                                                    border_doc_x,
                                                    draw_y,
                                                    border_box_w,
                                                    border_box_h,
                                                    border_top,
                                                    border_right,
                                                    border_bottom,
                                                    border_left,
                                                    border_color,
                                                    &ctx->clip);
            }
        }
    }

    int saved_body_x = ctx->body_x;
    int saved_body_w = ctx->body_w;
    int saved_max_x = ctx->max_x;
    video_color_t saved_bg = ctx->bg;

    ctx->body_x = content_doc_x;
    ctx->body_w = content_w;
    if (ctx->body_w < 0) ctx->body_w = 0;
    ctx->max_x = ctx->body_x + ctx->body_w;
    ctx->x = ctx->body_x;
    ctx->y = content_doc_y;
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

    if (style->has_background)
    {
        ctx->bg = style->background;
    }

    html_view_render_children(ctx, node, style);
    if (ctx->x != ctx->body_x)
    {
        html_view_new_line(ctx);
    }

    int content_end_y = ctx->y;
    int content_h = content_end_y - content_doc_y;
    if (specified_h > content_h)
    {
        content_end_y = content_doc_y + specified_h;
    }

    ctx->body_x = saved_body_x;
    ctx->body_w = saved_body_w;
    ctx->max_x = saved_max_x;
    ctx->x = ctx->body_x;
    ctx->y = content_end_y + pad_bottom + border_bottom + margin_bottom;
    ctx->bg = saved_bg;
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
    ctx->line_height = saved_line_height;
    return true;

    return false;
}
