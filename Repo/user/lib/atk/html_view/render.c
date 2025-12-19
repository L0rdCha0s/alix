static void html_view_render_node(html_view_ctx_t *ctx, const html_node_t *node, const css_style_t *parent_style);

static void html_view_render_children(html_view_ctx_t *ctx, const html_node_t *node, const css_style_t *style)
{
    if (!ctx || !node)
    {
        return;
    }
    for (const html_node_t *child = node->first_child; child; child = child->next_sibling)
    {
        html_view_render_node(ctx, child, style);
    }
}

static void html_view_render_node(html_view_ctx_t *ctx, const html_node_t *node, const css_style_t *parent_style)
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
        if (style->display == CSS_DISPLAY_INLINE)
        {
            block = false;
        }
        else if (style->display == CSS_DISPLAY_BLOCK || style->display == CSS_DISPLAY_LIST_ITEM)
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

    if (style->has_float && style->float_mode != CSS_FLOAT_NONE &&
        !html_view_is_form_control_tag(tag) &&
        strcmp(tag, "img") != 0)
    {
        html_view_render_float_box(ctx, node, style, style->float_mode);
        goto out;
    }

    if (strcmp(tag, "br") == 0)
    {
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
        goto out;
    }

    if (strcmp(tag, "table") == 0)
    {
        html_view_render_table(ctx, node, style, parent_style);
        goto out;
    }

    if (strcmp(tag, "input") == 0)
    {
        const char *type = html_attr_get(node, "type");
        if (!type || type[0] == '\0')
        {
            type = "text";
        }
        if (strcasecmp(type, "hidden") == 0)
        {
            goto out;
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
        goto out;
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
        goto out;
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
        goto out;
    }

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
        goto out;
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
        goto out;
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
            goto out;
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
        goto out;
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
        goto out;
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
            goto out;
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
        goto out;
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
        goto out;
    }

    if (strcmp(tag, "b") == 0 || strcmp(tag, "strong") == 0)
    {
        bool saved_bold = ctx->text_bold;
        ctx->text_bold = true;
        html_view_render_children(ctx, node, style);
        ctx->text_bold = saved_bold;
        goto out;
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
        ctx->text_underline = saved_underline;
        ctx->active_href = saved_href;
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
