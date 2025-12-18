static atk_html_view_priv_t *html_view_priv_mut(atk_widget_t *view)
{
    return (atk_html_view_priv_t *)atk_widget_priv(view, &ATK_HTML_VIEW_CLASS);
}

static void html_view_invalidate(const atk_widget_t *view)
{
    if (!view || !view->parent)
    {
        return;
    }
    int origin_x = view->parent->x + view->x;
    int origin_y = view->parent->y + view->y;
    atk_dirty_mark_rect(origin_x, origin_y, view->width, view->height);
    video_request_refresh_window(view->parent);
}

static bool html_view_hit_test_cb(const atk_widget_t *widget,
                                  int origin_x,
                                  int origin_y,
                                  int px,
                                  int py,
                                  void *context)
{
    (void)context;
    if (!widget)
    {
        return false;
    }
    int x0 = origin_x + widget->x;
    int y0 = origin_y + widget->y;
    int x1 = x0 + widget->width;
    int y1 = y0 + widget->height;
    return (px >= x0 && px < x1 && py >= y0 && py < y1);
}

static atk_mouse_response_t html_view_mouse_cb(atk_widget_t *widget,
                                               const atk_mouse_event_t *event,
                                               void *context)
{
    (void)context;

    if (!widget || !event)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    atk_html_view_priv_t *priv = html_view_priv_mut(widget);
    if (!priv)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    const html_view_render_cache_t *cache = &priv->render_cache;
    if (!cache->valid || !cache->tiles || cache->tile_used == 0 || cache->op_count == 0)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    int tile_h = cache->tile_h > 0 ? cache->tile_h : ATK_HTML_VIEW_RENDER_TILE_H;
    if (tile_h <= 0)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    int doc_x = event->local_x - cache->doc_origin_local_x;
    int doc_y = event->local_y - cache->doc_origin_local_y + priv->scroll_y;

    const char *hit_href = NULL;
    if (doc_x >= 0 && doc_y >= 0)
    {
        size_t tile_index = (size_t)((uint32_t)doc_y / (uint32_t)tile_h);
        for (int tile_off = -1; tile_off <= 1 && !hit_href; ++tile_off)
        {
            size_t t = tile_index;
            if (tile_off < 0)
            {
                if (t == 0)
                {
                    continue;
                }
                t -= 1;
            }
            else if (tile_off > 0)
            {
                t += 1;
            }
            if (t >= cache->tile_used || t >= cache->tile_count)
            {
                continue;
            }
            const html_view_tile_t *tile = &cache->tiles[t];
            for (size_t i = 0; i < tile->count; ++i)
            {
                size_t op_index = tile->ops[i];
                if (op_index >= cache->op_count)
                {
                    continue;
                }

                const html_view_op_t *op = &cache->ops[op_index];
                if (!op->href || op->href[0] == '\0' || op->w <= 0 || op->h <= 0)
                {
                    continue;
                }

                int32_t x0 = op->x;
                int32_t y0 = op->y;
                int32_t x1 = x0 + op->w;
                int32_t y1 = y0 + op->h;

                if (doc_x >= x0 && doc_x < x1 && doc_y >= y0 && doc_y < y1)
                {
                    hit_href = op->href;
                    break;
                }
            }
        }
    }

    if (event->pressed_edge && event->left_pressed)
    {
        if (hit_href && priv->link_handler)
        {
            priv->pressed_href = hit_href;
            return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_CAPTURE;
        }
        priv->pressed_href = NULL;
        return ATK_MOUSE_RESPONSE_NONE;
    }

    if (event->released_edge)
    {
        const char *pressed_href = priv->pressed_href;
        priv->pressed_href = NULL;

        if (pressed_href && hit_href && priv->link_handler && pressed_href == hit_href)
        {
            priv->link_handler(widget, hit_href, priv->link_context);
        }

        return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_RELEASE;
    }

    return ATK_MOUSE_RESPONSE_NONE;
}

static atk_key_response_t html_view_key_cb(atk_widget_t *widget,
                                           int key,
                                           int modifiers,
                                           int action,
                                           void *context)
{
    (void)widget;
    (void)key;
    (void)modifiers;
    (void)action;
    (void)context;
    return ATK_KEY_RESPONSE_NONE;
}

static bool html_view_buf_append(char **buf, size_t *len, size_t *cap, const char *data, size_t data_len)
{
    if (!buf || !len || !cap)
    {
        return false;
    }
    if (data_len == 0)
    {
        return true;
    }
    if (!data)
    {
        return false;
    }

    size_t needed = *len + data_len + 1;
    if (needed > *cap)
    {
        size_t new_cap = (*cap == 0) ? 1024 : *cap;
        while (new_cap < needed)
        {
            new_cap *= 2;
        }
        char *new_buf = (char *)realloc(*buf, new_cap);
        if (!new_buf)
        {
            return false;
        }
        *buf = new_buf;
        *cap = new_cap;
    }

    memcpy(*buf + *len, data, data_len);
    *len += data_len;
    (*buf)[*len] = '\0';
    return true;
}

static char *html_view_strdup(const char *src)
{
    if (!src)
    {
        src = "";
    }
    size_t len = strlen(src);
    char *dst = (char *)malloc(len + 1);
    if (!dst)
    {
        return NULL;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
    return dst;
}

static void html_view_render_cache_clear(html_view_render_cache_t *cache)
{
    if (!cache)
    {
        return;
    }

    for (size_t i = 0; i < cache->owned_text_count; ++i)
    {
        free(cache->owned_text[i]);
    }
    free(cache->owned_text);
    cache->owned_text = NULL;
    cache->owned_text_count = 0;
    cache->owned_text_cap = 0;

    if (cache->ops)
    {
        for (size_t i = 0; i < cache->op_count; ++i)
        {
            html_view_op_t *op = &cache->ops[i];
            if (op->kind == HTML_VIEW_OP_TEXT && op->text_owned)
            {
                free((void *)op->text);
            }
        }
    }

    for (size_t i = 0; i < cache->tile_count; ++i)
    {
        free(cache->tiles[i].ops);
        cache->tiles[i].ops = NULL;
        cache->tiles[i].count = 0;
        cache->tiles[i].cap = 0;
    }

    free(cache->tiles);
    free(cache->ops);
    memset(cache, 0, sizeof(*cache));
}

static bool html_view_render_cache_ensure_tiles(html_view_render_cache_t *cache, size_t needed)
{
    if (!cache)
    {
        return false;
    }
    if (needed <= cache->tile_count)
    {
        return true;
    }

    size_t new_count = cache->tile_count ? cache->tile_count : 8;
    while (new_count < needed)
    {
        new_count *= 2;
    }

    html_view_tile_t *new_tiles = (html_view_tile_t *)realloc(cache->tiles, new_count * sizeof(*new_tiles));
    if (!new_tiles)
    {
        return false;
    }
    memset(new_tiles + cache->tile_count, 0, (new_count - cache->tile_count) * sizeof(*new_tiles));
    cache->tiles = new_tiles;
    cache->tile_count = new_count;
    return true;
}

static bool html_view_render_cache_add_op_to_tile(html_view_render_cache_t *cache, size_t tile_index, size_t op_index)
{
    if (!cache)
    {
        return false;
    }
    if (!html_view_render_cache_ensure_tiles(cache, tile_index + 1))
    {
        return false;
    }
    if (tile_index + 1 > cache->tile_used)
    {
        cache->tile_used = tile_index + 1;
    }

    html_view_tile_t *tile = &cache->tiles[tile_index];
    if (tile->count == tile->cap)
    {
        size_t new_cap = tile->cap ? (tile->cap * 2) : 64;
        size_t *new_ops = (size_t *)realloc(tile->ops, new_cap * sizeof(*new_ops));
        if (!new_ops)
        {
            return false;
        }
        tile->ops = new_ops;
        tile->cap = new_cap;
    }
    tile->ops[tile->count++] = op_index;
    return true;
}

static char *html_view_render_cache_strdup(html_view_render_cache_t *cache, const char *text)
{
    if (!cache || !text)
    {
        return NULL;
    }

    char *dup = html_view_strdup(text);
    if (!dup)
    {
        return NULL;
    }

    if (cache->owned_text_count == cache->owned_text_cap)
    {
        size_t new_cap = cache->owned_text_cap ? (cache->owned_text_cap * 2) : 64;
        char **new_list = (char **)realloc(cache->owned_text, new_cap * sizeof(*new_list));
        if (!new_list)
        {
            free(dup);
            return NULL;
        }
        cache->owned_text = new_list;
        cache->owned_text_cap = new_cap;
    }

    cache->owned_text[cache->owned_text_count++] = dup;
    return dup;
}

static bool html_view_render_cache_push_op(html_view_render_cache_t *cache, const html_view_op_t *op, int tile_h)
{
    if (!cache || !op || tile_h <= 0)
    {
        return false;
    }

    if (cache->op_count == cache->op_cap)
    {
        size_t new_cap = cache->op_cap ? (cache->op_cap * 2) : 1024;
        html_view_op_t *new_ops = (html_view_op_t *)realloc(cache->ops, new_cap * sizeof(*new_ops));
        if (!new_ops)
        {
            return false;
        }
        cache->ops = new_ops;
        cache->op_cap = new_cap;
    }

    size_t index = cache->op_count++;
    cache->ops[index] = *op;

    int32_t y0 = op->y;
    int32_t y1 = op->y;
    if (op->kind == HTML_VIEW_OP_TEXT)
    {
        y1 = y0 + op->h;
    }
    else if (op->kind == HTML_VIEW_OP_RECT || op->kind == HTML_VIEW_OP_IMAGE || op->kind == HTML_VIEW_OP_CONTROL)
    {
        y1 = y0 + op->h;
    }

    if (y0 < 0)
    {
        y0 = 0;
    }
    if (y1 < y0)
    {
        y1 = y0;
    }

    size_t tile0 = (size_t)((uint32_t)y0 / (uint32_t)tile_h);
    size_t tile1 = (y1 > 0) ? (size_t)((uint32_t)(y1 - 1) / (uint32_t)tile_h) : tile0;
    for (size_t t = tile0; t <= tile1; ++t)
    {
        if (!html_view_render_cache_add_op_to_tile(cache, t, index))
        {
            return false;
        }
    }

    return true;
}

static void html_view_render_cache_draw_text_span(html_view_ctx_t *ctx,
                                                  int x,
                                                  int baseline_y,
                                                  const char *text,
                                                  uint32_t len,
                                                  video_color_t color)
{
    if (!ctx || !text || len == 0)
    {
        return;
    }

    char scratch[128];
    const char *tmp = NULL;
    char *heap = NULL;
    if (len < sizeof(scratch))
    {
        memcpy(scratch, text, len);
        scratch[len] = '\0';
        tmp = scratch;
    }
    else
    {
        heap = (char *)malloc((size_t)len + 1);
        if (!heap)
        {
            return;
        }
        memcpy(heap, text, len);
        heap[len] = '\0';
        tmp = heap;
    }

    html_view_draw_string_clipped(ctx, x, baseline_y, tmp, color, &ctx->clip);
    free(heap);
}

static void html_view_render_cache_draw_visible(html_view_ctx_t *ctx)
{
    if (!ctx || !ctx->priv)
    {
        return;
    }

    const html_view_render_cache_t *cache = &ctx->priv->render_cache;
    if (!cache->valid || !cache->tiles || cache->tile_used == 0)
    {
        return;
    }

    int tile_h = cache->tile_h > 0 ? cache->tile_h : ATK_HTML_VIEW_RENDER_TILE_H;
    if (tile_h <= 0)
    {
        return;
    }

    int scroll_y = ctx->priv->scroll_y;
    int visible_y0 = scroll_y - tile_h;
    int visible_y1 = scroll_y + ctx->viewport_h + tile_h;
    if (visible_y0 < 0) visible_y0 = 0;

    int start_tile = scroll_y / tile_h;
    int end_tile = (scroll_y + ctx->viewport_h) / tile_h;
    if (start_tile > 0) start_tile -= 1;
    end_tile += 1;
    if (start_tile < 0) start_tile = 0;
    if (cache->tile_used > 0 && (size_t)end_tile >= cache->tile_used)
    {
        end_tile = (int)cache->tile_used - 1;
    }

    int tile_count = (end_tile - start_tile) + 1;
    if (tile_count <= 0)
    {
        return;
    }

    size_t tile_pos_stack[32];
    size_t *tile_pos = tile_pos_stack;
    if (tile_count > (int)(sizeof(tile_pos_stack) / sizeof(tile_pos_stack[0])))
    {
        tile_pos = (size_t *)calloc((size_t)tile_count, sizeof(*tile_pos));
        if (!tile_pos)
        {
            return;
        }
    }
    else
    {
        memset(tile_pos, 0, (size_t)tile_count * sizeof(*tile_pos));
    }

    size_t last_op_index = (size_t)-1;
    for (;;)
    {
        size_t min_op_index = (size_t)-1;
        int min_tile_slot = -1;

        for (int i = 0; i < tile_count; ++i)
        {
            int t = start_tile + i;
            if (t < 0 || (size_t)t >= cache->tile_count)
            {
                continue;
            }

            const html_view_tile_t *tile = &cache->tiles[t];
            size_t pos = tile_pos[i];
            if (pos >= tile->count)
            {
                continue;
            }

            size_t op_index = tile->ops[pos];
            if (op_index < min_op_index)
            {
                min_op_index = op_index;
                min_tile_slot = i;
            }
        }

        if (min_tile_slot < 0)
        {
            break;
        }

        tile_pos[min_tile_slot] += 1;
        if (min_op_index == last_op_index)
        {
            continue;
        }
        last_op_index = min_op_index;

        if (min_op_index >= cache->op_count)
        {
            continue;
        }
        const html_view_op_t *op = &cache->ops[min_op_index];

        int op_y0 = (int)op->y;
        int op_y1 = (int)op->y + (int)op->h;
        if (op_y1 <= visible_y0 || op_y0 >= visible_y1)
        {
            continue;
        }

        int abs_x = ctx->doc_origin_x + (int)op->x;
        int abs_y = ctx->doc_origin_y + (int)op->y - scroll_y;

        switch (op->kind)
        {
            case HTML_VIEW_OP_RECT:
                html_view_draw_rect_clipped(ctx, abs_x, abs_y, (int)op->w, (int)op->h, op->color, &ctx->clip);
                break;
            case HTML_VIEW_OP_TEXT:
            {
                int baseline_y = abs_y + (int)op->baseline_off;
                int saved_font_px = ctx->actual_font_px;
                if (op->font_px > 0)
                {
                    ctx->actual_font_px = op->font_px;
                }
                html_view_render_cache_draw_text_span(ctx, abs_x, baseline_y, op->text, op->text_len, op->color);
                ctx->actual_font_px = saved_font_px;
                break;
            }
            case HTML_VIEW_OP_IMAGE:
                html_view_blit_rgba32_clipped(ctx,
                                             abs_x,
                                             abs_y,
                                             (int)op->w,
                                             (int)op->h,
                                             op->pixels,
                                             op->stride_bytes,
                                             &ctx->clip);
                break;
            case HTML_VIEW_OP_CONTROL:
                html_view_place_control_widget(ctx, op->widget, abs_x, abs_y, (int)op->w, (int)op->h);
                break;
            default:
                break;
        }
    }

    if (tile_pos != tile_pos_stack)
    {
        free(tile_pos);
    }
}

static void html_view_images_clear(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    html_view_image_t *img = priv->images;
    while (img)
    {
        html_view_image_t *next = img->next;
        free(img->src);
        free(img->pixels);
        free(img);
        img = next;
    }
    priv->images = NULL;
}

static void html_view_window_remove_widget(atk_widget_t *window, atk_widget_t *child)
{
    if (!window || !child)
    {
        return;
    }

    atk_window_priv_t *wpriv = (atk_window_priv_t *)atk_widget_priv(window, &ATK_WINDOW_CLASS);
    if (!wpriv)
    {
        return;
    }

    atk_list_node_t *node = atk_list_find(&wpriv->children, child);
    if (node)
    {
        atk_list_remove(&wpriv->children, node);
    }

    node = atk_list_find(&wpriv->buttons, child);
    if (node)
    {
        atk_list_remove(&wpriv->buttons, node);
    }

    node = atk_list_find(&wpriv->text_inputs, child);
    if (node)
    {
        atk_list_remove(&wpriv->text_inputs, node);
    }

    node = atk_list_find(&wpriv->scrollbars, child);
    if (node)
    {
        atk_list_remove(&wpriv->scrollbars, node);
    }

    atk_state_t *state = atk_state_get();
    if (state && atk_state_focus_widget(state) == child)
    {
        if (atk_widget_is_a(child, &ATK_TEXT_INPUT_CLASS))
        {
            atk_text_input_focus(state, NULL);
        }
        else
        {
            atk_state_set_focus_widget(state, NULL);
        }
    }

    atk_widget_destroy_any(child);
}

static void html_view_controls_clear(atk_widget_t *view, atk_html_view_priv_t *priv)
{
    if (!view || !priv)
    {
        return;
    }

    atk_widget_t *window = view->parent;
    html_view_control_t *ctrl = priv->controls;
    while (ctrl)
    {
        html_view_control_t *next = ctrl->next;
        if (window && ctrl->widget)
        {
            html_view_window_remove_widget(window, ctrl->widget);
        }
        free(ctrl);
        ctrl = next;
    }
    priv->controls = NULL;
}

static void html_view_controls_hide_all(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    for (html_view_control_t *ctrl = priv->controls; ctrl; ctrl = ctrl->next)
    {
        if (ctrl->widget)
        {
            ctrl->widget->used = false;
        }
    }
}

static html_view_control_t *html_view_control_find(atk_html_view_priv_t *priv, const html_node_t *node)
{
    if (!priv || !node)
    {
        return NULL;
    }
    for (html_view_control_t *ctrl = priv->controls; ctrl; ctrl = ctrl->next)
    {
        if (ctrl->node == node)
        {
            return ctrl;
        }
    }
    return NULL;
}

static void html_view_collect_text(const html_node_t *node, char **buf, size_t *len, size_t *cap)
{
    if (!node || !buf || !len || !cap)
    {
        return;
    }

    const html_node_t **stack = NULL;
    size_t stack_cap = 0;
    size_t sp = 0;

    const html_node_t *cur = node->first_child;
    while (cur)
    {
        if (cur->type == HTML_NODE_TEXT && cur->text)
        {
            (void)html_view_buf_append(buf, len, cap, cur->text, strlen(cur->text));
        }

        if (cur->type == HTML_NODE_ELEMENT && cur->first_child)
        {
            if (cur->next_sibling)
            {
                if (sp == stack_cap)
                {
                    size_t new_cap = stack_cap ? (stack_cap * 2) : 32;
                    const html_node_t **new_stack = (const html_node_t **)realloc(stack, new_cap * sizeof(*new_stack));
                    if (!new_stack)
                    {
                        break;
                    }
                    stack = new_stack;
                    stack_cap = new_cap;
                }
                stack[sp++] = cur->next_sibling;
            }
            cur = cur->first_child;
            continue;
        }

        if (cur->next_sibling)
        {
            cur = cur->next_sibling;
            continue;
        }
        if (sp > 0)
        {
            cur = stack[--sp];
            continue;
        }
        break;
    }

    free(stack);
}

static void html_view_trim_collapse_ws(char *text)
{
    if (!text)
    {
        return;
    }

    size_t len = strlen(text);
    size_t start = 0;
    while (start < len && isspace((unsigned char)text[start]))
    {
        start++;
    }
    size_t end = len;
    while (end > start && isspace((unsigned char)text[end - 1]))
    {
        end--;
    }

    size_t out = 0;
    bool pending_space = false;
    for (size_t i = start; i < end; ++i)
    {
        unsigned char c = (unsigned char)text[i];
        if (isspace(c))
        {
            pending_space = true;
            continue;
        }
        if (pending_space && out > 0)
        {
            text[out++] = ' ';
            pending_space = false;
        }
        text[out++] = (char)c;
    }
    text[out] = '\0';
}
