#include "atk/html_view/html_view_internal.h"

#define HTML_VIEW_RENDER_DEBOUNCE_MS 32u

static void html_view_position_scrollbar(atk_widget_t *view, atk_html_view_priv_t *priv)
{
    if (!view || !priv || !priv->scrollbar)
    {
        return;
    }
    int sb_w = priv->scrollbar_width;
    if (sb_w < 4)
    {
        sb_w = 4;
    }
    int sb_x = view->x + view->width - sb_w;
    if (sb_x < view->x)
    {
        sb_x = view->x;
    }
    priv->scrollbar->x = sb_x;
    priv->scrollbar->y = view->y;
    priv->scrollbar->width = sb_w;
    priv->scrollbar->height = view->height;
}

static void html_view_scrollbar_changed(atk_widget_t *scrollbar, void *context, int value)
{
    (void)scrollbar;
    atk_widget_t *view = (atk_widget_t *)context;
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        return;
    }
    priv->scroll_y = value;
    html_view_invalidate(view);
}

static void html_view_update_scrollbar(atk_widget_t *view, atk_html_view_priv_t *priv)
{
    if (!view || !priv || !priv->scrollbar)
    {
        return;
    }
    int viewport_h = view->height - ATK_HTML_VIEW_PADDING * 2;
    if (viewport_h < 0)
    {
        viewport_h = 0;
    }
    int max_scroll = priv->content_height - viewport_h;
    if (max_scroll < 0)
    {
        max_scroll = 0;
    }
    if (priv->scroll_y < 0) priv->scroll_y = 0;
    if (priv->scroll_y > max_scroll) priv->scroll_y = max_scroll;
    atk_scrollbar_set_range(priv->scrollbar, 0, max_scroll, viewport_h);
    atk_scrollbar_set_value(priv->scrollbar, priv->scroll_y);
}

bool html_view_render_try_lock(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return false;
    }
    return __sync_lock_test_and_set(&priv->render_lock.state, 1u) == 0u;
}

void html_view_render_unlock(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    alix_mutex_unlock(&priv->render_lock);
}

void html_view_render_cache_invalidate_locked(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    html_view_render_cache_clear(&priv->render_cache);
    __atomic_store_n(&priv->render_cache_dirty, 1u, __ATOMIC_RELEASE);
}

void html_view_render_cache_invalidate(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    __atomic_store_n(&priv->render_cache_dirty, 1u, __ATOMIC_RELEASE);
    if (html_view_render_try_lock(priv))
    {
        html_view_render_cache_clear(&priv->render_cache);
        html_view_render_unlock(priv);
    }
}

static bool html_view_render_cache_rebuild_locked(atk_widget_t *view, atk_html_view_priv_t *priv)
{
    if (!view || !priv)
    {
        return false;
    }

    int abs_x = 0;
    int abs_y = 0;
    atk_widget_absolute_position(view, &abs_x, &abs_y);

    int sb_w = priv->scrollbar ? priv->scrollbar_width : 0;
    int viewport_x = abs_x + ATK_HTML_VIEW_PADDING;
    int viewport_y = abs_y + ATK_HTML_VIEW_PADDING;
    int viewport_w = view->width - ATK_HTML_VIEW_PADDING * 2 - sb_w;
    int viewport_h = view->height - ATK_HTML_VIEW_PADDING * 2;
    if (viewport_w < 0) viewport_w = 0;
    if (viewport_h < 0) viewport_h = 0;

    video_color_t default_page_bg = video_make_color(0xFF, 0xFF, 0xFF);
    video_color_t default_text = video_make_color(0x00, 0x00, 0x00);

    css_style_t base_style = {0};
    base_style.has_color = true;
    base_style.color = default_text;
    base_style.has_font_size = true;
    base_style.font_size = (css_length_t){
        .valid = true,
        .is_auto = false,
        .value_milli = atk_font_line_height() * 1000,
        .unit = CSS_UNIT_PX,
    };
    base_style.has_line_height = true;
    base_style.line_height_milli = 1000;

    const html_node_t *html_node = NULL;
    const html_node_t *body_node = NULL;
    if (priv->doc && priv->doc->root)
    {
        html_node = html_view_find_first_element(priv->doc->root, "html");
        body_node = html_view_find_first_element(priv->doc->root, "body");
    }

    css_style_t html_style = {0};
    if (html_node)
    {
        html_view_style_for_node(&html_style, priv->sheet, &base_style, html_node);
    }
    else
    {
        html_style = base_style;
    }

    css_style_t body_style = {0};
    if (body_node)
    {
        html_view_style_for_node(&body_style, priv->sheet, &html_style, body_node);
    }
    else
    {
        body_style = html_style;
    }
    video_color_t body_bg = body_style.has_background ? body_style.background : default_page_bg;

    int actual_font_px = atk_font_line_height();
    int css_font_px = actual_font_px;
    const css_style_t *font_src = &html_style;
    if (!(html_style.has_font_size && html_style.font_size.valid && !html_style.font_size.is_auto) &&
        (body_style.has_font_size && body_style.font_size.valid && !body_style.font_size.is_auto))
    {
        font_src = &body_style;
    }

    if (font_src->has_font_size && font_src->font_size.valid && !font_src->font_size.is_auto)
    {
        int computed = html_view_length_to_px(&font_src->font_size,
                                              viewport_w,
                                              viewport_h,
                                              viewport_w,
                                              viewport_h,
                                              actual_font_px,
                                              true);
        if (computed > 0)
        {
            css_font_px = computed;
        }
    }
    if (css_font_px > HTML_VIEW_FONT_MAX_PX)
    {
        css_font_px = HTML_VIEW_FONT_MAX_PX;
    }

    int base_font_px = css_font_px;
    int base_line_height = base_font_px + 4;
    if (base_line_height < 8)
    {
        base_line_height = 8;
    }

    int border_px = 0;
    if (body_style.has_border)
    {
        border_px = html_view_length_to_px(&body_style.border_width.left,
                                           viewport_w,
                                           viewport_h,
                                           viewport_w,
                                           viewport_h,
                                           base_font_px,
                                           true);
        if (border_px < 0)
        {
            border_px = 0;
        }
    }

    int pad_top = 0;
    int pad_right = 0;
    int pad_bottom = 0;
    int pad_left = 0;
    if (body_style.has_padding)
    {
        pad_top = html_view_length_to_px(&body_style.padding.top,
                                         viewport_w,
                                         viewport_h,
                                         viewport_w,
                                         viewport_h,
                                         base_font_px,
                                         false);
        pad_right = html_view_length_to_px(&body_style.padding.right,
                                           viewport_w,
                                           viewport_h,
                                           viewport_w,
                                           viewport_h,
                                           base_font_px,
                                           true);
        pad_bottom = html_view_length_to_px(&body_style.padding.bottom,
                                            viewport_w,
                                            viewport_h,
                                            viewport_w,
                                            viewport_h,
                                            base_font_px,
                                            false);
        pad_left = html_view_length_to_px(&body_style.padding.left,
                                          viewport_w,
                                          viewport_h,
                                          viewport_w,
                                          viewport_h,
                                          base_font_px,
                                          true);
        if (pad_top < 0) pad_top = 0;
        if (pad_right < 0) pad_right = 0;
        if (pad_bottom < 0) pad_bottom = 0;
        if (pad_left < 0) pad_left = 0;
    }

    int body_content_w = viewport_w;
    if (body_style.has_width)
    {
        int computed = html_view_length_to_px(&body_style.width,
                                              viewport_w,
                                              viewport_h,
                                              viewport_w,
                                              viewport_h,
                                              base_font_px,
                                              true);
        if (computed > 0)
        {
            body_content_w = computed;
        }
    }
    if (body_content_w < 0) body_content_w = 0;

    int body_box_w = body_content_w + pad_left + pad_right + border_px * 2;
    if (body_box_w > viewport_w)
    {
        int max_content = viewport_w - pad_left - pad_right - border_px * 2;
        if (max_content < 0)
        {
            max_content = 0;
        }
        body_content_w = max_content;
        body_box_w = body_content_w + pad_left + pad_right + border_px * 2;
    }

    int body_box_x = viewport_x;
    if (body_style.has_margin)
    {
        bool auto_left = body_style.margin.left.valid && body_style.margin.left.is_auto;
        bool auto_right = body_style.margin.right.valid && body_style.margin.right.is_auto;
        if (auto_left && auto_right)
        {
            body_box_x = viewport_x + (viewport_w - body_box_w) / 2;
        }
        else if (body_style.margin.left.valid && !body_style.margin.left.is_auto)
        {
            body_box_x = viewport_x + html_view_length_to_px(&body_style.margin.left,
                                                             viewport_w,
                                                             viewport_h,
                                                             viewport_w,
                                                             viewport_h,
                                                             base_font_px,
                                                             true);
        }
    }

    int margin_top = 0;
    if (body_style.has_margin && body_style.margin.top.valid && !body_style.margin.top.is_auto)
    {
        margin_top = html_view_length_to_px(&body_style.margin.top,
                                            viewport_w,
                                            viewport_h,
                                            viewport_w,
                                            viewport_h,
                                            base_font_px,
                                            false);
    }

    int body_box_y0 = viewport_y + margin_top;
    int body_content_x = body_box_x + border_px + pad_left;
    int body_content_y0 = body_box_y0 + border_px + pad_top;
    const html_node_t *body = body_node;

    int effective_font_px = base_font_px;
    if (effective_font_px <= 0)
    {
        effective_font_px = atk_font_line_height();
    }

    if (!html_view_font_state_get_cache(&priv->font, effective_font_px))
    {
        effective_font_px = atk_font_line_height();
        base_font_px = effective_font_px;
        base_line_height = base_font_px + 4;
        if (base_line_height < 8)
        {
            base_line_height = 8;
        }
    }

    html_view_render_cache_t *cache = &priv->render_cache;
    __atomic_store_n(&priv->render_cache_dirty, 1u, __ATOMIC_RELEASE);
    html_view_render_cache_clear(cache);
    cache->tile_h = ATK_HTML_VIEW_RENDER_TILE_H;
    cache->doc = priv->doc;
    cache->sheet = priv->sheet;
    cache->viewport_w = viewport_w;
    cache->viewport_h = viewport_h;
    cache->doc_origin_local_x = body_content_x - abs_x;
    cache->doc_origin_local_y = body_content_y0 - abs_y;
    cache->body_w = body_content_w;
    cache->base_font_px = base_font_px;
    cache->base_line_height = base_line_height;

    html_view_float_ctx_t floats_record = {0};
    html_view_ctx_t record = {
        .state = NULL,
        .widget = view,
        .priv = priv,
        .sheet = priv->sheet,
        .bg = body_bg,
        .clip = { viewport_x, viewport_y, viewport_w, viewport_h },
        .viewport_x = viewport_x,
        .viewport_y = viewport_y,
        .viewport_w = viewport_w,
        .viewport_h = viewport_h,
        .window_x = abs_x,
        .window_y = abs_y,
        .body_x = body_content_x,
        .body_w = body_content_w,
        .floats = &floats_record,
        .actual_font_px = effective_font_px,
        .base_font_px = base_font_px,
        .base_line_height = base_line_height,
        .line_height = base_line_height,
        .space_w = 0,
        .x = body_content_x,
        .y = body_content_y0,
        .max_x = body_content_x + body_content_w,
        .measure_max_x = body_content_x,
        .content_bottom = body_content_y0,
        .list_level = 0,
        .text_align_mode = body_style.has_text_align ? body_style.text_align : CSS_TEXT_ALIGN_LEFT,
        .line_op_start = 0,
        .line_start_x = body_content_x,
        .line_start_y = body_content_y0,
        .pending_space = false,
        .draw = false,
        .record = true,
        .record_failed = false,
        .doc_origin_x = body_content_x,
        .doc_origin_y = body_content_y0
    };

    record.space_w = html_view_text_width(&record, " ");
    if (body)
    {
        html_view_render_children(&record, body, &body_style);
    }
    else
    {
        html_view_draw_text(&record, "No document.\n", default_text, false, false);
    }
    html_view_align_current_line(&record);
    html_view_style_stack_destroy(&record);

    if (!record.record_failed)
    {
        int body_box_h = (record.content_bottom - body_box_y0) + pad_bottom + border_px;
        int min_h = border_px * 2 + pad_top + pad_bottom;
        if (body_box_h < min_h)
        {
            body_box_h = min_h;
        }
        cache->body_box_h = body_box_h;

        int final_bottom = record.content_bottom;
        int body_bottom = body_box_y0 + body_box_h;
        if (body_bottom > final_bottom)
        {
            final_bottom = body_bottom;
        }

        cache->content_height = final_bottom - viewport_y;
        if (cache->content_height < 0)
        {
            cache->content_height = 0;
        }

        cache->valid = true;
        __atomic_store_n(&priv->render_cache_dirty, 0u, __ATOMIC_RELEASE);
        return true;
    }

    html_view_render_cache_clear(cache);
    return false;
}

static void html_view_render_thread(void *arg)
{
    atk_widget_t *view = (atk_widget_t *)arg;
    if (!view)
    {
        return;
    }
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        return;
    }

    uint32_t last_done = __atomic_load_n(&priv->render_done_seq, __ATOMIC_ACQUIRE);
    while (__atomic_load_n(&priv->render_stop, __ATOMIC_ACQUIRE) == 0u)
    {
        uint32_t target = __atomic_load_n(&priv->render_seq, __ATOMIC_ACQUIRE);
        if (target == last_done)
        {
            (void)sys_sleep_ms(1);
            continue;
        }

        uint64_t request_ms = __atomic_load_n(&priv->render_request_ms, __ATOMIC_ACQUIRE);
        uint64_t now_ms = sys_time_millis();
        if (now_ms - request_ms < HTML_VIEW_RENDER_DEBOUNCE_MS)
        {
            (void)sys_sleep_ms(1);
            continue;
        }

        if (!html_view_dom_try_lock(priv))
        {
            (void)sys_sleep_ms(1);
            continue;
        }
        if (!html_view_render_try_lock(priv))
        {
            html_view_dom_unlock(priv);
            (void)sys_sleep_ms(1);
            continue;
        }

        html_view_stylesheet_rebuild_if_needed(priv);
        (void)html_view_render_cache_rebuild_locked(view, priv);

        html_view_render_unlock(priv);
        html_view_dom_unlock(priv);

        last_done = target;
        __atomic_store_n(&priv->render_done_seq, last_done, __ATOMIC_RELEASE);
        __atomic_store_n(&priv->render_redraw_pending, 1u, __ATOMIC_RELEASE);
    }
}

static void html_view_render_start(atk_widget_t *view, atk_html_view_priv_t *priv)
{
    if (!view || !priv || !priv->render_async)
    {
        return;
    }
    if (priv->render_thread != 0)
    {
        return;
    }
    __atomic_store_n(&priv->render_stop, 0u, __ATOMIC_RELEASE);
    alix_thread_t thread = 0;
    if (alix_thread_create(&thread, "atk_html_render", html_view_render_thread, view) != 0)
    {
        return;
    }
    priv->render_thread = thread;
}

static void html_view_render_stop(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    __atomic_store_n(&priv->render_stop, 1u, __ATOMIC_RELEASE);
    alix_thread_t thread = priv->render_thread;
    priv->render_thread = 0;
    if (thread)
    {
        (void)alix_thread_join(thread, NULL);
    }
    __atomic_store_n(&priv->render_stop, 0u, __ATOMIC_RELEASE);
}

void html_view_render_request(atk_html_view_priv_t *priv)
{
    if (!priv || !priv->render_async)
    {
        return;
    }
    uint32_t done = __atomic_load_n(&priv->render_done_seq, __ATOMIC_ACQUIRE);
    uint32_t seq = __atomic_load_n(&priv->render_seq, __ATOMIC_ACQUIRE);
    if (seq != done)
    {
        return;
    }
    (void)__atomic_fetch_add(&priv->render_seq, 1u, __ATOMIC_ACQ_REL);
    __atomic_store_n(&priv->render_request_ms, sys_time_millis(), __ATOMIC_RELEASE);
}

static void html_view_draw_cb(const atk_state_t *state,
                              const atk_widget_t *widget,
                              int origin_x,
                              int origin_y,
                              void *context)
{
    (void)context;
    if (!state || !widget)
    {
        return;
    }

    atk_html_view_priv_t *priv = html_view_priv_mut((atk_widget_t *)widget);
    if (!priv)
    {
        return;
    }

    if (!html_view_dom_try_lock(priv))
    {
        html_view_invalidate(widget);
        return;
    }
    if (!html_view_render_try_lock(priv))
    {
        html_view_dom_unlock(priv);
        html_view_invalidate(widget);
        return;
    }
    if (!priv->render_async)
    {
        html_view_stylesheet_rebuild_if_needed(priv);
    }
    html_view_js_apply_dirty((atk_widget_t *)widget, priv);

    html_view_controls_hide_all(priv);

    int abs_x = origin_x + widget->x;
    int abs_y = origin_y + widget->y;

    int sb_w = priv->scrollbar ? priv->scrollbar_width : 0;
    int viewport_x = abs_x + ATK_HTML_VIEW_PADDING;
    int viewport_y = abs_y + ATK_HTML_VIEW_PADDING;
    int viewport_w = widget->width - ATK_HTML_VIEW_PADDING * 2 - sb_w;
    int viewport_h = widget->height - ATK_HTML_VIEW_PADDING * 2;
    if (viewport_w < 0) viewport_w = 0;
    if (viewport_h < 0) viewport_h = 0;

    video_color_t default_page_bg = video_make_color(0xFF, 0xFF, 0xFF);
    video_color_t default_text = video_make_color(0x00, 0x00, 0x00);

    css_style_t base_style = {0};
    base_style.has_color = true;
    base_style.color = default_text;
    base_style.has_font_size = true;
    base_style.font_size = (css_length_t){
        .valid = true,
        .is_auto = false,
        .value_milli = atk_font_line_height() * 1000,
        .unit = CSS_UNIT_PX,
    };
    base_style.has_line_height = true;
    base_style.line_height_milli = 1000;

    const html_node_t *html_node = NULL;
    const html_node_t *body_node = NULL;
    if (priv->doc && priv->doc->root)
    {
        html_node = html_view_find_first_element(priv->doc->root, "html");
        body_node = html_view_find_first_element(priv->doc->root, "body");
    }

    css_style_t html_style = {0};
    if (html_node)
    {
        html_view_style_for_node(&html_style, priv->sheet, &base_style, html_node);
    }
    else
    {
        html_style = base_style;
    }

    css_style_t body_style = {0};
    if (body_node)
    {
        html_view_style_for_node(&body_style, priv->sheet, &html_style, body_node);
    }
    else
    {
        body_style = html_style;
    }
    video_color_t page_bg = html_style.has_background ? html_style.background : default_page_bg;
    video_color_t body_bg = body_style.has_background ? body_style.background : default_page_bg;

    video_draw_rect(abs_x, abs_y, widget->width, widget->height, page_bg);
    video_draw_rect_outline(abs_x, abs_y, widget->width, widget->height, state->theme.window_border);

    atk_rect_t clip = { viewport_x, viewport_y, viewport_w, viewport_h };

    int actual_font_px = atk_font_line_height();
    int css_font_px = actual_font_px;
    const css_style_t *font_src = &html_style;
    if (!(html_style.has_font_size && html_style.font_size.valid && !html_style.font_size.is_auto) &&
        (body_style.has_font_size && body_style.font_size.valid && !body_style.font_size.is_auto))
    {
        font_src = &body_style;
    }

    if (font_src->has_font_size && font_src->font_size.valid && !font_src->font_size.is_auto)
    {
        int computed = html_view_length_to_px(&font_src->font_size,
                                              viewport_w,
                                              viewport_h,
                                              viewport_w,
                                              viewport_h,
                                              actual_font_px,
                                              true);
        if (computed > 0)
        {
            css_font_px = computed;
        }
    }
    if (css_font_px > HTML_VIEW_FONT_MAX_PX)
    {
        css_font_px = HTML_VIEW_FONT_MAX_PX;
    }

    int base_font_px = css_font_px;
    int base_line_height = base_font_px + 4;
    if (base_line_height < 8)
    {
        base_line_height = 8;
    }

    int border_px = 0;
    if (body_style.has_border)
    {
        border_px = html_view_length_to_px(&body_style.border_width.left,
                                           viewport_w,
                                           viewport_h,
                                           viewport_w,
                                           viewport_h,
                                           base_font_px,
                                           true);
        if (border_px < 0)
        {
            border_px = 0;
        }
    }

    int pad_top = 0;
    int pad_right = 0;
    int pad_bottom = 0;
    int pad_left = 0;
    if (body_style.has_padding)
    {
        pad_top = html_view_length_to_px(&body_style.padding.top,
                                         viewport_w,
                                         viewport_h,
                                         viewport_w,
                                         viewport_h,
                                         base_font_px,
                                         false);
        pad_right = html_view_length_to_px(&body_style.padding.right,
                                           viewport_w,
                                           viewport_h,
                                           viewport_w,
                                           viewport_h,
                                           base_font_px,
                                           true);
        pad_bottom = html_view_length_to_px(&body_style.padding.bottom,
                                            viewport_w,
                                            viewport_h,
                                            viewport_w,
                                            viewport_h,
                                            base_font_px,
                                            false);
        pad_left = html_view_length_to_px(&body_style.padding.left,
                                          viewport_w,
                                          viewport_h,
                                          viewport_w,
                                          viewport_h,
                                          base_font_px,
                                          true);
        if (pad_top < 0) pad_top = 0;
        if (pad_right < 0) pad_right = 0;
        if (pad_bottom < 0) pad_bottom = 0;
        if (pad_left < 0) pad_left = 0;
    }

    int body_content_w = viewport_w;
    if (body_style.has_width)
    {
        int computed = html_view_length_to_px(&body_style.width,
                                              viewport_w,
                                              viewport_h,
                                              viewport_w,
                                              viewport_h,
                                              base_font_px,
                                              true);
        if (computed > 0)
        {
            body_content_w = computed;
        }
    }
    if (body_content_w < 0) body_content_w = 0;

    int body_box_w = body_content_w + pad_left + pad_right + border_px * 2;
    if (body_box_w > viewport_w)
    {
        int max_content = viewport_w - pad_left - pad_right - border_px * 2;
        if (max_content < 0)
        {
            max_content = 0;
        }
        body_content_w = max_content;
        body_box_w = body_content_w + pad_left + pad_right + border_px * 2;
    }

    int body_box_x = viewport_x;
    if (body_style.has_margin)
    {
        bool auto_left = body_style.margin.left.valid && body_style.margin.left.is_auto;
        bool auto_right = body_style.margin.right.valid && body_style.margin.right.is_auto;
        if (auto_left && auto_right)
        {
            body_box_x = viewport_x + (viewport_w - body_box_w) / 2;
        }
        else if (body_style.margin.left.valid && !body_style.margin.left.is_auto)
        {
            body_box_x = viewport_x + html_view_length_to_px(&body_style.margin.left,
                                                             viewport_w,
                                                             viewport_h,
                                                             viewport_w,
                                                             viewport_h,
                                                             base_font_px,
                                                             true);
        }
    }

    int margin_top = 0;
    if (body_style.has_margin && body_style.margin.top.valid && !body_style.margin.top.is_auto)
    {
        margin_top = html_view_length_to_px(&body_style.margin.top,
                                            viewport_w,
                                            viewport_h,
                                            viewport_w,
                                            viewport_h,
                                            base_font_px,
                                            false);
    }

    int body_box_y0 = viewport_y + margin_top;
    int body_content_x = body_box_x + border_px + pad_left;
    int body_content_y0 = body_box_y0 + border_px + pad_top;

    int effective_font_px = base_font_px;
    if (effective_font_px <= 0)
    {
        effective_font_px = atk_font_line_height();
    }

    if (!html_view_font_state_get_cache(&priv->font, effective_font_px))
    {
        effective_font_px = atk_font_line_height();
        base_font_px = effective_font_px;
        base_line_height = base_font_px + 4;
        if (base_line_height < 8)
        {
            base_line_height = 8;
        }
    }

    html_view_render_cache_t *cache = &priv->render_cache;
    int doc_origin_local_x = body_content_x - abs_x;
    int doc_origin_local_y = body_content_y0 - abs_y;
    bool cache_dirty = __atomic_load_n(&priv->render_cache_dirty, __ATOMIC_ACQUIRE) != 0u;
    bool cache_matches = cache->valid &&
                         cache->doc == priv->doc &&
                         cache->sheet == priv->sheet &&
                         cache->viewport_w == viewport_w &&
                         cache->viewport_h == viewport_h &&
                         cache->body_w == body_content_w &&
                         cache->base_font_px == base_font_px &&
                         cache->base_line_height == base_line_height;

    if (!cache_matches)
    {
        if (priv->render_async)
        {
            html_view_render_request(priv);
        }
        else
        {
            (void)html_view_render_cache_rebuild_locked((atk_widget_t *)widget, priv);
        }
        cache_matches = cache->valid &&
                        cache->doc == priv->doc &&
                        cache->sheet == priv->sheet &&
                        cache->viewport_w == viewport_w &&
                        cache->viewport_h == viewport_h &&
                        cache->body_w == body_content_w &&
                        cache->base_font_px == base_font_px &&
                        cache->base_line_height == base_line_height;
    }

    cache->doc_origin_local_x = doc_origin_local_x;
    cache->doc_origin_local_y = doc_origin_local_y;

    bool cache_valid = cache_matches && cache->valid && !cache_dirty;
    int cache_body_box_h = cache->body_box_h;
    int cache_content_height = cache->content_height;
    bool has_scrollbar = (priv->scrollbar != NULL);
    const css_stylesheet_t *sheet = priv->sheet;

    html_view_dom_unlock(priv);

    html_view_position_scrollbar((atk_widget_t *)widget, priv);
    if (cache_valid)
    {
        priv->content_height = cache_content_height;
        if (priv->content_height < 0)
        {
            priv->content_height = 0;
        }
        if (has_scrollbar)
        {
            html_view_update_scrollbar((atk_widget_t *)widget, priv);
        }
    }

    html_view_ctx_t ctx = {
        .state = state,
        .widget = widget,
        .priv = priv,
        .sheet = sheet,
        .bg = body_bg,
        .clip = clip,
        .viewport_x = viewport_x,
        .viewport_y = viewport_y,
        .viewport_w = viewport_w,
        .viewport_h = viewport_h,
        .window_x = origin_x,
        .window_y = origin_y,
        .body_x = body_content_x,
        .body_w = body_content_w,
        .floats = NULL,
        .actual_font_px = effective_font_px,
        .base_font_px = base_font_px,
        .base_line_height = base_line_height,
        .line_height = base_line_height,
        .space_w = 0,
        .x = body_content_x,
        .y = body_content_y0,
        .max_x = body_content_x + body_content_w,
        .measure_max_x = body_content_x,
        .content_bottom = body_content_y0,
        .list_level = 0,
        .text_align_mode = body_style.has_text_align ? body_style.text_align : CSS_TEXT_ALIGN_LEFT,
        .line_op_start = 0,
        .line_start_x = body_content_x,
        .line_start_y = body_content_y0,
        .pending_space = false,
        .draw = true,
        .record = false,
        .record_failed = false,
        .doc_origin_x = body_content_x,
        .doc_origin_y = body_content_y0
    };

    ctx.space_w = html_view_text_width(&ctx, " ");

    if (!cache_valid)
    {
        const char *msg = priv->render_async ? "Rendering...\n" : "Render cache unavailable.\n";
        html_view_draw_text(&ctx, msg, default_text, false, false);
        html_view_render_unlock(priv);
        return;
    }

    int body_draw_y = body_box_y0 - priv->scroll_y;
    html_view_draw_rect_clipped(&ctx, body_box_x, body_draw_y, body_box_w, cache_body_box_h, body_bg, &clip);
    if (border_px > 0)
    {
        video_color_t border_color = body_style.has_border_color ? body_style.border_color : video_make_color(0x00, 0x00, 0x00);
        html_view_draw_border_clipped(&ctx, body_box_x, body_draw_y, body_box_w, cache_body_box_h, border_px, border_color, &clip);
    }

    html_view_render_cache_draw_visible(&ctx);
    html_view_render_unlock(priv);
}

static void html_view_destroy_cb(atk_widget_t *widget, void *context)
{
    (void)context;
    atk_html_view_priv_t *priv = html_view_priv_mut(widget);
    if (priv)
    {
        html_view_render_stop(priv);
        html_view_js_shutdown(widget, priv);
        alix_mutex_lock(&priv->render_lock);
        html_view_render_cache_invalidate_locked(priv);
        alix_mutex_unlock(&priv->render_lock);
        html_view_control_t *ctrl = priv->controls;
        while (ctrl)
        {
            html_view_control_t *next = ctrl->next;
            free(ctrl);
            ctrl = next;
        }
        priv->controls = NULL;
        html_view_images_clear(priv);
        if (priv->external_css)
        {
            free(priv->external_css);
            priv->external_css = NULL;
            priv->external_css_len = 0;
        }
        if (priv->doc)
        {
            html_document_destroy(priv->doc);
            priv->doc = NULL;
        }
        if (priv->sheet)
        {
            css_stylesheet_destroy(priv->sheet);
            priv->sheet = NULL;
        }
        html_view_font_state_reset(&priv->font);
        priv->scrollbar = NULL;
        priv->child_node = NULL;
    }
    atk_widget_destroy(widget);
}

static const atk_widget_vtable_t html_view_vtable = { 0 };
static const atk_widget_ops_t g_html_view_ops = {
    .destroy = html_view_destroy_cb,
    .draw = html_view_draw_cb,
    .hit_test = html_view_hit_test_cb,
    .on_mouse = html_view_mouse_cb,
    .on_key = html_view_key_cb
};

const atk_class_t ATK_HTML_VIEW_CLASS = { "HtmlView", &ATK_WIDGET_CLASS, &html_view_vtable, sizeof(atk_html_view_priv_t) };

atk_widget_t *atk_window_add_html_view(atk_widget_t *window, int x, int y, int width, int height)
{
    if (!window || width <= 0 || height <= 0)
    {
        return NULL;
    }

    atk_window_priv_t *wpriv = (atk_window_priv_t *)atk_widget_priv(window, &ATK_WINDOW_CLASS);
    if (!wpriv)
    {
        return NULL;
    }

    atk_widget_t *view = atk_widget_create(&ATK_HTML_VIEW_CLASS);
    if (!view)
    {
        return NULL;
    }

    view->x = x;
    view->y = y;
    view->width = width;
    view->height = height;
    view->parent = window;
    view->used = true;
    atk_widget_set_ops(view, &g_html_view_ops, NULL);

    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        atk_widget_destroy(view);
        return NULL;
    }
    priv->child_node = NULL;
    priv->scrollbar = NULL;
    priv->scrollbar_width = ATK_HTML_VIEW_SCROLLBAR_WIDTH;
    priv->scroll_y = 0;
    priv->content_height = 0;
    priv->last_width = width;
    priv->last_height = height;
    priv->doc = NULL;
    priv->sheet = NULL;
    priv->external_css = NULL;
    priv->external_css_len = 0;
    priv->images = NULL;
    priv->controls = NULL;
    priv->render_cache.tile_h = ATK_HTML_VIEW_RENDER_TILE_H;
    priv->link_handler = NULL;
    priv->link_context = NULL;
    alix_mutex_init(&priv->render_lock);
    priv->render_thread = 0;
    priv->render_stop = 0;
    priv->render_seq = 0;
    priv->render_done_seq = 0;
    priv->render_redraw_pending = 0;
    priv->render_request_ms = 0;
    priv->render_cache_dirty = 0;
    priv->stylesheet_dirty = 0;
    priv->render_async = false;
    html_view_js_init(priv);

    atk_list_node_t *child_node = atk_list_push_back(&wpriv->children, view);
    if (!child_node)
    {
        atk_widget_destroy(view);
        return NULL;
    }
    priv->child_node = child_node;

    int sb_x = x + width - priv->scrollbar_width;
    if (sb_x < x)
    {
        sb_x = x;
    }
    atk_widget_t *scrollbar = atk_window_add_scrollbar(window,
                                                       sb_x,
                                                       y,
                                                       priv->scrollbar_width,
                                                       height,
                                                       ATK_SCROLLBAR_VERTICAL);
    if (scrollbar)
    {
        priv->scrollbar = scrollbar;
        atk_scrollbar_set_change_handler(scrollbar, html_view_scrollbar_changed, view);
        html_view_update_scrollbar(view, priv);
    }

    return view;
}

void atk_html_view_set_link_handler(atk_widget_t *view, atk_html_view_link_t handler, void *context)
{
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        return;
    }
    priv->link_handler = handler;
    priv->link_context = context;
}

void atk_html_view_set_document(atk_widget_t *view, html_document_t *doc)
{
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        if (doc)
        {
            html_document_destroy(doc);
        }
        return;
    }

    html_view_js_stop(priv);

    html_view_dom_lock(priv);
    html_view_render_cache_invalidate(priv);
    priv->pressed_href = NULL;

    if (priv->doc)
    {
        html_document_destroy(priv->doc);
    }
    html_view_controls_clear(view, priv);
    html_view_images_clear(priv);
    if (priv->external_css)
    {
        free(priv->external_css);
        priv->external_css = NULL;
        priv->external_css_len = 0;
    }
    if (priv->sheet)
    {
        css_stylesheet_destroy(priv->sheet);
        priv->sheet = NULL;
    }
    priv->doc = doc;
    priv->scroll_y = 0;
    html_view_stylesheet_mark_dirty(priv);
    html_view_stylesheet_rebuild_if_needed(priv);
    html_view_controls_build(view, priv);
    html_view_dom_unlock(priv);
    html_view_render_request(priv);
    html_view_invalidate(view);
    html_view_js_start(view, priv);
}

bool atk_html_view_scroll_to_id(atk_widget_t *view, const char *id)
{
    if (!view)
    {
        return false;
    }
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        return false;
    }

    if (!id || id[0] == '\0')
    {
        priv->scroll_y = 0;
        html_view_update_scrollbar(view, priv);
        html_view_invalidate(view);
        return true;
    }

    if (!html_view_render_try_lock(priv))
    {
        if (priv->render_async)
        {
            html_view_render_request(priv);
        }
        return false;
    }

    const html_view_render_cache_t *cache = &priv->render_cache;
    if (!cache->valid || cache->anchor_count == 0)
    {
        html_view_render_unlock(priv);
        if (priv->render_async)
        {
            html_view_render_request(priv);
        }
        return false;
    }

    int target_y = -1;
    int content_height = cache->content_height;
    for (size_t i = 0; i < cache->anchor_count; ++i)
    {
        const html_view_anchor_t *anchor = &cache->anchors[i];
        if (anchor->id && strcmp(anchor->id, id) == 0)
        {
            target_y = anchor->y;
            break;
        }
    }

    html_view_render_unlock(priv);

    if (target_y < 0)
    {
        return false;
    }

    priv->scroll_y = target_y;
    if (content_height > 0)
    {
        priv->content_height = content_height;
    }
    html_view_update_scrollbar(view, priv);
    html_view_invalidate(view);
    return true;
}

bool atk_html_view_set_html(atk_widget_t *view, const char *html, html_parse_error_t *error_out)
{
    html_parse_error_t tmp = {0};
    if (!error_out)
    {
        error_out = &tmp;
    }
    html_document_t *doc = html_parse(html, error_out);
    if (!doc)
    {
        return false;
    }
    atk_html_view_set_document(view, doc);
    return true;
}

static bool html_view_set_external_stylesheet_impl(atk_widget_t *view, const char *css_text, bool try_only)
{
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        return false;
    }

    if (try_only)
    {
        if (!html_view_dom_try_lock(priv))
        {
            return false;
        }
    }
    else
    {
        html_view_dom_lock(priv);
    }
    html_view_render_cache_invalidate(priv);
    priv->pressed_href = NULL;

    if (priv->external_css)
    {
        free(priv->external_css);
        priv->external_css = NULL;
        priv->external_css_len = 0;
    }

    if (css_text && css_text[0] != '\0')
    {
        priv->external_css = html_view_strdup(css_text);
        if (priv->external_css)
        {
            priv->external_css_len = strlen(priv->external_css);
        }
    }

    html_view_stylesheet_mark_dirty(priv);
    if (!priv->render_async)
    {
        html_view_stylesheet_rebuild_if_needed(priv);
    }
    html_view_dom_unlock(priv);
    html_view_render_request(priv);
    html_view_invalidate(view);
    return true;
}

void atk_html_view_set_external_stylesheet(atk_widget_t *view, const char *css_text)
{
    (void)html_view_set_external_stylesheet_impl(view, css_text, false);
}

bool atk_html_view_try_set_external_stylesheet(atk_widget_t *view, const char *css_text)
{
    return html_view_set_external_stylesheet_impl(view, css_text, true);
}

bool atk_html_view_add_script(atk_widget_t *view, const char *script_text, size_t len)
{
    if (!view || !script_text || len == 0)
    {
        return false;
    }
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        return false;
    }
    return html_view_js_queue_external(view, priv, script_text, len);
}

bool atk_html_view_try_add_script(atk_widget_t *view, const char *script_text, size_t len)
{
    if (!view || !script_text || len == 0)
    {
        return false;
    }
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        return false;
    }
    return html_view_js_queue_external_try(view, priv, script_text, len);
}

void atk_html_view_stop_js(atk_widget_t *view)
{
    if (!view)
    {
        return;
    }
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        return;
    }
    html_view_js_stop(priv);
}

void atk_html_view_enable_async_render(atk_widget_t *view, bool enabled)
{
    if (!view)
    {
        return;
    }
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        return;
    }
    priv->render_async = enabled;
    if (enabled)
    {
        html_view_render_start(view, priv);
        html_view_render_request(priv);
    }
    else
    {
        html_view_render_stop(priv);
        __atomic_store_n(&priv->render_redraw_pending, 0u, __ATOMIC_RELEASE);
    }
}

bool atk_html_view_poll_js(atk_widget_t *view)
{
    if (!view || !view->parent)
    {
        return false;
    }
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        return false;
    }
    bool redraw = false;
    if (__atomic_exchange_n(&priv->js_redraw_pending, 0u, __ATOMIC_ACQ_REL) != 0u)
    {
        redraw = true;
    }
    if (__atomic_exchange_n(&priv->render_redraw_pending, 0u, __ATOMIC_ACQ_REL) != 0u)
    {
        redraw = true;
    }
    if (!redraw)
    {
        return false;
    }
    html_view_invalidate(view);
    return true;
}

bool atk_html_view_add_image_png(atk_widget_t *view, const char *src, const uint8_t *data, size_t size)
{
    if (!view || !src || src[0] == '\0' || !data || size == 0)
    {
        return false;
    }

    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        return false;
    }

    html_view_dom_lock(priv);
    if (html_view_image_find(priv, src))
    {
        html_view_dom_unlock(priv);
        return true;
    }
    html_view_dom_unlock(priv);

    video_color_t *pixels = NULL;
    int w = 0;
    int h = 0;
    int stride_bytes = 0;
    int rc = png_decode_rgba32(data, size, &pixels, &w, &h, &stride_bytes);
    if (rc != 0 || !pixels || w <= 0 || h <= 0 || stride_bytes <= 0)
    {
        free(pixels);
        return false;
    }

    html_view_image_t *img = (html_view_image_t *)calloc(1, sizeof(*img));
    if (!img)
    {
        free(pixels);
        return false;
    }

    img->src = html_view_strdup(src);
    if (!img->src)
    {
        free(pixels);
        free(img);
        return false;
    }

    img->pixels = pixels;
    img->width = w;
    img->height = h;
    img->stride_bytes = stride_bytes;

    html_view_dom_lock(priv);
    if (html_view_image_find(priv, src))
    {
        html_view_dom_unlock(priv);
        free(img->src);
        free(img);
        free(pixels);
        return true;
    }
    img->next = priv->images;
    priv->images = img;

    html_view_render_cache_invalidate(priv);
    html_view_dom_unlock(priv);
    html_view_render_request(priv);
    html_view_invalidate(view);
    return true;
}

bool atk_html_view_add_image_gif(atk_widget_t *view, const char *src, const uint8_t *data, size_t size)
{
    if (!view || !src || src[0] == '\0' || !data || size == 0)
    {
        return false;
    }

    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        return false;
    }

    html_view_dom_lock(priv);
    if (html_view_image_find(priv, src))
    {
        html_view_dom_unlock(priv);
        return true;
    }
    html_view_dom_unlock(priv);

    video_color_t *pixels = NULL;
    int w = 0;
    int h = 0;
    int stride_bytes = 0;
    int rc = gif_decode_rgba32(data, size, &pixels, &w, &h, &stride_bytes);
    if (rc != 0 || !pixels || w <= 0 || h <= 0 || stride_bytes <= 0)
    {
        free(pixels);
        return false;
    }

    html_view_image_t *img = (html_view_image_t *)calloc(1, sizeof(*img));
    if (!img)
    {
        free(pixels);
        return false;
    }

    img->src = html_view_strdup(src);
    if (!img->src)
    {
        free(pixels);
        free(img);
        return false;
    }

    img->pixels = pixels;
    img->width = w;
    img->height = h;
    img->stride_bytes = stride_bytes;

    html_view_dom_lock(priv);
    if (html_view_image_find(priv, src))
    {
        html_view_dom_unlock(priv);
        free(img->src);
        free(img);
        free(pixels);
        return true;
    }
    img->next = priv->images;
    priv->images = img;

    html_view_render_cache_invalidate(priv);
    html_view_dom_unlock(priv);
    html_view_render_request(priv);
    html_view_invalidate(view);
    return true;
}

static bool html_view_add_image_rgba_impl(atk_widget_t *view,
                                          const char *src,
                                          video_color_t *pixels,
                                          int width,
                                          int height,
                                          int stride_bytes,
                                          bool try_only)
{
    if (!view || !src || src[0] == '\0' || !pixels || width <= 0 || height <= 0 || stride_bytes <= 0)
    {
        return false;
    }

    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        return false;
    }

    if (try_only)
    {
        if (!html_view_dom_try_lock(priv))
        {
            return false;
        }
    }
    else
    {
        html_view_dom_lock(priv);
    }
    if (html_view_image_find(priv, src))
    {
        html_view_dom_unlock(priv);
        free(pixels);
        return true;
    }

    html_view_image_t *img = (html_view_image_t *)calloc(1, sizeof(*img));
    if (!img)
    {
        html_view_dom_unlock(priv);
        return false;
    }

    img->src = html_view_strdup(src);
    if (!img->src)
    {
        html_view_dom_unlock(priv);
        free(img);
        return false;
    }

    img->pixels = pixels;
    img->width = width;
    img->height = height;
    img->stride_bytes = stride_bytes;

    img->next = priv->images;
    priv->images = img;

    html_view_dom_unlock(priv);
    html_view_render_cache_invalidate(priv);
    html_view_render_request(priv);
    html_view_invalidate(view);
    return true;
}

bool atk_html_view_add_image_rgba(atk_widget_t *view,
                                  const char *src,
                                  video_color_t *pixels,
                                  int width,
                                  int height,
                                  int stride_bytes)
{
    bool ok = html_view_add_image_rgba_impl(view, src, pixels, width, height, stride_bytes, false);
    if (!ok)
    {
        free(pixels);
    }
    return ok;
}

bool atk_html_view_try_add_image_rgba(atk_widget_t *view,
                                      const char *src,
                                      video_color_t *pixels,
                                      int width,
                                      int height,
                                      int stride_bytes)
{
    return html_view_add_image_rgba_impl(view, src, pixels, width, height, stride_bytes, true);
}
