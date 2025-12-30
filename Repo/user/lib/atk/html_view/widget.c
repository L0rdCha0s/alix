#include "atk/html_view/html_view_internal.h"

#include "ctype.h"
#include "serial.h"
#include "stdarg.h"
#include "stdio.h"

#define HTML_VIEW_RENDER_DEBOUNCE_MS 32u

static void html_view_position_scrollbar(atk_widget_t *view, atk_html_view_priv_t *priv)
{
    if (!view || !priv || !priv->scrollbar)
    {
        return;
    }
    if (priv->scrollbar_hidden)
    {
        priv->scrollbar->used = false;
        return;
    }
    priv->scrollbar->used = true;
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
    if (priv->scrollbar_hidden)
    {
        priv->scrollbar->used = false;
        return;
    }
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
    bool overflow_hidden = (html_style.has_overflow && html_style.overflow == CSS_OVERFLOW_HIDDEN) ||
                           (body_style.has_overflow && body_style.overflow == CSS_OVERFLOW_HIDDEN);
    priv->scrollbar_hidden = overflow_hidden;
    if (overflow_hidden)
    {
        sb_w = 0;
        viewport_w = view->width - ATK_HTML_VIEW_PADDING * 2;
        if (viewport_w < 0) viewport_w = 0;
    }

    bool body_has_bg = body_style.has_background && !body_style.background_transparent;
    video_color_t body_bg = body_has_bg ? body_style.background : default_page_bg;

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
            body_box_x = viewport_x + html_view_length_to_px_signed(&body_style.margin.left,
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
        margin_top = html_view_length_to_px_signed(&body_style.margin.top,
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

    int body_height_basis = 0;
    bool body_height_valid = false;
    if (body_style.has_height && body_style.height.valid && !body_style.height.is_auto)
    {
        body_height_basis = html_view_length_to_px(&body_style.height,
                                                   viewport_w,
                                                   viewport_h,
                                                   viewport_w,
                                                   viewport_h,
                                                   base_font_px,
                                                   false);
        if (body_height_basis < 0)
        {
            body_height_basis = 0;
        }
        body_height_valid = true;
    }

    int effective_font_px = base_font_px;
    if (effective_font_px <= 0)
    {
        effective_font_px = atk_font_line_height();
    }

    html_view_font_size_cache_t *font_cache = html_view_font_state_get_cache(&priv->font, effective_font_px);
    if (!font_cache)
    {
        effective_font_px = atk_font_line_height();
        base_font_px = effective_font_px;
        base_line_height = base_font_px + 4;
        if (base_line_height < 8)
        {
            base_line_height = 8;
        }
        font_cache = html_view_font_state_get_cache(&priv->font, effective_font_px);
    }

    if (font_cache)
    {
        int descent = font_cache->metrics.descent;
        if (descent < 0)
        {
            descent = -descent;
        }
        int metrics_line = font_cache->metrics.ascent + descent;
        if (font_cache->metrics.line_gap > 0)
        {
            metrics_line += font_cache->metrics.line_gap;
        }
        if (metrics_line > base_line_height)
        {
            base_line_height = metrics_line;
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
        .pos_x = viewport_x,
        .pos_y = viewport_y,
        .pos_w = viewport_w,
        .pos_h = viewport_h,
        .height_basis = body_height_basis,
        .height_basis_valid = body_height_valid,
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
        .z_index = 0,
        .paint_layer = HTML_VIEW_PAINT_LAYER_BLOCK,
        .draw = false,
        .record = true,
        .record_failed = false,
        .fixed_mode = false,
        .table_mode = false,
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

    int sb_w = 0;
    int viewport_x = abs_x + ATK_HTML_VIEW_PADDING;
    int viewport_y = abs_y + ATK_HTML_VIEW_PADDING;
    int viewport_w = 0;
    int viewport_h = widget->height - ATK_HTML_VIEW_PADDING * 2;
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
    bool overflow_hidden = (html_style.has_overflow && html_style.overflow == CSS_OVERFLOW_HIDDEN) ||
                           (body_style.has_overflow && body_style.overflow == CSS_OVERFLOW_HIDDEN);
    priv->scrollbar_hidden = overflow_hidden;
    sb_w = (priv->scrollbar && !overflow_hidden) ? priv->scrollbar_width : 0;
    viewport_w = widget->width - ATK_HTML_VIEW_PADDING * 2 - sb_w;
    if (viewport_w < 0) viewport_w = 0;

    bool page_has_bg = html_style.has_background && !html_style.background_transparent;
    bool body_has_bg = body_style.has_background && !body_style.background_transparent;
    video_color_t page_bg = page_has_bg ? html_style.background : default_page_bg;
    video_color_t body_bg = body_has_bg ? body_style.background : default_page_bg;

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
            body_box_x = viewport_x + html_view_length_to_px_signed(&body_style.margin.left,
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
        margin_top = html_view_length_to_px_signed(&body_style.margin.top,
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

    int body_height_basis = 0;
    bool body_height_valid = false;
    if (body_style.has_height && body_style.height.valid && !body_style.height.is_auto)
    {
        body_height_basis = html_view_length_to_px(&body_style.height,
                                                   viewport_w,
                                                   viewport_h,
                                                   viewport_w,
                                                   viewport_h,
                                                   base_font_px,
                                                   false);
        if (body_height_basis < 0)
        {
            body_height_basis = 0;
        }
        body_height_valid = true;
    }

    int effective_font_px = base_font_px;
    if (effective_font_px <= 0)
    {
        effective_font_px = atk_font_line_height();
    }

    html_view_font_size_cache_t *font_cache = html_view_font_state_get_cache(&priv->font, effective_font_px);
    if (!font_cache)
    {
        effective_font_px = atk_font_line_height();
        base_font_px = effective_font_px;
        base_line_height = base_font_px + 4;
        if (base_line_height < 8)
        {
            base_line_height = 8;
        }
        font_cache = html_view_font_state_get_cache(&priv->font, effective_font_px);
    }

    if (font_cache)
    {
        int descent = font_cache->metrics.descent;
        if (descent < 0)
        {
            descent = -descent;
        }
        int metrics_line = font_cache->metrics.ascent + descent;
        if (font_cache->metrics.line_gap > 0)
        {
            metrics_line += font_cache->metrics.line_gap;
        }
        if (metrics_line > base_line_height)
        {
            base_line_height = metrics_line;
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
        .pos_x = viewport_x,
        .pos_y = viewport_y,
        .pos_w = viewport_w,
        .pos_h = viewport_h,
        .height_basis = body_height_basis,
        .height_basis_valid = body_height_valid,
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
        .z_index = 0,
        .paint_layer = HTML_VIEW_PAINT_LAYER_BLOCK,
        .draw = true,
        .record = false,
        .record_failed = false,
        .fixed_mode = false,
        .table_mode = false,
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
    if (border_px > 0 && !(body_style.has_border_color && body_style.border_transparent))
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
    priv->scrollbar_hidden = false;
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

static void html_view_dump_append(char *buf, size_t cap, size_t *offset, const char *fmt, ...)
{
    if (!buf || cap == 0 || !offset || *offset >= cap)
    {
        return;
    }
    va_list args;
    va_start(args, fmt);
    int written = vsnprintf(buf + *offset, cap - *offset, fmt, args);
    va_end(args);
    if (written <= 0)
    {
        return;
    }
    size_t add = (size_t)written;
    if (add >= cap - *offset)
    {
        *offset = cap - 1;
    }
    else
    {
        *offset += add;
    }
}

static void html_view_dump_indent(char *buf, size_t cap, int depth)
{
    if (!buf || cap == 0)
    {
        return;
    }
    int count = depth * 2;
    if (count < 0) count = 0;
    if ((size_t)count >= cap)
    {
        count = (int)cap - 1;
    }
    memset(buf, ' ', (size_t)count);
    buf[count] = '\0';
}

static void html_view_dump_color(char *buf, size_t cap, video_color_t color)
{
    if (!buf || cap == 0)
    {
        return;
    }
    uint8_t r = (uint8_t)((color >> 16) & 0xFF);
    uint8_t g = (uint8_t)((color >> 8) & 0xFF);
    uint8_t b = (uint8_t)(color & 0xFF);
    (void)snprintf(buf, cap, "#%02X%02X%02X", r, g, b);
}

static const char *html_view_dump_display(css_display_t display)
{
    switch (display)
    {
        case CSS_DISPLAY_INLINE: return "inline";
        case CSS_DISPLAY_BLOCK: return "block";
        case CSS_DISPLAY_LIST_ITEM: return "list-item";
        case CSS_DISPLAY_TABLE: return "table";
        case CSS_DISPLAY_TABLE_CELL: return "table-cell";
        case CSS_DISPLAY_FLEX: return "flex";
        case CSS_DISPLAY_INLINE_FLEX: return "inline-flex";
        case CSS_DISPLAY_NONE: return "none";
        default: return "unknown";
    }
}

static const char *html_view_dump_float(css_float_t value)
{
    switch (value)
    {
        case CSS_FLOAT_LEFT: return "left";
        case CSS_FLOAT_RIGHT: return "right";
        case CSS_FLOAT_NONE: return "none";
        default: return "unknown";
    }
}

static const char *html_view_dump_text_align(css_text_align_t align)
{
    switch (align)
    {
        case CSS_TEXT_ALIGN_CENTER: return "center";
        case CSS_TEXT_ALIGN_RIGHT: return "right";
        case CSS_TEXT_ALIGN_LEFT: return "left";
        default: return "unknown";
    }
}

static const char *html_view_dump_text_decoration(css_text_decoration_t value)
{
    switch (value)
    {
        case CSS_TEXT_DECORATION_UNDERLINE: return "underline";
        case CSS_TEXT_DECORATION_NONE: return "none";
        default: return "unknown";
    }
}

static void html_view_dump_length(char *buf, size_t cap, const css_length_t *len)
{
    if (!buf || cap == 0)
    {
        return;
    }
    if (!len || !len->valid)
    {
        (void)snprintf(buf, cap, "unset");
        return;
    }
    if (len->is_auto)
    {
        (void)snprintf(buf, cap, "auto");
        return;
    }
    int32_t v = len->value_milli;
    int32_t whole = v / 1000;
    int32_t frac = v % 1000;
    if (frac < 0) frac = -frac;

    const char *unit = "";
    switch (len->unit)
    {
        case CSS_UNIT_PX: unit = "px"; break;
        case CSS_UNIT_EM: unit = "em"; break;
        case CSS_UNIT_VW: unit = "vw"; break;
        case CSS_UNIT_VH: unit = "vh"; break;
        case CSS_UNIT_PERCENT: unit = "%"; break;
        case CSS_UNIT_NONE: default: unit = ""; break;
    }

    if (frac == 0)
    {
        (void)snprintf(buf, cap, "%d%s", whole, unit);
    }
    else
    {
        (void)snprintf(buf, cap, "%d.%03d%s", whole, frac, unit);
    }
}

static void html_view_dump_box(char *buf, size_t cap, size_t *offset, const char *name, const css_box_t *box)
{
    if (!buf || !offset || !name || !box)
    {
        return;
    }
    char len_buf[32];
    if (name[0] != '\0')
    {
        html_view_dump_append(buf, cap, offset, "%s=", name);
    }
    html_view_dump_length(len_buf, sizeof(len_buf), &box->top);
    html_view_dump_append(buf, cap, offset, "%s", len_buf);
    html_view_dump_length(len_buf, sizeof(len_buf), &box->right);
    html_view_dump_append(buf, cap, offset, " %s", len_buf);
    html_view_dump_length(len_buf, sizeof(len_buf), &box->bottom);
    html_view_dump_append(buf, cap, offset, " %s", len_buf);
    html_view_dump_length(len_buf, sizeof(len_buf), &box->left);
    html_view_dump_append(buf, cap, offset, " %s", len_buf);
}

static void html_view_dump_style_summary(const css_style_t *style, char *buf, size_t cap)
{
    if (!buf || cap == 0)
    {
        return;
    }
    if (!style)
    {
        (void)snprintf(buf, cap, "(none)");
        return;
    }
    size_t off = 0;
    bool any = false;
    char tmp[32];

    if (style->has_display)
    {
        html_view_dump_append(buf, cap, &off, "display=%s", html_view_dump_display(style->display));
        any = true;
    }
    if (style->has_color)
    {
        html_view_dump_color(tmp, sizeof(tmp), style->color);
        html_view_dump_append(buf, cap, &off, "%scolor=%s", any ? " " : "", tmp);
        any = true;
    }
    if (style->has_background)
    {
        if (style->background_transparent)
        {
            html_view_dump_append(buf, cap, &off, "%sbackground=none", any ? " " : "");
        }
        else
        {
            html_view_dump_color(tmp, sizeof(tmp), style->background);
            html_view_dump_append(buf, cap, &off, "%sbackground=%s", any ? " " : "", tmp);
        }
        any = true;
    }
    if (style->has_font_size)
    {
        char len_buf[32];
        html_view_dump_length(len_buf, sizeof(len_buf), &style->font_size);
        html_view_dump_append(buf, cap, &off, "%sfont-size=%s", any ? " " : "", len_buf);
        any = true;
    }
    if (style->has_line_height)
    {
        if (style->line_height_is_length)
        {
            char len_buf[32];
            html_view_dump_length(len_buf, sizeof(len_buf), &style->line_height);
            html_view_dump_append(buf, cap, &off, "%sline-height=%s", any ? " " : "", len_buf);
        }
        else
        {
            int32_t v = style->line_height_milli;
            int32_t whole = v / 1000;
            int32_t frac = v % 1000;
            if (frac < 0) frac = -frac;
            if (frac == 0)
            {
                html_view_dump_append(buf, cap, &off, "%sline-height=%d", any ? " " : "", whole);
            }
            else
            {
                html_view_dump_append(buf, cap, &off, "%sline-height=%d.%03d", any ? " " : "", whole, frac);
            }
        }
        any = true;
    }
    if (style->has_text_align)
    {
        html_view_dump_append(buf, cap, &off, "%stext-align=%s", any ? " " : "", html_view_dump_text_align(style->text_align));
        any = true;
    }
    if (style->has_text_decoration)
    {
        html_view_dump_append(buf, cap, &off, "%stext-decoration=%s", any ? " " : "", html_view_dump_text_decoration(style->text_decoration));
        any = true;
    }
    if (style->has_float)
    {
        html_view_dump_append(buf, cap, &off, "%sfloat=%s", any ? " " : "", html_view_dump_float(style->float_mode));
        any = true;
    }
    if (style->has_width)
    {
        char len_buf[32];
        html_view_dump_length(len_buf, sizeof(len_buf), &style->width);
        html_view_dump_append(buf, cap, &off, "%swidth=%s", any ? " " : "", len_buf);
        any = true;
    }
    if (style->has_height)
    {
        char len_buf[32];
        html_view_dump_length(len_buf, sizeof(len_buf), &style->height);
        html_view_dump_append(buf, cap, &off, "%sheight=%s", any ? " " : "", len_buf);
        any = true;
    }
    if (style->has_margin)
    {
        html_view_dump_append(buf, cap, &off, "%s", any ? " " : "");
        html_view_dump_box(buf, cap, &off, "margin", &style->margin);
        any = true;
    }
    if (style->has_padding)
    {
        html_view_dump_append(buf, cap, &off, "%s", any ? " " : "");
        html_view_dump_box(buf, cap, &off, "padding", &style->padding);
        any = true;
    }
    if (style->has_border)
    {
        html_view_dump_append(buf, cap, &off, "%s", any ? " " : "");
        html_view_dump_box(buf, cap, &off, "border-width", &style->border_width);
        any = true;
    }
    if (style->has_border_color)
    {
        if (style->border_transparent)
        {
            html_view_dump_append(buf, cap, &off, "%sborder-color=transparent", any ? " " : "");
        }
        else
        {
            html_view_dump_color(tmp, sizeof(tmp), style->border_color);
            html_view_dump_append(buf, cap, &off, "%sborder-color=%s", any ? " " : "", tmp);
        }
        any = true;
    }

    if (!any)
    {
        (void)snprintf(buf, cap, "(none)");
    }
}

static void html_view_dump_sanitize(const char *src, char *dst, size_t cap, size_t max_len)
{
    if (!dst || cap == 0)
    {
        return;
    }
    if (!src)
    {
        dst[0] = '\0';
        return;
    }

    size_t out = 0;
    size_t seen = 0;
    bool last_space = false;
    while (*src && out + 1 < cap && seen < max_len)
    {
        unsigned char ch = (unsigned char)*src++;
        seen++;
        if (ch < 0x20 || ch == 0x7F)
        {
            if (!last_space)
            {
                dst[out++] = ' ';
                last_space = true;
            }
            continue;
        }
        if (ch >= 0x80)
        {
            ch = '?';
        }
        if (isspace(ch))
        {
            if (!last_space)
            {
                dst[out++] = ' ';
                last_space = true;
            }
            continue;
        }
        dst[out++] = (char)ch;
        last_space = false;
    }
    if ((*src || seen >= max_len) && out + 4 < cap)
    {
        dst[out++] = '.';
        dst[out++] = '.';
        dst[out++] = '.';
    }
    dst[out] = '\0';
}

static void html_view_dump_attrs(const html_node_t *node, char *buf, size_t cap)
{
    if (!buf || cap == 0)
    {
        return;
    }
    buf[0] = '\0';
    if (!node || !node->attrs)
    {
        return;
    }

    size_t off = 0;
    for (const html_attr_t *attr = node->attrs; attr; attr = attr->next)
    {
        if (!attr->name || !attr->value)
        {
            continue;
        }
        char value_buf[64];
        html_view_dump_sanitize(attr->value, value_buf, sizeof(value_buf), 48);
        html_view_dump_append(buf, cap, &off, " %s=\"%s\"", attr->name, value_buf);
        if (off + 4 >= cap)
        {
            html_view_dump_append(buf, cap, &off, " ...");
            break;
        }
    }
}

typedef struct
{
    const html_node_t *node;
    css_style_t style;
    int depth;
    bool has_style;
} html_view_dump_frame_t;

static void html_view_dump_node_line(const html_node_t *node,
                                     const css_style_t *style,
                                     bool has_style,
                                     int depth)
{
    char indent[64];
    html_view_dump_indent(indent, sizeof(indent), depth);

    if (!node)
    {
        serial_printf("[html_view][dom] %s(null)", indent);
        return;
    }

    if (node->type == HTML_NODE_DOCUMENT)
    {
        serial_printf("[html_view][dom] %s#document", indent);
        return;
    }

    if (node->type == HTML_NODE_DOCTYPE)
    {
        char text_buf[96];
        html_view_dump_sanitize(node->name ? node->name : "", text_buf, sizeof(text_buf), 64);
        serial_printf("[html_view][dom] %s<!doctype %s>", indent, text_buf);
        return;
    }

    if (node->type == HTML_NODE_COMMENT)
    {
        char text_buf[96];
        html_view_dump_sanitize(node->text ? node->text : "", text_buf, sizeof(text_buf), 64);
        serial_printf("[html_view][dom] %s<!-- %s -->", indent, text_buf);
        return;
    }

    if (node->type == HTML_NODE_TEXT)
    {
        char text_buf[128];
        html_view_dump_sanitize(node->text ? node->text : "", text_buf, sizeof(text_buf), 80);
        serial_printf("[html_view][dom] %s#text \"%s\"", indent, text_buf);
        if (has_style && style && style->has_color)
        {
            char color_buf[16];
            html_view_dump_color(color_buf, sizeof(color_buf), style->color);
            serial_printf("[html_view][dom] %s  style color=%s", indent, color_buf);
        }
        return;
    }

    if (node->type == HTML_NODE_ELEMENT)
    {
        char attrs[256];
        html_view_dump_attrs(node, attrs, sizeof(attrs));
        serial_printf("[html_view][dom] %s<%s%s>", indent, node->name ? node->name : "?", attrs);
        if (has_style && style)
        {
            char style_buf[512];
            html_view_dump_style_summary(style, style_buf, sizeof(style_buf));
            serial_printf("[html_view][dom] %s  style %s", indent, style_buf);
        }
        return;
    }

    serial_printf("[html_view][dom] %s#node type=%d", indent, (int)node->type);
}

static void html_view_dump_tree(const html_node_t *root, const css_stylesheet_t *sheet)
{
    if (!root)
    {
        serial_printf("[html_view][dom] (empty)");
        return;
    }

    size_t cap = 64;
    size_t count = 0;
    html_view_dump_frame_t *stack = (html_view_dump_frame_t *)calloc(cap, sizeof(*stack));
    if (!stack)
    {
        return;
    }

    html_view_dump_frame_t root_frame = {0};
    root_frame.node = root;
    root_frame.depth = 0;
    if (root->type == HTML_NODE_ELEMENT)
    {
        html_view_style_for_node(&root_frame.style, sheet, NULL, root);
        root_frame.has_style = true;
    }
    stack[count++] = root_frame;

    while (count > 0)
    {
        html_view_dump_frame_t frame = stack[--count];
        const html_node_t *node = frame.node;
        const css_style_t *parent_style = frame.has_style ? &frame.style : NULL;

        html_view_dump_node_line(node, parent_style, frame.has_style, frame.depth);

        if (!node || !node->first_child)
        {
            continue;
        }

        for (const html_node_t *child = node->last_child; child; child = child->prev_sibling)
        {
            if (count >= cap)
            {
                size_t next_cap = cap * 2;
                html_view_dump_frame_t *next = (html_view_dump_frame_t *)realloc(stack, next_cap * sizeof(*next));
                if (!next)
                {
                    free(stack);
                    return;
                }
                memset(next + cap, 0, (next_cap - cap) * sizeof(*next));
                stack = next;
                cap = next_cap;
            }

            html_view_dump_frame_t child_frame = {0};
            child_frame.node = child;
            child_frame.depth = frame.depth + 1;
            child_frame.has_style = false;
            if (child && child->type == HTML_NODE_ELEMENT)
            {
                html_view_style_for_node(&child_frame.style, sheet, parent_style, child);
                child_frame.has_style = true;
            }
            else if (parent_style)
            {
                child_frame.style = *parent_style;
                child_frame.has_style = true;
            }
            stack[count++] = child_frame;
        }
    }

    free(stack);
}

void atk_html_view_dump_dom(atk_widget_t *view)
{
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        serial_printf("[html_view] dump: missing view");
        return;
    }
    if (!html_view_dom_try_lock(priv))
    {
        serial_printf("[html_view] dump: dom busy");
        return;
    }

    html_view_stylesheet_rebuild_if_needed(priv);
    if (!priv->doc || !priv->doc->root)
    {
        serial_printf("[html_view] dump: no document");
        html_view_dom_unlock(priv);
        return;
    }

    serial_printf("[html_view] dump begin view=%p", (void *)view);
    html_view_dump_tree(priv->doc->root, priv->sheet);
    serial_printf("[html_view] dump end view=%p", (void *)view);
    html_view_dom_unlock(priv);
}
