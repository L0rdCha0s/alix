#include "atk/html_view/render/render_internal.h"

#include "ctype.h"
#include "serial.h"
#include "string.h"

static bool html_view_style_uses_border_box(const css_style_t *style)
{
    return style && style->has_box_sizing && style->box_sizing == CSS_BOX_SIZING_BORDER_BOX;
}

static int html_view_box_sizing_content_width(const css_style_t *style,
                                              int width,
                                              int pad_left,
                                              int pad_right,
                                              int border_left,
                                              int border_right)
{
    if (html_view_style_uses_border_box(style))
    {
        width -= pad_left + pad_right + border_left + border_right;
        if (width < 0)
        {
            width = 0;
        }
    }
    return width;
}

static int html_view_box_sizing_content_height(const css_style_t *style,
                                               int height,
                                               int pad_top,
                                               int pad_bottom,
                                               int border_top,
                                               int border_bottom)
{
    if (html_view_style_uses_border_box(style))
    {
        height -= pad_top + pad_bottom + border_top + border_bottom;
        if (height < 0)
        {
            height = 0;
        }
    }
    return height;
}

static size_t html_view_record_rect_placeholder(html_view_ctx_t *ctx,
                                                int x,
                                                int y,
                                                int w,
                                                int h,
                                                video_color_t color,
                                                const atk_rect_t *clip)
{
    if (!ctx || !ctx->record || ctx->record_failed || !ctx->priv)
    {
        return (size_t)-1;
    }
    html_view_render_cache_t *cache = &ctx->priv->render_cache;
    html_view_op_t op = {0};
    op.kind = HTML_VIEW_OP_RECT;
    op.x = html_view_record_x(ctx, x);
    op.y = html_view_record_y(ctx, y);
    op.w = w;
    op.h = h;
    op.color = color;
    op.z_index = html_view_effective_z_index(ctx);
    op.fixed = ctx->fixed_mode;
    if (clip)
    {
        op.has_clip = true;
        op.clip_scroll = ctx->clip_scroll;
        op.clip_x = html_view_record_x(ctx, clip->x);
        op.clip_y = html_view_record_y(ctx, clip->y);
        op.clip_w = clip->width;
        op.clip_h = clip->height;
    }
    if (!html_view_render_cache_push_op(cache, &op, cache->tile_h))
    {
        ctx->record_failed = true;
        return (size_t)-1;
    }
    return cache->op_count - 1u;
}

static void html_view_align_line_partial(html_view_ctx_t *ctx, size_t end_ops)
{
    if (!ctx || !ctx->record || ctx->record_failed || !ctx->priv)
    {
        return;
    }
    if (ctx->text_align_mode == CSS_TEXT_ALIGN_LEFT)
    {
        ctx->line_op_start = end_ops;
        return;
    }

    html_view_render_cache_t *cache = &ctx->priv->render_cache;
    if (end_ops > cache->op_count)
    {
        end_ops = cache->op_count;
    }
    size_t start = ctx->line_op_start;
    size_t end = end_ops;
    if (start >= end)
    {
        ctx->line_op_start = end_ops;
        return;
    }

    int line_left = ctx->line_start_x;
    int avail = ctx->max_x - line_left;
    int line_w = ctx->x - line_left;
    if (avail <= 0 || line_w <= 0 || line_w >= avail)
    {
        ctx->line_op_start = end_ops;
        return;
    }

    int delta = 0;
    if (ctx->text_align_mode == CSS_TEXT_ALIGN_CENTER)
    {
        delta = (avail - line_w) / 2;
    }
    else if (ctx->text_align_mode == CSS_TEXT_ALIGN_RIGHT)
    {
        delta = (avail - line_w);
    }

    if (delta <= 0)
    {
        ctx->line_op_start = end_ops;
        return;
    }

    int max_shift_h = ctx->line_height + 2;
    for (size_t i = start; i < end; ++i)
    {
        html_view_op_t *op = &cache->ops[i];
        bool shift = false;
        if (op->kind == HTML_VIEW_OP_TEXT || op->kind == HTML_VIEW_OP_CONTROL)
        {
            shift = true;
        }
        else if (op->kind == HTML_VIEW_OP_RECT)
        {
            shift = (op->h > 0 && op->h <= max_shift_h);
        }
        else if (op->kind == HTML_VIEW_OP_IMAGE)
        {
            shift = (op->h > 0 && op->h <= max_shift_h);
        }

        if (shift)
        {
            op->x += delta;
        }
    }

    ctx->line_op_start = end_ops;
}

static void html_view_advance_line_no_align(html_view_ctx_t *ctx, int line_height, size_t line_op_start)
{
    if (!ctx)
    {
        return;
    }
    ctx->x = ctx->body_x;
    ctx->y += line_height;
    ctx->pending_space = false;
    int bottom = ctx->y + ctx->line_height;
    if (bottom > ctx->content_bottom)
    {
        ctx->content_bottom = bottom;
    }
    ctx->line_start_x = ctx->x;
    ctx->line_start_y = ctx->y;
    ctx->line_op_start = line_op_start;
}

static void html_view_shift_recorded_ops(html_view_ctx_t *ctx,
                                         size_t op_start,
                                         size_t op_end,
                                         int dx,
                                         int dy,
                                         size_t skip_op)
{
    if (!ctx || !ctx->priv || (dx == 0 && dy == 0))
    {
        return;
    }
    html_view_render_cache_t *cache = &ctx->priv->render_cache;
    if (op_end > cache->op_count)
    {
        op_end = cache->op_count;
    }
    for (size_t i = op_start; i < op_end; ++i)
    {
        if (i == skip_op)
        {
            continue;
        }
        html_view_op_t *op = &cache->ops[i];
        if (op->fixed)
        {
            continue;
        }
        op->x += dx;
        op->y += dy;
        html_view_render_cache_reindex_op(cache, i);
    }
}

static void html_view_shift_recorded_anchors(html_view_ctx_t *ctx,
                                             size_t anchor_start,
                                             size_t anchor_end,
                                             int dy)
{
    if (!ctx || !ctx->priv || dy == 0)
    {
        return;
    }
    html_view_render_cache_t *cache = &ctx->priv->render_cache;
    if (anchor_end > cache->anchor_count)
    {
        anchor_end = cache->anchor_count;
    }
    for (size_t i = anchor_start; i < anchor_end; ++i)
    {
        int updated = cache->anchors[i].y + dy;
        if (updated < 0)
        {
            updated = 0;
        }
        cache->anchors[i].y = updated;
    }
}

static void html_view_measure_inline_block_children(const html_view_ctx_t *ctx,
                                                    const html_node_t *node,
                                                    const css_style_t *style,
                                                    int content_w,
                                                    int *out_w,
                                                    int *out_h)
{
    if (out_w)
    {
        *out_w = 0;
    }
    if (out_h)
    {
        *out_h = 0;
    }
    if (!ctx || !node || !style)
    {
        return;
    }

    int cache_line_height = html_view_line_height_for_style(ctx, style);
    if (html_view_subtree_has_form_control(node) && cache_line_height < atk_font_line_height() + 8)
    {
        cache_line_height = atk_font_line_height() + 8;
    }
    if (ctx->priv)
    {
        int cached_w = 0;
        int cached_h = 0;
        if (html_view_measure_cache_lookup(ctx->priv,
                                           node,
                                           content_w,
                                           ctx->actual_font_px,
                                           cache_line_height,
                                           true,
                                           0,
                                           HTML_VIEW_MEASURE_KIND_INLINE_BLOCK,
                                           &cached_w,
                                           &cached_h))
        {
            if (out_w)
            {
                *out_w = cached_w;
            }
            if (out_h)
            {
                *out_h = cached_h;
            }
            return;
        }
    }

    html_view_ctx_t measure = *ctx;
    html_view_float_ctx_t floats = {0};
    measure.draw = false;
    measure.record = false;
    measure.record_failed = false;
    measure.floats = &floats;
    measure.style_block = NULL;
    measure.style_depth = 0;
    measure.measure_shrink = true;
    measure.body_x = 0;
    measure.body_w = content_w;
    if (measure.body_w < 0) measure.body_w = 0;
    measure.max_x = measure.body_x + measure.body_w;
    measure.x = measure.body_x;
    measure.y = 0;
    measure.content_bottom = 0;
    measure.pending_space = false;
    html_view_margin_state_reset(&measure.pending_margin);
    measure.underline_run_active = false;
    measure.underline_run_start_x = 0;
    measure.list_level = 0;
    measure.measure_max_x = measure.x;
    measure.space_w = html_view_text_width(&measure, " ");
    measure.line_height = cache_line_height;
    if (html_view_subtree_has_form_control(node) && measure.line_height < atk_font_line_height() + 8)
    {
        measure.line_height = atk_font_line_height() + 8;
    }
    measure.height_basis_valid = false;
    measure.height_basis = 0;
    measure.height_basis_explicit = false;

    html_view_trace_note_measure(HTML_VIEW_TRACE_MEASURE_INLINE_BLOCK);
    html_view_trace_note_measure(HTML_VIEW_TRACE_MEASURE_INLINE);
    html_view_render_children(&measure, node, style);
    if (measure.x != measure.body_x)
    {
        html_view_new_line(&measure);
    }
    html_view_style_stack_destroy(&measure);

    if (out_w)
    {
        int measured_w = measure.measure_max_x - measure.body_x;
        if (measured_w < 0) measured_w = 0;
        *out_w = measured_w;
    }
    if (out_h)
    {
        int measured_h = measure.content_bottom;
        if (measured_h < 0) measured_h = 0;
        *out_h = measured_h;
    }

    if (ctx->priv)
    {
        int measured_w = measure.measure_max_x - measure.body_x;
        int measured_h = measure.content_bottom;
        if (measured_w < 0) measured_w = 0;
        if (measured_h < 0) measured_h = 0;
        html_view_measure_cache_store(ctx->priv,
                                      node,
                                      content_w,
                                      ctx->actual_font_px,
                                      cache_line_height,
                                      true,
                                      0,
                                      HTML_VIEW_MEASURE_KIND_INLINE_BLOCK,
                                      measured_w,
                                      measured_h);
    }
}

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

static bool html_view_attr_has_class(const html_node_t *node, const char *token)
{
    if (!node || !token || !*token)
    {
        return false;
    }
    const char *classes = html_attr_get(node, "class");
    if (!classes || !*classes)
    {
        return false;
    }
    size_t token_len = strlen(token);
    const char *p = classes;
    while (*p)
    {
        while (*p && isspace((unsigned char)*p))
        {
            ++p;
        }
        if (!*p)
        {
            break;
        }
        const char *start = p;
        while (*p && !isspace((unsigned char)*p))
        {
            ++p;
        }
        size_t len = (size_t)(p - start);
        if (len == token_len && strncmp(start, token, len) == 0)
        {
            return true;
        }
    }
    return false;
}

static bool html_view_attr_has_id(const html_node_t *node, const char *token)
{
    if (!node || !token || !*token)
    {
        return false;
    }
    const char *id = html_attr_get(node, "id");
    if (!id || !*id)
    {
        return false;
    }
    return strcmp(id, token) == 0;
}

static bool html_view_node_has_ancestor_class(const html_node_t *node, const char *token)
{
    for (const html_node_t *cur = node; cur; cur = cur->parent)
    {
        if (html_view_attr_has_class(cur, token))
        {
            return true;
        }
    }
    return false;
}

static bool html_view_node_has_ancestor_id(const html_node_t *node, const char *token)
{
    for (const html_node_t *cur = node; cur; cur = cur->parent)
    {
        if (html_view_attr_has_id(cur, token))
        {
            return true;
        }
    }
    return false;
}

static const char *html_view_debug_inline_label(const html_node_t *node)
{
    if (!node || node->type != HTML_NODE_ELEMENT)
    {
        return NULL;
    }
    if (html_view_node_has_ancestor_id(node, "eyes-a"))
    {
        return "eyes-a-object";
    }
    if (html_view_node_has_ancestor_id(node, "eyes-b"))
    {
        return "eyes-b-object";
    }
    if (html_view_node_has_ancestor_class(node, "eyes"))
    {
        return "eyes-object";
    }
    if (node->name && strcmp(node->name, "span") == 0 &&
        html_view_node_has_ancestor_class(node, "smile"))
    {
        return "smile-span";
    }
    if (node->name && strcmp(node->name, "em") == 0 &&
        html_view_node_has_ancestor_class(node, "smile"))
    {
        return "smile-em";
    }
    if (node->name && strcmp(node->name, "strong") == 0 &&
        html_view_node_has_ancestor_class(node, "smile"))
    {
        return "smile-strong";
    }
    if (node->name && strcmp(node->name, "div") == 0 &&
        html_view_node_has_ancestor_class(node, "chin"))
    {
        return "chin-inline";
    }
    return NULL;
}

static uint32_t html_view_debug_hash_string(const char *text)
{
    if (!text)
    {
        return 0;
    }
    uint32_t hash = 2166136261u;
    const unsigned char *p = (const unsigned char *)text;
    while (*p)
    {
        hash ^= *p++;
        hash *= 16777619u;
    }
    return hash;
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

    int cache_w = ctx->body_w;
    int cache_origin_x = ctx->x - ctx->body_x;
    if (ctx->priv)
    {
        int cached_w = 0;
        int cached_h = 0;
        if (html_view_measure_cache_lookup(ctx->priv,
                                           node,
                                           cache_w,
                                           ctx->actual_font_px,
                                           ctx->line_height,
                                           ctx->measure_shrink,
                                           cache_origin_x,
                                           HTML_VIEW_MEASURE_KIND_INLINE,
                                           &cached_w,
                                           &cached_h))
        {
            if (out_w)
            {
                *out_w = cached_w;
            }
            if (out_h)
            {
                *out_h = cached_h;
            }
            if (out_wrapped)
            {
                *out_wrapped = false;
            }
            return true;
        }
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
    const char *debug_label = html_view_debug_inline_label(node);
    if (debug_label && ctx->record)
    {
        serial_printf("[html_view][acid2] inline-measure=%s start=%d,%d end=%d,%d width=%d height=%d line_h=%d wrapped=%d body_x=%d body_w=%d",
                      debug_label,
                      start_x,
                      start_y,
                      measure.x,
                      measure.y,
                      width,
                      height,
                      measure.line_height,
                      wrapped ? 1 : 0,
                      measure.body_x,
                      measure.body_w);
    }

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
    if (!wrapped && ctx->priv)
    {
        html_view_measure_cache_store(ctx->priv,
                                      node,
                                      cache_w,
                                      ctx->actual_font_px,
                                      ctx->line_height,
                                      ctx->measure_shrink,
                                      cache_origin_x,
                                      HTML_VIEW_MEASURE_KIND_INLINE,
                                      width,
                                      height);
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
    bool record_only = false;
    size_t record_op_start = 0;
    size_t record_op_end = 0;
    size_t anchor_start = 0;
    size_t bg_op = (size_t)-1;
    int start_x = 0;
    int start_y = 0;
    html_view_paint_layer_t saved_layer = ctx ? ctx->paint_layer : HTML_VIEW_PAINT_LAYER_BLOCK;

    if (ctx && ctx->record && !ctx->draw && ctx->priv && !ctx->record_failed &&
        !(style->has_background_image && style->background_image))
    {
        record_only = true;
        html_view_render_cache_t *cache = &ctx->priv->render_cache;
        record_op_start = cache->op_count;
        anchor_start = cache->anchor_count;

        if (ctx->paint_layer == HTML_VIEW_PAINT_LAYER_BLOCK)
        {
            ctx->paint_layer = HTML_VIEW_PAINT_LAYER_INLINE;
        }

        if (style->has_background && !style->background_transparent)
        {
            bg_op = html_view_record_rect_placeholder(ctx, 0, 0, 0, 0, style->background, &ctx->clip);
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
        inner.pending_space = false;
        html_view_margin_state_reset(&inner.pending_margin);
        inner.measure_max_x = inner.x;
        inner.content_bottom = inner.y;
        inner.line_height = html_view_line_height_for_style(&inner, style);
        if (html_view_subtree_has_form_control(node) && inner.line_height < atk_font_line_height() + 8)
        {
            inner.line_height = atk_font_line_height() + 8;
        }

        start_x = inner.x;
        start_y = inner.y;
        int start_line_y = inner.line_start_y;

        html_view_render_children(&inner, node, style);
        if (inner.x != inner.body_x)
        {
            html_view_ensure_line_visible(&inner);
        }
        html_view_style_stack_destroy(&inner);
        if (inner.record_failed)
        {
            ctx->record_failed = true;
        }

        record_op_end = cache->op_count;
        content_w = inner.x - start_x;
        content_h = inner.content_bottom - start_y;
        if (content_h <= 0)
        {
            content_h = inner.line_height;
        }
        wrapped = (inner.y != start_y) || (inner.line_start_y != start_line_y);
        if (wrapped)
        {
            if (bg_op != (size_t)-1 && bg_op < cache->op_count)
            {
                cache->ops[bg_op].w = 0;
                cache->ops[bg_op].h = 0;
            }
            ctx->x = inner.x;
            ctx->y = inner.y;
            ctx->line_height = inner.line_height;
            ctx->line_start_x = inner.line_start_x;
            ctx->line_start_y = inner.line_start_y;
            ctx->line_op_start = inner.line_op_start;
            ctx->measure_max_x = inner.measure_max_x;
            ctx->content_bottom = inner.content_bottom;
            ctx->pending_space = inner.pending_space;
            ctx->pending_margin = inner.pending_margin;
            ctx->underline_run_active = inner.underline_run_active;
            ctx->underline_run_start_x = inner.underline_run_start_x;
            ctx->underline_run_color = inner.underline_run_color;
            ctx->list_level = inner.list_level;
            ctx->active_href = inner.active_href;
            ctx->paint_layer = saved_layer;
            return true;
        }
    }
    else
    {
        if (!html_view_measure_inline_children(ctx, node, style, &content_w, &content_h, &wrapped))
        {
            return false;
        }
        if (wrapped)
        {
            return false;
        }
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

    int margin_top = 0;
    int margin_right = 0;
    int margin_bottom = 0;
    int margin_left = 0;
    if (style->has_margin)
    {
        if (style->margin.top.valid && !style->margin.top.is_auto)
        {
            margin_top = html_view_length_to_px_signed(&style->margin.top,
                                                       ctx->viewport_w,
                                                       ctx->viewport_h,
                                                       ctx->body_w,
                                                       ctx->viewport_h,
                                                       ctx->base_font_px,
                                                       true);
        }
        if (style->margin.right.valid && !style->margin.right.is_auto)
        {
            margin_right = html_view_length_to_px_signed(&style->margin.right,
                                                         ctx->viewport_w,
                                                         ctx->viewport_h,
                                                         ctx->body_w,
                                                         ctx->viewport_h,
                                                         ctx->base_font_px,
                                                         true);
        }
        if (style->margin.bottom.valid && !style->margin.bottom.is_auto)
        {
            margin_bottom = html_view_length_to_px_signed(&style->margin.bottom,
                                                          ctx->viewport_w,
                                                          ctx->viewport_h,
                                                          ctx->body_w,
                                                          ctx->viewport_h,
                                                          ctx->base_font_px,
                                                          true);
        }
        if (style->margin.left.valid && !style->margin.left.is_auto)
        {
            margin_left = html_view_length_to_px_signed(&style->margin.left,
                                                        ctx->viewport_w,
                                                        ctx->viewport_h,
                                                        ctx->body_w,
                                                        ctx->viewport_h,
                                                        ctx->base_font_px,
                                                        true);
        }
    }

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

    bool break_line = false;
    if (ctx->pending_space && ctx->x != ctx->body_x)
    {
        if (ctx->x + ctx->space_w + box_w > ctx->max_x)
        {
            break_line = true;
        }
        else
        {
            ctx->x += ctx->space_w;
        }
    }
    else if (ctx->x != ctx->body_x && ctx->x + box_w > ctx->max_x)
    {
        break_line = true;
    }

    if (break_line)
    {
        if (record_only)
        {
            html_view_flush_underline_run(ctx);
            html_view_align_line_partial(ctx, record_op_start);
            html_view_advance_line_no_align(ctx, ctx->line_height, record_op_start);
        }
        else
        {
            html_view_new_line(ctx);
        }
    }

    if (ctx->paint_layer == HTML_VIEW_PAINT_LAYER_BLOCK)
    {
        ctx->paint_layer = HTML_VIEW_PAINT_LAYER_INLINE;
    }

    bool measure_only = (!ctx->draw && !ctx->record);
    int draw_x = ctx->x;
    int doc_y = ctx->y + ctx->line_height - box_h;
    int draw_y = html_view_draw_y(ctx, doc_y);

    const char *debug_label = html_view_debug_inline_label(node);
    if (debug_label && ctx->record)
    {
        int display = style->has_display ? (int)style->display : -1;
        int position = style->has_position ? (int)style->position : -1;
        int float_mode = style->has_float ? (int)style->float_mode : -1;
        int clear_mode = style->has_clear ? (int)style->clear_mode : -1;
        serial_printf("[html_view][acid2] inline-box=%s display=%d position=%d float=%d clear=%d content=%dx%d box=%dx%d margin=%d,%d,%d,%d padding=%d,%d,%d,%d border=%d,%d,%d,%d line_h=%d base_lh=%d font_px=%d base_font=%d draw=%d,%d doc_y=%d wrapped=%d paint=%d z=%d",
                      debug_label,
                      display,
                      position,
                      float_mode,
                      clear_mode,
                      content_w,
                      content_h,
                      box_w,
                      box_h,
                      margin_top,
                      margin_right,
                      margin_bottom,
                      margin_left,
                      pad_top,
                      pad_right,
                      pad_bottom,
                      pad_left,
                      border_top,
                      border_right,
                      border_bottom,
                      border_left,
                      ctx->line_height,
                      ctx->base_line_height,
                      ctx->actual_font_px,
                      ctx->base_font_px,
                      draw_x,
                      draw_y,
                      doc_y,
                      wrapped ? 1 : 0,
                      ctx->paint_layer,
                      ctx->z_index);
    }

    if (!record_only)
    {
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
    else if (ctx->priv && bg_op != (size_t)-1 && bg_op < ctx->priv->render_cache.op_count)
    {
        html_view_render_cache_t *cache = &ctx->priv->render_cache;
        html_view_op_t *op = &cache->ops[bg_op];
        op->x = html_view_record_x(ctx, draw_x);
        op->y = html_view_record_y(ctx, draw_y);
        op->w = box_w;
        op->h = box_h;
        html_view_render_cache_reindex_op(cache, bg_op);
    }

    if (measure_only)
    {
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

    if (record_only)
    {
        int content_x = draw_x + border_left + pad_left;
        int content_y = doc_y + border_top + pad_top;
        int dx = content_x - start_x;
        int dy = content_y - start_y;
        html_view_shift_recorded_ops(ctx, record_op_start, record_op_end, dx, dy, bg_op);
        if (ctx->priv)
        {
            html_view_shift_recorded_anchors(ctx, anchor_start, ctx->priv->render_cache.anchor_count, dy);
        }

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
    html_view_margin_state_reset(&inner.pending_margin);
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

static bool html_view_render_inline_block_element(html_view_ctx_t *ctx,
                                                  const html_node_t *node,
                                                  const css_style_t *style)
{
    if (!ctx || !node || !style || node->type != HTML_NODE_ELEMENT)
    {
        return false;
    }
    if (!style->has_display || style->display != CSS_DISPLAY_INLINE_BLOCK)
    {
        return false;
    }

    html_view_paint_layer_t saved_layer = ctx->paint_layer;

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

    int margin_top = 0;
    int margin_right = 0;
    int margin_bottom = 0;
    int margin_left = 0;
    if (style->has_margin)
    {
        if (style->margin.top.valid && !style->margin.top.is_auto)
        {
            margin_top = html_view_length_to_px_signed(&style->margin.top,
                                                       ctx->viewport_w,
                                                       ctx->viewport_h,
                                                       ctx->body_w,
                                                       ctx->viewport_h,
                                                       ctx->base_font_px,
                                                       true);
        }
        if (style->margin.right.valid && !style->margin.right.is_auto)
        {
            margin_right = html_view_length_to_px_signed(&style->margin.right,
                                                         ctx->viewport_w,
                                                         ctx->viewport_h,
                                                         ctx->body_w,
                                                         ctx->viewport_h,
                                                         ctx->base_font_px,
                                                         true);
        }
        if (style->margin.bottom.valid && !style->margin.bottom.is_auto)
        {
            margin_bottom = html_view_length_to_px_signed(&style->margin.bottom,
                                                          ctx->viewport_w,
                                                          ctx->viewport_h,
                                                          ctx->body_w,
                                                          ctx->viewport_h,
                                                          ctx->base_font_px,
                                                          true);
        }
        if (style->margin.left.valid && !style->margin.left.is_auto)
        {
            margin_left = html_view_length_to_px_signed(&style->margin.left,
                                                        ctx->viewport_w,
                                                        ctx->viewport_h,
                                                        ctx->body_w,
                                                        ctx->viewport_h,
                                                        ctx->base_font_px,
                                                        true);
        }
    }

    bool record_only = false;
    bool record_children = false;
    size_t record_op_start = 0;
    size_t record_op_end = 0;
    size_t anchor_start = 0;
    size_t bg_op = (size_t)-1;
    int record_start_x = 0;
    int record_start_y = 0;

    int line_w = ctx->max_x - ctx->body_x;
    if (line_w < 0)
    {
        line_w = 0;
    }
    int available_content_w = line_w - margin_left - margin_right - pad_left - pad_right - border_left - border_right;
    if (available_content_w < 0)
    {
        available_content_w = 0;
    }

    bool width_specified = style->has_width && style->width.valid && !style->width.is_auto;
    int specified_h = 0;
    bool height_specified = html_view_length_to_px_height(ctx, &style->height, &specified_h);
    if (height_specified && specified_h < 0)
    {
        specified_h = 0;
    }
    if (height_specified)
    {
        specified_h = html_view_box_sizing_content_height(style,
                                                          specified_h,
                                                          pad_top,
                                                          pad_bottom,
                                                          border_top,
                                                          border_bottom);
    }

    int specified_content_w = 0;
    if (width_specified)
    {
        specified_content_w = html_view_length_to_px(&style->width,
                                                     ctx->viewport_w,
                                                     ctx->viewport_h,
                                                     ctx->body_w,
                                                     ctx->viewport_h,
                                                     ctx->base_font_px,
                                                     true);
        specified_content_w = html_view_box_sizing_content_width(style,
                                                                 specified_content_w,
                                                                 pad_left,
                                                                 pad_right,
                                                                 border_left,
                                                                 border_right);
        if (specified_content_w < 0)
        {
            specified_content_w = 0;
        }
    }

    int measured_w = 0;
    int measured_h = 0;
    if (ctx->record && !ctx->draw && ctx->priv && !ctx->record_failed &&
        !(style->has_background_image && style->background_image) &&
        (!width_specified || !height_specified))
    {
        record_only = true;
        html_view_render_cache_t *cache = &ctx->priv->render_cache;
        record_op_start = cache->op_count;
        anchor_start = cache->anchor_count;

        if (ctx->paint_layer == HTML_VIEW_PAINT_LAYER_BLOCK)
        {
            ctx->paint_layer = HTML_VIEW_PAINT_LAYER_INLINE;
        }

        if (style->has_background && !style->background_transparent)
        {
            bg_op = html_view_record_rect_placeholder(ctx, 0, 0, 0, 0, style->background, &ctx->clip);
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
        inner.draw = false;
        inner.record = true;
        inner.record_failed = false;
        inner.style_block = NULL;
        inner.style_depth = 0;
        inner.measure_shrink = true;
        inner.body_x = 0;
        int render_body_w = width_specified ? specified_content_w : available_content_w;
        if (width_specified && available_content_w > 0 && render_body_w > available_content_w)
        {
            render_body_w = available_content_w;
        }
        inner.body_w = render_body_w;
        if (inner.body_w < 0) inner.body_w = 0;
        inner.max_x = inner.body_x + inner.body_w;
        inner.x = inner.body_x;
        inner.y = 0;
        inner.line_start_x = inner.x;
        inner.line_start_y = inner.y;
        inner.pending_space = false;
        html_view_margin_state_reset(&inner.pending_margin);
        inner.measure_max_x = inner.x;
        inner.content_bottom = inner.y;
        inner.line_op_start = record_op_start;
        inner.space_w = html_view_text_width(&inner, " ");
        inner.line_height = html_view_line_height_for_style(&inner, style);
        if (html_view_subtree_has_form_control(node) && inner.line_height < atk_font_line_height() + 8)
        {
            inner.line_height = atk_font_line_height() + 8;
        }
        inner.height_basis_valid = false;
        inner.height_basis = 0;
        inner.height_basis_explicit = false;
        record_start_x = inner.x;
        record_start_y = inner.y;

        html_view_trace_note_measure(HTML_VIEW_TRACE_MEASURE_INLINE_BLOCK);
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

        record_op_end = cache->op_count;
        measured_w = inner.measure_max_x - inner.body_x;
        if (measured_w < 0) measured_w = 0;
        measured_h = inner.content_bottom;
        if (measured_h < 0) measured_h = 0;
        record_children = true;
    }
    if (!record_children && (!width_specified || !height_specified))
    {
        html_view_measure_inline_block_children(ctx, node, style, available_content_w, &measured_w, &measured_h);
    }

    int content_w = 0;
    if (width_specified)
    {
        content_w = specified_content_w;
    }
    else
    {
        content_w = measured_w;
    }

    int content_h = 0;
    if (height_specified)
    {
        content_h = specified_h;
    }
    else
    {
        content_h = measured_h;
    }

    if (content_w < 0) content_w = 0;
    if (content_h < 0) content_h = 0;
    if (available_content_w > 0 && content_w > available_content_w)
    {
        content_w = available_content_w;
    }

    int min_w = -1;
    int max_w = -1;
    if (style->has_min_width && style->min_width.valid && !style->min_width.is_auto)
    {
        min_w = html_view_length_to_px(&style->min_width,
                                       ctx->viewport_w,
                                       ctx->viewport_h,
                                       ctx->body_w,
                                       ctx->viewport_h,
                                       ctx->base_font_px,
                                       true);
        min_w = html_view_box_sizing_content_width(style,
                                                   min_w,
                                                   pad_left,
                                                   pad_right,
                                                   border_left,
                                                   border_right);
        if (min_w < 0) min_w = 0;
    }
    if (style->has_max_width && style->max_width.valid && !style->max_width.is_auto)
    {
        max_w = html_view_length_to_px(&style->max_width,
                                       ctx->viewport_w,
                                       ctx->viewport_h,
                                       ctx->body_w,
                                       ctx->viewport_h,
                                       ctx->base_font_px,
                                       true);
        max_w = html_view_box_sizing_content_width(style,
                                                   max_w,
                                                   pad_left,
                                                   pad_right,
                                                   border_left,
                                                   border_right);
        if (max_w < 0) max_w = 0;
    }
    if (max_w >= 0 && content_w > max_w)
    {
        content_w = max_w;
    }
    if (min_w >= 0 && content_w < min_w)
    {
        content_w = min_w;
    }
    if (max_w >= 0 && min_w > max_w)
    {
        content_w = min_w;
    }

    int min_h = -1;
    int max_h = -1;
    if (html_view_length_to_px_height(ctx, &style->min_height, &min_h))
    {
        min_h = html_view_box_sizing_content_height(style,
                                                    min_h,
                                                    pad_top,
                                                    pad_bottom,
                                                    border_top,
                                                    border_bottom);
        if (min_h < 0)
        {
            min_h = 0;
        }
    }
    else
    {
        min_h = -1;
    }
    if (html_view_length_to_px_height(ctx, &style->max_height, &max_h))
    {
        max_h = html_view_box_sizing_content_height(style,
                                                    max_h,
                                                    pad_top,
                                                    pad_bottom,
                                                    border_top,
                                                    border_bottom);
        if (max_h < 0)
        {
            max_h = 0;
        }
    }
    else
    {
        max_h = -1;
    }
    if (max_h >= 0 && content_h > max_h)
    {
        content_h = max_h;
    }
    if (min_h >= 0 && content_h < min_h)
    {
        content_h = min_h;
    }
    if (max_h >= 0 && min_h > max_h)
    {
        content_h = min_h;
    }

    int box_w = content_w + pad_left + pad_right + border_left + border_right;
    int box_h = content_h + pad_top + pad_bottom + border_top + border_bottom;
    int outer_w = box_w + margin_left + margin_right;
    int outer_h = box_h + margin_top + margin_bottom;
    if (box_w <= 0 || box_h <= 0)
    {
        ctx->paint_layer = saved_layer;
        return false;
    }

    if (outer_h > ctx->line_height)
    {
        ctx->line_height = outer_h;
    }

    if (ctx->pending_space && ctx->x != ctx->body_x)
    {
        if (ctx->x + ctx->space_w + outer_w > ctx->max_x)
        {
            if (record_only)
            {
                html_view_flush_underline_run(ctx);
                html_view_align_line_partial(ctx, record_op_start);
                html_view_advance_line_no_align(ctx, ctx->line_height, record_op_start);
            }
            else
            {
                html_view_new_line(ctx);
            }
        }
        else
        {
            ctx->x += ctx->space_w;
        }
    }
    else if (ctx->x != ctx->body_x && ctx->x + outer_w > ctx->max_x)
    {
        if (record_only)
        {
            html_view_flush_underline_run(ctx);
            html_view_align_line_partial(ctx, record_op_start);
            html_view_advance_line_no_align(ctx, ctx->line_height, record_op_start);
        }
        else
        {
            html_view_new_line(ctx);
        }
    }

    if (ctx->paint_layer == HTML_VIEW_PAINT_LAYER_BLOCK)
    {
        ctx->paint_layer = HTML_VIEW_PAINT_LAYER_INLINE;
    }

    bool measure_only = (!ctx->draw && !ctx->record);
    int outer_x = ctx->x;
    int border_box_x = outer_x + margin_left;
    int doc_y = ctx->y + ctx->line_height - outer_h + margin_top;
    int draw_y = html_view_draw_y(ctx, doc_y);

    if (!record_only)
    {
        if (style->has_background && !style->background_transparent)
        {
            html_view_draw_rect_clipped(ctx, border_box_x, draw_y, box_w, box_h, style->background, &ctx->clip);
        }
        html_view_draw_background_image(ctx, style, border_box_x, doc_y, box_w, box_h);

        if (style->has_border && (border_top > 0 || border_right > 0 || border_bottom > 0 || border_left > 0))
        {
            html_view_draw_border_sides_clipped(ctx,
                                                border_box_x,
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
    else if (ctx->priv && bg_op != (size_t)-1 && bg_op < ctx->priv->render_cache.op_count)
    {
        html_view_render_cache_t *cache = &ctx->priv->render_cache;
        html_view_op_t *op = &cache->ops[bg_op];
        op->x = html_view_record_x(ctx, border_box_x);
        op->y = html_view_record_y(ctx, draw_y);
        op->w = box_w;
        op->h = box_h;
        html_view_render_cache_reindex_op(cache, bg_op);
    }

    if (measure_only)
    {
        ctx->x = outer_x + outer_w;
        if (ctx->x > ctx->measure_max_x)
        {
            ctx->measure_max_x = ctx->x;
        }
        ctx->pending_space = true;
        html_view_ensure_line_visible(ctx);
        ctx->paint_layer = saved_layer;
        return true;
    }

    if (record_only)
    {
        int content_x = border_box_x + border_left + pad_left;
        int content_y = doc_y + border_top + pad_top;
        int dx = content_x - record_start_x;
        int dy = content_y - record_start_y;
        html_view_shift_recorded_ops(ctx, record_op_start, record_op_end, dx, dy, bg_op);
        if (ctx->priv)
        {
            html_view_shift_recorded_anchors(ctx, anchor_start, ctx->priv->render_cache.anchor_count, dy);
        }

        if (style->has_border && (border_top > 0 || border_right > 0 || border_bottom > 0 || border_left > 0))
        {
            html_view_draw_border_sides_clipped(ctx,
                                                border_box_x,
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

        ctx->x = outer_x + outer_w;
        if (ctx->x > ctx->measure_max_x)
        {
            ctx->measure_max_x = ctx->x;
        }
        ctx->pending_space = true;
        html_view_ensure_line_visible(ctx);
        ctx->paint_layer = saved_layer;
        return true;
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
    inner.body_x = border_box_x + border_left + pad_left;
    inner.body_w = content_w;
    if (inner.body_w < 0) inner.body_w = 0;
    inner.max_x = inner.body_x + inner.body_w;
    inner.x = inner.body_x;
    inner.y = doc_y + border_top + pad_top;
    inner.line_start_x = inner.x;
    inner.line_start_y = inner.y;
    inner.pending_space = false;
    html_view_margin_state_reset(&inner.pending_margin);
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

    ctx->x = outer_x + outer_w;
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
    if (ctx->pending_margin.valid && ctx->x == ctx->body_x)
    {
        ctx->y += html_view_margin_state_value(&ctx->pending_margin);
        html_view_margin_state_reset(&ctx->pending_margin);
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

    if (html_view_render_inline_block_element(ctx, node, style))
    {
        return true;
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

        if (style->has_width && style->width.valid && !style->width.is_auto)
        {
            content_w = html_view_box_sizing_content_width(style,
                                                           content_w,
                                                           pad_left,
                                                           pad_right,
                                                           border_left,
                                                           border_right);
        }
        if (style->has_height && style->height.valid && !style->height.is_auto)
        {
            content_h = html_view_box_sizing_content_height(style,
                                                            content_h,
                                                            pad_top,
                                                            pad_bottom,
                                                            border_top,
                                                            border_bottom);
        }

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
                    const char *debug_label = html_view_debug_inline_label(node);
                    if (debug_label && ctx->record)
                    {
                        int bg_repeat = style->has_background_repeat ? (int)style->background_repeat : -1;
                        int bg_attach = style->has_background_attachment ? (int)style->background_attachment : -1;
                        int bg_pos_x = 0;
                        int bg_pos_y = 0;
                        if (style->has_background_position)
                        {
                            bg_pos_x = html_view_length_to_px_signed(&style->background_pos_x,
                                                                     ctx->viewport_w,
                                                                     ctx->viewport_h,
                                                                     box_w,
                                                                     box_h,
                                                                     ctx->base_font_px,
                                                                     true);
                            bg_pos_y = html_view_length_to_px_signed(&style->background_pos_y,
                                                                     ctx->viewport_w,
                                                                     ctx->viewport_h,
                                                                     box_w,
                                                                     box_h,
                                                                     ctx->base_font_px,
                                                                     false);
                        }
                        bool bg_has_img = style->has_background_image && style->background_image;
                        uint32_t bg_hash = bg_has_img ? html_view_debug_hash_string(style->background_image) : 0;
                        int bg_w = 0;
                        int bg_h = 0;
                        if (bg_has_img && ctx->priv)
                        {
                            html_view_image_t *bg = html_view_image_find(ctx->priv, style->background_image);
                            if (!bg)
                            {
                                (void)html_view_try_load_data_image_locked(ctx->priv, style->background_image);
                                bg = html_view_image_find(ctx->priv, style->background_image);
                            }
                            if (bg)
                            {
                                bg_w = bg->width;
                                bg_h = bg->height;
                            }
                        }
                        video_color_t bg_color = style->has_background ? style->background : 0;
                        int bg_trans = (!style->has_background || style->background_transparent) ? 1 : 0;
                        serial_printf("[html_view][acid2] object=%s img=%dx%d box=%dx%d padding=%d,%d,%d,%d border=%d,%d,%d,%d bg=%08X bg_trans=%d bg_img=%d bg_hash=%08X bg_size=%dx%d bg_attach=%d bg_repeat=%d bg_pos=%d,%d",
                                      debug_label,
                                      content_w,
                                      content_h,
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
                                      bg_color,
                                      bg_trans,
                                      bg_has_img ? 1 : 0,
                                      bg_hash,
                                      bg_w,
                                      bg_h,
                                      bg_attach,
                                      bg_repeat,
                                      bg_pos_x,
                                      bg_pos_y);
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
