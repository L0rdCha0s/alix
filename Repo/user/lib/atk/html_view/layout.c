#include "atk/html_view/html_view_internal.h"

#include "ctype.h"

void html_view_draw_rect_clipped(html_view_ctx_t *ctx,
                                        int x,
                                        int y,
                                        int w,
                                        int h,
                                        video_color_t color,
                                        const atk_rect_t *clip)
{
    if (!ctx || w <= 0 || h <= 0)
    {
        return;
    }

    if (ctx->record)
    {
        if (!ctx->record_failed && ctx->priv)
        {
            html_view_render_cache_t *cache = &ctx->priv->render_cache;
            html_view_op_t op = {0};
            op.kind = HTML_VIEW_OP_RECT;
            op.x = x - ctx->doc_origin_x;
            op.y = (y + ctx->priv->scroll_y) - ctx->doc_origin_y;
            op.w = w;
            op.h = h;
            op.color = color;
            if (!html_view_render_cache_push_op(cache, &op, cache->tile_h))
            {
                ctx->record_failed = true;
            }
        }
        return;
    }
    if (!ctx->draw)
    {
        return;
    }

    int x0 = x;
    int y0 = y;
    int x1 = x + w;
    int y1 = y + h;

    if (clip)
    {
        int cx0 = clip->x;
        int cy0 = clip->y;
        int cx1 = clip->x + clip->width;
        int cy1 = clip->y + clip->height;
        if (x0 < cx0) x0 = cx0;
        if (y0 < cy0) y0 = cy0;
        if (x1 > cx1) x1 = cx1;
        if (y1 > cy1) y1 = cy1;
    }

    if (x1 <= x0 || y1 <= y0)
    {
        return;
    }
    video_draw_rect(x0, y0, x1 - x0, y1 - y0, color);
}

void html_view_draw_border_clipped(html_view_ctx_t *ctx,
                                         int x,
                                         int y,
                                         int w,
                                         int h,
                                         int thickness,
                                         video_color_t color,
                                         const atk_rect_t *clip)
{
    if (w <= 0 || h <= 0 || thickness <= 0)
    {
        return;
    }

    if (thickness * 2 > w)
    {
        thickness = w / 2;
    }
    if (thickness * 2 > h)
    {
        thickness = h / 2;
    }
    if (thickness <= 0)
    {
        return;
    }

    html_view_draw_rect_clipped(ctx, x, y, w, thickness, color, clip);                    /* top */
    html_view_draw_rect_clipped(ctx, x, y + h - thickness, w, thickness, color, clip);   /* bottom */
    html_view_draw_rect_clipped(ctx, x, y + thickness, thickness, h - thickness * 2, color, clip); /* left */
    html_view_draw_rect_clipped(ctx, x + w - thickness, y + thickness, thickness, h - thickness * 2, color, clip); /* right */
}

void html_view_blit_rgba32_clipped(html_view_ctx_t *ctx,
                                         int dst_x,
                                         int dst_y,
                                         int width,
                                         int height,
                                         const video_color_t *pixels,
                                         int stride_bytes,
                                         const atk_rect_t *clip)
{
    if (!ctx || !pixels || width <= 0 || height <= 0 || stride_bytes <= 0)
    {
        return;
    }

    if (ctx->record)
    {
        if (!ctx->record_failed && ctx->priv)
        {
            html_view_render_cache_t *cache = &ctx->priv->render_cache;
            html_view_op_t op = {0};
            op.kind = HTML_VIEW_OP_IMAGE;
            op.x = dst_x - ctx->doc_origin_x;
            op.y = (dst_y + ctx->priv->scroll_y) - ctx->doc_origin_y;
            op.w = width;
            op.h = height;
            op.pixels = pixels;
            op.stride_bytes = stride_bytes;
            op.href = ctx->active_href;
            if (!html_view_render_cache_push_op(cache, &op, cache->tile_h))
            {
                ctx->record_failed = true;
            }
        }
        return;
    }
    if (!ctx->draw)
    {
        return;
    }

    int x0 = dst_x;
    int y0 = dst_y;
    int x1 = dst_x + width;
    int y1 = dst_y + height;

    int clip_x0 = clip ? clip->x : 0;
    int clip_y0 = clip ? clip->y : 0;
    int clip_x1 = clip ? (clip->x + clip->width) : video_screen_width();
    int clip_y1 = clip ? (clip->y + clip->height) : video_screen_height();

    if (x0 < clip_x0) x0 = clip_x0;
    if (y0 < clip_y0) y0 = clip_y0;
    if (x1 > clip_x1) x1 = clip_x1;
    if (y1 > clip_y1) y1 = clip_y1;

    int draw_w = x1 - x0;
    int draw_h = y1 - y0;
    if (draw_w <= 0 || draw_h <= 0)
    {
        return;
    }

    int offset_x = x0 - dst_x;
    int offset_y = y0 - dst_y;
    int stride_px = stride_bytes / (int)sizeof(video_color_t);
    const video_color_t *src = pixels + offset_y * stride_px + offset_x;

    video_blit_rgba32_untracked(x0, y0, draw_w, draw_h, src, stride_bytes, true);
}

void html_view_align_current_line(html_view_ctx_t *ctx)
{
    if (!ctx || !ctx->record || ctx->record_failed || !ctx->priv)
    {
        return;
    }
    if (ctx->text_align_mode == CSS_TEXT_ALIGN_LEFT)
    {
        ctx->line_op_start = ctx->priv->render_cache.op_count;
        return;
    }

    html_view_render_cache_t *cache = &ctx->priv->render_cache;
    size_t start = ctx->line_op_start;
    size_t end = cache->op_count;
    if (start >= end)
    {
        return;
    }

    int line_left = ctx->line_start_x;
    int avail = ctx->max_x - line_left;
    int line_w = ctx->x - line_left;
    if (avail <= 0 || line_w <= 0 || line_w >= avail)
    {
        ctx->line_op_start = end;
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
        ctx->line_op_start = end;
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

    ctx->line_op_start = end;
}

void html_view_new_line(html_view_ctx_t *ctx)
{
    if (!ctx)
    {
        return;
    }

    html_view_align_current_line(ctx);

    ctx->x = ctx->body_x;
    ctx->y += ctx->line_height;
    ctx->pending_space = false;
    int bottom = ctx->y + ctx->line_height;
    if (bottom > ctx->content_bottom)
    {
        ctx->content_bottom = bottom;
    }

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

void html_view_ensure_line_visible(html_view_ctx_t *ctx)
{
    if (!ctx)
    {
        return;
    }
    int bottom = ctx->y + ctx->line_height;
    if (bottom > ctx->content_bottom)
    {
        ctx->content_bottom = bottom;
    }
}

bool html_view_line_visible(const html_view_ctx_t *ctx)
{
    if (!ctx)
    {
        return false;
    }
    int draw_top = ctx->y - ctx->priv->scroll_y;
    int draw_bottom = draw_top + ctx->line_height;
    int clip_y0 = ctx->clip.y;
    int clip_y1 = ctx->clip.y + ctx->clip.height;
    return !(draw_bottom <= clip_y0 || draw_top >= clip_y1);
}

void html_view_float_bounds_at_y(const html_view_float_ctx_t *floats,
                                 int y,
                                 int container_x,
                                 int container_w,
                                 int *out_left,
                                 int *out_right)
{
    if (!out_left || !out_right)
    {
        return;
    }
    int left = container_x;
    int right = container_x + container_w;
    if (floats)
    {
        for (size_t i = 0; i < floats->count; ++i)
        {
            const html_view_float_t *f = &floats->items[i];
            if (!f)
            {
                continue;
            }
            if (y < f->y || y >= f->y + f->h)
            {
                continue;
            }
            if (f->side == CSS_FLOAT_LEFT)
            {
                int edge = f->x + f->w;
                if (edge > left)
                {
                    left = edge;
                }
            }
            else if (f->side == CSS_FLOAT_RIGHT)
            {
                int edge = f->x;
                if (edge < right)
                {
                    right = edge;
                }
            }
        }
    }
    *out_left = left;
    *out_right = right;
}

int html_view_float_next_y(const html_view_float_ctx_t *floats, int y)
{
    if (!floats)
    {
        return y + 1;
    }
    int next = -1;
    for (size_t i = 0; i < floats->count; ++i)
    {
        const html_view_float_t *f = &floats->items[i];
        if (!f)
        {
            continue;
        }
        if (y < f->y || y >= f->y + f->h)
        {
            continue;
        }
        int bottom = f->y + f->h;
        if (bottom > y && (next < 0 || bottom < next))
        {
            next = bottom;
        }
    }
    return (next > y) ? next : (y + 1);
}

int html_view_float_max_bottom(const html_view_float_ctx_t *floats, css_clear_t clear_mode)
{
    if (!floats || clear_mode == CSS_CLEAR_NONE)
    {
        return 0;
    }
    int max_bottom = 0;
    for (size_t i = 0; i < floats->count; ++i)
    {
        const html_view_float_t *f = &floats->items[i];
        if (!f)
        {
            continue;
        }
        if (clear_mode == CSS_CLEAR_LEFT && f->side != CSS_FLOAT_LEFT)
        {
            continue;
        }
        if (clear_mode == CSS_CLEAR_RIGHT && f->side != CSS_FLOAT_RIGHT)
        {
            continue;
        }
        int bottom = f->y + f->h;
        if (bottom > max_bottom)
        {
            max_bottom = bottom;
        }
    }
    return max_bottom;
}

void html_view_draw_border_sides_clipped(html_view_ctx_t *ctx,
                                         int x,
                                         int y,
                                         int w,
                                         int h,
                                         int top,
                                         int right,
                                         int bottom,
                                         int left,
                                         video_color_t color,
                                         const atk_rect_t *clip)
{
    if (w <= 0 || h <= 0)
    {
        return;
    }

    if (top > 0)
    {
        html_view_draw_rect_clipped(ctx, x, y, w, top, color, clip);
    }
    if (bottom > 0)
    {
        html_view_draw_rect_clipped(ctx, x, y + h - bottom, w, bottom, color, clip);
    }

    int inner_y = y + top;
    int inner_h = h - top - bottom;
    if (inner_h <= 0)
    {
        return;
    }
    if (left > 0)
    {
        html_view_draw_rect_clipped(ctx, x, inner_y, left, inner_h, color, clip);
    }
    if (right > 0)
    {
        html_view_draw_rect_clipped(ctx, x + w - right, inner_y, right, inner_h, color, clip);
    }
}

static void html_view_draw_word(html_view_ctx_t *ctx,
                                const char *word,
                                size_t len,
                                video_color_t color,
                                bool underline,
                                bool bold)
{
    if (!ctx || !word || len == 0)
    {
        return;
    }

    char scratch[128];
    const char *text = NULL;
    char *heap = NULL;
    if (len < sizeof(scratch))
    {
        memcpy(scratch, word, len);
        scratch[len] = '\0';
        text = scratch;
    }
    else
    {
        heap = (char *)malloc(len + 1);
        if (!heap)
        {
            return;
        }
        memcpy(heap, word, len);
        heap[len] = '\0';
        text = heap;
    }

    int w = html_view_text_width(ctx, text);

    if (ctx->pending_space && ctx->x != ctx->body_x)
    {
        if (ctx->x + ctx->space_w + w > ctx->max_x)
        {
            html_view_new_line(ctx);
        }
        else
        {
            ctx->x += ctx->space_w;
        }
    }
    else if (ctx->x != ctx->body_x && ctx->x + w > ctx->max_x)
    {
        html_view_new_line(ctx);
    }

    int draw_x = ctx->x;
    int draw_top = ctx->y - ctx->priv->scroll_y;
    int baseline = html_view_baseline_for_rect(ctx, draw_top, ctx->line_height);

    if (ctx->record)
    {
        if (!ctx->record_failed && ctx->priv)
        {
            html_view_render_cache_t *cache = &ctx->priv->render_cache;
            html_view_op_t op = {0};
            op.kind = HTML_VIEW_OP_TEXT;
            op.x = draw_x - ctx->doc_origin_x;
            op.y = (draw_top + ctx->priv->scroll_y) - ctx->doc_origin_y;
            op.w = w;
            op.h = ctx->line_height;
            op.baseline_off = (int16_t)(baseline - draw_top);
            op.font_px = (int16_t)ctx->actual_font_px;
            op.color = color;
            op.text = word;
            op.text_len = (uint32_t)len;
            op.text_owned = false;
            op.href = ctx->active_href;
            if (!html_view_render_cache_push_op(cache, &op, cache->tile_h))
            {
                ctx->record_failed = true;
            }
            if (bold && !ctx->record_failed)
            {
                html_view_op_t bold_op = op;
                bold_op.x += 1;
                (void)html_view_render_cache_push_op(cache, &bold_op, cache->tile_h);
            }
        }
        if (underline)
        {
            int underline_y = draw_top + ctx->line_height - 3;
            html_view_draw_rect_clipped(ctx, draw_x, underline_y, w, 1, color, &ctx->clip);
        }
    }
    else if (ctx->draw && html_view_line_visible(ctx))
    {
        html_view_draw_string_clipped(ctx, draw_x, baseline, text, color, &ctx->clip);
        if (bold)
        {
            html_view_draw_string_clipped(ctx, draw_x + 1, baseline, text, color, &ctx->clip);
        }
        if (underline)
        {
            int underline_y = draw_top + ctx->line_height - 3;
            int clip_y0 = ctx->clip.y;
            int clip_y1 = ctx->clip.y + ctx->clip.height;
            if (underline_y >= clip_y0 && underline_y < clip_y1)
            {
                html_view_draw_rect_clipped(ctx, draw_x, underline_y, w, 1, color, &ctx->clip);
            }
        }
    }

    ctx->x += w;
    if (ctx->x > ctx->measure_max_x)
    {
        ctx->measure_max_x = ctx->x;
    }
    ctx->pending_space = true;
    html_view_ensure_line_visible(ctx);

    free(heap);
}

void html_view_draw_text(html_view_ctx_t *ctx,
                         const char *text,
                         video_color_t color,
                         bool underline,
                         bool bold)
{
    if (!ctx || !text)
    {
        return;
    }

    const char *p = text;
    while (*p)
    {
        while (*p && isspace((unsigned char)*p))
        {
            ctx->pending_space = true;
            p++;
        }
        if (!*p)
        {
            break;
        }

        const char *wstart = p;
        while (*p && !isspace((unsigned char)*p))
        {
            p++;
        }
        size_t wlen = (size_t)(p - wstart);
        html_view_draw_word(ctx, wstart, wlen, color, underline, bold);
    }
}

void html_view_place_control_widget(html_view_ctx_t *ctx,
                                    atk_widget_t *child,
                                    int abs_x,
                                    int abs_y,
                                    int width,
                                    int height)
{
    if (!ctx || !child || width <= 0 || height <= 0)
    {
        return;
    }

    child->x = abs_x - ctx->window_x;
    child->y = abs_y - ctx->window_y;
    child->width = width;
    child->height = height;

    int vx0 = ctx->viewport_x;
    int vy0 = ctx->viewport_y;
    int vx1 = vx0 + ctx->viewport_w;
    int vy1 = vy0 + ctx->viewport_h;
    int wx1 = abs_x + width;
    int wy1 = abs_y + height;

    bool visible = abs_x >= vx0 && abs_y >= vy0 && wx1 <= vx1 && wy1 <= vy1;
    child->used = visible;
}

void html_view_place_inline_control(html_view_ctx_t *ctx,
                                    atk_widget_t *child,
                                    int width,
                                    int height)
{
    if (!ctx || width <= 0 || height <= 0)
    {
        return;
    }

    int max_width = ctx->max_x - ctx->body_x;
    if (max_width < 0)
    {
        max_width = 0;
    }
    if (width > max_width)
    {
        width = max_width;
    }

    if (ctx->pending_space && ctx->x != ctx->body_x)
    {
        if (ctx->x + ctx->space_w + width > ctx->max_x)
        {
            html_view_new_line(ctx);
        }
        else
        {
            ctx->x += ctx->space_w;
        }
    }
    else if (ctx->x != ctx->body_x && ctx->x + width > ctx->max_x)
    {
        html_view_new_line(ctx);
    }

    int abs_x = ctx->x;
    int abs_y = ctx->y - ctx->priv->scroll_y;
    if (child)
    {
        if (ctx->record)
        {
            if (!ctx->record_failed && ctx->priv)
            {
                html_view_render_cache_t *cache = &ctx->priv->render_cache;
                html_view_op_t op = {0};
                op.kind = HTML_VIEW_OP_CONTROL;
                op.x = abs_x - ctx->doc_origin_x;
                op.y = (abs_y + ctx->priv->scroll_y) - ctx->doc_origin_y;
                op.w = width;
                op.h = height;
                op.widget = child;
                if (!html_view_render_cache_push_op(cache, &op, cache->tile_h))
                {
                    ctx->record_failed = true;
                }
            }
        }
        else if (ctx->draw)
        {
            html_view_place_control_widget(ctx, child, abs_x, abs_y, width, height);
        }
    }

    ctx->x += width;
    if (ctx->x > ctx->measure_max_x)
    {
        ctx->measure_max_x = ctx->x;
    }
    ctx->pending_space = true;
    html_view_ensure_line_visible(ctx);
}

void html_view_place_block_control(html_view_ctx_t *ctx,
                                   atk_widget_t *child,
                                   int width,
                                   int height)
{
    if (!ctx || width <= 0 || height <= 0)
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
    if (width > max_width)
    {
        width = max_width;
    }

    int abs_x = ctx->body_x;
    int abs_y = ctx->y - ctx->priv->scroll_y;
    if (child)
    {
        if (ctx->record)
        {
            if (!ctx->record_failed && ctx->priv)
            {
                html_view_render_cache_t *cache = &ctx->priv->render_cache;
                html_view_op_t op = {0};
                op.kind = HTML_VIEW_OP_CONTROL;
                op.x = abs_x - ctx->doc_origin_x;
                op.y = (abs_y + ctx->priv->scroll_y) - ctx->doc_origin_y;
                op.w = width;
                op.h = height;
                op.widget = child;
                if (!html_view_render_cache_push_op(cache, &op, cache->tile_h))
                {
                    ctx->record_failed = true;
                }
            }
        }
        else if (ctx->draw)
        {
            html_view_place_control_widget(ctx, child, abs_x, abs_y, width, height);
        }
    }

    int right_edge = abs_x + width;
    if (right_edge > ctx->measure_max_x)
    {
        ctx->measure_max_x = right_edge;
    }

    ctx->y += height;
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

bool html_view_is_block_tag(const char *tag)
{
    if (!tag)
    {
        return false;
    }
    return strcmp(tag, "html") == 0 ||
           strcmp(tag, "body") == 0 ||
           strcmp(tag, "div") == 0 ||
           strcmp(tag, "center") == 0 ||
           strcmp(tag, "form") == 0 ||
           strcmp(tag, "p") == 0 ||
           strcmp(tag, "h1") == 0 ||
           strcmp(tag, "h2") == 0 ||
           strcmp(tag, "h3") == 0 ||
           strcmp(tag, "h4") == 0 ||
           strcmp(tag, "h5") == 0 ||
           strcmp(tag, "h6") == 0 ||
           strcmp(tag, "ul") == 0 ||
           strcmp(tag, "dl") == 0 ||
           strcmp(tag, "dt") == 0 ||
           strcmp(tag, "dd") == 0 ||
           strcmp(tag, "blockquote") == 0 ||
           strcmp(tag, "address") == 0 ||
           strcmp(tag, "li") == 0 ||
           strcmp(tag, "fieldset") == 0 ||
           strcmp(tag, "legend") == 0 ||
           strcmp(tag, "table") == 0 ||
           strcmp(tag, "tbody") == 0 ||
           strcmp(tag, "thead") == 0 ||
           strcmp(tag, "tfoot") == 0 ||
           strcmp(tag, "tr") == 0 ||
           strcmp(tag, "td") == 0 ||
           strcmp(tag, "th") == 0 ||
           strcmp(tag, "img") == 0;
}

bool html_view_is_form_control_tag(const char *tag)
{
    if (!tag)
    {
        return false;
    }
    return strcmp(tag, "input") == 0 ||
           strcmp(tag, "select") == 0 ||
           strcmp(tag, "textarea") == 0 ||
           strcmp(tag, "button") == 0;
}
