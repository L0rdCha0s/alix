#include "atk/html_view/render/render_internal.h"

typedef struct
{
    const html_node_t *node;
    css_style_t style;
    int margin_top;
    int margin_right;
    int margin_bottom;
    int margin_left;
    int pad_top;
    int pad_right;
    int pad_bottom;
    int pad_left;
    int border_top;
    int border_right;
    int border_bottom;
    int border_left;
    int content_w;
    int content_h;
    int border_box_w;
    int border_box_h;
    int outer_w;
    int outer_h;
    int main_border;
    int main_outer;
    int cross_outer;
    int flex_grow_milli;
    int flex_shrink_milli;
    bool cross_explicit;
    int pos_main;
    int pos_cross;
} html_view_flex_item_t;

typedef struct
{
    size_t start;
    size_t count;
    int main_size;
    int cross_size;
    int gap_total;
    int grow_sum;
    int64_t shrink_weight_sum;
} html_view_flex_line_t;

static void html_view_calc_box_edges(const html_view_ctx_t *ctx,
                                     const css_style_t *style,
                                     int ref_w,
                                     int *margin_top,
                                     int *margin_right,
                                     int *margin_bottom,
                                     int *margin_left,
                                     int *pad_top,
                                     int *pad_right,
                                     int *pad_bottom,
                                     int *pad_left,
                                     int *border_top,
                                     int *border_right,
                                     int *border_bottom,
                                     int *border_left)
{
    if (!ctx || !style)
    {
        return;
    }
    if (margin_top) *margin_top = 0;
    if (margin_right) *margin_right = 0;
    if (margin_bottom) *margin_bottom = 0;
    if (margin_left) *margin_left = 0;
    if (pad_top) *pad_top = 0;
    if (pad_right) *pad_right = 0;
    if (pad_bottom) *pad_bottom = 0;
    if (pad_left) *pad_left = 0;
    if (border_top) *border_top = 0;
    if (border_right) *border_right = 0;
    if (border_bottom) *border_bottom = 0;
    if (border_left) *border_left = 0;

    int vw = ctx->viewport_w;
    int vh = ctx->viewport_h;
    int font_px = ctx->base_font_px;
    if (ref_w < 0) ref_w = 0;

    if (style->has_margin)
    {
        if (margin_top && style->margin.top.valid && !style->margin.top.is_auto)
        {
            *margin_top = html_view_length_to_px_signed(&style->margin.top, vw, vh, ref_w, vh, font_px, false);
        }
        if (margin_right && style->margin.right.valid && !style->margin.right.is_auto)
        {
            *margin_right = html_view_length_to_px_signed(&style->margin.right, vw, vh, ref_w, vh, font_px, true);
        }
        if (margin_bottom && style->margin.bottom.valid && !style->margin.bottom.is_auto)
        {
            *margin_bottom = html_view_length_to_px_signed(&style->margin.bottom, vw, vh, ref_w, vh, font_px, false);
        }
        if (margin_left && style->margin.left.valid && !style->margin.left.is_auto)
        {
            *margin_left = html_view_length_to_px_signed(&style->margin.left, vw, vh, ref_w, vh, font_px, true);
        }
    }

    if (style->has_padding)
    {
        if (pad_top)
        {
            *pad_top = html_view_length_to_px(&style->padding.top, vw, vh, ref_w, vh, font_px, false);
        }
        if (pad_right)
        {
            *pad_right = html_view_length_to_px(&style->padding.right, vw, vh, ref_w, vh, font_px, true);
        }
        if (pad_bottom)
        {
            *pad_bottom = html_view_length_to_px(&style->padding.bottom, vw, vh, ref_w, vh, font_px, false);
        }
        if (pad_left)
        {
            *pad_left = html_view_length_to_px(&style->padding.left, vw, vh, ref_w, vh, font_px, true);
        }
    }

    if (style->has_border)
    {
        if (border_top)
        {
            *border_top = html_view_length_to_px(&style->border_width.top, vw, vh, ref_w, vh, font_px, false);
        }
        if (border_right)
        {
            *border_right = html_view_length_to_px(&style->border_width.right, vw, vh, ref_w, vh, font_px, true);
        }
        if (border_bottom)
        {
            *border_bottom = html_view_length_to_px(&style->border_width.bottom, vw, vh, ref_w, vh, font_px, false);
        }
        if (border_left)
        {
            *border_left = html_view_length_to_px(&style->border_width.left, vw, vh, ref_w, vh, font_px, true);
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

    if (style->has_border_style)
    {
        html_view_apply_border_style_none(style, border_top, border_right, border_bottom, border_left);
    }
}

static void html_view_measure_node_size(const html_view_ctx_t *ctx,
                                        const html_node_t *node,
                                        const css_style_t *parent_style,
                                        int max_w,
                                        int *out_w,
                                        int *out_h)
{
    if (!ctx || !node || !out_w || !out_h)
    {
        return;
    }

    html_view_ctx_t measure = *ctx;
    measure.draw = false;
    measure.record = false;
    measure.record_failed = false;
    measure.floats = NULL;
    measure.style_block = NULL;
    measure.style_depth = 0;
    measure.body_x = 0;
    measure.body_w = max_w;
    if (measure.body_w < 0) measure.body_w = 0;
    measure.max_x = measure.body_x + measure.body_w;
    measure.x = measure.body_x;
    measure.y = 0;
    measure.content_bottom = 0;
    measure.pending_space = false;
    measure.underline_run_active = false;
    measure.underline_run_start_x = 0;
    measure.list_level = 0;
    measure.measure_max_x = measure.x;
    measure.space_w = html_view_text_width(&measure, " ");
    if (parent_style)
    {
        measure.line_height = html_view_line_height_for_style(&measure, parent_style);
    }

    html_view_render_node_internal(&measure, node, parent_style);
    html_view_style_stack_destroy(&measure);

    int used_w = measure.measure_max_x - measure.body_x;
    if (used_w < 0) used_w = 0;
    int used_h = measure.content_bottom;
    if (used_h < 0) used_h = 0;
    *out_w = used_w;
    *out_h = used_h;
}

static void html_view_flex_update_sizes(html_view_flex_item_t *item, bool row)
{
    if (!item)
    {
        return;
    }
    if (item->content_w < 0) item->content_w = 0;
    if (item->content_h < 0) item->content_h = 0;

    item->border_box_w = item->content_w + item->pad_left + item->pad_right + item->border_left + item->border_right;
    item->border_box_h = item->content_h + item->pad_top + item->pad_bottom + item->border_top + item->border_bottom;
    if (item->border_box_w < 0) item->border_box_w = 0;
    if (item->border_box_h < 0) item->border_box_h = 0;

    item->outer_w = item->border_box_w + item->margin_left + item->margin_right;
    item->outer_h = item->border_box_h + item->margin_top + item->margin_bottom;
    if (item->outer_w < 0) item->outer_w = 0;
    if (item->outer_h < 0) item->outer_h = 0;

    item->main_border = row ? item->border_box_w : item->border_box_h;
    item->main_outer = row ? item->outer_w : item->outer_h;
    item->cross_outer = row ? item->outer_h : item->outer_w;
}

void html_view_render_flex_container(html_view_ctx_t *ctx,
                                            const html_node_t *node,
                                            const css_style_t *style,
                                            bool inline_container)
{
    if (!ctx || !node || !style)
    {
        return;
    }

    css_flex_direction_t dir = style->has_flex_direction ? style->flex_direction : CSS_FLEX_DIRECTION_ROW;
    bool row = (dir == CSS_FLEX_DIRECTION_ROW || dir == CSS_FLEX_DIRECTION_ROW_REVERSE);
    bool reverse = (dir == CSS_FLEX_DIRECTION_ROW_REVERSE || dir == CSS_FLEX_DIRECTION_COLUMN_REVERSE);

    css_flex_wrap_t wrap_mode = style->has_flex_wrap ? style->flex_wrap : CSS_FLEX_WRAP_NOWRAP;
    bool wrap = (wrap_mode == CSS_FLEX_WRAP_WRAP || wrap_mode == CSS_FLEX_WRAP_WRAP_REVERSE);
    bool wrap_reverse = (wrap_mode == CSS_FLEX_WRAP_WRAP_REVERSE);

    int margin_top = 0;
    int margin_right = 0;
    int margin_bottom = 0;
    int margin_left = 0;
    int pad_top = 0;
    int pad_right = 0;
    int pad_bottom = 0;
    int pad_left = 0;
    int border_top = 0;
    int border_right = 0;
    int border_bottom = 0;
    int border_left = 0;

    html_view_calc_box_edges(ctx,
                             style,
                             ctx->body_w,
                             &margin_top,
                             &margin_right,
                             &margin_bottom,
                             &margin_left,
                             &pad_top,
                             &pad_right,
                             &pad_bottom,
                             &pad_left,
                             &border_top,
                             &border_right,
                             &border_bottom,
                             &border_left);

    int content_main = 0;
    int content_cross = 0;
    bool main_explicit = false;
    bool cross_explicit = false;

    if (row)
    {
        if (style->has_width && style->width.valid && !style->width.is_auto)
        {
            content_main = html_view_length_to_px(&style->width,
                                                  ctx->viewport_w,
                                                  ctx->viewport_h,
                                                  ctx->body_w,
                                                  ctx->viewport_h,
                                                  ctx->base_font_px,
                                                  true);
            main_explicit = true;
        }
        if (style->has_height && style->height.valid && !style->height.is_auto)
        {
            content_cross = html_view_length_to_px(&style->height,
                                                   ctx->viewport_w,
                                                   ctx->viewport_h,
                                                   ctx->viewport_w,
                                                   ctx->viewport_h,
                                                   ctx->base_font_px,
                                                   false);
            cross_explicit = true;
        }
    }
    else
    {
        if (style->has_height && style->height.valid && !style->height.is_auto)
        {
            content_main = html_view_length_to_px(&style->height,
                                                  ctx->viewport_w,
                                                  ctx->viewport_h,
                                                  ctx->viewport_w,
                                                  ctx->viewport_h,
                                                  ctx->base_font_px,
                                                  false);
            main_explicit = true;
        }
        if (style->has_width && style->width.valid && !style->width.is_auto)
        {
            content_cross = html_view_length_to_px(&style->width,
                                                   ctx->viewport_w,
                                                   ctx->viewport_h,
                                                   ctx->body_w,
                                                   ctx->viewport_h,
                                                   ctx->base_font_px,
                                                   true);
            cross_explicit = true;
        }
    }

    if (content_main < 0) content_main = 0;
    if (content_cross < 0) content_cross = 0;

    int layout_main = content_main;
    if (!main_explicit)
    {
        if (row)
        {
            layout_main = ctx->body_w - margin_left - margin_right;
            if (layout_main < 0) layout_main = 0;
        }
        else
        {
            layout_main = 0;
            wrap = false;
        }
    }

    int gap_main = 0;
    int gap_cross = 0;
    if (row)
    {
        if (style->has_column_gap)
        {
            gap_main = html_view_length_to_px(&style->column_gap,
                                              ctx->viewport_w,
                                              ctx->viewport_h,
                                              layout_main,
                                              ctx->viewport_h,
                                              ctx->base_font_px,
                                              true);
        }
        if (style->has_row_gap)
        {
            gap_cross = html_view_length_to_px(&style->row_gap,
                                               ctx->viewport_w,
                                               ctx->viewport_h,
                                               ctx->viewport_w,
                                               ctx->viewport_h,
                                               ctx->base_font_px,
                                               false);
        }
    }
    else
    {
        if (style->has_row_gap)
        {
            gap_main = html_view_length_to_px(&style->row_gap,
                                              ctx->viewport_w,
                                              ctx->viewport_h,
                                              ctx->viewport_w,
                                              ctx->viewport_h,
                                              ctx->base_font_px,
                                              false);
        }
        if (style->has_column_gap)
        {
            gap_cross = html_view_length_to_px(&style->column_gap,
                                               ctx->viewport_w,
                                               ctx->viewport_h,
                                               ctx->body_w,
                                               ctx->viewport_h,
                                               ctx->base_font_px,
                                               true);
        }
    }
    if (gap_main < 0) gap_main = 0;
    if (gap_cross < 0) gap_cross = 0;

    size_t child_cap = 0;
    for (const html_node_t *child = node->first_child; child; child = child->next_sibling)
    {
        if (child->type == HTML_NODE_ELEMENT || child->type == HTML_NODE_TEXT)
        {
            child_cap++;
        }
    }

    html_view_flex_item_t *items = NULL;
    html_view_flex_line_t *lines = NULL;
    size_t item_count = 0;
    size_t line_count = 0;

    if (child_cap > 0)
    {
        items = (html_view_flex_item_t *)calloc(child_cap, sizeof(*items));
        if (!items)
        {
            return;
        }

        for (const html_node_t *child = node->first_child; child; child = child->next_sibling)
        {
            if (child->type != HTML_NODE_ELEMENT && child->type != HTML_NODE_TEXT)
            {
                continue;
            }

            css_style_t child_style;
            html_view_style_for_node(&child_style, ctx->sheet, style, child);
            if (child_style.has_display && child_style.display == CSS_DISPLAY_NONE)
            {
                continue;
            }

            html_view_flex_item_t *item = &items[item_count++];
            item->node = child;
            item->style = child_style;
            item->flex_grow_milli = child_style.has_flex_grow ? child_style.flex_grow_milli : 0;
            item->flex_shrink_milli = child_style.has_flex_shrink ? child_style.flex_shrink_milli : 1000;
            if (item->flex_grow_milli < 0) item->flex_grow_milli = 0;
            if (item->flex_shrink_milli < 0) item->flex_shrink_milli = 0;

            html_view_calc_box_edges(ctx,
                                     &child_style,
                                     layout_main > 0 ? layout_main : ctx->body_w,
                                     &item->margin_top,
                                     &item->margin_right,
                                     &item->margin_bottom,
                                     &item->margin_left,
                                     &item->pad_top,
                                     &item->pad_right,
                                     &item->pad_bottom,
                                     &item->pad_left,
                                     &item->border_top,
                                     &item->border_right,
                                     &item->border_bottom,
                                     &item->border_left);

            bool has_basis = child_style.has_flex_basis && child_style.flex_basis.valid && !child_style.flex_basis.is_auto;
            int basis_px = 0;
            if (has_basis)
            {
                basis_px = html_view_length_to_px(&child_style.flex_basis,
                                                  ctx->viewport_w,
                                                  ctx->viewport_h,
                                                  layout_main,
                                                  ctx->viewport_h,
                                                  ctx->base_font_px,
                                                  row);
                if (basis_px < 0) basis_px = 0;
            }

            bool main_explicit_item = false;
            bool cross_explicit_item = false;
            int content_w = 0;
            int content_h = 0;
            int measured_w = 0;
            int measured_h = 0;
            bool need_measure = false;

            if (row)
            {
                if (has_basis)
                {
                    content_w = basis_px;
                    main_explicit_item = true;
                }
                else if (child_style.has_width && child_style.width.valid && !child_style.width.is_auto)
                {
                    content_w = html_view_length_to_px(&child_style.width,
                                                       ctx->viewport_w,
                                                       ctx->viewport_h,
                                                       layout_main,
                                                       ctx->viewport_h,
                                                       ctx->base_font_px,
                                                       true);
                    main_explicit_item = true;
                }
                else
                {
                    need_measure = true;
                }

                if (child_style.has_height && child_style.height.valid && !child_style.height.is_auto)
                {
                    content_h = html_view_length_to_px(&child_style.height,
                                                       ctx->viewport_w,
                                                       ctx->viewport_h,
                                                       ctx->viewport_w,
                                                       ctx->viewport_h,
                                                       ctx->base_font_px,
                                                       false);
                    cross_explicit_item = true;
                }
                else
                {
                    need_measure = true;
                }
            }
            else
            {
                if (has_basis)
                {
                    content_h = basis_px;
                    main_explicit_item = true;
                }
                else if (child_style.has_height && child_style.height.valid && !child_style.height.is_auto)
                {
                    content_h = html_view_length_to_px(&child_style.height,
                                                       ctx->viewport_w,
                                                       ctx->viewport_h,
                                                       ctx->viewport_w,
                                                       ctx->viewport_h,
                                                       ctx->base_font_px,
                                                       false);
                    main_explicit_item = true;
                }
                else
                {
                    need_measure = true;
                }

                if (child_style.has_width && child_style.width.valid && !child_style.width.is_auto)
                {
                    content_w = html_view_length_to_px(&child_style.width,
                                                       ctx->viewport_w,
                                                       ctx->viewport_h,
                                                       layout_main > 0 ? layout_main : ctx->body_w,
                                                       ctx->viewport_h,
                                                       ctx->base_font_px,
                                                       true);
                    cross_explicit_item = true;
                }
                else
                {
                    need_measure = true;
                }
            }

            if (need_measure)
            {
                int max_w = layout_main > 0 ? layout_main : ctx->body_w;
                html_view_measure_node_size(ctx, child, style, max_w, &measured_w, &measured_h);
            }

            if (row)
            {
                if (!main_explicit_item)
                {
                    content_w = measured_w;
                }
                if (!cross_explicit_item)
                {
                    content_h = measured_h;
                }
            }
            else
            {
                if (!main_explicit_item)
                {
                    content_h = measured_h;
                }
                if (!cross_explicit_item)
                {
                    content_w = measured_w;
                }
            }

            if (content_w < 0) content_w = 0;
            if (content_h < 0) content_h = 0;

            item->content_w = content_w;
            item->content_h = content_h;
            item->cross_explicit = cross_explicit_item;
            html_view_flex_update_sizes(item, row);
        }

        if (item_count > 0)
        {
            lines = (html_view_flex_line_t *)calloc(item_count, sizeof(*lines));
        }
    }

    if (item_count > 0 && lines)
    {
        int line_main = 0;
        int line_cross = 0;
        int grow_sum = 0;
        int64_t shrink_weight_sum = 0;
        size_t line_start = 0;
        size_t line_items = 0;

        for (size_t i = 0; i < item_count; ++i)
        {
            html_view_flex_item_t *item = &items[i];
            int item_main = item->main_outer;
            int gap = (line_items > 0) ? gap_main : 0;
            bool do_wrap = wrap && layout_main > 0 && line_items > 0 && (line_main + gap + item_main > layout_main);
            if (do_wrap)
            {
                lines[line_count++] = (html_view_flex_line_t){
                    .start = line_start,
                    .count = line_items,
                    .main_size = line_main,
                    .cross_size = line_cross,
                    .gap_total = gap_main * (line_items > 0 ? (int)(line_items - 1) : 0),
                    .grow_sum = grow_sum,
                    .shrink_weight_sum = shrink_weight_sum
                };
                line_start = i;
                line_items = 0;
                line_main = 0;
                line_cross = 0;
                grow_sum = 0;
                shrink_weight_sum = 0;
                gap = 0;
            }

            line_main += gap + item_main;
            if (item->cross_outer > line_cross)
            {
                line_cross = item->cross_outer;
            }
            grow_sum += item->flex_grow_milli;
            if (item->flex_shrink_milli > 0)
            {
                int base = item->main_border > 0 ? item->main_border : 1;
                shrink_weight_sum += (int64_t)item->flex_shrink_milli * (int64_t)base;
            }
            line_items++;
        }

        if (line_items > 0)
        {
            lines[line_count++] = (html_view_flex_line_t){
                .start = line_start,
                .count = line_items,
                .main_size = line_main,
                .cross_size = line_cross,
                .gap_total = gap_main * (line_items > 0 ? (int)(line_items - 1) : 0),
                .grow_sum = grow_sum,
                .shrink_weight_sum = shrink_weight_sum
            };
        }
    }

    if (item_count == 0 || !lines || line_count == 0)
    {
        free(lines);
        free(items);

        int content_w = row ? content_main : content_cross;
        int content_h = row ? content_cross : content_main;
        if (!row && !main_explicit)
        {
            content_h = 0;
        }
        if (!row && !cross_explicit)
        {
            content_w = 0;
        }
        if (row && !main_explicit)
        {
            content_w = layout_main;
        }
        int border_box_w = content_w + pad_left + pad_right + border_left + border_right;
        int border_box_h = content_h + pad_top + pad_bottom + border_top + border_bottom;
        if (border_box_w < 0) border_box_w = 0;
        if (border_box_h < 0) border_box_h = 0;
        int outer_w = border_box_w + margin_left + margin_right;

        if (!inline_container && ctx->x != ctx->body_x)
        {
            html_view_new_line(ctx);
        }

        int outer_x = inline_container ? ctx->x : ctx->body_x;
        if (inline_container)
        {
            if (ctx->pending_space && ctx->x != ctx->body_x)
            {
                if (ctx->x + ctx->space_w + outer_w > ctx->max_x)
                {
                    html_view_new_line(ctx);
                }
                else
                {
                    ctx->x += ctx->space_w;
                }
            }
            else if (ctx->x != ctx->body_x && ctx->x + outer_w > ctx->max_x)
            {
                html_view_new_line(ctx);
            }
            outer_x = ctx->x;
        }

        int border_box_x = outer_x + margin_left;
        int border_box_y = ctx->y + margin_top;
        int draw_y = html_view_draw_y(ctx, border_box_y);
        int right_edge = outer_x + outer_w;
        if (right_edge > ctx->measure_max_x)
        {
            ctx->measure_max_x = right_edge;
        }

        if (style->has_background && !style->background_transparent)
        {
            html_view_draw_rect_clipped(ctx, border_box_x, draw_y, border_box_w, border_box_h, style->background, &ctx->clip);
        }
        if (style->has_border && (border_top > 0 || border_right > 0 || border_bottom > 0 || border_left > 0))
        {
            html_view_draw_border_sides_clipped(ctx,
                                                border_box_x,
                                                draw_y,
                                                border_box_w,
                                                border_box_h,
                                                border_top,
                                                border_right,
                                                border_bottom,
                                                border_left,
                                                style,
                                                &ctx->clip);
        }

        int bottom = border_box_y + border_box_h + margin_bottom;
        if (bottom > ctx->content_bottom)
        {
            ctx->content_bottom = bottom;
        }

        if (inline_container)
        {
            ctx->x = outer_x + outer_w;
            if (ctx->x > ctx->measure_max_x)
            {
                ctx->measure_max_x = ctx->x;
            }
            ctx->pending_space = true;
            html_view_ensure_line_visible(ctx);
        }
        else
        {
            ctx->y = border_box_y + border_box_h + margin_bottom;
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
        }
        return;
    }

    css_align_t align_items = style->has_align_items ? style->align_items : CSS_ALIGN_STRETCH;
    css_justify_content_t justify = style->has_justify_content ? style->justify_content : CSS_JUSTIFY_FLEX_START;

    int max_line_main = 0;
    for (size_t li = 0; li < line_count; ++li)
    {
        if (lines[li].main_size > max_line_main)
        {
            max_line_main = lines[li].main_size;
        }
    }

    int flex_main = content_main;
    if (!main_explicit)
    {
        if (row)
        {
            flex_main = inline_container ? max_line_main : layout_main;
        }
        else
        {
            flex_main = max_line_main;
        }
    }

    for (size_t li = 0; li < line_count; ++li)
    {
        html_view_flex_line_t *line = &lines[li];
        int target_main = flex_main;
        if (!main_explicit && (inline_container || !row))
        {
            target_main = line->main_size;
        }
        int free_main = target_main - line->main_size;

        if (free_main > 0 && line->grow_sum > 0)
        {
            int remaining = free_main;
            for (size_t i = 0; i < line->count; ++i)
            {
                html_view_flex_item_t *item = &items[line->start + i];
                if (item->flex_grow_milli <= 0)
                {
                    continue;
                }
                int delta = (int)(((int64_t)free_main * (int64_t)item->flex_grow_milli) / (int64_t)line->grow_sum);
                if (delta < 0) delta = 0;
                if (row)
                {
                    item->content_w += delta;
                }
                else
                {
                    item->content_h += delta;
                }
                remaining -= delta;
            }

            for (size_t i = 0; i < line->count && remaining > 0; ++i)
            {
                html_view_flex_item_t *item = &items[line->start + i];
                if (item->flex_grow_milli <= 0)
                {
                    continue;
                }
                if (row)
                {
                    item->content_w += 1;
                }
                else
                {
                    item->content_h += 1;
                }
                remaining--;
            }
        }
        else if (free_main < 0 && line->shrink_weight_sum > 0)
        {
            int deficit = -free_main;
            int remaining = deficit;
            for (size_t i = 0; i < line->count; ++i)
            {
                html_view_flex_item_t *item = &items[line->start + i];
                if (item->flex_shrink_milli <= 0)
                {
                    continue;
                }
                int base = item->main_border > 0 ? item->main_border : 1;
                int64_t weight = (int64_t)item->flex_shrink_milli * (int64_t)base;
                int delta = (int)(((int64_t)deficit * weight) / line->shrink_weight_sum);
                if (delta < 0) delta = 0;
                if (row)
                {
                    if (delta > item->content_w) delta = item->content_w;
                    item->content_w -= delta;
                }
                else
                {
                    if (delta > item->content_h) delta = item->content_h;
                    item->content_h -= delta;
                }
                remaining -= delta;
            }

            for (size_t i = 0; i < line->count && remaining > 0; ++i)
            {
                html_view_flex_item_t *item = &items[line->start + i];
                if (item->flex_shrink_milli <= 0)
                {
                    continue;
                }
                if (row)
                {
                    if (item->content_w <= 0)
                    {
                        continue;
                    }
                    item->content_w -= 1;
                }
                else
                {
                    if (item->content_h <= 0)
                    {
                        continue;
                    }
                    item->content_h -= 1;
                }
                remaining--;
            }
        }

        line->main_size = 0;
        line->cross_size = 0;
        line->grow_sum = 0;
        line->shrink_weight_sum = 0;
        for (size_t i = 0; i < line->count; ++i)
        {
            html_view_flex_item_t *item = &items[line->start + i];
            html_view_flex_update_sizes(item, row);
            int gap = (i > 0) ? gap_main : 0;
            line->main_size += gap + item->main_outer;
            if (item->cross_outer > line->cross_size)
            {
                line->cross_size = item->cross_outer;
            }
            line->grow_sum += item->flex_grow_milli;
            if (item->flex_shrink_milli > 0)
            {
                int base = item->main_border > 0 ? item->main_border : 1;
                line->shrink_weight_sum += (int64_t)item->flex_shrink_milli * (int64_t)base;
            }
        }

        for (size_t i = 0; i < line->count; ++i)
        {
            html_view_flex_item_t *item = &items[line->start + i];
            css_align_t align = item->style.has_align_self ? item->style.align_self : align_items;
            if (align == CSS_ALIGN_BASELINE)
            {
                align = CSS_ALIGN_FLEX_START;
            }
            if (align == CSS_ALIGN_STRETCH && !item->cross_explicit)
            {
                if (row)
                {
                    int available = line->cross_size - item->margin_top - item->margin_bottom -
                                    item->border_top - item->border_bottom - item->pad_top - item->pad_bottom;
                    if (available < 0) available = 0;
                    item->content_h = available;
                }
                else
                {
                    int available = line->cross_size - item->margin_left - item->margin_right -
                                    item->border_left - item->border_right - item->pad_left - item->pad_right;
                    if (available < 0) available = 0;
                    item->content_w = available;
                }
                html_view_flex_update_sizes(item, row);
            }
        }

        line->cross_size = 0;
        for (size_t i = 0; i < line->count; ++i)
        {
            html_view_flex_item_t *item = &items[line->start + i];
            if (item->cross_outer > line->cross_size)
            {
                line->cross_size = item->cross_outer;
            }
        }

        int free_space = target_main - line->main_size;
        if (free_space < 0) free_space = 0;
        int offset = 0;
        int extra_gap = 0;
        if (justify == CSS_JUSTIFY_FLEX_END)
        {
            offset = free_space;
        }
        else if (justify == CSS_JUSTIFY_CENTER)
        {
            offset = free_space / 2;
        }
        else if (justify == CSS_JUSTIFY_SPACE_BETWEEN && line->count > 1)
        {
            extra_gap = free_space / (int)(line->count - 1);
        }
        else if (justify == CSS_JUSTIFY_SPACE_AROUND && line->count > 0)
        {
            extra_gap = free_space / (int)line->count;
            offset = extra_gap / 2;
        }
        else if (justify == CSS_JUSTIFY_SPACE_EVENLY && line->count > 0)
        {
            extra_gap = free_space / (int)(line->count + 1);
            offset = extra_gap;
        }

        int cursor = reverse ? (target_main - offset) : offset;
        for (size_t i = 0; i < line->count; ++i)
        {
            size_t idx = reverse ? (line->start + line->count - 1 - i) : (line->start + i);
            html_view_flex_item_t *item = &items[idx];
            int margin_start = row ? item->margin_left : item->margin_top;
            int margin_end = row ? item->margin_right : item->margin_bottom;
            if (reverse)
            {
                int tmp = margin_start;
                margin_start = margin_end;
                margin_end = tmp;
            }

            if (reverse)
            {
                cursor -= item->main_outer;
                item->pos_main = cursor + margin_start;
                cursor -= gap_main + extra_gap;
            }
            else
            {
                item->pos_main = cursor + margin_start;
                cursor += item->main_outer + gap_main + extra_gap;
            }

            css_align_t align = item->style.has_align_self ? item->style.align_self : align_items;
            if (align == CSS_ALIGN_BASELINE)
            {
                align = CSS_ALIGN_FLEX_START;
            }
            int free_cross = line->cross_size - item->cross_outer;
            if (free_cross < 0) free_cross = 0;
            int cross_offset = 0;
            if (align == CSS_ALIGN_FLEX_END)
            {
                cross_offset = free_cross;
            }
            else if (align == CSS_ALIGN_CENTER)
            {
                cross_offset = free_cross / 2;
            }
            item->pos_cross = cross_offset + (row ? item->margin_top : item->margin_left);
        }
    }

    int total_cross = 0;
    for (size_t li = 0; li < line_count; ++li)
    {
        total_cross += lines[li].cross_size;
    }
    if (line_count > 1)
    {
        total_cross += gap_cross * (int)(line_count - 1);
    }

    if (!cross_explicit)
    {
        content_cross = total_cross;
    }

    int content_w = row ? flex_main : content_cross;
    int content_h = row ? content_cross : flex_main;
    if (content_w < 0) content_w = 0;
    if (content_h < 0) content_h = 0;

    int border_box_w = content_w + pad_left + pad_right + border_left + border_right;
    int border_box_h = content_h + pad_top + pad_bottom + border_top + border_bottom;
    if (border_box_w < 0) border_box_w = 0;
    if (border_box_h < 0) border_box_h = 0;
    int outer_w = border_box_w + margin_left + margin_right;

    if (!inline_container && ctx->x != ctx->body_x)
    {
        html_view_new_line(ctx);
    }

    int outer_x = inline_container ? ctx->x : ctx->body_x;
    if (inline_container)
    {
        if (ctx->pending_space && ctx->x != ctx->body_x)
        {
            if (ctx->x + ctx->space_w + outer_w > ctx->max_x)
            {
                html_view_new_line(ctx);
            }
            else
            {
                ctx->x += ctx->space_w;
            }
        }
        else if (ctx->x != ctx->body_x && ctx->x + outer_w > ctx->max_x)
        {
            html_view_new_line(ctx);
        }
        outer_x = ctx->x;
    }

    int border_box_x = outer_x + margin_left;
    int border_box_y = ctx->y + margin_top;
    int content_x = border_box_x + border_left + pad_left;
    int content_y = border_box_y + border_top + pad_top;
    int right_edge = outer_x + outer_w;
    if (right_edge > ctx->measure_max_x)
    {
        ctx->measure_max_x = right_edge;
    }
    video_color_t container_bg = (style->has_background && !style->background_transparent) ? style->background : ctx->bg;

    if (style->has_background && !style->background_transparent)
    {
        int draw_y = html_view_draw_y(ctx, border_box_y);
        html_view_draw_rect_clipped(ctx, border_box_x, draw_y, border_box_w, border_box_h, style->background, &ctx->clip);
    }
    if (style->has_border && (border_top > 0 || border_right > 0 || border_bottom > 0 || border_left > 0))
    {
        int draw_y = html_view_draw_y(ctx, border_box_y);
        html_view_draw_border_sides_clipped(ctx,
                                            border_box_x,
                                            draw_y,
                                            border_box_w,
                                            border_box_h,
                                            border_top,
                                            border_right,
                                            border_bottom,
                                            border_left,
                                            style,
                                            &ctx->clip);
    }

    int cross_cursor = 0;
    for (size_t li = 0; li < line_count; ++li)
    {
        html_view_flex_line_t *line = &lines[li];
        int line_pos = wrap_reverse ? (content_cross - (cross_cursor + line->cross_size)) : cross_cursor;
        cross_cursor += line->cross_size + gap_cross;

        for (size_t i = 0; i < line->count; ++i)
        {
            html_view_flex_item_t *item = &items[line->start + i];
            int border_x = row ? (content_x + item->pos_main) : (content_x + item->pos_cross);
            int border_y = row ? (content_y + line_pos + item->pos_cross) : (content_y + line_pos + item->pos_main);

            if (item->style.has_background && !item->style.background_transparent)
            {
                int draw_y = html_view_draw_y(ctx, border_y);
                html_view_draw_rect_clipped(ctx,
                                            border_x,
                                            draw_y,
                                            item->border_box_w,
                                            item->border_box_h,
                                            item->style.background,
                                            &ctx->clip);
            }
            if (item->style.has_border &&
                (item->border_top > 0 || item->border_right > 0 || item->border_bottom > 0 || item->border_left > 0))
            {
                int draw_y = html_view_draw_y(ctx, border_y);
                html_view_draw_border_sides_clipped(ctx,
                                                    border_x,
                                                    draw_y,
                                                    item->border_box_w,
                                                    item->border_box_h,
                                                    item->border_top,
                                                    item->border_right,
                                                    item->border_bottom,
                                                    item->border_left,
                                                    &item->style,
                                                    &ctx->clip);
            }

            html_view_ctx_t inner = *ctx;
            inner.underline_run_active = false;
            inner.underline_run_start_x = 0;
            inner.body_x = border_x + item->border_left + item->pad_left;
            inner.body_w = item->content_w;
            if (inner.body_w < 0) inner.body_w = 0;
            inner.max_x = inner.body_x + inner.body_w;
            inner.x = inner.body_x;
            inner.y = border_y + item->border_top + item->pad_top;
            inner.pending_space = false;
            inner.list_level = 0;
            inner.floats = NULL;
            inner.style_block = NULL;
            inner.style_depth = 0;
            inner.line_height = html_view_line_height_for_style(&inner, &item->style);
            inner.space_w = html_view_text_width(&inner, " ");
            inner.bg = (item->style.has_background && !item->style.background_transparent) ? item->style.background : container_bg;
            inner.line_start_x = inner.x;
            inner.line_start_y = inner.y;
            inner.line_op_start = (inner.record && inner.priv) ? inner.priv->render_cache.op_count : 0;

            html_view_render_node_internal(&inner, item->node, style);
            html_view_style_stack_destroy(&inner);
            if (inner.record_failed)
            {
                ctx->record_failed = true;
            }
        }
    }

    free(lines);
    free(items);

    int bottom = border_box_y + border_box_h + margin_bottom;
    if (bottom > ctx->content_bottom)
    {
        ctx->content_bottom = bottom;
    }

    if (inline_container)
    {
        ctx->x = outer_x + outer_w;
        if (ctx->x > ctx->measure_max_x)
        {
            ctx->measure_max_x = ctx->x;
        }
        ctx->pending_space = true;
        html_view_ensure_line_visible(ctx);
    }
    else
    {
        ctx->y = border_box_y + border_box_h + margin_bottom;
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
    }
}
