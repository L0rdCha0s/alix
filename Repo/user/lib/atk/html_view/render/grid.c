#include "atk/html_view/render/render_internal.h"

#include "web/css/css_internal.h"
#include <ctype.h>

typedef struct
{
    const html_node_t *node;
    css_style_t style;
    int span;
    int start_line;
    int end_line;
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
    int pos_x;
    int pos_y;
} html_view_grid_item_t;

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
            *margin_top = html_view_length_to_px_signed(&style->margin.top, vw, vh, ref_w, vh, font_px, true);
        }
        if (margin_right && style->margin.right.valid && !style->margin.right.is_auto)
        {
            *margin_right = html_view_length_to_px_signed(&style->margin.right, vw, vh, ref_w, vh, font_px, true);
        }
        if (margin_bottom && style->margin.bottom.valid && !style->margin.bottom.is_auto)
        {
            *margin_bottom = html_view_length_to_px_signed(&style->margin.bottom, vw, vh, ref_w, vh, font_px, true);
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
            *pad_top = html_view_length_to_px(&style->padding.top, vw, vh, ref_w, vh, font_px, true);
        }
        if (pad_right)
        {
            *pad_right = html_view_length_to_px(&style->padding.right, vw, vh, ref_w, vh, font_px, true);
        }
        if (pad_bottom)
        {
            *pad_bottom = html_view_length_to_px(&style->padding.bottom, vw, vh, ref_w, vh, font_px, true);
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
    html_view_margin_state_reset(&measure.pending_margin);
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

static void html_view_grid_update_sizes(html_view_grid_item_t *item)
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
}

void html_view_render_grid_container(html_view_ctx_t *ctx,
                                     const html_node_t *node,
                                     const css_style_t *style,
                                     bool inline_container)
{
    if (!ctx || !node || !style)
    {
        return;
    }

    int cols = style->has_grid_template_columns ? style->grid_template_columns : 1;
    if (cols < 1) cols = 1;

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

    int content_w = 0;
    if (style->has_width && style->width.valid && !style->width.is_auto)
    {
        content_w = html_view_length_to_px(&style->width,
                                           ctx->viewport_w,
                                           ctx->viewport_h,
                                           ctx->body_w,
                                           ctx->viewport_h,
                                           ctx->base_font_px,
                                           true);
        content_w = html_view_box_sizing_content_width(style,
                                                       content_w,
                                                       pad_left,
                                                       pad_right,
                                                       border_left,
                                                       border_right);
    }
    else
    {
        content_w = ctx->body_w - margin_left - margin_right - pad_left - pad_right - border_left - border_right;
    }
    if (content_w < 0) content_w = 0;

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

    bool height_explicit = style->has_height && style->height.valid && !style->height.is_auto;
    int content_h = 0;
    if (height_explicit)
    {
        content_h = html_view_length_to_px(&style->height,
                                           ctx->viewport_w,
                                           ctx->viewport_h,
                                           ctx->viewport_w,
                                           ctx->viewport_h,
                                           ctx->base_font_px,
                                           false);
        content_h = html_view_box_sizing_content_height(style,
                                                        content_h,
                                                        pad_top,
                                                        pad_bottom,
                                                        border_top,
                                                        border_bottom);
        if (content_h < 0) content_h = 0;
    }

    int gap_x = 0;
    int gap_y = 0;
    if (style->has_column_gap)
    {
        gap_x = html_view_length_to_px(&style->column_gap,
                                       ctx->viewport_w,
                                       ctx->viewport_h,
                                       content_w,
                                       ctx->viewport_h,
                                       ctx->base_font_px,
                                       true);
    }
    if (style->has_row_gap)
    {
        gap_y = html_view_length_to_px(&style->row_gap,
                                       ctx->viewport_w,
                                       ctx->viewport_h,
                                       ctx->viewport_w,
                                       ctx->viewport_h,
                                       ctx->base_font_px,
                                       false);
    }
    if (gap_x < 0) gap_x = 0;
    if (gap_y < 0) gap_y = 0;

    int cell_w = content_w;
    if (cols > 1)
    {
        int total_gap = gap_x * (cols - 1);
        cell_w = (content_w - total_gap) / cols;
    }
    if (cell_w < 0) cell_w = 0;

    size_t child_cap = 0;
    for (const html_node_t *child = node->first_child; child; child = child->next_sibling)
    {
        if (child->type == HTML_NODE_ELEMENT || child->type == HTML_NODE_TEXT)
        {
            child_cap++;
        }
    }

    html_view_grid_item_t *items = NULL;
    size_t item_count = 0;
    if (child_cap > 0)
    {
        items = (html_view_grid_item_t *)calloc(child_cap, sizeof(*items));
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

            css_style_t child_style = {0};
            html_view_style_for_node(&child_style, ctx->sheet, style, child, ctx->priv);
            if (child_style.has_display && child_style.display == CSS_DISPLAY_NONE)
            {
                css_style_release(&child_style);
                continue;
            }

            html_view_grid_item_t *item = &items[item_count++];
            item->node = child;
            item->style = child_style;
            item->start_line = child_style.has_grid_column_start ? child_style.grid_column_start : 0;
            item->end_line = child_style.has_grid_column_end ? child_style.grid_column_end : 0;
            item->span = child_style.has_grid_column_span ? child_style.grid_column_span : 1;
            if (item->span < 1) item->span = 1;
            if (item->start_line > 0 && item->end_line > 0)
            {
                int diff = item->end_line - item->start_line;
                if (diff > 0)
                {
                    item->span = diff;
                }
            }
            if (item->start_line > cols && cols > 0)
            {
                item->start_line = cols;
            }
            if (item->end_line > cols + 1 && cols > 0)
            {
                item->end_line = cols + 1;
            }
            if (item->start_line > 0 && item->span > cols - (item->start_line - 1))
            {
                item->span = cols - (item->start_line - 1);
            }
            if (item->start_line <= 0 && item->end_line > 0 && item->span > item->end_line - 1)
            {
                item->span = item->end_line - 1;
            }
            if (item->span < 1) item->span = 1;
            if (item->span > cols) item->span = cols;

            int span_w = cell_w * item->span + gap_x * (item->span - 1);
            if (span_w < 0) span_w = 0;

            html_view_calc_box_edges(ctx,
                                     &child_style,
                                     span_w,
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

            bool explicit_w = child_style.has_width && child_style.width.valid && !child_style.width.is_auto;
            bool explicit_h = child_style.has_height && child_style.height.valid && !child_style.height.is_auto;
            int content_item_w = 0;
            int content_item_h = 0;
            int measured_w = 0;
            int measured_h = 0;

            int max_w = span_w - item->margin_left - item->margin_right - item->pad_left - item->pad_right - item->border_left - item->border_right;
            if (max_w < 0) max_w = 0;

            if (!explicit_w || !explicit_h)
            {
                html_view_measure_node_size(ctx, child, style, max_w, &measured_w, &measured_h);
            }

            if (explicit_w)
            {
                content_item_w = html_view_length_to_px(&child_style.width,
                                                        ctx->viewport_w,
                                                        ctx->viewport_h,
                                                        span_w,
                                                        ctx->viewport_h,
                                                        ctx->base_font_px,
                                                        true);
                content_item_w = html_view_box_sizing_content_width(&child_style,
                                                                    content_item_w,
                                                                    item->pad_left,
                                                                    item->pad_right,
                                                                    item->border_left,
                                                                    item->border_right);
            }
            else
            {
                content_item_w = measured_w;
            }

            if (explicit_h)
            {
                content_item_h = html_view_length_to_px(&child_style.height,
                                                        ctx->viewport_w,
                                                        ctx->viewport_h,
                                                        ctx->viewport_w,
                                                        ctx->viewport_h,
                                                        ctx->base_font_px,
                                                        false);
                content_item_h = html_view_box_sizing_content_height(&child_style,
                                                                     content_item_h,
                                                                     item->pad_top,
                                                                     item->pad_bottom,
                                                                     item->border_top,
                                                                     item->border_bottom);
            }
            else
            {
                content_item_h = measured_h;
            }

            if (content_item_w < 0) content_item_w = 0;
            if (content_item_h < 0) content_item_h = 0;
            item->content_w = content_item_w;
            item->content_h = content_item_h;
            html_view_grid_update_sizes(item);
        }
    }

    int col = 0;
    int row_y = 0;
    int row_height = 0;
    for (size_t i = 0; i < item_count; ++i)
    {
        html_view_grid_item_t *item = &items[i];
        int span = item->span;
        int start_line = item->start_line;
        int end_line = item->end_line;
        int start_col = -1;

        if (start_line <= 0 && end_line > 0)
        {
            start_line = end_line - span;
        }
        if (start_line > 0)
        {
            if (start_line < 1) start_line = 1;
            if (start_line > cols) start_line = cols;
            start_col = start_line - 1;
        }
        if (start_col >= 0 && start_col + span > cols)
        {
            span = cols - start_col;
            if (span < 1) span = 1;
        }

        if (start_col >= 0)
        {
            if (start_col < col)
            {
                row_y += row_height + gap_y;
                row_height = 0;
                col = 0;
            }
            col = start_col;
        }
        else if (col + span > cols)
        {
            row_y += row_height + gap_y;
            row_height = 0;
            col = 0;
        }

        item->pos_x = col * (cell_w + gap_x) + item->margin_left;
        item->pos_y = row_y + item->margin_top;
        if (item->outer_h > row_height)
        {
            row_height = item->outer_h;
        }
        col += span;
        if (col >= cols)
        {
            row_y += row_height + gap_y;
            row_height = 0;
            col = 0;
        }
    }

    int layout_h = 0;
    if (item_count > 0)
    {
        layout_h = row_y;
        if (row_height > 0)
        {
            layout_h += row_height;
        }
        if (layout_h < 0) layout_h = 0;
    }
    if (!height_explicit)
    {
        content_h = layout_h;
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

    for (size_t i = 0; i < item_count; ++i)
    {
        html_view_grid_item_t *item = &items[i];
        int border_x = content_x + item->pos_x;
        int border_y = content_y + item->pos_y;

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
        html_view_margin_state_reset(&inner.pending_margin);
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

    for (size_t i = 0; i < item_count; ++i)
    {
        css_style_release(&items[i].style);
    }
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
