#include "atk/html_view/render/render_internal.h"

#include "web/css/css_internal.h"
#include "ctype.h"
#include "serial.h"
#include "string.h"

static bool html_view_intersect_rect_local(const atk_rect_t *a, const atk_rect_t *b, atk_rect_t *out)
{
    if (!a || !b || !out)
    {
        return false;
    }
    int x0 = a->x > b->x ? a->x : b->x;
    int y0 = a->y > b->y ? a->y : b->y;
    int x1 = (a->x + a->width) < (b->x + b->width) ? (a->x + a->width) : (b->x + b->width);
    int y1 = (a->y + a->height) < (b->y + b->height) ? (a->y + a->height) : (b->y + b->height);
    int w = x1 - x0;
    int h = y1 - y0;
    if (w <= 0 || h <= 0)
    {
        return false;
    }
    out->x = x0;
    out->y = y0;
    out->width = w;
    out->height = h;
    return true;
}

static const char *html_view_dump_clear_mode(css_clear_t value)
{
    switch (value)
    {
        case CSS_CLEAR_LEFT: return "left";
        case CSS_CLEAR_RIGHT: return "right";
        case CSS_CLEAR_BOTH: return "both";
        case CSS_CLEAR_NONE: default: return "none";
    }
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

static const char *html_view_debug_block_label(const html_node_t *node)
{
    if (!node || node->type != HTML_NODE_ELEMENT)
    {
        return NULL;
    }
    if (node->name && strcmp(node->name, "h2") == 0)
    {
        const char *id = html_attr_get(node, "id");
        if (id && strcmp(id, "top") == 0)
        {
            return "h2#top";
        }
    }
    if (node->name && strcmp(node->name, "ul") == 0)
    {
        return "ul";
    }
    if (html_view_attr_has_class(node, "picture"))
    {
        return "picture";
    }
    if (html_view_attr_has_class(node, "forehead"))
    {
        return "forehead";
    }
    if (html_view_attr_has_class(node, "eyes"))
    {
        return "eyes";
    }
    if (html_view_attr_has_class(node, "nose"))
    {
        return "nose";
    }
    if (html_view_attr_has_class(node, "empty"))
    {
        return "empty";
    }
    if (html_view_attr_has_class(node, "smile"))
    {
        return "smile";
    }
    if (html_view_attr_has_class(node, "chin"))
    {
        return "chin";
    }
    if (html_view_attr_has_class(node, "parser"))
    {
        return "parser";
    }
    if (html_view_attr_has_class(node, "image-height-test"))
    {
        return "image-height-test";
    }
    if (node->name && strcmp(node->name, "div") == 0)
    {
        const html_node_t *parent = node->parent;
        if (parent && html_view_attr_has_class(parent, "smile"))
        {
            return "smile-box";
        }
        if (parent && parent->parent && html_view_attr_has_class(parent->parent, "smile"))
        {
            return "smile-abs";
        }
    }
    return NULL;
}

static int html_view_apply_block_margin_top(html_view_ctx_t *ctx,
                                            int margin_top,
                                            css_clear_t clear_mode,
                                            bool *out_clearance,
                                            html_view_margin_state_t *out_prev_pending)
{
    if (!ctx)
    {
        if (out_clearance)
        {
            *out_clearance = false;
        }
        if (out_prev_pending)
        {
            html_view_margin_state_reset(out_prev_pending);
        }
        return 0;
    }

    int start_y = ctx->y;
    html_view_margin_state_t prev_pending = ctx->pending_margin;
    bool prev_pending_valid = prev_pending.valid;
    html_view_margin_state_reset(&ctx->pending_margin);

    html_view_margin_state_t collapsed_state = html_view_margin_state_from_value(margin_top);
    if (prev_pending_valid)
    {
        html_view_margin_state_merge(&collapsed_state, &prev_pending);
    }
    int collapsed = html_view_margin_state_value(&collapsed_state);

    int used_top = collapsed;
    int clear_y = 0;
    bool clearance_applied = false;
    if (clear_mode != CSS_CLEAR_NONE)
    {
        int top_border_y = start_y + used_top;
        clear_y = html_view_float_max_bottom(ctx->floats, clear_mode);
        if (clear_y > top_border_y)
        {
            clearance_applied = true;
            used_top = clear_y - start_y;
        }
    }

    ctx->y = start_y + used_top;

    if (clear_mode != CSS_CLEAR_NONE)
    {
        int prev_pending_value = html_view_margin_state_value(&prev_pending);
        serial_printf("[html_view][layout] clear=%s start_y=%d prev_pending=%d prev_valid=%d margin_top=%d collapsed=%d clear_y=%d used_top=%d y=%d",
                      html_view_dump_clear_mode(clear_mode),
                      start_y,
                      prev_pending_value,
                      prev_pending_valid ? 1 : 0,
                      margin_top,
                      collapsed,
                      clear_y,
                      used_top,
                      ctx->y);
    }

    if (out_clearance)
    {
        *out_clearance = clearance_applied;
    }
    if (out_prev_pending)
    {
        if (!prev_pending_valid || clearance_applied)
        {
            html_view_margin_state_reset(&prev_pending);
        }
        *out_prev_pending = prev_pending;
    }

    return used_top;
}

static void html_view_measure_block_children(const html_view_ctx_t *ctx,
                                             const html_node_t *node,
                                             const css_style_t *style,
                                             int content_w,
                                             int *out_w,
                                             int *out_h)
{
    if (!ctx || !node || !style)
    {
        if (out_w)
        {
            *out_w = 0;
        }
        if (out_h)
        {
            *out_h = 0;
        }
        return;
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
    html_view_margin_state_reset(&measure.pending_margin);
    measure.underline_run_active = false;
    measure.underline_run_start_x = 0;
    measure.list_level = 0;
    measure.measure_max_x = measure.x;
    measure.space_w = html_view_text_width(&measure, " ");
    measure.line_height = html_view_line_height_for_style(&measure, style);
    if (html_view_subtree_has_form_control(node) && measure.line_height < atk_font_line_height() + 8)
    {
        measure.line_height = atk_font_line_height() + 8;
    }

    int height_basis = 0;
    bool height_basis_valid = html_view_length_to_px_height(ctx, &style->height, &height_basis);
    if (height_basis_valid && height_basis < 0)
    {
        height_basis = 0;
    }
    int min_h = -1;
    if (html_view_length_to_px_height(ctx, &style->min_height, &min_h))
    {
        if (min_h < 0)
        {
            min_h = 0;
        }
    }
    else
    {
        min_h = -1;
    }
    int max_h = -1;
    if (html_view_length_to_px_height(ctx, &style->max_height, &max_h))
    {
        if (max_h < 0)
        {
            max_h = 0;
        }
    }
    else
    {
        max_h = -1;
    }
    if (height_basis_valid)
    {
        if (max_h >= 0 && height_basis > max_h)
        {
            height_basis = max_h;
        }
        if (min_h >= 0 && height_basis < min_h)
        {
            height_basis = min_h;
        }
        if (max_h >= 0 && min_h > max_h)
        {
            height_basis = min_h;
        }
    }
    measure.height_basis_valid = height_basis_valid;
    measure.height_basis = height_basis_valid ? height_basis : 0;
    measure.height_basis_explicit = height_basis_valid;

    html_view_render_children(&measure, node, style);
    if (measure.x != measure.body_x)
    {
        html_view_new_line(&measure);
    }
    html_view_style_stack_destroy(&measure);

    int used_w = measure.measure_max_x - measure.body_x;
    if (used_w < 0)
    {
        used_w = 0;
    }
    int used_h = measure.content_bottom;
    if (used_h < 0)
    {
        used_h = 0;
    }
    if (out_w)
    {
        *out_w = used_w;
    }
    if (out_h)
    {
        *out_h = used_h;
    }
}

static void html_view_measure_css_table_cells(const html_view_ctx_t *ctx,
                                              const html_node_t *node,
                                              const css_style_t *style,
                                              int ref_w,
                                              int ref_h,
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

    int total_w = 0;
    int max_h = 0;
    for (const html_node_t *child = node->first_child; child; child = child->next_sibling)
    {
        if (child->type != HTML_NODE_ELEMENT)
        {
            continue;
        }

        css_style_t child_style = {0};
        html_view_style_for_node(&child_style, ctx->sheet, style, child);
        if (child_style.has_display && child_style.display == CSS_DISPLAY_NONE)
        {
            css_style_release(&child_style);
            continue;
        }

        int cell_w = 0;
        if (child_style.has_width && child_style.width.valid && !child_style.width.is_auto)
        {
            cell_w = html_view_length_to_px(&child_style.width,
                                            ctx->viewport_w,
                                            ctx->viewport_h,
                                            ref_w,
                                            ref_h,
                                            ctx->base_font_px,
                                            true);
        }

        int cell_h = 0;
        if (child_style.has_height && child_style.height.valid && !child_style.height.is_auto)
        {
            cell_h = html_view_length_to_px(&child_style.height,
                                            ctx->viewport_w,
                                            ctx->viewport_h,
                                            ref_w,
                                            ref_h,
                                            ctx->base_font_px,
                                            false);
        }

        int pad_left = 0;
        int pad_right = 0;
        int pad_top = 0;
        int pad_bottom = 0;
        if (child_style.has_padding)
        {
            pad_left = html_view_length_to_px(&child_style.padding.left,
                                              ctx->viewport_w,
                                              ctx->viewport_h,
                                              ref_w,
                                              ref_h,
                                              ctx->base_font_px,
                                              true);
            pad_right = html_view_length_to_px(&child_style.padding.right,
                                               ctx->viewport_w,
                                               ctx->viewport_h,
                                               ref_w,
                                               ref_h,
                                               ctx->base_font_px,
                                               true);
            pad_top = html_view_length_to_px(&child_style.padding.top,
                                             ctx->viewport_w,
                                             ctx->viewport_h,
                                             ref_w,
                                             ref_h,
                                             ctx->base_font_px,
                                             true);
            pad_bottom = html_view_length_to_px(&child_style.padding.bottom,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                ref_w,
                                                ref_h,
                                                ctx->base_font_px,
                                                true);
        }

        int border_left = 0;
        int border_right = 0;
        int border_top = 0;
        int border_bottom = 0;
        if (child_style.has_border)
        {
            border_left = html_view_length_to_px(&child_style.border_width.left,
                                                 ctx->viewport_w,
                                                 ctx->viewport_h,
                                                 ref_w,
                                                 ref_h,
                                                 ctx->base_font_px,
                                                 true);
            border_right = html_view_length_to_px(&child_style.border_width.right,
                                                  ctx->viewport_w,
                                                  ctx->viewport_h,
                                                  ref_w,
                                                  ref_h,
                                                  ctx->base_font_px,
                                                  true);
            border_top = html_view_length_to_px(&child_style.border_width.top,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                ref_w,
                                                ref_h,
                                                ctx->base_font_px,
                                                false);
            border_bottom = html_view_length_to_px(&child_style.border_width.bottom,
                                                   ctx->viewport_w,
                                                   ctx->viewport_h,
                                                   ref_w,
                                                   ref_h,
                                                   ctx->base_font_px,
                                                   false);
            html_view_apply_border_style_none(&child_style, &border_top, &border_right, &border_bottom, &border_left);
        }

        if (cell_w < 0) cell_w = 0;
        if (cell_h < 0) cell_h = 0;
        if (pad_left < 0) pad_left = 0;
        if (pad_right < 0) pad_right = 0;
        if (pad_top < 0) pad_top = 0;
        if (pad_bottom < 0) pad_bottom = 0;
        if (border_left < 0) border_left = 0;
        if (border_right < 0) border_right = 0;
        if (border_top < 0) border_top = 0;
        if (border_bottom < 0) border_bottom = 0;

        cell_w += pad_left + pad_right + border_left + border_right;
        cell_h += pad_top + pad_bottom + border_top + border_bottom;

        total_w += cell_w;
        if (cell_h > max_h)
        {
            max_h = cell_h;
        }
        css_style_release(&child_style);
    }

    if (out_w)
    {
        *out_w = total_w;
    }
    if (out_h)
    {
        *out_h = max_h;
    }
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

bool html_view_render_positioned_element(html_view_ctx_t *ctx,
                                         const html_node_t *node,
                                         const css_style_t *style,
                                         const css_style_t *parent_style)
{
    (void)parent_style;
    if (!ctx || !node || !style || node->type != HTML_NODE_ELEMENT)
    {
        return false;
    }

    css_position_t pos = style->has_position ? style->position : CSS_POSITION_STATIC;
    if (pos != CSS_POSITION_ABSOLUTE && pos != CSS_POSITION_FIXED)
    {
        return false;
    }

    bool fixed = (pos == CSS_POSITION_FIXED);
    int cont_x = fixed ? ctx->viewport_x : ctx->pos_x;
    int cont_y = fixed ? ctx->viewport_y : ctx->pos_y;
    int cont_w = fixed ? ctx->viewport_w : ctx->pos_w;
    int cont_h = fixed ? ctx->viewport_h : ctx->pos_h;
    if (cont_w < 0) cont_w = 0;
    if (cont_h < 0) cont_h = 0;

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
                                                       cont_w,
                                                       cont_h,
                                                       ctx->base_font_px,
                                                       true);
        }
        if (style->margin.right.valid && !style->margin.right.is_auto)
        {
            margin_right = html_view_length_to_px_signed(&style->margin.right,
                                                         ctx->viewport_w,
                                                         ctx->viewport_h,
                                                         cont_w,
                                                         cont_h,
                                                         ctx->base_font_px,
                                                         true);
        }
        if (style->margin.bottom.valid && !style->margin.bottom.is_auto)
        {
            margin_bottom = html_view_length_to_px_signed(&style->margin.bottom,
                                                          ctx->viewport_w,
                                                          ctx->viewport_h,
                                                          cont_w,
                                                          cont_h,
                                                          ctx->base_font_px,
                                                          true);
        }
        if (style->margin.left.valid && !style->margin.left.is_auto)
        {
            margin_left = html_view_length_to_px_signed(&style->margin.left,
                                                        ctx->viewport_w,
                                                        ctx->viewport_h,
                                                        cont_w,
                                                        cont_h,
                                                        ctx->base_font_px,
                                                        true);
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
                                         cont_w,
                                         cont_h,
                                         ctx->base_font_px,
                                         true);
        pad_right = html_view_length_to_px(&style->padding.right,
                                           ctx->viewport_w,
                                           ctx->viewport_h,
                                           cont_w,
                                           cont_h,
                                           ctx->base_font_px,
                                           true);
        pad_bottom = html_view_length_to_px(&style->padding.bottom,
                                            ctx->viewport_w,
                                            ctx->viewport_h,
                                            cont_w,
                                            cont_h,
                                            ctx->base_font_px,
                                            true);
        pad_left = html_view_length_to_px(&style->padding.left,
                                          ctx->viewport_w,
                                          ctx->viewport_h,
                                          cont_w,
                                          cont_h,
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
                                            cont_w,
                                            cont_h,
                                            ctx->base_font_px,
                                            false);
        border_right = html_view_length_to_px(&style->border_width.right,
                                              ctx->viewport_w,
                                              ctx->viewport_h,
                                              cont_w,
                                              cont_h,
                                              ctx->base_font_px,
                                              true);
        border_bottom = html_view_length_to_px(&style->border_width.bottom,
                                               ctx->viewport_w,
                                               ctx->viewport_h,
                                               cont_w,
                                               cont_h,
                                               ctx->base_font_px,
                                               false);
        border_left = html_view_length_to_px(&style->border_width.left,
                                             ctx->viewport_w,
                                             ctx->viewport_h,
                                             cont_w,
                                             cont_h,
                                             ctx->base_font_px,
                                             true);
    }
    if (border_top < 0) border_top = 0;
    if (border_right < 0) border_right = 0;
    if (border_bottom < 0) border_bottom = 0;
    if (border_left < 0) border_left = 0;
    html_view_apply_border_style_none(style, &border_top, &border_right, &border_bottom, &border_left);

    bool have_left = style->has_left && style->left.valid && !style->left.is_auto;
    bool have_right = style->has_right && style->right.valid && !style->right.is_auto;
    bool have_top = style->has_top && style->top.valid && !style->top.is_auto;
    bool have_bottom = style->has_bottom && style->bottom.valid && !style->bottom.is_auto;
    int left_px = have_left
        ? html_view_length_to_px_signed(&style->left,
                                        ctx->viewport_w,
                                        ctx->viewport_h,
                                        cont_w,
                                        cont_h,
                                        ctx->base_font_px,
                                        true)
        : 0;
    int right_px = have_right
        ? html_view_length_to_px_signed(&style->right,
                                        ctx->viewport_w,
                                        ctx->viewport_h,
                                        cont_w,
                                        cont_h,
                                        ctx->base_font_px,
                                        true)
        : 0;
    int top_px = have_top
        ? html_view_length_to_px_signed(&style->top,
                                        ctx->viewport_w,
                                        ctx->viewport_h,
                                        cont_w,
                                        cont_h,
                                        ctx->base_font_px,
                                        false)
        : 0;
    int bottom_px = have_bottom
        ? html_view_length_to_px_signed(&style->bottom,
                                        ctx->viewport_w,
                                        ctx->viewport_h,
                                        cont_w,
                                        cont_h,
                                        ctx->base_font_px,
                                        false)
        : 0;

    int available_w = cont_w - margin_left - margin_right - pad_left - pad_right - border_left - border_right;
    if (available_w < 0) available_w = 0;

    bool width_specified = style->has_width && style->width.valid && !style->width.is_auto;
    int specified_h = 0;
    bool height_specified = html_view_length_to_px_height(ctx, &style->height, &specified_h);
    if (height_specified && specified_h < 0)
    {
        specified_h = 0;
    }

    int measured_w = 0;
    int measured_h = 0;
    if (!width_specified || !height_specified)
    {
        html_view_measure_block_children(ctx, node, style, available_w, &measured_w, &measured_h);
    }
    if (style->has_display && style->display == CSS_DISPLAY_TABLE)
    {
        int table_w = 0;
        int table_h = 0;
        html_view_measure_css_table_cells(ctx, node, style, available_w, cont_h, &table_w, &table_h);
        if (table_w > 0)
        {
            measured_w = table_w;
        }
        if (table_h > 0)
        {
            measured_h = table_h;
        }
    }

    int content_w = 0;
    if (width_specified)
    {
        content_w = html_view_length_to_px(&style->width,
                                           ctx->viewport_w,
                                           ctx->viewport_h,
                                           cont_w,
                                           cont_h,
                                           ctx->base_font_px,
                                           true);
    }
    else if (have_left && have_right)
    {
        content_w = cont_w - left_px - right_px - margin_left - margin_right - pad_left - pad_right - border_left - border_right;
    }
    else
    {
        content_w = measured_w;
    }
    if (content_w < 0) content_w = 0;
    if (available_w > 0 && content_w > available_w)
    {
        content_w = available_w;
    }

    int min_w = -1;
    int max_w = -1;
    if (style->has_min_width && style->min_width.valid && !style->min_width.is_auto)
    {
        min_w = html_view_length_to_px(&style->min_width,
                                       ctx->viewport_w,
                                       ctx->viewport_h,
                                       cont_w,
                                       cont_h,
                                       ctx->base_font_px,
                                       true);
        if (min_w < 0) min_w = 0;
    }
    if (style->has_max_width && style->max_width.valid && !style->max_width.is_auto)
    {
        max_w = html_view_length_to_px(&style->max_width,
                                       ctx->viewport_w,
                                       ctx->viewport_h,
                                       cont_w,
                                       cont_h,
                                       ctx->base_font_px,
                                       true);
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

    int content_h = 0;
    if (height_specified)
    {
        content_h = specified_h;
    }
    else if (have_top && have_bottom)
    {
        content_h = cont_h - top_px - bottom_px - margin_top - margin_bottom - pad_top - pad_bottom - border_top - border_bottom;
    }
    else
    {
        content_h = measured_h;
    }
    if (content_h < 0) content_h = 0;

    int min_h = -1;
    int max_h = -1;
    if (html_view_length_to_px_height(ctx, &style->min_height, &min_h))
    {
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

    int border_box_w = content_w + pad_left + pad_right + border_left + border_right;
    int border_box_h = content_h + pad_top + pad_bottom + border_top + border_bottom;
    if (border_box_w < 0) border_box_w = 0;
    if (border_box_h < 0) border_box_h = 0;

    int border_x = cont_x + margin_left;
    if (have_left)
    {
        border_x = cont_x + left_px + margin_left;
    }
    else if (have_right)
    {
        border_x = cont_x + cont_w - right_px - border_box_w - margin_right;
    }

    int border_y = cont_y + margin_top;
    if (have_top)
    {
        border_y = cont_y + top_px + margin_top;
    }
    else if (have_bottom)
    {
        border_y = cont_y + cont_h - bottom_px - border_box_h - margin_bottom;
    }

    int draw_y = fixed ? border_y : html_view_draw_y(ctx, border_y);
    const char *debug_label = html_view_debug_block_label(node);
    if (debug_label)
    {
        int scroll_y = (ctx->priv ? ctx->priv->scroll_y : 0);
        serial_printf("[html_view][layout] posnode=%s border_y=%d draw_y=%d cont_y=%d cont_h=%d pos_x=%d pos_y=%d pos_w=%d pos_h=%d box_h=%d margin_t=%d margin_b=%d fixed=%d fixed_mode=%d scroll_y=%d doc_origin_y=%d record=%d",
                      debug_label,
                      border_y,
                      draw_y,
                      cont_y,
                      cont_h,
                      ctx->pos_x,
                      ctx->pos_y,
                      ctx->pos_w,
                      ctx->pos_h,
                      border_box_h,
                      margin_top,
                      margin_bottom,
                      fixed ? 1 : 0,
                      ctx->fixed_mode ? 1 : 0,
                      scroll_y,
                      ctx->doc_origin_y,
                      ctx->record ? 1 : 0);
    }
    html_view_ctx_t inner = *ctx;
    inner.fixed_mode = (ctx->fixed_mode || fixed);
    inner.underline_run_active = false;
    inner.underline_run_start_x = 0;
    html_view_margin_state_reset(&inner.pending_margin);
    if (style->has_background && !style->background_transparent && border_box_w > 0 && border_box_h > 0)
    {
        html_view_draw_rect_clipped(&inner, border_x, draw_y, border_box_w, border_box_h, style->background, &ctx->clip);
    }
    html_view_draw_background_image(&inner, style, border_x, border_y, border_box_w, border_box_h);
    if (style->has_border && border_box_w > 0 && border_box_h > 0)
    {
        if (border_top > 0 || border_right > 0 || border_bottom > 0 || border_left > 0)
        {
            html_view_draw_border_sides_clipped(&inner,
                                                border_x,
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
    }

    html_view_float_ctx_t inner_floats = {0};
    inner.floats = &inner_floats;
    inner.style_block = NULL;
    inner.style_depth = 0;
    inner.body_x = border_x + border_left + pad_left;
    inner.body_w = content_w;
    if (inner.body_w < 0) inner.body_w = 0;
    inner.max_x = inner.body_x + inner.body_w;
    inner.x = inner.body_x;
    inner.y = border_y + border_top + pad_top;
    inner.pending_space = false;
    inner.line_start_x = inner.x;
    inner.line_start_y = inner.y;
    inner.line_op_start = (inner.record && inner.priv) ? inner.priv->render_cache.op_count : 0;
    inner.measure_max_x = inner.x;
    inner.content_bottom = inner.y;
    inner.list_level = 0;
    inner.line_height = html_view_line_height_for_style(&inner, style);
    if (html_view_subtree_has_form_control(node) && inner.line_height < atk_font_line_height() + 8)
    {
        inner.line_height = atk_font_line_height() + 8;
    }
    bool inner_height_valid = height_specified || (have_top && have_bottom);
    inner.height_basis_valid = inner_height_valid;
    inner.height_basis = inner_height_valid ? content_h : 0;
    inner.height_basis_explicit = inner_height_valid;

    int pad_box_w = border_box_w - border_left - border_right;
    int pad_box_h = border_box_h - border_top - border_bottom;
    if (pad_box_w < 0) pad_box_w = 0;
    if (pad_box_h < 0) pad_box_h = 0;
    inner.pos_x = border_x + border_left;
    inner.pos_y = border_y + border_top;
    inner.pos_w = pad_box_w;
    inner.pos_h = pad_box_h;

    if (style->has_background && !style->background_transparent)
    {
        inner.bg = style->background;
    }

    if (style->has_overflow && style->overflow == CSS_OVERFLOW_HIDDEN)
    {
        atk_rect_t overflow_clip = {
            .x = inner.pos_x,
            .y = html_view_draw_y(&inner, inner.pos_y),
            .width = inner.pos_w,
            .height = inner.pos_h,
        };
        atk_rect_t clipped = {0};
        if (overflow_clip.width > 0 && overflow_clip.height > 0 &&
            html_view_intersect_rect_local(&overflow_clip, &inner.clip, &clipped))
        {
            inner.clip = clipped;
        }
        else
        {
            inner.clip = (atk_rect_t){0};
        }
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

        int margin_top = 0;
        int margin_bottom = 0;
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
                                             true);
            pad_bottom = html_view_length_to_px(&style->padding.bottom,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                ctx->base_font_px,
                                                true);
        }

        (void)html_view_apply_block_margin_top(ctx,
                                               margin_top,
                                               (style->has_clear ? style->clear_mode : CSS_CLEAR_NONE),
                                               NULL,
                                               NULL);
        ctx->y += pad_top;
        ctx->pending_space = false;
        html_view_record_anchor(ctx, node);

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

            int draw_top = html_view_draw_y(ctx, ctx->y);
            int baseline = html_view_baseline_for_rect(ctx, draw_top, ctx->line_height);
            html_view_paint_layer_t saved_layer = ctx->paint_layer;
            if (ctx->paint_layer == HTML_VIEW_PAINT_LAYER_BLOCK)
            {
                ctx->paint_layer = HTML_VIEW_PAINT_LAYER_INLINE;
            }

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
                            shadow_op.x = html_view_record_x(ctx, draw_x + dx);
                            shadow_op.y = html_view_record_y(ctx, draw_top);
                            shadow_op.h = ctx->line_height;
                            shadow_op.baseline_off = (int16_t)(baseline_off + dy);
                            shadow_op.font_px = (int16_t)ctx->actual_font_px;
                            shadow_op.color = shadow;
                            shadow_op.text = owned;
                            shadow_op.text_len = (uint32_t)owned_len;
                            shadow_op.text_owned = false;
                            shadow_op.fixed = ctx->fixed_mode;
                            shadow_op.z_index = html_view_effective_z_index(ctx);
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
                            main_op.x = html_view_record_x(ctx, draw_x);
                            main_op.y = html_view_record_y(ctx, draw_top);
                            main_op.h = ctx->line_height;
                            main_op.baseline_off = (int16_t)baseline_off;
                            main_op.font_px = (int16_t)ctx->actual_font_px;
                            main_op.color = color;
                            main_op.text = owned;
                            main_op.text_len = (uint32_t)owned_len;
                            main_op.text_owned = false;
                            main_op.fixed = ctx->fixed_mode;
                            main_op.z_index = html_view_effective_z_index(ctx);
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

            ctx->paint_layer = saved_layer;
            ctx->x = ctx->body_x;
            ctx->pending_space = false;
            html_view_ensure_line_visible(ctx);
        }
        free(text);

        html_view_new_line(ctx);
        ctx->y += pad_bottom;
        ctx->pending_margin = html_view_margin_state_from_value(margin_bottom);
        ctx->pending_space = false;
        return true;
    }

    if (strcmp(tag, "p") == 0)
    {
        if (ctx->x != ctx->body_x)
        {
            html_view_new_line(ctx);
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
                margin_top = html_view_length_to_px_signed(&style->margin.top,
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
        }
        else
        {
            if (ctx->y > ctx->viewport_y)
            {
                margin_top = ctx->line_height / 3;
            }
            margin_bottom = ctx->line_height / 3;
        }
        (void)html_view_apply_block_margin_top(ctx,
                                               margin_top,
                                               (style->has_clear ? style->clear_mode : CSS_CLEAR_NONE),
                                               NULL,
                                               NULL);
        ctx->pending_space = false;
        html_view_record_anchor(ctx, node);
        html_view_render_children(ctx, node, style);
        html_view_new_line(ctx);
        ctx->pending_margin = html_view_margin_state_from_value(margin_bottom);
        html_view_ensure_line_visible(ctx);
        ctx->line_height = saved_line_height;
        ctx->pending_space = false;
        return true;
    }

    if (strcmp(tag, "ul") == 0)
    {
        if (style->has_display && style->display == CSS_DISPLAY_TABLE)
        {
            /* Let the generic block renderer handle display: table. */
        }
        else
        {
        bool styled = style->has_margin ||
                      style->has_padding ||
                      style->has_border ||
                      style->has_background ||
                      style->has_width ||
                      style->has_height ||
                      style->has_float ||
                      (style->has_display && style->display != CSS_DISPLAY_INLINE);

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
                margin_top = html_view_length_to_px_signed(&style->margin.top,
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
        }
        else
        {
            if (ctx->y > ctx->viewport_y)
            {
                margin_top = ctx->line_height / 3;
            }
            margin_bottom = ctx->line_height / 3;
        }

        (void)html_view_apply_block_margin_top(ctx,
                                               margin_top,
                                               (style->has_clear ? style->clear_mode : CSS_CLEAR_NONE),
                                               NULL,
                                               NULL);
        ctx->pending_space = false;

        if (styled)
        {
            html_view_render_children(ctx, node, style);
            if (ctx->x != ctx->body_x)
            {
                html_view_new_line(ctx);
            }
            ctx->pending_margin = html_view_margin_state_from_value(margin_bottom);
            ctx->pending_space = false;
            return true;
        }

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
        ctx->pending_margin = html_view_margin_state_from_value(margin_bottom);
        ctx->pending_space = false;
        return true;
        }
    }

    if (strcmp(tag, "dl") == 0)
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
                margin_top = html_view_length_to_px_signed(&style->margin.top,
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
        }

        (void)html_view_apply_block_margin_top(ctx,
                                               margin_top,
                                               (style->has_clear ? style->clear_mode : CSS_CLEAR_NONE),
                                               NULL,
                                               NULL);

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
        ctx->pending_margin = html_view_margin_state_from_value(margin_bottom);
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

            int margin_top = 0;
            int margin_bottom = 0;
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
            }
            (void)html_view_apply_block_margin_top(ctx,
                                                   margin_top,
                                                   (style->has_clear ? style->clear_mode : CSS_CLEAR_NONE),
                                                   NULL,
                                                   NULL);

            html_view_render_children(ctx, node, style);
            if (ctx->x != ctx->body_x)
            {
                html_view_new_line(ctx);
            }
            ctx->pending_margin = html_view_margin_state_from_value(margin_bottom);
            ctx->pending_space = false;
            return true;
        }

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
                margin_top = html_view_length_to_px_signed(&style->margin.top,
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
        }
        (void)html_view_apply_block_margin_top(ctx,
                                               margin_top,
                                               (style->has_clear ? style->clear_mode : CSS_CLEAR_NONE),
                                               NULL,
                                               NULL);

        int saved_body_x = ctx->body_x;
        int saved_max_x = ctx->max_x;
        int saved_line_height = ctx->line_height;
        ctx->line_height = html_view_line_height_for_style(ctx, style);

        int level = ctx->list_level > 0 ? ctx->list_level : 1;
        int indent = level * 32;
        int bullet_size = 4;
        int bullet_x = saved_body_x + indent - 16;
        int bullet_draw_y = html_view_draw_y(ctx, ctx->y) + ctx->line_height / 2 - bullet_size / 2;
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
        ctx->pending_margin = html_view_margin_state_from_value(margin_bottom);
        ctx->pending_space = false;
        return true;
    }

    if (strcmp(tag, "img") == 0)
    {
        bool img_block = style->has_display &&
                         (style->display == CSS_DISPLAY_BLOCK ||
                          style->display == CSS_DISPLAY_LIST_ITEM);
        if (!img_block)
        {
            return false;
        }
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
                margin_top = html_view_length_to_px_signed(&style->margin.top,
                                                           ctx->viewport_w,
                                                           ctx->viewport_h,
                                                           ctx->viewport_w,
                                                           ctx->viewport_h,
                                                           ctx->base_font_px,
                                                           true);
            }
            if (style->margin.bottom.valid && !style->margin.bottom.is_auto)
            {
                margin_bottom = html_view_length_to_px_signed(&style->margin.bottom,
                                                             ctx->viewport_w,
                                                             ctx->viewport_h,
                                                             ctx->viewport_w,
                                                             ctx->viewport_h,
                                                             ctx->base_font_px,
                                                             true);
            }
        }
        (void)html_view_apply_block_margin_top(ctx,
                                               margin_top,
                                               (style->has_clear ? style->clear_mode : CSS_CLEAR_NONE),
                                               NULL,
                                               NULL);
        ctx->pending_space = false;

        const char *src = html_attr_get(node, "src");
        html_view_image_t *img = src ? html_view_image_find(ctx->priv, src) : NULL;
        if (!img && ctx->record && ctx->priv && src)
        {
            (void)html_view_try_load_data_image_locked(ctx->priv, src);
            img = html_view_image_find(ctx->priv, src);
        }
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
                    draw_x = ctx->body_x + html_view_length_to_px_signed(&style->margin.left,
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
            int draw_y = html_view_draw_y(ctx, ctx->y);
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
                html_view_apply_border_style_none(style, &bt, &br, &bb, &bl);
                if (bt > 0 || br > 0 || bb > 0 || bl > 0)
                {
                    html_view_draw_border_sides_clipped(ctx,
                                                        draw_x,
                                                        draw_y,
                                                        img_w,
                                                        img_h,
                                                        bt,
                                                        br,
                                                        bb,
                                                        bl,
                                                        style,
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

        ctx->x = ctx->body_x;
        ctx->pending_margin = html_view_margin_state_from_value(margin_bottom);
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
                  style->has_height ||
                  (style->has_display && style->display == CSS_DISPLAY_TABLE);
    if (!styled)
    {
        return false;
    }

    bool force_block = false;
    if (style->has_display)
    {
        if (style->display == CSS_DISPLAY_BLOCK ||
            style->display == CSS_DISPLAY_LIST_ITEM ||
            style->display == CSS_DISPLAY_TABLE ||
            style->display == CSS_DISPLAY_FLEX)
        {
            force_block = true;
        }
    }

    if (!html_view_is_block_tag(tag) && !force_block)
    {
        return false;
    }

    if (ctx->x != ctx->body_x)
    {
        html_view_new_line(ctx);
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
        auto_left = style->margin.left.valid && style->margin.left.is_auto;
        auto_right = style->margin.right.valid && style->margin.right.is_auto;
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

    int available_w = ctx->body_w;
    if (available_w < 0) available_w = 0;
    bool width_specified = style->has_width && style->width.valid && !style->width.is_auto;
    int content_w = available_w - margin_left - margin_right - pad_left - pad_right - border_left - border_right;
    if (width_specified)
    {
        content_w = html_view_length_to_px(&style->width,
                                           ctx->viewport_w,
                                           ctx->viewport_h,
                                           ctx->body_w,
                                           ctx->viewport_h,
                                           ctx->base_font_px,
                                           true);
    }
    else if (style->has_display && style->display == CSS_DISPLAY_TABLE)
    {
        int table_w = 0;
        int table_h = 0;
        html_view_measure_css_table_cells(ctx, node, style, available_w, ctx->viewport_h, &table_w, &table_h);
        if (table_w > 0)
        {
            content_w = table_w;
        }
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

    int start_y = ctx->y;
    html_view_margin_state_t prev_pending = {0};
    bool prev_pending_valid = false;
    bool clearance_applied = false;
    (void)html_view_apply_block_margin_top(ctx,
                                           margin_top,
                                           (style->has_clear ? style->clear_mode : CSS_CLEAR_NONE),
                                           &clearance_applied,
                                           &prev_pending);
    prev_pending_valid = prev_pending.valid;
    const char *debug_label = html_view_debug_block_label(node);

    int border_doc_x = ctx->body_x + margin_left;
    int border_doc_y = ctx->y;

    int outer_w = border_box_w + margin_left + margin_right;
    bool avoid_floats = false;
    if (style->has_overflow && style->overflow != CSS_OVERFLOW_VISIBLE)
    {
        avoid_floats = true;
    }
    if (style->has_display && style->display == CSS_DISPLAY_TABLE)
    {
        avoid_floats = true;
    }

    if (avoid_floats && ctx->floats && ctx->floats->count > 0 && outer_w > 0)
    {
        int place_y = border_doc_y;
        for (int it = 0; it < 256; ++it)
        {
            int left = ctx->body_x;
            int right = ctx->body_x + ctx->body_w;
            html_view_float_bounds_at_y(ctx->floats, place_y, ctx->body_x, ctx->body_w, &left, &right);
            int avail = right - left;
            if (outer_w <= avail)
            {
                border_doc_x = left + margin_left;
                border_doc_y = place_y;
                ctx->y = place_y;
                break;
            }
            int next_y = html_view_float_next_y(ctx->floats, place_y);
            if (next_y <= place_y)
            {
                next_y = place_y + 1;
            }
            place_y = next_y;
        }
    }

    int content_doc_x = border_doc_x + border_left + pad_left;
    int content_doc_y = border_doc_y + border_top + pad_top;
    int rel_x = 0;
    int rel_y = 0;
    if (style->has_position && style->position == CSS_POSITION_RELATIVE)
    {
        if (style->has_left && style->left.valid && !style->left.is_auto)
        {
            rel_x += html_view_length_to_px_signed(&style->left,
                                                   ctx->viewport_w,
                                                   ctx->viewport_h,
                                                   ctx->body_w,
                                                   ctx->viewport_h,
                                                   ctx->base_font_px,
                                                   true);
        }
        else if (style->has_right && style->right.valid && !style->right.is_auto)
        {
            rel_x -= html_view_length_to_px_signed(&style->right,
                                                   ctx->viewport_w,
                                                   ctx->viewport_h,
                                                   ctx->body_w,
                                                   ctx->viewport_h,
                                                   ctx->base_font_px,
                                                   true);
        }

        if (style->has_top && style->top.valid && !style->top.is_auto)
        {
            rel_y += html_view_length_to_px_signed(&style->top,
                                                   ctx->viewport_w,
                                                   ctx->viewport_h,
                                                   ctx->body_w,
                                                   ctx->viewport_h,
                                                   ctx->base_font_px,
                                                   false);
        }
        else if (style->has_bottom && style->bottom.valid && !style->bottom.is_auto)
        {
            rel_y -= html_view_length_to_px_signed(&style->bottom,
                                                   ctx->viewport_w,
                                                   ctx->viewport_h,
                                                   ctx->body_w,
                                                   ctx->viewport_h,
                                                   ctx->base_font_px,
                                                   false);
        }
    }
    int draw_border_x = border_doc_x + rel_x;
    int draw_border_y = border_doc_y + rel_y;
    int draw_content_x = content_doc_x + rel_x;
    int draw_content_y = content_doc_y + rel_y;

    int specified_h = 0;
    bool height_specified = html_view_length_to_px_height(ctx, &style->height, &specified_h);
    if (height_specified && specified_h < 0)
    {
        specified_h = 0;
    }
    int min_h = -1;
    if (html_view_length_to_px_height(ctx, &style->min_height, &min_h))
    {
        if (min_h < 0)
        {
            min_h = 0;
        }
    }
    else
    {
        min_h = -1;
    }
    int max_h = -1;
    if (html_view_length_to_px_height(ctx, &style->max_height, &max_h))
    {
        if (max_h < 0)
        {
            max_h = 0;
        }
    }
    else
    {
        max_h = -1;
    }

    int height_basis = specified_h;
    if (height_specified)
    {
        if (max_h >= 0 && height_basis > max_h)
        {
            height_basis = max_h;
        }
        if (min_h >= 0 && height_basis < min_h)
        {
            height_basis = min_h;
        }
        if (max_h >= 0 && min_h > max_h)
        {
            height_basis = min_h;
        }
    }

    if (style->has_background || style->has_border)
    {
        int content_h = 0;
        if (height_specified)
        {
            content_h = height_basis;
        }
        else
        {
            html_view_measure_block_children(ctx, node, style, content_w, NULL, &content_h);
            if (style->has_display && style->display == CSS_DISPLAY_TABLE)
            {
                int table_w = 0;
                int table_h = 0;
                html_view_measure_css_table_cells(ctx, node, style, content_w, ctx->viewport_h, &table_w, &table_h);
                if (table_h > 0)
                {
                    content_h = table_h;
                }
            }
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

        int border_box_h = content_h + pad_top + pad_bottom + border_top + border_bottom;
        if (border_box_h < 0) border_box_h = 0;
        int draw_y = html_view_draw_y(ctx, draw_border_y);
        if (style->has_background && !style->background_transparent && border_box_w > 0 && border_box_h > 0)
        {
            html_view_draw_rect_clipped(ctx, draw_border_x, draw_y, border_box_w, border_box_h, style->background, &ctx->clip);
        }
        html_view_draw_background_image(ctx, style, draw_border_x, draw_border_y, border_box_w, border_box_h);
        if (style->has_border && border_box_w > 0 && border_box_h > 0)
        {
            if (border_top > 0 || border_right > 0 || border_bottom > 0 || border_left > 0)
            {
                html_view_draw_border_sides_clipped(ctx,
                                                    draw_border_x,
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
        }
    }

    int saved_body_x = ctx->body_x;
    int saved_body_w = ctx->body_w;
    int saved_max_x = ctx->max_x;
    video_color_t saved_bg = ctx->bg;
    int saved_pos_x = ctx->pos_x;
    int saved_pos_y = ctx->pos_y;
    int saved_pos_w = ctx->pos_w;
    int saved_pos_h = ctx->pos_h;
    int saved_height_basis = ctx->height_basis;
    bool saved_height_basis_valid = ctx->height_basis_valid;
    bool saved_height_basis_explicit = ctx->height_basis_explicit;

    if (style->has_position && style->position != CSS_POSITION_STATIC)
    {
        int pad_box_w = border_box_w - border_left - border_right;
        int pad_box_h = (height_specified ? height_basis : 0) + pad_top + pad_bottom;
        if (pad_box_w < 0) pad_box_w = 0;
        if (pad_box_h < 0) pad_box_h = 0;
        ctx->pos_x = draw_border_x + border_left;
        ctx->pos_y = draw_border_y + border_top;
        ctx->pos_w = pad_box_w;
        ctx->pos_h = pad_box_h;
    }

    if (ctx->record)
    {
        int anchor_saved_y = ctx->y;
        ctx->y = draw_border_y;
        html_view_record_anchor(ctx, node);
        ctx->y = anchor_saved_y;
    }

    ctx->body_x = draw_content_x;
    ctx->body_w = content_w;
    if (ctx->body_w < 0) ctx->body_w = 0;
    ctx->height_basis_valid = height_specified;
    ctx->height_basis = height_specified ? height_basis : 0;
    ctx->height_basis_explicit = height_specified;
    ctx->max_x = ctx->body_x + ctx->body_w;
    ctx->x = ctx->body_x;
    ctx->y = draw_content_y;
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

    if (style->has_background && !style->background_transparent)
    {
        ctx->bg = style->background;
    }

    atk_rect_t saved_clip = ctx->clip;
    bool clip_applied = false;
    if (style->has_overflow && style->overflow == CSS_OVERFLOW_HIDDEN && height_specified)
    {
        int pad_box_x = draw_border_x + border_left;
        int pad_box_y_doc = draw_border_y + border_top;
        int pad_box_y = html_view_draw_y(ctx, pad_box_y_doc);
        int pad_box_w = content_w + pad_left + pad_right;
        int pad_box_h = height_basis + pad_top + pad_bottom;
        if (pad_box_w < 0) pad_box_w = 0;
        if (pad_box_h < 0) pad_box_h = 0;

        atk_rect_t pad_box = {
            .x = pad_box_x,
            .y = pad_box_y,
            .width = pad_box_w,
            .height = pad_box_h
        };
        atk_rect_t clipped = {0};
        if (html_view_intersect_rect_local(&ctx->clip, &pad_box, &clipped))
        {
            ctx->clip = clipped;
        }
        else
        {
            ctx->clip = (atk_rect_t){0, 0, 0, 0};
        }
        clip_applied = true;
    }

    bool table_layout = style->has_display && style->display == CSS_DISPLAY_TABLE;
    html_view_float_ctx_t table_floats = {0};
    html_view_float_ctx_t *saved_floats = ctx->floats;
    bool saved_table_mode = ctx->table_mode;
    if (table_layout)
    {
        ctx->floats = &table_floats;
        ctx->table_mode = true;
    }

    html_view_margin_state_reset(&ctx->pending_margin);
    html_view_render_children(ctx, node, style);
    if (ctx->x != ctx->body_x)
    {
        html_view_new_line(ctx);
    }

    if (table_layout)
    {
        int float_bottom = html_view_float_max_bottom(ctx->floats, CSS_CLEAR_BOTH);
        if (float_bottom > ctx->y)
        {
            ctx->y = float_bottom;
        }
        if (float_bottom > ctx->content_bottom)
        {
            ctx->content_bottom = float_bottom;
        }
        ctx->floats = saved_floats;
        ctx->table_mode = saved_table_mode;
    }
    if (clip_applied)
    {
        ctx->clip = saved_clip;
    }

    html_view_margin_state_t child_pending = ctx->pending_margin;
    bool child_pending_valid = child_pending.valid;
    html_view_margin_state_reset(&ctx->pending_margin);

    bool can_collapse_bottom = (border_bottom == 0 &&
                                pad_bottom == 0 &&
                                !height_specified &&
                                min_h <= 0);
    if (!can_collapse_bottom && child_pending_valid)
    {
        ctx->y += html_view_margin_state_value(&child_pending);
        child_pending_valid = false;
    }

    int content_end_y = ctx->y - rel_y;
    int flow_content_h = content_end_y - content_doc_y;
    int content_h = height_specified ? height_basis : flow_content_h;
    if (!height_specified)
    {
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
    }
    content_end_y = content_doc_y + content_h;

    bool empty_block = (!height_specified &&
                        min_h <= 0 &&
                        border_top == 0 &&
                        border_bottom == 0 &&
                        pad_top == 0 &&
                        pad_bottom == 0 &&
                        flow_content_h == 0 &&
                        !clearance_applied);
    html_view_margin_state_t merged_margin = {0};
    if (empty_block)
    {
        merged_margin = html_view_margin_state_from_value(margin_top);
        html_view_margin_state_add(&merged_margin, margin_bottom);
        if (child_pending_valid)
        {
            html_view_margin_state_merge(&merged_margin, &child_pending);
        }
        if (prev_pending_valid)
        {
            html_view_margin_state_merge(&merged_margin, &prev_pending);
        }
    }

    html_view_margin_state_t outgoing_margin = html_view_margin_state_from_value(margin_bottom);
    if (can_collapse_bottom && child_pending_valid)
    {
        html_view_margin_state_merge(&outgoing_margin, &child_pending);
    }

    ctx->body_x = saved_body_x;
    ctx->body_w = saved_body_w;
    ctx->max_x = saved_max_x;
    ctx->x = ctx->body_x;
    if (empty_block)
    {
        ctx->y = start_y;
    }
    else
    {
        ctx->y = content_end_y + pad_bottom + border_bottom;
    }
    ctx->bg = saved_bg;
    ctx->pos_x = saved_pos_x;
    ctx->pos_y = saved_pos_y;
    ctx->pos_w = saved_pos_w;
    ctx->pos_h = saved_pos_h;
    ctx->height_basis = saved_height_basis;
    ctx->height_basis_valid = saved_height_basis_valid;
    ctx->height_basis_explicit = saved_height_basis_explicit;
    ctx->pending_space = false;
    if (empty_block)
    {
        ctx->pending_margin = merged_margin;
    }
    else
    {
        ctx->pending_margin = outgoing_margin;
    }
    if (debug_label)
    {
        int prev_pending_value = html_view_margin_state_value(&prev_pending);
        int child_pending_value = html_view_margin_state_value(&child_pending);
        int pending_out_value = html_view_margin_state_value(&ctx->pending_margin);
        int scroll_y = (ctx->priv ? ctx->priv->scroll_y : 0);
        int draw_border_y = html_view_draw_y(ctx, border_doc_y);
        int draw_content_y = html_view_draw_y(ctx, content_doc_y);
        serial_printf("[html_view][layout] node=%s start_y=%d border_y=%d draw_border_y=%d content_y=%d draw_content_y=%d end_y=%d flow_h=%d height_spec=%d min_h=%d max_h=%d margin_t=%d margin_b=%d prev_pending=%d prev_valid=%d child_pending=%d child_valid=%d empty=%d clearance=%d pending_out=%d y=%d scroll_y=%d doc_origin_y=%d record=%d",
                      debug_label,
                      start_y,
                      border_doc_y,
                      draw_border_y,
                      content_doc_y,
                      draw_content_y,
                      content_end_y,
                      flow_content_h,
                      height_specified ? 1 : 0,
                      min_h,
                      max_h,
                      margin_top,
                      margin_bottom,
                      prev_pending_value,
                      prev_pending_valid ? 1 : 0,
                      child_pending_value,
                      child_pending_valid ? 1 : 0,
                      empty_block ? 1 : 0,
                      clearance_applied ? 1 : 0,
                      pending_out_value,
                      ctx->y,
                      scroll_y,
                      ctx->doc_origin_y,
                      ctx->record ? 1 : 0);
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
    html_view_ensure_line_visible(ctx);
    ctx->line_height = saved_line_height;
    return true;

    return false;
}
