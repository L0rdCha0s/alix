#include "atk/html_view/html_view_internal.h"

#include "ctype.h"
#include "serial.h"
#include "string.h"

typedef struct
{
    const html_node_t *node;
    css_style_t style;
    int colspan;
    int x;
    int y;
    int w;
    int h;
    int content_x;
    int content_y;
    int content_w;
    int pad_top;
    int pad_right;
    int pad_bottom;
    int pad_left;
    int border_top;
    int border_right;
    int border_bottom;
    int border_left;
} html_view_table_cell_layout_t;

typedef struct
{
    const html_node_t *node;
    css_style_t style;
    html_view_table_cell_layout_t *cells;
    size_t cell_count;
    size_t cell_cap;
    int y;
    int h;
    int min_h;
} html_view_table_row_layout_t;

typedef struct
{
    html_view_table_row_layout_t *rows;
    size_t row_count;
    size_t row_cap;
    int col_count;
    int *col_w;
    int cellpadding;
    int cellspacing;
    int table_x;
    int table_y;
    int content_w;
    int pad_top;
    int pad_right;
    int pad_bottom;
    int pad_left;
    int border_top;
    int border_right;
    int border_bottom;
    int border_left;
    int margin_top;
    int margin_right;
    int margin_bottom;
    int margin_left;
    int table_h;
} html_view_table_layout_t;

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

static bool html_view_node_in_smile(const html_node_t *node)
{
    for (const html_node_t *cur = node; cur; cur = cur->parent)
    {
        if (html_view_attr_has_class(cur, "smile"))
        {
            return true;
        }
    }
    return false;
}

static bool html_view_table_mode_is_cell(const html_node_t *node, const css_style_t *style)
{
    if (!node || node->type != HTML_NODE_ELEMENT)
    {
        return false;
    }
    if (style && style->has_display)
    {
        if (style->display == CSS_DISPLAY_TABLE_CELL ||
            style->display == CSS_DISPLAY_TABLE ||
            style->display == CSS_DISPLAY_LIST_ITEM)
        {
            return true;
        }
    }
    else if (node->name && strcmp(node->name, "li") == 0)
    {
        return true;
    }
    return false;
}

static const char *html_view_debug_float_label(const html_node_t *node)
{
    if (!node || node->type != HTML_NODE_ELEMENT)
    {
        return NULL;
    }
    if (html_view_attr_has_id(node, "eyes-b"))
    {
        return "eyes-b";
    }
    if (node->name && strcmp(node->name, "address") == 0)
    {
        return "address";
    }
    if (html_view_attr_has_class(node, "nose"))
    {
        return "nose";
    }
    if (node->name && html_view_node_in_smile(node))
    {
        if (strcmp(node->name, "span") == 0)
        {
            return "smile-span";
        }
        if (strcmp(node->name, "em") == 0)
        {
            return "smile-em";
        }
    }
    return NULL;
}

static const char *html_view_debug_table_cell_label(const html_node_t *node)
{
    if (!node || node->type != HTML_NODE_ELEMENT)
    {
        return NULL;
    }
    if (html_view_attr_has_class(node, "first-part"))
    {
        return "first-part";
    }
    if (html_view_attr_has_class(node, "second-part"))
    {
        return "second-part";
    }
    if (html_view_attr_has_class(node, "third-part"))
    {
        return "third-part";
    }
    if (html_view_attr_has_class(node, "fourth-part"))
    {
        return "fourth-part";
    }
    return NULL;
}

static void html_view_table_layout_destroy(html_view_table_layout_t *layout)
{
    if (!layout)
    {
        return;
    }
    for (size_t i = 0; i < layout->row_count; ++i)
    {
        free(layout->rows[i].cells);
        layout->rows[i].cells = NULL;
        layout->rows[i].cell_count = 0;
        layout->rows[i].cell_cap = 0;
    }
    free(layout->rows);
    layout->rows = NULL;
    layout->row_count = 0;
    layout->row_cap = 0;
    free(layout->col_w);
    layout->col_w = NULL;
    layout->col_count = 0;
}

static int html_view_attr_to_int(const html_node_t *node, const char *name, int fallback)
{
    const char *v = html_attr_get(node, name);
    if (!v || v[0] == '\0')
    {
        return fallback;
    }
    int n = atoi(v);
    return n >= 0 ? n : fallback;
}

void html_view_render_children(html_view_ctx_t *ctx, const html_node_t *node, const css_style_t *style);

static int html_view_measure_rendered_width(html_view_ctx_t *ctx, const html_node_t *node, const css_style_t *parent_style, int max_w, int *out_h)
{
    if (out_h)
    {
        *out_h = 0;
    }
    if (!ctx || !node || !parent_style || max_w <= 0)
    {
        return 0;
    }

    int cached_w = 0;
    int cached_h = 0;
    if (ctx->priv &&
        html_view_measure_cache_lookup(ctx->priv,
                                       node,
                                       max_w,
                                       ctx->actual_font_px,
                                       ctx->line_height,
                                       ctx->measure_shrink,
                                       0,
                                       HTML_VIEW_MEASURE_KIND_TABLE,
                                       &cached_w,
                                       &cached_h))
    {
        if (out_h)
        {
            *out_h = cached_h;
        }
        return cached_w;
    }

    html_view_float_ctx_t floats = {0};
    html_view_ctx_t measure = *ctx;
    measure.draw = false;
    measure.record = false;
    measure.record_failed = false;
    measure.floats = &floats;
    measure.style_block = NULL;
    measure.style_depth = 0;
    measure.body_x = 0;
    measure.body_w = max_w;
    measure.max_x = measure.body_x + measure.body_w;
    measure.x = measure.body_x;
    measure.y = 0;
    measure.content_bottom = measure.y;
    measure.pending_space = false;
    html_view_margin_state_reset(&measure.pending_margin);
    measure.underline_run_active = false;
    measure.underline_run_start_x = 0;
    measure.list_level = 0;
    measure.measure_max_x = measure.x;
    measure.space_w = html_view_text_width(&measure, " ");

    int height_basis = 0;
    bool height_basis_valid = html_view_length_to_px_height(ctx, &parent_style->height, &height_basis);
    if (height_basis_valid && height_basis < 0)
    {
        height_basis = 0;
    }
    int min_h = -1;
    if (html_view_length_to_px_height(ctx, &parent_style->min_height, &min_h))
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
    if (html_view_length_to_px_height(ctx, &parent_style->max_height, &max_h))
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

    html_view_trace_note_measure(HTML_VIEW_TRACE_MEASURE_TABLE);
    html_view_render_children(&measure, node, parent_style);
    if (measure.x != measure.body_x)
    {
        html_view_new_line(&measure);
    }

    int used_w = measure.measure_max_x - measure.body_x;
    if (used_w < 0)
    {
        used_w = 0;
    }
    if (used_w > max_w)
    {
        used_w = max_w;
    }

    int used_h = measure.content_bottom;
    if (measure.y > used_h)
    {
        used_h = measure.y;
    }
    if (used_h < 0)
    {
        used_h = 0;
    }
    if (out_h)
    {
        *out_h = used_h;
    }

    if (ctx->priv)
    {
        html_view_measure_cache_store(ctx->priv,
                                      node,
                                      max_w,
                                      ctx->actual_font_px,
                                      ctx->line_height,
                                      ctx->measure_shrink,
                                      0,
                                      HTML_VIEW_MEASURE_KIND_TABLE,
                                      used_w,
                                      used_h);
    }

    html_view_style_stack_destroy(&measure);
    return used_w;
}

static bool html_view_table_row_add_cell(html_view_table_row_layout_t *row, const html_view_table_cell_layout_t *cell)
{
    if (!row || !cell)
    {
        return false;
    }
    if (row->cell_count == row->cell_cap)
    {
        size_t new_cap = row->cell_cap ? (row->cell_cap * 2) : 8;
        html_view_table_cell_layout_t *new_cells = (html_view_table_cell_layout_t *)realloc(row->cells, new_cap * sizeof(*new_cells));
        if (!new_cells)
        {
            return false;
        }
        row->cells = new_cells;
        row->cell_cap = new_cap;
    }
    row->cells[row->cell_count++] = *cell;
    return true;
}

static bool html_view_table_layout_add_row(html_view_table_layout_t *layout, const html_node_t *tr, const css_style_t *parent_style, html_view_ctx_t *ctx)
{
    if (!layout || !tr || !parent_style || !ctx)
    {
        return false;
    }
    if (layout->row_count == layout->row_cap)
    {
        size_t new_cap = layout->row_cap ? (layout->row_cap * 2) : 8;
        html_view_table_row_layout_t *new_rows = (html_view_table_row_layout_t *)realloc(layout->rows, new_cap * sizeof(*new_rows));
        if (!new_rows)
        {
            return false;
        }
        layout->rows = new_rows;
        layout->row_cap = new_cap;
    }

    html_view_table_row_layout_t *row = &layout->rows[layout->row_count++];
    memset(row, 0, sizeof(*row));
    row->node = tr;
    html_view_style_for_node(&row->style, ctx->sheet, parent_style, tr, ctx->priv);

    if (row->style.has_height && row->style.height.valid && !row->style.height.is_auto)
    {
        row->min_h = html_view_length_to_px(&row->style.height,
                                            ctx->viewport_w,
                                            ctx->viewport_h,
                                            layout->content_w,
                                            ctx->viewport_h,
                                            ctx->base_font_px,
                                            false);
        if (row->min_h < 0)
        {
            row->min_h = 0;
        }
    }

    for (const html_node_t *child = tr->first_child; child; child = child->next_sibling)
    {
        if (child->type != HTML_NODE_ELEMENT || !child->name)
        {
            continue;
        }
        if (strcmp(child->name, "td") != 0 && strcmp(child->name, "th") != 0)
        {
            continue;
        }

        html_view_table_cell_layout_t cell = {0};
        cell.node = child;
        html_view_style_for_node(&cell.style, ctx->sheet, &row->style, child, ctx->priv);
        cell.colspan = html_view_attr_to_int(child, "colspan", 1);
        if (cell.colspan < 1)
        {
            cell.colspan = 1;
        }
        if (!html_view_table_row_add_cell(row, &cell))
        {
            return false;
        }
    }

    return true;
}

bool html_view_subtree_has_form_control(const html_node_t *root)
{
    if (!root)
    {
        return false;
    }

    const html_node_t *stack[64];
    size_t sp = 0;
    stack[sp++] = root;

    while (sp > 0)
    {
        const html_node_t *node = stack[--sp];
        if (node->type == HTML_NODE_ELEMENT && node->name && html_view_is_form_control_tag(node->name))
        {
            return true;
        }
        for (const html_node_t *child = node->first_child; child; child = child->next_sibling)
        {
            if (sp < (sizeof(stack) / sizeof(stack[0])))
            {
                stack[sp++] = child;
            }
        }
    }

    return false;
}

void html_view_render_table(html_view_ctx_t *ctx,
                            const html_node_t *node,
                            const css_style_t *style,
                            const css_style_t *parent_style);

void html_view_render_float_box(html_view_ctx_t *ctx,
                                const html_node_t *node,
                                const css_style_t *style,
                                css_float_t side)
{
    if (!ctx || !node || !style || side == CSS_FLOAT_NONE)
    {
        return;
    }

    html_view_paint_layer_t saved_layer = ctx->paint_layer;
    ctx->paint_layer = HTML_VIEW_PAINT_LAYER_FLOAT;

    html_view_margin_state_t saved_pending_margin = ctx->pending_margin;
    int saved_line_height = ctx->line_height;

    if (ctx->x != ctx->body_x)
    {
        html_view_new_line(ctx);
    }
    ctx->line_height = html_view_line_height_for_style(ctx, style);

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

    if (pad_top < 0) pad_top = 0;
    if (pad_right < 0) pad_right = 0;
    if (pad_bottom < 0) pad_bottom = 0;
    if (pad_left < 0) pad_left = 0;
    if (border_top < 0) border_top = 0;
    if (border_right < 0) border_right = 0;
    if (border_bottom < 0) border_bottom = 0;
    if (border_left < 0) border_left = 0;
    html_view_apply_border_style_none(style, &border_top, &border_right, &border_bottom, &border_left);

    int float_start_y = ctx->y;
    if (ctx->pending_margin.valid)
    {
        float_start_y += html_view_margin_state_value(&ctx->pending_margin);
    }

    if (ctx->record && html_view_node_in_smile(node))
    {
        serial_printf("[html_view][smile-float] tag=%s y=%d line_h=%d base_lh=%d font_px=%d base_font=%d body_x=%d body_w=%d start_y=%d",
                      node->name ? node->name : "(null)",
                      ctx->y,
                      ctx->line_height,
                      ctx->base_line_height,
                      ctx->actual_font_px,
                      ctx->base_font_px,
                      ctx->body_x,
                      ctx->body_w,
                      float_start_y);
    }

    const char *debug_label = html_view_debug_float_label(node);
    int debug_scroll_y = (ctx->priv ? ctx->priv->scroll_y : 0);

    int content_w = 0;
    bool explicit_w = style->has_width && style->width.valid && !style->width.is_auto;
    if (explicit_w)
    {
        content_w = html_view_length_to_px(&style->width,
                                           ctx->viewport_w,
                                           ctx->viewport_h,
                                           ctx->body_w,
                                           ctx->viewport_h,
                                           ctx->base_font_px,
                                           true);
    }
    if (content_w < 0)
    {
        content_w = 0;
    }

    int content_h = 0;
    bool explicit_h = html_view_length_to_px_height(ctx, &style->height, &content_h);
    if (explicit_h && content_h < 0)
    {
        content_h = 0;
    }
    int explicit_h_px = explicit_h ? content_h : 0;

    int measured_w = 0;
    int measured_h = 0;
    if (!explicit_w || !explicit_h)
    {
        measured_w = html_view_measure_rendered_width(ctx, node, style, ctx->body_w, &measured_h);
        if (!explicit_w && measured_w > 0)
        {
            content_w = measured_w;
        }
        if (!explicit_h && measured_h > 0)
        {
            content_h = measured_h;
        }
    }

    if (ctx->record && html_view_node_in_smile(node))
    {
        serial_printf("[html_view][smile-float] tag=%s measured_w=%d measured_h=%d content_w=%d content_h=%d",
                      node->name ? node->name : "(null)",
                      measured_w,
                      measured_h,
                      content_w,
                      content_h);
    }
    if (ctx->record && html_view_attr_has_class(node, "nose"))
    {
        serial_printf("[html_view][acid2] float=nose measured_w=%d measured_h=%d content_w=%d content_h=%d",
                      measured_w,
                      measured_h,
                      content_w,
                      content_h);
    }

    if (content_w < 0)
    {
        content_w = 0;
    }
    if (content_h < 0)
    {
        content_h = 0;
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

    int max_content = ctx->body_w - margin_left - margin_right - pad_left - pad_right - border_left - border_right;
    if (max_content < 0)
    {
        max_content = 0;
    }
    if (content_w > max_content)
    {
        content_w = max_content;
    }

    int min_h = -1;
    if (html_view_length_to_px_height(ctx, &style->min_height, &min_h))
    {
        if (min_h < 0) min_h = 0;
    }
    else
    {
        min_h = -1;
    }
    int max_h = -1;
    if (html_view_length_to_px_height(ctx, &style->max_height, &max_h))
    {
        if (max_h < 0) max_h = 0;
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

    int height_basis = explicit_h_px;
    bool height_basis_valid = explicit_h;
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

    int border_box_w = content_w + pad_left + pad_right + border_left + border_right;
    int border_box_h = content_h + pad_top + pad_bottom + border_top + border_bottom;
    if (ctx->table_mode &&
        ctx->table_row_height_valid &&
        html_view_table_mode_is_cell(node, style) &&
        ctx->table_row_height > border_box_h)
    {
        int extra = ctx->table_row_height - border_box_h;
        content_h += extra;
        border_box_h = ctx->table_row_height;
    }
    if (ctx->record && ctx->table_mode)
    {
        const char *cell_label = html_view_debug_table_cell_label(node);
        if (cell_label)
        {
            serial_printf("[html_view][acid2-table] cell=%s content=%dx%d border_box=%dx%d margin=%d,%d,%d,%d row_h=%d row_valid=%d",
                          cell_label,
                          content_w,
                          content_h,
                          border_box_w,
                          border_box_h,
                          margin_top,
                          margin_right,
                          margin_bottom,
                          margin_left,
                          ctx->table_row_height,
                          ctx->table_row_height_valid ? 1 : 0);
        }
    }
    int outer_w = border_box_w + margin_left + margin_right;
    int outer_h = border_box_h + margin_top + margin_bottom;
    bool measuring = (!ctx->draw && !ctx->record);

    if (ctx->record && html_view_node_in_smile(node))
    {
        serial_printf("[html_view][smile-float] tag=%s content_w=%d border_box_w=%d content_h=%d border_box_h=%d border_top=%d border_bottom=%d margin_top=%d margin_bottom=%d",
                      node->name ? node->name : "(null)",
                      content_w,
                      border_box_w,
                      content_h,
                      border_box_h,
                      border_top,
                      border_bottom,
                      margin_top,
                      margin_bottom);
    }

    if (debug_label)
    {
        serial_printf("[html_view][layout] floatnode=%s start_y=%d margin_t=%d margin_b=%d body_x=%d body_w=%d explicit_h=%d explicit_h_px=%d min_h=%d max_h=%d content_h=%d border_box_h=%d hb_valid=%d hb_explicit=%d hb=%d ctx_hb_valid=%d ctx_hb_explicit=%d ctx_hb=%d scroll_y=%d doc_origin_y=%d record=%d",
                      debug_label,
                      float_start_y,
                      margin_top,
                      margin_bottom,
                      ctx->body_x,
                      ctx->body_w,
                      explicit_h ? 1 : 0,
                      explicit_h_px,
                      min_h,
                      max_h,
                      content_h,
                      border_box_h,
                      height_basis_valid ? 1 : 0,
                      height_basis_valid ? 1 : 0,
                      height_basis,
                      ctx->height_basis_valid ? 1 : 0,
                      ctx->height_basis_explicit ? 1 : 0,
                      ctx->height_basis,
                      debug_scroll_y,
                      ctx->doc_origin_y,
                      ctx->record ? 1 : 0);
    }
    if (debug_label && ctx->record)
    {
        int display = style->has_display ? (int)style->display : -1;
        int position = style->has_position ? (int)style->position : -1;
        int float_mode = style->has_float ? (int)style->float_mode : -1;
        int clear_mode = style->has_clear ? (int)style->clear_mode : -1;
        int bg_repeat = style->has_background_repeat ? (int)style->background_repeat : -1;
        int bg_attach = style->has_background_attachment ? (int)style->background_attachment : -1;
        int bg_pos_x = 0;
        int bg_pos_y = 0;
        if (style->has_background_position)
        {
            bg_pos_x = html_view_length_to_px_signed(&style->background_pos_x,
                                                     ctx->viewport_w,
                                                     ctx->viewport_h,
                                                     border_box_w,
                                                     border_box_h,
                                                     ctx->base_font_px,
                                                     true);
            bg_pos_y = html_view_length_to_px_signed(&style->background_pos_y,
                                                     ctx->viewport_w,
                                                     ctx->viewport_h,
                                                     border_box_w,
                                                     border_box_h,
                                                     ctx->base_font_px,
                                                     false);
        }
        bool bg_has_img = style->has_background_image && style->background_image;
        uint32_t bg_hash = bg_has_img ? html_view_debug_hash_string(style->background_image) : 0;
        int bg_w = 0;
        int bg_h = 0;
        if (bg_has_img && ctx->priv)
        {
            html_view_image_t *img = html_view_image_find(ctx->priv, style->background_image);
            if (!img)
            {
                (void)html_view_try_load_data_image_locked(ctx->priv, style->background_image);
                img = html_view_image_find(ctx->priv, style->background_image);
            }
            if (img)
            {
                bg_w = img->width;
                bg_h = img->height;
            }
        }
        video_color_t bg_color = style->has_background ? style->background : 0;
        int bg_trans = (!style->has_background || style->background_transparent) ? 1 : 0;
        serial_printf("[html_view][acid2] float=%s display=%d position=%d float=%d clear=%d content=%dx%d border_box=%dx%d margin=%d,%d,%d,%d padding=%d,%d,%d,%d border=%d,%d,%d,%d bg=%08X bg_trans=%d bg_img=%d bg_hash=%08X bg_size=%dx%d bg_attach=%d bg_repeat=%d bg_pos=%d,%d side=%d z=%d",
                      debug_label,
                      display,
                      position,
                      float_mode,
                      clear_mode,
                      content_w,
                      content_h,
                      border_box_w,
                      border_box_h,
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
                      bg_color,
                      bg_trans,
                      bg_has_img ? 1 : 0,
                      bg_hash,
                      bg_w,
                      bg_h,
                      bg_attach,
                      bg_repeat,
                      bg_pos_x,
                      bg_pos_y,
                      (int)side,
                      ctx->z_index);
    }

    int place_y = float_start_y;
    int place_x = ctx->body_x;
    int container_w = ctx->body_w;
    if (container_w < 0) container_w = 0;

    for (int it = 0; it < 256; ++it)
    {
        int left = ctx->body_x;
        int right = ctx->body_x + container_w;
        html_view_float_bounds_at_y(ctx->floats, place_y, ctx->body_x, container_w, &left, &right);
        int avail = right - left;
        if (outer_w <= avail)
        {
            if (side == CSS_FLOAT_RIGHT)
            {
                place_x = right - outer_w;
            }
            else
            {
                place_x = left;
            }
            break;
        }
        place_y = html_view_float_next_y(ctx->floats, place_y);
    }

    if (debug_label && ctx->record)
    {
        serial_printf("[html_view][layout] floatplace=%s x=%d y=%d outer=%dx%d border_box=%dx%d margin=%d,%d,%d,%d side=%d body_x=%d body_w=%d",
                      debug_label,
                      place_x,
                      place_y,
                      outer_w,
                      outer_h,
                      border_box_w,
                      border_box_h,
                      margin_top,
                      margin_right,
                      margin_bottom,
                      margin_left,
                      (int)side,
                      ctx->body_x,
                      ctx->body_w);
    }

    if (ctx->floats && ctx->floats->count < (sizeof(ctx->floats->items) / sizeof(ctx->floats->items[0])))
    {
        ctx->floats->items[ctx->floats->count++] = (html_view_float_t){
            .x = place_x,
            .y = place_y,
            .w = outer_w,
            .h = outer_h,
            .side = side,
        };
    }

    int outer_bottom = place_y + outer_h;
    if (outer_bottom > ctx->content_bottom)
    {
        ctx->content_bottom = outer_bottom;
    }

    int border_box_x = place_x + margin_left;
    int border_box_y = place_y + margin_top;
    if (measuring)
    {
        border_box_x = ctx->body_x + margin_left;
        border_box_y = ctx->y + margin_top;
    }
    int draw_y = html_view_draw_y(ctx, border_box_y);

    int measure_edge = (ctx->draw || ctx->record) ? (border_box_x + border_box_w) : (ctx->body_x + outer_w);
    if (measure_edge > ctx->measure_max_x)
    {
        ctx->measure_max_x = measure_edge;
    }

    if (ctx->draw || ctx->record)
    {
        if (style->has_background && !style->background_transparent)
        {
            html_view_draw_rect_clipped(ctx, border_box_x, draw_y, border_box_w, border_box_h, style->background, &ctx->clip);
        }
        if (debug_label && ctx->record && style->has_background_image && style->background_image)
        {
            int bg_pos_x = 0;
            int bg_pos_y = 0;
            if (style->has_background_position)
            {
                bg_pos_x = html_view_length_to_px_signed(&style->background_pos_x,
                                                         ctx->viewport_w,
                                                         ctx->viewport_h,
                                                         border_box_w,
                                                         border_box_h,
                                                         ctx->base_font_px,
                                                         true);
                bg_pos_y = html_view_length_to_px_signed(&style->background_pos_y,
                                                         ctx->viewport_w,
                                                         ctx->viewport_h,
                                                         border_box_w,
                                                         border_box_h,
                                                         ctx->base_font_px,
                                                         false);
            }
            int bg_repeat = style->has_background_repeat ? (int)style->background_repeat : -1;
            bool fixed = style->has_background_attachment &&
                         style->background_attachment == CSS_BACKGROUND_ATTACHMENT_FIXED;
            bool element_fixed = style->has_position &&
                                 style->position == CSS_POSITION_FIXED;
            int origin_x = fixed ? (ctx->viewport_x + bg_pos_x) : (border_box_x + bg_pos_x);
            int origin_y = fixed ? (ctx->viewport_y + bg_pos_y) : (draw_y + bg_pos_y);
            int bg_w = 0;
            int bg_h = 0;
            if (ctx->priv)
            {
                html_view_image_t *img = html_view_image_find(ctx->priv, style->background_image);
                if (!img)
                {
                    (void)html_view_try_load_data_image_locked(ctx->priv, style->background_image);
                    img = html_view_image_find(ctx->priv, style->background_image);
                }
                if (img)
                {
                    bg_w = img->width;
                    bg_h = img->height;
                }
            }
            serial_printf("[html_view][acid2-bg] float=%s border=%d,%d %dx%d draw_y=%d pos=%d,%d origin=%d,%d fixed=%d element_fixed=%d repeat=%d clip=%d,%d %dx%d img=%dx%d",
                          debug_label,
                          border_box_x,
                          border_box_y,
                          border_box_w,
                          border_box_h,
                          draw_y,
                          bg_pos_x,
                          bg_pos_y,
                          origin_x,
                          origin_y,
                          fixed ? 1 : 0,
                          element_fixed ? 1 : 0,
                          bg_repeat,
                          ctx->clip.x,
                          ctx->clip.y,
                          ctx->clip.width,
                          ctx->clip.height,
                          bg_w,
                          bg_h);
        }
        html_view_draw_background_image(ctx, style, border_box_x, border_box_y, border_box_w, border_box_h);

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
    }

    int saved_body_x = ctx->body_x;
    int saved_body_w = ctx->body_w;
    int saved_max_x = ctx->max_x;
    int saved_x = ctx->x;
    int saved_y = ctx->y;
    bool saved_pending = ctx->pending_space;
    video_color_t saved_bg = ctx->bg;
    html_view_float_ctx_t *saved_floats = ctx->floats;
    css_text_align_t saved_align = ctx->text_align_mode;
    size_t saved_line_op_start = ctx->line_op_start;
    int saved_line_start_x = ctx->line_start_x;
    int saved_line_start_y = ctx->line_start_y;
    int saved_height_basis = ctx->height_basis;
    bool saved_height_basis_valid = ctx->height_basis_valid;
    bool saved_height_basis_explicit = ctx->height_basis_explicit;

    html_view_float_ctx_t *inner_floats = (html_view_float_ctx_t *)calloc(1, sizeof(*inner_floats));
    ctx->floats = inner_floats ? inner_floats : saved_floats;

    ctx->body_x = border_box_x + border_left + pad_left;
    ctx->body_w = content_w;
    ctx->max_x = ctx->body_x + content_w;
    ctx->height_basis_valid = height_basis_valid;
    ctx->height_basis = height_basis_valid ? height_basis : 0;
    ctx->height_basis_explicit = height_basis_valid;
    ctx->x = ctx->body_x;
    ctx->y = border_box_y + border_top + pad_top;
    ctx->pending_space = false;
    html_view_margin_state_reset(&ctx->pending_margin);
    if (style->has_background && !style->background_transparent)
    {
        ctx->bg = style->background;
    }
    ctx->text_align_mode = style->has_text_align ? style->text_align : ctx->text_align_mode;
    ctx->line_start_x = ctx->x;
    ctx->line_start_y = ctx->y;
    ctx->line_op_start = (ctx->record && ctx->priv) ? ctx->priv->render_cache.op_count : 0;

    html_view_render_children(ctx, node, style);
    html_view_align_current_line(ctx);

    ctx->floats = saved_floats;
    free(inner_floats);
    ctx->bg = saved_bg;
    ctx->body_x = saved_body_x;
    ctx->body_w = saved_body_w;
    ctx->max_x = saved_max_x;
    ctx->x = saved_x;
    ctx->y = saved_y;
    ctx->pending_space = saved_pending;
    ctx->line_height = saved_line_height;
    ctx->text_align_mode = saved_align;
    ctx->line_op_start = saved_line_op_start;
    ctx->line_start_x = saved_line_start_x;
    ctx->line_start_y = saved_line_start_y;
    ctx->height_basis = saved_height_basis;
    ctx->height_basis_valid = saved_height_basis_valid;
    ctx->height_basis_explicit = saved_height_basis_explicit;
    ctx->pending_margin = saved_pending_margin;
    ctx->paint_layer = saved_layer;
}

void html_view_render_table(html_view_ctx_t *ctx,
                            const html_node_t *node,
                            const css_style_t *style,
                            const css_style_t *parent_style)
{
    if (!ctx || !node || !style)
    {
        return;
    }

    if (ctx->x != ctx->body_x)
    {
        html_view_new_line(ctx);
    }

    html_view_table_layout_t layout = {0};
    layout.cellpadding = html_view_attr_to_int(node, "cellpadding", 0);
    layout.cellspacing = html_view_attr_to_int(node, "cellspacing", 0);
    if (layout.cellpadding < 0) layout.cellpadding = 0;
    if (layout.cellspacing < 0) layout.cellspacing = 0;

    layout.margin_top = 0;
    layout.margin_right = 0;
    layout.margin_bottom = 0;
    layout.margin_left = 0;
    if (style->has_margin)
    {
        if (style->margin.top.valid && !style->margin.top.is_auto)
        {
            layout.margin_top = html_view_length_to_px_signed(&style->margin.top,
                                                              ctx->viewport_w,
                                                              ctx->viewport_h,
                                                              ctx->body_w,
                                                              ctx->viewport_h,
                                                              ctx->base_font_px,
                                                              true);
        }
        if (style->margin.right.valid && !style->margin.right.is_auto)
        {
            layout.margin_right = html_view_length_to_px_signed(&style->margin.right,
                                                                ctx->viewport_w,
                                                                ctx->viewport_h,
                                                                ctx->body_w,
                                                                ctx->viewport_h,
                                                                ctx->base_font_px,
                                                                true);
        }
        if (style->margin.bottom.valid && !style->margin.bottom.is_auto)
        {
            layout.margin_bottom = html_view_length_to_px_signed(&style->margin.bottom,
                                                                 ctx->viewport_w,
                                                                 ctx->viewport_h,
                                                                 ctx->body_w,
                                                                 ctx->viewport_h,
                                                                 ctx->base_font_px,
                                                                 true);
        }
        if (style->margin.left.valid && !style->margin.left.is_auto)
        {
            layout.margin_left = html_view_length_to_px_signed(&style->margin.left,
                                                               ctx->viewport_w,
                                                               ctx->viewport_h,
                                                               ctx->body_w,
                                                               ctx->viewport_h,
                                                               ctx->base_font_px,
                                                               true);
        }
    }
    layout.pad_top = 0;
    layout.pad_right = 0;
    layout.pad_bottom = 0;
    layout.pad_left = 0;
    if (style->has_padding)
    {
        layout.pad_top = html_view_length_to_px(&style->padding.top,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                ctx->body_w,
                                                ctx->viewport_h,
                                                ctx->base_font_px,
                                                true);
        layout.pad_right = html_view_length_to_px(&style->padding.right,
                                                  ctx->viewport_w,
                                                  ctx->viewport_h,
                                                  ctx->body_w,
                                                  ctx->viewport_h,
                                                  ctx->base_font_px,
                                                  true);
        layout.pad_bottom = html_view_length_to_px(&style->padding.bottom,
                                                   ctx->viewport_w,
                                                   ctx->viewport_h,
                                                   ctx->body_w,
                                                   ctx->viewport_h,
                                                   ctx->base_font_px,
                                                   true);
        layout.pad_left = html_view_length_to_px(&style->padding.left,
                                                 ctx->viewport_w,
                                                 ctx->viewport_h,
                                                 ctx->body_w,
                                                 ctx->viewport_h,
                                                 ctx->base_font_px,
                                                 true);
    }
    if (layout.pad_top < 0) layout.pad_top = 0;
    if (layout.pad_right < 0) layout.pad_right = 0;
    if (layout.pad_bottom < 0) layout.pad_bottom = 0;
    if (layout.pad_left < 0) layout.pad_left = 0;

    layout.border_top = 0;
    layout.border_right = 0;
    layout.border_bottom = 0;
    layout.border_left = 0;
    if (style->has_border)
    {
        layout.border_top = html_view_length_to_px(&style->border_width.top,
                                                   ctx->viewport_w,
                                                   ctx->viewport_h,
                                                   ctx->body_w,
                                                   ctx->viewport_h,
                                                   ctx->base_font_px,
                                                   false);
        layout.border_right = html_view_length_to_px(&style->border_width.right,
                                                     ctx->viewport_w,
                                                     ctx->viewport_h,
                                                     ctx->body_w,
                                                     ctx->viewport_h,
                                                     ctx->base_font_px,
                                                     true);
        layout.border_bottom = html_view_length_to_px(&style->border_width.bottom,
                                                      ctx->viewport_w,
                                                      ctx->viewport_h,
                                                      ctx->body_w,
                                                      ctx->viewport_h,
                                                      ctx->base_font_px,
                                                      false);
        layout.border_left = html_view_length_to_px(&style->border_width.left,
                                                    ctx->viewport_w,
                                                    ctx->viewport_h,
                                                    ctx->body_w,
                                                    ctx->viewport_h,
                                                    ctx->base_font_px,
                                                    true);
    }
    if (layout.border_top < 0) layout.border_top = 0;
    if (layout.border_right < 0) layout.border_right = 0;
    if (layout.border_bottom < 0) layout.border_bottom = 0;
    if (layout.border_left < 0) layout.border_left = 0;
    html_view_apply_border_style_none(style, &layout.border_top, &layout.border_right, &layout.border_bottom, &layout.border_left);

    layout.content_w = ctx->body_w;
    if (style->has_width && style->width.valid && !style->width.is_auto)
    {
        int w = html_view_length_to_px(&style->width,
                                       ctx->viewport_w,
                                       ctx->viewport_h,
                                       ctx->body_w,
                                       ctx->viewport_h,
                                       ctx->base_font_px,
                                       true);
        if (w > 0)
        {
            layout.content_w = w;
        }
    }
    if (layout.content_w < 0)
    {
        layout.content_w = 0;
    }
    if (layout.content_w > ctx->body_w)
    {
        layout.content_w = ctx->body_w;
    }

    int table_box_w = layout.content_w + layout.pad_left + layout.pad_right + layout.border_left + layout.border_right;

    int base_x = ctx->body_x + layout.margin_left;
    bool centered = false;
    if (style->has_margin)
    {
        bool auto_left = style->margin.left.valid && style->margin.left.is_auto;
        bool auto_right = style->margin.right.valid && style->margin.right.is_auto;
        if (auto_left && auto_right)
        {
            centered = true;
        }
    }
    if (!centered && parent_style && parent_style->has_text_align && parent_style->text_align == CSS_TEXT_ALIGN_CENTER)
    {
        centered = true;
    }
    if (centered && table_box_w < ctx->body_w)
    {
        base_x = ctx->body_x + (ctx->body_w - table_box_w) / 2;
    }

    layout.table_x = base_x;
    int used_top = layout.margin_top;
    if (ctx->pending_margin.valid)
    {
        html_view_margin_state_t collapsed = html_view_margin_state_from_value(layout.margin_top);
        html_view_margin_state_merge(&collapsed, &ctx->pending_margin);
        used_top = html_view_margin_state_value(&collapsed);
        html_view_margin_state_reset(&ctx->pending_margin);
    }
    ctx->y += used_top;
    layout.table_y = ctx->y;

    const html_node_t *child = node->first_child;
    while (child)
    {
        if (child->type == HTML_NODE_ELEMENT && child->name)
        {
            if (strcmp(child->name, "tr") == 0)
            {
                if (!html_view_table_layout_add_row(&layout, child, style, ctx))
                {
                    html_view_table_layout_destroy(&layout);
                    return;
                }
            }
            else if (strcmp(child->name, "tbody") == 0 || strcmp(child->name, "thead") == 0 || strcmp(child->name, "tfoot") == 0)
            {
                for (const html_node_t *row = child->first_child; row; row = row->next_sibling)
                {
                    if (row->type == HTML_NODE_ELEMENT && row->name && strcmp(row->name, "tr") == 0)
                    {
                        if (!html_view_table_layout_add_row(&layout, row, style, ctx))
                        {
                            html_view_table_layout_destroy(&layout);
                            return;
                        }
                    }
                }
            }
        }
        child = child->next_sibling;
    }

    int col_count = 0;
    for (size_t r = 0; r < layout.row_count; ++r)
    {
        int cols = 0;
        for (size_t c = 0; c < layout.rows[r].cell_count; ++c)
        {
            cols += layout.rows[r].cells[c].colspan > 0 ? layout.rows[r].cells[c].colspan : 1;
        }
        if (cols > col_count)
        {
            col_count = cols;
        }
    }
    layout.col_count = col_count;
    if (layout.col_count <= 0)
    {
        if (ctx->draw || ctx->record)
        {
            html_view_render_children(ctx, node, style);
        }
        html_view_table_layout_destroy(&layout);
        return;
    }

    layout.col_w = (int *)calloc((size_t)layout.col_count, sizeof(*layout.col_w));
    if (!layout.col_w)
    {
        html_view_table_layout_destroy(&layout);
        return;
    }

    for (size_t r = 0; r < layout.row_count; ++r)
    {
        int col = 0;
        for (size_t c = 0; c < layout.rows[r].cell_count; ++c)
        {
            html_view_table_cell_layout_t *cell = &layout.rows[r].cells[c];
            int colspan = cell->colspan > 0 ? cell->colspan : 1;
            int cell_font_px = html_view_font_px_for_style(ctx, &cell->style, ctx->base_font_px);
            if (cell_font_px <= 0)
            {
                cell_font_px = ctx->base_font_px;
            }

            int desired_content_w = 0;
            if (cell->style.has_width && cell->style.width.valid && !cell->style.width.is_auto)
            {
                desired_content_w = html_view_length_to_px(&cell->style.width,
                                                          ctx->viewport_w,
                                                          ctx->viewport_h,
                                                          layout.content_w,
                                                          ctx->viewport_h,
                                                          cell_font_px,
                                                          true);
            }
            else
            {
                html_view_ctx_t measure_cell_ctx = *ctx;
                measure_cell_ctx.measure_shrink = true;
                measure_cell_ctx.base_font_px = cell_font_px;
                measure_cell_ctx.actual_font_px = cell_font_px;
                measure_cell_ctx.line_height = html_view_line_height_for_style(&measure_cell_ctx, &cell->style);
                measure_cell_ctx.space_w = html_view_text_width(&measure_cell_ctx, " ");
                measure_cell_ctx.underline_run_active = false;
                measure_cell_ctx.underline_run_start_x = 0;
                html_view_margin_state_reset(&measure_cell_ctx.pending_margin);
                desired_content_w = html_view_measure_rendered_width(&measure_cell_ctx, cell->node, &cell->style, layout.content_w, NULL);
            }
            if (desired_content_w < 0) desired_content_w = 0;

            int pad_l = layout.cellpadding;
            int pad_r = layout.cellpadding;
            if (cell->style.has_padding)
            {
                pad_l += html_view_length_to_px(&cell->style.padding.left,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                layout.content_w,
                                                ctx->viewport_h,
                                                cell_font_px,
                                                true);
                pad_r += html_view_length_to_px(&cell->style.padding.right,
                                                ctx->viewport_w,
                                                ctx->viewport_h,
                                                layout.content_w,
                                                ctx->viewport_h,
                                                cell_font_px,
                                                true);
            }
            if (pad_l < 0) pad_l = 0;
            if (pad_r < 0) pad_r = 0;

            int border_l = 0;
            int border_r = 0;
            if (cell->style.has_border)
            {
                border_l = html_view_length_to_px(&cell->style.border_width.left,
                                                  ctx->viewport_w,
                                                  ctx->viewport_h,
                                                  layout.content_w,
                                                  ctx->viewport_h,
                                                  cell_font_px,
                                                  true);
                border_r = html_view_length_to_px(&cell->style.border_width.right,
                                                  ctx->viewport_w,
                                                  ctx->viewport_h,
                                                  layout.content_w,
                                                  ctx->viewport_h,
                                                  cell_font_px,
                                                  true);
                if (border_l < 0) border_l = 0;
                if (border_r < 0) border_r = 0;
            }

            int desired_total_w = desired_content_w + pad_l + pad_r + border_l + border_r;
            if (desired_total_w < 0) desired_total_w = 0;

            if (colspan == 1 && col < layout.col_count)
            {
                if (desired_total_w > layout.col_w[col])
                {
                    layout.col_w[col] = desired_total_w;
                }
            }
            col += colspan;
        }
    }

    int total_cols = 0;
    for (int i = 0; i < layout.col_count; ++i)
    {
        if (layout.col_w[i] < 0) layout.col_w[i] = 0;
        total_cols += layout.col_w[i];
    }
    int gaps = layout.cellspacing * (layout.col_count > 0 ? (layout.col_count - 1) : 0);
    int total_w = total_cols + gaps;
    if (total_w < layout.content_w)
    {
        layout.col_w[layout.col_count - 1] += layout.content_w - total_w;
    }
    else if (total_w > layout.content_w)
    {
        int over = total_w - layout.content_w;
        if (layout.col_w[layout.col_count - 1] > over)
        {
            layout.col_w[layout.col_count - 1] -= over;
        }
    }

    int rows_y0 = layout.table_y + layout.border_top + layout.pad_top + layout.cellspacing;
    int y_cursor = rows_y0;
    for (size_t r = 0; r < layout.row_count; ++r)
    {
        html_view_table_row_layout_t *row = &layout.rows[r];
        row->y = y_cursor;
        int row_h = row->min_h;

        int x_cursor = layout.table_x + layout.border_left + layout.pad_left + layout.cellspacing;
        int col = 0;
        for (size_t c = 0; c < row->cell_count; ++c)
        {
            html_view_table_cell_layout_t *cell = &row->cells[c];
            int colspan = cell->colspan > 0 ? cell->colspan : 1;

            int cell_w = 0;
            for (int k = 0; k < colspan && (col + k) < layout.col_count; ++k)
            {
                cell_w += layout.col_w[col + k];
            }
            if (cell_w < 0) cell_w = 0;

            cell->x = x_cursor;
            cell->y = row->y;
            cell->w = cell_w;

            int cell_font_px = html_view_font_px_for_style(ctx, &cell->style, ctx->base_font_px);
            if (cell_font_px <= 0)
            {
                cell_font_px = ctx->base_font_px;
            }

            cell->pad_top = layout.cellpadding;
            cell->pad_right = layout.cellpadding;
            cell->pad_bottom = layout.cellpadding;
            cell->pad_left = layout.cellpadding;
            if (cell->style.has_padding)
            {
                cell->pad_top += html_view_length_to_px(&cell->style.padding.top,
                                                        ctx->viewport_w,
                                                        ctx->viewport_h,
                                                        cell_w,
                                                        ctx->viewport_h,
                                                        cell_font_px,
                                                        true);
                cell->pad_right += html_view_length_to_px(&cell->style.padding.right,
                                                          ctx->viewport_w,
                                                          ctx->viewport_h,
                                                          cell_w,
                                                          ctx->viewport_h,
                                                          cell_font_px,
                                                          true);
                cell->pad_bottom += html_view_length_to_px(&cell->style.padding.bottom,
                                                           ctx->viewport_w,
                                                           ctx->viewport_h,
                                                           cell_w,
                                                           ctx->viewport_h,
                                                           cell_font_px,
                                                           true);
                cell->pad_left += html_view_length_to_px(&cell->style.padding.left,
                                                         ctx->viewport_w,
                                                         ctx->viewport_h,
                                                         cell_w,
                                                         ctx->viewport_h,
                                                         cell_font_px,
                                                         true);
            }
            if (cell->pad_top < 0) cell->pad_top = 0;
            if (cell->pad_right < 0) cell->pad_right = 0;
            if (cell->pad_bottom < 0) cell->pad_bottom = 0;
            if (cell->pad_left < 0) cell->pad_left = 0;

            cell->border_top = 0;
            cell->border_right = 0;
            cell->border_bottom = 0;
            cell->border_left = 0;
            if (cell->style.has_border)
            {
                cell->border_top = html_view_length_to_px(&cell->style.border_width.top,
                                                          ctx->viewport_w,
                                                          ctx->viewport_h,
                                                          cell_w,
                                                          ctx->viewport_h,
                                                          cell_font_px,
                                                          false);
                cell->border_right = html_view_length_to_px(&cell->style.border_width.right,
                                                            ctx->viewport_w,
                                                            ctx->viewport_h,
                                                            cell_w,
                                                            ctx->viewport_h,
                                                            cell_font_px,
                                                            true);
                cell->border_bottom = html_view_length_to_px(&cell->style.border_width.bottom,
                                                             ctx->viewport_w,
                                                             ctx->viewport_h,
                                                             cell_w,
                                                             ctx->viewport_h,
                                                             cell_font_px,
                                                             false);
                cell->border_left = html_view_length_to_px(&cell->style.border_width.left,
                                                           ctx->viewport_w,
                                                           ctx->viewport_h,
                                                           cell_w,
                                                           ctx->viewport_h,
                                                           cell_font_px,
                                                           true);
                if (cell->border_top < 0) cell->border_top = 0;
                if (cell->border_right < 0) cell->border_right = 0;
                if (cell->border_bottom < 0) cell->border_bottom = 0;
                if (cell->border_left < 0) cell->border_left = 0;
                html_view_apply_border_style_none(&cell->style,
                                                  &cell->border_top,
                                                  &cell->border_right,
                                                  &cell->border_bottom,
                                                  &cell->border_left);
            }

            cell->content_x = cell->x + cell->border_left + cell->pad_left;
            cell->content_y = cell->y + cell->border_top + cell->pad_top;
            cell->content_w = cell->w - (cell->border_left + cell->border_right + cell->pad_left + cell->pad_right);
            if (cell->content_w < 0) cell->content_w = 0;

            html_view_ctx_t measure = *ctx;
            measure.draw = false;
            measure.record = false;
            measure.record_failed = false;
            measure.floats = NULL;
            measure.style_block = NULL;
            measure.style_depth = 0;
            measure.body_x = cell->content_x;
            measure.body_w = cell->content_w;
            measure.max_x = measure.body_x + measure.body_w;
            measure.x = measure.body_x;
            measure.y = cell->content_y;
            measure.content_bottom = measure.y;
            measure.pending_space = false;
            html_view_margin_state_reset(&measure.pending_margin);
            measure.underline_run_active = false;
            measure.underline_run_start_x = 0;
            measure.list_level = 0;
            measure.base_font_px = cell_font_px;
            measure.actual_font_px = cell_font_px;
            measure.line_height = html_view_line_height_for_style(&measure, &cell->style);
            measure.space_w = html_view_text_width(&measure, " ");
            html_view_trace_note_measure(HTML_VIEW_TRACE_MEASURE_TABLE);
            html_view_render_children(&measure, cell->node, &cell->style);
            html_view_style_stack_destroy(&measure);

            int content_h = measure.content_bottom - cell->content_y;
            if (content_h < 0) content_h = 0;
            if (cell->style.has_height && cell->style.height.valid && !cell->style.height.is_auto)
            {
                int h = html_view_length_to_px(&cell->style.height,
                                               ctx->viewport_w,
                                               ctx->viewport_h,
                                               cell->w,
                                               ctx->viewport_h,
                                               cell_font_px,
                                               false);
                if (h > content_h)
                {
                    content_h = h;
                }
            }

            int cell_h = content_h + cell->pad_top + cell->pad_bottom + cell->border_top + cell->border_bottom;
            if (cell_h > row_h)
            {
                row_h = cell_h;
            }

            col += colspan;
            x_cursor += cell->w;
            if (c + 1 < row->cell_count)
            {
                x_cursor += layout.cellspacing;
            }
        }

        row->h = row_h;
        for (size_t c = 0; c < row->cell_count; ++c)
        {
            row->cells[c].h = row_h;
        }

        y_cursor += row_h + layout.cellspacing;
    }

    int y_end = y_cursor;
    layout.table_h = (y_end - layout.table_y) + layout.pad_bottom + layout.border_bottom;

    if (ctx->draw || ctx->record)
    {
        if (style->has_background && !style->background_transparent && table_box_w > 0 && layout.table_h > 0)
        {
            int draw_y = html_view_draw_y(ctx, layout.table_y);
            html_view_draw_rect_clipped(ctx, layout.table_x, draw_y, table_box_w, layout.table_h, style->background, &ctx->clip);
        }
        html_view_draw_background_image(ctx, style, layout.table_x, layout.table_y, table_box_w, layout.table_h);

        if (style->has_border && (layout.border_top > 0 || layout.border_right > 0 || layout.border_bottom > 0 || layout.border_left > 0))
        {
            int draw_y = html_view_draw_y(ctx, layout.table_y);
            html_view_draw_border_sides_clipped(ctx,
                                                layout.table_x,
                                                draw_y,
                                                table_box_w,
                                                layout.table_h,
                                                layout.border_top,
                                                layout.border_right,
                                                layout.border_bottom,
                                                layout.border_left,
                                                style,
                                                &ctx->clip);
        }

        for (size_t r = 0; r < layout.row_count; ++r)
        {
            html_view_table_row_layout_t *row = &layout.rows[r];
            for (size_t c = 0; c < row->cell_count; ++c)
            {
                html_view_table_cell_layout_t *cell = &row->cells[c];
                if (cell->w <= 0 || cell->h <= 0)
                {
                    continue;
                }

                int cell_draw_y = html_view_draw_y(ctx, cell->y);
                if (cell->style.has_background && !cell->style.background_transparent)
                {
                    html_view_draw_rect_clipped(ctx, cell->x, cell_draw_y, cell->w, cell->h, cell->style.background, &ctx->clip);
                }
                if (cell->style.has_border && (cell->border_top > 0 || cell->border_right > 0 || cell->border_bottom > 0 || cell->border_left > 0))
                {
                    html_view_draw_border_sides_clipped(ctx,
                                                        cell->x,
                                                        cell_draw_y,
                                                        cell->w,
                                                        cell->h,
                                                        cell->border_top,
                                                        cell->border_right,
                                                        cell->border_bottom,
                                                        cell->border_left,
                                                        &cell->style,
                                                        &ctx->clip);
                }

                html_view_ctx_t inner = *ctx;
                inner.underline_run_active = false;
                inner.underline_run_start_x = 0;
                inner.floats = NULL;
                inner.style_block = NULL;
                inner.style_depth = 0;
                inner.body_x = cell->content_x;
                inner.body_w = cell->content_w;
                inner.max_x = inner.body_x + inner.body_w;
                inner.x = inner.body_x;
                inner.y = cell->content_y;
                inner.content_bottom = inner.y;
                inner.pending_space = false;
                html_view_margin_state_reset(&inner.pending_margin);
                inner.list_level = 0;
                inner.bg = (cell->style.has_background && !cell->style.background_transparent) ? cell->style.background : ctx->bg;
                inner.measure_max_x = inner.x;
                inner.text_align_mode = cell->style.has_text_align ? cell->style.text_align : ctx->text_align_mode;
                inner.line_start_x = inner.x;
                inner.line_start_y = inner.y;
                inner.line_op_start = (inner.record && inner.priv) ? inner.priv->render_cache.op_count : 0;
                int cell_font_px = html_view_font_px_for_style(&inner, &cell->style, inner.base_font_px);
                if (cell_font_px > 0)
                {
                    inner.base_font_px = cell_font_px;
                    inner.actual_font_px = cell_font_px;
                }
                inner.line_height = html_view_line_height_for_style(&inner, &cell->style);
                inner.space_w = html_view_text_width(&inner, " ");

                html_view_render_children(&inner, cell->node, &cell->style);
                html_view_align_current_line(&inner);
                if (inner.record_failed)
                {
                    ctx->record_failed = true;
                }
                html_view_style_stack_destroy(&inner);
                if (ctx->record_failed)
                {
                    break;
                }
            }
            if (ctx->record_failed)
            {
                break;
            }
        }
    }

    int bottom = layout.table_y + layout.table_h;
    if (bottom > ctx->y)
    {
        ctx->y = bottom;
    }
    ctx->x = ctx->body_x;
    ctx->pending_space = false;
    ctx->pending_margin = html_view_margin_state_from_value(layout.margin_bottom);
    ctx->line_start_x = ctx->x;
    ctx->line_start_y = ctx->y;
    ctx->line_op_start = (ctx->record && ctx->priv) ? ctx->priv->render_cache.op_count : 0;
    html_view_ensure_line_visible(ctx);

    html_view_table_layout_destroy(&layout);
}
