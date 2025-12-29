#include "atk/html_view/html_view_internal.h"

#include "ctype.h"

static void html_view_trim_range(const char **start, const char **end)
{
    if (!start || !end || !*start || !*end)
    {
        return;
    }
    while (*start < *end && isspace((unsigned char)**start))
    {
        (*start)++;
    }
    while (*end > *start && isspace((unsigned char)(*end)[-1]))
    {
        (*end)--;
    }
}

static bool html_view_node_has_class(const html_node_t *node, const char *cls_start, size_t cls_len)
{
    if (!node || node->type != HTML_NODE_ELEMENT || !cls_start || cls_len == 0)
    {
        return false;
    }
    const char *classes = html_attr_get(node, "class");
    if (!classes || classes[0] == '\0')
    {
        return false;
    }

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
        if (len == cls_len && strncasecmp(start, cls_start, cls_len) == 0)
        {
            return true;
        }
    }

    return false;
}

static bool html_view_simple_selector_matches_range(const char *sel_start,
                                                    const char *sel_end,
                                                    const html_node_t *node)
{
    if (!sel_start || !sel_end || sel_end <= sel_start || !node || node->type != HTML_NODE_ELEMENT || !node->name)
    {
        return false;
    }

    html_view_trim_range(&sel_start, &sel_end);
    if (sel_end <= sel_start)
    {
        return false;
    }

    const char *p = sel_start;
    bool have_tag = false;
    bool match = true;

    if (*p == '*')
    {
        ++p;
    }
    else if (*p != '#' && *p != '.')
    {
        const char *tag_end = p;
        while (tag_end < sel_end && *tag_end != ':' && *tag_end != '.' && *tag_end != '#' && *tag_end != '[' && !isspace((unsigned char)*tag_end))
        {
            tag_end++;
        }
        size_t tag_len = (size_t)(tag_end - p);
        if (tag_len == 0 || strlen(node->name) != tag_len || strncasecmp(node->name, p, tag_len) != 0)
        {
            match = false;
        }
        have_tag = true;
        p = tag_end;
    }

    (void)have_tag;

    while (match && p < sel_end)
    {
        if (*p == '.')
        {
            ++p;
            const char *cls_end = p;
            while (cls_end < sel_end && *cls_end != ':' && *cls_end != '.' && *cls_end != '#' && *cls_end != '[' && !isspace((unsigned char)*cls_end))
            {
                cls_end++;
            }
            size_t cls_len = (size_t)(cls_end - p);
            if (cls_len == 0 || !html_view_node_has_class(node, p, cls_len))
            {
                match = false;
                break;
            }
            p = cls_end;
            continue;
        }

        if (*p == '#')
        {
            ++p;
            const char *id_end = p;
            while (id_end < sel_end && *id_end != ':' && *id_end != '.' && *id_end != '#' && *id_end != '[' && !isspace((unsigned char)*id_end))
            {
                id_end++;
            }
            size_t id_len = (size_t)(id_end - p);
            const char *id = (id_len > 0) ? html_attr_get(node, "id") : NULL;
            if (!id || strlen(id) != id_len || strncasecmp(id, p, id_len) != 0)
            {
                match = false;
                break;
            }
            p = id_end;
            continue;
        }

        if (*p == ':' || *p == '[' || isspace((unsigned char)*p))
        {
            break;
        }

        ++p;
    }

    return match;
}

static bool html_view_selector_matches(const char *selector, const html_node_t *node)
{
    if (!selector || !node || node->type != HTML_NODE_ELEMENT)
    {
        return false;
    }

    const char *start = selector;
    const char *end = selector + strlen(selector);
    html_view_trim_range(&start, &end);
    if (end <= start)
    {
        return false;
    }

    /* Very small selector subset: tag, .class, #id, tag.class, tag#id, and a single descendant "A B". */
    const char *last_space = NULL;
    for (const char *p = start; p < end; ++p)
    {
        if (isspace((unsigned char)*p))
        {
            last_space = p;
        }
    }

    if (!last_space)
    {
        return html_view_simple_selector_matches_range(start, end, node);
    }

    const char *target_start = last_space;
    while (target_start < end && isspace((unsigned char)*target_start))
    {
        target_start++;
    }
    if (!html_view_simple_selector_matches_range(target_start, end, node))
    {
        return false;
    }

    const char *ancestor_end = last_space;
    html_view_trim_range(&start, &ancestor_end);
    if (ancestor_end <= start)
    {
        return false;
    }

    const char *ancestor_start = ancestor_end;
    while (ancestor_start > start && !isspace((unsigned char)ancestor_start[-1]))
    {
        ancestor_start--;
    }

    for (const html_node_t *p = node->parent; p; p = p->parent)
    {
        if (html_view_simple_selector_matches_range(ancestor_start, ancestor_end, p))
        {
            return true;
        }
    }
    return false;
}

static bool html_view_parse_color(const char *s, video_color_t *out)
{
    if (!s || !out || s[0] == '\0')
    {
        return false;
    }

    const char *start = s;
    while (*start && isspace((unsigned char)*start))
    {
        ++start;
    }
    const char *end = start + strlen(start);
    while (end > start && isspace((unsigned char)end[-1]))
    {
        --end;
    }
    if (end <= start)
    {
        return false;
    }

    if (*start == '#')
    {
        ++start;
        size_t len = (size_t)(end - start);
        if (len != 3 && len != 6)
        {
            return false;
        }

        uint32_t value = 0;
        for (size_t i = 0; i < len; ++i)
        {
            unsigned char c = (unsigned char)start[i];
            uint32_t d = 0;
            if (c >= '0' && c <= '9')
            {
                d = (uint32_t)(c - '0');
            }
            else if (c >= 'a' && c <= 'f')
            {
                d = 10u + (uint32_t)(c - 'a');
            }
            else if (c >= 'A' && c <= 'F')
            {
                d = 10u + (uint32_t)(c - 'A');
            }
            else
            {
                return false;
            }
            value = (value << 4) | d;
        }

        if (len == 3)
        {
            uint8_t r = (uint8_t)(((value >> 8) & 0xFu) * 17u);
            uint8_t g = (uint8_t)(((value >> 4) & 0xFu) * 17u);
            uint8_t b = (uint8_t)(((value >> 0) & 0xFu) * 17u);
            *out = video_make_color(r, g, b);
            return true;
        }

        uint8_t r = (uint8_t)((value >> 16) & 0xFFu);
        uint8_t g = (uint8_t)((value >> 8) & 0xFFu);
        uint8_t b = (uint8_t)((value >> 0) & 0xFFu);
        *out = video_make_color(r, g, b);
        return true;
    }

    size_t len = (size_t)(end - start);
    if (len == 5 && strncasecmp(start, "black", 5) == 0)
    {
        *out = video_make_color(0x00, 0x00, 0x00);
        return true;
    }
    if (len == 5 && strncasecmp(start, "white", 5) == 0)
    {
        *out = video_make_color(0xFF, 0xFF, 0xFF);
        return true;
    }
    if (len == 6 && strncasecmp(start, "silver", 6) == 0)
    {
        *out = video_make_color(0xC0, 0xC0, 0xC0);
        return true;
    }
    if ((len == 4 && strncasecmp(start, "gray", 4) == 0) ||
        (len == 4 && strncasecmp(start, "grey", 4) == 0))
    {
        *out = video_make_color(0x80, 0x80, 0x80);
        return true;
    }
    if (len == 6 && strncasecmp(start, "maroon", 6) == 0)
    {
        *out = video_make_color(0x80, 0x00, 0x00);
        return true;
    }
    if (len == 3 && strncasecmp(start, "red", 3) == 0)
    {
        *out = video_make_color(0xFF, 0x00, 0x00);
        return true;
    }
    if (len == 6 && strncasecmp(start, "purple", 6) == 0)
    {
        *out = video_make_color(0x80, 0x00, 0x80);
        return true;
    }
    if (len == 7 && strncasecmp(start, "fuchsia", 7) == 0)
    {
        *out = video_make_color(0xFF, 0x00, 0xFF);
        return true;
    }
    if (len == 5 && strncasecmp(start, "green", 5) == 0)
    {
        *out = video_make_color(0x00, 0x80, 0x00);
        return true;
    }
    if (len == 4 && strncasecmp(start, "lime", 4) == 0)
    {
        *out = video_make_color(0x00, 0xFF, 0x00);
        return true;
    }
    if (len == 5 && strncasecmp(start, "olive", 5) == 0)
    {
        *out = video_make_color(0x80, 0x80, 0x00);
        return true;
    }
    if (len == 6 && strncasecmp(start, "yellow", 6) == 0)
    {
        *out = video_make_color(0xFF, 0xFF, 0x00);
        return true;
    }
    if (len == 4 && strncasecmp(start, "navy", 4) == 0)
    {
        *out = video_make_color(0x00, 0x00, 0x80);
        return true;
    }
    if (len == 4 && strncasecmp(start, "blue", 4) == 0)
    {
        *out = video_make_color(0x00, 0x00, 0xFF);
        return true;
    }
    if (len == 4 && strncasecmp(start, "teal", 4) == 0)
    {
        *out = video_make_color(0x00, 0x80, 0x80);
        return true;
    }
    if (len == 4 && strncasecmp(start, "aqua", 4) == 0)
    {
        *out = video_make_color(0x00, 0xFF, 0xFF);
        return true;
    }
    if (len == 6 && strncasecmp(start, "orange", 6) == 0)
    {
        *out = video_make_color(0xFF, 0xA5, 0x00);
        return true;
    }

    return false;
}

static int html_view_font_size_percent(int size)
{
    static const int sizes[] = {67, 83, 100, 117, 150, 200, 300};
    if (size < 1)
    {
        size = 1;
    }
    if (size > (int)(sizeof(sizes) / sizeof(sizes[0])))
    {
        size = (int)(sizeof(sizes) / sizeof(sizes[0]));
    }
    return sizes[size - 1];
}

static bool html_view_parse_font_size_attr(const char *value, css_length_t *out)
{
    if (!value || !out)
    {
        return false;
    }
    while (*value && isspace((unsigned char)*value))
    {
        ++value;
    }
    if (*value == '\0')
    {
        return false;
    }

    bool relative = false;
    int sign = 1;
    if (*value == '+' || *value == '-')
    {
        relative = true;
        sign = (*value == '-') ? -1 : 1;
        ++value;
    }

    int number = 0;
    bool have_digit = false;
    while (*value && isdigit((unsigned char)*value))
    {
        have_digit = true;
        number = number * 10 + (*value - '0');
        ++value;
    }
    if (!have_digit)
    {
        return false;
    }

    int size = relative ? (3 + sign * number) : number;
    int percent = html_view_font_size_percent(size);
    out->valid = true;
    out->is_auto = false;
    out->value_milli = percent * 1000;
    out->unit = CSS_UNIT_PERCENT;
    return true;
}

static bool html_view_parse_html_length_attr(const char *value, css_length_t *out)
{
    if (!value || !out)
    {
        return false;
    }
    while (*value && isspace((unsigned char)*value))
    {
        ++value;
    }
    if (*value == '\0')
    {
        return false;
    }

    bool percent = false;
    int32_t number = 0;
    bool have_digit = false;
    const char *p = value;
    while (*p && isdigit((unsigned char)*p))
    {
        have_digit = true;
        number = number * 10 + (*p - '0');
        ++p;
        if (number > 1000000)
        {
            break;
        }
    }
    while (*p && isspace((unsigned char)*p))
    {
        ++p;
    }
    if (*p == '%')
    {
        percent = true;
    }

    if (!have_digit)
    {
        return false;
    }

    out->valid = true;
    out->is_auto = false;
    out->value_milli = number * 1000;
    out->unit = percent ? CSS_UNIT_PERCENT : CSS_UNIT_PX;
    return true;
}

static void html_view_apply_presentational_attrs(css_style_t *style, const css_style_t *parent, const html_node_t *node)
{
    (void)parent;
    if (!style || !node || node->type != HTML_NODE_ELEMENT || !node->name)
    {
        return;
    }

    const char *bgcolor = html_attr_get(node, "bgcolor");
    if (bgcolor && bgcolor[0] != '\0' && !style->has_background)
    {
        video_color_t c;
        if (html_view_parse_color(bgcolor, &c))
        {
            style->has_background = true;
            style->background = c;
        }
    }

    const char *color = html_attr_get(node, "color");
    if (color && color[0] != '\0' && !style->has_color)
    {
        video_color_t c;
        if (html_view_parse_color(color, &c))
        {
            style->has_color = true;
            style->color = c;
        }
    }

    const char *w = html_attr_get(node, "width");
    if (w && w[0] != '\0' && !style->has_width)
    {
        css_length_t len = {0};
        if (html_view_parse_html_length_attr(w, &len))
        {
            style->has_width = true;
            style->width = len;
        }
    }

    const char *h = html_attr_get(node, "height");
    if (h && h[0] != '\0' && !style->has_height)
    {
        css_length_t len = {0};
        if (html_view_parse_html_length_attr(h, &len))
        {
            style->has_height = true;
            style->height = len;
        }
    }

    const char *align = html_attr_get(node, "align");
    if (align && align[0] != '\0' && !style->has_text_align)
    {
        if (strcasecmp(align, "center") == 0)
        {
            style->has_text_align = true;
            style->text_align = CSS_TEXT_ALIGN_CENTER;
        }
        else if (strcasecmp(align, "right") == 0)
        {
            style->has_text_align = true;
            style->text_align = CSS_TEXT_ALIGN_RIGHT;
        }
        else if (strcasecmp(align, "left") == 0)
        {
            style->has_text_align = true;
            style->text_align = CSS_TEXT_ALIGN_LEFT;
        }
    }

    if (strcmp(node->name, "table") == 0)
    {
        const char *border = html_attr_get(node, "border");
        if (border && border[0] != '\0' && !style->has_border)
        {
            int b = atoi(border);
            if (b > 0)
            {
                css_length_t px = {
                    .valid = true,
                    .is_auto = false,
                    .value_milli = b * 1000,
                    .unit = CSS_UNIT_PX,
                };
                style->has_border = true;
                style->border_width.top = px;
                style->border_width.right = px;
                style->border_width.bottom = px;
                style->border_width.left = px;
            }
        }

        const char *table_align = html_attr_get(node, "align");
        if (table_align && table_align[0] != '\0' && strcasecmp(table_align, "center") == 0)
        {
            style->has_margin = true;
            style->margin.left.valid = true;
            style->margin.left.is_auto = true;
            style->margin.right.valid = true;
            style->margin.right.is_auto = true;
        }
    }

    if (strcmp(node->name, "center") == 0 && !style->has_text_align)
    {
        style->has_text_align = true;
        style->text_align = CSS_TEXT_ALIGN_CENTER;
    }

    if (strcmp(node->name, "font") == 0)
    {
        const char *size = html_attr_get(node, "size");
        if (size && size[0] != '\0' && !style->has_font_size)
        {
            css_length_t len = {0};
            if (html_view_parse_font_size_attr(size, &len))
            {
                style->has_font_size = true;
                style->font_size = len;
            }
        }
    }
}

static void html_view_apply_inline_style(css_style_t *style, const char *inline_style)
{
    if (!style || !inline_style || inline_style[0] == '\0')
    {
        return;
    }
    size_t len = strlen(inline_style);
    char *buf = (char *)malloc(len + 4);
    if (!buf)
    {
        return;
    }
    memcpy(buf, "x{", 2);
    memcpy(buf + 2, inline_style, len);
    buf[2 + len] = '}';
    buf[3 + len] = '\0';

    css_stylesheet_t *sheet = css_parse(buf);
    free(buf);
    if (!sheet)
    {
        return;
    }
    if (sheet->rules)
    {
        css_style_merge(style, &sheet->rules->style);
    }
    css_stylesheet_destroy(sheet);
}

void html_view_style_for_node(css_style_t *out,
                              const css_stylesheet_t *sheet,
                              const css_style_t *parent,
                              const html_node_t *node)
{
    if (!out)
    {
        return;
    }
    memset(out, 0, sizeof(*out));

    bool is_table_cell = false;
    bool is_table_header = false;
    if (node && node->type == HTML_NODE_ELEMENT && node->name)
    {
        is_table_cell = (strcmp(node->name, "td") == 0 || strcmp(node->name, "th") == 0);
        is_table_header = (strcmp(node->name, "th") == 0);
    }

    if (parent)
    {
        if (parent->has_color)
        {
            out->has_color = true;
            out->color = parent->color;
        }
        if (parent->has_font_size)
        {
            out->has_font_size = true;
            out->font_size = parent->font_size;
        }
        if (parent->has_line_height)
        {
            out->has_line_height = true;
            out->line_height_milli = parent->line_height_milli;
            out->line_height_is_length = parent->line_height_is_length;
            out->line_height = parent->line_height;
        }
        if (parent->has_text_align && !is_table_cell)
        {
            out->has_text_align = true;
            out->text_align = parent->text_align;
        }
        if (parent->has_letter_spacing)
        {
            out->has_letter_spacing = true;
            out->letter_spacing = parent->letter_spacing;
        }
    }

    if (sheet && node && node->type == HTML_NODE_ELEMENT)
    {
        for (const css_rule_t *rule = sheet->rules; rule; rule = rule->next)
        {
            if (rule->selector && html_view_selector_matches(rule->selector, node))
            {
                css_style_merge(out, &rule->style);
            }
        }
    }

    html_view_apply_presentational_attrs(out, parent, node);

    const char *inline_style = html_attr_get(node, "style");
    if (inline_style && inline_style[0] != '\0')
    {
        html_view_apply_inline_style(out, inline_style);
    }

    if (is_table_cell && !out->has_text_align)
    {
        out->has_text_align = true;
        out->text_align = is_table_header ? CSS_TEXT_ALIGN_CENTER : CSS_TEXT_ALIGN_LEFT;
    }
}

void html_view_style_stack_destroy(html_view_ctx_t *ctx)
{
    if (!ctx)
    {
        return;
    }

    html_view_style_block_t *blk = ctx->style_block;
    while (blk)
    {
        html_view_style_block_t *prev = blk->prev;
        free(blk);
        blk = prev;
    }
    ctx->style_block = NULL;
    ctx->style_depth = 0;
}

const css_style_t *html_view_style_push(html_view_ctx_t *ctx, const css_style_t *parent, const html_node_t *node)
{
    if (!ctx)
    {
        return NULL;
    }

    if (!ctx->style_block || ctx->style_block->used >= (sizeof(ctx->style_block->styles) / sizeof(ctx->style_block->styles[0])))
    {
        html_view_style_block_t *blk = (html_view_style_block_t *)calloc(1, sizeof(*blk));
        if (!blk)
        {
            return NULL;
        }
        blk->prev = ctx->style_block;
        ctx->style_block = blk;
    }

    css_style_t *slot = &ctx->style_block->styles[ctx->style_block->used++];
    ctx->style_depth++;
    html_view_style_for_node(slot, ctx->sheet, parent, node);
    return slot;
}

void html_view_style_pop(html_view_ctx_t *ctx)
{
    if (!ctx || ctx->style_depth == 0)
    {
        return;
    }

    ctx->style_depth--;

    html_view_style_block_t *blk = ctx->style_block;
    if (!blk)
    {
        return;
    }
    if (blk->used > 0)
    {
        blk->used--;
    }
    if (blk->used == 0 && blk->prev)
    {
        ctx->style_block = blk->prev;
        free(blk);
    }
}

int html_view_length_to_px(const css_length_t *len,
                           int viewport_w,
                           int viewport_h,
                           int ref_w,
                           int ref_h,
                           int font_px,
                           bool horizontal)
{
    if (!len || !len->valid || len->is_auto)
    {
        return 0;
    }
    int32_t v = len->value_milli;
    if (v <= 0)
    {
        return 0;
    }

    switch (len->unit)
    {
        case CSS_UNIT_VW:
            return (int)(((int64_t)viewport_w * (int64_t)v + 50000LL) / 100000LL);
        case CSS_UNIT_VH:
            return (int)(((int64_t)viewport_h * (int64_t)v + 50000LL) / 100000LL);
        case CSS_UNIT_PERCENT:
        {
            int ref = horizontal ? ref_w : ref_h;
            return (int)(((int64_t)ref * (int64_t)v + 50000LL) / 100000LL);
        }
        case CSS_UNIT_EM:
            return (int)(((int64_t)font_px * (int64_t)v + 500LL) / 1000LL);
        case CSS_UNIT_PX:
        case CSS_UNIT_NONE:
        default:
            return (int)((v + 500) / 1000);
    }
}

int html_view_line_height_for_style(const html_view_ctx_t *ctx, const css_style_t *style)
{
    if (!ctx)
    {
        return atk_font_line_height() + 4;
    }

    int metrics_total = 0;
    if (ctx->priv && ctx->actual_font_px > 0)
    {
        html_view_font_size_cache_t *cache = html_view_font_state_get_cache(&ctx->priv->font, ctx->actual_font_px);
        if (cache)
        {
            int descent = cache->metrics.descent;
            if (descent < 0)
            {
                descent = -descent;
            }
            metrics_total = cache->metrics.ascent + descent;
            if (cache->metrics.line_gap > 0)
            {
                metrics_total += cache->metrics.line_gap;
            }
        }
    }

    int actual_font_px = ctx->actual_font_px > 0 ? ctx->actual_font_px : atk_font_line_height();
    int base_font_px = ctx->base_font_px > 0 ? ctx->base_font_px : actual_font_px;
    int line_height = ctx->base_line_height > 0 ? ctx->base_line_height : (base_font_px + 4);

    if (style && style->has_line_height)
    {
        if (style->line_height_is_length)
        {
            int px = html_view_length_to_px(&style->line_height,
                                            ctx->viewport_w,
                                            ctx->viewport_h,
                                            ctx->viewport_w,
                                            ctx->viewport_h,
                                            base_font_px,
                                            false);
            if (px > 0)
            {
                line_height = px;
            }
        }
        else if (style->line_height_milli > 0)
        {
            line_height = (int)(((int64_t)base_font_px * (int64_t)style->line_height_milli + 500LL) / 1000LL);
            if (line_height < base_font_px)
            {
                line_height = base_font_px;
            }
        }
    }

    if (line_height < actual_font_px)
    {
        line_height = actual_font_px;
    }
    if (metrics_total > line_height)
    {
        line_height = metrics_total;
    }

    if (line_height < 8)
    {
        line_height = 8;
    }
    return line_height;
}

int html_view_font_px_for_style(const html_view_ctx_t *ctx, const css_style_t *style, int parent_font_px)
{
    int clamped_parent = parent_font_px;
    if (clamped_parent > HTML_VIEW_FONT_MAX_PX)
    {
        clamped_parent = HTML_VIEW_FONT_MAX_PX;
    }
    if (!ctx || !style || !style->has_font_size || !style->font_size.valid || style->font_size.is_auto)
    {
        return clamped_parent;
    }

    if (style->font_size.unit == CSS_UNIT_PERCENT)
    {
        int64_t scaled = (int64_t)clamped_parent * (int64_t)style->font_size.value_milli;
        int px = (int)((scaled + 50000LL) / 100000LL);
        if (px > HTML_VIEW_FONT_MAX_PX)
        {
            px = HTML_VIEW_FONT_MAX_PX;
        }
        return px > 0 ? px : clamped_parent;
    }

    int px = html_view_length_to_px(&style->font_size,
                                    ctx->viewport_w,
                                    ctx->viewport_h,
                                    ctx->viewport_w,
                                    ctx->viewport_h,
                                    clamped_parent,
                                    true);
    if (px > HTML_VIEW_FONT_MAX_PX)
    {
        px = HTML_VIEW_FONT_MAX_PX;
    }
    return px > 0 ? px : clamped_parent;
}

void html_view_font_scope_push(html_view_ctx_t *ctx, const css_style_t *style, bool block, html_view_font_scope_t *saved)
{
    if (!ctx || !saved)
    {
        return;
    }

    saved->actual_font_px = ctx->actual_font_px;
    saved->base_font_px = ctx->base_font_px;
    saved->line_height = ctx->line_height;
    saved->space_w = ctx->space_w;

    int parent_font_px = ctx->base_font_px > 0 ? ctx->base_font_px : ctx->actual_font_px;
    if (parent_font_px <= 0)
    {
        parent_font_px = atk_font_line_height();
    }

    int font_px = html_view_font_px_for_style(ctx, style, parent_font_px);
    if (font_px <= 0)
    {
        font_px = parent_font_px;
    }

    if (style && style->has_font_size && font_px > 0)
    {
        css_style_t *mutable_style = (css_style_t *)style;
        mutable_style->font_size.valid = true;
        mutable_style->font_size.is_auto = false;
        mutable_style->font_size.unit = CSS_UNIT_PX;
        mutable_style->font_size.value_milli = font_px * 1000;
    }

    ctx->base_font_px = font_px;
    ctx->actual_font_px = font_px;
    ctx->space_w = html_view_text_width(ctx, " ");

    int candidate_line_height = html_view_line_height_for_style(ctx, style);
    if (block)
    {
        ctx->line_height = candidate_line_height;
    }
    else if (candidate_line_height > ctx->line_height)
    {
        ctx->line_height = candidate_line_height;
    }
}

void html_view_font_scope_pop(html_view_ctx_t *ctx, const html_view_font_scope_t *saved)
{
    if (!ctx || !saved)
    {
        return;
    }

    ctx->actual_font_px = saved->actual_font_px;
    ctx->base_font_px = saved->base_font_px;
    ctx->line_height = saved->line_height;
    ctx->space_w = saved->space_w;
}
