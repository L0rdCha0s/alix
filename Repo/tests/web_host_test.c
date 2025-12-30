#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "video.h"
#include "web/css.h"
#include "web/html.h"
#include "web/url.h"

video_color_t video_make_color(uint8_t r, uint8_t g, uint8_t b)
{
    return 0xFF000000U | ((video_color_t)r << 16) | ((video_color_t)g << 8) | (video_color_t)b;
}

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

typedef struct
{
    char *data;
    size_t len;
    size_t cap;
} sb_t;

static void sb_destroy(sb_t *sb)
{
    if (!sb)
    {
        return;
    }
    free(sb->data);
    sb->data = NULL;
    sb->len = 0;
    sb->cap = 0;
}

static bool sb_reserve(sb_t *sb, size_t extra)
{
    if (!sb)
    {
        return false;
    }
    if (extra > SIZE_MAX - sb->len - 1)
    {
        return false;
    }
    size_t needed = sb->len + extra + 1;
    if (sb->cap >= needed)
    {
        return true;
    }
    size_t new_cap = sb->cap ? sb->cap : 256;
    while (new_cap < needed)
    {
        if (new_cap > SIZE_MAX / 2)
        {
            new_cap = needed;
            break;
        }
        new_cap *= 2;
    }
    char *new_data = (char *)realloc(sb->data, new_cap);
    if (!new_data)
    {
        return false;
    }
    sb->data = new_data;
    sb->cap = new_cap;
    return true;
}

static bool sb_append_mem(sb_t *sb, const char *data, size_t len)
{
    if (!sb || (!data && len != 0))
    {
        return false;
    }
    if (!sb_reserve(sb, len))
    {
        return false;
    }
    if (len)
    {
        memcpy(sb->data + sb->len, data, len);
        sb->len += len;
    }
    sb->data[sb->len] = '\0';
    return true;
}

static bool sb_append_cstr(sb_t *sb, const char *s)
{
    if (!s)
    {
        s = "";
    }
    return sb_append_mem(sb, s, strlen(s));
}

static bool sb_append_char(sb_t *sb, char c)
{
    return sb_append_mem(sb, &c, 1);
}

static bool sb_appendf(sb_t *sb, const char *fmt, ...)
{
    if (!sb || !fmt)
    {
        return false;
    }

    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    int needed = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (needed < 0)
    {
        va_end(ap2);
        return false;
    }

    if (!sb_reserve(sb, (size_t)needed))
    {
        va_end(ap2);
        return false;
    }

    int written = vsnprintf(sb->data + sb->len, sb->cap - sb->len, fmt, ap2);
    va_end(ap2);
    if (written != needed)
    {
        return false;
    }
    sb->len += (size_t)written;
    return true;
}

static bool sb_append_escaped(sb_t *sb, const char *s)
{
    if (!sb)
    {
        return false;
    }
    if (!s)
    {
        return true;
    }
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p)
    {
        unsigned char c = *p;
        if (c == '\\')
        {
            if (!sb_append_cstr(sb, "\\\\"))
            {
                return false;
            }
        }
        else if (c == '"')
        {
            if (!sb_append_cstr(sb, "\\\""))
            {
                return false;
            }
        }
        else if (c == '\n')
        {
            if (!sb_append_cstr(sb, "\\n"))
            {
                return false;
            }
        }
        else if (c == '\r')
        {
            if (!sb_append_cstr(sb, "\\r"))
            {
                return false;
            }
        }
        else if (c == '\t')
        {
            if (!sb_append_cstr(sb, "\\t"))
            {
                return false;
            }
        }
        else if (c < 0x20)
        {
            if (!sb_appendf(sb, "\\x%02X", (unsigned)c))
            {
                return false;
            }
        }
        else
        {
            if (!sb_append_char(sb, (char)c))
            {
                return false;
            }
        }
    }
    return true;
}

static size_t trimmed_len(const char *s)
{
    if (!s)
    {
        return 0;
    }
    size_t len = strlen(s);
    while (len > 0)
    {
        char c = s[len - 1];
        if (c != '\n' && c != '\r' && c != ' ' && c != '\t')
        {
            break;
        }
        len--;
    }
    return len;
}

static bool str_eq_trimmed(const char *a, const char *b)
{
    size_t al = trimmed_len(a);
    size_t bl = trimmed_len(b);
    if (al != bl)
    {
        return false;
    }
    if (al == 0)
    {
        return true;
    }
    return strncmp(a, b, al) == 0;
}

static bool html_serialize_node(sb_t *sb, const html_node_t *node, int depth)
{
    if (!sb)
    {
        return false;
    }
    if (!node)
    {
        return true;
    }

    for (int i = 0; i < depth; ++i)
    {
        if (!sb_append_cstr(sb, "  "))
        {
            return false;
        }
    }

    switch (node->type)
    {
        case HTML_NODE_DOCUMENT:
            if (!sb_append_cstr(sb, "#document\n"))
            {
                return false;
            }
            break;
        case HTML_NODE_ELEMENT:
        {
            if (!sb_append_char(sb, '<'))
            {
                return false;
            }
            if (!sb_append_cstr(sb, node->name ? node->name : "?"))
            {
                return false;
            }
            for (const html_attr_t *attr = node->attrs; attr; attr = attr->next)
            {
                if (!sb_append_char(sb, ' ') ||
                    !sb_append_cstr(sb, attr->name ? attr->name : "?") ||
                    !sb_append_cstr(sb, "=\"") ||
                    !sb_append_escaped(sb, attr->value ? attr->value : "") ||
                    !sb_append_char(sb, '"'))
                {
                    return false;
                }
            }
            if (!sb_append_cstr(sb, ">\n"))
            {
                return false;
            }
            break;
        }
        case HTML_NODE_TEXT:
            if (!sb_append_char(sb, '"') ||
                !sb_append_escaped(sb, node->text ? node->text : "") ||
                !sb_append_cstr(sb, "\"\n"))
            {
                return false;
            }
            break;
        case HTML_NODE_DOCTYPE:
            if (!sb_append_cstr(sb, "<!doctype"))
            {
                return false;
            }
            if (node->name && node->name[0] != '\0')
            {
                if (!sb_append_char(sb, ' ') || !sb_append_cstr(sb, node->name))
                {
                    return false;
                }
            }
            if (!sb_append_cstr(sb, ">\n"))
            {
                return false;
            }
            break;
        case HTML_NODE_COMMENT:
            if (!sb_append_cstr(sb, "<!--") ||
                !sb_append_escaped(sb, node->text ? node->text : "") ||
                !sb_append_cstr(sb, "-->\n"))
            {
                return false;
            }
            break;
    }

    for (const html_node_t *child = node->first_child; child; child = child->next_sibling)
    {
        if (!html_serialize_node(sb, child, depth + 1))
        {
            return false;
        }
    }
    return true;
}

static bool html_serialize_doc(sb_t *sb, const html_document_t *doc)
{
    if (!sb)
    {
        return false;
    }
    sb->len = 0;
    if (sb->data)
    {
        sb->data[0] = '\0';
    }
    if (!doc || !doc->root)
    {
        return true;
    }
    return html_serialize_node(sb, doc->root, 0);
}

static bool css_append_milli(sb_t *sb, int32_t milli)
{
    if (!sb)
    {
        return false;
    }
    if (milli < 0)
    {
        if (!sb_append_char(sb, '-'))
        {
            return false;
        }
        milli = -milli;
    }
    int32_t integer = milli / 1000;
    int32_t frac = milli % 1000;
    if (!sb_appendf(sb, "%d", integer))
    {
        return false;
    }
    if (frac == 0)
    {
        return true;
    }
    char frac_buf[4];
    (void)snprintf(frac_buf, sizeof(frac_buf), "%03d", frac);
    size_t frac_len = 3;
    while (frac_len > 0 && frac_buf[frac_len - 1] == '0')
    {
        frac_len--;
    }
    if (frac_len == 0)
    {
        return true;
    }
    if (!sb_append_char(sb, '.'))
    {
        return false;
    }
    return sb_append_mem(sb, frac_buf, frac_len);
}

static bool css_append_color(sb_t *sb, video_color_t color)
{
    uint8_t r = (uint8_t)((color >> 16) & 0xFF);
    uint8_t g = (uint8_t)((color >> 8) & 0xFF);
    uint8_t b = (uint8_t)(color & 0xFF);
    return sb_appendf(sb, "#%02X%02X%02X", (unsigned)r, (unsigned)g, (unsigned)b);
}

static bool css_append_length(sb_t *sb, const css_length_t *len)
{
    if (!sb)
    {
        return false;
    }
    if (!len || !len->valid)
    {
        return sb_append_cstr(sb, "<invalid>");
    }
    if (len->is_auto)
    {
        return sb_append_cstr(sb, "auto");
    }

    if (!css_append_milli(sb, len->value_milli))
    {
        return false;
    }

    const char *suffix = "";
    switch (len->unit)
    {
        case CSS_UNIT_NONE: suffix = ""; break;
        case CSS_UNIT_PX: suffix = "px"; break;
        case CSS_UNIT_VW: suffix = "vw"; break;
        case CSS_UNIT_VH: suffix = "vh"; break;
        case CSS_UNIT_EM: suffix = "em"; break;
        case CSS_UNIT_PERCENT: suffix = "%"; break;
    }
    return sb_append_cstr(sb, suffix);
}

static bool css_append_box(sb_t *sb, const css_box_t *box)
{
    if (!sb || !box)
    {
        return false;
    }
    if (!css_append_length(sb, &box->top) ||
        !sb_append_char(sb, ' ') ||
        !css_append_length(sb, &box->right) ||
        !sb_append_char(sb, ' ') ||
        !css_append_length(sb, &box->bottom) ||
        !sb_append_char(sb, ' ') ||
        !css_append_length(sb, &box->left))
    {
        return false;
    }
    return true;
}

static bool css_serialize_style(sb_t *sb, const css_style_t *style, int depth)
{
    if (!sb || !style)
    {
        return false;
    }

    const char *indent = (depth > 0) ? "  " : "";
    if (style->has_background)
    {
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "background: ") ||
            !css_append_color(sb, style->background) || !sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    if (style->has_color)
    {
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "color: ") ||
            !css_append_color(sb, style->color) || !sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    if (style->has_font_size)
    {
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "font-size: ") ||
            !css_append_length(sb, &style->font_size) || !sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    if (style->has_width)
    {
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "width: ") ||
            !css_append_length(sb, &style->width) || !sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    if (style->has_height)
    {
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "height: ") ||
            !css_append_length(sb, &style->height) || !sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    if (style->has_margin)
    {
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "margin: ") ||
            !css_append_box(sb, &style->margin) || !sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    if (style->has_padding)
    {
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "padding: ") ||
            !css_append_box(sb, &style->padding) || !sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    if (style->has_border)
    {
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "border-width: ") ||
            !css_append_box(sb, &style->border_width) || !sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    if (style->has_border_color)
    {
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "border-color: "))
        {
            return false;
        }
        if (style->border_transparent)
        {
            if (!sb_append_cstr(sb, "transparent") || !sb_append_char(sb, '\n'))
            {
                return false;
            }
        }
        else
        {
            if (!css_append_color(sb, style->border_color) || !sb_append_char(sb, '\n'))
            {
                return false;
            }
        }
    }
    if (style->has_float)
    {
        const char *v = "none";
        if (style->float_mode == CSS_FLOAT_LEFT) v = "left";
        else if (style->float_mode == CSS_FLOAT_RIGHT) v = "right";
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "float: ") ||
            !sb_append_cstr(sb, v) || !sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    if (style->has_clear)
    {
        const char *v = "none";
        if (style->clear_mode == CSS_CLEAR_LEFT) v = "left";
        else if (style->clear_mode == CSS_CLEAR_RIGHT) v = "right";
        else if (style->clear_mode == CSS_CLEAR_BOTH) v = "both";
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "clear: ") ||
            !sb_append_cstr(sb, v) || !sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    if (style->has_z_index)
    {
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "z-index: ") ||
            !sb_appendf(sb, "%d\n", (int)style->z_index))
        {
            return false;
        }
    }
    if (style->has_text_align)
    {
        const char *v = "left";
        if (style->text_align == CSS_TEXT_ALIGN_CENTER) v = "center";
        else if (style->text_align == CSS_TEXT_ALIGN_RIGHT) v = "right";
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "text-align: ") ||
            !sb_append_cstr(sb, v) || !sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    if (style->has_text_decoration)
    {
        const char *v = (style->text_decoration == CSS_TEXT_DECORATION_UNDERLINE) ? "underline" : "none";
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "text-decoration: ") ||
            !sb_append_cstr(sb, v) || !sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    if (style->has_text_shadow)
    {
        css_length_t zero = { .valid = true, .is_auto = false, .value_milli = 0, .unit = CSS_UNIT_NONE };
        const css_length_t *blur = style->text_shadow_blur.valid ? &style->text_shadow_blur : &zero;
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "text-shadow: ") ||
            !css_append_length(sb, &style->text_shadow_x) || !sb_append_char(sb, ' ') ||
            !css_append_length(sb, &style->text_shadow_y) || !sb_append_char(sb, ' ') ||
            !css_append_length(sb, blur))
        {
            return false;
        }
        if (style->has_text_shadow_color)
        {
            if (!sb_append_char(sb, ' ') || !css_append_color(sb, style->text_shadow_color))
            {
                return false;
            }
        }
        if (!sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    if (style->has_display)
    {
        const char *v = "inline";
        if (style->display == CSS_DISPLAY_BLOCK) v = "block";
        else if (style->display == CSS_DISPLAY_LIST_ITEM) v = "list-item";
        else if (style->display == CSS_DISPLAY_TABLE) v = "table";
        else if (style->display == CSS_DISPLAY_TABLE_CELL) v = "table-cell";
        else if (style->display == CSS_DISPLAY_FLEX) v = "flex";
        else if (style->display == CSS_DISPLAY_INLINE_FLEX) v = "inline-flex";
        else if (style->display == CSS_DISPLAY_NONE) v = "none";
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "display: ") ||
            !sb_append_cstr(sb, v) || !sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    if (style->has_flex_direction)
    {
        const char *v = "row";
        if (style->flex_direction == CSS_FLEX_DIRECTION_ROW_REVERSE) v = "row-reverse";
        else if (style->flex_direction == CSS_FLEX_DIRECTION_COLUMN) v = "column";
        else if (style->flex_direction == CSS_FLEX_DIRECTION_COLUMN_REVERSE) v = "column-reverse";
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "flex-direction: ") ||
            !sb_append_cstr(sb, v) || !sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    if (style->has_flex_wrap)
    {
        const char *v = "nowrap";
        if (style->flex_wrap == CSS_FLEX_WRAP_WRAP) v = "wrap";
        else if (style->flex_wrap == CSS_FLEX_WRAP_WRAP_REVERSE) v = "wrap-reverse";
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "flex-wrap: ") ||
            !sb_append_cstr(sb, v) || !sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    if (style->has_justify_content)
    {
        const char *v = "flex-start";
        if (style->justify_content == CSS_JUSTIFY_FLEX_END) v = "flex-end";
        else if (style->justify_content == CSS_JUSTIFY_CENTER) v = "center";
        else if (style->justify_content == CSS_JUSTIFY_SPACE_BETWEEN) v = "space-between";
        else if (style->justify_content == CSS_JUSTIFY_SPACE_AROUND) v = "space-around";
        else if (style->justify_content == CSS_JUSTIFY_SPACE_EVENLY) v = "space-evenly";
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "justify-content: ") ||
            !sb_append_cstr(sb, v) || !sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    if (style->has_align_items)
    {
        const char *v = "stretch";
        if (style->align_items == CSS_ALIGN_FLEX_START) v = "flex-start";
        else if (style->align_items == CSS_ALIGN_FLEX_END) v = "flex-end";
        else if (style->align_items == CSS_ALIGN_CENTER) v = "center";
        else if (style->align_items == CSS_ALIGN_BASELINE) v = "baseline";
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "align-items: ") ||
            !sb_append_cstr(sb, v) || !sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    if (style->has_align_self)
    {
        const char *v = "stretch";
        if (style->align_self == CSS_ALIGN_FLEX_START) v = "flex-start";
        else if (style->align_self == CSS_ALIGN_FLEX_END) v = "flex-end";
        else if (style->align_self == CSS_ALIGN_CENTER) v = "center";
        else if (style->align_self == CSS_ALIGN_BASELINE) v = "baseline";
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "align-self: ") ||
            !sb_append_cstr(sb, v) || !sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    if (style->has_align_content)
    {
        const char *v = "stretch";
        if (style->align_content == CSS_ALIGN_FLEX_START) v = "flex-start";
        else if (style->align_content == CSS_ALIGN_FLEX_END) v = "flex-end";
        else if (style->align_content == CSS_ALIGN_CENTER) v = "center";
        else if (style->align_content == CSS_ALIGN_BASELINE) v = "baseline";
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "align-content: ") ||
            !sb_append_cstr(sb, v) || !sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    if (style->has_row_gap)
    {
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "row-gap: ") ||
            !css_append_length(sb, &style->row_gap) || !sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    if (style->has_column_gap)
    {
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "column-gap: ") ||
            !css_append_length(sb, &style->column_gap) || !sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    if (style->has_flex_grow)
    {
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "flex-grow: ") ||
            !css_append_milli(sb, style->flex_grow_milli) || !sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    if (style->has_flex_shrink)
    {
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "flex-shrink: ") ||
            !css_append_milli(sb, style->flex_shrink_milli) || !sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    if (style->has_flex_basis)
    {
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "flex-basis: ") ||
            !css_append_length(sb, &style->flex_basis) || !sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    if (style->has_line_height)
    {
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "line-height: "))
        {
            return false;
        }
        if (style->line_height_is_length)
        {
            if (!css_append_length(sb, &style->line_height))
            {
                return false;
            }
        }
        else if (!css_append_milli(sb, style->line_height_milli))
        {
            return false;
        }
        if (!sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    if (style->has_letter_spacing)
    {
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "letter-spacing: ") ||
            !css_append_length(sb, &style->letter_spacing) || !sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    if (style->has_opacity)
    {
        if (!sb_append_cstr(sb, indent) || !sb_append_cstr(sb, "opacity: ") ||
            !css_append_milli(sb, style->opacity_milli) || !sb_append_char(sb, '\n'))
        {
            return false;
        }
    }
    return true;
}

static bool css_serialize_sheet(sb_t *sb, const css_stylesheet_t *sheet)
{
    if (!sb)
    {
        return false;
    }
    sb->len = 0;
    if (sb->data)
    {
        sb->data[0] = '\0';
    }
    if (!sheet)
    {
        return true;
    }
    for (const css_rule_t *rule = sheet->rules; rule; rule = rule->next)
    {
        if (!sb_append_cstr(sb, "selector: ") ||
            !sb_append_cstr(sb, rule->selector ? rule->selector : "") ||
            !sb_append_char(sb, '\n'))
        {
            return false;
        }
        if (!css_serialize_style(sb, &rule->style, 1))
        {
            return false;
        }
    }
    return true;
}

typedef struct
{
    const char *suite;
    const char *name;
    bool expect_pass;
    const char *input;
    const char *expected;
} parse_case_t;

typedef struct
{
    const char *suite;
    const char *name;
    bool expect_pass;
    const char *selector;
    const char *tag;
    bool expected_match;
} css_match_case_t;

typedef struct
{
    const char *suite;
    const char *name;
    bool expect_pass;
    const char *url;
    bool expected_svg;
} url_case_t;

typedef struct
{
    size_t total;
    size_t pass;
    size_t fail;
    size_t xfail;
    size_t xpass;
} test_counts_t;

static void test_counts_add(test_counts_t *counts, bool ok, bool expect_pass)
{
    if (!counts)
    {
        return;
    }
    counts->total++;
    if (ok)
    {
        if (expect_pass)
        {
            counts->pass++;
        }
        else
        {
            counts->xpass++;
        }
    }
    else
    {
        if (expect_pass)
        {
            counts->fail++;
        }
        else
        {
            counts->xfail++;
        }
    }
}

static test_counts_t test_counts_sum(test_counts_t a, test_counts_t b)
{
    test_counts_t out = {0};
    out.total = a.total + b.total;
    out.pass = a.pass + b.pass;
    out.fail = a.fail + b.fail;
    out.xfail = a.xfail + b.xfail;
    out.xpass = a.xpass + b.xpass;
    return out;
}

static void test_counts_print(const char *label, const test_counts_t *c)
{
    if (!label || !c)
    {
        return;
    }
    printf("web_host_test: %s total=%zu pass=%zu fail=%zu xfail=%zu xpass=%zu\n",
           label, c->total, c->pass, c->fail, c->xfail, c->xpass);
}

#define HTML_CASE(suite_val, name_val, expect_val, input_val, expected_val) \
    { .suite = suite_val, .name = name_val, .expect_pass = expect_val, .input = input_val, .expected = expected_val }

#define HTML_VOID_TAG_CASE(tag) \
    HTML_CASE("html/current", "void-" tag, true, "<" tag ">", "#document\n  <" tag ">\n")

#define HTML_VOID_SELF_CLOSE_CASE(tag) \
    HTML_CASE("html/current", "void-" tag "-self-close", true, "<" tag "/>", "#document\n  <" tag ">\n")

#define HTML_VOID_IN_P_CASE(tag) \
    HTML_CASE("html/current", "void-" tag "-in-p", true, "<p>a<" tag ">b</p>", "#document\n  <p>\n    \"a\"\n    <" tag ">\n    \"b\"\n")

#define CSS_CASE(suite_val, name_val, expect_val, input_val, expected_val) \
    { .suite = suite_val, .name = name_val, .expect_pass = expect_val, .input = input_val, .expected = expected_val }

static const parse_case_t html_cases[] = {
    {
        .suite = "html/current",
        .name = "plain-text",
        .expect_pass = true,
        .input = "Hello",
        .expected =
            "#document\n"
            "  \"Hello\"\n",
    },
    {
        .suite = "html/current",
        .name = "basic-element",
        .expect_pass = true,
        .input = "<p>Hello</p>",
        .expected =
            "#document\n"
            "  <p>\n"
            "    \"Hello\"\n",
    },
    {
        .suite = "html/current",
        .name = "case-insensitive-tag-and-attrs",
        .expect_pass = true,
        .input = "<DIV ID=main>Hi</DIV>",
        .expected =
            "#document\n"
            "  <div id=\"main\">\n"
            "    \"Hi\"\n",
    },
    {
        .suite = "html/current",
        .name = "attrs-quoted-and-entities",
        .expect_pass = true,
        .input = "<a href=\"https://example.com\" title='A &amp; B'>x</a>",
        .expected =
            "#document\n"
            "  <a href=\"https://example.com\" title=\"A & B\">\n"
            "    \"x\"\n",
    },
    {
        .suite = "html/current",
        .name = "boolean-attr",
        .expect_pass = true,
        .input = "<input disabled>",
        .expected =
            "#document\n"
            "  <input disabled=\"\">\n",
    },
    {
        .suite = "html/current",
        .name = "void-element-not-pushed",
        .expect_pass = true,
        .input = "<p>Hi<br>There</p>",
        .expected =
            "#document\n"
            "  <p>\n"
            "    \"Hi\"\n"
            "    <br>\n"
            "    \"There\"\n",
    },
    {
        .suite = "html/current",
        .name = "self-closing-void",
        .expect_pass = true,
        .input = "<br/>",
        .expected =
            "#document\n"
            "  <br>\n",
    },
    {
        .suite = "html/current",
        .name = "self-closing-nonvoid",
        .expect_pass = true,
        .input = "<div/>",
        .expected =
            "#document\n"
            "  <div>\n",
    },
    {
        .suite = "html/current",
        .name = "implicit-close-p",
        .expect_pass = true,
        .input = "<p>one<p>two",
        .expected =
            "#document\n"
            "  <p>\n"
            "    \"one\"\n"
            "  <p>\n"
            "    \"two\"\n",
    },
    {
        .suite = "html/current",
        .name = "implicit-close-p-on-table",
        .expect_pass = true,
        .input = "<p>one<table><tr><td>two</td></tr></table>three",
        .expected =
            "#document\n"
            "  <p>\n"
            "    \"one\"\n"
            "  <table>\n"
            "    <tr>\n"
            "      <td>\n"
            "        \"two\"\n"
            "  \"three\"\n",
    },
    {
        .suite = "html/current",
        .name = "head-closed-on-body",
        .expect_pass = true,
        .input = "<head><title>T</title><body>Hi",
        .expected =
            "#document\n"
            "  <head>\n"
            "    <title>\n"
            "      \"T\"\n"
            "  <body>\n"
            "    \"Hi\"\n",
    },
    {
        .suite = "html/current",
        .name = "script-raw-text",
        .expect_pass = true,
        .input = "<script>if (a < b) alert(\"&\");</script><p>ok</p>",
        .expected =
            "#document\n"
            "  <script>\n"
            "    \"if (a < b) alert(\\\"&\\\");\"\n"
            "  <p>\n"
            "    \"ok\"\n",
    },
    {
        .suite = "html/current",
        .name = "style-raw-text-case-insensitive-close",
        .expect_pass = true,
        .input = "<style>p{color:red}</STYLE><p>x</p>",
        .expected =
            "#document\n"
            "  <style>\n"
            "    \"p{color:red}\"\n"
            "  <p>\n"
            "    \"x\"\n",
    },
    {
        .suite = "html/current",
        .name = "comment-ignored",
        .expect_pass = true,
        .input = "A<!--c--><b>B</b>",
        .expected =
            "#document\n"
            "  \"A\"\n"
            "  <b>\n"
            "    \"B\"\n",
    },
    {
        .suite = "html/current",
        .name = "doctype-ignored",
        .expect_pass = true,
        .input = "<!DOCTYPE html><p>x</p>",
        .expected =
            "#document\n"
            "  <p>\n"
            "    \"x\"\n",
    },
    {
        .suite = "html/current",
        .name = "invalid-tag-becomes-text",
        .expect_pass = true,
        .input = "<>",
        .expected =
            "#document\n"
            "  \"<\"\n"
            "  \">\"\n",
    },
    {
        .suite = "html/current",
        .name = "entity-decoding-text",
        .expect_pass = true,
        .input = "<p>&lt;&amp;&gt;</p>",
        .expected =
            "#document\n"
            "  <p>\n"
            "    \"<&>\"\n",
    },
    {
        .suite = "html/current",
        .name = "numeric-entity-decoding",
        .expect_pass = true,
        .input = "<p>&#65;&#x42;</p>",
        .expected =
            "#document\n"
            "  <p>\n"
            "    \"AB\"\n",
    },
    {
        .suite = "html/current",
        .name = "unsupported-entity-left-as-is",
        .expect_pass = true,
        .input = "<p>&copy;</p>",
        .expected =
            "#document\n"
            "  <p>\n"
            "    \"&copy;\"\n",
    },
    {
        .suite = "html/current",
        .name = "empty-input",
        .expect_pass = true,
        .input = "",
        .expected = "#document\n",
    },
    {
        .suite = "html/current",
        .name = "single-space-text",
        .expect_pass = true,
        .input = " ",
        .expected =
            "#document\n"
            "  \" \"\n",
    },
    {
        .suite = "html/current",
        .name = "orphan-end-tag",
        .expect_pass = true,
        .input = "</p>",
        .expected = "#document\n",
    },
    {
        .suite = "html/current",
        .name = "processing-instruction-skipped",
        .expect_pass = true,
        .input = "A<?xml version=\"1.0\"?>B",
        .expected =
            "#document\n"
            "  \"A\"\n"
            "  \"B\"\n",
    },
    {
        .suite = "html/current",
        .name = "processing-instruction-unclosed",
        .expect_pass = true,
        .input = "A<?xml",
        .expected =
            "#document\n"
            "  \"A\"\n",
    },
    {
        .suite = "html/current",
        .name = "comment-unclosed",
        .expect_pass = true,
        .input = "A<!--",
        .expected =
            "#document\n"
            "  \"A\"\n",
    },
    {
        .suite = "html/current",
        .name = "doctype-unclosed",
        .expect_pass = true,
        .input = "<!DOCTYPE html",
        .expected = "#document\n",
    },
    {
        .suite = "html/current",
        .name = "self-closing-void-with-space",
        .expect_pass = true,
        .input = "<br />",
        .expected =
            "#document\n"
            "  <br>\n",
    },
    {
        .suite = "html/current",
        .name = "nested-elements",
        .expect_pass = true,
        .input = "<div><span>t</span></div>",
        .expected =
            "#document\n"
            "  <div>\n"
            "    <span>\n"
            "      \"t\"\n",
    },
    {
        .suite = "html/current",
        .name = "siblings-text-element-text",
        .expect_pass = true,
        .input = "A<b>B</b>C",
        .expected =
            "#document\n"
            "  \"A\"\n"
            "  <b>\n"
            "    \"B\"\n"
            "  \"C\"\n",
    },
    {
        .suite = "html/current",
        .name = "nested-with-whitespace",
        .expect_pass = true,
        .input = "<p>Hello <b>bold</b> world</p>",
        .expected =
            "#document\n"
            "  <p>\n"
            "    \"Hello \"\n"
            "    <b>\n"
            "      \"bold\"\n"
            "    \" world\"\n",
    },
    {
        .suite = "html/current",
        .name = "tag-with-colon",
        .expect_pass = true,
        .input = "<svg:rect>t</svg:rect>",
        .expected =
            "#document\n"
            "  <svg:rect>\n"
            "    \"t\"\n",
    },
    {
        .suite = "html/current",
        .name = "attr-unquoted-url",
        .expect_pass = true,
        .input = "<a href=https://example.com>ok</a>",
        .expected =
            "#document\n"
            "  <a href=\"https://example.com\">\n"
            "    \"ok\"\n",
    },
    {
        .suite = "html/current",
        .name = "attr-spaces-around-equals",
        .expect_pass = true,
        .input = "<div a = b>t</div>",
        .expected =
            "#document\n"
            "  <div a=\"b\">\n"
            "    \"t\"\n",
    },
    {
        .suite = "html/current",
        .name = "attr-empty-after-equals",
        .expect_pass = true,
        .input = "<div a=>t</div>",
        .expected =
            "#document\n"
            "  <div a=\"\">\n"
            "    \"t\"\n",
    },
    {
        .suite = "html/current",
        .name = "attr-entity-decoded-single-quoted",
        .expect_pass = true,
        .input = "<div title='A &lt; B'>x</div>",
        .expected =
            "#document\n"
            "  <div title=\"A < B\">\n"
            "    \"x\"\n",
    },
    {
        .suite = "html/current",
        .name = "attr-entity-decoded-unquoted",
        .expect_pass = true,
        .input = "<div title=A&amp;B>x</div>",
        .expected =
            "#document\n"
            "  <div title=\"A&B\">\n"
            "    \"x\"\n",
    },
    {
        .suite = "html/current",
        .name = "nbsp-decoding-to-nbsp",
        .expect_pass = true,
        .input = "<p>a&nbsp;b</p>",
        .expected =
            "#document\n"
            "  <p>\n"
            "    \"a\xC2\xA0""b\"\n",
    },
    {
        .suite = "html/current",
        .name = "numeric-entity-160-to-nbsp",
        .expect_pass = true,
        .input = "<p>a&#160;b</p>",
        .expected =
            "#document\n"
            "  <p>\n"
            "    \"a\xC2\xA0""b\"\n",
    },
    {
        .suite = "html/current",
        .name = "numeric-entity-169-to-question",
        .expect_pass = true,
        .input = "<p>&#169;</p>",
        .expected =
            "#document\n"
            "  <p>\n"
            "    \"?\"\n",
    },
    {
        .suite = "html/current",
        .name = "numeric-entity-hex-169-to-question",
        .expect_pass = true,
        .input = "<p>&#xA9;</p>",
        .expected =
            "#document\n"
            "  <p>\n"
            "    \"?\"\n",
    },
    {
        .suite = "html/current",
        .name = "unknown-numeric-entity-left-as-is",
        .expect_pass = true,
        .input = "<p>&#x110000;</p>",
        .expected =
            "#document\n"
            "  <p>\n"
            "    \"&#x110000;\"\n",
    },
    {
        .suite = "html/current",
        .name = "entity-without-semicolon-left-as-is",
        .expect_pass = true,
        .input = "<p>&amp</p>",
        .expected =
            "#document\n"
            "  <p>\n"
            "    \"&amp\"\n",
    },
    {
        .suite = "html/current",
        .name = "end-tag-with-whitespace",
        .expect_pass = true,
        .input = "<div>Hi</ div>",
        .expected =
            "#document\n"
            "  <div>\n"
            "    \"Hi\"\n",
    },
    {
        .suite = "html/current",
        .name = "start-tag-with-leading-whitespace",
        .expect_pass = true,
        .input = "< div>Hi</div>",
        .expected =
            "#document\n"
            "  <div>\n"
            "    \"Hi\"\n",
    },
    {
        .suite = "html/current",
        .name = "mismatched-closing-tag-pops-stack",
        .expect_pass = true,
        .input = "<div><span>x</div>y",
        .expected =
            "#document\n"
            "  <div>\n"
            "    <span>\n"
            "      \"x\"\n"
            "  \"y\"\n",
    },

    HTML_VOID_TAG_CASE("meta"),
    HTML_VOID_SELF_CLOSE_CASE("meta"),
    HTML_VOID_IN_P_CASE("meta"),
    HTML_VOID_TAG_CASE("link"),
    HTML_VOID_SELF_CLOSE_CASE("link"),
    HTML_VOID_IN_P_CASE("link"),
    HTML_VOID_TAG_CASE("br"),
    HTML_VOID_SELF_CLOSE_CASE("br"),
    HTML_VOID_IN_P_CASE("br"),
    HTML_VOID_TAG_CASE("hr"),
    HTML_VOID_SELF_CLOSE_CASE("hr"),
    HTML_VOID_IN_P_CASE("hr"),
    HTML_VOID_TAG_CASE("img"),
    HTML_VOID_SELF_CLOSE_CASE("img"),
    HTML_VOID_IN_P_CASE("img"),
    HTML_VOID_TAG_CASE("input"),
    HTML_VOID_SELF_CLOSE_CASE("input"),
    HTML_VOID_IN_P_CASE("input"),
    HTML_VOID_TAG_CASE("area"),
    HTML_VOID_SELF_CLOSE_CASE("area"),
    HTML_VOID_IN_P_CASE("area"),
    HTML_VOID_TAG_CASE("base"),
    HTML_VOID_SELF_CLOSE_CASE("base"),
    HTML_VOID_IN_P_CASE("base"),
    HTML_VOID_TAG_CASE("col"),
    HTML_VOID_SELF_CLOSE_CASE("col"),
    HTML_VOID_IN_P_CASE("col"),
    HTML_VOID_TAG_CASE("embed"),
    HTML_VOID_SELF_CLOSE_CASE("embed"),
    HTML_VOID_IN_P_CASE("embed"),
    HTML_VOID_TAG_CASE("param"),
    HTML_VOID_SELF_CLOSE_CASE("param"),
    HTML_VOID_IN_P_CASE("param"),
    HTML_VOID_TAG_CASE("source"),
    HTML_VOID_SELF_CLOSE_CASE("source"),
    HTML_VOID_IN_P_CASE("source"),
    HTML_VOID_TAG_CASE("track"),
    HTML_VOID_SELF_CLOSE_CASE("track"),
    HTML_VOID_IN_P_CASE("track"),
    HTML_VOID_TAG_CASE("wbr"),
    HTML_VOID_SELF_CLOSE_CASE("wbr"),
    HTML_VOID_IN_P_CASE("wbr"),

    {
        .suite = "html/html5",
        .name = "implied-html-head-body",
        .expect_pass = false,
        .input = "Hello",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      \"Hello\"\n",
    },
    {
        .suite = "html/html5",
        .name = "comment-node",
        .expect_pass = false,
        .input = "a<!--c-->b",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      \"a\"\n"
            "      <!--c-->\n"
            "      \"b\"\n",
    },
    {
        .suite = "html/html5",
        .name = "doctype-node",
        .expect_pass = false,
        .input = "<!doctype html><p>x</p>",
        .expected =
            "#document\n"
            "  <!doctype html>\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <p>\n"
            "        \"x\"\n",
    },
    {
        .suite = "html/html5",
        .name = "self-closing-nonvoid-ignored",
        .expect_pass = false,
        .input = "<div/>Hi",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <div>\n"
            "        \"Hi\"\n",
    },
    {
        .suite = "html/html5",
        .name = "p-closed-by-block",
        .expect_pass = false,
        .input = "<p>one<div>two",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <p>\n"
            "        \"one\"\n"
            "      <div>\n"
            "        \"two\"\n",
    },
    {
        .suite = "html/html5",
        .name = "named-entity-copy",
        .expect_pass = false,
        .input = "<p>&copy;</p>",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <p>\n"
            "        \"©\"\n",
    },
    {
        .suite = "html/html5",
        .name = "title-in-implied-head",
        .expect_pass = false,
        .input = "<title>T</title>",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "      <title>\n"
            "        \"T\"\n"
            "    <body>\n",
    },
    {
        .suite = "html/html5",
        .name = "style-in-implied-head",
        .expect_pass = false,
        .input = "<style>p{color:red}</style><p>x</p>",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "      <style>\n"
            "        \"p{color:red}\"\n"
            "    <body>\n"
            "      <p>\n"
            "        \"x\"\n",
    },
    {
        .suite = "html/html5",
        .name = "script-in-implied-body",
        .expect_pass = false,
        .input = "<script>1</script><p>x</p>",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <script>\n"
            "        \"1\"\n"
            "      <p>\n"
            "        \"x\"\n",
    },
    {
        .suite = "html/html5",
        .name = "meta-in-implied-head",
        .expect_pass = false,
        .input = "<meta charset=utf-8><p>x</p>",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "      <meta charset=\"utf-8\">\n"
            "    <body>\n"
            "      <p>\n"
            "        \"x\"\n",
    },
    {
        .suite = "html/html5",
        .name = "comment-node-in-element",
        .expect_pass = false,
        .input = "<p>a<!--c-->b</p>",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <p>\n"
            "        \"a\"\n"
            "        <!--c-->\n"
            "        \"b\"\n",
    },
    {
        .suite = "html/html5",
        .name = "doctype-and-comment-order",
        .expect_pass = false,
        .input = "<!doctype html><!--c--><p>x</p>",
        .expected =
            "#document\n"
            "  <!doctype html>\n"
            "  <!--c-->\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <p>\n"
            "        \"x\"\n",
    },
    {
        .suite = "html/html5",
        .name = "doctype-case-insensitive",
        .expect_pass = false,
        .input = "<!DOCTYPE HTML><p>x</p>",
        .expected =
            "#document\n"
            "  <!doctype html>\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <p>\n"
            "        \"x\"\n",
    },
    {
        .suite = "html/html5",
        .name = "named-entity-euro",
        .expect_pass = false,
        .input = "<p>&euro;</p>",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <p>\n"
            "        \"\xE2\x82\xAC\"\n",
    },
    {
        .suite = "html/html5",
        .name = "numeric-entity-euro",
        .expect_pass = false,
        .input = "<p>&#8364;</p>",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <p>\n"
            "        \"\xE2\x82\xAC\"\n",
    },
    {
        .suite = "html/html5",
        .name = "hex-entity-snowman",
        .expect_pass = false,
        .input = "<p>&#x2603;</p>",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <p>\n"
            "        \"\xE2\x98\x83\"\n",
    },
    {
        .suite = "html/html5",
        .name = "rcdata-title",
        .expect_pass = false,
        .input = "<title><b>&lt;</b></title>",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "      <title>\n"
            "        \"<b><</b>\"\n"
            "    <body>\n",
    },
    {
        .suite = "html/html5",
        .name = "rcdata-textarea",
        .expect_pass = false,
        .input = "<textarea><b>&lt;</b></textarea>",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <textarea>\n"
            "        \"<b><</b>\"\n",
    },
    {
        .suite = "html/html5",
        .name = "p-closed-by-ul",
        .expect_pass = false,
        .input = "<p>one<ul><li>x</li></ul>",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <p>\n"
            "        \"one\"\n"
            "      <ul>\n"
            "        <li>\n"
            "          \"x\"\n",
    },
    {
        .suite = "html/html5",
        .name = "p-closed-by-h1",
        .expect_pass = false,
        .input = "<p>one<h1>two</h1>",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <p>\n"
            "        \"one\"\n"
            "      <h1>\n"
            "        \"two\"\n",
    },
    {
        .suite = "html/html5",
        .name = "p-closed-by-table",
        .expect_pass = false,
        .input = "<p>one<table><tbody><tr><td>x</td></tr></tbody></table>",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <p>\n"
            "        \"one\"\n"
            "      <table>\n"
            "        <tbody>\n"
            "          <tr>\n"
            "            <td>\n"
            "              \"x\"\n",
    },
    {
        .suite = "html/html5",
        .name = "li-implicit-close",
        .expect_pass = false,
        .input = "<ul><li>one<li>two</ul>",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <ul>\n"
            "        <li>\n"
            "          \"one\"\n"
            "        <li>\n"
            "          \"two\"\n",
    },
    {
        .suite = "html/html5",
        .name = "dt-implicit-close",
        .expect_pass = false,
        .input = "<dl><dt>a<dt>b</dl>",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <dl>\n"
            "        <dt>\n"
            "          \"a\"\n"
            "        <dt>\n"
            "          \"b\"\n",
    },
    {
        .suite = "html/html5",
        .name = "option-implicit-close",
        .expect_pass = false,
        .input = "<select><option>one<option>two</select>",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <select>\n"
            "        <option>\n"
            "          \"one\"\n"
            "        <option>\n"
            "          \"two\"\n",
    },
    {
        .suite = "html/html5",
        .name = "duplicate-attr-ignored",
        .expect_pass = false,
        .input = "<div id=a id=b></div>",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <div id=\"a\">\n",
    },
    {
        .suite = "html/html5",
        .name = "duplicate-attr-case-insensitive",
        .expect_pass = false,
        .input = "<div ID=a id=b></div>",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <div id=\"a\">\n",
    },
    {
        .suite = "html/html5",
        .name = "named-entity-nbsp",
        .expect_pass = false,
        .input = "<p>&nbsp;</p>",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <p>\n"
            "        \"\xC2\xA0\"\n",
    },
    {
        .suite = "html/html5",
        .name = "numeric-entity-nbsp",
        .expect_pass = false,
        .input = "<p>&#160;</p>",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <p>\n"
            "        \"\xC2\xA0\"\n",
    },
    {
        .suite = "html/html5",
        .name = "legacy-entity-copy-no-semicolon",
        .expect_pass = false,
        .input = "<p>&copy</p>",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <p>\n"
            "        \"\xC2\xA9\"\n",
    },
    {
        .suite = "html/html5",
        .name = "legacy-entity-amp-no-semicolon",
        .expect_pass = false,
        .input = "<p>&amp</p>",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <p>\n"
            "        \"&\"\n",
    },
    {
        .suite = "html/html5",
        .name = "h1-implicit-close",
        .expect_pass = false,
        .input = "<h1>one<h1>two",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <h1>\n"
            "        \"one\"\n"
            "      <h1>\n"
            "        \"two\"\n",
    },
    {
        .suite = "html/html5",
        .name = "table-implied-tbody",
        .expect_pass = false,
        .input = "<table><tr><td>x</td></tr></table>",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <table>\n"
            "        <tbody>\n"
            "          <tr>\n"
            "            <td>\n"
            "              \"x\"\n",
    },
    {
        .suite = "html/html5",
        .name = "table-implied-tr-td",
        .expect_pass = false,
        .input = "<table><td>x</td></table>",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <table>\n"
            "        <tbody>\n"
            "          <tr>\n"
            "            <td>\n"
            "              \"x\"\n",
    },
    {
        .suite = "html/html5",
        .name = "self-closing-nonvoid-nested",
        .expect_pass = false,
        .input = "<div><span/>Hi</div>",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "    <body>\n"
            "      <div>\n"
            "        <span>\n"
            "          \"Hi\"\n",
    },
    {
        .suite = "html/html5",
        .name = "link-in-implied-head",
        .expect_pass = false,
        .input = "<link rel=stylesheet href=a.css><p>x</p>",
        .expected =
            "#document\n"
            "  <html>\n"
            "    <head>\n"
            "      <link rel=\"stylesheet\" href=\"a.css\">\n"
            "    <body>\n"
            "      <p>\n"
            "        \"x\"\n",
    },
};

static const parse_case_t css_cases[] = {
    {
        .suite = "css/current",
        .name = "empty-stylesheet",
        .expect_pass = true,
        .input = "",
        .expected = "",
    },
    {
        .suite = "css/current",
        .name = "basic-color",
        .expect_pass = true,
        .input = "body { color: red; }",
        .expected =
            "selector: body\n"
            "  color: #FF0000\n",
    },
    {
        .suite = "css/current",
        .name = "multi-selector",
        .expect_pass = true,
        .input = "h1, h2 { color: blue; }",
        .expected =
            "selector: h1\n"
            "  color: #0000FF\n"
            "selector: h2\n"
            "  color: #0000FF\n",
    },
    {
        .suite = "css/current",
        .name = "comments-and-whitespace",
        .expect_pass = true,
        .input = "/*c*/\n p { /*x*/ color: #0a0; }\n",
        .expected =
            "selector: p\n"
            "  color: #00AA00\n",
    },
    {
        .suite = "css/current",
        .name = "rgb-percent",
        .expect_pass = true,
        .input = "p { color: rgb(100%,0%,0%); }",
        .expected =
            "selector: p\n"
            "  color: #FF0000\n",
    },
    {
        .suite = "css/current",
        .name = "font-shorthand",
        .expect_pass = true,
        .input = "p { font: 16px/1.5 serif; }",
        .expected =
            "selector: p\n"
            "  font-size: 16px\n"
            "  line-height: 1.5\n",
    },
    {
        .suite = "css/current",
        .name = "all-properties",
        .expect_pass = true,
        .input =
            "div {\n"
            "  background: #123456;\n"
            "  color: rgb(10,20,30);\n"
            "  font-size: 12px;\n"
            "  width: auto;\n"
            "  height: 10pt;\n"
            "  margin: 1px 2px 3px 4px;\n"
            "  padding: 5px 6px;\n"
            "  border: 1px solid red;\n"
            "  float: right;\n"
            "  clear: both;\n"
            "  text-align: center;\n"
            "  text-decoration: underline;\n"
            "  text-shadow: 1px 2px 3px #010203;\n"
            "  display: list-item;\n"
            "  line-height: 1.5;\n"
            "  letter-spacing: 0.25em;\n"
            "  opacity: 0.5;\n"
            "}\n",
        .expected =
            "selector: div\n"
            "  background: #123456\n"
            "  color: #0A141E\n"
            "  font-size: 12px\n"
            "  width: auto\n"
            "  height: 13.333px\n"
            "  margin: 1px 2px 3px 4px\n"
            "  padding: 5px 6px 5px 6px\n"
            "  border-width: 1px 1px 1px 1px\n"
            "  border-color: #FF0000\n"
            "  float: right\n"
            "  clear: both\n"
            "  text-align: center\n"
            "  text-decoration: underline\n"
            "  text-shadow: 1px 2px 3px #010203\n"
            "  display: list-item\n"
            "  line-height: 1.5\n"
            "  letter-spacing: 0.25em\n"
            "  opacity: 0.5\n",
    },

    CSS_CASE("css/current", "selector-trim-and-lower", true,
             "  BODY  { COLOR : RED }",
             "selector: body\n"
             "  color: #FF0000\n"),
    CSS_CASE("css/current", "color-black", true,
             "p { color: black; }",
             "selector: p\n"
             "  color: #000000\n"),
    CSS_CASE("css/current", "color-white", true,
             "p { color: white; }",
             "selector: p\n"
             "  color: #FFFFFF\n"),
    CSS_CASE("css/current", "color-green", true,
             "p { color: green; }",
             "selector: p\n"
             "  color: #008000\n"),
    CSS_CASE("css/current", "color-grey", true,
             "p { color: grey; }",
             "selector: p\n"
             "  color: #808080\n"),
    CSS_CASE("css/current", "color-yellow", true,
             "p { color: yellow; }",
             "selector: p\n"
             "  color: #FFFF00\n"),
    CSS_CASE("css/current", "color-hex3", true,
             "p { color: #abc; }",
             "selector: p\n"
             "  color: #AABBCC\n"),
    CSS_CASE("css/current", "color-hex6-mixed-case", true,
             "p { color: #AaBbCc; }",
             "selector: p\n"
             "  color: #AABBCC\n"),
    CSS_CASE("css/current", "color-rgb-spaces", true,
             "p { color: rgb( 10 , 20 , 30 ); }",
             "selector: p\n"
             "  color: #0A141E\n"),
    CSS_CASE("css/current", "color-rgb-clamp", true,
             "p { color: rgb(999,0,0); }",
             "selector: p\n"
             "  color: #FF0000\n"),
    CSS_CASE("css/current", "color-rgb-percent-50", true,
             "p { color: rgb(50%,0%,0%); }",
             "selector: p\n"
             "  color: #7F0000\n"),
    CSS_CASE("css/current", "color-navy", true,
             "p { color: navy; }",
             "selector: p\n"
             "  color: #000080\n"),
    CSS_CASE("css/current", "color-maroon", true,
             "p { color: maroon; }",
             "selector: p\n"
             "  color: #800000\n"),
    CSS_CASE("css/current", "color-purple", true,
             "p { color: purple; }",
             "selector: p\n"
             "  color: #800080\n"),
    CSS_CASE("css/current", "color-orange", true,
             "p { color: orange; }",
             "selector: p\n"
             "  color: #FFA500\n"),
    CSS_CASE("css/current", "color-pink", true,
             "p { color: pink; }",
             "selector: p\n"
             "  color: #FFC0CB\n"),
    CSS_CASE("css/current", "background-color-alias", true,
             "p { background-color: blue; }",
             "selector: p\n"
             "  background: #0000FF\n"),
    CSS_CASE("css/current", "background-shorthand-hex3", true,
             "p { background: #123; }",
             "selector: p\n"
             "  background: #112233\n"),
    CSS_CASE("css/current", "width-auto", true,
             "p { width: auto; }",
             "selector: p\n"
             "  width: auto\n"),
    CSS_CASE("css/current", "width-percent", true,
             "p { width: 50%; }",
             "selector: p\n"
             "  width: 50%\n"),
    CSS_CASE("css/current", "width-vw", true,
             "p { width: 20vw; }",
             "selector: p\n"
             "  width: 20vw\n"),
    CSS_CASE("css/current", "height-vh", true,
             "p { height: 10vh; }",
             "selector: p\n"
             "  height: 10vh\n"),
    CSS_CASE("css/current", "height-pt-to-px", true,
             "p { height: 12pt; }",
             "selector: p\n"
             "  height: 16px\n"),
    CSS_CASE("css/current", "margin-1", true,
             "p { margin: 1px; }",
             "selector: p\n"
             "  margin: 1px 1px 1px 1px\n"),
    CSS_CASE("css/current", "margin-2", true,
             "p { margin: 1px 2px; }",
             "selector: p\n"
             "  margin: 1px 2px 1px 2px\n"),
    CSS_CASE("css/current", "margin-3", true,
             "p { margin: 1px 2px 3px; }",
             "selector: p\n"
             "  margin: 1px 2px 3px 2px\n"),
    CSS_CASE("css/current", "padding-2", true,
             "p { padding: 5px 6px; }",
             "selector: p\n"
             "  padding: 5px 6px 5px 6px\n"),
    CSS_CASE("css/current", "border-width-4", true,
             "p { border-width: 1px 2px 3px 4px; }",
             "selector: p\n"
             "  border-width: 1px 2px 3px 4px\n"),
    CSS_CASE("css/current", "border-color-hex3", true,
             "p { border-color: #abc; }",
             "selector: p\n"
             "  border-color: #AABBCC\n"),
    CSS_CASE("css/current", "border-shorthand-width-color", true,
             "p { border: 2px solid blue; }",
             "selector: p\n"
             "  border-width: 2px 2px 2px 2px\n"
             "  border-color: #0000FF\n"),
    CSS_CASE("css/current", "border-color-transparent", true,
             "p { border-color: transparent; }",
             "selector: p\n"
             "  border-color: transparent\n"),
    CSS_CASE("css/current", "border-shorthand-transparent", true,
             "p { border: 2px solid transparent; }",
             "selector: p\n"
             "  border-width: 2px 2px 2px 2px\n"
             "  border-color: transparent\n"),
    CSS_CASE("css/current", "border-shorthand-width-only", true,
             "p { border: 2px; }",
             "selector: p\n"
             "  border-width: 2px 2px 2px 2px\n"),
    CSS_CASE("css/current", "border-shorthand-color-only-ignored", true,
             "p { border: red; }",
             "selector: p\n"),
    CSS_CASE("css/current", "float-right", true,
             "p { float: right; }",
             "selector: p\n"
             "  float: right\n"),
    CSS_CASE("css/current", "clear-both", true,
             "p { clear: both; }",
             "selector: p\n"
             "  clear: both\n"),
    CSS_CASE("css/current", "text-align-right", true,
             "p { text-align: right; }",
             "selector: p\n"
             "  text-align: right\n"),
    CSS_CASE("css/current", "text-decoration-none", true,
             "p { text-decoration: none; }",
             "selector: p\n"
             "  text-decoration: none\n"),
    CSS_CASE("css/current", "text-shadow-two-lengths", true,
             "p { text-shadow: 1px 2px; }",
             "selector: p\n"
             "  text-shadow: 1px 2px 0\n"),
    CSS_CASE("css/current", "text-shadow-color-name", true,
             "p { text-shadow: 1px 2px red; }",
             "selector: p\n"
             "  text-shadow: 1px 2px 0 #FF0000\n"),
    CSS_CASE("css/current", "display-none", true,
             "p { display: none; }",
             "selector: p\n"
             "  display: none\n"),
    CSS_CASE("css/current", "display-table", true,
             "ul { display: table; } li { display: table-cell; }",
             "selector: ul\n"
             "  display: table\n"
             "selector: li\n"
             "  display: table-cell\n"),
    CSS_CASE("css/current", "z-index", true,
             "p { position: relative; z-index: 2; }",
             "selector: p\n"
             "  z-index: 2\n"),
    CSS_CASE("css/current", "line-height-percent", true,
             "p { line-height: 120%; }",
             "selector: p\n"
             "  line-height: 1.2\n"),
    CSS_CASE("css/current", "line-height-px", true,
             "p { line-height: 18px; }",
             "selector: p\n"
             "  line-height: 18px\n"),
    CSS_CASE("css/current", "line-height-pt", true,
             "p { line-height: 12pt; }",
             "selector: p\n"
             "  line-height: 16px\n"),
    CSS_CASE("css/current", "font-shorthand-percent-line-height", true,
             "p { font: 12pt/150% serif; }",
             "selector: p\n"
             "  font-size: 16px\n"
             "  line-height: 1.5\n"),
    CSS_CASE("css/current", "letter-spacing-dot5em", true,
             "p { letter-spacing: .5em; }",
             "selector: p\n"
             "  letter-spacing: 0.5em\n"),
    CSS_CASE("css/current", "opacity-clamp", true,
             "p { opacity: 2.5; }",
             "selector: p\n"
             "  opacity: 1\n"),
    CSS_CASE("css/current", "opacity-0.25", true,
             "p { opacity: 0.25; }",
             "selector: p\n"
             "  opacity: 0.25\n"),
    CSS_CASE("css/current", "unknown-property-ignored", true,
             "p { foo: bar; }",
             "selector: p\n"),
    CSS_CASE("css/current", "unknown-color-ignored", true,
             "p { color: magenta; }",
             "selector: p\n"),
    CSS_CASE("css/current", "missing-semicolon-ok", true,
             "p { color: red }",
             "selector: p\n"
             "  color: #FF0000\n"),
    CSS_CASE("css/current", "missing-closing-brace-ok", true,
             "p { color: red;",
             "selector: p\n"
             "  color: #FF0000\n"),
    CSS_CASE("css/current", "multiple-rules", true,
             "p { color:red; } div { width:10px; }",
             "selector: p\n"
             "  color: #FF0000\n"
             "selector: div\n"
             "  width: 10px\n"),
    CSS_CASE("css/current", "selector-leading-comma-ignored", false,
             ", p { color: red; }",
             "selector: p\n"
             "  color: #FF0000\n"),

    {
        .suite = "css/css4",
        .name = "rgba-color",
        .expect_pass = false,
        .input = "p { color: rgba(255,0,0,0.5); }",
        .expected =
            "selector: p\n"
            "  color: rgba(255,0,0,0.5)\n",
    },
    {
        .suite = "css/css4",
        .name = "space-separated-rgb",
        .expect_pass = false,
        .input = "p { color: rgb(255 0 0 / 50%); }",
        .expected =
            "selector: p\n"
            "  color: rgb(255 0 0 / 50%)\n",
    },
    {
        .suite = "css/css4",
        .name = "calc-length",
        .expect_pass = false,
        .input = "div { width: calc(100% - 10px); }",
        .expected =
            "selector: div\n"
            "  width: calc(100% - 10px)\n",
    },
    {
        .suite = "css/css4",
        .name = "rem-unit",
        .expect_pass = false,
        .input = "p { font-size: 2rem; }",
        .expected =
            "selector: p\n"
            "  font-size: 2rem\n",
    },
    CSS_CASE("css/css4", "hsl-color", false,
             "p { color: hsl(0 100% 50%); }",
             "selector: p\n"
             "  color: hsl(0 100% 50%)\n"),
    CSS_CASE("css/css4", "hsla-color", false,
             "p { color: hsla(120, 100%, 25%, 0.5); }",
             "selector: p\n"
             "  color: hsla(120, 100%, 25%, 0.5)\n"),
    CSS_CASE("css/css4", "hex8-alpha", false,
             "p { color: #ff000080; }",
             "selector: p\n"
             "  color: #FF000080\n"),
    CSS_CASE("css/css4", "hex4-alpha", false,
             "p { color: #f008; }",
             "selector: p\n"
             "  color: #F008\n"),
    CSS_CASE("css/css4", "transparent-keyword", false,
             "p { color: transparent; }",
             "selector: p\n"
             "  color: transparent\n"),
    CSS_CASE("css/css4", "currentcolor-keyword", false,
             "p { color: currentColor; }",
             "selector: p\n"
             "  color: currentcolor\n"),
    CSS_CASE("css/css4", "color-mix", false,
             "p { color: color-mix(in srgb, red 50%, blue); }",
             "selector: p\n"
             "  color: color-mix(in srgb, red 50%, blue)\n"),
    CSS_CASE("css/css4", "var-function", false,
             "p { color: var(--c); }",
             "selector: p\n"
             "  color: var(--c)\n"),
    CSS_CASE("css/css4", "clamp-length", false,
             "div { width: clamp(10px, 5vw, 100px); }",
             "selector: div\n"
             "  width: clamp(10px, 5vw, 100px)\n"),
    CSS_CASE("css/css4", "vmin-unit", false,
             "div { width: 10vmin; }",
             "selector: div\n"
             "  width: 10vmin\n"),
    CSS_CASE("css/css4", "display-flex", false,
             "div { display: flex; }",
             "selector: div\n"
             "  display: flex\n"),
    CSS_CASE("css/css4", "border-color-from-shorthand", false,
             "p { border: red; }",
             "selector: p\n"
             "  border-color: #FF0000\n"),
    CSS_CASE("css/css4", "border-default-width", false,
             "p { border: solid red; }",
             "selector: p\n"
             "  border-width: medium\n"
             "  border-color: #FF0000\n"),
    CSS_CASE("css/css4", "negative-margin", false,
             "p { margin: -1px 2px; }",
             "selector: p\n"
             "  margin: -1px 2px -1px 2px\n"),
    CSS_CASE("css/css4", "line-height-normal", false,
             "p { line-height: normal; }",
             "selector: p\n"
             "  line-height: normal\n"),
    CSS_CASE("css/css4", "font-size-keyword", false,
             "p { font-size: medium; }",
             "selector: p\n"
             "  font-size: medium\n"),
    CSS_CASE("css/css4", "at-media-nesting", false,
             "@media screen { p { color: red; } }",
             "@media screen {\n"
             "  selector: p\n"
             "    color: #FF0000\n"
             "}\n"),
    CSS_CASE("css/css4", "rebeccapurple-color", false,
             "p { color: rebeccapurple; }",
             "selector: p\n"
             "  color: #663399\n"),
    CSS_CASE("css/css4", "aliceblue-color", false,
             "p { color: aliceblue; }",
             "selector: p\n"
             "  color: #F0F8FF\n"),
    CSS_CASE("css/css4", "rgb-space-alpha-number", false,
             "p { color: rgb(255 0 0 / 0.5); }",
             "selector: p\n"
             "  color: rgb(255 0 0 / 0.5)\n"),
    CSS_CASE("css/css4", "var-function-fallback", false,
             "p { color: var(--c, red); }",
             "selector: p\n"
             "  color: var(--c, red)\n"),
    CSS_CASE("css/css4", "min-length", false,
             "div { width: min(10px, 5vw); }",
             "selector: div\n"
             "  width: min(10px, 5vw)\n"),
    CSS_CASE("css/css4", "max-length", false,
             "div { width: max(10px, 5vw); }",
             "selector: div\n"
             "  width: max(10px, 5vw)\n"),
    CSS_CASE("css/css4", "vmax-unit", false,
             "div { width: 10vmax; }",
             "selector: div\n"
             "  width: 10vmax\n"),
    CSS_CASE("css/css4", "svh-unit", false,
             "div { height: 100svh; }",
             "selector: div\n"
             "  height: 100svh\n"),
    CSS_CASE("css/css4", "font-size-calc", false,
             "p { font-size: calc(1rem + 2px); }",
             "selector: p\n"
             "  font-size: calc(1rem + 2px)\n"),
    CSS_CASE("css/css4", "background-transparent", false,
             "p { background: transparent; }",
             "selector: p\n"
             "  background: transparent\n"),
    CSS_CASE("css/css4", "margin-too-many-values-invalid", false,
             "p { margin: 1px 2px 3px 4px 5px; }",
             "selector: p\n"),
};

static const css_match_case_t css_match_cases[] = {
    { .suite = "css/current", .name = "tag-match", .expect_pass = true, .selector = "div", .tag = "div", .expected_match = true },
    { .suite = "css/current", .name = "tag-mismatch", .expect_pass = true, .selector = "div", .tag = "span", .expected_match = false },
    { .suite = "css/current", .name = "tag-with-pseudo", .expect_pass = true, .selector = "div:hover", .tag = "div", .expected_match = true },
    { .suite = "css/current", .name = "tag-with-class-suffix", .expect_pass = true, .selector = "div.note", .tag = "div", .expected_match = true },
    { .suite = "css/current", .name = "tag-with-id-suffix", .expect_pass = true, .selector = "div#main", .tag = "div", .expected_match = true },
    { .suite = "css/current", .name = "tag-with-attr-suffix", .expect_pass = true, .selector = "div[data-x]", .tag = "div", .expected_match = true },
    { .suite = "css/current", .name = "tag-with-descendant", .expect_pass = true, .selector = "div span", .tag = "div", .expected_match = true },
    { .suite = "css/current", .name = "tag-with-leading-whitespace", .expect_pass = true, .selector = "  div", .tag = "div", .expected_match = true },
    { .suite = "css/current", .name = "uppercase-tag", .expect_pass = true, .selector = "DIV.note", .tag = "div", .expected_match = true },
    { .suite = "css/current", .name = "hyphenated-tag", .expect_pass = true, .selector = "custom-element", .tag = "custom-element", .expected_match = true },

    { .suite = "css/css4", .name = "class-only-selector", .expect_pass = false, .selector = ".note", .tag = "div", .expected_match = true },
    { .suite = "css/css4", .name = "universal-selector", .expect_pass = false, .selector = "*", .tag = "div", .expected_match = true },
    { .suite = "css/css4", .name = "id-selector", .expect_pass = false, .selector = "#main", .tag = "div", .expected_match = true },
    { .suite = "css/css4", .name = "attr-selector", .expect_pass = false, .selector = "[data-x]", .tag = "div", .expected_match = true },
    { .suite = "css/css4", .name = "attr-selector-equals", .expect_pass = false, .selector = "[data-x=\"1\"]", .tag = "div", .expected_match = true },
    { .suite = "css/css4", .name = "root-pseudo", .expect_pass = false, .selector = ":root", .tag = "html", .expected_match = true },
    { .suite = "css/css4", .name = "before-pseudo-element", .expect_pass = false, .selector = "div::before", .tag = "div", .expected_match = true },
    { .suite = "css/css4", .name = "descendant-selector-target", .expect_pass = false, .selector = "div span", .tag = "span", .expected_match = true },
    { .suite = "css/css4", .name = "descendant-selector-not-target", .expect_pass = false, .selector = "div span", .tag = "div", .expected_match = false },
    { .suite = "css/css4", .name = "child-selector-target", .expect_pass = false, .selector = "div > span", .tag = "span", .expected_match = true },
    { .suite = "css/css4", .name = "child-selector-not-target", .expect_pass = false, .selector = "div > span", .tag = "div", .expected_match = false },
    { .suite = "css/css4", .name = "adjacent-sibling-target", .expect_pass = false, .selector = "div + span", .tag = "span", .expected_match = true },
    { .suite = "css/css4", .name = "adjacent-sibling-not-target", .expect_pass = false, .selector = "div + span", .tag = "div", .expected_match = false },
    { .suite = "css/css4", .name = "general-sibling-target", .expect_pass = false, .selector = "div ~ span", .tag = "span", .expected_match = true },
    { .suite = "css/css4", .name = "general-sibling-not-target", .expect_pass = false, .selector = "div ~ span", .tag = "div", .expected_match = false },
    { .suite = "css/css4", .name = "not-pseudo-class", .expect_pass = false, .selector = ":not(span)", .tag = "div", .expected_match = true },
    { .suite = "css/css4", .name = "is-pseudo-class", .expect_pass = false, .selector = ":is(div, span)", .tag = "div", .expected_match = true },
    { .suite = "css/css4", .name = "nth-child-pseudo-class", .expect_pass = false, .selector = ":nth-child(2)", .tag = "div", .expected_match = true },
};

static const url_case_t url_cases[] = {
    { .suite = "url/current", .name = "svg-extension", .expect_pass = true, .url = "https://news.ycombinator.com/y18.svg", .expected_svg = true },
    { .suite = "url/current", .name = "svg-extension-uppercase", .expect_pass = true, .url = "https://example.com/icon.SVG", .expected_svg = true },
    { .suite = "url/current", .name = "svg-extension-query", .expect_pass = true, .url = "https://example.com/icon.svg?cache=1", .expected_svg = true },
    { .suite = "url/current", .name = "svg-extension-fragment", .expect_pass = true, .url = "https://example.com/icon.svg#hash", .expected_svg = true },
    { .suite = "url/current", .name = "svg-extensionz", .expect_pass = true, .url = "https://example.com/icon.svgz", .expected_svg = false },
    { .suite = "url/current", .name = "png-extension", .expect_pass = true, .url = "https://example.com/icon.png", .expected_svg = false },
    { .suite = "url/current", .name = "empty-url", .expect_pass = true, .url = "", .expected_svg = false },
    { .suite = "url/current", .name = "null-url", .expect_pass = true, .url = NULL, .expected_svg = false },
};

static bool run_html_case(const parse_case_t *tc, sb_t *scratch, bool show_failures)
{
    html_parse_error_t err = {0};
    html_document_t *doc = html_parse(tc->input, &err);
    if (!doc)
    {
        if (show_failures)
        {
            printf("html: %s/%s: parse failed at %zu: %s\n",
                   tc->suite, tc->name, err.offset, err.message ? err.message : "<no message>");
        }
        return false;
    }
    bool ok = html_serialize_doc(scratch, doc) && str_eq_trimmed(scratch->data ? scratch->data : "", tc->expected);
    if (!ok && show_failures)
    {
        printf("html: %s/%s: mismatch\n", tc->suite, tc->name);
        printf("expected:\n%s\n", tc->expected ? tc->expected : "");
        printf("got:\n%s\n", scratch->data ? scratch->data : "");
    }
    html_document_destroy(doc);
    return ok;
}

static bool run_css_case(const parse_case_t *tc, sb_t *scratch, bool show_failures)
{
    css_stylesheet_t *sheet = css_parse(tc->input);
    if (!sheet)
    {
        if (show_failures)
        {
            printf("css: %s/%s: parse returned NULL\n", tc->suite, tc->name);
        }
        return false;
    }
    bool ok = css_serialize_sheet(scratch, sheet) && str_eq_trimmed(scratch->data ? scratch->data : "", tc->expected);
    if (!ok && show_failures)
    {
        printf("css: %s/%s: mismatch\n", tc->suite, tc->name);
        printf("expected:\n%s\n", tc->expected ? tc->expected : "");
        printf("got:\n%s\n", scratch->data ? scratch->data : "");
    }
    css_stylesheet_destroy(sheet);
    return ok;
}

static bool run_css_match_case(const css_match_case_t *tc, bool show_failures)
{
    css_rule_t rule = {0};
    rule.selector = (char *)tc->selector;
    bool got = css_rule_matches_tag(&rule, tc->tag);
    if (got != tc->expected_match)
    {
        if (show_failures)
        {
            printf("css: %s/%s: selector=\"%s\" tag=\"%s\" expected=%s got=%s\n",
                   tc->suite,
                   tc->name,
                   tc->selector ? tc->selector : "",
                   tc->tag ? tc->tag : "",
                   tc->expected_match ? "true" : "false",
                   got ? "true" : "false");
        }
        return false;
    }
    return true;
}

static bool run_url_case(const url_case_t *tc, bool show_failures)
{
    bool got = web_url_is_svg(tc->url);
    if (got != tc->expected_svg)
    {
        if (show_failures)
        {
            printf("url: %s/%s: url=\"%s\" expected=%s got=%s\n",
                   tc->suite,
                   tc->name,
                   tc->url ? tc->url : "<null>",
                   tc->expected_svg ? "svg" : "not svg",
                   got ? "svg" : "not svg");
        }
        return false;
    }
    return true;
}

static bool run_html_null_input_test(bool show_failures)
{
    html_parse_error_t err = {0};
    html_document_t *doc = html_parse(NULL, &err);
    if (doc != NULL)
    {
        if (show_failures)
        {
            printf("html: html/current/null-input: expected NULL doc\n");
        }
        html_document_destroy(doc);
        return false;
    }
    if (!err.message || strcmp(err.message, "null input") != 0)
    {
        if (show_failures)
        {
            printf("html: html/current/null-input: expected message \"null input\" got \"%s\"\n",
                   err.message ? err.message : "<null>");
        }
        return false;
    }
    return true;
}

static bool run_css_null_input_test(bool show_failures)
{
    css_stylesheet_t *sheet = css_parse(NULL);
    if (sheet != NULL)
    {
        if (show_failures)
        {
            printf("css: css/current/null-input: expected NULL sheet\n");
        }
        css_stylesheet_destroy(sheet);
        return false;
    }
    return true;
}

int main(void)
{
    const char *verbose_env = getenv("WEB_TEST_VERBOSE");
    const bool verbose = (verbose_env && verbose_env[0] != '\0' && strcmp(verbose_env, "0") != 0);
    sb_t scratch = {0};

    test_counts_t html_counts = {0};
    test_counts_t css_counts = {0};
    test_counts_t url_counts = {0};

    struct
    {
        test_counts_t *counts;
        const char *suite;
        const char *name;
        bool expect_pass;
        bool (*fn)(bool show_failures);
    } fn_tests[] = {
        { &html_counts, "html/current", "null-input", true, run_html_null_input_test },
        { &css_counts, "css/current", "null-input", true, run_css_null_input_test },
    };

    for (size_t i = 0; i < ARRAY_LEN(fn_tests); ++i)
    {
        bool ok = fn_tests[i].fn(verbose || fn_tests[i].expect_pass);
        test_counts_add(fn_tests[i].counts, ok, fn_tests[i].expect_pass);
    }

    for (size_t i = 0; i < ARRAY_LEN(html_cases); ++i)
    {
        bool ok = run_html_case(&html_cases[i], &scratch, verbose || html_cases[i].expect_pass);
        test_counts_add(&html_counts, ok, html_cases[i].expect_pass);
    }

    for (size_t i = 0; i < ARRAY_LEN(css_cases); ++i)
    {
        bool ok = run_css_case(&css_cases[i], &scratch, verbose || css_cases[i].expect_pass);
        test_counts_add(&css_counts, ok, css_cases[i].expect_pass);
    }

    for (size_t i = 0; i < ARRAY_LEN(css_match_cases); ++i)
    {
        bool ok = run_css_match_case(&css_match_cases[i], verbose || css_match_cases[i].expect_pass);
        test_counts_add(&css_counts, ok, css_match_cases[i].expect_pass);
    }

    for (size_t i = 0; i < ARRAY_LEN(url_cases); ++i)
    {
        bool ok = run_url_case(&url_cases[i], verbose || url_cases[i].expect_pass);
        test_counts_add(&url_counts, ok, url_cases[i].expect_pass);
    }

    sb_destroy(&scratch);

    test_counts_t all_counts = test_counts_sum(html_counts, css_counts);
    all_counts = test_counts_sum(all_counts, url_counts);
    test_counts_print("html", &html_counts);
    test_counts_print("css", &css_counts);
    test_counts_print("url", &url_counts);
    test_counts_print("all", &all_counts);

    return all_counts.fail == 0 ? 0 : 1;
}
