#include "web/css/css_internal.h"

#include "ctype.h"
#include "libc.h"

static bool css_next_token(const char **p, const char *end, const char **tok_start, const char **tok_end)
{
    if (!p || !*p || !end || !tok_start || !tok_end)
    {
        return false;
    }
    const char *s = *p;
    while (s < end && isspace((unsigned char)*s))
    {
        ++s;
    }
    if (s >= end)
    {
        *p = end;
        return false;
    }
    const char *start = s;
    while (s < end && !isspace((unsigned char)*s))
    {
        ++s;
    }
    *tok_start = start;
    *tok_end = s;
    *p = s;
    return true;
}

static bool css_parse_border_width_token(const char *start,
                                         const char *end,
                                         css_length_t *out)
{
    if (!out)
    {
        return false;
    }

    css_trim_range(&start, &end);
    if (!start || !end || end <= start)
    {
        return false;
    }

    size_t len = (size_t)(end - start);
    if (len == 4 && strncasecmp(start, "thin", 4) == 0)
    {
        out->valid = true;
        out->is_auto = false;
        out->unit = CSS_UNIT_PX;
        out->value_milli = 1000;
        return true;
    }
    if (len == 6 && strncasecmp(start, "medium", 6) == 0)
    {
        out->valid = true;
        out->is_auto = false;
        out->unit = CSS_UNIT_PX;
        out->value_milli = 3000;
        return true;
    }
    if (len == 5 && strncasecmp(start, "thick", 5) == 0)
    {
        out->valid = true;
        out->is_auto = false;
        out->unit = CSS_UNIT_PX;
        out->value_milli = 5000;
        return true;
    }

    if (!css_parse_length_token(start, end, out))
    {
        return false;
    }
    if (out->is_auto)
    {
        return false;
    }
    return true;
}

static bool css_parse_border_width_value(const char *start, const char *end, css_box_t *out)
{
    if (!out)
    {
        return false;
    }
    memset(out, 0, sizeof(*out));

    css_trim_range(&start, &end);
    if (!start || !end || end <= start)
    {
        return false;
    }

    const char *tokens[4] = {0};
    size_t token_lens[4] = {0};
    size_t count = 0;

    const char *p = start;
    while (p < end && count < 4)
    {
        while (p < end && isspace((unsigned char)*p))
        {
            p++;
        }
        if (p >= end)
        {
            break;
        }
        const char *tstart = p;
        while (p < end && !isspace((unsigned char)*p))
        {
            p++;
        }
        tokens[count] = tstart;
        token_lens[count] = (size_t)(p - tstart);
        count++;
    }

    if (count == 0)
    {
        return false;
    }

    css_length_t parsed[4] = {0};
    for (size_t i = 0; i < count; ++i)
    {
        const char *tstart = tokens[i];
        const char *tend = tstart + token_lens[i];
        if (!css_parse_border_width_token(tstart, tend, &parsed[i]))
        {
            return false;
        }
    }

    if (count == 1)
    {
        out->top = parsed[0];
        out->right = parsed[0];
        out->bottom = parsed[0];
        out->left = parsed[0];
        return true;
    }
    if (count == 2)
    {
        out->top = parsed[0];
        out->bottom = parsed[0];
        out->left = parsed[1];
        out->right = parsed[1];
        return true;
    }
    if (count == 3)
    {
        out->top = parsed[0];
        out->left = parsed[1];
        out->right = parsed[1];
        out->bottom = parsed[2];
        return true;
    }
    out->top = parsed[0];
    out->right = parsed[1];
    out->bottom = parsed[2];
    out->left = parsed[3];
    return true;
}

static bool css_parse_border_value(const char *start,
                                   const char *end,
                                   css_length_t *out_width,
                                   video_color_t *out_color,
                                   bool *out_has_color)
{
    if (!out_width || !out_color || !out_has_color)
    {
        return false;
    }
    memset(out_width, 0, sizeof(*out_width));
    *out_color = video_make_color(0x00, 0x00, 0x00);
    *out_has_color = false;

    css_trim_range(&start, &end);
    if (!start || !end || end <= start)
    {
        return false;
    }

    bool have_width = false;
    const char *p = start;
    const char *tok_s = NULL;
    const char *tok_e = NULL;

    while (css_next_token(&p, end, &tok_s, &tok_e))
    {
        if (!have_width)
        {
            css_length_t len;
            if (css_parse_border_width_token(tok_s, tok_e, &len))
            {
                *out_width = len;
                have_width = true;
                continue;
            }
        }

        if (!*out_has_color)
        {
            video_color_t c;
            if (css_parse_color(tok_s, tok_e, &c))
            {
                *out_color = c;
                *out_has_color = true;
                continue;
            }
        }
    }

    return have_width;
}

static bool css_parse_text_shadow_value(const char *start,
                                       const char *end,
                                       css_length_t *out_x,
                                       css_length_t *out_y,
                                       css_length_t *out_blur,
                                       video_color_t *out_color,
                                       bool *out_has_color)
{
    if (!out_x || !out_y || !out_blur || !out_color || !out_has_color)
    {
        return false;
    }

    memset(out_x, 0, sizeof(*out_x));
    memset(out_y, 0, sizeof(*out_y));
    memset(out_blur, 0, sizeof(*out_blur));
    *out_color = video_make_color(0x00, 0x00, 0x00);
    *out_has_color = false;

    css_trim_range(&start, &end);
    if (!start || !end || end <= start)
    {
        return false;
    }

    css_length_t lens[3] = {0};
    int len_count = 0;

    const char *p = start;
    const char *tok_s = NULL;
    const char *tok_e = NULL;
    while (css_next_token(&p, end, &tok_s, &tok_e))
    {
        if (len_count < 3)
        {
            css_length_t len;
            if (css_parse_length_token(tok_s, tok_e, &len) && !len.is_auto)
            {
                lens[len_count++] = len;
                continue;
            }
        }

        video_color_t c;
        if (css_parse_color(tok_s, tok_e, &c))
        {
            *out_color = c;
            *out_has_color = true;
            continue;
        }
    }

    if (len_count < 2)
    {
        return false;
    }

    *out_x = lens[0];
    *out_y = lens[1];
    if (len_count >= 3)
    {
        *out_blur = lens[2];
    }
    return true;
}

static bool css_parse_flex_direction_keyword(const char *start, const char *end, css_flex_direction_t *out)
{
    if (!out)
    {
        return false;
    }
    css_trim_range(&start, &end);
    size_t len = (size_t)(end - start);
    if (len == 3 && strncasecmp(start, "row", 3) == 0)
    {
        *out = CSS_FLEX_DIRECTION_ROW;
        return true;
    }
    if (len == 11 && strncasecmp(start, "row-reverse", 11) == 0)
    {
        *out = CSS_FLEX_DIRECTION_ROW_REVERSE;
        return true;
    }
    if (len == 6 && strncasecmp(start, "column", 6) == 0)
    {
        *out = CSS_FLEX_DIRECTION_COLUMN;
        return true;
    }
    if (len == 14 && strncasecmp(start, "column-reverse", 14) == 0)
    {
        *out = CSS_FLEX_DIRECTION_COLUMN_REVERSE;
        return true;
    }
    return false;
}

static bool css_parse_flex_wrap_keyword(const char *start, const char *end, css_flex_wrap_t *out)
{
    if (!out)
    {
        return false;
    }
    css_trim_range(&start, &end);
    size_t len = (size_t)(end - start);
    if (len == 6 && strncasecmp(start, "nowrap", 6) == 0)
    {
        *out = CSS_FLEX_WRAP_NOWRAP;
        return true;
    }
    if (len == 4 && strncasecmp(start, "wrap", 4) == 0)
    {
        *out = CSS_FLEX_WRAP_WRAP;
        return true;
    }
    if (len == 11 && strncasecmp(start, "wrap-reverse", 11) == 0)
    {
        *out = CSS_FLEX_WRAP_WRAP_REVERSE;
        return true;
    }
    return false;
}

static bool css_parse_justify_keyword(const char *start, const char *end, css_justify_content_t *out)
{
    if (!out)
    {
        return false;
    }
    css_trim_range(&start, &end);
    size_t len = (size_t)(end - start);
    if ((len == 10 && strncasecmp(start, "flex-start", 10) == 0) ||
        (len == 5 && strncasecmp(start, "start", 5) == 0))
    {
        *out = CSS_JUSTIFY_FLEX_START;
        return true;
    }
    if ((len == 8 && strncasecmp(start, "flex-end", 8) == 0) ||
        (len == 3 && strncasecmp(start, "end", 3) == 0))
    {
        *out = CSS_JUSTIFY_FLEX_END;
        return true;
    }
    if (len == 6 && strncasecmp(start, "center", 6) == 0)
    {
        *out = CSS_JUSTIFY_CENTER;
        return true;
    }
    if (len == 13 && strncasecmp(start, "space-between", 13) == 0)
    {
        *out = CSS_JUSTIFY_SPACE_BETWEEN;
        return true;
    }
    if (len == 11 && strncasecmp(start, "space-around", 11) == 0)
    {
        *out = CSS_JUSTIFY_SPACE_AROUND;
        return true;
    }
    if (len == 12 && strncasecmp(start, "space-evenly", 12) == 0)
    {
        *out = CSS_JUSTIFY_SPACE_EVENLY;
        return true;
    }
    return false;
}

static bool css_parse_align_keyword(const char *start, const char *end, css_align_t *out)
{
    if (!out)
    {
        return false;
    }
    css_trim_range(&start, &end);
    size_t len = (size_t)(end - start);
    if (len == 7 && strncasecmp(start, "stretch", 7) == 0)
    {
        *out = CSS_ALIGN_STRETCH;
        return true;
    }
    if ((len == 10 && strncasecmp(start, "flex-start", 10) == 0) ||
        (len == 5 && strncasecmp(start, "start", 5) == 0))
    {
        *out = CSS_ALIGN_FLEX_START;
        return true;
    }
    if ((len == 8 && strncasecmp(start, "flex-end", 8) == 0) ||
        (len == 3 && strncasecmp(start, "end", 3) == 0))
    {
        *out = CSS_ALIGN_FLEX_END;
        return true;
    }
    if (len == 6 && strncasecmp(start, "center", 6) == 0)
    {
        *out = CSS_ALIGN_CENTER;
        return true;
    }
    if (len == 8 && strncasecmp(start, "baseline", 8) == 0)
    {
        *out = CSS_ALIGN_BASELINE;
        return true;
    }
    return false;
}

static bool css_parse_gap_value(const char *start,
                                const char *end,
                                css_length_t *out_row,
                                css_length_t *out_col,
                                bool *out_row_set,
                                bool *out_col_set)
{
    if (!out_row || !out_col || !out_row_set || !out_col_set)
    {
        return false;
    }
    *out_row_set = false;
    *out_col_set = false;
    css_trim_range(&start, &end);
    if (end <= start)
    {
        return false;
    }
    const char *p = start;
    const char *tok_s = NULL;
    const char *tok_e = NULL;
    if (!css_next_token(&p, end, &tok_s, &tok_e))
    {
        return false;
    }
    if (!css_parse_length_token(tok_s, tok_e, out_row))
    {
        return false;
    }
    *out_row_set = true;

    if (css_next_token(&p, end, &tok_s, &tok_e))
    {
        if (!css_parse_length_token(tok_s, tok_e, out_col))
        {
            return false;
        }
        *out_col_set = true;
    }
    else
    {
        *out_col = *out_row;
        *out_col_set = true;
    }
    return true;
}

static void css_apply_flex_shorthand(css_style_t *style, const char *start, const char *end)
{
    if (!style)
    {
        return;
    }
    css_trim_range(&start, &end);
    if (end <= start)
    {
        return;
    }
    size_t len = (size_t)(end - start);
    if (len == 4 && strncasecmp(start, "none", 4) == 0)
    {
        style->has_flex_grow = true;
        style->flex_grow_milli = 0;
        style->has_flex_shrink = true;
        style->flex_shrink_milli = 0;
        style->has_flex_basis = true;
        style->flex_basis.valid = true;
        style->flex_basis.is_auto = true;
        style->flex_basis.value_milli = 0;
        style->flex_basis.unit = CSS_UNIT_NONE;
        return;
    }
    if (len == 4 && strncasecmp(start, "auto", 4) == 0)
    {
        style->has_flex_grow = true;
        style->flex_grow_milli = 1000;
        style->has_flex_shrink = true;
        style->flex_shrink_milli = 1000;
        style->has_flex_basis = true;
        style->flex_basis.valid = true;
        style->flex_basis.is_auto = true;
        style->flex_basis.value_milli = 0;
        style->flex_basis.unit = CSS_UNIT_NONE;
        return;
    }
    if (len == 7 && strncasecmp(start, "initial", 7) == 0)
    {
        style->has_flex_grow = true;
        style->flex_grow_milli = 0;
        style->has_flex_shrink = true;
        style->flex_shrink_milli = 1000;
        style->has_flex_basis = true;
        style->flex_basis.valid = true;
        style->flex_basis.is_auto = true;
        style->flex_basis.value_milli = 0;
        style->flex_basis.unit = CSS_UNIT_NONE;
        return;
    }

    int32_t grow = -1;
    int32_t shrink = -1;
    css_length_t basis = {0};
    bool basis_set = false;

    const char *p = start;
    const char *tok_s = NULL;
    const char *tok_e = NULL;
    while (css_next_token(&p, end, &tok_s, &tok_e))
    {
        if (tok_s >= tok_e)
        {
            continue;
        }
        int32_t num_milli = 0;
        if (css_parse_number_milli(tok_s, tok_e, &num_milli))
        {
            if (grow < 0)
            {
                grow = num_milli;
            }
            else if (shrink < 0)
            {
                shrink = num_milli;
            }
            continue;
        }

        if ((size_t)(tok_e - tok_s) == 4 && strncasecmp(tok_s, "auto", 4) == 0)
        {
            basis.valid = true;
            basis.is_auto = true;
            basis.value_milli = 0;
            basis.unit = CSS_UNIT_NONE;
            basis_set = true;
            continue;
        }

        css_length_t len_val;
        if (css_parse_length_token(tok_s, tok_e, &len_val))
        {
            basis = len_val;
            basis_set = true;
            continue;
        }
    }

    if (grow >= 0)
    {
        style->has_flex_grow = true;
        style->flex_grow_milli = grow;
    }
    if (shrink >= 0)
    {
        style->has_flex_shrink = true;
        style->flex_shrink_milli = shrink;
    }
    if (basis_set)
    {
        style->has_flex_basis = true;
        style->flex_basis = basis;
    }

    if (grow >= 0 && shrink < 0)
    {
        style->has_flex_shrink = true;
        style->flex_shrink_milli = 1000;
    }
    if (grow >= 0 && !basis_set)
    {
        css_length_t zero = { .valid = true, .is_auto = false, .value_milli = 0, .unit = CSS_UNIT_PX };
        style->has_flex_basis = true;
        style->flex_basis = zero;
    }
}

void css_style_apply_property(css_style_t *style,
                              const char *prop_start,
                              const char *prop_end,
                              const char *val_start,
                              const char *val_end)
{
    if (!style || !prop_start || !prop_end || !val_start || !val_end)
    {
        return;
    }

    css_trim_range(&prop_start, &prop_end);
    css_trim_range(&val_start, &val_end);
    if (prop_end <= prop_start)
    {
        return;
    }

    if ((size_t)(prop_end - prop_start) == 10 && strncasecmp(prop_start, "background", 10) == 0)
    {
        video_color_t c;
        if (css_parse_color(val_start, val_end, &c))
        {
            style->has_background = true;
            style->background = c;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 16 && strncasecmp(prop_start, "background-color", 16) == 0)
    {
        video_color_t c;
        if (css_parse_color(val_start, val_end, &c))
        {
            style->has_background = true;
            style->background = c;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 5 && strncasecmp(prop_start, "color", 5) == 0)
    {
        video_color_t c;
        if (css_parse_color(val_start, val_end, &c))
        {
            style->has_color = true;
            style->color = c;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 9 && strncasecmp(prop_start, "font-size", 9) == 0)
    {
        css_length_t len;
        if (css_parse_length_token(val_start, val_end, &len))
        {
            style->has_font_size = true;
            style->font_size = len;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 4 && strncasecmp(prop_start, "font", 4) == 0)
    {
        const char *p = val_start;
        const char *tok_s = NULL;
        const char *tok_e = NULL;
        while (css_next_token(&p, val_end, &tok_s, &tok_e))
        {
            if (!tok_s || tok_s >= tok_e)
            {
                continue;
            }
            if (!(isdigit((unsigned char)tok_s[0]) || tok_s[0] == '.'))
            {
                continue;
            }
            const char *slash = NULL;
            for (const char *s = tok_s; s < tok_e; ++s)
            {
                if (*s == '/')
                {
                    slash = s;
                    break;
                }
            }
            const char *size_s = tok_s;
            const char *size_e = slash ? slash : tok_e;

            css_length_t font_size;
            if (css_parse_length_token(size_s, size_e, &font_size))
            {
                style->has_font_size = true;
                style->font_size = font_size;
            }

            if (slash && slash + 1 < tok_e)
            {
                const char *lh_s = slash + 1;
                const char *lh_e = tok_e;
                int32_t num_milli = 0;
            if (css_parse_number_milli(lh_s, lh_e, &num_milli))
            {
                if (num_milli < 0) num_milli = 0;
                style->has_line_height = true;
                style->line_height_milli = num_milli;
                style->line_height_is_length = false;
            }
            else
            {
                css_length_t lh_len;
                if (css_parse_length_token(lh_s, lh_e, &lh_len) && !lh_len.is_auto)
                {
                    if (lh_len.unit == CSS_UNIT_EM)
                    {
                        style->has_line_height = true;
                        style->line_height_milli = lh_len.value_milli;
                        style->line_height_is_length = false;
                    }
                    else if (lh_len.unit == CSS_UNIT_PERCENT)
                    {
                        style->has_line_height = true;
                        style->line_height_milli = lh_len.value_milli / 100;
                        style->line_height_is_length = false;
                    }
                    else
                    {
                        style->has_line_height = true;
                        style->line_height_is_length = true;
                        style->line_height = lh_len;
                    }
                }
            }
            }
            break;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 5 && strncasecmp(prop_start, "width", 5) == 0)
    {
        css_length_t len;
        if (css_parse_length_token(val_start, val_end, &len))
        {
            style->has_width = true;
            style->width = len;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 6 && strncasecmp(prop_start, "height", 6) == 0)
    {
        css_length_t len;
        if (css_parse_length_token(val_start, val_end, &len))
        {
            style->has_height = true;
            style->height = len;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 6 && strncasecmp(prop_start, "margin", 6) == 0)
    {
        css_box_t box;
        if (css_parse_margin_value(val_start, val_end, &box))
        {
            style->has_margin = true;
            style->margin = box;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 10 && strncasecmp(prop_start, "margin-top", 10) == 0)
    {
        css_length_t len;
        if (css_parse_length_token(val_start, val_end, &len))
        {
            style->has_margin = true;
            style->margin.top = len;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 12 && strncasecmp(prop_start, "margin-right", 12) == 0)
    {
        css_length_t len;
        if (css_parse_length_token(val_start, val_end, &len))
        {
            style->has_margin = true;
            style->margin.right = len;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 13 && strncasecmp(prop_start, "margin-bottom", 13) == 0)
    {
        css_length_t len;
        if (css_parse_length_token(val_start, val_end, &len))
        {
            style->has_margin = true;
            style->margin.bottom = len;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 11 && strncasecmp(prop_start, "margin-left", 11) == 0)
    {
        css_length_t len;
        if (css_parse_length_token(val_start, val_end, &len))
        {
            style->has_margin = true;
            style->margin.left = len;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 5 && strncasecmp(prop_start, "float", 5) == 0)
    {
        const char *s = val_start;
        const char *e = val_end;
        css_trim_range(&s, &e);
        size_t len = (size_t)(e - s);
        style->has_float = true;
        style->float_mode = CSS_FLOAT_NONE;
        if (len == 4 && strncasecmp(s, "left", 4) == 0)
        {
            style->float_mode = CSS_FLOAT_LEFT;
        }
        else if (len == 5 && strncasecmp(s, "right", 5) == 0)
        {
            style->float_mode = CSS_FLOAT_RIGHT;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 5 && strncasecmp(prop_start, "clear", 5) == 0)
    {
        const char *s = val_start;
        const char *e = val_end;
        css_trim_range(&s, &e);
        size_t len = (size_t)(e - s);
        style->has_clear = true;
        style->clear_mode = CSS_CLEAR_NONE;
        if (len == 4 && strncasecmp(s, "left", 4) == 0)
        {
            style->clear_mode = CSS_CLEAR_LEFT;
        }
        else if (len == 5 && strncasecmp(s, "right", 5) == 0)
        {
            style->clear_mode = CSS_CLEAR_RIGHT;
        }
        else if (len == 4 && strncasecmp(s, "both", 4) == 0)
        {
            style->clear_mode = CSS_CLEAR_BOTH;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 7 && strncasecmp(prop_start, "padding", 7) == 0)
    {
        css_box_t box;
        if (css_parse_margin_value(val_start, val_end, &box))
        {
            style->has_padding = true;
            style->padding = box;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 11 && strncasecmp(prop_start, "padding-top", 11) == 0)
    {
        css_length_t len;
        if (css_parse_length_token(val_start, val_end, &len))
        {
            style->has_padding = true;
            style->padding.top = len;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 13 && strncasecmp(prop_start, "padding-right", 13) == 0)
    {
        css_length_t len;
        if (css_parse_length_token(val_start, val_end, &len))
        {
            style->has_padding = true;
            style->padding.right = len;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 14 && strncasecmp(prop_start, "padding-bottom", 14) == 0)
    {
        css_length_t len;
        if (css_parse_length_token(val_start, val_end, &len))
        {
            style->has_padding = true;
            style->padding.bottom = len;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 12 && strncasecmp(prop_start, "padding-left", 12) == 0)
    {
        css_length_t len;
        if (css_parse_length_token(val_start, val_end, &len))
        {
            style->has_padding = true;
            style->padding.left = len;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 6 && strncasecmp(prop_start, "border", 6) == 0)
    {
        css_length_t width;
        video_color_t color;
        bool has_color = false;
        if (css_parse_border_value(val_start, val_end, &width, &color, &has_color))
        {
            style->has_border = true;
            style->border_width = css_box_from_length(width);
            if (has_color)
            {
                style->has_border_color = true;
                style->border_color = color;
            }
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 12 && strncasecmp(prop_start, "border-width", 12) == 0)
    {
        css_box_t box;
        if (css_parse_border_width_value(val_start, val_end, &box))
        {
            style->has_border = true;
            style->border_width = box;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 12 && strncasecmp(prop_start, "border-color", 12) == 0)
    {
        video_color_t c;
        if (css_parse_color(val_start, val_end, &c))
        {
            style->has_border_color = true;
            style->border_color = c;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 10 && strncasecmp(prop_start, "text-align", 10) == 0)
    {
        const char *s = val_start;
        const char *e = val_end;
        css_trim_range(&s, &e);
        size_t len = (size_t)(e - s);
        if (len == 6 && strncasecmp(s, "center", 6) == 0)
        {
            style->has_text_align = true;
            style->text_align = CSS_TEXT_ALIGN_CENTER;
        }
        else if (len == 5 && strncasecmp(s, "right", 5) == 0)
        {
            style->has_text_align = true;
            style->text_align = CSS_TEXT_ALIGN_RIGHT;
        }
        else if (len == 4 && strncasecmp(s, "left", 4) == 0)
        {
            style->has_text_align = true;
            style->text_align = CSS_TEXT_ALIGN_LEFT;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 15 && strncasecmp(prop_start, "text-decoration", 15) == 0)
    {
        const char *s = val_start;
        const char *e = val_end;
        css_trim_range(&s, &e);
        size_t len = (size_t)(e - s);
        if (len == 4 && strncasecmp(s, "none", 4) == 0)
        {
            style->has_text_decoration = true;
            style->text_decoration = CSS_TEXT_DECORATION_NONE;
        }
        else if (len == 9 && strncasecmp(s, "underline", 9) == 0)
        {
            style->has_text_decoration = true;
            style->text_decoration = CSS_TEXT_DECORATION_UNDERLINE;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 11 && strncasecmp(prop_start, "text-shadow", 11) == 0)
    {
        css_length_t dx, dy, blur;
        video_color_t color;
        bool has_color = false;
        if (css_parse_text_shadow_value(val_start, val_end, &dx, &dy, &blur, &color, &has_color))
        {
            style->has_text_shadow = true;
            style->text_shadow_x = dx;
            style->text_shadow_y = dy;
            style->text_shadow_blur = blur;
            if (has_color)
            {
                style->has_text_shadow_color = true;
                style->text_shadow_color = color;
            }
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 7 && strncasecmp(prop_start, "display", 7) == 0)
    {
        const char *s = val_start;
        const char *e = val_end;
        css_trim_range(&s, &e);
        size_t len = (size_t)(e - s);
        if (len == 5 && strncasecmp(s, "block", 5) == 0)
        {
            style->has_display = true;
            style->display = CSS_DISPLAY_BLOCK;
        }
        else if (len == 6 && strncasecmp(s, "inline", 6) == 0)
        {
            style->has_display = true;
            style->display = CSS_DISPLAY_INLINE;
        }
        else if (len == 11 && strncasecmp(s, "inline-block", 11) == 0)
        {
            /* Closest supported fallback. */
            style->has_display = true;
            style->display = CSS_DISPLAY_INLINE;
        }
        else if (len == 4 && strncasecmp(s, "flex", 4) == 0)
        {
            style->has_display = true;
            style->display = CSS_DISPLAY_FLEX;
        }
        else if (len == 10 && strncasecmp(s, "inline-flex", 10) == 0)
        {
            style->has_display = true;
            style->display = CSS_DISPLAY_INLINE_FLEX;
        }
        else if (len == 11 && strncasecmp(s, "-webkit-box", 11) == 0)
        {
            style->has_display = true;
            style->display = CSS_DISPLAY_FLEX;
        }
        else if (len == 12 && strncasecmp(s, "-webkit-flex", 12) == 0)
        {
            style->has_display = true;
            style->display = CSS_DISPLAY_FLEX;
        }
        else if (len == 9 && strncasecmp(s, "list-item", 9) == 0)
        {
            style->has_display = true;
            style->display = CSS_DISPLAY_LIST_ITEM;
        }
        else if (len == 4 && strncasecmp(s, "none", 4) == 0)
        {
            style->has_display = true;
            style->display = CSS_DISPLAY_NONE;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 14 && strncasecmp(prop_start, "flex-direction", 14) == 0)
    {
        css_flex_direction_t dir = CSS_FLEX_DIRECTION_ROW;
        if (css_parse_flex_direction_keyword(val_start, val_end, &dir))
        {
            style->has_flex_direction = true;
            style->flex_direction = dir;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 9 && strncasecmp(prop_start, "flex-wrap", 9) == 0)
    {
        css_flex_wrap_t wrap = CSS_FLEX_WRAP_NOWRAP;
        if (css_parse_flex_wrap_keyword(val_start, val_end, &wrap))
        {
            style->has_flex_wrap = true;
            style->flex_wrap = wrap;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 15 && strncasecmp(prop_start, "justify-content", 15) == 0)
    {
        css_justify_content_t justify = CSS_JUSTIFY_FLEX_START;
        if (css_parse_justify_keyword(val_start, val_end, &justify))
        {
            style->has_justify_content = true;
            style->justify_content = justify;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 11 && strncasecmp(prop_start, "align-items", 11) == 0)
    {
        css_align_t align = CSS_ALIGN_STRETCH;
        if (css_parse_align_keyword(val_start, val_end, &align))
        {
            style->has_align_items = true;
            style->align_items = align;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 10 && strncasecmp(prop_start, "align-self", 10) == 0)
    {
        css_align_t align = CSS_ALIGN_STRETCH;
        if (css_parse_align_keyword(val_start, val_end, &align))
        {
            style->has_align_self = true;
            style->align_self = align;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 13 && strncasecmp(prop_start, "align-content", 13) == 0)
    {
        css_align_t align = CSS_ALIGN_STRETCH;
        if (css_parse_align_keyword(val_start, val_end, &align))
        {
            style->has_align_content = true;
            style->align_content = align;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 3 && strncasecmp(prop_start, "gap", 3) == 0)
    {
        css_length_t row = {0};
        css_length_t col = {0};
        bool row_set = false;
        bool col_set = false;
        if (css_parse_gap_value(val_start, val_end, &row, &col, &row_set, &col_set))
        {
            if (row_set)
            {
                style->has_row_gap = true;
                style->row_gap = row;
            }
            if (col_set)
            {
                style->has_column_gap = true;
                style->column_gap = col;
            }
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 7 && strncasecmp(prop_start, "row-gap", 7) == 0)
    {
        css_length_t len;
        if (css_parse_length_token(val_start, val_end, &len))
        {
            style->has_row_gap = true;
            style->row_gap = len;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 10 && strncasecmp(prop_start, "column-gap", 10) == 0)
    {
        css_length_t len;
        if (css_parse_length_token(val_start, val_end, &len))
        {
            style->has_column_gap = true;
            style->column_gap = len;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 9 && strncasecmp(prop_start, "flex-grow", 9) == 0)
    {
        int32_t num_milli = 0;
        if (css_parse_number_milli(val_start, val_end, &num_milli))
        {
            if (num_milli < 0) num_milli = 0;
            style->has_flex_grow = true;
            style->flex_grow_milli = num_milli;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 11 && strncasecmp(prop_start, "flex-shrink", 11) == 0)
    {
        int32_t num_milli = 0;
        if (css_parse_number_milli(val_start, val_end, &num_milli))
        {
            if (num_milli < 0) num_milli = 0;
            style->has_flex_shrink = true;
            style->flex_shrink_milli = num_milli;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 10 && strncasecmp(prop_start, "flex-basis", 10) == 0)
    {
        css_length_t len;
        if (css_parse_length_token(val_start, val_end, &len))
        {
            style->has_flex_basis = true;
            style->flex_basis = len;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 4 && strncasecmp(prop_start, "flex", 4) == 0)
    {
        css_apply_flex_shorthand(style, val_start, val_end);
        return;
    }

    if ((size_t)(prop_end - prop_start) == 11 && strncasecmp(prop_start, "line-height", 11) == 0)
    {
        int32_t num_milli = 0;
        if (css_parse_number_milli(val_start, val_end, &num_milli))
        {
            if (num_milli < 0) num_milli = 0;
            style->has_line_height = true;
            style->line_height_milli = num_milli;
            style->line_height_is_length = false;
        }
        else
        {
            css_length_t lh_len;
            if (css_parse_length_token(val_start, val_end, &lh_len) && !lh_len.is_auto)
            {
                if (lh_len.unit == CSS_UNIT_EM)
                {
                    style->has_line_height = true;
                    style->line_height_milli = lh_len.value_milli;
                    style->line_height_is_length = false;
                }
                else if (lh_len.unit == CSS_UNIT_PERCENT)
                {
                    style->has_line_height = true;
                    style->line_height_milli = lh_len.value_milli / 100;
                    style->line_height_is_length = false;
                }
                else
                {
                    style->has_line_height = true;
                    style->line_height_is_length = true;
                    style->line_height = lh_len;
                }
            }
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 14 && strncasecmp(prop_start, "letter-spacing", 14) == 0)
    {
        css_length_t len;
        if (css_parse_length_token(val_start, val_end, &len))
        {
            style->has_letter_spacing = true;
            style->letter_spacing = len;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 7 && strncasecmp(prop_start, "opacity", 7) == 0)
    {
        int32_t num_milli = 0;
        if (css_parse_number_milli(val_start, val_end, &num_milli))
        {
            if (num_milli < 0) num_milli = 0;
            if (num_milli > 1000) num_milli = 1000;
            style->has_opacity = true;
            style->opacity_milli = num_milli;
        }
        return;
    }
}
