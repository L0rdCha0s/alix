#include "web/css.h"

#include "ctype.h"
#include "libc.h"

static void css_skip_ws_and_comments(const char **p)
{
    if (!p || !*p)
    {
        return;
    }

    while (**p)
    {
        while (**p && isspace((unsigned char)**p))
        {
            (*p)++;
        }
        if ((*p)[0] == '/' && (*p)[1] == '*')
        {
            const char *end = strstr(*p + 2, "*/");
            if (!end)
            {
                *p += strlen(*p);
                return;
            }
            *p = end + 2;
            continue;
        }
        break;
    }
}

static void css_trim_range(const char **start, const char **end)
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

static char *css_strdup_lower(const char *start, const char *end)
{
    if (!start || !end || end < start)
    {
        return NULL;
    }
    size_t len = (size_t)(end - start);
    char *out = (char *)malloc(len + 1);
    if (!out)
    {
        return NULL;
    }
    for (size_t i = 0; i < len; ++i)
    {
        out[i] = (char)tolower((unsigned char)start[i]);
    }
    out[len] = '\0';
    return out;
}

static bool css_parse_hex_digit(char c, uint8_t *out)
{
    if (!out)
    {
        return false;
    }
    if (c >= '0' && c <= '9')
    {
        *out = (uint8_t)(c - '0');
        return true;
    }
    if (c >= 'a' && c <= 'f')
    {
        *out = 10u + (uint8_t)(c - 'a');
        return true;
    }
    if (c >= 'A' && c <= 'F')
    {
        *out = 10u + (uint8_t)(c - 'A');
        return true;
    }
    return false;
}

static bool css_parse_color(const char *start, const char *end, video_color_t *out)
{
    if (!start || !end || end <= start || !out)
    {
        return false;
    }
    css_trim_range(&start, &end);
    if (end <= start)
    {
        return false;
    }

    size_t len = (size_t)(end - start);
    if (len >= 5 && strncasecmp(start, "rgb(", 4) == 0 && end[-1] == ')')
    {
        const char *p = start + 4;
        int comps[3] = {0, 0, 0};
        for (int i = 0; i < 3; ++i)
        {
            while (p < end && isspace((unsigned char)*p))
            {
                ++p;
            }
            if (p >= end || !isdigit((unsigned char)*p))
            {
                return false;
            }
            int value = 0;
            while (p < end && isdigit((unsigned char)*p))
            {
                value = value * 10 + (*p - '0');
                ++p;
            }
            bool percent = false;
            if (p < end && *p == '%')
            {
                percent = true;
                ++p;
            }
            if (percent)
            {
                if (value < 0) value = 0;
                if (value > 100) value = 100;
                value = (value * 255) / 100;
            }
            else
            {
                if (value < 0) value = 0;
                if (value > 255) value = 255;
            }
            comps[i] = value;
            while (p < end && isspace((unsigned char)*p))
            {
                ++p;
            }
            if (i < 2)
            {
                if (p >= end || *p != ',')
                {
                    return false;
                }
                ++p;
            }
        }
        *out = video_make_color((uint8_t)comps[0], (uint8_t)comps[1], (uint8_t)comps[2]);
        return true;
    }

    size_t name_len = (size_t)(end - start);
    if (*start != '#')
    {
        if (name_len == 5 && strncasecmp(start, "black", 5) == 0)
        {
            *out = video_make_color(0x00, 0x00, 0x00);
            return true;
        }
        if (name_len == 5 && strncasecmp(start, "white", 5) == 0)
        {
            *out = video_make_color(0xFF, 0xFF, 0xFF);
            return true;
        }
        if (name_len == 3 && strncasecmp(start, "red", 3) == 0)
        {
            *out = video_make_color(0xFF, 0x00, 0x00);
            return true;
        }
        if (name_len == 4 && strncasecmp(start, "blue", 4) == 0)
        {
            *out = video_make_color(0x00, 0x00, 0xFF);
            return true;
        }
        if (name_len == 5 && strncasecmp(start, "green", 5) == 0)
        {
            *out = video_make_color(0x00, 0x80, 0x00);
            return true;
        }
        if ((name_len == 4 && strncasecmp(start, "gray", 4) == 0) ||
            (name_len == 4 && strncasecmp(start, "grey", 4) == 0))
        {
            *out = video_make_color(0x80, 0x80, 0x80);
            return true;
        }
        return false;
    }
    start++;
    size_t hex_len = (size_t)(end - start);
    if (hex_len == 3)
    {
        uint8_t r, g, b;
        if (!css_parse_hex_digit(start[0], &r) ||
            !css_parse_hex_digit(start[1], &g) ||
            !css_parse_hex_digit(start[2], &b))
        {
            return false;
        }
        r = (uint8_t)((r << 4) | r);
        g = (uint8_t)((g << 4) | g);
        b = (uint8_t)((b << 4) | b);
        *out = video_make_color(r, g, b);
        return true;
    }
    if (hex_len == 6)
    {
        uint8_t hi, lo;
        uint8_t r, g, b;
        if (!css_parse_hex_digit(start[0], &hi) || !css_parse_hex_digit(start[1], &lo)) return false;
        r = (uint8_t)((hi << 4) | lo);
        if (!css_parse_hex_digit(start[2], &hi) || !css_parse_hex_digit(start[3], &lo)) return false;
        g = (uint8_t)((hi << 4) | lo);
        if (!css_parse_hex_digit(start[4], &hi) || !css_parse_hex_digit(start[5], &lo)) return false;
        b = (uint8_t)((hi << 4) | lo);
        *out = video_make_color(r, g, b);
        return true;
    }
    return false;
}

static bool css_parse_number_milli(const char *start, const char *end, int32_t *out_milli)
{
    if (!start || !end || end <= start || !out_milli)
    {
        return false;
    }
    css_trim_range(&start, &end);
    if (end <= start)
    {
        return false;
    }

    int32_t integer = 0;
    int32_t frac = 0;
    int32_t frac_scale = 1;
    bool saw_digit = false;

    const char *p = start;
    while (p < end && isdigit((unsigned char)*p))
    {
        saw_digit = true;
        integer = integer * 10 + (int32_t)(*p - '0');
        p++;
    }

    if (p < end && *p == '.')
    {
        p++;
        while (p < end && isdigit((unsigned char)*p) && frac_scale < 1000)
        {
            saw_digit = true;
            frac = frac * 10 + (int32_t)(*p - '0');
            frac_scale *= 10;
            p++;
        }
        while (frac_scale < 1000)
        {
            frac *= 10;
            frac_scale *= 10;
        }
    }

    if (!saw_digit)
    {
        return false;
    }

    *out_milli = integer * 1000 + frac;
    return true;
}

static bool css_parse_length_token(const char *start, const char *end, css_length_t *out)
{
    if (!out)
    {
        return false;
    }
    memset(out, 0, sizeof(*out));

    if (!start || !end || end <= start)
    {
        return false;
    }
    css_trim_range(&start, &end);
    if (end <= start)
    {
        return false;
    }

    if ((size_t)(end - start) == 4 && strncasecmp(start, "auto", 4) == 0)
    {
        out->valid = true;
        out->is_auto = true;
        out->value_milli = 0;
        out->unit = CSS_UNIT_NONE;
        return true;
    }

    const char *num_start = start;
    const char *p = num_start;
    while (p < end && (isdigit((unsigned char)*p) || *p == '.'))
    {
        p++;
    }
    const char *num_end = p;
    if (num_end == num_start)
    {
        return false;
    }

    int32_t number_milli = 0;
    if (!css_parse_number_milli(num_start, num_end, &number_milli))
    {
        return false;
    }

    css_unit_t unit = CSS_UNIT_NONE;
    if (p < end)
    {
        size_t ulen = (size_t)(end - p);
        if (ulen == 2 && (p[0] == 'p' || p[0] == 'P') && (p[1] == 'x' || p[1] == 'X'))
        {
            unit = CSS_UNIT_PX;
        }
        else if (ulen == 2 && (p[0] == 'v' || p[0] == 'V') && (p[1] == 'w' || p[1] == 'W'))
        {
            unit = CSS_UNIT_VW;
        }
        else if (ulen == 2 && (p[0] == 'v' || p[0] == 'V') && (p[1] == 'h' || p[1] == 'H'))
        {
            unit = CSS_UNIT_VH;
        }
        else if (ulen == 2 && (p[0] == 'e' || p[0] == 'E') && (p[1] == 'm' || p[1] == 'M'))
        {
            unit = CSS_UNIT_EM;
        }
        else if (ulen == 1 && p[0] == '%')
        {
            unit = CSS_UNIT_PERCENT;
        }
    }

    out->valid = true;
    out->is_auto = false;
    out->value_milli = number_milli;
    out->unit = unit;
    return true;
}

static bool css_parse_margin_value(const char *start, const char *end, css_box_t *out)
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
        if (!css_parse_length_token(tstart, tend, &parsed[i]))
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

static css_box_t css_box_from_length(css_length_t len)
{
    return (css_box_t){
        .top = len,
        .right = len,
        .bottom = len,
        .left = len,
    };
}

void css_style_merge(css_style_t *dst, const css_style_t *src)
{
    if (!dst || !src)
    {
        return;
    }
    if (src->has_background)
    {
        dst->has_background = true;
        dst->background = src->background;
    }
    if (src->has_color)
    {
        dst->has_color = true;
        dst->color = src->color;
    }
    if (src->has_font_size)
    {
        dst->has_font_size = true;
        dst->font_size = src->font_size;
    }
    if (src->has_width)
    {
        dst->has_width = true;
        dst->width = src->width;
    }
    if (src->has_height)
    {
        dst->has_height = true;
        dst->height = src->height;
    }
    if (src->has_margin)
    {
        dst->has_margin = true;
        dst->margin = src->margin;
    }
    if (src->has_padding)
    {
        dst->has_padding = true;
        dst->padding = src->padding;
    }
    if (src->has_border)
    {
        dst->has_border = true;
        dst->border_width = src->border_width;
    }
    if (src->has_border_color)
    {
        dst->has_border_color = true;
        dst->border_color = src->border_color;
    }
    if (src->has_float)
    {
        dst->has_float = true;
        dst->float_mode = src->float_mode;
    }
    if (src->has_clear)
    {
        dst->has_clear = true;
        dst->clear_mode = src->clear_mode;
    }
    if (src->has_text_align)
    {
        dst->has_text_align = true;
        dst->text_align = src->text_align;
    }
    if (src->has_text_shadow)
    {
        dst->has_text_shadow = true;
        dst->text_shadow_x = src->text_shadow_x;
        dst->text_shadow_y = src->text_shadow_y;
        dst->text_shadow_blur = src->text_shadow_blur;
        if (src->has_text_shadow_color)
        {
            dst->has_text_shadow_color = true;
            dst->text_shadow_color = src->text_shadow_color;
        }
    }
    if (src->has_display)
    {
        dst->has_display = true;
        dst->display = src->display;
    }
    if (src->has_line_height)
    {
        dst->has_line_height = true;
        dst->line_height_milli = src->line_height_milli;
    }
    if (src->has_letter_spacing)
    {
        dst->has_letter_spacing = true;
        dst->letter_spacing = src->letter_spacing;
    }
    if (src->has_opacity)
    {
        dst->has_opacity = true;
        dst->opacity_milli = src->opacity_milli;
    }
}

bool css_rule_matches_tag(const css_rule_t *rule, const char *tag_name)
{
    if (!rule || !rule->selector || !tag_name || tag_name[0] == '\0')
    {
        return false;
    }

    const char *sel = rule->selector;
    while (*sel && isspace((unsigned char)*sel))
    {
        sel++;
    }
    if (*sel == '\0')
    {
        return false;
    }

    const char *end = sel;
    while (*end && *end != ':' && *end != '.' && *end != '#' && *end != '[' && !isspace((unsigned char)*end))
    {
        end++;
    }
    size_t len = (size_t)(end - sel);
    if (len == 0)
    {
        return false;
    }

    if (strlen(tag_name) != len)
    {
        return false;
    }
    return strncasecmp(sel, tag_name, len) == 0;
}

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
            if (css_parse_length_token(tok_s, tok_e, &len) && !len.is_auto)
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

static void css_style_apply_property(css_style_t *style,
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
                        }
                        else if (lh_len.unit == CSS_UNIT_PERCENT)
                        {
                            style->has_line_height = true;
                            style->line_height_milli = lh_len.value_milli / 100;
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
        if (css_parse_margin_value(val_start, val_end, &box))
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
        style->has_display = true;
        style->display = CSS_DISPLAY_INLINE;
        if (len == 5 && strncasecmp(s, "block", 5) == 0)
        {
            style->display = CSS_DISPLAY_BLOCK;
        }
        else if (len == 9 && strncasecmp(s, "list-item", 9) == 0)
        {
            style->display = CSS_DISPLAY_LIST_ITEM;
        }
        else if (len == 4 && strncasecmp(s, "none", 4) == 0)
        {
            style->display = CSS_DISPLAY_NONE;
        }
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
                }
                else if (lh_len.unit == CSS_UNIT_PERCENT)
                {
                    style->has_line_height = true;
                    style->line_height_milli = lh_len.value_milli / 100;
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

static bool css_append_rule(css_stylesheet_t *sheet, const char *selector_start, const char *selector_end, const css_style_t *style)
{
    if (!sheet || !selector_start || !selector_end || selector_end <= selector_start || !style)
    {
        return false;
    }
    css_trim_range(&selector_start, &selector_end);
    if (selector_end <= selector_start)
    {
        return true;
    }

    css_rule_t *rule = (css_rule_t *)calloc(1, sizeof(*rule));
    if (!rule)
    {
        return false;
    }
    rule->selector = css_strdup_lower(selector_start, selector_end);
    if (!rule->selector)
    {
        free(rule);
        return false;
    }
    rule->style = *style;
    rule->next = NULL;

    if (!sheet->rules)
    {
        sheet->rules = rule;
        return true;
    }
    css_rule_t *tail = sheet->rules;
    while (tail->next)
    {
        tail = tail->next;
    }
    tail->next = rule;
    return true;
}

css_stylesheet_t *css_parse(const char *css_text)
{
    if (!css_text)
    {
        return NULL;
    }

    css_stylesheet_t *sheet = (css_stylesheet_t *)calloc(1, sizeof(*sheet));
    if (!sheet)
    {
        return NULL;
    }

    const char *p = css_text;
    while (*p)
    {
        css_skip_ws_and_comments(&p);
        if (*p == '\0')
        {
            break;
        }

        const char *sel_start = p;
        while (*p && *p != '{')
        {
            p++;
        }
        if (*p != '{')
        {
            break;
        }
        const char *sel_end = p;
        p++;

        css_style_t style = {0};
        while (*p)
        {
            css_skip_ws_and_comments(&p);
            if (*p == '\0' || *p == '}')
            {
                break;
            }

            const char *prop_start = p;
            while (*p && *p != ':' && *p != ';' && *p != '}')
            {
                p++;
            }
            const char *prop_end = p;
            if (*p != ':')
            {
                if (*p == ';')
                {
                    p++;
                }
                continue;
            }
            p++;

            const char *val_start = p;
            while (*p && *p != ';' && *p != '}')
            {
                p++;
            }
            const char *val_end = p;

            css_style_apply_property(&style, prop_start, prop_end, val_start, val_end);

            if (*p == ';')
            {
                p++;
            }
        }
        if (*p == '}')
        {
            p++;
        }

        const char *cur = sel_start;
        while (cur < sel_end)
        {
            const char *comma = cur;
            while (comma < sel_end && *comma != ',')
            {
                comma++;
            }
            if (!css_append_rule(sheet, cur, comma, &style))
            {
                css_stylesheet_destroy(sheet);
                return NULL;
            }
            cur = (comma < sel_end) ? comma + 1 : sel_end;
        }
    }

    return sheet;
}

void css_stylesheet_destroy(css_stylesheet_t *sheet)
{
    if (!sheet)
    {
        return;
    }
    css_rule_t *rule = sheet->rules;
    while (rule)
    {
        css_rule_t *next = rule->next;
        free(rule->selector);
        free(rule);
        rule = next;
    }
    free(sheet);
}
