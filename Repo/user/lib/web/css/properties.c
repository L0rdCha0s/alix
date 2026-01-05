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
    css_skip_ws_and_comments_range(&s, end);
    if (s >= end)
    {
        *p = end;
        return false;
    }
    const char *start = s;
    while (s < end)
    {
        if (isspace((unsigned char)*s))
        {
            break;
        }
        if (s + 1 < end && s[0] == '/' && s[1] == '*')
        {
            break;
        }
        ++s;
    }
    *tok_start = start;
    *tok_end = s;
    *p = s;
    return true;
}

void css_style_release(css_style_t *style)
{
    if (!style)
    {
        return;
    }
    if (style->background_image_owned && style->background_image)
    {
        free((void *)style->background_image);
        style->background_image = NULL;
    }
    if (style->content_owned && style->content)
    {
        free((void *)style->content);
        style->content = NULL;
    }
    style->background_image_owned = false;
    style->has_background_image = false;
    style->content_owned = false;
    style->has_content = false;
}

static bool css_value_is_keyword(const char *start, const char *end, const char *keyword)
{
    if (!start || !end || !keyword)
    {
        return false;
    }
    css_trim_range(&start, &end);
    size_t len = (size_t)(end - start);
    size_t klen = strlen(keyword);
    if (len != klen)
    {
        return false;
    }
    return strncasecmp(start, keyword, len) == 0;
}

static bool css_parse_list_style_type_token(const char *start,
                                            const char *end,
                                            css_list_style_type_t *out_type)
{
    if (!out_type)
    {
        return false;
    }
    if (css_value_is_keyword(start, end, "none"))
    {
        *out_type = CSS_LIST_STYLE_NONE;
        return true;
    }
    if (css_value_is_keyword(start, end, "disc"))
    {
        *out_type = CSS_LIST_STYLE_DISC;
        return true;
    }
    if (css_value_is_keyword(start, end, "decimal"))
    {
        *out_type = CSS_LIST_STYLE_DECIMAL;
        return true;
    }
    if (css_value_is_keyword(start, end, "circle") ||
        css_value_is_keyword(start, end, "square"))
    {
        *out_type = CSS_LIST_STYLE_DISC;
        return true;
    }
    return false;
}

static bool css_parse_grid_template_columns_count(const char *start, const char *end, int32_t *out_cols)
{
    if (!out_cols)
    {
        return false;
    }
    *out_cols = 0;
    if (!start || !end || end <= start)
    {
        return false;
    }
    css_trim_range(&start, &end);
    if (end <= start)
    {
        return false;
    }
    if ((size_t)(end - start) >= 7 && strncasecmp(start, "repeat(", 7) == 0)
    {
        const char *p = start + 7;
        while (p < end && isspace((unsigned char)*p))
        {
            ++p;
        }
        int32_t value = 0;
        bool any = false;
        while (p < end && isdigit((unsigned char)*p))
        {
            any = true;
            value = value * 10 + (*p - '0');
            ++p;
        }
        if (any && value > 0)
        {
            *out_cols = value;
            return true;
        }
    }

    int depth = 0;
    bool in_token = false;
    int count = 0;
    for (const char *p = start; p < end; ++p)
    {
        char c = *p;
        if (c == '(')
        {
            depth++;
            in_token = true;
            continue;
        }
        if (c == ')')
        {
            if (depth > 0)
            {
                depth--;
            }
            continue;
        }
        if (depth == 0 && (isspace((unsigned char)c) || c == ','))
        {
            if (in_token)
            {
                count++;
                in_token = false;
            }
            continue;
        }
        if (depth == 0 && !in_token && !isspace((unsigned char)c))
        {
            in_token = true;
        }
    }
    if (in_token)
    {
        count++;
    }
    if (count <= 0)
    {
        return false;
    }
    *out_cols = count;
    return true;
}

static bool css_parse_grid_span_value(const char *start, const char *end, int32_t *out_span)
{
    if (!out_span)
    {
        return false;
    }
    *out_span = 0;
    if (!start || !end || end <= start)
    {
        return false;
    }
    css_trim_range(&start, &end);
    if (end <= start)
    {
        return false;
    }

    for (const char *p = start; p + 4 <= end; ++p)
    {
        if (strncasecmp(p, "span", 4) != 0)
        {
            continue;
        }
        if (p != start && isalnum((unsigned char)p[-1]))
        {
            continue;
        }
        const char *q = p + 4;
        if (q < end && isalnum((unsigned char)*q))
        {
            continue;
        }
        while (q < end && (isspace((unsigned char)*q) || *q == '/' || *q == ':'))
        {
            ++q;
        }
        int32_t value = 0;
        bool any = false;
        while (q < end && isdigit((unsigned char)*q))
        {
            any = true;
            value = value * 10 + (*q - '0');
            ++q;
        }
        if (any && value > 0)
        {
            *out_span = value;
            return true;
        }
    }
    return false;
}

static bool css_parse_grid_line_index(const char *start, const char *end, int32_t *out_line)
{
    if (!out_line)
    {
        return false;
    }
    *out_line = 0;
    if (!start || !end || end <= start)
    {
        return false;
    }
    css_trim_range(&start, &end);
    if (end <= start)
    {
        return false;
    }
    size_t len = (size_t)(end - start);
    if (len == 4 && strncasecmp(start, "auto", 4) == 0)
    {
        return false;
    }
    if (len >= 4 && strncasecmp(start, "span", 4) == 0)
    {
        return false;
    }

    const char *p = start;
    bool negative = false;
    if (*p == '+' || *p == '-')
    {
        negative = (*p == '-');
        ++p;
    }
    int32_t value = 0;
    bool any = false;
    while (p < end && isdigit((unsigned char)*p))
    {
        any = true;
        value = value * 10 + (*p - '0');
        ++p;
    }
    if (!any || negative || value <= 0)
    {
        return false;
    }
    *out_line = value;
    return true;
}

static void css_parse_grid_column_value(const char *start,
                                        const char *end,
                                        int32_t *out_start,
                                        bool *has_start,
                                        int32_t *out_end,
                                        bool *has_end,
                                        int32_t *out_span,
                                        bool *has_span)
{
    if (has_start) *has_start = false;
    if (has_end) *has_end = false;
    if (has_span) *has_span = false;
    if (out_start) *out_start = 0;
    if (out_end) *out_end = 0;
    if (out_span) *out_span = 0;
    if (!start || !end || end <= start)
    {
        return;
    }

    const char *sep = NULL;
    int depth = 0;
    for (const char *p = start; p < end; ++p)
    {
        if (*p == '(')
        {
            depth++;
            continue;
        }
        if (*p == ')')
        {
            if (depth > 0)
            {
                depth--;
            }
            continue;
        }
        if (depth == 0 && *p == '/')
        {
            sep = p;
            break;
        }
    }

    const char *part1_start = start;
    const char *part1_end = sep ? sep : end;
    const char *part2_start = sep ? sep + 1 : NULL;
    const char *part2_end = sep ? end : NULL;

    int32_t span = 0;
    if (css_parse_grid_span_value(part1_start, part1_end, &span) && has_span && out_span)
    {
        *has_span = true;
        *out_span = span;
    }

    int32_t line = 0;
    if (css_parse_grid_line_index(part1_start, part1_end, &line) && has_start && out_start)
    {
        *has_start = true;
        *out_start = line;
    }

    if (sep && part2_start && part2_end)
    {
        if (css_parse_grid_span_value(part2_start, part2_end, &span) && has_span && out_span)
        {
            *has_span = true;
            *out_span = span;
        }
        if (css_parse_grid_line_index(part2_start, part2_end, &line))
        {
            if ((has_start && *has_start) || (has_span && *has_span))
            {
                if (has_end && out_end)
                {
                    *has_end = true;
                    *out_end = line;
                }
            }
            else if (has_start && out_start)
            {
                *has_start = true;
                *out_start = line;
            }
        }
    }
}

static char *css_strdup_unescape(const char *start, const char *end)
{
    if (!start || !end || end <= start)
    {
        return NULL;
    }
    size_t cap = (size_t)(end - start) + 1;
    char *out = (char *)malloc(cap);
    if (!out)
    {
        return NULL;
    }
    size_t len = 0;
    for (const char *p = start; p < end; ++p)
    {
        if (*p == '\\' && (p + 1) < end)
        {
            ++p;
        }
        out[len++] = *p;
    }
    out[len] = '\0';
    return out;
}

static bool css_parse_url_token(const char *start, const char *end, char **out_url)
{
    if (!out_url)
    {
        return false;
    }
    *out_url = NULL;
    if (!start || !end || end <= start)
    {
        return false;
    }
    css_trim_range(&start, &end);
    if ((size_t)(end - start) < 5)
    {
        return false;
    }
    if (strncasecmp(start, "url(", 4) != 0)
    {
        return false;
    }
    const char *p = start + 4;
    const char *p_end = end;
    if (p_end <= p || p_end[-1] != ')')
    {
        return false;
    }
    --p_end;
    css_trim_range(&p, &p_end);
    if (p_end <= p)
    {
        return false;
    }
    if (*p == '"' || *p == '\'')
    {
        char quote = *p++;
        if (p_end <= p || p_end[-1] != quote)
        {
            return false;
        }
        --p_end;
    }
    if (p_end < p)
    {
        return false;
    }
    *out_url = css_strdup_unescape(p, p_end);
    return *out_url != NULL;
}

static void css_style_set_background_image(css_style_t *style, char *url, bool owned)
{
    if (!style)
    {
        return;
    }
    css_style_release(style);
    style->has_background_image = true;
    style->background_image = url;
    style->background_image_owned = owned;
}

static bool css_parse_background_position_tokens(const char *start,
                                                 const char *end,
                                                 css_length_t *out_x,
                                                 css_length_t *out_y,
                                                 bool *out_has_pos)
{
    if (!out_x || !out_y || !out_has_pos)
    {
        return false;
    }
    *out_has_pos = false;
    css_trim_range(&start, &end);
    if (!start || !end || end <= start)
    {
        return false;
    }

    const char *p = start;
    const char *tok_s = NULL;
    const char *tok_e = NULL;
    css_length_t vals[2] = {0};
    size_t count = 0;
    while (css_next_token(&p, end, &tok_s, &tok_e) && count < 2)
    {
        css_length_t len = {0};
        if (!css_parse_length_token(tok_s, tok_e, &len))
        {
            return false;
        }
        vals[count++] = len;
    }

    if (count == 0)
    {
        return false;
    }
    *out_x = vals[0];
    if (count > 1)
    {
        *out_y = vals[1];
    }
    else
    {
        *out_y = (css_length_t){ .valid = true, .is_auto = false, .value_milli = 0, .unit = CSS_UNIT_NONE };
    }
    *out_has_pos = true;
    return true;
}

static void css_style_apply_background_shorthand(css_style_t *style, const char *start, const char *end)
{
    if (!style || !start || !end)
    {
        return;
    }

    css_trim_range(&start, &end);
    if (end <= start)
    {
        return;
    }

    bool valid = true;
    bool have_color = false;
    bool have_image = false;
    bool have_repeat = false;
    bool have_attachment = false;
    bool background_transparent = true;
    video_color_t background = 0;
    char *background_image = NULL;
    bool background_image_owned = false;
    css_background_repeat_t background_repeat = CSS_BACKGROUND_REPEAT_REPEAT;
    css_background_attachment_t background_attachment = CSS_BACKGROUND_ATTACHMENT_SCROLL;
    css_length_t background_pos_x = { .valid = true, .is_auto = false, .value_milli = 0, .unit = CSS_UNIT_NONE };
    css_length_t background_pos_y = { .valid = true, .is_auto = false, .value_milli = 0, .unit = CSS_UNIT_NONE };

    const char *p = start;
    const char *tok_s = NULL;
    const char *tok_e = NULL;
    css_length_t pos_x = {0};
    css_length_t pos_y = {0};
    size_t pos_count = 0;

    while (css_next_token(&p, end, &tok_s, &tok_e))
    {
        if (css_value_is_keyword(tok_s, tok_e, "none"))
        {
            if (have_image)
            {
                valid = false;
                break;
            }
            have_image = true;
            continue;
        }

        if (css_value_is_keyword(tok_s, tok_e, "repeat"))
        {
            if (have_repeat)
            {
                valid = false;
                break;
            }
            have_repeat = true;
            background_repeat = CSS_BACKGROUND_REPEAT_REPEAT;
            continue;
        }
        if (css_value_is_keyword(tok_s, tok_e, "no-repeat"))
        {
            if (have_repeat)
            {
                valid = false;
                break;
            }
            have_repeat = true;
            background_repeat = CSS_BACKGROUND_REPEAT_NO_REPEAT;
            continue;
        }
        if (css_value_is_keyword(tok_s, tok_e, "repeat-x"))
        {
            if (have_repeat)
            {
                valid = false;
                break;
            }
            have_repeat = true;
            background_repeat = CSS_BACKGROUND_REPEAT_REPEAT_X;
            continue;
        }
        if (css_value_is_keyword(tok_s, tok_e, "repeat-y"))
        {
            if (have_repeat)
            {
                valid = false;
                break;
            }
            have_repeat = true;
            background_repeat = CSS_BACKGROUND_REPEAT_REPEAT_Y;
            continue;
        }
        if (css_value_is_keyword(tok_s, tok_e, "fixed"))
        {
            if (have_attachment)
            {
                valid = false;
                break;
            }
            have_attachment = true;
            background_attachment = CSS_BACKGROUND_ATTACHMENT_FIXED;
            continue;
        }
        if (css_value_is_keyword(tok_s, tok_e, "scroll"))
        {
            if (have_attachment)
            {
                valid = false;
                break;
            }
            have_attachment = true;
            background_attachment = CSS_BACKGROUND_ATTACHMENT_SCROLL;
            continue;
        }

        char *url = NULL;
        if (css_parse_url_token(tok_s, tok_e, &url))
        {
            if (have_image)
            {
                free(url);
                valid = false;
                break;
            }
            have_image = true;
            background_image = url;
            background_image_owned = true;
            continue;
        }

        if (css_value_is_keyword(tok_s, tok_e, "transparent"))
        {
            if (have_color)
            {
                valid = false;
                break;
            }
            have_color = true;
            background_transparent = true;
            continue;
        }

        video_color_t c = 0;
        if (css_parse_color(tok_s, tok_e, &c))
        {
            if (have_color)
            {
                valid = false;
                break;
            }
            have_color = true;
            background_transparent = false;
            background = c;
            continue;
        }

        if (pos_count < 2)
        {
            css_length_t len = {0};
            if (css_parse_length_token(tok_s, tok_e, &len))
            {
                if (pos_count == 0)
                {
                    pos_x = len;
                }
                else
                {
                    pos_y = len;
                }
                pos_count++;
                continue;
            }
        }
        valid = false;
        break;
    }

    if (!valid)
    {
        if (background_image_owned && background_image)
        {
            free(background_image);
        }
        return;
    }

    css_style_release(style);
    style->has_background = true;
    style->background_transparent = background_transparent;
    if (!background_transparent)
    {
        style->background = background;
    }
    style->has_background_image = true;
    style->background_image = background_image;
    style->background_image_owned = background_image_owned;
    style->has_background_repeat = true;
    style->background_repeat = background_repeat;
    style->has_background_attachment = true;
    style->background_attachment = background_attachment;
    style->has_background_position = true;
    style->background_pos_x = background_pos_x;
    style->background_pos_y = background_pos_y;

    if (pos_count > 0)
    {
        style->has_background_position = true;
        style->background_pos_x = pos_x;
        if (pos_count > 1)
        {
            style->background_pos_y = pos_y;
        }
        else
        {
            style->background_pos_y = (css_length_t){ .valid = true, .is_auto = false, .value_milli = 0, .unit = CSS_UNIT_NONE };
        }
    }
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

static bool css_parse_border_style_value(const char *start, const char *end, bool out_none[4])
{
    if (!out_none)
    {
        return false;
    }
    out_none[0] = false;
    out_none[1] = false;
    out_none[2] = false;
    out_none[3] = false;

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

    bool none_flags[4] = {false, false, false, false};
    for (size_t i = 0; i < count; ++i)
    {
        const char *tstart = tokens[i];
        const char *tend = tstart + token_lens[i];
        css_trim_range(&tstart, &tend);
        size_t len = (size_t)(tend - tstart);
        if (len == 4 && strncasecmp(tstart, "none", 4) == 0)
        {
            none_flags[i] = true;
        }
    }

    if (count == 1)
    {
        out_none[0] = none_flags[0];
        out_none[1] = none_flags[0];
        out_none[2] = none_flags[0];
        out_none[3] = none_flags[0];
        return true;
    }
    if (count == 2)
    {
        out_none[0] = none_flags[0];
        out_none[2] = none_flags[0];
        out_none[1] = none_flags[1];
        out_none[3] = none_flags[1];
        return true;
    }
    if (count == 3)
    {
        out_none[0] = none_flags[0];
        out_none[1] = none_flags[1];
        out_none[3] = none_flags[1];
        out_none[2] = none_flags[2];
        return true;
    }
    out_none[0] = none_flags[0];
    out_none[1] = none_flags[1];
    out_none[2] = none_flags[2];
    out_none[3] = none_flags[3];
    return true;
}

static void css_set_length_zero(css_length_t *len)
{
    if (!len)
    {
        return;
    }
    len->valid = true;
    len->is_auto = false;
    len->value_milli = 0;
    len->unit = CSS_UNIT_PX;
}

static void css_apply_border_style_none_mask(css_style_t *style)
{
    if (!style || !style->has_border_style)
    {
        return;
    }

    if (style->border_style_none[CSS_BORDER_SIDE_TOP])
    {
        css_set_length_zero(&style->border_width.top);
    }
    if (style->border_style_none[CSS_BORDER_SIDE_RIGHT])
    {
        css_set_length_zero(&style->border_width.right);
    }
    if (style->border_style_none[CSS_BORDER_SIDE_BOTTOM])
    {
        css_set_length_zero(&style->border_width.bottom);
    }
    if (style->border_style_none[CSS_BORDER_SIDE_LEFT])
    {
        css_set_length_zero(&style->border_width.left);
    }
}

static bool css_parse_border_color_value(const char *start,
                                         const char *end,
                                         video_color_t out_colors[4],
                                         bool out_transparent[4])
{
    if (!out_colors || !out_transparent)
    {
        return false;
    }
    for (size_t i = 0; i < 4; ++i)
    {
        out_colors[i] = video_make_color(0x00, 0x00, 0x00);
        out_transparent[i] = false;
    }

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

    video_color_t parsed[4] = {0};
    bool transparent[4] = {false, false, false, false};
    for (size_t i = 0; i < count; ++i)
    {
        const char *tstart = tokens[i];
        const char *tend = tstart + token_lens[i];
        css_trim_range(&tstart, &tend);
        if (css_value_is_keyword(tstart, tend, "transparent"))
        {
            parsed[i] = video_make_color(0x00, 0x00, 0x00);
            transparent[i] = true;
            continue;
        }
        video_color_t c;
        if (!css_parse_color(tstart, tend, &c))
        {
            return false;
        }
        parsed[i] = c;
        transparent[i] = false;
    }

    if (count == 1)
    {
        out_colors[0] = parsed[0];
        out_colors[1] = parsed[0];
        out_colors[2] = parsed[0];
        out_colors[3] = parsed[0];
        out_transparent[0] = transparent[0];
        out_transparent[1] = transparent[0];
        out_transparent[2] = transparent[0];
        out_transparent[3] = transparent[0];
        return true;
    }
    if (count == 2)
    {
        out_colors[0] = parsed[0];
        out_colors[2] = parsed[0];
        out_colors[1] = parsed[1];
        out_colors[3] = parsed[1];
        out_transparent[0] = transparent[0];
        out_transparent[2] = transparent[0];
        out_transparent[1] = transparent[1];
        out_transparent[3] = transparent[1];
        return true;
    }
    if (count == 3)
    {
        out_colors[0] = parsed[0];
        out_colors[1] = parsed[1];
        out_colors[3] = parsed[1];
        out_colors[2] = parsed[2];
        out_transparent[0] = transparent[0];
        out_transparent[1] = transparent[1];
        out_transparent[3] = transparent[1];
        out_transparent[2] = transparent[2];
        return true;
    }
    out_colors[0] = parsed[0];
    out_colors[1] = parsed[1];
    out_colors[2] = parsed[2];
    out_colors[3] = parsed[3];
    out_transparent[0] = transparent[0];
    out_transparent[1] = transparent[1];
    out_transparent[2] = transparent[2];
    out_transparent[3] = transparent[3];
    return true;
}

static bool css_parse_content_value(const char *start, const char *end, char **out)
{
    if (!out)
    {
        return false;
    }
    *out = NULL;
    css_trim_range(&start, &end);
    if (!start || !end || end <= start)
    {
        return false;
    }
    if (css_value_is_keyword(start, end, "none") || css_value_is_keyword(start, end, "normal"))
    {
        return true;
    }
    if ((*start == '\'' || *start == '"') && end > start + 1 && end[-1] == *start)
    {
        if (end == start + 2)
        {
            char *empty = (char *)malloc(1);
            if (!empty)
            {
                return false;
            }
            empty[0] = '\0';
            *out = empty;
            return true;
        }
        *out = css_strdup_unescape(start + 1, end - 1);
        return *out != NULL;
    }
    return false;
}

static bool css_parse_border_value(const char *start,
                                   const char *end,
                                   css_length_t *out_width,
                                   video_color_t *out_color,
                                   bool *out_has_color,
                                   bool *out_transparent)
{
    if (!out_width || !out_color || !out_has_color)
    {
        return false;
    }
    memset(out_width, 0, sizeof(*out_width));
    *out_color = video_make_color(0x00, 0x00, 0x00);
    *out_has_color = false;
    if (out_transparent)
    {
        *out_transparent = false;
    }

    css_trim_range(&start, &end);
    if (!start || !end || end <= start)
    {
        return false;
    }

    bool have_width = false;
    bool have_style = false;
    bool style_none = false;
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
        else
        {
            css_length_t len;
            if (css_parse_border_width_token(tok_s, tok_e, &len))
            {
                return false;
            }
        }

        if (!have_style)
        {
            if (css_value_is_keyword(tok_s, tok_e, "none"))
            {
                have_style = true;
                style_none = true;
                continue;
            }
            if (css_value_is_keyword(tok_s, tok_e, "solid") ||
                css_value_is_keyword(tok_s, tok_e, "dotted") ||
                css_value_is_keyword(tok_s, tok_e, "dashed") ||
                css_value_is_keyword(tok_s, tok_e, "double") ||
                css_value_is_keyword(tok_s, tok_e, "groove") ||
                css_value_is_keyword(tok_s, tok_e, "ridge") ||
                css_value_is_keyword(tok_s, tok_e, "inset") ||
                css_value_is_keyword(tok_s, tok_e, "outset"))
            {
                have_style = true;
                continue;
            }
        }
        else
        {
            if (css_value_is_keyword(tok_s, tok_e, "none") ||
                css_value_is_keyword(tok_s, tok_e, "solid") ||
                css_value_is_keyword(tok_s, tok_e, "dotted") ||
                css_value_is_keyword(tok_s, tok_e, "dashed") ||
                css_value_is_keyword(tok_s, tok_e, "double") ||
                css_value_is_keyword(tok_s, tok_e, "groove") ||
                css_value_is_keyword(tok_s, tok_e, "ridge") ||
                css_value_is_keyword(tok_s, tok_e, "inset") ||
                css_value_is_keyword(tok_s, tok_e, "outset"))
            {
                return false;
            }
        }

        if (!*out_has_color)
        {
            if (css_value_is_keyword(tok_s, tok_e, "transparent"))
            {
                *out_has_color = true;
                if (out_transparent)
                {
                    *out_transparent = true;
                }
                continue;
            }
            video_color_t c;
            if (css_parse_color(tok_s, tok_e, &c))
            {
                *out_color = c;
                *out_has_color = true;
                continue;
            }
        }
        else
        {
            if (css_value_is_keyword(tok_s, tok_e, "transparent"))
            {
                return false;
            }
            video_color_t c;
            if (css_parse_color(tok_s, tok_e, &c))
            {
                return false;
            }
        }

        return false;
    }

    if (!have_width && !have_style)
    {
        return false;
    }
    if (style_none)
    {
        out_width->valid = true;
        out_width->is_auto = false;
        out_width->unit = CSS_UNIT_PX;
        out_width->value_milli = 0;
        have_width = true;
    }
    if (!have_width)
    {
        out_width->valid = true;
        out_width->is_auto = false;
        out_width->unit = CSS_UNIT_PX;
        out_width->value_milli = 3000;
        have_width = true;
    }
    return true;
}

static bool css_parse_int_value(const char *start, const char *end, int32_t *out)
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

    int sign = 1;
    const char *p = start;
    if (*p == '-' || *p == '+')
    {
        if (*p == '-')
        {
            sign = -1;
        }
        ++p;
    }
    if (p >= end || !isdigit((unsigned char)*p))
    {
        return false;
    }

    int64_t value = 0;
    const int64_t limit = 2147483647;
    while (p < end && isdigit((unsigned char)*p))
    {
        value = value * 10 + (*p - '0');
        if (value > limit)
        {
            value = limit;
            break;
        }
        ++p;
    }
    if (p != end)
    {
        return false;
    }

    *out = (int32_t)(sign * value);
    return true;
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
        css_style_apply_background_shorthand(style, val_start, val_end);
        return;
    }

    if ((size_t)(prop_end - prop_start) == 16 && strncasecmp(prop_start, "background-color", 16) == 0)
    {
        video_color_t c;
        if (css_value_is_keyword(val_start, val_end, "transparent"))
        {
            style->has_background = true;
            style->background_transparent = true;
            return;
        }
        if (css_parse_color(val_start, val_end, &c))
        {
            style->has_background = true;
            style->background_transparent = false;
            style->background = c;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 16 && strncasecmp(prop_start, "background-image", 16) == 0)
    {
        if (css_value_is_keyword(val_start, val_end, "none"))
        {
            css_style_set_background_image(style, NULL, false);
            return;
        }
        char *url = NULL;
        if (css_parse_url_token(val_start, val_end, &url))
        {
            css_style_set_background_image(style, url, true);
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 17 && strncasecmp(prop_start, "background-repeat", 17) == 0)
    {
        if (css_value_is_keyword(val_start, val_end, "repeat"))
        {
            style->has_background_repeat = true;
            style->background_repeat = CSS_BACKGROUND_REPEAT_REPEAT;
            return;
        }
        if (css_value_is_keyword(val_start, val_end, "no-repeat"))
        {
            style->has_background_repeat = true;
            style->background_repeat = CSS_BACKGROUND_REPEAT_NO_REPEAT;
            return;
        }
        if (css_value_is_keyword(val_start, val_end, "repeat-x"))
        {
            style->has_background_repeat = true;
            style->background_repeat = CSS_BACKGROUND_REPEAT_REPEAT_X;
            return;
        }
        if (css_value_is_keyword(val_start, val_end, "repeat-y"))
        {
            style->has_background_repeat = true;
            style->background_repeat = CSS_BACKGROUND_REPEAT_REPEAT_Y;
            return;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 21 && strncasecmp(prop_start, "background-attachment", 21) == 0)
    {
        if (css_value_is_keyword(val_start, val_end, "fixed"))
        {
            style->has_background_attachment = true;
            style->background_attachment = CSS_BACKGROUND_ATTACHMENT_FIXED;
            return;
        }
        if (css_value_is_keyword(val_start, val_end, "scroll"))
        {
            style->has_background_attachment = true;
            style->background_attachment = CSS_BACKGROUND_ATTACHMENT_SCROLL;
            return;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 19 && strncasecmp(prop_start, "background-position", 19) == 0)
    {
        css_length_t pos_x = {0};
        css_length_t pos_y = {0};
        bool has_pos = false;
        if (css_parse_background_position_tokens(val_start, val_end, &pos_x, &pos_y, &has_pos) && has_pos)
        {
            style->has_background_position = true;
            style->background_pos_x = pos_x;
            style->background_pos_y = pos_y;
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

    if ((size_t)(prop_end - prop_start) == 9 && strncasecmp(prop_start, "min-width", 9) == 0)
    {
        css_length_t len;
        if (css_parse_length_token(val_start, val_end, &len))
        {
            style->has_min_width = true;
            style->min_width = len;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 9 && strncasecmp(prop_start, "max-width", 9) == 0)
    {
        css_length_t len;
        if (css_parse_length_token(val_start, val_end, &len))
        {
            style->has_max_width = true;
            style->max_width = len;
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

    if ((size_t)(prop_end - prop_start) == 10 && strncasecmp(prop_start, "min-height", 10) == 0)
    {
        css_length_t len;
        if (css_parse_length_token(val_start, val_end, &len))
        {
            style->has_min_height = true;
            style->min_height = len;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 10 && strncasecmp(prop_start, "max-height", 10) == 0)
    {
        css_length_t len;
        if (css_parse_length_token(val_start, val_end, &len))
        {
            style->has_max_height = true;
            style->max_height = len;
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
        style->float_inherit = false;
        style->float_mode = CSS_FLOAT_NONE;
        if (len == 7 && strncasecmp(s, "inherit", 7) == 0)
        {
            style->float_inherit = true;
            style->float_mode = CSS_FLOAT_NONE;
        }
        else if (len == 4 && strncasecmp(s, "left", 4) == 0)
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
        bool transparent = false;
        if (css_parse_border_value(val_start, val_end, &width, &color, &has_color, &transparent))
        {
            style->has_border = true;
            style->border_width = css_box_from_length(width);
            css_apply_border_style_none_mask(style);
            if (has_color)
            {
                style->has_border_color = true;
                style->border_color = color;
                style->border_transparent = transparent;
                for (size_t i = 0; i < 4; ++i)
                {
                    style->border_color_side_set[i] = true;
                    style->border_color_side[i] = color;
                    style->border_color_side_transparent[i] = transparent;
                }
            }
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 10 && strncasecmp(prop_start, "border-top", 10) == 0)
    {
        css_length_t width;
        video_color_t color;
        bool has_color = false;
        bool transparent = false;
        if (css_parse_border_value(val_start, val_end, &width, &color, &has_color, &transparent))
        {
            style->has_border = true;
            style->border_width.top = width;
            css_apply_border_style_none_mask(style);
            if (has_color)
            {
                style->has_border_color = true;
                style->border_color = color;
                style->border_transparent = transparent;
                style->border_color_side_set[CSS_BORDER_SIDE_TOP] = true;
                style->border_color_side[CSS_BORDER_SIDE_TOP] = color;
                style->border_color_side_transparent[CSS_BORDER_SIDE_TOP] = transparent;
            }
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 12 && strncasecmp(prop_start, "border-right", 12) == 0)
    {
        css_length_t width;
        video_color_t color;
        bool has_color = false;
        bool transparent = false;
        if (css_parse_border_value(val_start, val_end, &width, &color, &has_color, &transparent))
        {
            style->has_border = true;
            style->border_width.right = width;
            css_apply_border_style_none_mask(style);
            if (has_color)
            {
                style->has_border_color = true;
                style->border_color = color;
                style->border_transparent = transparent;
                style->border_color_side_set[CSS_BORDER_SIDE_RIGHT] = true;
                style->border_color_side[CSS_BORDER_SIDE_RIGHT] = color;
                style->border_color_side_transparent[CSS_BORDER_SIDE_RIGHT] = transparent;
            }
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 13 && strncasecmp(prop_start, "border-bottom", 13) == 0)
    {
        css_length_t width;
        video_color_t color;
        bool has_color = false;
        bool transparent = false;
        if (css_parse_border_value(val_start, val_end, &width, &color, &has_color, &transparent))
        {
            style->has_border = true;
            style->border_width.bottom = width;
            css_apply_border_style_none_mask(style);
            if (has_color)
            {
                style->has_border_color = true;
                style->border_color = color;
                style->border_transparent = transparent;
                style->border_color_side_set[CSS_BORDER_SIDE_BOTTOM] = true;
                style->border_color_side[CSS_BORDER_SIDE_BOTTOM] = color;
                style->border_color_side_transparent[CSS_BORDER_SIDE_BOTTOM] = transparent;
            }
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 11 && strncasecmp(prop_start, "border-left", 11) == 0)
    {
        css_length_t width;
        video_color_t color;
        bool has_color = false;
        bool transparent = false;
        if (css_parse_border_value(val_start, val_end, &width, &color, &has_color, &transparent))
        {
            style->has_border = true;
            style->border_width.left = width;
            css_apply_border_style_none_mask(style);
            if (has_color)
            {
                style->has_border_color = true;
                style->border_color = color;
                style->border_transparent = transparent;
                style->border_color_side_set[CSS_BORDER_SIDE_LEFT] = true;
                style->border_color_side[CSS_BORDER_SIDE_LEFT] = color;
                style->border_color_side_transparent[CSS_BORDER_SIDE_LEFT] = transparent;
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
            css_apply_border_style_none_mask(style);
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 16 && strncasecmp(prop_start, "border-top-width", 16) == 0)
    {
        css_length_t len;
        if (css_parse_border_width_token(val_start, val_end, &len))
        {
            style->has_border = true;
            style->border_width.top = len;
            css_apply_border_style_none_mask(style);
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 18 && strncasecmp(prop_start, "border-right-width", 18) == 0)
    {
        css_length_t len;
        if (css_parse_border_width_token(val_start, val_end, &len))
        {
            style->has_border = true;
            style->border_width.right = len;
            css_apply_border_style_none_mask(style);
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 19 && strncasecmp(prop_start, "border-bottom-width", 19) == 0)
    {
        css_length_t len;
        if (css_parse_border_width_token(val_start, val_end, &len))
        {
            style->has_border = true;
            style->border_width.bottom = len;
            css_apply_border_style_none_mask(style);
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 17 && strncasecmp(prop_start, "border-left-width", 17) == 0)
    {
        css_length_t len;
        if (css_parse_border_width_token(val_start, val_end, &len))
        {
            style->has_border = true;
            style->border_width.left = len;
            css_apply_border_style_none_mask(style);
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 12 && strncasecmp(prop_start, "border-color", 12) == 0)
    {
        video_color_t colors[4] = {0};
        bool transparent[4] = {false, false, false, false};
        if (css_parse_border_color_value(val_start, val_end, colors, transparent))
        {
            style->has_border_color = true;
            style->border_color = colors[0];
            style->border_transparent = transparent[0];
            for (size_t i = 0; i < 4; ++i)
            {
                style->border_color_side_set[i] = true;
                style->border_color_side[i] = colors[i];
                style->border_color_side_transparent[i] = transparent[i];
            }
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 12 && strncasecmp(prop_start, "border-style", 12) == 0)
    {
        bool none_flags[4] = {false, false, false, false};
        if (css_parse_border_style_value(val_start, val_end, none_flags))
        {
            style->has_border_style = true;
            style->border_style_none[CSS_BORDER_SIDE_TOP] = none_flags[0];
            style->border_style_none[CSS_BORDER_SIDE_RIGHT] = none_flags[1];
            style->border_style_none[CSS_BORDER_SIDE_BOTTOM] = none_flags[2];
            style->border_style_none[CSS_BORDER_SIDE_LEFT] = none_flags[3];
            style->has_border = true;
            css_apply_border_style_none_mask(style);
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 8 && strncasecmp(prop_start, "position", 8) == 0)
    {
        const char *s = val_start;
        const char *e = val_end;
        css_trim_range(&s, &e);
        size_t len = (size_t)(e - s);
        style->has_position = true;
        style->position = CSS_POSITION_STATIC;
        if (len == 6 && strncasecmp(s, "static", 6) == 0)
        {
            style->position = CSS_POSITION_STATIC;
        }
        else if (len == 8 && strncasecmp(s, "relative", 8) == 0)
        {
            style->position = CSS_POSITION_RELATIVE;
        }
        else if (len == 8 && strncasecmp(s, "absolute", 8) == 0)
        {
            style->position = CSS_POSITION_ABSOLUTE;
        }
        else if (len == 5 && strncasecmp(s, "fixed", 5) == 0)
        {
            style->position = CSS_POSITION_FIXED;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 7 && strncasecmp(prop_start, "z-index", 7) == 0)
    {
        int32_t z = 0;
        if (css_parse_int_value(val_start, val_end, &z))
        {
            style->has_z_index = true;
            style->z_index = z;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 3 && strncasecmp(prop_start, "top", 3) == 0)
    {
        css_length_t len;
        if (css_parse_length_token(val_start, val_end, &len))
        {
            style->has_top = true;
            style->top = len;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 5 && strncasecmp(prop_start, "right", 5) == 0)
    {
        css_length_t len;
        if (css_parse_length_token(val_start, val_end, &len))
        {
            style->has_right = true;
            style->right = len;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 6 && strncasecmp(prop_start, "bottom", 6) == 0)
    {
        css_length_t len;
        if (css_parse_length_token(val_start, val_end, &len))
        {
            style->has_bottom = true;
            style->bottom = len;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 4 && strncasecmp(prop_start, "left", 4) == 0)
    {
        css_length_t len;
        if (css_parse_length_token(val_start, val_end, &len))
        {
            style->has_left = true;
            style->left = len;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 8 && strncasecmp(prop_start, "overflow", 8) == 0)
    {
        const char *s = val_start;
        const char *e = val_end;
        css_trim_range(&s, &e);
        size_t len = (size_t)(e - s);
        style->has_overflow = true;
        style->overflow = CSS_OVERFLOW_VISIBLE;
        if (len == 7 && strncasecmp(s, "visible", 7) == 0)
        {
            style->overflow = CSS_OVERFLOW_VISIBLE;
        }
        else if (len == 6 && strncasecmp(s, "hidden", 6) == 0)
        {
            style->overflow = CSS_OVERFLOW_HIDDEN;
        }
        else if (len == 6 && strncasecmp(s, "scroll", 6) == 0)
        {
            style->overflow = CSS_OVERFLOW_SCROLL;
        }
        else if (len == 4 && strncasecmp(s, "auto", 4) == 0)
        {
            style->overflow = CSS_OVERFLOW_AUTO;
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

    if ((size_t)(prop_end - prop_start) == 7 && strncasecmp(prop_start, "content", 7) == 0)
    {
        char *content = NULL;
        if (css_parse_content_value(val_start, val_end, &content))
        {
            if (style->content_owned && style->content)
            {
                free((void *)style->content);
            }
            style->content = content;
            style->content_owned = (content != NULL);
            style->has_content = (content != NULL);
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
            style->has_display = true;
            style->display = CSS_DISPLAY_INLINE_BLOCK;
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
        else if (len == 4 && strncasecmp(s, "grid", 4) == 0)
        {
            style->has_display = true;
            style->display = CSS_DISPLAY_GRID;
        }
        else if (len == 11 && strncasecmp(s, "inline-grid", 11) == 0)
        {
            style->has_display = true;
            style->display = CSS_DISPLAY_INLINE_GRID;
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
        else if (len == 5 && strncasecmp(s, "table", 5) == 0)
        {
            style->has_display = true;
            style->display = CSS_DISPLAY_TABLE;
        }
        else if (len == 10 && strncasecmp(s, "table-cell", 10) == 0)
        {
            style->has_display = true;
            style->display = CSS_DISPLAY_TABLE_CELL;
        }
        else if (len == 4 && strncasecmp(s, "none", 4) == 0)
        {
            style->has_display = true;
            style->display = CSS_DISPLAY_NONE;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 10 && strncasecmp(prop_start, "box-sizing", 10) == 0)
    {
        const char *s = val_start;
        const char *e = val_end;
        css_trim_range(&s, &e);
        size_t len = (size_t)(e - s);
        style->has_box_sizing = true;
        style->box_sizing_inherit = false;
        style->box_sizing = CSS_BOX_SIZING_CONTENT_BOX;
        if (len == 7 && strncasecmp(s, "inherit", 7) == 0)
        {
            style->box_sizing_inherit = true;
        }
        else if (len == 10 && strncasecmp(s, "border-box", 10) == 0)
        {
            style->box_sizing = CSS_BOX_SIZING_BORDER_BOX;
        }
        else if (len == 11 && strncasecmp(s, "content-box", 11) == 0)
        {
            style->box_sizing = CSS_BOX_SIZING_CONTENT_BOX;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 15 && strncasecmp(prop_start, "list-style-type", 15) == 0)
    {
        css_list_style_type_t type;
        if (css_parse_list_style_type_token(val_start, val_end, &type))
        {
            style->has_list_style_type = true;
            style->list_style_type = type;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 10 && strncasecmp(prop_start, "list-style", 10) == 0)
    {
        const char *p = val_start;
        const char *tok_s = NULL;
        const char *tok_e = NULL;
        while (css_next_token(&p, val_end, &tok_s, &tok_e))
        {
            css_list_style_type_t type;
            if (css_parse_list_style_type_token(tok_s, tok_e, &type))
            {
                style->has_list_style_type = true;
                style->list_style_type = type;
            }
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 21 && strncasecmp(prop_start, "grid-template-columns", 21) == 0)
    {
        int32_t cols = 0;
        if (css_parse_grid_template_columns_count(val_start, val_end, &cols))
        {
            style->has_grid_template_columns = true;
            style->grid_template_columns = cols;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 17 && strncasecmp(prop_start, "grid-column-start", 17) == 0)
    {
        int32_t line = 0;
        if (css_parse_grid_line_index(val_start, val_end, &line))
        {
            style->has_grid_column_start = true;
            style->grid_column_start = line;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 15 && strncasecmp(prop_start, "grid-column-end", 15) == 0)
    {
        int32_t line = 0;
        if (css_parse_grid_line_index(val_start, val_end, &line))
        {
            style->has_grid_column_end = true;
            style->grid_column_end = line;
        }
        return;
    }

    if ((size_t)(prop_end - prop_start) == 11 && strncasecmp(prop_start, "grid-column", 11) == 0)
    {
        int32_t start = 0;
        int32_t end = 0;
        int32_t span = 0;
        bool has_start = false;
        bool has_end = false;
        bool has_span = false;
        css_parse_grid_column_value(val_start,
                                    val_end,
                                    &start,
                                    &has_start,
                                    &end,
                                    &has_end,
                                    &span,
                                    &has_span);
        if (has_span)
        {
            style->has_grid_column_span = true;
            style->grid_column_span = span;
        }
        if (has_start)
        {
            style->has_grid_column_start = true;
            style->grid_column_start = start;
        }
        if (has_end)
        {
            style->has_grid_column_end = true;
            style->grid_column_end = end;
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
