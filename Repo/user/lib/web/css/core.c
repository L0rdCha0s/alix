#include "web/css/css_internal.h"

#include "ctype.h"
#include "libc.h"

void css_skip_ws_and_comments(const char **p)
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

void css_trim_range(const char **start, const char **end)
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

char *css_strdup_lower(const char *start, const char *end)
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

bool css_parse_color(const char *start, const char *end, video_color_t *out)
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
        if (name_len == 6 && strncasecmp(start, "yellow", 6) == 0)
        {
            *out = video_make_color(0xFF, 0xFF, 0x00);
            return true;
        }
        if (name_len == 4 && strncasecmp(start, "blue", 4) == 0)
        {
            *out = video_make_color(0x00, 0x00, 0xFF);
            return true;
        }
        if (name_len == 4 && strncasecmp(start, "navy", 4) == 0)
        {
            *out = video_make_color(0x00, 0x00, 0x80);
            return true;
        }
        if (name_len == 5 && strncasecmp(start, "green", 5) == 0)
        {
            *out = video_make_color(0x00, 0x80, 0x00);
            return true;
        }
        if (name_len == 6 && strncasecmp(start, "maroon", 6) == 0)
        {
            *out = video_make_color(0x80, 0x00, 0x00);
            return true;
        }
        if (name_len == 6 && strncasecmp(start, "purple", 6) == 0)
        {
            *out = video_make_color(0x80, 0x00, 0x80);
            return true;
        }
        if (name_len == 6 && strncasecmp(start, "orange", 6) == 0)
        {
            *out = video_make_color(0xFF, 0xA5, 0x00);
            return true;
        }
        if (name_len == 4 && strncasecmp(start, "pink", 4) == 0)
        {
            *out = video_make_color(0xFF, 0xC0, 0xCB);
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

bool css_parse_number_milli(const char *start, const char *end, int32_t *out_milli)
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
    bool negative = false;
    if (p < end && (*p == '-' || *p == '+'))
    {
        negative = (*p == '-');
        p++;
    }
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

    /* Reject trailing units/suffixes (e.g. "12pt"). */
    if (p != end)
    {
        return false;
    }

    int32_t value = integer * 1000 + frac;
    if (negative)
    {
        value = -value;
    }
    *out_milli = value;
    return true;
}

bool css_parse_length_token(const char *start, const char *end, css_length_t *out)
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
    if (p < end && (*p == '-' || *p == '+'))
    {
        p++;
    }
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
        else if (ulen == 2 && (p[0] == 'p' || p[0] == 'P') && (p[1] == 't' || p[1] == 'T'))
        {
            /* Approximate: 1pt = 4/3 px */
            unit = CSS_UNIT_PX;
            number_milli = (int32_t)(((int64_t)number_milli * 4 + 1) / 3);
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

bool css_parse_margin_value(const char *start, const char *end, css_box_t *out)
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

css_box_t css_box_from_length(css_length_t len)
{
    return (css_box_t){
        .top = len,
        .right = len,
        .bottom = len,
        .left = len,
    };
}
