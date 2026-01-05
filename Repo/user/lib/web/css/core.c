#include "web/css/css_internal.h"

#include "ctype.h"
#include "libc.h"
#include "math.h"

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

void css_skip_ws_and_comments_range(const char **p, const char *end)
{
    if (!p || !*p || !end)
    {
        return;
    }
    while (*p < end)
    {
        while (*p < end && isspace((unsigned char)**p))
        {
            (*p)++;
        }
        if (*p + 1 < end && (*p)[0] == '/' && (*p)[1] == '*')
        {
            *p += 2;
            while (*p + 1 < end && !((*p)[0] == '*' && (*p)[1] == '/'))
            {
                (*p)++;
            }
            if (*p + 1 < end)
            {
                *p += 2;
            }
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

typedef struct css_calc_value
{
    int32_t value_milli;
    css_unit_t unit;
    bool valid;
} css_calc_value_t;

static void css_calc_skip_ws(const char **p, const char *end)
{
    if (!p || !*p || !end)
    {
        return;
    }
    css_skip_ws_and_comments_range(p, end);
}

static bool css_calc_parse_number(const char **p, const char *end, css_calc_value_t *out)
{
    if (!p || !*p || !out)
    {
        return false;
    }

    const char *s = *p;
    bool negative = false;
    if (s < end && (*s == '-' || *s == '+'))
    {
        negative = (*s == '-');
        ++s;
    }

    bool saw_digit = false;
    int64_t integer = 0;
    int64_t frac = 0;
    int64_t frac_scale = 1;
    while (s < end && isdigit((unsigned char)*s))
    {
        saw_digit = true;
        integer = integer * 10 + (int64_t)(*s - '0');
        ++s;
    }
    if (s < end && *s == '.')
    {
        ++s;
        while (s < end && isdigit((unsigned char)*s) && frac_scale < 1000000)
        {
            saw_digit = true;
            frac = frac * 10 + (int64_t)(*s - '0');
            frac_scale *= 10;
            ++s;
        }
    }
    if (!saw_digit)
    {
        return false;
    }

    int64_t milli = integer * 1000;
    if (frac_scale > 1)
    {
        milli += (frac * 1000) / frac_scale;
    }
    if (negative)
    {
        milli = -milli;
    }

    css_unit_t unit = CSS_UNIT_NONE;
    const char *u = s;
    if (u < end && *u == '%')
    {
        unit = CSS_UNIT_PERCENT;
        ++u;
    }
    else if (u < end && isalpha((unsigned char)*u))
    {
        size_t ulen = (size_t)(end - u);
        if (ulen >= 2 && (u[0] == 'p' || u[0] == 'P') && (u[1] == 'x' || u[1] == 'X'))
        {
            unit = CSS_UNIT_PX;
            u += 2;
        }
        else if (ulen >= 2 && (u[0] == 'p' || u[0] == 'P') && (u[1] == 't' || u[1] == 'T'))
        {
            unit = CSS_UNIT_PX;
            milli = (milli * 4 + 1) / 3;
            u += 2;
        }
        else if (ulen >= 2 && (u[0] == 'v' || u[0] == 'V') && (u[1] == 'w' || u[1] == 'W'))
        {
            unit = CSS_UNIT_VW;
            u += 2;
        }
        else if (ulen >= 2 && (u[0] == 'v' || u[0] == 'V') && (u[1] == 'h' || u[1] == 'H'))
        {
            unit = CSS_UNIT_VH;
            u += 2;
        }
        else if (ulen >= 2 && (u[0] == 'e' || u[0] == 'E') && (u[1] == 'm' || u[1] == 'M'))
        {
            unit = CSS_UNIT_EM;
            u += 2;
        }
        else if (ulen >= 3 &&
                 (u[0] == 'r' || u[0] == 'R') &&
                 (u[1] == 'e' || u[1] == 'E') &&
                 (u[2] == 'm' || u[2] == 'M'))
        {
            unit = CSS_UNIT_EM;
            u += 3;
        }
        else if (ulen >= 3 &&
                 (u[0] == 'd' || u[0] == 'D') &&
                 (u[1] == 'e' || u[1] == 'E') &&
                 (u[2] == 'g' || u[2] == 'G'))
        {
            unit = CSS_UNIT_NONE;
            u += 3;
        }
        else
        {
            return false;
        }
    }

    *p = u;
    out->value_milli = (int32_t)milli;
    out->unit = unit;
    out->valid = true;
    return true;
}

static const char *css_calc_find_paren_end(const char *start, const char *end)
{
    int depth = 1;
    const char *p = start;
    while (p < end)
    {
        char c = *p;
        if (c == '(')
        {
            ++depth;
        }
        else if (c == ')')
        {
            --depth;
            if (depth == 0)
            {
                return p;
            }
        }
        ++p;
    }
    return NULL;
}

static bool css_calc_coerce_units(css_calc_value_t *a, css_calc_value_t *b)
{
    if (!a || !b)
    {
        return false;
    }
    if (a->unit == b->unit)
    {
        return true;
    }
    if (a->unit == CSS_UNIT_NONE && a->value_milli == 0)
    {
        a->unit = b->unit;
        return true;
    }
    if (b->unit == CSS_UNIT_NONE && b->value_milli == 0)
    {
        b->unit = a->unit;
        return true;
    }
    return false;
}

static size_t css_calc_split_args(const char *start, const char *end, const char **out_starts, const char **out_ends, size_t max_args)
{
    if (!start || !end || end < start)
    {
        return 0;
    }
    size_t count = 0;
    const char *arg_start = start;
    const char *p = start;
    int depth = 0;
    char quote = '\0';

    while (p < end)
    {
        char c = *p;
        if (quote)
        {
            if (c == '\\' && p + 1 < end)
            {
                p += 2;
                continue;
            }
            if (c == quote)
            {
                quote = '\0';
            }
            ++p;
            continue;
        }
        if (c == '"' || c == '\'')
        {
            quote = c;
            ++p;
            continue;
        }
        if (c == '/' && p + 1 < end && p[1] == '*')
        {
            p += 2;
            while (p + 1 < end && !(p[0] == '*' && p[1] == '/'))
            {
                ++p;
            }
            if (p + 1 < end)
            {
                p += 2;
            }
            continue;
        }
        if (c == '(')
        {
            ++depth;
            ++p;
            continue;
        }
        if (c == ')')
        {
            if (depth > 0)
            {
                --depth;
            }
            ++p;
            continue;
        }
        if (c == ',' && depth == 0)
        {
            if (count < max_args)
            {
                out_starts[count] = arg_start;
                out_ends[count] = p;
                ++count;
            }
            arg_start = p + 1;
        }
        ++p;
    }

    if (count < max_args)
    {
        out_starts[count] = arg_start;
        out_ends[count] = end;
        ++count;
    }
    return count;
}

static bool css_calc_combine_add(css_calc_value_t *acc, const css_calc_value_t *rhs, int sign)
{
    if (!acc || !rhs)
    {
        return false;
    }
    if (acc->unit == rhs->unit)
    {
        int64_t value = (int64_t)acc->value_milli + (int64_t)sign * rhs->value_milli;
        acc->value_milli = (int32_t)value;
        return true;
    }
    if (acc->unit == CSS_UNIT_NONE && acc->value_milli == 0)
    {
        acc->unit = rhs->unit;
        acc->value_milli = sign * rhs->value_milli;
        return true;
    }
    if (rhs->unit == CSS_UNIT_NONE && rhs->value_milli == 0)
    {
        return true;
    }
    return false;
}

static bool css_calc_combine_mul(css_calc_value_t *acc, const css_calc_value_t *rhs, bool divide)
{
    if (!acc || !rhs)
    {
        return false;
    }
    if (divide && rhs->value_milli == 0)
    {
        return false;
    }

    bool acc_unit = (acc->unit != CSS_UNIT_NONE);
    bool rhs_unit = (rhs->unit != CSS_UNIT_NONE);
    if (acc_unit && rhs_unit)
    {
        return false;
    }

    int64_t value = 0;
    if (!divide)
    {
        value = (int64_t)acc->value_milli * (int64_t)rhs->value_milli;
        value /= 1000;
    }
    else
    {
        value = (int64_t)acc->value_milli * 1000;
        value /= rhs->value_milli;
    }

    if (!acc_unit && rhs_unit)
    {
        acc->unit = rhs->unit;
    }
    acc->value_milli = (int32_t)value;
    return true;
}

static bool css_calc_parse_expr(const char **p, const char *end, css_calc_value_t *out);
static bool css_parse_calc_value(const char *start, const char *end, css_calc_value_t *out);

static bool css_calc_parse_function(const char **p, const char *end, css_calc_value_t *out)
{
    if (!p || !*p || !out)
    {
        return false;
    }
    const char *start = *p;
    if (end <= start)
    {
        return false;
    }

    struct
    {
        const char *name;
        size_t len;
    } names[] = {
        {"calc", 4},
        {"min", 3},
        {"max", 3},
        {"clamp", 5},
    };

    size_t name_index = 0;
    size_t name_len = 0;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
    {
        if ((size_t)(end - start) >= names[i].len + 1 &&
            strncasecmp(start, names[i].name, names[i].len) == 0 &&
            start[names[i].len] == '(')
        {
            name_index = i;
            name_len = names[i].len;
            break;
        }
    }
    if (name_len == 0)
    {
        return false;
    }

    const char *sub_start = start + name_len + 1;
    const char *sub_end = css_calc_find_paren_end(sub_start, end);
    if (!sub_end)
    {
        return false;
    }

    if (strcmp(names[name_index].name, "calc") == 0)
    {
        const char *scan = sub_start;
        css_calc_value_t inner = {0};
        if (!css_calc_parse_expr(&scan, sub_end, &inner))
        {
            return false;
        }
        css_calc_skip_ws(&scan, sub_end);
        if (scan != sub_end)
        {
            return false;
        }
        *p = sub_end + 1;
        *out = inner;
        return true;
    }

    const char *arg_starts[4];
    const char *arg_ends[4];
    size_t arg_count = css_calc_split_args(sub_start, sub_end, arg_starts, arg_ends, 4);
    if (arg_count == 0)
    {
        return false;
    }

    if (strcmp(names[name_index].name, "clamp") == 0)
    {
        if (arg_count != 3)
        {
            return false;
        }
        css_calc_value_t parts[3] = {0};
        for (size_t i = 0; i < 3; ++i)
        {
            const char *a = arg_starts[i];
            const char *b = arg_ends[i];
            css_trim_range(&a, &b);
            if (!css_parse_calc_value(a, b, &parts[i]))
            {
                return false;
            }
        }
        if (!css_calc_coerce_units(&parts[0], &parts[1]) || !css_calc_coerce_units(&parts[1], &parts[2]))
        {
            *p = sub_end + 1;
            *out = parts[1];
            return true;
        }
        if (parts[1].value_milli < parts[0].value_milli)
        {
            parts[1].value_milli = parts[0].value_milli;
        }
        if (parts[1].value_milli > parts[2].value_milli)
        {
            parts[1].value_milli = parts[2].value_milli;
        }
        *p = sub_end + 1;
        *out = parts[1];
        return true;
    }

    if (arg_count < 2)
    {
        return false;
    }
    css_calc_value_t best = {0};
    for (size_t i = 0; i < arg_count; ++i)
    {
        const char *a = arg_starts[i];
        const char *b = arg_ends[i];
        css_trim_range(&a, &b);
        css_calc_value_t value = {0};
        if (!css_parse_calc_value(a, b, &value))
        {
            return false;
        }
        if (i == 0)
        {
            best = value;
            continue;
        }
        css_calc_value_t lhs = best;
        css_calc_value_t rhs = value;
        if (!css_calc_coerce_units(&lhs, &rhs))
        {
            continue;
        }
        if (strcmp(names[name_index].name, "min") == 0)
        {
            if (rhs.value_milli < lhs.value_milli)
            {
                best = value;
            }
        }
        else
        {
            if (rhs.value_milli > lhs.value_milli)
            {
                best = value;
            }
        }
    }
    *p = sub_end + 1;
    *out = best;
    return true;
}

static bool css_calc_parse_factor(const char **p, const char *end, css_calc_value_t *out)
{
    if (!p || !*p || !out)
    {
        return false;
    }
    css_calc_skip_ws(p, end);

    bool negate = false;
    while (*p < end && (**p == '+' || **p == '-'))
    {
        if (**p == '-')
        {
            negate = !negate;
        }
        ++(*p);
        css_calc_skip_ws(p, end);
    }

    if (*p >= end)
    {
        return false;
    }

    css_calc_value_t func = {0};
    if (css_calc_parse_function(p, end, &func))
    {
        if (negate)
        {
            func.value_milli = -func.value_milli;
        }
        *out = func;
        return true;
    }

    if (**p == '(')
    {
        const char *sub_start = *p + 1;
        const char *sub_end = css_calc_find_paren_end(sub_start, end);
        if (!sub_end)
        {
            return false;
        }
        const char *scan = sub_start;
        css_calc_value_t inner = {0};
        if (!css_calc_parse_expr(&scan, sub_end, &inner))
        {
            return false;
        }
        css_calc_skip_ws(&scan, sub_end);
        if (scan != sub_end)
        {
            return false;
        }
        *p = sub_end + 1;
        if (negate)
        {
            inner.value_milli = -inner.value_milli;
        }
        *out = inner;
        return true;
    }

    css_calc_value_t value = {0};
    if (!css_calc_parse_number(p, end, &value))
    {
        return false;
    }
    if (negate)
    {
        value.value_milli = -value.value_milli;
    }
    *out = value;
    return true;
}

static bool css_calc_parse_term(const char **p, const char *end, css_calc_value_t *out)
{
    css_calc_value_t acc = {0};
    if (!css_calc_parse_factor(p, end, &acc))
    {
        return false;
    }

    while (*p < end)
    {
        css_calc_skip_ws(p, end);
        if (*p >= end)
        {
            break;
        }
        char op = **p;
        if (op != '*' && op != '/')
        {
            break;
        }
        ++(*p);
        css_calc_value_t rhs = {0};
        if (!css_calc_parse_factor(p, end, &rhs))
        {
            return false;
        }
        if (!css_calc_combine_mul(&acc, &rhs, op == '/'))
        {
            return false;
        }
    }
    *out = acc;
    return true;
}

static bool css_calc_parse_expr(const char **p, const char *end, css_calc_value_t *out)
{
    css_calc_value_t acc = {0};
    if (!css_calc_parse_term(p, end, &acc))
    {
        return false;
    }
    while (*p < end)
    {
        css_calc_skip_ws(p, end);
        if (*p >= end)
        {
            break;
        }
        char op = **p;
        if (op != '+' && op != '-')
        {
            break;
        }
        ++(*p);
        css_calc_value_t rhs = {0};
        if (!css_calc_parse_term(p, end, &rhs))
        {
            return false;
        }
        if (!css_calc_combine_add(&acc, &rhs, op == '+' ? 1 : -1))
        {
            return false;
        }
    }
    *out = acc;
    return true;
}

static bool css_parse_calc_value(const char *start, const char *end, css_calc_value_t *out)
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
    const char *expr_start = start;
    const char *expr_end = end;
    if (len >= 6 && strncasecmp(start, "calc(", 5) == 0 && end[-1] == ')')
    {
        expr_start = start + 5;
        expr_end = end - 1;
    }

    const char *p = expr_start;
    css_calc_value_t value = {0};
    if (!css_calc_parse_expr(&p, expr_end, &value))
    {
        return false;
    }
    css_calc_skip_ws(&p, expr_end);
    if (p != expr_end)
    {
        return false;
    }
    *out = value;
    return true;
}

static bool css_parse_color_component(const char **p, const char *end, double *out_value, bool *out_percent)
{
    if (!p || !*p || !out_value || !out_percent)
    {
        return false;
    }
    css_calc_value_t value = {0};
    if (!css_calc_parse_number(p, end, &value))
    {
        return false;
    }
    if (value.unit == CSS_UNIT_PERCENT)
    {
        *out_value = (double)value.value_milli / 1000.0;
        *out_percent = true;
        return true;
    }
    if (value.unit == CSS_UNIT_NONE)
    {
        *out_value = (double)value.value_milli / 1000.0;
        *out_percent = false;
        return true;
    }
    return false;
}

static double css_fmod(double x, double y)
{
    if (y == 0.0)
    {
        return 0.0;
    }
    double q = floor(x / y);
    return x - q * y;
}

static void css_hsl_to_rgb(double h, double s, double l, uint8_t *out_r, uint8_t *out_g, uint8_t *out_b)
{
    if (!out_r || !out_g || !out_b)
    {
        return;
    }
    if (s < 0.0) s = 0.0;
    if (s > 1.0) s = 1.0;
    if (l < 0.0) l = 0.0;
    if (l > 1.0) l = 1.0;

    h = css_fmod(h, 360.0);
    if (h < 0.0)
    {
        h += 360.0;
    }

    double c = (1.0 - fabs(2.0 * l - 1.0)) * s;
    double hh = h / 60.0;
    double x = c * (1.0 - fabs(css_fmod(hh, 2.0) - 1.0));
    double r1 = 0.0;
    double g1 = 0.0;
    double b1 = 0.0;

    if (hh >= 0.0 && hh < 1.0)
    {
        r1 = c;
        g1 = x;
    }
    else if (hh >= 1.0 && hh < 2.0)
    {
        r1 = x;
        g1 = c;
    }
    else if (hh >= 2.0 && hh < 3.0)
    {
        g1 = c;
        b1 = x;
    }
    else if (hh >= 3.0 && hh < 4.0)
    {
        g1 = x;
        b1 = c;
    }
    else if (hh >= 4.0 && hh < 5.0)
    {
        r1 = x;
        b1 = c;
    }
    else
    {
        r1 = c;
        b1 = x;
    }

    double m = l - c * 0.5;
    int r = (int)((r1 + m) * 255.0 + 0.5);
    int g = (int)((g1 + m) * 255.0 + 0.5);
    int b = (int)((b1 + m) * 255.0 + 0.5);

    if (r < 0) r = 0;
    if (r > 255) r = 255;
    if (g < 0) g = 0;
    if (g > 255) g = 255;
    if (b < 0) b = 0;
    if (b > 255) b = 255;

    *out_r = (uint8_t)r;
    *out_g = (uint8_t)g;
    *out_b = (uint8_t)b;
}

static bool css_parse_hsl_component(const char *start,
                                    const char *end,
                                    bool expect_percent,
                                    double *out_value)
{
    if (!out_value)
    {
        return false;
    }
    css_calc_value_t value = {0};
    if (!css_parse_calc_value(start, end, &value))
    {
        return false;
    }
    double v = (double)value.value_milli / 1000.0;
    if (expect_percent)
    {
        if (value.unit == CSS_UNIT_PERCENT)
        {
            *out_value = v;
            return true;
        }
        if (value.unit == CSS_UNIT_NONE)
        {
            if (v <= 1.0)
            {
                v *= 100.0;
            }
            *out_value = v;
            return true;
        }
        return false;
    }
    if (value.unit == CSS_UNIT_PERCENT)
    {
        *out_value = v * 3.6;
        return true;
    }
    if (value.unit == CSS_UNIT_NONE)
    {
        *out_value = v;
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
    bool is_rgb = (len >= 5 && strncasecmp(start, "rgb(", 4) == 0);
    bool is_rgba = (len >= 6 && strncasecmp(start, "rgba(", 5) == 0);
    if ((is_rgb || is_rgba) && end[-1] == ')')
    {
        const char *p = start + (is_rgba ? 5 : 4);
        const char *args_end = end - 1;
        double comps[3] = {0.0, 0.0, 0.0};
        bool perc[3] = {false, false, false};

        for (int i = 0; i < 3; ++i)
        {
            css_calc_skip_ws(&p, args_end);
            if (!css_parse_color_component(&p, args_end, &comps[i], &perc[i]))
            {
                return false;
            }
            css_calc_skip_ws(&p, args_end);
            if (i < 2)
            {
                if (p < args_end && *p == ',')
                {
                    ++p;
                    continue;
                }
            }
        }

        css_calc_skip_ws(&p, args_end);
        if (p < args_end && (*p == '/' || *p == ','))
        {
            ++p;
            css_calc_skip_ws(&p, args_end);
            double alpha = 1.0;
            bool alpha_percent = false;
            (void)css_parse_color_component(&p, args_end, &alpha, &alpha_percent);
        }
        css_calc_skip_ws(&p, args_end);
        if (p != args_end)
        {
            return false;
        }

        int rgb[3] = {0, 0, 0};
        for (int i = 0; i < 3; ++i)
        {
            double v = comps[i];
            if (perc[i])
            {
                if (v < 0.0) v = 0.0;
                if (v > 100.0) v = 100.0;
                v = v * 255.0 / 100.0;
            }
            if (v < 0.0) v = 0.0;
            if (v > 255.0) v = 255.0;
            rgb[i] = (int)(v + 0.5);
        }
        *out = video_make_color((uint8_t)rgb[0], (uint8_t)rgb[1], (uint8_t)rgb[2]);
        return true;
    }

    bool is_hsl = (len >= 5 && strncasecmp(start, "hsl(", 4) == 0);
    bool is_hsla = (len >= 6 && strncasecmp(start, "hsla(", 5) == 0);
    if ((is_hsl || is_hsla) && end[-1] == ')')
    {
        const char *args_start = start + (is_hsla ? 5 : 4);
        const char *args_end = end - 1;
        const char *parts[4] = {0};
        const char *part_ends[4] = {0};
        size_t count = 0;
        const char *seg_start = args_start;
        int depth = 0;
        for (const char *scan = args_start; scan < args_end; ++scan)
        {
            char c = *scan;
            if (c == '(')
            {
                ++depth;
                continue;
            }
            if (c == ')' && depth > 0)
            {
                --depth;
                continue;
            }
            if (c == ',' && depth == 0)
            {
                if (count < 4)
                {
                    parts[count] = seg_start;
                    part_ends[count] = scan;
                    ++count;
                }
                seg_start = scan + 1;
            }
        }
        if (count < 4)
        {
            parts[count] = seg_start;
            part_ends[count] = args_end;
            ++count;
        }
        if (count >= 3)
        {
            double h = 0.0;
            double s = 0.0;
            double l = 0.0;
            if (!css_parse_hsl_component(parts[0], part_ends[0], false, &h) ||
                !css_parse_hsl_component(parts[1], part_ends[1], true, &s) ||
                !css_parse_hsl_component(parts[2], part_ends[2], true, &l))
            {
                return false;
            }
            if (s < 0.0) s = 0.0;
            if (s > 100.0) s = 100.0;
            if (l < 0.0) l = 0.0;
            if (l > 100.0) l = 100.0;
            s /= 100.0;
            l /= 100.0;
            uint8_t r = 0;
            uint8_t g = 0;
            uint8_t b = 0;
            css_hsl_to_rgb(h, s, l, &r, &g, &b);
            *out = video_make_color(r, g, b);
            return true;
        }
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

    css_calc_value_t calc = {0};
    if (!css_parse_calc_value(start, end, &calc))
    {
        return false;
    }
    if (calc.unit == CSS_UNIT_NONE && calc.value_milli != 0)
    {
        return false;
    }

    out->valid = true;
    out->is_auto = false;
    out->value_milli = calc.value_milli;
    out->unit = calc.unit;
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
