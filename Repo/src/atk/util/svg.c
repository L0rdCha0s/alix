#include "atk/util/svg.h"

#ifdef SVG_HOST_BUILD
#include <stdlib.h>
#include <string.h>
#else
#include "heap.h"
#include "libc.h"
#endif

#define SVG_FIXED_SHIFT 16
#define SVG_FIXED_ONE (1 << SVG_FIXED_SHIFT)

typedef int32_t svg_fixed_t;

typedef struct
{
    int x;
    int y;
} svg_point_t;

typedef struct
{
    video_color_t *pixels;
    int width;
    int height;
    int stride_bytes;
} svg_canvas_t;

typedef struct
{
    svg_fixed_t view_x;
    svg_fixed_t view_y;
    svg_fixed_t view_w;
    svg_fixed_t view_h;
    svg_fixed_t scale_x;
    svg_fixed_t scale_y;
} svg_view_t;

typedef struct
{
    bool fill_none;
    bool stroke_none;
    video_color_t fill;
    video_color_t stroke;
    int stroke_width;
    uint8_t opacity;
    uint8_t fill_opacity;
    uint8_t stroke_opacity;
} svg_paint_t;

typedef struct
{
    svg_point_t *points;
    size_t count;
    size_t capacity;
} svg_point_list_t;

static const char *g_svg_error = "ok";

static void svg_set_error(const char *msg)
{
    g_svg_error = msg ? msg : "svg error";
}

const char *svg_last_error(void)
{
    return g_svg_error;
}

static inline bool svg_is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static inline bool svg_is_alpha(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static inline bool svg_is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static inline bool svg_is_name_char(char c)
{
    return svg_is_alpha(c) || svg_is_digit(c) || c == '-' || c == ':' || c == '_';
}

static inline char svg_tolower(char c)
{
    if (c >= 'A' && c <= 'Z')
    {
        return (char)(c + 32);
    }
    return c;
}

static int svg_strncasecmp(const char *a, const char *b, size_t n)
{
    if (!a || !b) return -1;
    for (size_t i = 0; i < n; ++i)
    {
        char ca = svg_tolower(a[i]);
        char cb = svg_tolower(b[i]);
        if (ca != cb)
        {
            return (int)(unsigned char)ca - (int)(unsigned char)cb;
        }
        if (ca == '\0')
        {
            return 0;
        }
    }
    return 0;
}

static const char *svg_skip_ws(const char *p, const char *end)
{
    while (p < end && svg_is_space(*p))
    {
        ++p;
    }
    return p;
}

static const char *svg_skip_delim(const char *p, const char *end)
{
    while (p < end && (svg_is_space(*p) || *p == ','))
    {
        ++p;
    }
    return p;
}

static bool svg_parse_fixed_span(const char **cursor, const char *end, svg_fixed_t *out)
{
    if (!cursor || !*cursor || !out)
    {
        return false;
    }

    const char *p = svg_skip_delim(*cursor, end);
    if (p >= end)
    {
        return false;
    }

    int sign = 1;
    if (*p == '-')
    {
        sign = -1;
        ++p;
    }
    else if (*p == '+')
    {
        ++p;
    }

    uint64_t int_part = 0;
    uint64_t frac_part = 0;
    uint64_t frac_scale = 1;
    bool has_digit = false;

    while (p < end && svg_is_digit(*p))
    {
        has_digit = true;
        int_part = int_part * 10u + (uint64_t)(*p - '0');
        ++p;
    }

    if (p < end && *p == '.')
    {
        ++p;
        while (p < end && svg_is_digit(*p))
        {
            has_digit = true;
            if (frac_scale < 1000000u)
            {
                frac_part = frac_part * 10u + (uint64_t)(*p - '0');
                frac_scale *= 10u;
            }
            ++p;
        }
    }

    if (!has_digit)
    {
        return false;
    }

    int64_t fixed = (int64_t)int_part << SVG_FIXED_SHIFT;
    if (frac_part && frac_scale > 1u)
    {
        fixed += (int64_t)((frac_part << SVG_FIXED_SHIFT) / frac_scale);
    }
    fixed *= (int64_t)sign;

    if (fixed > INT32_MAX) fixed = INT32_MAX;
    if (fixed < INT32_MIN) fixed = INT32_MIN;

    *out = (svg_fixed_t)fixed;
    *cursor = p;
    return true;
}

static int svg_fixed_to_int_round(svg_fixed_t value)
{
    int64_t v = (int64_t)value;
    if (v >= 0)
    {
        return (int)((v + (SVG_FIXED_ONE / 2)) >> SVG_FIXED_SHIFT);
    }
    return (int)((v - (SVG_FIXED_ONE / 2)) >> SVG_FIXED_SHIFT);
}

static video_color_t svg_pack_rgba(uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
    return ((video_color_t)a << 24) | ((video_color_t)r << 16) | ((video_color_t)g << 8) | (video_color_t)b;
}

static bool svg_hex_digit(char c, uint8_t *out)
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
        *out = (uint8_t)(10 + (c - 'a'));
        return true;
    }
    if (c >= 'A' && c <= 'F')
    {
        *out = (uint8_t)(10 + (c - 'A'));
        return true;
    }
    return false;
}

static bool svg_parse_rgb_component(const char **cursor, const char *end, uint8_t *out)
{
    svg_fixed_t value = 0;
    if (!svg_parse_fixed_span(cursor, end, &value))
    {
        return false;
    }

    int v = svg_fixed_to_int_round(value);
    const char *p = *cursor;
    if (p < end && *p == '%')
    {
        ++p;
        if (v < 0) v = 0;
        if (v > 100) v = 100;
        v = (v * 255 + 50) / 100;
        *cursor = p;
    }

    if (v < 0) v = 0;
    if (v > 255) v = 255;
    *out = (uint8_t)v;
    return true;
}

static bool svg_parse_alpha_component(const char **cursor, const char *end, uint8_t *out)
{
    svg_fixed_t value = 0;
    if (!svg_parse_fixed_span(cursor, end, &value))
    {
        return false;
    }

    const char *p = *cursor;
    if (p < end && *p == '%')
    {
        ++p;
        int v = svg_fixed_to_int_round(value);
        if (v < 0) v = 0;
        if (v > 100) v = 100;
        *out = (uint8_t)((v * 255 + 50) / 100);
        *cursor = p;
        return true;
    }

    int64_t v = value;
    if (v < 0) v = 0;
    if (v > SVG_FIXED_ONE) v = SVG_FIXED_ONE;
    *out = (uint8_t)((v * 255 + (SVG_FIXED_ONE / 2)) >> SVG_FIXED_SHIFT);
    return true;
}

static bool svg_parse_color(const char *start, const char *end, video_color_t *out_color, bool *out_none)
{
    if (!start || !end || !out_color || !out_none)
    {
        return false;
    }

    const char *p = svg_skip_ws(start, end);
    if (p >= end)
    {
        return false;
    }

    size_t len = (size_t)(end - p);
    while (len > 0 && svg_is_space(p[len - 1]))
    {
        --len;
    }

    if (len == 0)
    {
        return false;
    }

    if (len == 4 && svg_strncasecmp(p, "none", 4) == 0)
    {
        *out_none = true;
        *out_color = 0;
        return true;
    }

    if (len == 11 && svg_strncasecmp(p, "transparent", 11) == 0)
    {
        *out_none = false;
        *out_color = svg_pack_rgba(0, 0, 0, 0);
        return true;
    }

    if (*p == '#')
    {
        p++;
        len--;
        uint8_t r = 0, g = 0, b = 0, a = 255;
        if (len == 3)
        {
            uint8_t hr = 0, hg = 0, hb = 0;
            if (!svg_hex_digit(p[0], &hr) || !svg_hex_digit(p[1], &hg) || !svg_hex_digit(p[2], &hb))
            {
                return false;
            }
            r = (uint8_t)(hr * 17u);
            g = (uint8_t)(hg * 17u);
            b = (uint8_t)(hb * 17u);
        }
        else if (len == 6 || len == 8)
        {
            uint8_t hr = 0, hg = 0, hb = 0;
            uint8_t hr2 = 0, hg2 = 0, hb2 = 0;
            if (!svg_hex_digit(p[0], &hr) || !svg_hex_digit(p[1], &hr2) ||
                !svg_hex_digit(p[2], &hg) || !svg_hex_digit(p[3], &hg2) ||
                !svg_hex_digit(p[4], &hb) || !svg_hex_digit(p[5], &hb2))
            {
                return false;
            }
            r = (uint8_t)((hr << 4) | hr2);
            g = (uint8_t)((hg << 4) | hg2);
            b = (uint8_t)((hb << 4) | hb2);
            if (len == 8)
            {
                uint8_t ha = 0, ha2 = 0;
                if (!svg_hex_digit(p[6], &ha) || !svg_hex_digit(p[7], &ha2))
                {
                    return false;
                }
                a = (uint8_t)((ha << 4) | ha2);
            }
        }
        else
        {
            return false;
        }

        *out_none = false;
        *out_color = svg_pack_rgba(r, g, b, a);
        return true;
    }

    if (len >= 4 && svg_strncasecmp(p, "rgb(", 4) == 0)
    {
        const char *cursor = p + 4;
        const char *stop = p + len;
        uint8_t r = 0, g = 0, b = 0;
        if (!svg_parse_rgb_component(&cursor, stop, &r) ||
            !svg_parse_rgb_component(&cursor, stop, &g) ||
            !svg_parse_rgb_component(&cursor, stop, &b))
        {
            return false;
        }
        *out_none = false;
        *out_color = svg_pack_rgba(r, g, b, 255);
        return true;
    }

    if (len >= 5 && svg_strncasecmp(p, "rgba(", 5) == 0)
    {
        const char *cursor = p + 5;
        const char *stop = p + len;
        uint8_t r = 0, g = 0, b = 0, a = 255;
        if (!svg_parse_rgb_component(&cursor, stop, &r) ||
            !svg_parse_rgb_component(&cursor, stop, &g) ||
            !svg_parse_rgb_component(&cursor, stop, &b) ||
            !svg_parse_alpha_component(&cursor, stop, &a))
        {
            return false;
        }
        *out_none = false;
        *out_color = svg_pack_rgba(r, g, b, a);
        return true;
    }

    if (len == 5 && svg_strncasecmp(p, "black", 5) == 0)
    {
        *out_none = false;
        *out_color = svg_pack_rgba(0, 0, 0, 255);
        return true;
    }
    if (len == 5 && svg_strncasecmp(p, "white", 5) == 0)
    {
        *out_none = false;
        *out_color = svg_pack_rgba(255, 255, 255, 255);
        return true;
    }
    if (len == 3 && svg_strncasecmp(p, "red", 3) == 0)
    {
        *out_none = false;
        *out_color = svg_pack_rgba(255, 0, 0, 255);
        return true;
    }
    if (len == 5 && svg_strncasecmp(p, "green", 5) == 0)
    {
        *out_none = false;
        *out_color = svg_pack_rgba(0, 128, 0, 255);
        return true;
    }
    if (len == 4 && svg_strncasecmp(p, "blue", 4) == 0)
    {
        *out_none = false;
        *out_color = svg_pack_rgba(0, 0, 255, 255);
        return true;
    }
    if (len == 4 && svg_strncasecmp(p, "gray", 4) == 0)
    {
        *out_none = false;
        *out_color = svg_pack_rgba(128, 128, 128, 255);
        return true;
    }
    if (len == 4 && svg_strncasecmp(p, "grey", 4) == 0)
    {
        *out_none = false;
        *out_color = svg_pack_rgba(128, 128, 128, 255);
        return true;
    }
    if (len == 6 && svg_strncasecmp(p, "yellow", 6) == 0)
    {
        *out_none = false;
        *out_color = svg_pack_rgba(255, 255, 0, 255);
        return true;
    }
    if (len == 4 && svg_strncasecmp(p, "cyan", 4) == 0)
    {
        *out_none = false;
        *out_color = svg_pack_rgba(0, 255, 255, 255);
        return true;
    }
    if (len == 7 && svg_strncasecmp(p, "magenta", 7) == 0)
    {
        *out_none = false;
        *out_color = svg_pack_rgba(255, 0, 255, 255);
        return true;
    }

    return false;
}

static uint8_t svg_parse_opacity(const char *start, const char *end, uint8_t fallback)
{
    svg_fixed_t value = 0;
    const char *cursor = start;
    if (!svg_parse_fixed_span(&cursor, end, &value))
    {
        return fallback;
    }

    cursor = svg_skip_ws(cursor, end);
    if (cursor < end && *cursor == '%')
    {
        int v = svg_fixed_to_int_round(value);
        if (v < 0) v = 0;
        if (v > 100) v = 100;
        return (uint8_t)((v * 255 + 50) / 100);
    }

    int64_t v = value;
    if (v < 0) v = 0;
    if (v > SVG_FIXED_ONE) v = SVG_FIXED_ONE;
    return (uint8_t)((v * 255 + (SVG_FIXED_ONE / 2)) >> SVG_FIXED_SHIFT);
}

static bool svg_attr_value(const char *start, const char *end, const char *name,
                           const char **value_start, const char **value_end)
{
    if (!start || !end || !name || !value_start || !value_end)
    {
        return false;
    }

    size_t name_len = strlen(name);
    const char *p = start;
    while (p < end)
    {
        p = svg_skip_ws(p, end);
        if (p >= end)
        {
            break;
        }

        const char *attr_start = p;
        while (p < end && svg_is_name_char(*p))
        {
            ++p;
        }
        if (p == attr_start)
        {
            ++p;
            continue;
        }

        size_t attr_len = (size_t)(p - attr_start);
        p = svg_skip_ws(p, end);

        const char *val_start = NULL;
        const char *val_end = NULL;
        if (p < end && *p == '=')
        {
            ++p;
            p = svg_skip_ws(p, end);
            if (p < end && (*p == '\"' || *p == '\''))
            {
                char quote = *p++;
                val_start = p;
                while (p < end && *p != quote)
                {
                    ++p;
                }
                val_end = p;
                if (p < end) ++p;
            }
            else
            {
                val_start = p;
                while (p < end && !svg_is_space(*p) && *p != '>' && *p != '/')
                {
                    ++p;
                }
                val_end = p;
            }
        }

        if (attr_len == name_len && svg_strncasecmp(attr_start, name, name_len) == 0 && val_start && val_end)
        {
            *value_start = val_start;
            *value_end = val_end;
            return true;
        }
    }

    return false;
}

static bool svg_style_value(const char *start, const char *end, const char *name,
                            const char **value_start, const char **value_end)
{
    if (!start || !end || !name || !value_start || !value_end)
    {
        return false;
    }

    size_t name_len = strlen(name);
    const char *p = start;
    while (p < end)
    {
        while (p < end && (svg_is_space(*p) || *p == ';'))
        {
            ++p;
        }
        if (p >= end)
        {
            break;
        }

        const char *prop_start = p;
        while (p < end && svg_is_name_char(*p))
        {
            ++p;
        }
        size_t prop_len = (size_t)(p - prop_start);
        while (p < end && svg_is_space(*p))
        {
            ++p;
        }
        if (p >= end || *p != ':')
        {
            while (p < end && *p != ';')
            {
                ++p;
            }
            continue;
        }
        ++p;
        const char *val_start = p = svg_skip_ws(p, end);
        while (p < end && *p != ';')
        {
            ++p;
        }
        const char *val_end = p;

        if (prop_len == name_len && svg_strncasecmp(prop_start, name, name_len) == 0)
        {
            *value_start = val_start;
            *value_end = val_end;
            return true;
        }
    }

    return false;
}

static const char *svg_find_tag_end(const char *start, const char *end)
{
    if (!start || !end || start >= end)
    {
        return NULL;
    }

    bool in_quote = false;
    char quote = '\0';
    for (const char *p = start; p < end; ++p)
    {
        if (in_quote)
        {
            if (*p == quote)
            {
                in_quote = false;
            }
            continue;
        }
        if (*p == '\"' || *p == '\'')
        {
            in_quote = true;
            quote = *p;
            continue;
        }
        if (*p == '>')
        {
            return p;
        }
    }

    return NULL;
}

static bool svg_tag_name_matches(const char *name, size_t len, const char *target)
{
    if (!name || !target)
    {
        return false;
    }

    const char *segment = name;
    size_t seg_len = len;
    for (size_t i = 0; i < len; ++i)
    {
        if (name[i] == ':')
        {
            segment = name + i + 1;
            seg_len = len - i - 1;
        }
    }

    size_t target_len = strlen(target);
    if (seg_len != target_len)
    {
        return false;
    }

    return svg_strncasecmp(segment, target, seg_len) == 0;
}

static int svg_map_x(const svg_view_t *view, svg_fixed_t x)
{
    int64_t adj = (int64_t)x - (int64_t)view->view_x;
    int64_t scaled = adj * (int64_t)view->scale_x;
    int64_t fixed = scaled >> SVG_FIXED_SHIFT;
    return (int)((fixed + (SVG_FIXED_ONE / 2)) >> SVG_FIXED_SHIFT);
}

static int svg_map_y(const svg_view_t *view, svg_fixed_t y)
{
    int64_t adj = (int64_t)y - (int64_t)view->view_y;
    int64_t scaled = adj * (int64_t)view->scale_y;
    int64_t fixed = scaled >> SVG_FIXED_SHIFT;
    return (int)((fixed + (SVG_FIXED_ONE / 2)) >> SVG_FIXED_SHIFT);
}

static int svg_map_len(const svg_view_t *view, svg_fixed_t value, bool use_x)
{
    int64_t scaled = (int64_t)value * (int64_t)(use_x ? view->scale_x : view->scale_y);
    int64_t fixed = scaled >> SVG_FIXED_SHIFT;
    int out = (int)((fixed + (SVG_FIXED_ONE / 2)) >> SVG_FIXED_SHIFT);
    if (out < 0) out = -out;
    return out;
}

static void svg_point_list_init(svg_point_list_t *list)
{
    if (!list)
    {
        return;
    }
    list->points = NULL;
    list->count = 0;
    list->capacity = 0;
}

static void svg_point_list_reset(svg_point_list_t *list)
{
    if (!list)
    {
        return;
    }
    list->count = 0;
}

static void svg_point_list_destroy(svg_point_list_t *list)
{
    if (!list)
    {
        return;
    }
    free(list->points);
    list->points = NULL;
    list->count = 0;
    list->capacity = 0;
}

static bool svg_point_list_push(svg_point_list_t *list, int x, int y)
{
    if (!list)
    {
        return false;
    }
    if (list->count == list->capacity)
    {
        size_t new_cap = list->capacity ? list->capacity * 2u : 8u;
        svg_point_t *next = (svg_point_t *)realloc(list->points, new_cap * sizeof(svg_point_t));
        if (!next)
        {
            return false;
        }
        list->points = next;
        list->capacity = new_cap;
    }
    list->points[list->count++] = (svg_point_t){ x, y };
    return true;
}

static void svg_paint_init(svg_paint_t *paint)
{
    if (!paint)
    {
        return;
    }
    paint->fill_none = false;
    paint->stroke_none = true;
    paint->fill = svg_pack_rgba(0, 0, 0, 255);
    paint->stroke = svg_pack_rgba(0, 0, 0, 255);
    paint->stroke_width = 1;
    paint->opacity = 255;
    paint->fill_opacity = 255;
    paint->stroke_opacity = 255;
}

static void svg_paint_apply_opacity(svg_paint_t *paint)
{
    if (!paint)
    {
        return;
    }

    if (!paint->fill_none)
    {
        uint8_t base = (uint8_t)(paint->fill >> 24);
        uint8_t combined = (uint8_t)((uint16_t)base * (uint16_t)paint->opacity / 255u);
        combined = (uint8_t)((uint16_t)combined * (uint16_t)paint->fill_opacity / 255u);
        paint->fill = (paint->fill & 0x00FFFFFFu) | ((video_color_t)combined << 24);
    }

    if (!paint->stroke_none)
    {
        uint8_t base = (uint8_t)(paint->stroke >> 24);
        uint8_t combined = (uint8_t)((uint16_t)base * (uint16_t)paint->opacity / 255u);
        combined = (uint8_t)((uint16_t)combined * (uint16_t)paint->stroke_opacity / 255u);
        paint->stroke = (paint->stroke & 0x00FFFFFFu) | ((video_color_t)combined << 24);
    }
}

static void svg_parse_paint(svg_paint_t *paint,
                            const char *attr_start,
                            const char *attr_end,
                            const svg_view_t *view)
{
    if (!paint || !attr_start || !attr_end)
    {
        return;
    }

    svg_paint_init(paint);

    const char *value_start = NULL;
    const char *value_end = NULL;

    if (svg_attr_value(attr_start, attr_end, "fill", &value_start, &value_end))
    {
        bool none = false;
        video_color_t color = 0;
        if (svg_parse_color(value_start, value_end, &color, &none))
        {
            paint->fill_none = none;
            if (!none)
            {
                paint->fill = color;
            }
        }
    }

    if (svg_attr_value(attr_start, attr_end, "stroke", &value_start, &value_end))
    {
        bool none = false;
        video_color_t color = 0;
        if (svg_parse_color(value_start, value_end, &color, &none))
        {
            paint->stroke_none = none;
            if (!none)
            {
                paint->stroke = color;
            }
        }
    }

    if (svg_attr_value(attr_start, attr_end, "stroke-width", &value_start, &value_end))
    {
        svg_fixed_t width = 0;
        const char *cursor = value_start;
        if (svg_parse_fixed_span(&cursor, value_end, &width) && view)
        {
            int px = svg_map_len(view, width, true);
            if (px < 1) px = 1;
            paint->stroke_width = px;
        }
    }

    if (svg_attr_value(attr_start, attr_end, "opacity", &value_start, &value_end))
    {
        paint->opacity = svg_parse_opacity(value_start, value_end, paint->opacity);
    }

    if (svg_attr_value(attr_start, attr_end, "fill-opacity", &value_start, &value_end))
    {
        paint->fill_opacity = svg_parse_opacity(value_start, value_end, paint->fill_opacity);
    }

    if (svg_attr_value(attr_start, attr_end, "stroke-opacity", &value_start, &value_end))
    {
        paint->stroke_opacity = svg_parse_opacity(value_start, value_end, paint->stroke_opacity);
    }

    if (svg_attr_value(attr_start, attr_end, "style", &value_start, &value_end))
    {
        const char *style = value_start;
        const char *style_end = value_end;
        if (svg_style_value(style, style_end, "fill", &value_start, &value_end))
        {
            bool none = false;
            video_color_t color = 0;
            if (svg_parse_color(value_start, value_end, &color, &none))
            {
                paint->fill_none = none;
                if (!none)
                {
                    paint->fill = color;
                }
            }
        }
        if (svg_style_value(style, style_end, "stroke", &value_start, &value_end))
        {
            bool none = false;
            video_color_t color = 0;
            if (svg_parse_color(value_start, value_end, &color, &none))
            {
                paint->stroke_none = none;
                if (!none)
                {
                    paint->stroke = color;
                }
            }
        }
        if (svg_style_value(style, style_end, "stroke-width", &value_start, &value_end))
        {
            svg_fixed_t width = 0;
            const char *cursor = value_start;
            if (svg_parse_fixed_span(&cursor, value_end, &width) && view)
            {
                int px = svg_map_len(view, width, true);
                if (px < 1) px = 1;
                paint->stroke_width = px;
            }
        }
        if (svg_style_value(style, style_end, "opacity", &value_start, &value_end))
        {
            paint->opacity = svg_parse_opacity(value_start, value_end, paint->opacity);
        }
        if (svg_style_value(style, style_end, "fill-opacity", &value_start, &value_end))
        {
            paint->fill_opacity = svg_parse_opacity(value_start, value_end, paint->fill_opacity);
        }
        if (svg_style_value(style, style_end, "stroke-opacity", &value_start, &value_end))
        {
            paint->stroke_opacity = svg_parse_opacity(value_start, value_end, paint->stroke_opacity);
        }
    }

    svg_paint_apply_opacity(paint);
}

static void svg_blend_pixel(video_color_t *dst, video_color_t src)
{
    if (!dst)
    {
        return;
    }

    uint8_t sa = (uint8_t)(src >> 24);
    if (sa == 0)
    {
        return;
    }
    if (sa == 255)
    {
        *dst = src;
        return;
    }

    video_color_t dst_px = *dst;
    uint8_t da = (uint8_t)(dst_px >> 24);

    uint8_t sr = (uint8_t)(src >> 16);
    uint8_t sg = (uint8_t)(src >> 8);
    uint8_t sb = (uint8_t)(src);

    uint8_t dr = (uint8_t)(dst_px >> 16);
    uint8_t dg = (uint8_t)(dst_px >> 8);
    uint8_t db = (uint8_t)(dst_px);

    uint16_t inv_sa = (uint16_t)(255 - sa);
    uint16_t out_a = (uint16_t)sa + (uint16_t)((da * inv_sa + 127) / 255u);
    if (out_a == 0)
    {
        *dst = 0;
        return;
    }

    uint32_t src_term = (uint32_t)sa;
    uint32_t dst_term = (uint32_t)da * (uint32_t)inv_sa / 255u;

    uint32_t out_r = ((uint32_t)sr * src_term + (uint32_t)dr * dst_term + (out_a / 2u)) / out_a;
    uint32_t out_g = ((uint32_t)sg * src_term + (uint32_t)dg * dst_term + (out_a / 2u)) / out_a;
    uint32_t out_b = ((uint32_t)sb * src_term + (uint32_t)db * dst_term + (out_a / 2u)) / out_a;

    *dst = svg_pack_rgba((uint8_t)out_r, (uint8_t)out_g, (uint8_t)out_b, (uint8_t)out_a);
}

static bool svg_clip_rect(const svg_canvas_t *canvas, int *x, int *y, int *w, int *h)
{
    if (!canvas || !x || !y || !w || !h)
    {
        return false;
    }

    int x0 = *x;
    int y0 = *y;
    int x1 = x0 + *w;
    int y1 = y0 + *h;

    if (x1 <= 0 || y1 <= 0 || x0 >= canvas->width || y0 >= canvas->height)
    {
        return false;
    }

    if (x0 < 0) x0 = 0;
    if (y0 < 0) y0 = 0;
    if (x1 > canvas->width) x1 = canvas->width;
    if (y1 > canvas->height) y1 = canvas->height;

    int cw = x1 - x0;
    int ch = y1 - y0;
    if (cw <= 0 || ch <= 0)
    {
        return false;
    }

    *x = x0;
    *y = y0;
    *w = cw;
    *h = ch;
    return true;
}

static void svg_fill_rect(svg_canvas_t *canvas, int x, int y, int w, int h, video_color_t color)
{
    if (!canvas || w <= 0 || h <= 0)
    {
        return;
    }

    uint8_t a = (uint8_t)(color >> 24);
    if (a == 0)
    {
        return;
    }

    if (!svg_clip_rect(canvas, &x, &y, &w, &h))
    {
        return;
    }

    for (int row = 0; row < h; ++row)
    {
        video_color_t *dst = (video_color_t *)((uint8_t *)canvas->pixels +
                                              (size_t)(y + row) * (size_t)canvas->stride_bytes) + x;
        if (a == 255)
        {
            for (int col = 0; col < w; ++col)
            {
                dst[col] = color;
            }
        }
        else
        {
            for (int col = 0; col < w; ++col)
            {
                svg_blend_pixel(&dst[col], color);
            }
        }
    }
}

static void svg_draw_rect_outline(svg_canvas_t *canvas, int x, int y, int w, int h, int thickness, video_color_t color)
{
    if (!canvas || w <= 0 || h <= 0 || thickness <= 0)
    {
        return;
    }

    if (thickness * 2 > w)
    {
        thickness = w / 2;
    }
    if (thickness * 2 > h)
    {
        thickness = h / 2;
    }
    if (thickness <= 0)
    {
        return;
    }

    svg_fill_rect(canvas, x, y, w, thickness, color);
    svg_fill_rect(canvas, x, y + h - thickness, w, thickness, color);
    svg_fill_rect(canvas, x, y + thickness, thickness, h - thickness * 2, color);
    svg_fill_rect(canvas, x + w - thickness, y + thickness, thickness, h - thickness * 2, color);
}

static void svg_draw_circle(svg_canvas_t *canvas, int cx, int cy, int r, video_color_t color)
{
    if (!canvas || r <= 0)
    {
        return;
    }

    int x0 = cx - r;
    int y0 = cy - r;
    int w = r * 2 + 1;
    int h = r * 2 + 1;

    if (!svg_clip_rect(canvas, &x0, &y0, &w, &h))
    {
        return;
    }

    int rr = r * r;
    uint8_t a = (uint8_t)(color >> 24);
    if (a == 0)
    {
        return;
    }

    for (int y = y0; y < y0 + h; ++y)
    {
        video_color_t *row = (video_color_t *)((uint8_t *)canvas->pixels +
                                              (size_t)y * (size_t)canvas->stride_bytes);
        int dy = y - cy;
        for (int x = x0; x < x0 + w; ++x)
        {
            int dx = x - cx;
            int dist2 = dx * dx + dy * dy;
            if (dist2 <= rr)
            {
                if (a == 255)
                {
                    row[x] = color;
                }
                else
                {
                    svg_blend_pixel(&row[x], color);
                }
            }
        }
    }
}

static void svg_draw_circle_stroke(svg_canvas_t *canvas, int cx, int cy, int r, int stroke_w, video_color_t color)
{
    if (!canvas || r <= 0 || stroke_w <= 0)
    {
        return;
    }

    int outer = r;
    int inner = r - stroke_w;
    if (inner < 0) inner = 0;

    int x0 = cx - outer;
    int y0 = cy - outer;
    int w = outer * 2 + 1;
    int h = outer * 2 + 1;

    if (!svg_clip_rect(canvas, &x0, &y0, &w, &h))
    {
        return;
    }

    int outer2 = outer * outer;
    int inner2 = inner * inner;
    uint8_t a = (uint8_t)(color >> 24);
    if (a == 0)
    {
        return;
    }

    for (int y = y0; y < y0 + h; ++y)
    {
        video_color_t *row = (video_color_t *)((uint8_t *)canvas->pixels +
                                              (size_t)y * (size_t)canvas->stride_bytes);
        int dy = y - cy;
        for (int x = x0; x < x0 + w; ++x)
        {
            int dx = x - cx;
            int dist2 = dx * dx + dy * dy;
            if (dist2 <= outer2 && dist2 >= inner2)
            {
                if (a == 255)
                {
                    row[x] = color;
                }
                else
                {
                    svg_blend_pixel(&row[x], color);
                }
            }
        }
    }
}

static void svg_draw_line(svg_canvas_t *canvas, int x0, int y0, int x1, int y1, int thickness, video_color_t color)
{
    if (!canvas || thickness <= 0)
    {
        return;
    }

    int dx = (x0 < x1) ? (x1 - x0) : (x0 - x1);
    int sx = (x0 < x1) ? 1 : -1;
    int dy = (y0 < y1) ? (y0 - y1) : (y1 - y0);
    int sy = (y0 < y1) ? 1 : -1;
    int err = dx + dy;
    int half = thickness / 2;

    for (;;)
    {
        svg_fill_rect(canvas, x0 - half, y0 - half, thickness, thickness, color);
        if (x0 == x1 && y0 == y1)
        {
            break;
        }
        int e2 = err * 2;
        if (e2 >= dy)
        {
            err += dy;
            x0 += sx;
        }
        if (e2 <= dx)
        {
            err += dx;
            y0 += sy;
        }
    }
}

static void svg_draw_polyline(svg_canvas_t *canvas, const svg_point_t *pts, size_t count,
                              int thickness, video_color_t color, bool closed)
{
    if (!canvas || !pts || count < 2)
    {
        return;
    }

    for (size_t i = 0; i + 1 < count; ++i)
    {
        svg_draw_line(canvas, pts[i].x, pts[i].y, pts[i + 1].x, pts[i + 1].y, thickness, color);
    }
    if (closed)
    {
        svg_draw_line(canvas, pts[count - 1].x, pts[count - 1].y, pts[0].x, pts[0].y, thickness, color);
    }
}

static void svg_fill_polygon(svg_canvas_t *canvas, const svg_point_t *pts, size_t count, video_color_t color)
{
    if (!canvas || !pts || count < 3)
    {
        return;
    }

    int min_y = pts[0].y;
    int max_y = pts[0].y;
    for (size_t i = 1; i < count; ++i)
    {
        if (pts[i].y < min_y) min_y = pts[i].y;
        if (pts[i].y > max_y) max_y = pts[i].y;
    }

    if (min_y < 0) min_y = 0;
    if (max_y >= canvas->height) max_y = canvas->height - 1;
    if (min_y > max_y)
    {
        return;
    }

    int *intersections = (int *)malloc(count * sizeof(int));
    if (!intersections)
    {
        return;
    }

    uint8_t a = (uint8_t)(color >> 24);
    for (int y = min_y; y <= max_y; ++y)
    {
        size_t nodes = 0;
        for (size_t i = 0, j = count - 1; i < count; j = i++)
        {
            int y0 = pts[i].y;
            int y1 = pts[j].y;
            int x0 = pts[i].x;
            int x1 = pts[j].x;

            bool intersect = ((y0 < y && y1 >= y) || (y1 < y && y0 >= y));
            if (intersect && (y1 != y0))
            {
                int64_t num = (int64_t)(y - y0) * (int64_t)(x1 - x0);
                int x = x0 + (int)(num / (int64_t)(y1 - y0));
                intersections[nodes++] = x;
            }
        }

        if (nodes < 2)
        {
            continue;
        }

        for (size_t i = 1; i < nodes; ++i)
        {
            int key = intersections[i];
            size_t k = i;
            while (k > 0 && intersections[k - 1] > key)
            {
                intersections[k] = intersections[k - 1];
                --k;
            }
            intersections[k] = key;
        }

        for (size_t i = 0; i + 1 < nodes; i += 2)
        {
            int x_start = intersections[i];
            int x_end = intersections[i + 1];
            if (x_start > x_end)
            {
                int tmp = x_start;
                x_start = x_end;
                x_end = tmp;
            }

            if (x_end < 0 || x_start >= canvas->width)
            {
                continue;
            }
            if (x_start < 0) x_start = 0;
            if (x_end >= canvas->width) x_end = canvas->width - 1;

            video_color_t *row = (video_color_t *)((uint8_t *)canvas->pixels +
                                                  (size_t)y * (size_t)canvas->stride_bytes);
            if (a == 255)
            {
                for (int x = x_start; x <= x_end; ++x)
                {
                    row[x] = color;
                }
            }
            else
            {
                for (int x = x_start; x <= x_end; ++x)
                {
                    svg_blend_pixel(&row[x], color);
                }
            }
        }
    }

    free(intersections);
}

static bool svg_parse_points(const char *start, const char *end, const svg_view_t *view, svg_point_list_t *list)
{
    if (!start || !end || !view || !list)
    {
        return false;
    }

    const char *cursor = start;
    while (cursor < end)
    {
        svg_fixed_t fx = 0;
        svg_fixed_t fy = 0;
        if (!svg_parse_fixed_span(&cursor, end, &fx))
        {
            break;
        }
        if (!svg_parse_fixed_span(&cursor, end, &fy))
        {
            break;
        }

        int x = svg_map_x(view, fx);
        int y = svg_map_y(view, fy);
        if (!svg_point_list_push(list, x, y))
        {
            return false;
        }
    }

    return list->count > 0;
}

static void svg_render_path(svg_canvas_t *canvas, const svg_view_t *view,
                            const char *start, const char *end, const svg_paint_t *paint)
{
    if (!canvas || !view || !start || !end || !paint)
    {
        return;
    }

    svg_point_list_t list;
    svg_point_list_init(&list);

    svg_fixed_t cur_x = 0;
    svg_fixed_t cur_y = 0;
    svg_fixed_t sub_x = 0;
    svg_fixed_t sub_y = 0;
    bool have_subpath = false;
    bool closed = false;

    char cmd = 0;
    const char *p = start;
    while (p < end)
    {
        p = svg_skip_delim(p, end);
        if (p >= end)
        {
            break;
        }

        if (svg_is_alpha(*p))
        {
            cmd = *p++;
        }
        else if (!cmd)
        {
            ++p;
            continue;
        }

        switch (cmd)
        {
            case 'M':
            case 'm':
            {
                svg_fixed_t x = 0;
                svg_fixed_t y = 0;
                if (!svg_parse_fixed_span(&p, end, &x) || !svg_parse_fixed_span(&p, end, &y))
                {
                    goto cleanup;
                }
                if (cmd == 'm')
                {
                    x += cur_x;
                    y += cur_y;
                }
                if (list.count > 1)
                {
                    if (!paint->fill_none && closed)
                    {
                        svg_fill_polygon(canvas, list.points, list.count, paint->fill);
                    }
                    if (!paint->stroke_none)
                    {
                        svg_draw_polyline(canvas, list.points, list.count, paint->stroke_width, paint->stroke, closed);
                    }
                }
                svg_point_list_reset(&list);
                closed = false;
                cur_x = x;
                cur_y = y;
                sub_x = x;
                sub_y = y;
                have_subpath = true;
                svg_point_list_push(&list, svg_map_x(view, cur_x), svg_map_y(view, cur_y));
                cmd = (cmd == 'm') ? 'l' : 'L';
                break;
            }
            case 'L':
            case 'l':
            {
                svg_fixed_t x = 0;
                svg_fixed_t y = 0;
                if (!svg_parse_fixed_span(&p, end, &x) || !svg_parse_fixed_span(&p, end, &y))
                {
                    goto cleanup;
                }
                if (cmd == 'l')
                {
                    x += cur_x;
                    y += cur_y;
                }
                cur_x = x;
                cur_y = y;
                have_subpath = true;
                svg_point_list_push(&list, svg_map_x(view, cur_x), svg_map_y(view, cur_y));
                break;
            }
            case 'H':
            case 'h':
            {
                svg_fixed_t x = 0;
                if (!svg_parse_fixed_span(&p, end, &x))
                {
                    goto cleanup;
                }
                if (cmd == 'h')
                {
                    x += cur_x;
                }
                cur_x = x;
                have_subpath = true;
                svg_point_list_push(&list, svg_map_x(view, cur_x), svg_map_y(view, cur_y));
                break;
            }
            case 'V':
            case 'v':
            {
                svg_fixed_t y = 0;
                if (!svg_parse_fixed_span(&p, end, &y))
                {
                    goto cleanup;
                }
                if (cmd == 'v')
                {
                    y += cur_y;
                }
                cur_y = y;
                have_subpath = true;
                svg_point_list_push(&list, svg_map_x(view, cur_x), svg_map_y(view, cur_y));
                break;
            }
            case 'Z':
            case 'z':
            {
                closed = true;
                if (have_subpath && list.count > 1)
                {
                    if (!paint->fill_none)
                    {
                        svg_fill_polygon(canvas, list.points, list.count, paint->fill);
                    }
                    if (!paint->stroke_none)
                    {
                        svg_draw_polyline(canvas, list.points, list.count, paint->stroke_width, paint->stroke, true);
                    }
                }
                svg_point_list_reset(&list);
                cur_x = sub_x;
                cur_y = sub_y;
                cmd = 0;
                have_subpath = false;
                break;
            }
            default:
                goto cleanup;
        }
    }

    if (list.count > 1)
    {
        if (!paint->fill_none && closed)
        {
            svg_fill_polygon(canvas, list.points, list.count, paint->fill);
        }
        if (!paint->stroke_none)
        {
            svg_draw_polyline(canvas, list.points, list.count, paint->stroke_width, paint->stroke, closed);
        }
    }

cleanup:
    svg_point_list_destroy(&list);
}

static void svg_render_elements(svg_canvas_t *canvas, const svg_view_t *view, const char *text, const char *end)
{
    if (!canvas || !view || !text || !end)
    {
        return;
    }

    const char *p = text;
    while (p < end)
    {
        const char *tag = strchr(p, '<');
        if (!tag || tag >= end)
        {
            break;
        }
        const char *tag_end = svg_find_tag_end(tag, end);
        if (!tag_end)
        {
            break;
        }

        const char *name_start = tag + 1;
        if (name_start < end && (*name_start == '/' || *name_start == '!' || *name_start == '?'))
        {
            p = tag_end + 1;
            continue;
        }

        while (name_start < end && svg_is_space(*name_start))
        {
            ++name_start;
        }
        const char *name_end = name_start;
        while (name_end < end && svg_is_name_char(*name_end))
        {
            ++name_end;
        }
        if (name_end <= name_start)
        {
            p = tag_end + 1;
            continue;
        }

        size_t name_len = (size_t)(name_end - name_start);
        const char *attr_start = name_end;
        const char *attr_end = tag_end;

        svg_paint_t paint;

        if (svg_tag_name_matches(name_start, name_len, "rect"))
        {
            svg_parse_paint(&paint, attr_start, attr_end, view);
            svg_fixed_t fx = 0, fy = 0, fw = 0, fh = 0;
            const char *value_start = NULL;
            const char *value_end = NULL;
            if (svg_attr_value(attr_start, attr_end, "x", &value_start, &value_end))
            {
                const char *cursor = value_start;
                (void)svg_parse_fixed_span(&cursor, value_end, &fx);
            }
            if (svg_attr_value(attr_start, attr_end, "y", &value_start, &value_end))
            {
                const char *cursor = value_start;
                (void)svg_parse_fixed_span(&cursor, value_end, &fy);
            }
            if (svg_attr_value(attr_start, attr_end, "width", &value_start, &value_end))
            {
                const char *cursor = value_start;
                (void)svg_parse_fixed_span(&cursor, value_end, &fw);
            }
            if (svg_attr_value(attr_start, attr_end, "height", &value_start, &value_end))
            {
                const char *cursor = value_start;
                (void)svg_parse_fixed_span(&cursor, value_end, &fh);
            }

            int x = svg_map_x(view, fx);
            int y = svg_map_y(view, fy);
            int w = svg_map_len(view, fw, true);
            int h = svg_map_len(view, fh, false);
            if (w > 0 && h > 0)
            {
                if (!paint.fill_none)
                {
                    svg_fill_rect(canvas, x, y, w, h, paint.fill);
                }
                if (!paint.stroke_none && paint.stroke_width > 0)
                {
                    svg_draw_rect_outline(canvas, x, y, w, h, paint.stroke_width, paint.stroke);
                }
            }
        }
        else if (svg_tag_name_matches(name_start, name_len, "circle"))
        {
            svg_parse_paint(&paint, attr_start, attr_end, view);
            svg_fixed_t fcx = 0, fcy = 0, fr = 0;
            const char *value_start = NULL;
            const char *value_end = NULL;
            if (svg_attr_value(attr_start, attr_end, "cx", &value_start, &value_end))
            {
                const char *cursor = value_start;
                (void)svg_parse_fixed_span(&cursor, value_end, &fcx);
            }
            if (svg_attr_value(attr_start, attr_end, "cy", &value_start, &value_end))
            {
                const char *cursor = value_start;
                (void)svg_parse_fixed_span(&cursor, value_end, &fcy);
            }
            if (svg_attr_value(attr_start, attr_end, "r", &value_start, &value_end))
            {
                const char *cursor = value_start;
                (void)svg_parse_fixed_span(&cursor, value_end, &fr);
            }

            int cx = svg_map_x(view, fcx);
            int cy = svg_map_y(view, fcy);
            int r = svg_map_len(view, fr, true);
            if (r > 0)
            {
                if (!paint.fill_none)
                {
                    svg_draw_circle(canvas, cx, cy, r, paint.fill);
                }
                if (!paint.stroke_none && paint.stroke_width > 0)
                {
                    svg_draw_circle_stroke(canvas, cx, cy, r, paint.stroke_width, paint.stroke);
                }
            }
        }
        else if (svg_tag_name_matches(name_start, name_len, "line"))
        {
            svg_parse_paint(&paint, attr_start, attr_end, view);
            svg_fixed_t fx1 = 0, fy1 = 0, fx2 = 0, fy2 = 0;
            const char *value_start = NULL;
            const char *value_end = NULL;
            if (svg_attr_value(attr_start, attr_end, "x1", &value_start, &value_end))
            {
                const char *cursor = value_start;
                (void)svg_parse_fixed_span(&cursor, value_end, &fx1);
            }
            if (svg_attr_value(attr_start, attr_end, "y1", &value_start, &value_end))
            {
                const char *cursor = value_start;
                (void)svg_parse_fixed_span(&cursor, value_end, &fy1);
            }
            if (svg_attr_value(attr_start, attr_end, "x2", &value_start, &value_end))
            {
                const char *cursor = value_start;
                (void)svg_parse_fixed_span(&cursor, value_end, &fx2);
            }
            if (svg_attr_value(attr_start, attr_end, "y2", &value_start, &value_end))
            {
                const char *cursor = value_start;
                (void)svg_parse_fixed_span(&cursor, value_end, &fy2);
            }

            if (!paint.stroke_none && paint.stroke_width > 0)
            {
                int x1 = svg_map_x(view, fx1);
                int y1 = svg_map_y(view, fy1);
                int x2 = svg_map_x(view, fx2);
                int y2 = svg_map_y(view, fy2);
                svg_draw_line(canvas, x1, y1, x2, y2, paint.stroke_width, paint.stroke);
            }
        }
        else if (svg_tag_name_matches(name_start, name_len, "polyline"))
        {
            svg_parse_paint(&paint, attr_start, attr_end, view);
            const char *value_start = NULL;
            const char *value_end = NULL;
            if (svg_attr_value(attr_start, attr_end, "points", &value_start, &value_end))
            {
                svg_point_list_t list;
                svg_point_list_init(&list);
                if (svg_parse_points(value_start, value_end, view, &list))
                {
                    if (!paint.stroke_none && paint.stroke_width > 0)
                    {
                        svg_draw_polyline(canvas, list.points, list.count, paint.stroke_width, paint.stroke, false);
                    }
                }
                svg_point_list_destroy(&list);
            }
        }
        else if (svg_tag_name_matches(name_start, name_len, "polygon"))
        {
            svg_parse_paint(&paint, attr_start, attr_end, view);
            const char *value_start = NULL;
            const char *value_end = NULL;
            if (svg_attr_value(attr_start, attr_end, "points", &value_start, &value_end))
            {
                svg_point_list_t list;
                svg_point_list_init(&list);
                if (svg_parse_points(value_start, value_end, view, &list))
                {
                    if (!paint.fill_none)
                    {
                        svg_fill_polygon(canvas, list.points, list.count, paint.fill);
                    }
                    if (!paint.stroke_none && paint.stroke_width > 0)
                    {
                        svg_draw_polyline(canvas, list.points, list.count, paint.stroke_width, paint.stroke, true);
                    }
                }
                svg_point_list_destroy(&list);
            }
        }
        else if (svg_tag_name_matches(name_start, name_len, "path"))
        {
            svg_parse_paint(&paint, attr_start, attr_end, view);
            const char *value_start = NULL;
            const char *value_end = NULL;
            if (svg_attr_value(attr_start, attr_end, "d", &value_start, &value_end))
            {
                svg_render_path(canvas, view, value_start, value_end, &paint);
            }
        }

        p = tag_end + 1;
    }
}

int svg_decode_rgba32(const uint8_t *svg,
                      size_t len,
                      video_color_t **out_pixels,
                      int *out_w,
                      int *out_h,
                      int *out_stride_bytes)
{
    svg_set_error("invalid arguments");
    if (!svg || len == 0 || !out_pixels || !out_w || !out_h || !out_stride_bytes)
    {
        return -1;
    }

    char *text = (char *)malloc(len + 1);
    if (!text)
    {
        svg_set_error("out of memory");
        return -1;
    }
    memcpy(text, svg, len);
    text[len] = '\0';

    const char *doc_start = text;
    const char *doc_end = text + len;

    const char *svg_tag = NULL;
    for (const char *p = doc_start; p < doc_end; ++p)
    {
        if (*p == '<')
        {
            const char *name = p + 1;
            while (name < doc_end && svg_is_space(*name))
            {
                ++name;
            }
            const char *name_end = name;
            while (name_end < doc_end && svg_is_name_char(*name_end))
            {
                ++name_end;
            }
            size_t name_len = (size_t)(name_end - name);
            if (name_len > 0 && svg_tag_name_matches(name, name_len, "svg"))
            {
                svg_tag = p;
                break;
            }
        }
    }

    if (!svg_tag)
    {
        free(text);
        svg_set_error("svg tag not found");
        return -1;
    }

    const char *svg_tag_end = svg_find_tag_end(svg_tag, doc_end);
    if (!svg_tag_end)
    {
        free(text);
        svg_set_error("svg tag unterminated");
        return -1;
    }

    const char *svg_name = svg_tag + 1;
    while (svg_name < doc_end && svg_is_space(*svg_name))
    {
        ++svg_name;
    }
    const char *svg_name_end = svg_name;
    while (svg_name_end < doc_end && svg_is_name_char(*svg_name_end))
    {
        ++svg_name_end;
    }

    const char *attr_start = svg_name_end;
    const char *attr_end = svg_tag_end;

    svg_fixed_t width_fixed = 0;
    svg_fixed_t height_fixed = 0;
    svg_fixed_t view_x = 0;
    svg_fixed_t view_y = 0;
    svg_fixed_t view_w = 0;
    svg_fixed_t view_h = 0;
    bool have_viewbox = false;

    const char *value_start = NULL;
    const char *value_end = NULL;
    if (svg_attr_value(attr_start, attr_end, "width", &value_start, &value_end))
    {
        const char *cursor = value_start;
        (void)svg_parse_fixed_span(&cursor, value_end, &width_fixed);
    }
    if (svg_attr_value(attr_start, attr_end, "height", &value_start, &value_end))
    {
        const char *cursor = value_start;
        (void)svg_parse_fixed_span(&cursor, value_end, &height_fixed);
    }
    if (svg_attr_value(attr_start, attr_end, "viewBox", &value_start, &value_end))
    {
        const char *cursor = value_start;
        if (svg_parse_fixed_span(&cursor, value_end, &view_x) &&
            svg_parse_fixed_span(&cursor, value_end, &view_y) &&
            svg_parse_fixed_span(&cursor, value_end, &view_w) &&
            svg_parse_fixed_span(&cursor, value_end, &view_h))
        {
            have_viewbox = true;
        }
    }

    int out_width = svg_fixed_to_int_round(width_fixed);
    int out_height = svg_fixed_to_int_round(height_fixed);

    if (out_width <= 0 || out_height <= 0)
    {
        if (have_viewbox)
        {
            out_width = svg_fixed_to_int_round(view_w);
            out_height = svg_fixed_to_int_round(view_h);
        }
    }
    if (out_width <= 0) out_width = 300;
    if (out_height <= 0) out_height = 150;

    if (!have_viewbox)
    {
        view_x = 0;
        view_y = 0;
        view_w = (svg_fixed_t)(out_width << SVG_FIXED_SHIFT);
        view_h = (svg_fixed_t)(out_height << SVG_FIXED_SHIFT);
    }

    if (view_w <= 0 || view_h <= 0)
    {
        free(text);
        svg_set_error("invalid viewBox");
        return -1;
    }

    svg_view_t view = {
        .view_x = view_x,
        .view_y = view_y,
        .view_w = view_w,
        .view_h = view_h,
        .scale_x = 0,
        .scale_y = 0
    };

    view.scale_x = (svg_fixed_t)(((int64_t)out_width << SVG_FIXED_SHIFT) / view.view_w);
    view.scale_y = (svg_fixed_t)(((int64_t)out_height << SVG_FIXED_SHIFT) / view.view_h);

    if (out_width <= 0 || out_height <= 0)
    {
        free(text);
        svg_set_error("invalid dimensions");
        return -1;
    }

    if ((size_t)out_width > SIZE_MAX / sizeof(video_color_t) / (size_t)out_height)
    {
        free(text);
        svg_set_error("size overflow");
        return -1;
    }

    video_color_t *pixels = (video_color_t *)calloc((size_t)out_width * (size_t)out_height, sizeof(video_color_t));
    if (!pixels)
    {
        free(text);
        svg_set_error("out of memory");
        return -1;
    }

    svg_canvas_t canvas = {
        .pixels = pixels,
        .width = out_width,
        .height = out_height,
        .stride_bytes = out_width * (int)sizeof(video_color_t)
    };

    svg_render_elements(&canvas, &view, svg_tag_end + 1, doc_end);

    free(text);

    *out_pixels = pixels;
    *out_w = out_width;
    *out_h = out_height;
    *out_stride_bytes = canvas.stride_bytes;
    svg_set_error("ok");
    return 0;
}
