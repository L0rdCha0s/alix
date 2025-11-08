#include "ttf.h"

#include "libc.h"

#if TTF_HOST_BUILD
#include <stdio.h>
#else
#include "serial.h"
#endif

#define TTF_TAG(a, b, c, d) (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))

#define TTF_FP_SHIFT 6
#define TTF_FP_ONE   (1 << TTF_FP_SHIFT)

#define TTF_MAX_FLATTEN_DEPTH 16

typedef struct
{
    const uint8_t *table;
    uint32_t length;
    uint16_t seg_count;
    const uint8_t *end_codes;
    const uint8_t *start_codes;
    const uint8_t *id_deltas;
    const uint8_t *id_range_offsets;
} ttf_cmap4_t;

typedef struct
{
    const uint8_t *table;
    uint32_t length;
    uint32_t group_count;
} ttf_cmap12_t;

typedef struct
{
    uint8_t *data;
    size_t size;
    uint16_t units_per_em;
    int16_t ascent;
    int16_t descent;
    int16_t line_gap;
    uint16_t num_glyphs;
    uint16_t num_hmetrics;
    int16_t index_to_loc_format;
    const uint8_t *glyf_table;
    uint32_t glyf_length;
    const uint8_t *hmtx_table;
    uint32_t hmtx_length;
    uint32_t *glyph_offsets;
    ttf_cmap4_t cmap4;
    ttf_cmap12_t cmap12;
} ttf_font_impl_t;

static void ttf_log(const char *msg);
static void ttf_log_tag(const char *prefix, uint32_t tag);
static void ttf_log_u32(const char *prefix, uint32_t value);
static bool ttf_fail(const char *msg);

typedef struct
{
    int32_t x;
    int32_t y;
    bool on_curve;
} ttf_point_t;

typedef struct
{
    int32_t x0;
    int32_t y0;
    int32_t x1;
    int32_t y1;
} ttf_edge_t;

typedef struct
{
    int32_t min_x;
    int32_t min_y;
    int32_t max_x;
    int32_t max_y;
    bool initialized;
} ttf_bounds_t;

typedef struct
{
    ttf_edge_t *edges;
    size_t count;
    size_t capacity;
} ttf_edge_list_t;

static void ttf_tag_to_string(uint32_t tag, char out[5])
{
    out[0] = (char)((tag >> 24) & 0xFF);
    out[1] = (char)((tag >> 16) & 0xFF);
    out[2] = (char)((tag >> 8) & 0xFF);
    out[3] = (char)(tag & 0xFF);
    out[4] = '\0';
}

#if TTF_HOST_BUILD
static void ttf_log(const char *msg)
{
    fprintf(stderr, "[ttf] %s\n", msg);
}

static void ttf_log_tag(const char *prefix, uint32_t tag)
{
    char name[5];
    ttf_tag_to_string(tag, name);
    fprintf(stderr, "[ttf] %s%s\n", prefix, name);
}

static void __attribute__((unused)) ttf_log_u32(const char *prefix, uint32_t value)
{
    fprintf(stderr, "[ttf] %s0x%08X\n", prefix, value);
}
#else
static void ttf_log(const char *msg)
{
    serial_write_string("[ttf] ");
    serial_write_string(msg);
    serial_write_string("\r\n");
}

static void ttf_log_tag(const char *prefix, uint32_t tag)
{
    char name[5];
    ttf_tag_to_string(tag, name);
    serial_write_string("[ttf] ");
    serial_write_string(prefix);
    for (int i = 0; i < 4 && name[i] != '\0'; ++i)
    {
        serial_write_char(name[i]);
    }
    serial_write_string("\r\n");
}

static void __attribute__((unused)) ttf_log_u32(const char *prefix, uint32_t value)
{
    serial_write_string("[ttf] ");
    serial_write_string(prefix);
    serial_write_string("0x");
    serial_write_hex64(value);
    serial_write_string("\r\n");
}
#endif

static bool ttf_fail(const char *msg)
{
    ttf_log(msg);
    return false;
}

static uint16_t ttf_read_u16(const uint8_t *ptr)
{
    return (uint16_t)((uint16_t)ptr[0] << 8 | (uint16_t)ptr[1]);
}

static int16_t ttf_read_i16(const uint8_t *ptr)
{
    return (int16_t)((int16_t)ptr[0] << 8 | (int16_t)ptr[1]);
}

static uint32_t ttf_read_u32(const uint8_t *ptr)
{
    return ((uint32_t)ptr[0] << 24) |
           ((uint32_t)ptr[1] << 16) |
           ((uint32_t)ptr[2] << 8) |
           (uint32_t)ptr[3];
}

static int32_t ttf_abs_i32(int32_t v)
{
    return (v >= 0) ? v : -v;
}

static int32_t ttf_floor_fixed(int32_t value)
{
    if (value >= 0)
    {
        return value >> TTF_FP_SHIFT;
    }
    int32_t neg = -value;
    int32_t bits = neg >> TTF_FP_SHIFT;
    if ((neg & (TTF_FP_ONE - 1)) == 0)
    {
        return -bits;
    }
    return -(bits + 1);
}

static int32_t ttf_ceil_fixed(int32_t value)
{
    if (value >= 0)
    {
        int32_t bits = value >> TTF_FP_SHIFT;
        if ((value & (TTF_FP_ONE - 1)) == 0)
        {
            return bits;
        }
        return bits + 1;
    }
    int32_t neg = -value;
    int32_t bits = neg >> TTF_FP_SHIFT;
    return -bits;
}

static int32_t ttf_round_fixed(int32_t value)
{
    if (value >= 0)
    {
        return (value + (TTF_FP_ONE / 2)) >> TTF_FP_SHIFT;
    }
    return -((-value + (TTF_FP_ONE / 2)) >> TTF_FP_SHIFT);
}

static void ttf_bounds_include(ttf_bounds_t *bounds, int32_t x, int32_t y)
{
    if (!bounds)
    {
        return;
    }
    if (!bounds->initialized)
    {
        bounds->min_x = bounds->max_x = x;
        bounds->min_y = bounds->max_y = y;
        bounds->initialized = true;
        return;
    }
    if (x < bounds->min_x) bounds->min_x = x;
    if (x > bounds->max_x) bounds->max_x = x;
    if (y < bounds->min_y) bounds->min_y = y;
    if (y > bounds->max_y) bounds->max_y = y;
}

static void ttf_edge_list_reset(ttf_edge_list_t *list)
{
    if (!list)
    {
        return;
    }
    if (list->edges)
    {
        free(list->edges);
        list->edges = NULL;
    }
    list->count = 0;
    list->capacity = 0;
}

static bool ttf_edge_list_add(ttf_edge_list_t *list,
                              int32_t x0,
                              int32_t y0,
                              int32_t x1,
                              int32_t y1,
                              ttf_bounds_t *bounds)
{
    if (!list)
    {
        return false;
    }
    if (x0 == x1 && y0 == y1)
    {
        return true;
    }

    if (list->count >= list->capacity)
    {
        size_t new_cap = (list->capacity == 0) ? 32 : list->capacity * 2;
        ttf_edge_t *edges = (ttf_edge_t *)realloc(list->edges, new_cap * sizeof(ttf_edge_t));
        if (!edges)
        {
            return false;
        }
        list->edges = edges;
        list->capacity = new_cap;
    }

    list->edges[list->count].x0 = x0;
    list->edges[list->count].y0 = y0;
    list->edges[list->count].x1 = x1;
    list->edges[list->count].y1 = y1;
    list->count++;

    ttf_bounds_include(bounds, x0, y0);
    ttf_bounds_include(bounds, x1, y1);
    return true;
}

static void ttf_font_impl_destroy(ttf_font_impl_t *impl)
{
    if (!impl)
    {
        return;
    }
    if (impl->glyph_offsets)
    {
        free(impl->glyph_offsets);
    }
    if (impl->data)
    {
        free(impl->data);
    }
    free(impl);
}

static bool ttf_locate_table(const ttf_font_impl_t *impl,
                             uint32_t tag,
                             uint32_t *offset_out,
                             uint32_t *length_out)
{
    if (!impl || !impl->data || impl->size < 12)
    {
        return false;
    }
    uint16_t num_tables = ttf_read_u16(impl->data + 4);
    const uint8_t *entry = impl->data + 12;
    for (uint16_t i = 0; i < num_tables; ++i)
    {
        if (entry + 16 > impl->data + impl->size)
        {
            return false;
        }
        uint32_t entry_tag = ttf_read_u32(entry);
        if (entry_tag == tag)
        {
            uint32_t offset = ttf_read_u32(entry + 8);
            uint32_t length = ttf_read_u32(entry + 12);
            if (offset > impl->size || length > impl->size - offset)
            {
                return false;
            }
            if (offset_out) *offset_out = offset;
            if (length_out) *length_out = length;
            return true;
        }
        entry += 16;
    }
    return false;
}

static bool ttf_require_table(const ttf_font_impl_t *impl,
                              uint32_t tag,
                              uint32_t *offset_out,
                              uint32_t *length_out)
{
    if (ttf_locate_table(impl, tag, offset_out, length_out))
    {
        return true;
    }
    ttf_log_tag("missing table ", tag);
    return false;
}

static bool ttf_parse_cmap_format4(ttf_font_impl_t *impl,
                                   const uint8_t *table,
                                   uint32_t length)
{
    if (!impl || !table || length < 16)
    {
        return ttf_fail("cmap4: table too small");
    }
    uint16_t seg_count_x2 = ttf_read_u16(table + 6);
    if (seg_count_x2 == 0 || (seg_count_x2 & 1))
    {
        return ttf_fail("cmap4: invalid segCount");
    }
    uint16_t seg_count = seg_count_x2 / 2;
    uint32_t end_codes_offset = 14;
    uint32_t reserved_offset = end_codes_offset + seg_count * 2;
    uint32_t start_codes_offset = reserved_offset + 2;
    uint32_t id_delta_offset = start_codes_offset + seg_count * 2;
    uint32_t id_range_offset = id_delta_offset + seg_count * 2;
    if (id_range_offset + seg_count * 2 > length)
    {
        return ttf_fail("cmap4: truncated arrays");
    }

    impl->cmap4.table = table;
    impl->cmap4.length = length;
    impl->cmap4.seg_count = seg_count;
    impl->cmap4.end_codes = table + end_codes_offset;
    impl->cmap4.start_codes = table + start_codes_offset;
    impl->cmap4.id_deltas = table + id_delta_offset;
    impl->cmap4.id_range_offsets = table + id_range_offset;
    return true;
}

static bool ttf_parse_cmap_format12(ttf_font_impl_t *impl,
                                    const uint8_t *table,
                                    uint32_t length)
{
    if (!impl || !table || length < 16)
    {
        return ttf_fail("cmap12: table too small");
    }
    uint32_t declared_length = ttf_read_u32(table + 4);
    if (declared_length > length)
    {
        return ttf_fail("cmap12: declared length too large");
    }
    uint32_t group_count = ttf_read_u32(table + 12);
    uint64_t required = (uint64_t)group_count * 12ULL;
    if (group_count == 0 || 16ULL + required > length)
    {
        return ttf_fail("cmap12: group data truncated");
    }

    impl->cmap12.table = table;
    impl->cmap12.length = length;
    impl->cmap12.group_count = group_count;
    ttf_log("cmap: using format 12 subtable");
    return true;
}

static uint16_t ttf_cmap12_lookup(const ttf_cmap12_t *cmap, uint32_t codepoint)
{
    if (!cmap || !cmap->table || cmap->group_count == 0)
    {
        return 0;
    }
    const uint8_t *groups = cmap->table + 16;
    uint32_t left = 0;
    uint32_t right = cmap->group_count;
    while (left < right)
    {
        uint32_t mid = left + (right - left) / 2;
        const uint8_t *entry = groups + mid * 12;
        uint32_t start = ttf_read_u32(entry);
        uint32_t end = ttf_read_u32(entry + 4);
        if (codepoint < start)
        {
            right = mid;
        }
        else if (codepoint > end)
        {
            left = mid + 1;
        }
        else
        {
            uint32_t start_glyph = ttf_read_u32(entry + 8);
            uint32_t glyph = start_glyph + (codepoint - start);
            if (glyph > 0xFFFF)
            {
                glyph &= 0xFFFF;
            }
            return (uint16_t)glyph;
        }
    }
    return 0;
}

static bool ttf_parse_cmap(ttf_font_impl_t *impl, uint32_t offset, uint32_t length)
{
    if (!impl || length < 4 || offset > impl->size || length > impl->size - offset)
    {
        return ttf_fail("cmap: invalid bounds");
    }
    const uint8_t *table = impl->data + offset;
    uint16_t num_subtables = ttf_read_u16(table + 2);

    const uint8_t *best4 = NULL;
    uint32_t best4_length = 0;
    const uint8_t *best12 = NULL;
    uint32_t best12_length = 0;
    for (uint16_t i = 0; i < num_subtables; ++i)
    {
        const uint8_t *record = table + 4 + i * 8;
        if (record + 8 > table + length)
        {
            return ttf_fail("cmap: record truncated");
        }
        uint16_t platform = ttf_read_u16(record);
        uint16_t encoding = ttf_read_u16(record + 2);
        uint32_t sub_offset = ttf_read_u32(record + 4);
        if (sub_offset >= length)
        {
            continue;
        }
        const uint8_t *subtable = table + sub_offset;
        uint16_t format = ttf_read_u16(subtable);
        if (format == 12)
        {
            best12 = subtable;
            best12_length = length - sub_offset;
            if (platform == 3 && (encoding == 1 || encoding == 10))
            {
                break;
            }
            continue;
        }
        if (format != 4)
        {
            continue;
        }
        if (platform == 3 && (encoding == 1 || encoding == 10))
        {
            best4 = subtable;
            best4_length = length - sub_offset;
            break;
        }
        if (!best4 && (platform == 0 || platform == 3))
        {
            best4 = subtable;
            best4_length = length - sub_offset;
        }
    }

    bool parsed = false;
    if (best12)
    {
        parsed = ttf_parse_cmap_format12(impl, best12, best12_length);
    }
    if (!parsed && best4)
    {
        parsed = ttf_parse_cmap_format4(impl, best4, best4_length);
    }
    if (!parsed)
    {
        return ttf_fail("cmap: no supported subtable");
    }
    return true;
}

static bool ttf_build_glyph_offsets(ttf_font_impl_t *impl,
                                    const uint8_t *loca_table,
                                    uint32_t loca_length)
{
    if (!impl || !loca_table || impl->num_glyphs == 0)
    {
        return ttf_fail("loca: invalid arguments");
    }
    size_t count = (size_t)impl->num_glyphs + 1;
    uint32_t *offsets = (uint32_t *)malloc(count * sizeof(uint32_t));
    if (!offsets)
    {
        return ttf_fail("loca: offset allocation failed");
    }

    if (impl->index_to_loc_format == 0)
    {
        if (loca_length < count * 2)
        {
            free(offsets);
            return ttf_fail("loca: 16-bit table truncated");
        }
        for (size_t i = 0; i < count; ++i)
        {
            offsets[i] = (uint32_t)ttf_read_u16(loca_table + i * 2) * 2u;
        }
    }
    else if (impl->index_to_loc_format == 1)
    {
        if (loca_length < count * 4)
        {
            free(offsets);
            return ttf_fail("loca: 32-bit table truncated");
        }
        for (size_t i = 0; i < count; ++i)
        {
            offsets[i] = ttf_read_u32(loca_table + i * 4);
        }
    }
    else
    {
        free(offsets);
        return ttf_fail("loca: unsupported format");
    }

    impl->glyph_offsets = offsets;
    return true;
}

static bool ttf_parse_tables(ttf_font_impl_t *impl)
{
    uint32_t head_offset = 0, head_length = 0;
    uint32_t maxp_offset = 0, maxp_length = 0;
    uint32_t cmap_offset = 0, cmap_length = 0;
    uint32_t loca_offset = 0, loca_length = 0;
    uint32_t glyf_offset = 0, glyf_length = 0;
    uint32_t hhea_offset = 0, hhea_length = 0;
    uint32_t hmtx_offset = 0, hmtx_length = 0;

    if (!ttf_require_table(impl, TTF_TAG('h', 'e', 'a', 'd'), &head_offset, &head_length) ||
        !ttf_require_table(impl, TTF_TAG('m', 'a', 'x', 'p'), &maxp_offset, &maxp_length) ||
        !ttf_require_table(impl, TTF_TAG('c', 'm', 'a', 'p'), &cmap_offset, &cmap_length) ||
        !ttf_require_table(impl, TTF_TAG('l', 'o', 'c', 'a'), &loca_offset, &loca_length) ||
        !ttf_require_table(impl, TTF_TAG('g', 'l', 'y', 'f'), &glyf_offset, &glyf_length) ||
        !ttf_require_table(impl, TTF_TAG('h', 'h', 'e', 'a'), &hhea_offset, &hhea_length) ||
        !ttf_require_table(impl, TTF_TAG('h', 'm', 't', 'x'), &hmtx_offset, &hmtx_length))
    {
        return false;
    }

    const uint8_t *head = impl->data + head_offset;
    const uint8_t *maxp = impl->data + maxp_offset;
    const uint8_t *hhea = impl->data + hhea_offset;

    if (head_length < 54 || maxp_length < 6 || hhea_length < 36)
    {
        return ttf_fail("metrics tables truncated");
    }

    impl->units_per_em = ttf_read_u16(head + 18);
    impl->index_to_loc_format = ttf_read_i16(head + 50);
    impl->num_glyphs = ttf_read_u16(maxp + 4);
    impl->ascent = ttf_read_i16(hhea + 4);
    impl->descent = ttf_read_i16(hhea + 6);
    impl->line_gap = ttf_read_i16(hhea + 8);
    impl->num_hmetrics = ttf_read_u16(hhea + 34);

    if (impl->units_per_em == 0 || impl->num_hmetrics == 0)
    {
        return ttf_fail("metrics tables invalid");
    }

    if (!ttf_parse_cmap(impl, cmap_offset, cmap_length))
    {
        ttf_log("failed to parse cmap");
        return false;
    }
    if (!ttf_build_glyph_offsets(impl, impl->data + loca_offset, loca_length))
    {
        ttf_log("failed to build glyph offsets");
        return false;
    }

    impl->glyf_table = impl->data + glyf_offset;
    impl->glyf_length = glyf_length;
    impl->hmtx_table = impl->data + hmtx_offset;
    impl->hmtx_length = hmtx_length;
    return true;
}

bool ttf_font_load(ttf_font_t *font, const uint8_t *data, size_t size)
{
    if (!font || !data || size < 12)
    {
        ttf_log("font_load: invalid arguments");
        return false;
    }

    ttf_font_impl_t *impl = (ttf_font_impl_t *)malloc(sizeof(ttf_font_impl_t));
    if (!impl)
    {
        ttf_log("font_load: impl allocation failed");
        return false;
    }
    memset(impl, 0, sizeof(*impl));

    impl->data = (uint8_t *)malloc(size);
    if (!impl->data)
    {
        ttf_log("font_load: data allocation failed");
        ttf_font_impl_destroy(impl);
        return false;
    }
    memcpy(impl->data, data, size);
    impl->size = size;

    if (!ttf_parse_tables(impl))
    {
        ttf_log("font_load: parse tables failed");
        ttf_font_impl_destroy(impl);
        return false;
    }

    font->impl = impl;
    return true;
}

void ttf_font_unload(ttf_font_t *font)
{
    if (!font)
    {
        return;
    }
    if (font->impl)
    {
        ttf_font_impl_destroy((ttf_font_impl_t *)font->impl);
        font->impl = NULL;
    }
}

bool ttf_font_metrics(const ttf_font_t *font, int pixel_height, ttf_font_metrics_t *out_metrics)
{
    if (!font || !font->impl || !out_metrics || pixel_height <= 0)
    {
        ttf_log("metrics: invalid arguments");
        return false;
    }
    const ttf_font_impl_t *impl = (const ttf_font_impl_t *)font->impl;
    if (impl->units_per_em == 0)
    {
        ttf_log("metrics: units_per_em is zero");
        return false;
    }
    int64_t numerator = (int64_t)pixel_height * TTF_FP_ONE;
    int32_t ascent = (int32_t)((numerator * impl->ascent) / impl->units_per_em);
    int32_t descent = (int32_t)((numerator * impl->descent) / impl->units_per_em);
    int32_t line_gap = (int32_t)((numerator * impl->line_gap) / impl->units_per_em);

    out_metrics->ascent = ttf_round_fixed(ascent);
    out_metrics->descent = ttf_round_fixed(descent);
    out_metrics->line_gap = ttf_round_fixed(line_gap);
    return true;
}

uint16_t ttf_font_lookup_glyph(const ttf_font_t *font, uint32_t codepoint)
{
    if (!font || !font->impl)
    {
        return 0;
    }
    const ttf_font_impl_t *impl = (const ttf_font_impl_t *)font->impl;

    if (impl->cmap12.table && impl->cmap12.group_count > 0)
    {
        uint16_t glyph = ttf_cmap12_lookup(&impl->cmap12, codepoint);
        if (glyph != 0)
        {
            return glyph;
        }
    }

    const ttf_cmap4_t *cmap = &impl->cmap4;
    if (!cmap->table || cmap->seg_count == 0)
    {
        return 0;
    }

    for (uint16_t i = 0; i < cmap->seg_count; ++i)
    {
        uint16_t end_code = ttf_read_u16(cmap->end_codes + i * 2);
        if (codepoint > end_code)
        {
            continue;
        }
        uint16_t start_code = ttf_read_u16(cmap->start_codes + i * 2);
        if (codepoint < start_code)
        {
            return 0;
        }
        int16_t id_delta = ttf_read_i16(cmap->id_deltas + i * 2);
        uint16_t id_range_offset = ttf_read_u16(cmap->id_range_offsets + i * 2);
        if (id_range_offset == 0)
        {
            return (uint16_t)((codepoint + id_delta) & 0xFFFF);
        }
        uint32_t offset = id_range_offset + 2 * (codepoint - start_code);
        const uint8_t *range_ptr = cmap->id_range_offsets + i * 2 + offset;
        if (range_ptr + 2 > cmap->table + cmap->length)
        {
            return 0;
        }
        uint16_t glyph = ttf_read_u16(range_ptr);
        if (glyph == 0)
        {
            return 0;
        }
        return (uint16_t)((glyph + id_delta) & 0xFFFF);
    }
    return 0;
}

static bool ttf_get_glyph_data(const ttf_font_impl_t *impl,
                               uint16_t glyph_index,
                               const uint8_t **data_out,
                               uint32_t *length_out)
{
    if (!impl || !impl->glyph_offsets || glyph_index >= impl->num_glyphs)
    {
        return ttf_fail("glyph: invalid index");
    }
    uint32_t offset = impl->glyph_offsets[glyph_index];
    uint32_t next = impl->glyph_offsets[glyph_index + 1];
    if (offset >= impl->glyf_length || next > impl->glyf_length || next < offset)
    {
        ttf_log("glyph: bounds outside glyf table");
        return false;
    }
    if (data_out)
    {
        *data_out = impl->glyf_table + offset;
    }
    if (length_out)
    {
        *length_out = next - offset;
    }
    return true;
}

static bool ttf_get_hmetrics(const ttf_font_impl_t *impl,
                             uint16_t glyph_index,
                             uint16_t *advance_out,
                             int16_t *lsb_out)
{
    if (!impl || !impl->hmtx_table || impl->hmtx_length == 0)
    {
        return ttf_fail("hmtx: table missing");
    }

    uint16_t advance = 0;
    int16_t lsb = 0;
    if (glyph_index < impl->num_hmetrics)
    {
        size_t offset = (size_t)glyph_index * 4;
        if (offset + 4 > impl->hmtx_length)
        {
            return ttf_fail("hmtx: glyph metrics truncated");
        }
        advance = ttf_read_u16(impl->hmtx_table + offset);
        lsb = ttf_read_i16(impl->hmtx_table + offset + 2);
    }
    else
    {
        size_t last = (size_t)(impl->num_hmetrics - 1) * 4;
        if (last + 4 > impl->hmtx_length)
        {
            return ttf_fail("hmtx: last metric truncated");
        }
        advance = ttf_read_u16(impl->hmtx_table + last);
        size_t extra_index = (size_t)(glyph_index - impl->num_hmetrics);
        size_t extra_offset = (size_t)impl->num_hmetrics * 4 + extra_index * 2;
        if (extra_offset + 2 > impl->hmtx_length)
        {
            return ttf_fail("hmtx: long metrics truncated");
        }
        lsb = ttf_read_i16(impl->hmtx_table + extra_offset);
    }

    if (advance_out) *advance_out = advance;
    if (lsb_out) *lsb_out = lsb;
    return true;
}

static int32_t ttf_scale_value(int32_t value, int pixel_height, uint16_t units_per_em)
{
    int64_t numerator = (int64_t)value * (int64_t)pixel_height;
    numerator <<= TTF_FP_SHIFT;
    return (int32_t)(numerator / units_per_em);
}

static void ttf_point_mid(const ttf_point_t *a,
                          const ttf_point_t *b,
                          ttf_point_t *out)
{
    out->x = (a->x + b->x) / 2;
    out->y = (a->y + b->y) / 2;
    out->on_curve = true;
}

static bool ttf_flatten_quadratic(ttf_edge_list_t *edges,
                                  ttf_bounds_t *bounds,
                                  const ttf_point_t *p0,
                                  const ttf_point_t *p1,
                                  const ttf_point_t *p2,
                                  int32_t tolerance,
                                  int depth)
{
    if (depth >= TTF_MAX_FLATTEN_DEPTH)
    {
        return ttf_edge_list_add(edges, p0->x, p0->y, p2->x, p2->y, bounds);
    }

    int32_t dx = (p0->x + p2->x) - (p1->x << 1);
    int32_t dy = (p0->y + p2->y) - (p1->y << 1);
    if (ttf_abs_i32(dx) <= tolerance && ttf_abs_i32(dy) <= tolerance)
    {
        return ttf_edge_list_add(edges, p0->x, p0->y, p2->x, p2->y, bounds);
    }

    ttf_point_t q0, q1, mid;
    ttf_point_mid(p0, p1, &q0);
    ttf_point_mid(p1, p2, &q1);
    ttf_point_mid(&q0, &q1, &mid);

    if (!ttf_flatten_quadratic(edges, bounds, p0, &q0, &mid, tolerance, depth + 1))
    {
        return false;
    }
    return ttf_flatten_quadratic(edges, bounds, &mid, &q1, p2, tolerance, depth + 1);
}

static bool ttf_emit_contour(const ttf_point_t *points,
                             int count,
                             ttf_edge_list_t *edges,
                             ttf_bounds_t *bounds,
                             int32_t tolerance)
{
    if (count <= 0)
    {
        return true;
    }

    int max_points = count * 2 + 4;
    ttf_point_t *work = (ttf_point_t *)malloc((size_t)max_points * sizeof(ttf_point_t));
    if (!work)
    {
        return false;
    }

    int total = 0;
    for (int i = 0; i < count; ++i)
    {
        work[total++] = points[i];
    }

    if (!work[0].on_curve)
    {
        ttf_point_t insert;
        if (!work[total - 1].on_curve)
        {
            ttf_point_mid(&work[0], &work[total - 1], &insert);
        }
        else
        {
            insert = work[total - 1];
        }
        memmove(work + 1, work, (size_t)total * sizeof(ttf_point_t));
        work[0] = insert;
        total++;
    }
    if (!work[total - 1].on_curve)
    {
        ttf_point_t insert;
        ttf_point_mid(&work[total - 1], &work[0], &insert);
        work[total++] = insert;
    }

    ttf_point_t *processed = (ttf_point_t *)malloc((size_t)(total * 2 + 2) * sizeof(ttf_point_t));
    if (!processed)
    {
        free(work);
        return false;
    }

    int processed_count = 0;
    for (int i = 0; i < total; ++i)
    {
        ttf_point_t current = work[i];
        ttf_point_t next = work[(i + 1) % total];
        processed[processed_count++] = current;
        if (!current.on_curve && !next.on_curve)
        {
            ttf_point_t mid;
            ttf_point_mid(&current, &next, &mid);
            processed[processed_count++] = mid;
        }
    }
    processed[processed_count++] = processed[0];
    processed[processed_count++] = processed[1];

    int idx = 0;
    while (idx < processed_count - 2)
    {
        ttf_point_t p0 = processed[idx];
        ttf_point_t p1 = processed[idx + 1];
        if (p0.on_curve && p1.on_curve)
        {
            if (!ttf_edge_list_add(edges, p0.x, p0.y, p1.x, p1.y, bounds))
            {
                free(processed);
                free(work);
                return false;
            }
            idx += 1;
        }
        else
        {
            ttf_point_t p2 = processed[idx + 2];
            if (!ttf_flatten_quadratic(edges, bounds, &p0, &p1, &p2, tolerance, 0))
            {
                free(processed);
                free(work);
                return false;
            }
            idx += 2;
        }
    }

    free(processed);
    free(work);
    return true;
}

static bool ttf_build_segments(const ttf_point_t *points,
                               const uint16_t *end_points,
                               uint16_t contour_count,
                               ttf_edge_list_t *edges,
                               ttf_bounds_t *bounds,
                               int32_t tolerance)
{
    int start = 0;
    for (uint16_t c = 0; c < contour_count; ++c)
    {
        uint16_t end = end_points[c];
        if (end < start)
        {
            return false;
        }
        int count = (int)end - start + 1;
        if (count > 0)
        {
            if (!ttf_emit_contour(points + start, count, edges, bounds, tolerance))
            {
                return false;
            }
        }
        start = end + 1;
    }
    return true;
}

static bool ttf_point_in_winding(const ttf_edge_t *edges,
                                 size_t edge_count,
                                 int32_t sample_x,
                                 int32_t sample_y)
{
    int winding = 0;
    for (size_t i = 0; i < edge_count; ++i)
    {
        int32_t y0 = edges[i].y0;
        int32_t y1 = edges[i].y1;
        bool upward = (y0 <= sample_y) && (y1 > sample_y);
        bool downward = (y0 > sample_y) && (y1 <= sample_y);
        if (!upward && !downward)
        {
            continue;
        }
        int64_t dy = (int64_t)y1 - (int64_t)y0;
        if (dy == 0)
        {
            continue;
        }
        int64_t t = ((int64_t)sample_y - (int64_t)y0) << TTF_FP_SHIFT;
        int64_t dx = (int64_t)edges[i].x1 - (int64_t)edges[i].x0;
        int64_t ix = (int64_t)edges[i].x0 + (dx * t) / dy;
        if (ix > sample_x)
        {
            winding += (dy > 0) ? 1 : -1;
        }
    }
    return winding != 0;
}

bool ttf_font_render_glyph_bitmap(const ttf_font_t *font,
                                  uint32_t codepoint,
                                  int pixel_height,
                                  ttf_bitmap_t *out_bitmap,
                                  ttf_glyph_metrics_t *out_metrics)
{
    if (!font || !font->impl || !out_bitmap || pixel_height <= 0)
    {
        return false;
    }

    ttf_glyph_metrics_t local_metrics = {0};
    ttf_glyph_metrics_t *metrics = out_metrics ? out_metrics : &local_metrics;
    metrics->advance = 0;
    metrics->bearing_x = 0;
    metrics->bearing_y = 0;
    metrics->width = 0;
    metrics->height = 0;

    out_bitmap->width = 0;
    out_bitmap->height = 0;
    out_bitmap->stride = 0;
    out_bitmap->offset_x = 0;
    out_bitmap->offset_y = 0;
    out_bitmap->pixels = NULL;

    ttf_font_impl_t *impl = (ttf_font_impl_t *)font->impl;
    uint16_t glyph_index = ttf_font_lookup_glyph(font, codepoint);
    if (glyph_index == 0 && codepoint != '?')
    {
        glyph_index = ttf_font_lookup_glyph(font, '?');
    }

    uint16_t advance_raw = 0;
    int16_t lsb_raw = 0;
    if (!ttf_get_hmetrics(impl, glyph_index, &advance_raw, &lsb_raw))
    {
        return false;
    }

    int32_t advance_fixed = ttf_scale_value(advance_raw, pixel_height, impl->units_per_em);
    int32_t bearing_fixed = ttf_scale_value(lsb_raw, pixel_height, impl->units_per_em);
    metrics->advance = ttf_round_fixed(advance_fixed);
    metrics->bearing_x = ttf_round_fixed(bearing_fixed);

    const uint8_t *glyph_data = NULL;
    uint32_t glyph_length = 0;
    if (!ttf_get_glyph_data(impl, glyph_index, &glyph_data, &glyph_length))
    {
        return false;
    }
    if (!glyph_data || glyph_length < 10)
    {
        return true;
    }

    int16_t contour_count = ttf_read_i16(glyph_data);
    if (contour_count <= 0)
    {
        return true;
    }

    const uint8_t *cursor = glyph_data + 10;
    if ((uint32_t)(cursor - glyph_data) + contour_count * 2 > glyph_length)
    {
        return false;
    }

    uint16_t *end_points = (uint16_t *)malloc((size_t)contour_count * sizeof(uint16_t));
    if (!end_points)
    {
        return false;
    }
    for (int i = 0; i < contour_count; ++i)
    {
        end_points[i] = ttf_read_u16(cursor + i * 2);
    }
    cursor += contour_count * 2;

    if ((uint32_t)(cursor - glyph_data) + 2 > glyph_length)
    {
        free(end_points);
        return false;
    }

    uint16_t instruction_length = ttf_read_u16(cursor);
    cursor += 2;
    if ((uint32_t)(cursor - glyph_data) + instruction_length > glyph_length)
    {
        free(end_points);
        return false;
    }
    cursor += instruction_length;

    uint16_t point_count = end_points[contour_count - 1] + 1;
    if (point_count == 0)
    {
        free(end_points);
        return true;
    }

    uint8_t *flags = (uint8_t *)malloc(point_count);
    ttf_point_t *points = (ttf_point_t *)malloc(point_count * sizeof(ttf_point_t));
    if (!flags || !points)
    {
        free(flags);
        free(points);
        free(end_points);
        return false;
    }

    uint16_t filled = 0;
    while (filled < point_count)
    {
        if ((uint32_t)(cursor - glyph_data) >= glyph_length)
        {
            free(flags);
            free(points);
            free(end_points);
            return false;
        }
        uint8_t flag = *cursor++;
        flags[filled++] = flag;
        if (flag & 0x08)
        {
            if ((uint32_t)(cursor - glyph_data) >= glyph_length)
            {
                free(flags);
                free(points);
                free(end_points);
                return false;
            }
            uint8_t repeat = *cursor++;
            for (uint8_t r = 0; r < repeat && filled < point_count; ++r)
            {
                flags[filled++] = flag;
            }
        }
    }

    int32_t x = 0;
    for (uint16_t i = 0; i < point_count; ++i)
    {
        uint8_t flag = flags[i];
        int32_t delta = 0;
        if (flag & 0x02)
        {
            if ((uint32_t)(cursor - glyph_data) >= glyph_length)
            {
                free(flags);
                free(points);
                free(end_points);
                return false;
            }
            uint8_t value = *cursor++;
            delta = (flag & 0x10) ? (int32_t)value : -(int32_t)value;
        }
        else
        {
            if (flag & 0x10)
            {
                delta = 0;
            }
            else
            {
                if ((uint32_t)(cursor - glyph_data) + 2 > glyph_length)
                {
                    free(flags);
                    free(points);
                    free(end_points);
                    return false;
                }
                delta = ttf_read_i16(cursor);
                cursor += 2;
            }
        }
        x += delta;
        points[i].x = ttf_scale_value(x, pixel_height, impl->units_per_em);
        points[i].on_curve = (flag & 0x01) != 0;
    }

    int32_t y = 0;
    for (uint16_t i = 0; i < point_count; ++i)
    {
        uint8_t flag = flags[i];
        int32_t delta = 0;
        if (flag & 0x04)
        {
            if ((uint32_t)(cursor - glyph_data) >= glyph_length)
            {
                free(flags);
                free(points);
                free(end_points);
                return false;
            }
            uint8_t value = *cursor++;
            delta = (flag & 0x20) ? (int32_t)value : -(int32_t)value;
        }
        else
        {
            if (flag & 0x20)
            {
                delta = 0;
            }
            else
            {
                if ((uint32_t)(cursor - glyph_data) + 2 > glyph_length)
                {
                    free(flags);
                    free(points);
                    free(end_points);
                    return false;
                }
                delta = ttf_read_i16(cursor);
                cursor += 2;
            }
        }
        y += delta;
        points[i].y = ttf_scale_value(y, pixel_height, impl->units_per_em);
    }

    ttf_edge_list_t edges = {0};
    ttf_bounds_t bounds = {0};
    int32_t tolerance = TTF_FP_ONE / 2;

    bool built = ttf_build_segments(points, end_points, (uint16_t)contour_count, &edges, &bounds, tolerance);
    free(flags);
    free(points);
    free(end_points);

    if (!built)
    {
        ttf_edge_list_reset(&edges);
        return false;
    }

    if (edges.count == 0 || !bounds.initialized)
    {
        ttf_edge_list_reset(&edges);
        return true;
    }

    int32_t min_x = bounds.min_x;
    int32_t max_x = bounds.max_x;
    int32_t min_y = bounds.min_y;
    int32_t max_y = bounds.max_y;

    int width = ttf_ceil_fixed(max_x) - ttf_floor_fixed(min_x);
    int height = ttf_ceil_fixed(max_y) - ttf_floor_fixed(min_y);
    if (width <= 0 || height <= 0)
    {
        ttf_edge_list_reset(&edges);
        return true;
    }

    size_t pixel_count = (size_t)width * (size_t)height;
    uint8_t *pixels = (uint8_t *)malloc(pixel_count);
    if (!pixels)
    {
        ttf_edge_list_reset(&edges);
        return false;
    }
    memset(pixels, 0, pixel_count);

    ttf_edge_t *local_edges = (ttf_edge_t *)malloc(edges.count * sizeof(ttf_edge_t));
    if (!local_edges)
    {
        free(pixels);
        ttf_edge_list_reset(&edges);
        return false;
    }

    int32_t shift_x = min_x;
    int32_t shift_y = max_y;
    for (size_t i = 0; i < edges.count; ++i)
    {
        local_edges[i].x0 = edges.edges[i].x0 - shift_x;
        local_edges[i].x1 = edges.edges[i].x1 - shift_x;
        local_edges[i].y0 = shift_y - edges.edges[i].y0;
        local_edges[i].y1 = shift_y - edges.edges[i].y1;
    }

    const int32_t sample_offsets[2] = { TTF_FP_ONE / 4, (TTF_FP_ONE * 3) / 4 };
    for (int py = 0; py < height; ++py)
    {
        for (int px = 0; px < width; ++px)
        {
            int coverage = 0;
            int32_t base_y = (int32_t)py << TTF_FP_SHIFT;
            int32_t base_x = (int32_t)px << TTF_FP_SHIFT;
            for (int sy = 0; sy < 2; ++sy)
            {
                int32_t sample_y = base_y + sample_offsets[sy];
                for (int sx = 0; sx < 2; ++sx)
                {
                    int32_t sample_x = base_x + sample_offsets[sx];
                    if (ttf_point_in_winding(local_edges, edges.count, sample_x, sample_y))
                    {
                        coverage++;
                    }
                }
            }
            uint8_t alpha = (uint8_t)((coverage * 255 + 2) / 4);
            pixels[(size_t)py * (size_t)width + (size_t)px] = alpha;
        }
    }

    metrics->width = width;
    metrics->height = height;
    metrics->bearing_y = ttf_ceil_fixed(max_y);

    out_bitmap->width = width;
    out_bitmap->height = height;
    out_bitmap->stride = width;
    out_bitmap->offset_x = ttf_floor_fixed(min_x);
    out_bitmap->offset_y = ttf_ceil_fixed(max_y);
    out_bitmap->pixels = pixels;

    free(local_edges);
    ttf_edge_list_reset(&edges);
    return true;
}

void ttf_bitmap_destroy(ttf_bitmap_t *bitmap)
{
    if (!bitmap)
    {
        return;
    }
    if (bitmap->pixels)
    {
        free(bitmap->pixels);
        bitmap->pixels = NULL;
    }
    bitmap->width = 0;
    bitmap->height = 0;
    bitmap->stride = 0;
    bitmap->offset_x = 0;
    bitmap->offset_y = 0;
}
