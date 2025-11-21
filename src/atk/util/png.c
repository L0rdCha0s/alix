#include "atk/util/png.h"

#ifdef PNG_HOST_BUILD
#include <stdlib.h>
#include <string.h>
#else
#include "heap.h"
#include "libc.h"
#endif

#define PNG_SIG_SIZE 8
#define PNG_CHUNK_HEADER 8
#define PNG_CRC_SIZE 4
#define PNG_IHDR_LEN 13
#define PNG_BITSIZE_MAX 15

typedef struct
{
    const uint8_t *data;
    size_t size;
    size_t pos;
    uint32_t bitbuf;
    int bitcount;
} bitstream_t;

typedef struct
{
    uint16_t counts[PNG_BITSIZE_MAX + 1];
    uint16_t symbols[288];
    uint16_t first_code[PNG_BITSIZE_MAX + 1];
    uint16_t first_symbol[PNG_BITSIZE_MAX + 1];
} huff_table_t;

static const char *g_png_error = "ok";

static void png_set_error(const char *msg)
{
    g_png_error = msg ? msg : "png error";
}

const char *png_last_error(void)
{
    return g_png_error;
}

static uint32_t png_read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static bool br_fill(bitstream_t *br, int count)
{
    while (br->bitcount < count)
    {
        if (br->pos >= br->size)
        {
            return false;
        }
        br->bitbuf |= (uint32_t)br->data[br->pos++] << br->bitcount;
        br->bitcount += 8;
    }
    return true;
}

static bool br_read(bitstream_t *br, int count, uint32_t *out_bits)
{
    if (count == 0)
    {
        *out_bits = 0;
        return true;
    }
    if (count > 24)
    {
        return false;
    }
    if (!br_fill(br, count))
    {
        return false;
    }
    uint32_t mask = (1u << count) - 1u;
    *out_bits = br->bitbuf & mask;
    br->bitbuf >>= count;
    br->bitcount -= count;
    return true;
}

static void br_align_byte(bitstream_t *br)
{
    br->bitbuf = 0;
    br->bitcount = 0;
}

static bool huff_build(huff_table_t *table, const uint8_t *lengths, int length_count)
{
    if (!table || !lengths || length_count <= 0)
    {
        return false;
    }

    memset(table, 0, sizeof(*table));
    for (int i = 0; i < length_count; ++i)
    {
        uint8_t len = lengths[i];
        if (len > PNG_BITSIZE_MAX)
        {
            return false;
        }
        if (len)
        {
            table->counts[len]++;
        }
    }

    int left = 1;
    for (int len = 1; len <= PNG_BITSIZE_MAX; ++len)
    {
        left <<= 1;
        left -= table->counts[len];
        if (left < 0)
        {
            return false;
        }
    }

    uint16_t offsets[PNG_BITSIZE_MAX + 1];
    offsets[1] = 0;
    for (int len = 1; len < PNG_BITSIZE_MAX; ++len)
    {
        offsets[len + 1] = offsets[len] + table->counts[len];
    }

    for (int sym = 0; sym < length_count; ++sym)
    {
        uint8_t len = lengths[sym];
        if (len == 0)
        {
            continue;
        }
        table->symbols[offsets[len]++] = (uint16_t)sym;
    }

    /* Compute canonical first_code and first_symbol for decoding */
    uint16_t code = 0;
    table->first_symbol[0] = 0;
    table->first_code[0] = 0;
    for (int bits = 1; bits <= PNG_BITSIZE_MAX; ++bits)
    {
        code = (uint16_t)((code + table->counts[bits - 1]) << 1);
        table->first_code[bits] = code;
        table->first_symbol[bits] = (uint16_t)(table->first_symbol[bits - 1] + table->counts[bits - 1]);
    }
    return true;
}

static inline uint32_t reverse_bits(uint32_t v, int bits)
{
    uint32_t r = 0;
    for (int i = 0; i < bits; ++i)
    {
        r = (r << 1) | (v & 1u);
        v >>= 1;
    }
    return r;
}

static bool huff_decode(bitstream_t *br, const huff_table_t *table, int *out_symbol)
{
    if (!br || !table || !out_symbol)
    {
        return false;
    }

    uint32_t code = 0;

    for (int len = 1; len <= PNG_BITSIZE_MAX; ++len)
    {
        uint32_t bit;
        if (!br_read(br, 1, &bit))
        {
            return false;
        }
        code |= bit << (len - 1);
        uint32_t count = table->counts[len];
        if (count != 0)
        {
            uint32_t rev = reverse_bits(code, len);
            uint32_t first_code = table->first_code[len];
            if (rev >= first_code && rev < first_code + count)
            {
                uint32_t idx = table->first_symbol[len] + (rev - first_code);
                if (idx < sizeof(table->symbols) / sizeof(table->symbols[0]))
                {
                    *out_symbol = table->symbols[idx];
                    return true;
                }
                return false;
            }
        }
    }
    return false;
}

static bool build_fixed_tables(huff_table_t *litlen, huff_table_t *dist)
{
    static bool built = false;
    static huff_table_t fixed_litlen;
    static huff_table_t fixed_dist;

    if (built)
    {
        if (litlen)
        {
            *litlen = fixed_litlen;
        }
        if (dist)
        {
            *dist = fixed_dist;
        }
        return true;
    }

    uint8_t lens[288];
    for (int i = 0; i <= 143; ++i) lens[i] = 8;
    for (int i = 144; i <= 255; ++i) lens[i] = 9;
    for (int i = 256; i <= 279; ++i) lens[i] = 7;
    for (int i = 280; i <= 287; ++i) lens[i] = 8;
    if (!huff_build(&fixed_litlen, lens, 288))
    {
        return false;
    }

    uint8_t dist_lens[32];
    for (int i = 0; i < 32; ++i) dist_lens[i] = 5;
    if (!huff_build(&fixed_dist, dist_lens, 32))
    {
        return false;
    }

    built = true;
    if (litlen)
    {
        *litlen = fixed_litlen;
    }
    if (dist)
    {
        *dist = fixed_dist;
    }
    return true;
}

static bool parse_dynamic_trees(bitstream_t *br, huff_table_t *litlen, huff_table_t *dist, const char **err_out)
{
#define PNG_TREE_ERR(msg) do { if (err_out) *(err_out) = (msg); return false; } while (0)
    static const int code_order[19] = {
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5,
        11, 4, 12, 3, 13, 2, 14, 1, 15
    };

    uint32_t hlit, hdist, hclen;
    if (!br_read(br, 5, &hlit) || !br_read(br, 5, &hdist) || !br_read(br, 4, &hclen))
    {
        PNG_TREE_ERR("dynamic header bits exhausted");
    }
    int litlen_count = (int)(hlit + 257);
    int dist_count = (int)(hdist + 1);
    int code_count = (int)(hclen + 4);

    uint8_t code_lengths[19] = { 0 };
    for (int i = 0; i < code_count; ++i)
    {
        uint32_t v = 0;
        if (!br_read(br, 3, &v))
        {
            PNG_TREE_ERR("code length header exhausted");
        }
        code_lengths[code_order[i]] = (uint8_t)v;
    }

    huff_table_t code_table;
    if (!huff_build(&code_table, code_lengths, 19))
    {
        PNG_TREE_ERR("code length table build failed");
    }

    uint8_t lengths[288 + 32] = { 0 };
    int idx = 0;
    while (idx < litlen_count + dist_count)
    {
        int sym = 0;
        if (!huff_decode(br, &code_table, &sym))
        {
            PNG_TREE_ERR("code length decode failed");
        }

        if (sym <= 15)
        {
            lengths[idx++] = (uint8_t)sym;
            continue;
        }

        uint32_t repeat = 0;
        uint8_t value = 0;
        if (sym == 16)
        {
            if (idx == 0) return false;
            value = lengths[idx - 1];
            if (!br_read(br, 2, &repeat)) return false;
            repeat += 3;
        }
        else if (sym == 17)
        {
            value = 0;
            if (!br_read(br, 3, &repeat)) return false;
            repeat += 3;
        }
        else if (sym == 18)
        {
            value = 0;
            if (!br_read(br, 7, &repeat)) return false;
            repeat += 11;
        }
        else
        {
            return false;
        }

        if (idx + (int)repeat > litlen_count + dist_count)
        {
            PNG_TREE_ERR("repeat overruns table");
        }
        for (uint32_t r = 0; r < repeat; ++r)
        {
            lengths[idx++] = value;
        }
    }

    uint8_t lit_lens[288] = { 0 };
    uint8_t dist_lens[32] = { 0 };
    for (int i = 0; i < litlen_count; ++i)
    {
        lit_lens[i] = lengths[i];
    }
    for (int i = 0; i < dist_count; ++i)
    {
        dist_lens[i] = lengths[litlen_count + i];
    }
    if (lit_lens[256] == 0)
    {
        PNG_TREE_ERR("missing end-of-block");
    }
    if (!huff_build(litlen, lit_lens, 288))
    {
        PNG_TREE_ERR("lit/len table build failed");
    }

    bool any_dist = false;
    for (int i = 0; i < dist_count; ++i)
    {
        if (dist_lens[i] != 0)
        {
            any_dist = true;
            break;
        }
    }
    if (!any_dist)
    {
        dist_lens[0] = 1;
    }
    if (!huff_build(dist, dist_lens, 32))
    {
        PNG_TREE_ERR("distance table build failed");
    }
    return true;
#undef PNG_TREE_ERR
}

static bool zlib_inflate(const uint8_t *data,
                         size_t size,
                         uint8_t *out,
                         size_t out_capacity,
                         size_t *out_size,
                         const char **err_out)
{
#define PNG_ERR(msg) do { if (err_out) *(err_out) = (msg); return false; } while (0)
    if (!data || size < 6 || !out || out_capacity == 0 || !out_size)
    {
        PNG_ERR("invalid zlib input");
    }

    uint8_t cmf = data[0];
    uint8_t flg = data[1];
    if ((cmf & 0x0F) != 8)
    {
        PNG_ERR("bad CMF");
    }
    if (((cmf << 8) | flg) % 31 != 0)
    {
        PNG_ERR("bad FCHECK");
    }
    if (flg & 0x20)
    {
        PNG_ERR("preset dictionary unsupported");
    }

    bitstream_t br = {
        .data = data + 2,
        .size = (size >= 6) ? (size - 6) : 0,
        .pos = 0,
        .bitbuf = 0,
        .bitcount = 0
    };

    size_t written = 0;
    bool last_block = false;

    static const uint16_t length_base[29] = {
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13,
        15, 17, 19, 23, 27, 31, 35, 43, 51, 59,
        67, 83, 99, 115, 131, 163, 195, 227, 258
    };
    static const uint8_t length_extra[29] = {
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1,
        1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
        4, 4, 4, 4, 5, 5, 5, 5, 0
    };
    static const uint16_t dist_base[30] = {
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25,
        33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
        1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577
    };
    static const uint8_t dist_extra[30] = {
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3,
        4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
        9, 9, 10, 10, 11, 11, 12, 12, 13, 13
    };

    huff_table_t litlen = {0};
    huff_table_t dist = {0};

    while (!last_block)
    {
        uint32_t bfinal = 0, btype = 0;
        if (!br_read(&br, 1, &bfinal) || !br_read(&br, 2, &btype))
        {
            PNG_ERR("header bits exhausted");
        }
        last_block = (bfinal != 0);

        if (btype == 0)
        {
            br_align_byte(&br);
            uint32_t len = 0, nlen = 0;
            if (!br_read(&br, 16, &len) || !br_read(&br, 16, &nlen))
            {
                PNG_ERR("stored length read failed");
            }
            if ((len ^ 0xFFFFu) != nlen)
            {
                PNG_ERR("stored length mismatch");
            }
            if (br.pos + len > br.size)
            {
                PNG_ERR("stored block overruns input");
            }
            if (written + len > out_capacity)
            {
                PNG_ERR("stored block overruns output");
            }
            memcpy(out + written, br.data + br.pos, len);
            br.pos += len;
            written += len;
            continue;
        }

        if (btype == 1)
        {
            if (!build_fixed_tables(&litlen, &dist))
            {
                PNG_ERR("fixed tables build failed");
            }
        }
        else if (btype == 2)
        {
            if (!parse_dynamic_trees(&br, &litlen, &dist, err_out))
            {
                PNG_ERR(*err_out ? *err_out : "dynamic tables parse failed");
            }
        }
        else
        {
            PNG_ERR("unsupported BTYPE");
        }

        while (true)
        {
            int sym = 0;
            if (!huff_decode(&br, &litlen, &sym))
            {
                PNG_ERR("litlen decode failed");
            }

            if (sym < 256)
            {
                if (written >= out_capacity)
                {
                    PNG_ERR("output overflow");
                }
                out[written++] = (uint8_t)sym;
                continue;
            }
            if (sym == 256)
            {
                break;
            }

            int len_idx = sym - 257;
            if (len_idx < 0 || len_idx >= 29)
            {
                PNG_ERR("length symbol out of range");
            }
            uint32_t length = length_base[len_idx];
            uint32_t extra_bits = length_extra[len_idx];
            if (extra_bits)
            {
                uint32_t extra_val = 0;
                if (!br_read(&br, (int)extra_bits, &extra_val))
                {
                    PNG_ERR("length extra bits exhausted");
                }
                length += extra_val;
            }

            int dist_sym = 0;
            if (!huff_decode(&br, &dist, &dist_sym))
            {
                PNG_ERR("distance decode failed");
            }
            if (dist_sym < 0 || dist_sym >= 30)
            {
                PNG_ERR("distance symbol out of range");
            }
            uint32_t distance = dist_base[dist_sym];
            uint8_t dist_bits = dist_extra[dist_sym];
            if (dist_bits)
            {
                uint32_t extra_val = 0;
                if (!br_read(&br, dist_bits, &extra_val))
                {
                    PNG_ERR("distance extra bits exhausted");
                }
                distance += extra_val;
            }

            if (distance == 0 || distance > written)
            {
                PNG_ERR("invalid distance");
            }
            if (written + length > out_capacity)
            {
                PNG_ERR("match overruns output");
            }
            for (uint32_t i = 0; i < length; ++i)
            {
                out[written] = out[written - distance];
                ++written;
            }
        }
    }

    *out_size = written;
    return true;
#undef PNG_ERR
}

static uint8_t png_paeth(uint8_t a, uint8_t b, uint8_t c)
{
    int p = (int)a + (int)b - (int)c;
    int pa = p - (int)a;
    if (pa < 0) pa = -pa;
    int pb = p - (int)b;
    if (pb < 0) pb = -pb;
    int pc = p - (int)c;
    if (pc < 0) pc = -pc;

    if (pa <= pb && pa <= pc) return a;
    if (pb <= pc) return b;
    return c;
}

static bool png_apply_filters(const uint8_t *scanlines,
                              uint32_t width,
                              uint32_t height,
                              int bpp,
                              video_color_t *out_pixels)
{
    size_t row_bytes = (size_t)width * (size_t)bpp;
    const uint8_t *prev = NULL;
    const uint8_t *cursor = scanlines;

    for (uint32_t y = 0; y < height; ++y)
    {
        uint8_t filter = *cursor++;
        const uint8_t *row = cursor;
        uint8_t *recon = (uint8_t *)cursor;

        for (size_t i = 0; i < row_bytes; ++i)
        {
            uint8_t left = (i >= (size_t)bpp) ? recon[i - bpp] : 0;
            uint8_t up = prev ? prev[i] : 0;
            uint8_t up_left = (prev && i >= (size_t)bpp) ? prev[i - bpp] : 0;
            uint8_t raw = row[i];

            switch (filter)
            {
                case 0: /* None */
                    recon[i] = raw;
                    break;
                case 1: /* Sub */
                    recon[i] = (uint8_t)(raw + left);
                    break;
                case 2: /* Up */
                    recon[i] = (uint8_t)(raw + up);
                    break;
                case 3: /* Average */
                    recon[i] = (uint8_t)(raw + (uint8_t)((left + up) / 2));
                    break;
                case 4: /* Paeth */
                    recon[i] = (uint8_t)(raw + png_paeth(left, up, up_left));
                    break;
                default:
                    return false;
            }
        }

        for (uint32_t x = 0; x < width; ++x)
        {
            size_t offset = (size_t)x * (size_t)bpp;
            uint8_t r = recon[offset];
            uint8_t g = recon[offset + 1];
            uint8_t b = recon[offset + 2];
            uint8_t a = (bpp == 4) ? recon[offset + 3] : 0xFF;
            out_pixels[(size_t)y * width + x] =
                ((video_color_t)a << 24) |
                ((video_color_t)r << 16) |
                ((video_color_t)g << 8) |
                (video_color_t)b;
        }

        prev = recon;
        cursor += row_bytes;
    }

    return true;
}

int png_decode_rgba32(const uint8_t *png,
                      size_t len,
                      video_color_t **out_pixels,
                      int *out_w,
                      int *out_h,
                      int *out_stride_bytes)
{
    png_set_error("invalid arguments");
    if (!png || len < PNG_SIG_SIZE || !out_pixels || !out_w || !out_h || !out_stride_bytes)
    {
        return -1;
    }

    static const uint8_t signature[PNG_SIG_SIZE] = { 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A };
    if (memcmp(png, signature, PNG_SIG_SIZE) != 0)
    {
        png_set_error("bad signature");
        return -1;
    }

    size_t pos = PNG_SIG_SIZE;
    bool have_ihdr = false;
    uint32_t width = 0, height = 0;
    int bit_depth = 0, color_type = 0;
    uint8_t *idat = NULL;
    size_t idat_size = 0;

    while (pos + PNG_CHUNK_HEADER <= len)
    {
        uint32_t chunk_len = png_read_be32(&png[pos]);
        pos += 4;
        uint32_t chunk_type = png_read_be32(&png[pos]);
        pos += 4;

        if (pos + chunk_len + PNG_CRC_SIZE > len)
        {
            png_set_error("chunk truncated");
            free(idat);
            return -1;
        }

        const uint8_t *chunk_data = &png[pos];
        pos += chunk_len + PNG_CRC_SIZE; /* skip CRC */

        switch (chunk_type)
        {
            case 0x49484452: /* IHDR */
                if (chunk_len != PNG_IHDR_LEN)
                {
                    png_set_error("bad IHDR length");
                    free(idat);
                    return -1;
                }
                width = png_read_be32(chunk_data);
                height = png_read_be32(chunk_data + 4);
                bit_depth = chunk_data[8];
                color_type = chunk_data[9];
                if (chunk_data[10] != 0 || chunk_data[11] != 0)
                {
                    png_set_error("unsupported compression/filter");
                    free(idat);
                    return -1;
                }
                if (chunk_data[12] != 0) /* interlace */
                {
                    png_set_error("interlaced PNG not supported");
                    free(idat);
                    return -1;
                }
                have_ihdr = true;
                break;

            case 0x49444154: /* IDAT */
            {
                uint8_t *new_buf = (uint8_t *)realloc(idat, idat_size + chunk_len);
                if (!new_buf)
                {
                    free(idat);
                    png_set_error("out of memory");
                    return -1;
                }
                idat = new_buf;
                memcpy(idat + idat_size, chunk_data, chunk_len);
                idat_size += chunk_len;
                break;
            }

            case 0x49454E44: /* IEND */
                pos = len; /* force exit */
                break;

            default:
                break;
        }
    }

    if (!have_ihdr || width == 0 || height == 0)
    {
        free(idat);
        png_set_error("missing IHDR");
        return -1;
    }
    if (bit_depth != 8)
    {
        free(idat);
        png_set_error("only 8-bit depth supported");
        return -1;
    }
    if (color_type != 6 && color_type != 2)
    {
        free(idat);
        png_set_error("unsupported color type");
        return -1;
    }
    if (idat_size == 0)
    {
        png_set_error("missing IDAT");
        return -1;
    }

    int bpp = (color_type == 6) ? 4 : 3;
    size_t row_bytes = (size_t)width * (size_t)bpp;
    if (row_bytes / (size_t)bpp != width)
    {
        free(idat);
        png_set_error("dimension overflow");
        return -1;
    }

    size_t expected_bytes = ((size_t)height * (row_bytes + 1));
    if (row_bytes + 1 == 0 || expected_bytes / (row_bytes + 1) != height)
    {
        free(idat);
        png_set_error("size overflow");
        return -1;
    }

    uint8_t *scanlines = (uint8_t *)malloc(expected_bytes);
    if (!scanlines)
    {
        free(idat);
        png_set_error("out of memory");
        return -1;
    }

    size_t inflated = 0;
    const char *inflate_err = NULL;
    bool ok = zlib_inflate(idat, idat_size, scanlines, expected_bytes, &inflated, &inflate_err);
    free(idat);
    if (!ok || inflated != expected_bytes)
    {
        free(scanlines);
        png_set_error(inflate_err ? inflate_err : "inflate failed");
        return -1;
    }

    video_color_t *pixels = (video_color_t *)malloc((size_t)width * (size_t)height * sizeof(video_color_t));
    if (!pixels)
    {
        free(scanlines);
        png_set_error("out of memory");
        return -1;
    }

    if (!png_apply_filters(scanlines, width, height, bpp, pixels))
    {
        free(pixels);
        free(scanlines);
        png_set_error("filter failed");
        return -1;
    }

    free(scanlines);
    png_set_error("ok");
    *out_pixels = pixels;
    *out_w = (int)width;
    *out_h = (int)height;
    *out_stride_bytes = (int)((size_t)width * sizeof(video_color_t));
    return 0;
}
