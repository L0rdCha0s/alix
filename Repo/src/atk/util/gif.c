#include "atk/util/gif.h"

#ifdef GIF_HOST_BUILD
#include <stdlib.h>
#include <string.h>
#else
#include "heap.h"
#include "libc.h"
#endif

#define GIF_SIG_SIZE 6
#define GIF_LSD_SIZE 7
#define GIF_TRAILER 0x3B
#define GIF_EXTENSION 0x21
#define GIF_IMAGE_SEPARATOR 0x2C
#define GIF_GCE_LABEL 0xF9

static const char *g_gif_error = "ok";

static void gif_set_error(const char *msg)
{
    g_gif_error = msg ? msg : "gif error";
}

const char *gif_last_error(void)
{
    return g_gif_error;
}

static uint16_t gif_read_le16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static bool gif_read_color_table(const uint8_t *data,
                                 size_t len,
                                 size_t count,
                                 video_color_t **out_table)
{
    if (!data || !out_table || count == 0 || count > 256)
    {
        return false;
    }

    size_t needed = count * 3;
    if (len < needed)
    {
        return false;
    }

    video_color_t *table = (video_color_t *)malloc(count * sizeof(video_color_t));
    if (!table)
    {
        return false;
    }

    for (size_t i = 0; i < count; ++i)
    {
        size_t base = i * 3;
        uint8_t r = data[base];
        uint8_t g = data[base + 1];
        uint8_t b = data[base + 2];
        table[i] = video_make_color(r, g, b);
    }

    *out_table = table;
    return true;
}

static bool gif_collect_sub_blocks(const uint8_t *data,
                                   size_t len,
                                   size_t *pos_io,
                                   uint8_t **out_buf,
                                   size_t *out_len)
{
    if (!data || !pos_io || !out_buf || !out_len)
    {
        return false;
    }

    size_t pos = *pos_io;
    size_t total = 0;
    uint8_t *buf = NULL;

    while (pos < len)
    {
        uint8_t block = data[pos++];
        if (block == 0)
        {
            *pos_io = pos;
            *out_buf = buf;
            *out_len = total;
            return true;
        }
        if (pos + block > len)
        {
            free(buf);
            return false;
        }
        if (total + block < total)
        {
            free(buf);
            return false;
        }
        uint8_t *new_buf = (uint8_t *)realloc(buf, total + block);
        if (!new_buf)
        {
            free(buf);
            return false;
        }
        buf = new_buf;
        memcpy(buf + total, data + pos, block);
        total += block;
        pos += block;
    }

    free(buf);
    return false;
}

typedef struct
{
    const uint8_t *data;
    size_t len;
    size_t byte_pos;
    uint32_t bit_buf;
    int bit_count;
} gif_bit_reader_t;

static bool gif_read_code(gif_bit_reader_t *reader, int code_size, int *out_code)
{
    if (!reader || !out_code || code_size <= 0 || code_size > 12)
    {
        return false;
    }

    while (reader->bit_count < code_size)
    {
        if (reader->byte_pos >= reader->len)
        {
            return false;
        }
        reader->bit_buf |= ((uint32_t)reader->data[reader->byte_pos++]) << reader->bit_count;
        reader->bit_count += 8;
    }

    uint32_t mask = (1u << code_size) - 1u;
    *out_code = (int)(reader->bit_buf & mask);
    reader->bit_buf >>= code_size;
    reader->bit_count -= code_size;
    return true;
}

static bool gif_decode_indices(const uint8_t *data,
                               size_t data_len,
                               uint8_t min_code_size,
                               uint8_t *out,
                               size_t out_len)
{
    if (!data || data_len == 0 || !out || out_len == 0)
    {
        gif_set_error("invalid lzw data");
        return false;
    }
    if (min_code_size < 2 || min_code_size > 8)
    {
        gif_set_error("unsupported lzw code size");
        return false;
    }

    uint16_t *prefix = (uint16_t *)malloc(4096 * sizeof(uint16_t));
    uint8_t *suffix = (uint8_t *)malloc(4096);
    uint8_t *stack = (uint8_t *)malloc(4096);
    if (!prefix || !suffix || !stack)
    {
        free(prefix);
        free(suffix);
        free(stack);
        gif_set_error("out of memory");
        return false;
    }

    int clear_code = 1 << min_code_size;
    int end_code = clear_code + 1;
    int code_size = min_code_size + 1;
    int available = clear_code + 2;
    int old_code = -1;
    uint8_t first = 0;

    for (int i = 0; i < clear_code; ++i)
    {
        prefix[i] = 0xFFFFu;
        suffix[i] = (uint8_t)i;
    }

    gif_bit_reader_t reader = {
        .data = data,
        .len = data_len,
        .byte_pos = 0,
        .bit_buf = 0,
        .bit_count = 0
    };

    size_t out_pos = 0;
    while (out_pos < out_len)
    {
        int code = 0;
        if (!gif_read_code(&reader, code_size, &code))
        {
            gif_set_error("truncated lzw stream");
            break;
        }

        if (code == clear_code)
        {
            code_size = min_code_size + 1;
            available = clear_code + 2;
            old_code = -1;
            continue;
        }
        if (code == end_code)
        {
            break;
        }

        if (old_code < 0)
        {
            if (code >= available)
            {
                gif_set_error("bad lzw code");
                break;
            }
            out[out_pos++] = (uint8_t)code;
            first = (uint8_t)code;
            old_code = code;
            continue;
        }

        int in_code = code;
        int top = 0;
        if (code >= available)
        {
            if (code != available)
            {
                gif_set_error("bad lzw code");
                break;
            }
            if (top >= 4096)
            {
                gif_set_error("lzw stack overflow");
                break;
            }
            stack[top++] = first;
            code = old_code;
        }

        while (code >= clear_code)
        {
            if (code >= 4096)
            {
                gif_set_error("lzw code overflow");
                goto decode_fail;
            }
            if (top >= 4096)
            {
                gif_set_error("lzw stack overflow");
                goto decode_fail;
            }
            stack[top++] = suffix[code];
            code = prefix[code];
        }

        first = (uint8_t)code;
        if (top >= 4096)
        {
            gif_set_error("lzw stack overflow");
            break;
        }
        stack[top++] = first;

        while (top > 0 && out_pos < out_len)
        {
            out[out_pos++] = stack[--top];
        }
        if (out_pos >= out_len)
        {
            old_code = in_code;
            break;
        }

        if (available < 4096)
        {
            prefix[available] = (uint16_t)old_code;
            suffix[available] = first;
            available++;
            if (available == (1 << code_size) && code_size < 12)
            {
                code_size++;
            }
        }
        old_code = in_code;
    }

    if (out_pos != out_len)
    {
        gif_set_error("lzw output truncated");
        goto decode_fail;
    }

    free(prefix);
    free(suffix);
    free(stack);
    return true;

decode_fail:
    free(prefix);
    free(suffix);
    free(stack);
    return false;
}

int gif_decode_rgba32(const uint8_t *gif,
                      size_t len,
                      video_color_t **out_pixels,
                      int *out_w,
                      int *out_h,
                      int *out_stride_bytes)
{
    gif_set_error("invalid arguments");
    if (!gif || len < (GIF_SIG_SIZE + GIF_LSD_SIZE) ||
        !out_pixels || !out_w || !out_h || !out_stride_bytes)
    {
        return -1;
    }

    if (memcmp(gif, "GIF87a", 6) != 0 && memcmp(gif, "GIF89a", 6) != 0)
    {
        gif_set_error("bad signature");
        return -1;
    }

    uint16_t canvas_w = gif_read_le16(gif + 6);
    uint16_t canvas_h = gif_read_le16(gif + 8);
    if (canvas_w == 0 || canvas_h == 0)
    {
        gif_set_error("invalid dimensions");
        return -1;
    }

    uint8_t packed = gif[10];
    bool gct_flag = (packed & 0x80u) != 0;
    size_t gct_count = gct_flag ? (size_t)1u << ((packed & 0x07u) + 1u) : 0;
    uint8_t bg_index = gif[11];

    size_t pos = GIF_SIG_SIZE + GIF_LSD_SIZE;
    video_color_t *gct = NULL;
    if (gct_flag)
    {
        size_t gct_bytes = gct_count * 3u;
        if (pos + gct_bytes > len)
        {
            gif_set_error("truncated global color table");
            return -1;
        }
        if (!gif_read_color_table(gif + pos, len - pos, gct_count, &gct))
        {
            gif_set_error("global color table failed");
            return -1;
        }
        pos += gct_bytes;
    }

    bool have_transparency = false;
    uint8_t transparent_index = 0;
    video_color_t *pixels = NULL;
    bool decoded = false;

    while (pos < len)
    {
        uint8_t separator = gif[pos++];
        if (separator == GIF_TRAILER)
        {
            break;
        }
        if (separator == GIF_EXTENSION)
        {
            if (pos >= len)
            {
                gif_set_error("truncated extension");
                break;
            }
            uint8_t label = gif[pos++];
            if (label == GIF_GCE_LABEL)
            {
                if (pos >= len)
                {
                    gif_set_error("truncated gce");
                    break;
                }
                uint8_t block_size = gif[pos++];
                if (block_size != 4 || pos + block_size > len)
                {
                    gif_set_error("bad gce size");
                    break;
                }
                uint8_t flags = gif[pos];
                have_transparency = (flags & 0x01u) != 0;
                transparent_index = gif[pos + 3];
                pos += block_size;
                if (pos >= len || gif[pos] != 0)
                {
                    gif_set_error("missing gce terminator");
                    break;
                }
                pos += 1;
            }
            else
            {
                uint8_t *skip = NULL;
                size_t skip_len = 0;
                size_t skip_pos = pos;
                if (!gif_collect_sub_blocks(gif, len, &skip_pos, &skip, &skip_len))
                {
                    gif_set_error("truncated extension data");
                    break;
                }
                free(skip);
                pos = skip_pos;
            }
            continue;
        }
        if (separator != GIF_IMAGE_SEPARATOR)
        {
            gif_set_error("unknown block");
            break;
        }

        if (pos + 9 > len)
        {
            gif_set_error("truncated image descriptor");
            break;
        }
        uint16_t left = gif_read_le16(gif + pos);
        uint16_t top = gif_read_le16(gif + pos + 2);
        uint16_t img_w = gif_read_le16(gif + pos + 4);
        uint16_t img_h = gif_read_le16(gif + pos + 6);
        uint8_t img_packed = gif[pos + 8];
        pos += 9;

        if (img_w == 0 || img_h == 0)
        {
            gif_set_error("invalid image size");
            break;
        }
        if ((uint32_t)left + (uint32_t)img_w > canvas_w ||
            (uint32_t)top + (uint32_t)img_h > canvas_h)
        {
            gif_set_error("image outside canvas");
            break;
        }

        bool lct_flag = (img_packed & 0x80u) != 0;
        bool interlaced = (img_packed & 0x40u) != 0;
        size_t lct_count = lct_flag ? (size_t)1u << ((img_packed & 0x07u) + 1u) : 0;
        video_color_t *lct = NULL;
        video_color_t *color_table = gct;
        size_t color_count = gct_count;

        if (lct_flag)
        {
            size_t lct_bytes = lct_count * 3u;
            if (pos + lct_bytes > len)
            {
                gif_set_error("truncated local color table");
                break;
            }
            if (!gif_read_color_table(gif + pos, len - pos, lct_count, &lct))
            {
                gif_set_error("local color table failed");
                break;
            }
            color_table = lct;
            color_count = lct_count;
            pos += lct_bytes;
        }

        if (!color_table || color_count == 0)
        {
            gif_set_error("missing color table");
            free(lct);
            break;
        }
        if (pos >= len)
        {
            gif_set_error("truncated image data");
            free(lct);
            break;
        }
        uint8_t min_code_size = gif[pos++];

        uint8_t *lzw_data = NULL;
        size_t lzw_len = 0;
        if (!gif_collect_sub_blocks(gif, len, &pos, &lzw_data, &lzw_len))
        {
            gif_set_error("truncated image data");
            free(lct);
            break;
        }

        size_t img_pixels = (size_t)img_w * (size_t)img_h;
        if (img_pixels / img_w != img_h)
        {
            gif_set_error("image size overflow");
            free(lzw_data);
            free(lct);
            break;
        }

        uint8_t *indices = (uint8_t *)malloc(img_pixels);
        if (!indices)
        {
            gif_set_error("out of memory");
            free(lzw_data);
            free(lct);
            break;
        }

        if (!gif_decode_indices(lzw_data, lzw_len, min_code_size, indices, img_pixels))
        {
            free(indices);
            free(lzw_data);
            free(lct);
            break;
        }

        free(lzw_data);

        size_t canvas_pixels = (size_t)canvas_w * (size_t)canvas_h;
        if (canvas_pixels / canvas_w != canvas_h)
        {
            gif_set_error("canvas size overflow");
            free(indices);
            free(lct);
            break;
        }

        pixels = (video_color_t *)malloc(canvas_pixels * sizeof(video_color_t));
        if (!pixels)
        {
            gif_set_error("out of memory");
            free(indices);
            free(lct);
            break;
        }

        video_color_t bg = video_make_color(0x00, 0x00, 0x00);
        if (gct && bg_index < gct_count)
        {
            bg = gct[bg_index];
        }
        for (size_t i = 0; i < canvas_pixels; ++i)
        {
            pixels[i] = bg;
        }

        size_t src_index = 0;
        if (!interlaced)
        {
            for (uint16_t y = 0; y < img_h; ++y)
            {
                size_t dst_row = ((size_t)top + y) * canvas_w + left;
                for (uint16_t x = 0; x < img_w; ++x)
                {
                    if (src_index >= img_pixels)
                    {
                        break;
                    }
                    uint8_t ci = indices[src_index++];
                    if (have_transparency && ci == transparent_index)
                    {
                        pixels[dst_row + x] = 0x00000000u;
                    }
                    else if (ci < color_count)
                    {
                        pixels[dst_row + x] = color_table[ci];
                    }
                    else
                    {
                        pixels[dst_row + x] = bg;
                    }
                }
            }
        }
        else
        {
            static const uint8_t pass_starts[4] = {0, 4, 2, 1};
            static const uint8_t pass_steps[4] = {8, 8, 4, 2};
            for (int pass = 0; pass < 4; ++pass)
            {
                for (uint16_t y = pass_starts[pass]; y < img_h; y += pass_steps[pass])
                {
                    size_t dst_row = ((size_t)top + y) * canvas_w + left;
                    for (uint16_t x = 0; x < img_w; ++x)
                    {
                        if (src_index >= img_pixels)
                        {
                            break;
                        }
                        uint8_t ci = indices[src_index++];
                        if (have_transparency && ci == transparent_index)
                        {
                            pixels[dst_row + x] = 0x00000000u;
                        }
                        else if (ci < color_count)
                        {
                            pixels[dst_row + x] = color_table[ci];
                        }
                        else
                        {
                            pixels[dst_row + x] = bg;
                        }
                    }
                }
            }
        }

        free(indices);
        free(lct);
        decoded = true;
        break;
    }

    free(gct);

    if (!decoded || !pixels)
    {
        free(pixels);
        if (g_gif_error && strcmp(g_gif_error, "ok") == 0)
        {
            gif_set_error("no image found");
        }
        return -1;
    }

    *out_pixels = pixels;
    *out_w = (int)canvas_w;
    *out_h = (int)canvas_h;
    *out_stride_bytes = (int)(canvas_w * sizeof(video_color_t));
    gif_set_error("ok");
    return 0;
}
