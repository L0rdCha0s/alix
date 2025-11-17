#include "atk/atk_font.h"

#include "atk_internal.h"
#include "libc.h"
#include "ttf.h"
#include "video.h"

#ifndef ATK_NO_DESKTOP_APPS
#include "vfs.h"
#else
#include "syscall_defs.h"
#endif

#define ATK_FONT_PATH "/usr/share/fonts/PublicSans.ttf"
#define ATK_FONT_PIXEL_SIZE 22
#define ATK_FONT_CACHE_FIRST 32
#define ATK_FONT_CACHE_LAST  126
#define ATK_FONT_CACHE_COUNT (ATK_FONT_CACHE_LAST - ATK_FONT_CACHE_FIRST + 1)
#define ATK_FONT_MAX_ROW_PIXELS 96

typedef struct
{
    bool ready;
    uint8_t *alpha;
    int width;
    int height;
    int stride;
    int advance;
    int bearing_x;
    int bearing_y;
} atk_font_glyph_t;

typedef struct
{
    bool ready;
    ttf_font_t font;
    ttf_font_metrics_t metrics;
    atk_font_glyph_t glyphs[ATK_FONT_CACHE_COUNT];
} atk_font_state_t;

static atk_font_state_t g_font_state = { 0 };

static bool atk_font_load(void);
static atk_font_glyph_t *atk_font_get_glyph(uint32_t codepoint);
static uint16_t rgb565_blend(uint16_t bg, uint16_t fg, uint8_t alpha);

#ifdef ATK_NO_DESKTOP_APPS
static bool atk_font_read_user(uint8_t **data_out, size_t *size_out);
#endif

bool atk_font_available(void)
{
    return atk_font_load();
}

int atk_font_text_width(const char *text)
{
    if (!text || *text == '\0')
    {
        return 0;
    }

    if (!atk_font_load())
    {
        return (int)strlen(text) * ATK_FONT_WIDTH;
    }

    int width = 0;
    for (const unsigned char *cursor = (const unsigned char *)text; *cursor; ++cursor)
    {
        atk_font_glyph_t *glyph = atk_font_get_glyph(*cursor);
        if (glyph && glyph->ready)
        {
            width += glyph->advance;
        }
        else
        {
            width += ATK_FONT_WIDTH;
        }
    }
    return width;
}

int atk_font_line_height(void)
{
    if (!atk_font_load())
    {
        return ATK_FONT_HEIGHT;
    }
    int descent = g_font_state.metrics.descent;
    if (descent < 0)
    {
        descent = -descent;
    }
    int line = g_font_state.metrics.ascent + descent;
    if (line <= 0)
    {
        line = ATK_FONT_PIXEL_SIZE;
    }
    return line;
}

int atk_font_baseline_for_rect(int top, int height)
{
    if (height <= 0)
    {
        return top;
    }

    if (!atk_font_load())
    {
        return top + height / 2 + ATK_FONT_HEIGHT / 2;
    }

    int ascent = g_font_state.metrics.ascent;
    int descent = g_font_state.metrics.descent;
    if (descent < 0)
    {
        descent = -descent;
    }
    int total = ascent + descent;
    if (total <= 0)
    {
        total = atk_font_line_height();
    }
    int offset = (height - total) / 2 + ascent;
    return top + offset;
}

void atk_font_draw_string(int x, int baseline_y, const char *text, uint16_t fg, uint16_t bg)
{
    atk_font_draw_string_clipped(x, baseline_y, text, fg, bg, NULL);
}

void atk_font_draw_string_clipped(int x,
                                  int baseline_y,
                                  const char *text,
                                  uint16_t fg,
                                  uint16_t bg,
                                  const atk_rect_t *clip)
{
    if (!text || *text == '\0')
    {
        return;
    }

    if (!atk_font_load())
    {
        (void)clip;
        int top = baseline_y - ATK_FONT_HEIGHT;
        video_draw_text(x, top, text, fg, bg);
        return;
    }

    int clip_x0 = 0;
    int clip_y0 = 0;
    int clip_x1 = VIDEO_WIDTH;
    int clip_y1 = VIDEO_HEIGHT;
    if (clip)
    {
        if (clip->width <= 0 || clip->height <= 0)
        {
            return;
        }
        if (clip->x > clip_x0) clip_x0 = clip->x;
        if (clip->y > clip_y0) clip_y0 = clip->y;
        int cx1 = clip->x + clip->width;
        int cy1 = clip->y + clip->height;
        if (cx1 < clip_x1) clip_x1 = cx1;
        if (cy1 < clip_y1) clip_y1 = cy1;

        /* allow ~10% extra space vertically to avoid clipping descenders,
           while still keeping glyphs within the broader area */
        int margin = (atk_font_line_height() + 9) / 10;
        clip_y0 -= margin;
        clip_y1 += margin;
        if (clip_x1 <= clip_x0 || clip_y1 <= clip_y0)
        {
            return;
        }
    }

    uint16_t row_pixels[ATK_FONT_MAX_ROW_PIXELS];
    int pen_x = x;

    for (const unsigned char *cursor = (const unsigned char *)text; *cursor; ++cursor)
    {
        atk_font_glyph_t *glyph = atk_font_get_glyph(*cursor);
        if (!glyph || !glyph->ready)
        {
            pen_x += ATK_FONT_WIDTH;
            continue;
        }

        if (glyph->width <= 0 || glyph->height <= 0 || !glyph->alpha)
        {
            pen_x += glyph->advance;
            continue;
        }

        if (glyph->width > ATK_FONT_MAX_ROW_PIXELS)
        {
            pen_x += glyph->advance;
            continue;
        }

        int dst_x = pen_x + glyph->bearing_x;
        int dst_y = baseline_y - glyph->bearing_y;

        int glyph_x0 = dst_x;
        int glyph_y0 = dst_y;
        int glyph_x1 = glyph_x0 + glyph->width;
        int glyph_y1 = glyph_y0 + glyph->height;

        if (glyph_x1 <= clip_x0 || glyph_x0 >= clip_x1 ||
            glyph_y1 <= clip_y0 || glyph_y0 >= clip_y1)
        {
            pen_x += glyph->advance;
            continue;
        }

        int visible_x0 = (glyph_x0 < clip_x0) ? clip_x0 : glyph_x0;
        int visible_x1 = (glyph_x1 > clip_x1) ? clip_x1 : glyph_x1;
        int visible_y0 = (glyph_y0 < clip_y0) ? clip_y0 : glyph_y0;
        int visible_y1 = (glyph_y1 > clip_y1) ? clip_y1 : glyph_y1;

        int start_col = visible_x0 - glyph_x0;
        int width = visible_x1 - visible_x0;
        int start_row = visible_y0 - glyph_y0;
        int rows = visible_y1 - visible_y0;

        if (width <= 0 || rows <= 0)
        {
            pen_x += glyph->advance;
            continue;
        }

        for (int row = 0; row < rows; ++row)
        {
            const uint8_t *src = glyph->alpha + (start_row + row) * glyph->stride + start_col;
            for (int col = 0; col < width; ++col)
            {
                uint8_t alpha = src[col];
                row_pixels[col] = rgb565_blend(bg, fg, alpha);
            }
            video_blit_rgb565(visible_x0,
                              visible_y0 + row,
                              width,
                              1,
                              row_pixels,
                              width * (int)sizeof(uint16_t));
        }

        pen_x += glyph->advance;
    }
}

static bool atk_font_load(void)
{
    if (g_font_state.ready)
    {
        return true;
    }

#ifndef ATK_NO_DESKTOP_APPS
    vfs_node_t *node = vfs_open_file(vfs_root(), ATK_FONT_PATH, false, false);
    if (!node)
    {
        return false;
    }
    size_t size = 0;
    const char *data = vfs_data(node, &size);
    if (!data || size == 0)
    {
        return false;
    }
    if (!ttf_font_load(&g_font_state.font, (const uint8_t *)data, size))
    {
        return false;
    }
#else
    uint8_t *buffer = NULL;
    size_t size = 0;
    if (!atk_font_read_user(&buffer, &size))
    {
        return false;
    }
    bool ok = ttf_font_load(&g_font_state.font, buffer, size);
    free(buffer);
    if (!ok)
    {
        return false;
    }
#endif

    if (!ttf_font_metrics(&g_font_state.font, ATK_FONT_PIXEL_SIZE, &g_font_state.metrics))
    {
        ttf_font_unload(&g_font_state.font);
        g_font_state.font.impl = NULL;
        return false;
    }

    g_font_state.ready = true;
    return true;
}

static atk_font_glyph_t *atk_font_get_glyph(uint32_t codepoint)
{
    if (!atk_font_load())
    {
        return NULL;
    }

    if (codepoint < ATK_FONT_CACHE_FIRST || codepoint > ATK_FONT_CACHE_LAST)
    {
        codepoint = '?';
    }

    atk_font_glyph_t *glyph = &g_font_state.glyphs[codepoint - ATK_FONT_CACHE_FIRST];
    if (glyph->ready)
    {
        return glyph;
    }

    ttf_bitmap_t bitmap;
    ttf_glyph_metrics_t metrics;
    memset(&bitmap, 0, sizeof(bitmap));
    memset(&metrics, 0, sizeof(metrics));

    if (!ttf_font_render_glyph_bitmap(&g_font_state.font,
                                      codepoint,
                                      ATK_FONT_PIXEL_SIZE,
                                      &bitmap,
                                      &metrics))
    {
        glyph->ready = true;
        glyph->width = 0;
        glyph->height = 0;
        glyph->stride = 0;
        glyph->advance = ATK_FONT_WIDTH;
        glyph->bearing_x = 0;
        glyph->bearing_y = ATK_FONT_HEIGHT;
        glyph->alpha = NULL;
        return glyph;
    }

    size_t alpha_bytes = (size_t)bitmap.stride * (size_t)bitmap.height;
    uint8_t *alpha = NULL;
    if (alpha_bytes > 0)
    {
        alpha = (uint8_t *)malloc(alpha_bytes);
        if (!alpha)
        {
            ttf_bitmap_destroy(&bitmap);
            return NULL;
        }
        for (int row = 0; row < bitmap.height; ++row)
        {
            memcpy(alpha + (size_t)row * bitmap.stride,
                   bitmap.pixels + (size_t)row * bitmap.stride,
                   (size_t)bitmap.stride);
        }
    }

    glyph->alpha = alpha;
    glyph->width = bitmap.width;
    glyph->height = bitmap.height;
    glyph->stride = bitmap.stride;
    glyph->advance = metrics.advance;
    glyph->bearing_x = metrics.bearing_x;
    glyph->bearing_y = metrics.bearing_y;
    glyph->ready = true;

    ttf_bitmap_destroy(&bitmap);
    return glyph;
}

static uint16_t rgb565_blend(uint16_t bg, uint16_t fg, uint8_t alpha)
{
    if (alpha == 0)
    {
        return bg;
    }
    if (alpha == 255)
    {
        return fg;
    }

    uint16_t br = (uint16_t)((((bg >> 11) & 0x1F) * 527 + 23) >> 6);
    uint16_t bgc = (uint16_t)((((bg >> 5) & 0x3F) * 259 + 33) >> 6);
    uint16_t bb = (uint16_t)(((bg & 0x1F) * 527 + 23) >> 6);

    uint16_t fr = (uint16_t)((((fg >> 11) & 0x1F) * 527 + 23) >> 6);
    uint16_t fgc = (uint16_t)((((fg >> 5) & 0x3F) * 259 + 33) >> 6);
    uint16_t fb = (uint16_t)(((fg & 0x1F) * 527 + 23) >> 6);

    uint16_t rr = (uint16_t)((fr * alpha + br * (255 - alpha)) / 255);
    uint16_t rg = (uint16_t)((fgc * alpha + bgc * (255 - alpha)) / 255);
    uint16_t rb = (uint16_t)((fb * alpha + bb * (255 - alpha)) / 255);

    return (uint16_t)(((rr & 0xF8) << 8) | ((rg & 0xFC) << 3) | (rb >> 3));
}

#ifdef ATK_NO_DESKTOP_APPS
static bool atk_font_read_user(uint8_t **data_out, size_t *size_out)
{
    if (!data_out || !size_out)
    {
        return false;
    }

    int fd = open(ATK_FONT_PATH, SYSCALL_OPEN_READ);
    if (fd < 0)
    {
        return false;
    }

    size_t capacity = 0;
    size_t size = 0;
    uint8_t *buffer = NULL;

    while (1)
    {
        if (size == capacity)
        {
            size_t new_capacity = capacity ? capacity * 2 : 4096;
            uint8_t *new_buffer = (uint8_t *)realloc(buffer, new_capacity);
            if (!new_buffer)
            {
                free(buffer);
                close(fd);
                return false;
            }
            buffer = new_buffer;
            capacity = new_capacity;
        }

        ssize_t bytes = read(fd, buffer + size, capacity - size);
        if (bytes < 0)
        {
            free(buffer);
            close(fd);
            return false;
        }
        if (bytes == 0)
        {
            break;
        }
        size += (size_t)bytes;
    }

    close(fd);

    if (size == 0)
    {
        free(buffer);
        return false;
    }

    *data_out = buffer;
    *size_out = size;
    return true;
}
#endif
