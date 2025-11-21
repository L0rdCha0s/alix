#include "video_surface.h"

#include "video.h"
#include "font.h"
#include "libc.h"
#include <stddef.h>

#define FONT_WIDTH 8
#define FONT_HEIGHT 16

static video_color_t *g_surface = NULL;
static uint32_t g_surface_width = VIDEO_WIDTH;
static uint32_t g_surface_height = VIDEO_HEIGHT;
static bool g_surface_dirty = false;
static bool g_surface_track_dirty = false;

static inline bool surface_ready(void)
{
    return (g_surface != NULL && g_surface_width > 0 && g_surface_height > 0);
}

static inline void surface_touch(void)
{
    if (!surface_ready())
    {
        return;
    }
    g_surface_dirty = true;
}

static inline void surface_log(const char *msg, uint64_t value)
{
    (void)msg;
    (void)value;
}

void video_surface_attach(video_color_t *buffer, uint32_t width, uint32_t height)
{
    surface_log("attach buffer=", (uintptr_t)buffer);
    surface_log("attach width=", width);
    surface_log("attach height=", height);
    g_surface = buffer;
    g_surface_width = width;
    g_surface_height = height;
    g_surface_track_dirty = false;
    surface_touch();
}

void video_surface_detach(void)
{
    surface_log("detach buffer=", (uintptr_t)g_surface);
    g_surface = NULL;
    g_surface_width = 0;
    g_surface_height = 0;
    g_surface_dirty = false;
    g_surface_track_dirty = false;
}

video_color_t video_make_color(uint8_t r, uint8_t g, uint8_t b)
{
    return 0xFF000000U | ((video_color_t)r << 16) | ((video_color_t)g << 8) | (video_color_t)b;
}

void video_init(void) {}
bool video_enter_mode(void) { return true; }
void video_run_loop(void) {}
void video_exit_mode(void) {}
void video_on_mouse_event(int dx, int dy, bool left_pressed)
{
    (void)dx;
    (void)dy;
    (void)left_pressed;
}

void video_cursor_set_shape(video_cursor_shape_t shape)
{
    (void)shape;
}

void video_fill(video_color_t color)
{
    surface_log("fill color=", color);
    if (!surface_ready())
    {
        return;
    }
    size_t pixels = (size_t)g_surface_width * (size_t)g_surface_height;
    for (size_t i = 0; i < pixels; ++i)
    {
        g_surface[i] = color;
    }
    surface_touch();
}

static void video_draw_char(int x, int y, char c, video_color_t fg, video_color_t bg)
{
    if (!surface_ready())
    {
        return;
    }

    uint8_t glyph[FONT_BASIC_HEIGHT_X2];
    font_basic_copy_glyph8x16((uint8_t)c, glyph);

    bool wrote = false;
    for (int row = 0; row < FONT_BASIC_HEIGHT_X2; ++row)
    {
        int dst_y = y + row;
        if (dst_y < 0 || dst_y >= (int)g_surface_height)
        {
            continue;
        }
        video_color_t *dst = &g_surface[(size_t)dst_y * g_surface_width];
        uint8_t bits = glyph[row];
        for (int col = 0; col < FONT_WIDTH; ++col)
        {
            int dst_x = x + col;
            if (dst_x < 0 || dst_x >= (int)g_surface_width)
            {
                continue;
            }
            video_color_t color = (bits & (1U << (7 - col))) ? fg : bg;
            dst[dst_x] = color;
            wrote = true;
        }
    }
    if (wrote)
    {
        surface_touch();
    }
}

void video_draw_rect(int x, int y, int width, int height, video_color_t color)
{
    surface_log("rect x=", x);
    surface_log("rect y=", y);
    surface_log("rect w=", width);
    surface_log("rect h=", height);
    if (!surface_ready() || width <= 0 || height <= 0)
    {
        return;
    }

    int x0 = x;
    int y0 = y;
    int x1 = x + width;
    int y1 = y + height;

    if (x1 <= 0 || y1 <= 0 || x0 >= (int)g_surface_width || y0 >= (int)g_surface_height)
    {
        return;
    }

    if (x0 < 0) x0 = 0;
    if (y0 < 0) y0 = 0;
    if (x1 > (int)g_surface_width)  x1 = (int)g_surface_width;
    if (y1 > (int)g_surface_height) y1 = (int)g_surface_height;

    for (int row = y0; row < y1; ++row)
    {
        video_color_t *dst = &g_surface[(size_t)row * g_surface_width + x0];
        for (int col = x0; col < x1; ++col)
        {
            *dst++ = color;
        }
    }
    surface_touch();
}

void video_draw_rect_outline(int x, int y, int width, int height, video_color_t color)
{
    surface_log("rect_outline x=", x);
    surface_log("rect_outline y=", y);
    surface_log("rect_outline w=", width);
    surface_log("rect_outline h=", height);
    if (width <= 0 || height <= 0)
    {
        return;
    }
    video_draw_rect(x, y, width, 1, color);
    video_draw_rect(x, y + height - 1, width, 1, color);
    video_draw_rect(x, y, 1, height, color);
    video_draw_rect(x + width - 1, y, 1, height, color);
}

void video_draw_text(int x, int y, const char *text, video_color_t fg, video_color_t bg)
{
    surface_log("text x=", x);
    surface_log("text y=", y);
    if (!text)
    {
        return;
    }
    for (size_t i = 0; text[i] != '\0'; ++i)
    {
        video_draw_char(x + (int)(i * FONT_WIDTH), y, text[i], fg, bg);
    }
}

void video_draw_text_clipped(int x, int y, int width, int height,
                             const char *text, video_color_t fg, video_color_t bg)
{
    if (!text || width <= 0 || height <= 0)
    {
        return;
    }

    int max_chars_per_line = width / FONT_WIDTH;
    if (max_chars_per_line <= 0)
    {
        return;
    }

    int line_height = FONT_HEIGHT + 2;
    int max_lines = height / line_height;
    if (max_lines <= 0)
    {
        return;
    }

    const char *cursor = text;
    int drawn_lines = 0;
    char buffer[256];
    int buf_cap = (int)sizeof(buffer) - 1;

    while (drawn_lines < max_lines && *cursor != '\0')
    {
        const char *line_start = cursor;
        int chars = 0;
        while (*cursor != '\0' && *cursor != '\n' && chars < max_chars_per_line)
        {
            ++cursor;
            ++chars;
        }

        int copy_len = chars;
        if (copy_len > buf_cap)
        {
            copy_len = buf_cap;
        }
        for (int i = 0; i < copy_len; ++i)
        {
            buffer[i] = line_start[i];
        }
        buffer[copy_len] = '\0';

        video_draw_text(x, y + drawn_lines * line_height, buffer, fg, bg);
        ++drawn_lines;

        if (*cursor == '\n')
        {
            ++cursor;
        }
    }
}

void video_invalidate_rect(int x, int y, int width, int height)
{
    (void)x;
    (void)y;
    (void)width;
    (void)height;
    surface_touch();
}

void video_invalidate_all(void)
{
    surface_touch();
}

void video_blit_rgba32(int x,
                       int y,
                       int width,
                       int height,
                       const video_color_t *pixels,
                       int stride_bytes,
                       bool use_alpha)
{
    if (!surface_ready() || !pixels || width <= 0 || height <= 0)
    {
        return;
    }

    if (stride_bytes <= 0)
    {
        stride_bytes = width * (int)sizeof(video_color_t);
    }

    int x0 = x;
    int y0 = y;
    int x1 = x + width;
    int y1 = y + height;
    int src_x = 0;
    int src_y = 0;

    if (x0 < 0) { src_x = -x0; x0 = 0; }
    if (y0 < 0) { src_y = -y0; y0 = 0; }
    if (x1 > (int)g_surface_width)  x1 = (int)g_surface_width;
    if (y1 > (int)g_surface_height) y1 = (int)g_surface_height;

    int copy_w = x1 - x0;
    int copy_h = y1 - y0;
    if (copy_w <= 0 || copy_h <= 0)
    {
        return;
    }

    const uint8_t *row = (const uint8_t *)pixels +
                         (size_t)src_y * (size_t)stride_bytes +
                         (size_t)src_x * sizeof(video_color_t);
    for (int row_idx = 0; row_idx < copy_h; ++row_idx)
    {
        const video_color_t *src_row = (const video_color_t *)row;
        video_color_t *dst = &g_surface[(size_t)(y0 + row_idx) * g_surface_width + x0];
        if (!use_alpha)
        {
            memcpy(dst, src_row, (size_t)copy_w * sizeof(video_color_t));
        }
        else
        {
            for (int col = 0; col < copy_w; ++col)
            {
                video_color_t src_px = src_row[col];
                uint8_t a = (uint8_t)(src_px >> 24);
                if (a == 0)
                {
                    continue;
                }
                if (a == 255)
                {
                    dst[col] = src_px;
                    continue;
                }
                uint8_t sr = (uint8_t)(src_px >> 16);
                uint8_t sg = (uint8_t)(src_px >> 8);
                uint8_t sb = (uint8_t)src_px;

                video_color_t dst_px = dst[col];
                uint8_t dr = (uint8_t)(dst_px >> 16);
                uint8_t dg = (uint8_t)(dst_px >> 8);
                uint8_t db = (uint8_t)dst_px;

                uint8_t ia = (uint8_t)(255 - a);
                uint8_t rr = (uint8_t)((sr * a + dr * ia) / 255);
                uint8_t rg = (uint8_t)((sg * a + dg * ia) / 255);
                uint8_t rb = (uint8_t)((sb * a + db * ia) / 255);

                dst[col] = 0xFF000000U | ((video_color_t)rr << 16) |
                           ((video_color_t)rg << 8) | (video_color_t)rb;
            }
        }
        row += stride_bytes;
    }
    surface_touch();
}

bool video_is_active(void)
{
    return surface_ready();
}

void video_request_refresh(void)
{
    surface_touch();
}

void video_request_refresh_window(struct atk_widget *window)
{
    (void)window;
    surface_touch();
}

void video_pump_events(void) {}

bool video_surface_has_dirty(void)
{
    return !g_surface_track_dirty || g_surface_dirty;
}

bool video_surface_consume_dirty(void)
{
    if (!g_surface_track_dirty)
    {
        return true;
    }
    if (!g_surface_dirty)
    {
        return false;
    }
    g_surface_dirty = false;
    return true;
}

void video_surface_force_dirty(void)
{
    if (surface_ready())
    {
        g_surface_dirty = true;
    }
}

void video_surface_set_tracking(bool enable)
{
    g_surface_track_dirty = enable;
    if (!enable)
    {
        g_surface_dirty = true;
    }
}

bool video_surface_tracking_enabled(void)
{
    return g_surface_track_dirty;
}
