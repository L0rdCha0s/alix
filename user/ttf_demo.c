#include "atk_user.h"

#include "libc.h"
#include "video.h"
#include "ttf.h"
#include "userlib.h"
#include "font.h"

#define GLYPH_COLUMNS 6
#define CELL_PADDING 12
#define LABEL_HEIGHT 18
#define WINDOW_MARGIN 16

typedef struct
{
    uint32_t codepoint;
    ttf_bitmap_t bitmap;
    ttf_glyph_metrics_t metrics;
} glyph_entry_t;

static const char *const GLYPH_SEQUENCE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

static void append_text(char *buffer, size_t capacity, size_t *length, const char *text)
{
    while (text && *text && *length + 1 < capacity)
    {
        buffer[*length] = *text;
        (*length)++;
        text++;
    }
}

static void append_int(char *buffer, size_t capacity, size_t *length, int value)
{
    if (*length + 1 >= capacity)
    {
        return;
    }
    if (value < 0)
    {
        buffer[(*length)++] = '-';
        value = -value;
    }
    char temp[32];
    int idx = 0;
    if (value == 0)
    {
        temp[idx++] = '0';
    }
    while (value > 0 && idx < (int)sizeof(temp))
    {
        temp[idx++] = (char)('0' + (value % 10));
        value /= 10;
    }
    while (idx > 0 && *length + 1 < capacity)
    {
        buffer[*length] = temp[--idx];
        (*length)++;
    }
}

static uint8_t *read_entire_file(const char *path, size_t *size_out)
{
    if (!path)
    {
        return NULL;
    }

    printf("ttf_demo: read_entire_file '%s'\n", path);
    int fd = open(path, 0);
    if (fd < 0)
    {
        printf("ttf_demo: open failed (%s)\n", path);
        return NULL;
    }

    size_t capacity = 4194304;
    size_t size = 0;
    uint8_t *buffer = (uint8_t *)malloc(capacity);
    if (!buffer)
    {
        printf("ttf_demo: malloc failed (%s)\n", path);
        close(fd);
        return NULL;
    }

    for (;;)
    {
        if (size == capacity)
        {
            size_t new_capacity = capacity * 2;
            uint8_t *new_buffer = (uint8_t *)realloc(buffer, new_capacity);
            if (!new_buffer)
            {
                printf("ttf_demo: realloc failed (%s, new_capacity=%zu)\n", path, new_capacity);
                free(buffer);
                close(fd);
                return NULL;
            }
            buffer = new_buffer;
            capacity = new_capacity;
        }

        ssize_t bytes = read(fd, buffer + size, capacity - size);
        if (bytes < 0)
        {
            printf("ttf_demo: read error on %s\n", path);
            free(buffer);
            close(fd);
            return NULL;
        }
        if (bytes == 0)
        {
            break;
        }
        size += (size_t)bytes;
    }
    close(fd);
    printf("ttf_demo: read %zu bytes from %s\n", size, path);
    if (size_out)
    {
        *size_out = size;
    }
    return buffer;
}

static int parse_font_size(const char *text, int fallback)
{
    if (!text)
    {
        return fallback;
    }
    int value = 0;
    const char *cursor = text;
    while (*cursor >= '0' && *cursor <= '9')
    {
        value = value * 10 + (*cursor - '0');
        ++cursor;
    }
    if (value < 8)
    {
        value = 64;
    }
    if (value > 256)
    {
        value = 256;
    }
    return value;
}

static video_color_t rgba_blend(video_color_t bg, video_color_t fg, uint8_t alpha)
{
    if (alpha == 0)
    {
        return bg;
    }
    if (alpha == 255)
    {
        return fg;
    }

    uint8_t br = (uint8_t)(bg >> 16);
    uint8_t bgc = (uint8_t)(bg >> 8);
    uint8_t bb = (uint8_t)bg;

    uint8_t fr = (uint8_t)(fg >> 16);
    uint8_t fgx = (uint8_t)(fg >> 8);
    uint8_t fb = (uint8_t)fg;

    uint8_t ia = (uint8_t)(255 - alpha);
    uint8_t rr = (uint8_t)((fr * alpha + br * ia) / 255);
    uint8_t rg = (uint8_t)((fgx * alpha + bgc * ia) / 255);
    uint8_t rb = (uint8_t)((fb * alpha + bb * ia) / 255);

    return 0xFF000000U | ((video_color_t)rr << 16) | ((video_color_t)rg << 8) | (video_color_t)rb;
}

static bool render_glyphs(ttf_font_t *font,
                          int size_px,
                          glyph_entry_t *entries,
                          size_t count)
{
    if (!font || !entries || count == 0)
    {
        return false;
    }

    for (size_t i = 0; i < count; ++i)
    {
        entries[i].codepoint = (uint32_t)GLYPH_SEQUENCE[i];
        entries[i].bitmap.width = 0;
        entries[i].bitmap.height = 0;
        entries[i].bitmap.pixels = NULL;
        entries[i].metrics.advance = 0;

        if (!ttf_font_render_glyph_bitmap(font,
                                          entries[i].codepoint,
                                          size_px,
                                          &entries[i].bitmap,
                                          &entries[i].metrics))
        {
            return false;
        }
    }
    return true;
}

static bool build_atlas(const glyph_entry_t *entries,
                        size_t count,
                        video_color_t fg,
                        video_color_t bg,
                        int *out_width,
                        int *out_height,
                        video_color_t **out_pixels,
                        int cell_padding,
                        int *out_cell_width,
                        int *out_cell_height,
                        int *out_max_above)
{
    if (!entries || !out_pixels || !out_width || !out_height)
    {
        return false;
    }

    int max_left = 0;
    int max_right = 0;
    int max_above = 0;
    int max_below = 0;

    for (size_t i = 0; i < count; ++i)
    {
        const ttf_bitmap_t *bmp = &entries[i].bitmap;
        const ttf_glyph_metrics_t *metrics = &entries[i].metrics;
        int left_extent = -bmp->offset_x;
        if (left_extent > max_left)
        {
            max_left = left_extent;
        }
        int right_extent = bmp->offset_x + bmp->width;
        if (right_extent > max_right)
        {
            max_right = right_extent;
        }
        if (metrics->bearing_y > max_above)
        {
            max_above = metrics->bearing_y;
        }
        int below = metrics->height - metrics->bearing_y;
        if (below > max_below)
        {
            max_below = below;
        }
    }

    int cell_width = max_left + max_right + cell_padding * 2;
    int cell_height = max_above + max_below + cell_padding * 2;
    if (cell_width < 1) cell_width = 1;
    if (cell_height < 1) cell_height = 1;

    int columns = GLYPH_COLUMNS;
    int rows = (int)((count + (size_t)columns - 1) / (size_t)columns);
    int atlas_width = cell_width * columns;
    int atlas_height = cell_height * rows;

    size_t total_pixels = (size_t)atlas_width * (size_t)atlas_height;
    video_color_t *pixels = (video_color_t *)malloc(total_pixels * sizeof(video_color_t));
    if (!pixels)
    {
        return false;
    }

    for (size_t i = 0; i < total_pixels; ++i)
    {
        pixels[i] = bg;
    }

    for (size_t index = 0; index < count; ++index)
    {
        int col = (int)(index % (size_t)columns);
        int row = (int)(index / (size_t)columns);
        int origin_x = col * cell_width + cell_padding + max_left;
        int origin_y = row * cell_height + cell_padding + max_above;

        const ttf_bitmap_t *bmp = &entries[index].bitmap;
        if (!bmp->pixels || bmp->width <= 0 || bmp->height <= 0)
        {
            continue;
        }

        int target_x = origin_x + bmp->offset_x;
        int target_y = origin_y - bmp->offset_y;

        for (int y = 0; y < bmp->height; ++y)
        {
            int dst_y = target_y + y;
            if (dst_y < 0 || dst_y >= atlas_height)
            {
                continue;
            }
            for (int x = 0; x < bmp->width; ++x)
            {
                int dst_x = target_x + x;
                if (dst_x < 0 || dst_x >= atlas_width)
                {
                    continue;
                }
                uint8_t alpha = bmp->pixels[y * bmp->stride + x];
                if (alpha == 0)
                {
                    continue;
                }
                size_t offset = (size_t)dst_y * (size_t)atlas_width + (size_t)dst_x;
                pixels[offset] = rgba_blend(pixels[offset], fg, alpha);
            }
        }
    }

    *out_cell_width = cell_width;
    *out_cell_height = cell_height;
    *out_width = atlas_width;
    *out_height = atlas_height;
    *out_pixels = pixels;
    if (out_max_above)
    {
        *out_max_above = max_above;
    }
    return true;
}

static void destroy_glyphs(glyph_entry_t *entries, size_t count)
{
    if (!entries)
    {
        return;
    }
    for (size_t i = 0; i < count; ++i)
    {
        ttf_bitmap_destroy(&entries[i].bitmap);
    }
}

static inline bool surface_ready(const atk_user_window_t *session)
{
    return session && session->buffer && session->width > 0 && session->height > 0;
}

static void surface_fill(const atk_user_window_t *session, video_color_t color)
{
    if (!surface_ready(session))
    {
        return;
    }
    size_t pixels = (size_t)session->width * (size_t)session->height;
    for (size_t i = 0; i < pixels; ++i)
    {
        session->buffer[i] = color;
    }
}

static void surface_draw_rect(const atk_user_window_t *session,
                              int x,
                              int y,
                              int width,
                              int height,
                              video_color_t color)
{
    if (!surface_ready(session) || width <= 0 || height <= 0)
    {
        return;
    }

    int x0 = x;
    int y0 = y;
    int x1 = x + width;
    int y1 = y + height;

    if (x1 <= 0 || y1 <= 0 || x0 >= (int)session->width || y0 >= (int)session->height)
    {
        return;
    }
    if (x0 < 0) x0 = 0;
    if (y0 < 0) y0 = 0;
    if (x1 > (int)session->width) x1 = (int)session->width;
    if (y1 > (int)session->height) y1 = (int)session->height;

    for (int row = y0; row < y1; ++row)
    {
        video_color_t *dst = session->buffer + (size_t)row * session->width + x0;
        for (int col = x0; col < x1; ++col)
        {
            *dst++ = color;
        }
    }
}

static void surface_draw_rect_outline(const atk_user_window_t *session,
                                      int x,
                                      int y,
                                      int width,
                                      int height,
                                      video_color_t color)
{
    if (width <= 0 || height <= 0)
    {
        return;
    }
    surface_draw_rect(session, x, y, width, 1, color);
    surface_draw_rect(session, x, y + height - 1, width, 1, color);
    surface_draw_rect(session, x, y, 1, height, color);
    surface_draw_rect(session, x + width - 1, y, 1, height, color);
}

static void surface_draw_char(const atk_user_window_t *session,
                              int x,
                              int y,
                              char c,
                              video_color_t fg,
                              video_color_t bg)
{
    if (!surface_ready(session))
    {
        return;
    }
    uint8_t glyph[FONT_BASIC_HEIGHT_X2];
    font_basic_copy_glyph8x16((uint8_t)c, glyph);

    for (int row = 0; row < FONT_BASIC_HEIGHT_X2; ++row)
    {
        int dst_y = y + row;
        if (dst_y < 0 || dst_y >= (int)session->height)
        {
            continue;
        }
        uint8_t bits = glyph[row];
        video_color_t *dst = session->buffer + (size_t)dst_y * session->width;
        for (int col = 0; col < FONT_BASIC_WIDTH; ++col)
        {
            int dst_x = x + col;
            if (dst_x < 0 || dst_x >= (int)session->width)
            {
                continue;
            }
            video_color_t color = (bits & (1U << (7 - col))) ? fg : bg;
            dst[dst_x] = color;
        }
    }
}

static void surface_draw_text(const atk_user_window_t *session,
                              int x,
                              int y,
                              const char *text,
                              video_color_t fg,
                              video_color_t bg)
{
    if (!surface_ready(session) || !text)
    {
        return;
    }
    int cursor_x = x;
    for (size_t i = 0; text[i] != '\0'; ++i)
    {
        surface_draw_char(session, cursor_x, y, text[i], fg, bg);
        cursor_x += FONT_BASIC_WIDTH;
    }
}

static void blit_atlas_into_window(const atk_user_window_t *session,
                                   int dst_x,
                                   int dst_y,
                                   const video_color_t *atlas_pixels,
                                   int atlas_width,
                                   int atlas_height)
{
    if (!surface_ready(session) || !atlas_pixels)
    {
        return;
    }

    for (int y = 0; y < atlas_height; ++y)
    {
        int target_y = dst_y + y;
        if (target_y < 0 || target_y >= (int)session->height)
        {
            continue;
        }

        const video_color_t *src_row = atlas_pixels + (size_t)y * (size_t)atlas_width;
        video_color_t *dst_row = session->buffer + (size_t)target_y * session->width;

        int start_x = dst_x;
        int copy_width = atlas_width;

        if (start_x < 0)
        {
            int skip = -start_x;
            start_x = 0;
            copy_width -= skip;
            src_row += skip;
        }
        if (start_x + copy_width > (int)session->width)
        {
            copy_width = (int)session->width - start_x;
        }
        if (copy_width <= 0)
        {
            continue;
        }

        memcpy(dst_row + start_x, src_row, (size_t)copy_width * sizeof(video_color_t));
    }
}

static void render_scene(const atk_user_window_t *session,
                         const char *font_path,
                         int font_size,
                         const video_color_t *atlas_pixels,
                         int atlas_width,
                         int atlas_height)
{
    if (!surface_ready(session))
    {
        return;
    }

    video_color_t bg = video_make_color(0x21, 0x25, 0x30);
    video_color_t text = video_make_color(0xF4, 0xF4, 0xF4);
    video_color_t accent = video_make_color(0x15, 0x19, 0x24);
    video_color_t border = video_make_color(0x30, 0x34, 0x40);

    surface_fill(session, bg);

    char info[256];
    size_t len = 0;
    append_text(info, sizeof(info), &len, "Font: ");
    append_text(info, sizeof(info), &len, font_path ? font_path : "(null)");
    append_text(info, sizeof(info), &len, " (");
    append_int(info, sizeof(info), &len, font_size);
    append_text(info, sizeof(info), &len, " px)");
    if (len < sizeof(info))
    {
        info[len] = '\0';
    }
    else
    {
        info[sizeof(info) - 1] = '\0';
    }

    surface_draw_text(session,
                      WINDOW_MARGIN,
                      WINDOW_MARGIN,
                      info,
                      text,
                      bg);

    int atlas_x = WINDOW_MARGIN;
    int atlas_y = WINDOW_MARGIN * 2 + LABEL_HEIGHT;
    int outline_width = atlas_width + WINDOW_MARGIN;
    int outline_height = atlas_height + WINDOW_MARGIN;

    surface_draw_rect(session,
                      atlas_x - WINDOW_MARGIN / 2,
                      atlas_y - WINDOW_MARGIN / 2,
                      outline_width,
                      outline_height,
                      accent);
    surface_draw_rect_outline(session,
                              atlas_x - WINDOW_MARGIN / 2,
                              atlas_y - WINDOW_MARGIN / 2,
                              outline_width,
                              outline_height,
                              border);

    blit_atlas_into_window(session, atlas_x, atlas_y, atlas_pixels, atlas_width, atlas_height);
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        printf("Usage: ttf_demo <font_path> [size]\n");
        return 1;
    }

    const char *font_path = argv[1];
    int font_size = (argc >= 3) ? parse_font_size(argv[2], 16) : 16;
    size_t font_size_bytes = 0;
    uint8_t *font_data = read_entire_file(font_path, &font_size_bytes);
    if (!font_data || font_size_bytes == 0)
    {
        printf("ttf_demo: failed to read font %s\n", font_path);
        free(font_data);
        return 1;
    }

    printf("ttf_demo: font size=%u bytes\n", (unsigned)font_size_bytes);
    ttf_font_t font = {0};
    if (!ttf_font_load(&font, font_data, font_size_bytes))
    {
        printf("ttf_demo: invalid font file (size=%u)\n", (unsigned)font_size_bytes);
        free(font_data);
        return 1;
    }
    free(font_data);

    size_t glyph_count = strlen(GLYPH_SEQUENCE);
    glyph_entry_t *entries = (glyph_entry_t *)calloc(glyph_count, sizeof(glyph_entry_t));
    if (!entries)
    {
        ttf_font_unload(&font);
        return 1;
    }

    if (!render_glyphs(&font, font_size, entries, glyph_count))
    {
        printf("ttf_demo: failed to render glyphs\n");
        destroy_glyphs(entries, glyph_count);
        free(entries);
        ttf_font_unload(&font);
        return 1;
    }

    int atlas_width = 0;
    int atlas_height = 0;
    int cell_width = 0;
    int cell_height = 0;
    int max_above = 0;
    video_color_t *atlas_pixels = NULL;
    video_color_t fg = video_make_color(0xF4, 0xF4, 0xF4);
    video_color_t bg = video_make_color(0x18, 0x1C, 0x27);

    if (!build_atlas(entries,
                     glyph_count,
                     fg,
                     bg,
                     &atlas_width,
                     &atlas_height,
                     &atlas_pixels,
                     CELL_PADDING,
                     &cell_width,
                     &cell_height,
                     &max_above))
    {
        printf("ttf_demo: failed to build atlas\n");
        destroy_glyphs(entries, glyph_count);
        free(entries);
        ttf_font_unload(&font);
        return 1;
    }

    destroy_glyphs(entries, glyph_count);
    free(entries);

    atk_user_window_t session = {0};
    if (!atk_user_window_open(&session, "TTF Demo", VIDEO_WIDTH, VIDEO_HEIGHT))
    {
        printf("ttf_demo: unable to open window\n");
        free(atlas_pixels);
        ttf_font_unload(&font);
        return 1;
    }

    render_scene(&session, font_path, font_size, atlas_pixels, atlas_width, atlas_height);
    free(atlas_pixels);
    atk_user_present(&session);

    bool running = true;
    while (running)
    {
        user_atk_event_t event;
        if (!atk_user_wait_event(&session, &event))
        {
            continue;
        }

        switch (event.type)
        {
            case USER_ATK_EVENT_CLOSE:
                running = false;
                break;
            case USER_ATK_EVENT_KEY:
                if (event.data0 == 27) /* ESC */
                {
                    running = false;
                }
                break;
            default:
                break;
        }
    }

    atk_user_close(&session);
    ttf_font_unload(&font);
    return 0;
}
