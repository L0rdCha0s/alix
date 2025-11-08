#include "atk_user.h"

#include "atk.h"
#include "atk_internal.h"
#include "atk_window.h"
#include "atk/atk_label.h"
#include "atk/atk_image.h"
#include "libc.h"
#include "video.h"
#include "ttf.h"
#include "userlib.h"

#define GLYPH_COLUMNS 6
#define CELL_PADDING 12
#define LABEL_HEIGHT 40
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

    size_t capacity = 4096;
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
                        uint16_t fg,
                        uint16_t bg,
                        int *out_width,
                        int *out_height,
                        uint16_t **out_pixels,
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
    uint16_t *pixels = (uint16_t *)malloc(total_pixels * sizeof(uint16_t));
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
                pixels[offset] = rgb565_blend(pixels[offset], fg, alpha);
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

static void apply_ui_theme(atk_state_t *state)
{
    if (!state)
    {
        return;
    }
    state->theme.background = video_make_color(0x15, 0x19, 0x24);
    state->theme.window_border = video_make_color(0x30, 0x34, 0x40);
    state->theme.window_title = video_make_color(0x28, 0x3C, 0x66);
    state->theme.window_title_text = video_make_color(0xFF, 0xFF, 0xFF);
    state->theme.window_body = video_make_color(0x21, 0x25, 0x30);
    state->theme.button_face = video_make_color(0x31, 0x36, 0x45);
    state->theme.button_text = video_make_color(0xE6, 0xE6, 0xE6);
}

static void process_mouse_event(const user_atk_event_t *event)
{
    bool left = (event->flags & USER_ATK_MOUSE_FLAG_LEFT) != 0;
    bool press = (event->flags & USER_ATK_MOUSE_FLAG_PRESS) != 0;
    bool release = (event->flags & USER_ATK_MOUSE_FLAG_RELEASE) != 0;
    atk_mouse_event_result_t result = atk_handle_mouse_event(event->x,
                                                             event->y,
                                                             press,
                                                             release,
                                                             left);
    if (result.redraw)
    {
        atk_render();
    }
}

static void process_key_event(const user_atk_event_t *event)
{
    atk_key_event_result_t result = atk_handle_key_char((char)event->data0);
    if (result.redraw)
    {
        atk_render();
    }
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
    uint16_t *atlas_pixels = NULL;
    uint16_t fg = video_make_color(0xF4, 0xF4, 0xF4);
    uint16_t bg = video_make_color(0x18, 0x1C, 0x27);

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

    atk_init();
    atk_state_t *state = atk_state_get();
    apply_ui_theme(state);

    atk_widget_t *window = atk_window_create_at(state, VIDEO_WIDTH / 2, VIDEO_HEIGHT / 2);
    if (!window)
    {
        printf("ttf_demo: failed to create window\n");
        atk_user_close(&session);
        free(atlas_pixels);
        ttf_font_unload(&font);
        return 1;
    }
    atk_window_set_title_text(window, "TrueType Demo");

    int content_width = atlas_width + WINDOW_MARGIN * 2;
    int content_height = atlas_height + LABEL_HEIGHT + WINDOW_MARGIN * 3;
    if (window->width < content_width)
    {
        window->width = content_width;
    }
    if (window->height < content_height + ATK_WINDOW_TITLE_HEIGHT)
    {
        window->height = content_height + ATK_WINDOW_TITLE_HEIGHT;
    }
    window->x = (VIDEO_WIDTH - window->width) / 2;
    window->y = (VIDEO_HEIGHT - window->height) / 2 - ATK_WINDOW_TITLE_HEIGHT / 2;

    int label_x = WINDOW_MARGIN;
    int label_y = ATK_WINDOW_TITLE_HEIGHT + WINDOW_MARGIN;
    atk_widget_t *label = atk_window_add_label(window,
                                               label_x,
                                               label_y,
                                               window->width - WINDOW_MARGIN * 2,
                                               LABEL_HEIGHT);
    if (label)
    {
        char info[256];
        size_t len = 0;
        append_text(info, sizeof(info), &len, "Font: ");
        append_text(info, sizeof(info), &len, font_path);
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
        atk_label_set_text(label, info);
    }

    atk_widget_t *image = atk_window_add_image(window,
                                               WINDOW_MARGIN,
                                               label_y + LABEL_HEIGHT + WINDOW_MARGIN / 2);
    if (!image)
    {
        printf("ttf_demo: failed to create image widget\n");
        atk_user_close(&session);
        free(atlas_pixels);
        ttf_font_unload(&font);
        return 1;
    }

    if (!atk_image_set_pixels(image,
                              atlas_pixels,
                              atlas_width,
                              atlas_height,
                              atlas_width * (int)sizeof(uint16_t),
                              true))
    {
        printf("ttf_demo: failed to upload atlas\n");
        atk_user_close(&session);
        free(atlas_pixels);
        ttf_font_unload(&font);
        return 1;
    }

    atk_window_mark_dirty(window);
    atk_render();
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
            case USER_ATK_EVENT_MOUSE:
                process_mouse_event(&event);
                atk_user_present(&session);
                break;
            case USER_ATK_EVENT_KEY:
                process_key_event(&event);
                atk_user_present(&session);
                break;
            case USER_ATK_EVENT_CLOSE:
                running = false;
                break;
            default:
                break;
        }
    }

    atk_user_close(&session);
    ttf_font_unload(&font);
    return 0;
}
