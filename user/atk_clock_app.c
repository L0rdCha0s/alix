#include "atk_user.h"

#include "atk.h"
#include "atk_app.h"
#include "atk_internal.h"
#include "atk_window.h"
#include "atk_menu_bar.h"
#include "atk/atk_image.h"
#include "atk/atk_label.h"
#include "libc.h"
#include "stdio.h"
#include "video.h"
#include "usyscall.h"
#include "user_atk_defs.h"

#define CLOCK_WINDOW_WIDTH   420
#define CLOCK_WINDOW_HEIGHT  520
#define CLOCK_MARGIN         18
#define CLOCK_LABEL_HEIGHT   28
#define CLOCK_UPDATE_MS      75
#define CLOCK_TZ_NAME_MAX    64
#define CLOCK_TZ_PATH        "/etc/timezone/current"

typedef struct
{
    atk_user_window_t remote;
    atk_widget_t *window;
    atk_widget_t *image;
    atk_widget_t *label;
    video_color_t *pixels;
    int pix_width;
    int pix_height;
    int pix_stride_bytes;
    int offset_minutes;
    bool running;
    uint64_t next_tick_ms;
    char timezone_name[CLOCK_TZ_NAME_MAX];
    bool timezone_has_name;
} atk_clock_app_t;

static const double CLOCK_PI = 3.141592653589793;
static const double CLOCK_TWO_PI = 6.283185307179586;

static double clock_absd(double value)
{
    return (value < 0.0) ? -value : value;
}

static void clock_fast_sin_cos(double angle, double *out_sin, double *out_cos)
{
    const double B = 4.0 / CLOCK_PI;
    const double C = -4.0 / (CLOCK_PI * CLOCK_PI);
    const double P = 0.225;

    while (angle < -CLOCK_PI)
    {
        angle += CLOCK_TWO_PI;
    }
    while (angle > CLOCK_PI)
    {
        angle -= CLOCK_TWO_PI;
    }

    double y = B * angle + C * angle * clock_absd(angle);
    double sine = P * (y * clock_absd(y) - y) + y;

    double shifted = angle + CLOCK_PI * 0.5;
    while (shifted < -CLOCK_PI)
    {
        shifted += CLOCK_TWO_PI;
    }
    while (shifted > CLOCK_PI)
    {
        shifted -= CLOCK_TWO_PI;
    }
    double y2 = B * shifted + C * shifted * clock_absd(shifted);
    double cosine = P * (y2 * clock_absd(y2) - y2) + y2;

    if (out_sin)
    {
        *out_sin = sine;
    }
    if (out_cos)
    {
        *out_cos = cosine;
    }
}

static inline video_color_t clock_with_alpha(video_color_t color, uint8_t alpha)
{
    return (color & 0x00FFFFFFu) | ((video_color_t)alpha << 24);
}

static inline uint8_t clock_channel_r(video_color_t color)
{
    return (uint8_t)(color >> 16);
}

static inline uint8_t clock_channel_g(video_color_t color)
{
    return (uint8_t)(color >> 8);
}

static inline uint8_t clock_channel_b(video_color_t color)
{
    return (uint8_t)color;
}

static video_color_t clock_tint(video_color_t base, int delta)
{
    int r = (int)clock_channel_r(base) + delta;
    int g = (int)clock_channel_g(base) + delta;
    int b = (int)clock_channel_b(base) + delta;
    if (r < 0) r = 0;
    if (g < 0) g = 0;
    if (b < 0) b = 0;
    if (r > 255) r = 255;
    if (g > 255) g = 255;
    if (b > 255) b = 255;
    return clock_with_alpha(video_make_color((uint8_t)r, (uint8_t)g, (uint8_t)b), 0xFF);
}

static uint64_t clock_normalize_ms(uint64_t base_ms, int offset_minutes)
{
    const int64_t day_ms = 86400000LL;
    int64_t adjusted = (int64_t)base_ms + (int64_t)offset_minutes * 60000LL;
    int64_t mod = adjusted % day_ms;
    if (mod < 0)
    {
        mod += day_ms;
    }
    return (uint64_t)mod;
}

static void clock_breakdown(uint64_t ms, int offset_minutes, int *hour_out, int *minute_out, int *second_out)
{
    uint64_t day_ms = clock_normalize_ms(ms, offset_minutes);
    uint64_t total_seconds = day_ms / 1000ULL;
    if (second_out)
    {
        *second_out = (int)(total_seconds % 60ULL);
    }
    if (minute_out)
    {
        *minute_out = (int)((total_seconds / 60ULL) % 60ULL);
    }
    if (hour_out)
    {
        *hour_out = (int)((total_seconds / 3600ULL) % 24ULL);
    }
}

static bool clock_parse_offset(const char *arg, int *out_minutes)
{
    if (!out_minutes)
    {
        return false;
    }
    *out_minutes = 0;
    if (!arg)
    {
        return true;
    }

    bool negative = false;
    const char *cursor = arg;
    if (*cursor == '+')
    {
        cursor++;
    }
    else if (*cursor == '-')
    {
        negative = true;
        cursor++;
    }

    int value0 = 0;
    while (*cursor >= '0' && *cursor <= '9')
    {
        value0 = value0 * 10 + (*cursor - '0');
        cursor++;
    }

    int minutes = 0;
    if (*cursor == ':' && *(cursor + 1) != '\0')
    {
        cursor++;
        int value1 = 0;
        while (*cursor >= '0' && *cursor <= '9')
        {
            value1 = value1 * 10 + (*cursor - '0');
            cursor++;
        }
        if (*cursor != '\0' || value1 >= 60)
        {
            return false;
        }
        minutes = value0 * 60 + value1;
    }
    else if (*cursor == '\0')
    {
        minutes = value0;
    }
    else
    {
        return false;
    }

    if (negative)
    {
        minutes = -minutes;
    }
    *out_minutes = minutes;
    return true;
}

static void clock_clear(atk_clock_app_t *app, video_color_t color)
{
    if (!app || !app->pixels || app->pix_width <= 0 || app->pix_height <= 0)
    {
        return;
    }
    size_t count = (size_t)app->pix_width * (size_t)app->pix_height;
    for (size_t i = 0; i < count; ++i)
    {
        app->pixels[i] = color;
    }
}

static void clock_plot(atk_clock_app_t *app, int x, int y, int thickness, video_color_t color)
{
    if (!app || !app->pixels || thickness <= 0)
    {
        return;
    }
    int half = thickness / 2;
    for (int dy = -half; dy <= half; ++dy)
    {
        int py = y + dy;
        if (py < 0 || py >= app->pix_height)
        {
            continue;
        }
        for (int dx = -half; dx <= half; ++dx)
        {
            int px = x + dx;
            if (px < 0 || px >= app->pix_width)
            {
                continue;
            }
            size_t idx = (size_t)py * (size_t)app->pix_width + (size_t)px;
            app->pixels[idx] = color;
        }
    }
}

static void clock_draw_line(atk_clock_app_t *app,
                            int x0,
                            int y0,
                            int x1,
                            int y1,
                            int thickness,
                            video_color_t color)
{
    if (!app || !app->pixels)
    {
        return;
    }
    int dx = x1 > x0 ? (x1 - x0) : (x0 - x1);
    int sx = x0 < x1 ? 1 : -1;
    int dy = y1 > y0 ? (y0 - y1) : (y1 - y0);
    int sy = y0 < y1 ? 1 : -1;
    int err = dx + dy;

    for (;;)
    {
        clock_plot(app, x0, y0, thickness, color);
        if (x0 == x1 && y0 == y1)
        {
            break;
        }
        int e2 = err << 1;
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

static void clock_draw_hand(atk_clock_app_t *app,
                            int cx,
                            int cy,
                            double angle,
                            int length,
                            int thickness,
                            video_color_t color,
                            int tail)
{
    double s = 0.0;
    double c = 0.0;
    clock_fast_sin_cos(angle, &s, &c);
    int x1 = cx + (int)(c * (double)length);
    int y1 = cy + (int)(s * (double)length);
    int x0 = cx - (int)(c * (double)tail);
    int y0 = cy - (int)(s * (double)tail);
    clock_draw_line(app, x0, y0, x1, y1, thickness, color);
}

static void clock_draw_face(atk_clock_app_t *app, uint64_t now_ms)
{
    if (!app || !app->pixels || app->pix_width <= 0 || app->pix_height <= 0)
    {
        return;
    }

    const atk_state_t *state = atk_state_get();
    const atk_theme_t *theme = state ? &state->theme : NULL;

    video_color_t body = theme ? theme->window_body : video_make_color(0x12, 0x16, 0x1E);
    video_color_t face_color = theme ? clock_tint(theme->window_body, -32) : video_make_color(0x14, 0x1C, 0x28);
    video_color_t rim_color = theme ? clock_tint(theme->window_title, 16) : video_make_color(0x3E, 0x6A, 0xA8);
    video_color_t tick_major = video_make_color(0xF1, 0xF4, 0xF8);
    video_color_t tick_minor = video_make_color(0x9B, 0xA7, 0xB8);
    video_color_t hand_hour = video_make_color(0xF4, 0xD3, 0x90);
    video_color_t hand_minute = video_make_color(0x64, 0xC7, 0xF5);
    video_color_t hand_second = video_make_color(0xF0, 0x5A, 0x5A);
    video_color_t center_cap = video_make_color(0xE8, 0xA4, 0x50);

    int w = app->pix_width;
    int h = app->pix_height;
    int cx = w / 2;
    int cy = h / 2;
    int radius = (w < h ? w : h) / 2 - 4;
    if (radius <= 4)
    {
        return;
    }

    uint64_t day_ms = clock_normalize_ms(now_ms, app->offset_minutes);
    double second_part = ((double)(day_ms % 60000ULL)) / 1000.0;
    double minute_whole = (double)((day_ms / 60000ULL) % 60ULL);
    double hour_whole = (double)((day_ms / 3600000ULL) % 12ULL);

    double sec_angle = (second_part / 60.0) * CLOCK_TWO_PI - CLOCK_PI * 0.5;
    double min_angle = ((minute_whole + second_part / 60.0) / 60.0) * CLOCK_TWO_PI - CLOCK_PI * 0.5;
    double hour_angle = ((hour_whole + minute_whole / 60.0) / 12.0) * CLOCK_TWO_PI - CLOCK_PI * 0.5;

    int rim = radius / 10;
    if (rim < 4)
    {
        rim = 4;
    }
    int inner_r = radius - rim;
    int highlight_r = inner_r - (rim / 2);

    video_color_t transparent_body = clock_with_alpha(body, 0);
    clock_clear(app, transparent_body);

    int radius_sq = radius * radius;
    int inner_sq = inner_r * inner_r;
    int highlight_sq = highlight_r * highlight_r;
    for (int y = 0; y < h; ++y)
    {
        int dy = y - cy;
        for (int x = 0; x < w; ++x)
        {
            int dx = x - cx;
            int dist2 = dx * dx + dy * dy;
            video_color_t color = transparent_body;
            if (dist2 <= radius_sq)
            {
                if (dist2 >= inner_sq)
                {
                    color = rim_color;
                }
                else if (dist2 >= highlight_sq)
                {
                    color = face_color;
                }
                else
                {
                    color = clock_tint(face_color, 12);
                }
            }
            size_t idx = (size_t)y * (size_t)w + (size_t)x;
            app->pixels[idx] = color;
        }
    }

    int tick_outer = radius - 2;
    for (int i = 0; i < 60; ++i)
    {
        double a = ((double)i / 60.0) * CLOCK_TWO_PI - CLOCK_PI * 0.5;
        double s = 0.0;
        double c = 0.0;
        clock_fast_sin_cos(a, &s, &c);
        bool major = (i % 5) == 0;
        int tick_len = major ? (radius / 6) : (radius / 10);
        int inner = tick_outer - tick_len;
        int x0 = cx + (int)(c * (double)inner);
        int y0 = cy + (int)(s * (double)inner);
        int x1 = cx + (int)(c * (double)tick_outer);
        int y1 = cy + (int)(s * (double)tick_outer);
        clock_draw_line(app, x0, y0, x1, y1, major ? 3 : 2, major ? tick_major : tick_minor);
    }

    int hour_len = radius - rim - 28;
    int minute_len = radius - rim - 12;
    int second_len = radius - rim - 6;
    if (hour_len < radius / 3) hour_len = radius / 3;
    if (minute_len < radius / 2) minute_len = radius / 2;

    clock_draw_hand(app, cx, cy, hour_angle, hour_len, 5, hand_hour, 8);
    clock_draw_hand(app, cx, cy, min_angle, minute_len, 4, hand_minute, 10);
    clock_draw_hand(app, cx, cy, sec_angle, second_len, 2, hand_second, 14);

    int cap_r = 6;
    for (int dy = -cap_r; dy <= cap_r; ++dy)
    {
        for (int dx = -cap_r; dx <= cap_r; ++dx)
        {
            int dist2 = dx * dx + dy * dy;
            if (dist2 <= cap_r * cap_r)
            {
                clock_plot(app, cx + dx, cy + dy, 1, center_cap);
            }
        }
    }
}

static void clock_update_label(atk_clock_app_t *app, uint64_t now_ms)
{
    if (!app || !app->label)
    {
        return;
    }
    int hour = 0;
    int minute = 0;
    int second = 0;
    clock_breakdown(now_ms, app->offset_minutes, &hour, &minute, &second);
    char text[64];
    int offset_abs = app->offset_minutes >= 0 ? app->offset_minutes : -app->offset_minutes;
    int offset_h = offset_abs / 60;
    int offset_m = offset_abs % 60;
    const char sign = (app->offset_minutes < 0) ? '-' : '+';
    const char *tz = (app->timezone_has_name && app->timezone_name[0]) ? app->timezone_name : NULL;
    snprintf(text,
             sizeof(text),
             "%02d:%02d:%02d (%s%c%02d:%02d)",
             hour,
             minute,
             second,
             tz ? tz : "UTC",
             sign,
             offset_h,
             offset_m);
    atk_label_set_text(app->label, text);
}

static bool clock_resize_surface(atk_clock_app_t *app, int width, int height)
{
    if (!app || width <= 0 || height <= 0)
    {
        return false;
    }
    size_t pixels = 0;
    if (__builtin_mul_overflow((size_t)width, (size_t)height, &pixels) ||
        __builtin_mul_overflow(pixels, sizeof(video_color_t), &pixels))
    {
        return false;
    }

    video_color_t *new_pixels = (video_color_t *)malloc(pixels);
    if (!new_pixels)
    {
        return false;
    }

    free(app->pixels);
    app->pixels = new_pixels;
    app->pix_width = width;
    app->pix_height = height;
    app->pix_stride_bytes = width * (int)sizeof(video_color_t);
    memset(app->pixels, 0, pixels);

    if (app->image)
    {
        atk_image_set_pixels(app->image,
                             app->pixels,
                             app->pix_width,
                             app->pix_height,
                             app->pix_stride_bytes,
                             false);
    }
    return true;
}

static void clock_layout(atk_clock_app_t *app)
{
    if (!app || !app->window || !app->image)
    {
        return;
    }

    int chrome_top = atk_window_is_chrome_visible(app->window) ? ATK_WINDOW_TITLE_HEIGHT : 0;
    int available_w = app->window->width - CLOCK_MARGIN * 2;
    int available_h = app->window->height - chrome_top - CLOCK_MARGIN * 3 - CLOCK_LABEL_HEIGHT;
    if (available_w <= 0 || available_h <= 0)
    {
        return;
    }

    int face_size = (available_w < available_h) ? available_w : available_h;
    int min_face = 64;
    if (face_size < min_face && available_w >= min_face && available_h >= min_face)
    {
        face_size = min_face;
    }

    int img_x = (app->window->width - face_size) / 2;
    int img_y = chrome_top + CLOCK_MARGIN;

    app->image->x = img_x;
    app->image->y = img_y;
    app->image->width = face_size;
    app->image->height = face_size;
    atk_widget_set_layout(app->image, ATK_WIDGET_ANCHOR_LEFT | ATK_WIDGET_ANCHOR_RIGHT | ATK_WIDGET_ANCHOR_TOP);

    if (app->pix_width != face_size || app->pix_height != face_size)
    {
        clock_resize_surface(app, face_size, face_size);
    }

    if (app->label)
    {
        int label_y = img_y + face_size + CLOCK_MARGIN;
        app->label->x = CLOCK_MARGIN;
        app->label->y = label_y;
        app->label->width = app->window->width - CLOCK_MARGIN * 2;
        app->label->height = CLOCK_LABEL_HEIGHT;
        atk_widget_set_layout(app->label,
                              ATK_WIDGET_ANCHOR_LEFT |
                              ATK_WIDGET_ANCHOR_RIGHT |
                              ATK_WIDGET_ANCHOR_BOTTOM);
    }
}

static void clock_apply_theme(atk_state_t *state)
{
    if (!state)
    {
        return;
    }
    state->theme.background = video_make_color(0x12, 0x18, 0x21);
    state->theme.window_border = video_make_color(0x24, 0x2C, 0x38);
    state->theme.window_title = video_make_color(0x3B, 0x6D, 0xA7);
    state->theme.window_title_text = video_make_color(0xF3, 0xF6, 0xFB);
    state->theme.window_body = video_make_color(0x0D, 0x12, 0x1A);
    state->theme.button_face = video_make_color(0x2C, 0x3C, 0x54);
    state->theme.button_border = video_make_color(0x16, 0x1E, 0x28);
    state->theme.button_text = video_make_color(0xE8, 0xED, 0xF4);
    state->theme.desktop_icon_face = video_make_color(0x45, 0x72, 0xA8);
    state->theme.desktop_icon_text = state->theme.window_title_text;
    state->theme.menu_bar_face = video_make_color(0x18, 0x20, 0x2C);
    state->theme.menu_bar_text = video_make_color(0xE5, 0xE9, 0xF1);
    state->theme.menu_bar_highlight = video_make_color(0x2C, 0x44, 0x68);
    state->theme.menu_dropdown_face = video_make_color(0x10, 0x14, 0x1C);
    state->theme.menu_dropdown_border = video_make_color(0x22, 0x2C, 0x38);
    state->theme.menu_dropdown_text = state->theme.menu_bar_text;
    state->theme.menu_dropdown_highlight = video_make_color(0x35, 0x52, 0x7A);
    atk_state_theme_commit(state);
}

static bool clock_tick(atk_clock_app_t *app)
{
    if (!app || !app->window)
    {
        return false;
    }
    uint64_t now = sys_time_millis();
    if (now < app->next_tick_ms)
    {
        return false;
    }
    app->next_tick_ms = now + CLOCK_UPDATE_MS;
    clock_draw_face(app, now);
    clock_update_label(app, now);
    atk_window_mark_dirty(app->window);
    return true;
}

static bool clock_load_timezone(int *offset_out, char *name_out, size_t name_len)
{
    if (!offset_out)
    {
        return false;
    }

    int fd = open(CLOCK_TZ_PATH, 0);
    if (fd < 0)
    {
        return false;
    }

    char buffer[256];
    ssize_t bytes = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (bytes <= 0)
    {
        return false;
    }
    buffer[bytes] = '\0';

    char *line1 = buffer;
    char *newline = strchr(buffer, '\n');
    if (!newline)
    {
        return false;
    }
    *newline = '\0';
    char *line2 = newline + 1;
    char *newline2 = strchr(line2, '\n');
    if (newline2)
    {
        *newline2 = '\0';
    }

    if (name_out && name_len > 0)
    {
        size_t len = strlen(line1);
        if (len >= name_len)
        {
            len = name_len - 1;
        }
        memcpy(name_out, line1, len);
        name_out[len] = '\0';
    }

    int sign = 1;
    const char *cursor = line2;
    if (*cursor == '-')
    {
        sign = -1;
        cursor++;
    }
    else if (*cursor == '+')
    {
        cursor++;
    }

    int value = 0;
    while (*cursor >= '0' && *cursor <= '9')
    {
        value = value * 10 + (*cursor - '0');
        cursor++;
    }
    if (*cursor != '\0')
    {
        return false;
    }

    *offset_out = value * sign;
    return true;
}

static void clock_present(atk_clock_app_t *app)
{
    if (!app)
    {
        return;
    }
    atk_render();
    atk_user_present_force(&app->remote);
}

static void clock_handle_resize(atk_clock_app_t *app, uint32_t width, uint32_t height)
{
    if (!app || !app->window || width == 0 || height == 0)
    {
        return;
    }
    app->window->width = (int)width;
    app->window->height = (int)height;
    atk_window_request_layout(app->window);
    clock_layout(app);
    atk_window_mark_dirty(app->window);
}

static bool clock_on_resize_event(uint32_t width, uint32_t height, void *context)
{
    clock_handle_resize((atk_clock_app_t *)context, width, height);
    return true;
}

static void clock_on_close_event(void *context)
{
    atk_clock_app_t *app = (atk_clock_app_t *)context;
    if (app)
    {
        app->running = false;
    }
    atk_main_request_exit();
}

static bool clock_on_tick(void *context)
{
    atk_clock_app_t *app = (atk_clock_app_t *)context;
    if (!app || !app->running)
    {
        return false;
    }
    return clock_tick(app);
}

static bool clock_init_ui(atk_clock_app_t *app)
{
    if (!app)
    {
        return false;
    }
    atk_init();
    atk_state_t *state = atk_state_get();
    if (!state)
    {
        return false;
    }
    atk_menu_bar_set_enabled(state, false);
    clock_apply_theme(state);

    atk_widget_t *window = atk_window_create_at(state, CLOCK_WINDOW_WIDTH / 2, CLOCK_WINDOW_HEIGHT / 2);
    if (!window)
    {
        return false;
    }

    window->x = 0;
    window->y = 0;
    window->width = CLOCK_WINDOW_WIDTH;
    window->height = CLOCK_WINDOW_HEIGHT;
    atk_window_set_title_text(window, "Analog Clock");
    atk_window_set_chrome_visible(window, false);
    atk_window_ensure_inside(window);

    atk_widget_t *image = atk_window_add_image(window, CLOCK_MARGIN, CLOCK_MARGIN + ATK_WINDOW_TITLE_HEIGHT);
    if (!image)
    {
        atk_window_close(state, window);
        return false;
    }

    atk_widget_t *label = atk_window_add_label(window,
                                               CLOCK_MARGIN,
                                               CLOCK_WINDOW_HEIGHT - CLOCK_LABEL_HEIGHT - CLOCK_MARGIN,
                                               CLOCK_WINDOW_WIDTH - CLOCK_MARGIN * 2,
                                               CLOCK_LABEL_HEIGHT);
    if (!label)
    {
        atk_window_close(state, window);
        return false;
    }

    app->window = window;
    app->image = image;
    app->label = label;
    app->next_tick_ms = sys_time_millis();

    clock_layout(app);
    clock_draw_face(app, app->next_tick_ms);
    clock_update_label(app, app->next_tick_ms);
    atk_window_mark_dirty(window);
    return true;
}

static void clock_destroy(atk_clock_app_t *app)
{
    if (!app)
    {
        return;
    }
    free(app->pixels);
    app->pixels = NULL;
    app->pix_width = 0;
    app->pix_height = 0;
}

int main(int argc, char **argv)
{
    atk_clock_app_t app;
    memset(&app, 0, sizeof(app));
    app.running = true;
    app.offset_minutes = 0;
    app.next_tick_ms = sys_time_millis();
    app.timezone_has_name = false;
    app.timezone_name[0] = '\0';

    if (argc > 2)
    {
        printf("Usage: atk_clock [offset_minutes | [+/-]HH:MM]\n");
        return 1;
    }

    if (argc > 1)
    {
        if (!clock_parse_offset(argv[1], &app.offset_minutes))
        {
            printf("Usage: atk_clock [offset_minutes | [+/-]HH:MM]\n");
            return 1;
        }
        strncpy(app.timezone_name, "Custom", sizeof(app.timezone_name) - 1);
        app.timezone_name[sizeof(app.timezone_name) - 1] = '\0';
        app.timezone_has_name = true;
    }
    else
    {
        syscall_time_info_t info;
        if (sys_time_info(&info) == 0)
        {
            app.offset_minutes = info.offset_minutes;
            strncpy(app.timezone_name, info.timezone_name, sizeof(app.timezone_name) - 1);
            app.timezone_name[sizeof(app.timezone_name) - 1] = '\0';
            app.timezone_has_name = (app.timezone_name[0] != '\0');
        }
        else
        {
            if (clock_load_timezone(&app.offset_minutes, app.timezone_name, sizeof(app.timezone_name)))
            {
                app.timezone_has_name = (app.timezone_name[0] != '\0');
            }
            else
            {
                app.offset_minutes = 0;
            }
        }
    }

    if (!atk_user_window_open_with_flags(&app.remote,
                                         "Analog Clock",
                                         CLOCK_WINDOW_WIDTH,
                                         CLOCK_WINDOW_HEIGHT,
                                         USER_ATK_WINDOW_FLAG_RESIZABLE))
    {
        printf("atk_clock: failed to open remote window\n");
        return 1;
    }
    atk_user_enable_dirty_tracking(&app.remote, true);

    if (!clock_init_ui(&app))
    {
        printf("atk_clock: failed to init UI\n");
        atk_user_close(&app.remote);
        clock_destroy(&app);
        return 1;
    }

    clock_present(&app);

    atk_main_config_t main_cfg = {
        .window = &app.remote,
        .tick = clock_on_tick,
        .tick_context = &app,
        .present_on_idle = false,
        .legacy_input = false
    };

    atk_main_register_resize_handler(clock_on_resize_event, &app);
    atk_main_register_close_handler(clock_on_close_event, &app);

    atk_main(&main_cfg);

    atk_user_close(&app.remote);
    clock_destroy(&app);
    return 0;
}
