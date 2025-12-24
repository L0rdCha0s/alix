#include "atk_menu_bar.h"

#include "atk/atk_image.h"
#include "atk/atk_label.h"
#include "atk/atk_menu.h"
#include "atk/atk_font.h"
#include "atk/atk_scrollbar.h"
#include "atk_window.h"
#include "font.h"
#include "libc.h"
#include "video.h"
#ifdef KERNEL_BUILD
#include "serial.h"
#include "power.h"
#include "vfs.h"
#include "process.h"
#include "shell_commands.h"
#endif
#ifndef ATK_NO_DESKTOP_APPS
#include "timekeeping.h"
#endif

#define ATK_MENU_BAR_TITLE_PADDING 14
#define ATK_MENU_BAR_ENTRY_SPACING 8
#define ATK_MENU_BAR_LOGO_MARGIN_X 12
#define ATK_MENU_BAR_LOGO_MARGIN_Y 6
#define ATK_MENU_BAR_VOLUME_BUTTON_WIDTH 28
#ifdef ATK_NO_DESKTOP_APPS
#define ATK_MENU_BAR_CLOCK_RESERVE 0
#else
#define ATK_MENU_BAR_CLOCK_RESERVE 140
#endif

#ifndef MENU_BAR_TRACE
#define MENU_BAR_TRACE 0
#endif

struct atk_menu_bar_entry
{
    char title[ATK_MENU_ITEM_TITLE_MAX];
    atk_widget_t *menu;
    atk_list_node_t *list_node;
    int x;
    int width;
    int text_width;
    bool is_logo;
};

static void atk_menu_bar_entry_destroy(void *value);
static void atk_menu_bar_update_layout(atk_state_t *state);
static atk_menu_bar_entry_t *atk_menu_bar_entry_hit_test(atk_state_t *state, int px);
static bool atk_menu_bar_build_logo(atk_state_t *state);
static void menu_action_welcome(void *context);
#ifdef KERNEL_BUILD
static void menu_action_shutdown(void *context);
static void menu_shutdown_thread(void *arg);
#endif
static int atk_menu_bar_measure_title(const char *title);
static int atk_menu_bar_height_pixels(const atk_state_t *state);
static void atk_menu_bar_mark_dirty(const atk_state_t *state);
static void atk_menu_bar_mark_menu_area(const atk_widget_t *menu);
#ifndef ATK_NO_DESKTOP_APPS
#define ATK_MENU_BAR_CLOCK_REFRESH_INTERVAL_MS 5000ULL
static bool g_clock_poll_enabled = false;
static uint64_t g_clock_next_refresh_ms = 0;
static atk_widget_t *g_volume_window = NULL;
static atk_widget_t *g_volume_scrollbar = NULL;
#endif

static inline void menu_log(const char *msg) { (void)msg; }
static inline void menu_log_pair(const char *msg, const char *detail) { (void)msg; (void)detail; }
static inline void menu_log_coords(const char *msg, int x, int y) { (void)msg; (void)x; (void)y; }
void atk_menu_bar_reset(atk_state_t *state)
{
    if (!state)
    {
        return;
    }

#ifndef ATK_NO_DESKTOP_APPS
    if (g_volume_window)
    {
        atk_window_close(state, g_volume_window);
        g_volume_window = NULL;
        g_volume_scrollbar = NULL;
    }
#endif

    atk_guard_check(&state->menu_guard_front, &state->menu_guard_back, "state->menu_entries");
    atk_list_clear(&state->menu_entries, atk_menu_bar_entry_destroy);
    atk_list_init(&state->menu_entries);
    atk_guard_reset(&state->menu_guard_front, &state->menu_guard_back);
    state->menu_open_entry = NULL;
    state->menu_hover_entry = NULL;

    if (state->menu_logo)
    {
        atk_image_destroy(state->menu_logo);
        atk_widget_destroy(state->menu_logo);
        state->menu_logo = NULL;
    }

    state->menu_bar_height = ATK_MENU_BAR_DEFAULT_HEIGHT;
}

void atk_menu_bar_set_enabled(atk_state_t *state, bool enabled)
{
    if (!state)
    {
        return;
    }

    int previous_height = atk_menu_bar_height_pixels(state);
    bool was_enabled = previous_height > 0;

    if (enabled)
    {
        if (!was_enabled)
        {
            state->menu_bar_height = ATK_MENU_BAR_DEFAULT_HEIGHT;
            atk_menu_bar_mark_dirty(state);
        }
        return;
    }

    if (!was_enabled)
    {
        return;
    }

    state->menu_bar_height = 0;
    if (state->menu_open_entry && state->menu_open_entry->menu)
    {
        atk_menu_hide(state->menu_open_entry->menu);
        atk_menu_bar_mark_menu_area(state->menu_open_entry->menu);
    }
    state->menu_open_entry = NULL;
    state->menu_hover_entry = NULL;
    atk_dirty_mark_rect(0, 0, video_screen_width(), previous_height);
}

int atk_menu_bar_height(const atk_state_t *state)
{
    return atk_menu_bar_height_pixels(state);
}

#ifdef ATK_NO_DESKTOP_APPS
void atk_menu_bar_enable_clock_timer(void)
{
}
#else
void atk_menu_bar_enable_clock_timer(void)
{
    g_clock_poll_enabled = true;
    g_clock_next_refresh_ms = 0;
}
#endif

#ifdef ATK_NO_DESKTOP_APPS
void atk_menu_bar_poll_clock(void)
{
}
#else
void atk_menu_bar_poll_clock(void)
{
    if (!g_clock_poll_enabled)
    {
        return;
    }

    uint64_t now_ms = timekeeping_now_millis();
    if (g_clock_next_refresh_ms != 0 && now_ms < g_clock_next_refresh_ms)
    {
        return;
    }
    g_clock_next_refresh_ms = now_ms + ATK_MENU_BAR_CLOCK_REFRESH_INTERVAL_MS;

    atk_state_lock_init();
    uint64_t irq_state = atk_state_lock_acquire();
    atk_state_t *state = atk_state_get();
    int height = atk_menu_bar_height_pixels(state);
    bool request_refresh = false;
    if (height > 0)
    {
        atk_dirty_mark_rect(video_screen_width() - ATK_MENU_BAR_CLOCK_RESERVE,
                            0,
                            ATK_MENU_BAR_CLOCK_RESERVE,
                            height);
        request_refresh = true;
    }
    atk_state_lock_release(irq_state);

    if (request_refresh)
    {
        video_request_refresh();
    }
}
#endif

void atk_menu_bar_build_default(atk_state_t *state)
{
    if (!state)
    {
        return;
    }

    atk_guard_check(&state->menu_guard_front, &state->menu_guard_back, "state->menu_entries");
    if (state->menu_bar_height <= 0)
    {
        state->menu_bar_height = ATK_MENU_BAR_DEFAULT_HEIGHT;
    }

    if (!atk_menu_bar_build_logo(state))
    {
        state->menu_logo = NULL;
    }

#ifdef KERNEL_BUILD
    atk_widget_t *logo_menu = atk_menu_create();
    if (logo_menu)
    {
        if (!atk_menu_add_item(logo_menu, "Shutdown", menu_action_shutdown, state))
        {
            atk_menu_destroy(logo_menu);
            logo_menu = NULL;
        }
    }

    if (logo_menu)
    {
        atk_menu_bar_entry_t *entry = (atk_menu_bar_entry_t *)malloc(sizeof(atk_menu_bar_entry_t));
        if (entry)
        {
            memset(entry, 0, sizeof(*entry));
            const char logo_title[] = "AlixOS";
            size_t len = strlen(logo_title);
            if (len >= sizeof(entry->title))
            {
                len = sizeof(entry->title) - 1;
            }
            memcpy(entry->title, logo_title, len);
            entry->title[len] = '\0';
            entry->menu = logo_menu;
            entry->text_width = 0;
            entry->is_logo = true;
            entry->width = (state->menu_logo ? state->menu_logo->width : atk_menu_bar_measure_title(entry->title)) +
                           ATK_MENU_BAR_ENTRY_SPACING;
            atk_list_node_t *node = atk_list_push_back(&state->menu_entries, entry);
            if (!node)
            {
                atk_menu_destroy(logo_menu);
                free(entry);
            }
            else
            {
                entry->list_node = node;
            }
        }
        else
        {
            atk_menu_destroy(logo_menu);
        }
    }
#endif

    atk_widget_t *help_menu = atk_menu_create();
    if (help_menu)
    {
        if (!atk_menu_add_item(help_menu, "Welcome", menu_action_welcome, state))
        {
            atk_menu_destroy(help_menu);
            help_menu = NULL;
        }
    }

    if (help_menu)
    {
        atk_menu_bar_entry_t *entry = (atk_menu_bar_entry_t *)malloc(sizeof(atk_menu_bar_entry_t));
        if (entry)
        {
            memset(entry, 0, sizeof(*entry));
#ifdef KERNEL_BUILD
            if (state->menu_entries.size > 8)
            {
                serial_printf("atk_menu_bar: entry count=%016llX",
                              (unsigned long long)(state->menu_entries.size));
            }
#endif
            const char help_title[] = "Help";
            size_t len = strlen(help_title);
            if (len >= sizeof(entry->title))
            {
                len = sizeof(entry->title) - 1;
            }
            memcpy(entry->title, help_title, len);
            entry->title[len] = '\0';
            entry->menu = help_menu;
            entry->text_width = atk_font_text_width(entry->title);
            entry->width = atk_menu_bar_measure_title(entry->title);
            atk_list_node_t *node = atk_list_push_back(&state->menu_entries, entry);
            if (!node)
            {
                atk_menu_destroy(help_menu);
                free(entry);
            }
            else
            {
                entry->list_node = node;
            }
        }
        else
        {
            atk_menu_destroy(help_menu);
        }
    }

    atk_menu_bar_update_layout(state);
    atk_menu_bar_mark_dirty(state);
}

#ifndef ATK_NO_DESKTOP_APPS
static void atk_menu_bar_clock_layout(int height,
                                      int *clock_x_out,
                                      int *clock_width_out,
                                      int *volume_x_out,
                                      int *volume_width_out)
{
    if (clock_x_out)
    {
        *clock_x_out = 0;
    }
    if (clock_width_out)
    {
        *clock_width_out = 0;
    }
    if (volume_x_out)
    {
        *volume_x_out = 0;
    }
    if (volume_width_out)
    {
        *volume_width_out = 0;
    }

    int screen_w = video_screen_width();
    if (screen_w <= 0)
    {
        return;
    }

    (void)height;
    char clock_text[16];
    timekeeping_format_time(clock_text, sizeof(clock_text));
    int clock_text_width = atk_font_text_width(clock_text);
    int clock_padding = 8;
    int clock_box_width = clock_text_width + clock_padding * 2;

    int min_clock_width = ATK_MENU_BAR_CLOCK_RESERVE -
                          ATK_MENU_BAR_VOLUME_BUTTON_WIDTH -
                          ATK_MENU_BAR_ENTRY_SPACING * 2;
    if (min_clock_width < 0)
    {
        min_clock_width = 0;
    }
    if (clock_box_width < min_clock_width)
    {
        clock_box_width = min_clock_width;
    }

    int clock_x = screen_w - clock_box_width - ATK_MENU_BAR_ENTRY_SPACING;
    if (clock_x < 0)
    {
        clock_x = 0;
    }

    int volume_width = ATK_MENU_BAR_VOLUME_BUTTON_WIDTH;
    int volume_x = clock_x - volume_width - ATK_MENU_BAR_ENTRY_SPACING;
    if (volume_x < 0)
    {
        volume_x = 0;
    }

    if (clock_x_out)
    {
        *clock_x_out = clock_x;
    }
    if (clock_width_out)
    {
        *clock_width_out = clock_box_width;
    }
    if (volume_x_out)
    {
        *volume_x_out = volume_x;
    }
    if (volume_width_out)
    {
        *volume_width_out = volume_width;
    }
}

static bool atk_menu_bar_point_in_window(const atk_widget_t *window, int px, int py)
{
    if (!window || !window->used)
    {
        return false;
    }
    int x0 = window->x;
    int y0 = window->y;
    int x1 = x0 + window->width;
    int y1 = y0 + window->height;
    return (px >= x0 && px < x1 && py >= y0 && py < y1);
}

static bool atk_menu_bar_sys_read_volume(uint32_t *value_out)
{
#ifdef KERNEL_BUILD
    if (!value_out)
    {
        return false;
    }
    vfs_node_t *node = vfs_resolve(vfs_root(), "/proc/sys/audio/volume");
    if (!node || !vfs_is_file(node))
    {
        return false;
    }
    char buf[16];
    ssize_t n = vfs_read_at(node, 0, buf, sizeof(buf));
    if (n <= 0)
    {
        return false;
    }
    size_t count = (size_t)n;
    size_t idx = 0;
    while (idx < count && (buf[idx] == ' ' || buf[idx] == '\t'))
    {
        ++idx;
    }
    uint64_t value = 0;
    size_t digits = 0;
    while (idx < count)
    {
        char ch = buf[idx];
        if (ch < '0' || ch > '9')
        {
            break;
        }
        value = value * 10u + (uint64_t)(ch - '0');
        ++idx;
        ++digits;
        if (value > 1000u)
        {
            return false;
        }
    }
    if (digits == 0)
    {
        return false;
    }
    if (value > 100u)
    {
        value = 100u;
    }
    *value_out = (uint32_t)value;
    return true;
#else
    (void)value_out;
    return false;
#endif
}

static void atk_menu_bar_sys_write_volume(uint32_t value)
{
#ifdef KERNEL_BUILD
    if (value > 100)
    {
        value = 100;
    }
    vfs_node_t *node = vfs_resolve(vfs_root(), "/proc/sys/audio/volume");
    if (!node || !vfs_is_file(node))
    {
        return;
    }

    char buf[8];
    size_t pos = 0;
    char tmp[3];
    size_t digits = 0;
    if (value == 0)
    {
        tmp[digits++] = '0';
    }
    else
    {
        while (value > 0 && digits < sizeof(tmp))
        {
            tmp[digits++] = (char)('0' + (value % 10u));
            value /= 10u;
        }
    }
    while (digits > 0 && pos < sizeof(buf))
    {
        buf[pos++] = tmp[--digits];
    }
    if (pos < sizeof(buf))
    {
        buf[pos++] = '\n';
    }
    (void)vfs_write_at(node, 0, buf, pos);
#else
    (void)value;
#endif
}

static void atk_menu_bar_volume_close(atk_state_t *state)
{
    if (!state || !g_volume_window)
    {
        return;
    }
    atk_window_close(state, g_volume_window);
    g_volume_window = NULL;
    g_volume_scrollbar = NULL;
}

static void atk_menu_bar_volume_scroll_changed(atk_widget_t *scrollbar, void *context, int value)
{
    (void)scrollbar;
    (void)context;
    if (value < 0)
    {
        value = 0;
    }
    if (value > 100)
    {
        value = 100;
    }
    /* Scrollbar top is min; map to volume so top == 100%. */
    uint32_t volume = (uint32_t)(100 - value);
    atk_menu_bar_sys_write_volume(volume);
}

static void atk_menu_bar_volume_open(atk_state_t *state, int volume_x, int volume_width, int menu_height)
{
    if (!state || g_volume_window)
    {
        return;
    }

    const int panel_w = 52;
    const int panel_h = 180;
    const int padding = 8;

    atk_widget_t *window = atk_window_create_at(state,
                                                volume_x + volume_width / 2,
                                                menu_height + panel_h / 2);
    if (!window)
    {
        return;
    }

    atk_window_set_chrome_visible(window, false);
    window->width = panel_w;
    window->height = panel_h;
    window->x = volume_x + (volume_width - panel_w) / 2;
    window->y = menu_height;
    atk_window_ensure_inside(window);

    int sb_w = window->width - padding * 2;
    int sb_h = window->height - padding * 2;
    if (sb_w < 12)
    {
        sb_w = 12;
    }
    if (sb_h < 24)
    {
        sb_h = 24;
    }

    atk_widget_t *scrollbar = atk_window_add_scrollbar(window,
                                                       padding,
                                                       padding,
                                                       sb_w,
                                                       sb_h,
                                                       ATK_SCROLLBAR_VERTICAL);
    if (!scrollbar)
    {
        atk_window_close(state, window);
        return;
    }

    atk_scrollbar_set_range(scrollbar, 0, 100, 1);
    uint32_t current = 100;
    if (atk_menu_bar_sys_read_volume(&current))
    {
        if (current > 100)
        {
            current = 100;
        }
    }
    atk_scrollbar_set_value(scrollbar, 100 - (int)current);
    atk_scrollbar_set_change_handler(scrollbar, atk_menu_bar_volume_scroll_changed, NULL);

    g_volume_window = window;
    g_volume_scrollbar = scrollbar;
    atk_window_bring_to_front(state, window);
    atk_window_mark_dirty(window);
    video_request_refresh_window(window);
}

static void atk_menu_bar_draw_speaker_icon(int x,
                                           int y,
                                           int width,
                                           int height,
                                           video_color_t fg)
{
    if (width <= 0 || height <= 0)
    {
        return;
    }

    int icon_w = width - 8;
    int icon_h = height - 10;
    if (icon_w > 18)
    {
        icon_w = 18;
    }
    if (icon_h > 18)
    {
        icon_h = 18;
    }
    if (icon_w < 12)
    {
        icon_w = 12;
    }
    if (icon_h < 12)
    {
        icon_h = 12;
    }

    int icon_x = x + (width - icon_w) / 2;
    int icon_y = y + (height - icon_h) / 2;

    int body_w = icon_w / 3;
    if (body_w < 4)
    {
        body_w = 4;
    }
    int body_h = icon_h / 2;
    if (body_h < 6)
    {
        body_h = 6;
    }
    int body_x = icon_x;
    int body_y = icon_y + (icon_h - body_h) / 2;

    /* Speaker body. */
    video_draw_rect(body_x, body_y, body_w, body_h, fg);

    /* Speaker cone (simple trapezoid-ish shape via a few rectangles). */
    int cone_x = body_x + body_w;
    int cone_w = icon_w - body_w - 6;
    if (cone_w < 5)
    {
        cone_w = 5;
    }
    int cone_h = body_h + 4;
    int cone_y = body_y - 2;
    video_draw_rect(cone_x, cone_y + 1, cone_w - 2, cone_h - 2, fg);
    video_draw_rect(cone_x + cone_w - 2, cone_y + 2, 2, cone_h - 4, fg);

    /* Sound waves: open rectangles without the left edge. */
    int tip_x = cone_x + cone_w;
    int wave2_x = tip_x + 1;
    int wave2_w = icon_x + icon_w - wave2_x;
    if (wave2_w > 5)
    {
        int wave2_y = icon_y + 3;
        int wave2_h = icon_h - 6;
        video_draw_rect(wave2_x, wave2_y, wave2_w, 1, fg);
        video_draw_rect(wave2_x, wave2_y + wave2_h - 1, wave2_w, 1, fg);
        video_draw_rect(wave2_x + wave2_w - 1, wave2_y, 1, wave2_h, fg);

        int wave1_x = wave2_x + 2;
        int wave1_w = wave2_w - 2;
        if (wave1_w > 3)
        {
            int wave1_y = wave2_y + 2;
            int wave1_h = wave2_h - 4;
            video_draw_rect(wave1_x, wave1_y, wave1_w, 1, fg);
            video_draw_rect(wave1_x, wave1_y + wave1_h - 1, wave1_w, 1, fg);
            video_draw_rect(wave1_x + wave1_w - 1, wave1_y, 1, wave1_h, fg);
        }
    }
}
#endif

void atk_menu_bar_draw(const atk_state_t *state)
{
    if (!state)
    {
        return;
    }

    atk_guard_check((uint64_t *)&state->menu_guard_front, (uint64_t *)&state->menu_guard_back, "state->menu_entries");
    atk_state_theme_validate(state, "atk_menu_bar_draw");
    int height = atk_menu_bar_height_pixels(state);
    if (height <= 0)
    {
        return;
    }
    const atk_theme_t *theme = &state->theme;

    int screen_w = video_screen_width();
    video_color_t bar_top = atk_color_tint(theme->menu_bar_face, 8);
    video_color_t bar_bottom = atk_color_tint(theme->menu_bar_face, -8);
    atk_draw_vertical_gradient(0, 0, screen_w, height, bar_top, bar_bottom);
    video_draw_rect(0, height - 1, screen_w, 1, atk_color_tint(theme->menu_dropdown_border, 8));
    video_draw_rect(0, 0, screen_w, 1, atk_color_tint(theme->menu_bar_face, 18));

    if (state->menu_logo && state->menu_logo->used)
    {
        atk_image_draw(state, state->menu_logo);
    }

    int baseline = atk_font_baseline_for_rect(0, height - 1);

    ATK_LIST_FOR_EACH(node, &state->menu_entries)
    {
        atk_menu_bar_entry_t *entry = (atk_menu_bar_entry_t *)node->value;
        if (!entry)
        {
            continue;
        }
        bool highlighted = (entry == state->menu_hover_entry) || (entry == state->menu_open_entry);
        if (entry->is_logo)
        {
            if (highlighted)
            {
                video_color_t entry_top = atk_color_tint(theme->menu_bar_highlight, 10);
                video_color_t entry_bottom = atk_color_tint(theme->menu_bar_highlight, -12);
                atk_draw_vertical_gradient(entry->x, 0, entry->width, height - 1, entry_top, entry_bottom);
                if (entry->width > 2 && height > 3)
                {
                    atk_draw_bevel_outline(entry->x,
                                           0,
                                           entry->width,
                                           height - 1,
                                           atk_color_tint(theme->menu_bar_highlight, 18),
                                           atk_color_tint(theme->menu_bar_highlight, -18));
                }
                if (state->menu_logo && state->menu_logo->used)
                {
                    atk_image_draw(state, state->menu_logo);
                }
            }
            continue;
        }
        if (highlighted)
        {
            video_color_t entry_top = atk_color_tint(theme->menu_bar_highlight, 10);
            video_color_t entry_bottom = atk_color_tint(theme->menu_bar_highlight, -12);
            atk_draw_vertical_gradient(entry->x, 0, entry->width, height - 1, entry_top, entry_bottom);
            if (entry->width > 2 && height > 3)
            {
                atk_draw_bevel_outline(entry->x,
                                       0,
                                       entry->width,
                                       height - 1,
                                       atk_color_tint(theme->menu_bar_highlight, 18),
                                       atk_color_tint(theme->menu_bar_highlight, -18));
            }
        }
        video_color_t fg = highlighted ? theme->menu_dropdown_face : theme->menu_bar_text;
        video_color_t bg = highlighted ? theme->menu_bar_highlight : theme->menu_bar_face;
        int text_width = entry->text_width;
        if (text_width <= 0)
        {
            text_width = atk_font_text_width(entry->title);
        }
        int text_x = entry->x + (entry->width - text_width) / 2;
        if (text_x < entry->x + 2)
        {
            text_x = entry->x + 2;
        }
        atk_rect_t clip = { entry->x, 0, entry->width, height };
        atk_font_draw_string_clipped(text_x, baseline, entry->title, fg, bg, &clip);
    }

    if (state->menu_open_entry && state->menu_open_entry->menu)
    {
        atk_menu_draw(state, state->menu_open_entry->menu);
    }

#ifndef ATK_NO_DESKTOP_APPS
    int clock_x = 0;
    int clock_box_width = 0;
    int volume_x = 0;
    int volume_width = 0;
    atk_menu_bar_clock_layout(height, &clock_x, &clock_box_width, &volume_x, &volume_width);

    bool volume_open = g_volume_window != NULL;
    video_color_t volume_bg = volume_open ? theme->menu_bar_highlight : theme->menu_bar_face;
    video_color_t volume_fg = volume_open ? theme->menu_dropdown_face : theme->menu_bar_text;
    if (volume_open)
    {
        video_color_t volume_top = atk_color_tint(volume_bg, 10);
        video_color_t volume_bottom = atk_color_tint(volume_bg, -12);
        atk_draw_vertical_gradient(volume_x, 0, volume_width, height - 1, volume_top, volume_bottom);
    }
    else
    {
        atk_draw_vertical_gradient(volume_x, 0, volume_width, height - 1, bar_top, bar_bottom);
    }
    atk_menu_bar_draw_speaker_icon(volume_x, 0, volume_width, height, volume_fg);

    char clock_text[16];
    timekeeping_format_time(clock_text, sizeof(clock_text));
    int clock_padding = 8;
    atk_draw_vertical_gradient(clock_x, 0, clock_box_width, height - 1, bar_top, bar_bottom);
    atk_rect_t clock_clip = { clock_x, 0, clock_box_width, height };
    atk_font_draw_string_clipped(clock_x + clock_padding,
                                 baseline,
                                 clock_text,
                                 theme->menu_bar_text,
                                 theme->menu_bar_face,
                                 &clock_clip);
#endif
}

bool atk_menu_bar_handle_mouse(atk_state_t *state,
                               int cursor_x,
                               int cursor_y,
                               bool pressed_edge,
                               bool released_edge,
                               bool left_pressed,
                               bool *redraw_out)
{
    (void)left_pressed;
    bool consumed = false;
    bool redraw = false;

    if (!state)
    {
        if (redraw_out)
        {
            *redraw_out = false;
        }
        return false;
    }

    int height = atk_menu_bar_height(state);
#if defined(KERNEL_BUILD) && MENU_BAR_TRACE
    if (pressed_edge || released_edge)
    {
        serial_printf("[menu_bar] event x=%016llX y=%016llX press=%016llX release=%016llX left=%016llX",
                      (unsigned long long)((uint64_t)(int64_t)cursor_x),
                      (unsigned long long)((uint64_t)(int64_t)cursor_y),
                      (unsigned long long)(pressed_edge ? 1 : 0),
                      (unsigned long long)(released_edge ? 1 : 0),
                      (unsigned long long)(left_pressed ? 1 : 0));
    }
#endif
    if (height <= 0)
    {
        if (redraw_out)
        {
            *redraw_out = false;
        }
        return false;
    }
    bool inside_bar = (cursor_y >= 0 && cursor_y < height);

#ifndef ATK_NO_DESKTOP_APPS
    int volume_x = 0;
    int volume_w = 0;
    atk_menu_bar_clock_layout(height, NULL, NULL, &volume_x, &volume_w);
    bool volume_button_hit = inside_bar && cursor_x >= volume_x && cursor_x < volume_x + volume_w;
    bool volume_window_hit = (!inside_bar) && atk_menu_bar_point_in_window(g_volume_window, cursor_x, cursor_y);

    if (pressed_edge && g_volume_window && !volume_button_hit && !volume_window_hit)
    {
        atk_menu_bar_volume_close(state);
        redraw = true;
        atk_menu_bar_mark_dirty(state);
    }

    if (pressed_edge && volume_button_hit)
    {
        consumed = true;
        if (state->menu_open_entry && state->menu_open_entry->menu)
        {
            atk_menu_hide(state->menu_open_entry->menu);
            atk_menu_bar_mark_menu_area(state->menu_open_entry->menu);
            state->menu_open_entry = NULL;
        }
        if (g_volume_window)
        {
            atk_menu_bar_volume_close(state);
        }
        else
        {
            atk_menu_bar_volume_open(state, volume_x, volume_w, height);
        }
        redraw = true;
        atk_menu_bar_mark_dirty(state);
    }
#endif

    atk_menu_bar_entry_t *hover_entry = inside_bar ? atk_menu_bar_entry_hit_test(state, cursor_x) : NULL;

    if (hover_entry != state->menu_hover_entry)
    {
        state->menu_hover_entry = hover_entry;
        redraw = true;
        atk_menu_bar_mark_dirty(state);
    }

    if (pressed_edge && inside_bar && hover_entry)
    {
#if defined(KERNEL_BUILD) && MENU_BAR_TRACE
        serial_printf("[menu_bar] press entry: %s", hover_entry->title ? hover_entry->title : "(null)");
#endif
        consumed = true;
        if (state->menu_open_entry == hover_entry)
        {
            atk_menu_hide(hover_entry->menu);
            state->menu_open_entry = NULL;
            atk_menu_bar_mark_menu_area(hover_entry->menu);
            atk_menu_bar_mark_dirty(state);
        }
        else
        {
            if (state->menu_open_entry && state->menu_open_entry->menu)
            {
                atk_menu_hide(state->menu_open_entry->menu);
                atk_menu_bar_mark_menu_area(state->menu_open_entry->menu);
            }
            int menu_x = hover_entry->x;
            if (hover_entry->menu)
            {
                int menu_width = hover_entry->menu->width;
                int screen_w = video_screen_width();
                if (menu_x + menu_width > screen_w - 2)
                {
                    menu_x = screen_w - menu_width - 2;
                }
                if (menu_x < 0)
                {
                    menu_x = 0;
                }
                atk_menu_show(hover_entry->menu, menu_x, height);
            }
            state->menu_open_entry = hover_entry;
            atk_menu_bar_mark_dirty(state);
        }
        redraw = true;
    }
    else if (pressed_edge &&
             state->menu_open_entry &&
             !inside_bar &&
             !atk_menu_contains(state->menu_open_entry->menu, cursor_x, cursor_y))
    {
        atk_menu_hide(state->menu_open_entry->menu);
        state->menu_open_entry = NULL;
        consumed = true;
        redraw = true;
        atk_menu_bar_mark_dirty(state);
    }

    if (state->menu_open_entry && state->menu_open_entry->menu)
    {
        if (!pressed_edge && !released_edge)
        {
            if (atk_menu_update_hover(state->menu_open_entry->menu, cursor_x, cursor_y))
            {
                redraw = true;
            }
        }

        if (released_edge)
        {
#ifdef KERNEL_BUILD
            menu_log_pair("release", state->menu_open_entry->title);
            menu_log_coords("release coords", cursor_x, cursor_y);
            serial_printf("[menu_bar] menu bounds x=%016llX y=%016llX w=%016llX h=%016llX",
                          (unsigned long long)((uint64_t)(int64_t)state->menu_open_entry->menu->x),
                          (unsigned long long)((uint64_t)(int64_t)state->menu_open_entry->menu->y),
                          (unsigned long long)((uint64_t)(int64_t)state->menu_open_entry->menu->width),
                          (unsigned long long)((uint64_t)(int64_t)state->menu_open_entry->menu->height));
#endif
            if (atk_menu_contains(state->menu_open_entry->menu, cursor_x, cursor_y))
            {
#ifdef KERNEL_BUILD
                menu_log("release inside menu");
#endif
                if (atk_menu_handle_click(state->menu_open_entry->menu, cursor_x, cursor_y))
                {
                    atk_menu_hide(state->menu_open_entry->menu);
                    state->menu_open_entry = NULL;
                    redraw = true;
                    atk_menu_bar_mark_dirty(state);
                }
                consumed = true;
            }
            else if (!inside_bar)
            {
#ifdef KERNEL_BUILD
                menu_log("release outside menu");
#endif
                atk_menu_hide(state->menu_open_entry->menu);
                state->menu_open_entry = NULL;
                redraw = true;
                consumed = true;
            }
        }
    }

    bool menu_visible = state->menu_open_entry &&
                        state->menu_open_entry->menu &&
                        atk_menu_is_visible(state->menu_open_entry->menu);
    if (!consumed && menu_visible)
    {
        consumed = true;
    }

    if (redraw_out)
    {
        *redraw_out = redraw;
    }
    return consumed;
}

static void atk_menu_bar_entry_destroy(void *value)
{
    atk_menu_bar_entry_t *entry = (atk_menu_bar_entry_t *)value;
    if (!entry)
    {
        return;
    }
    if (entry->menu)
    {
        atk_menu_destroy(entry->menu);
        entry->menu = NULL;
    }
    entry->list_node = NULL;
    free(entry);
}

static void atk_menu_bar_update_layout(atk_state_t *state)
{
    if (!state)
    {
        return;
    }
    int cursor = ATK_MENU_BAR_LOGO_MARGIN_X;
    int max_right = video_screen_width() - ATK_MENU_BAR_CLOCK_RESERVE;
    if (max_right < cursor)
    {
        max_right = cursor;
    }

    ATK_LIST_FOR_EACH(node, &state->menu_entries)
    {
        atk_menu_bar_entry_t *entry = (atk_menu_bar_entry_t *)node->value;
        if (!entry)
        {
            continue;
        }
        entry->text_width = entry->is_logo ? 0 : atk_font_text_width(entry->title);
        if (entry->is_logo)
        {
            int logo_width = state->menu_logo ? state->menu_logo->width : atk_menu_bar_measure_title(entry->title);
            entry->width = logo_width + ATK_MENU_BAR_ENTRY_SPACING;
        }
        else
        {
            entry->width = atk_menu_bar_measure_title(entry->title);
        }
        entry->x = cursor;
        if (entry->x + entry->width > max_right)
        {
            entry->x = max_right - entry->width;
            if (entry->x < ATK_MENU_BAR_LOGO_MARGIN_X)
            {
                entry->x = ATK_MENU_BAR_LOGO_MARGIN_X;
            }
        }
        cursor += entry->width + ATK_MENU_BAR_ENTRY_SPACING;
        if (cursor > max_right)
        {
            cursor = max_right;
        }
    }
}

static atk_menu_bar_entry_t *atk_menu_bar_entry_hit_test(atk_state_t *state, int px)
{
    if (!state)
    {
        return NULL;
    }
    ATK_LIST_FOR_EACH(node, &state->menu_entries)
    {
        atk_menu_bar_entry_t *entry = (atk_menu_bar_entry_t *)node->value;
        if (!entry)
        {
            continue;
        }
        if (px >= entry->x && px < entry->x + entry->width)
        {
            return entry;
        }
    }
    return NULL;
}

static bool atk_menu_bar_build_logo(atk_state_t *state)
{
    if (!state)
    {
        return false;
    }

    static const char logo_text[] = "AlixOS";
    size_t text_len = strlen(logo_text);
    if (text_len == 0)
    {
        return false;
    }

    int glyph_width = FONT_BASIC_WIDTH;
    int glyph_height = FONT_BASIC_HEIGHT_X2;
    int spacing = 2;
    int margin_x = ATK_MENU_BAR_LOGO_MARGIN_X;
    int margin_y = ATK_MENU_BAR_LOGO_MARGIN_Y;
    int width = margin_x * 2 + (int)text_len * glyph_width + (int)(text_len - 1) * spacing;
    int height = margin_y * 2 + glyph_height;

    size_t pixel_count = (size_t)width * (size_t)height;
    video_color_t *pixels = (video_color_t *)malloc(pixel_count * sizeof(video_color_t));
    if (!pixels)
    {
        return false;
    }

    video_color_t bg = video_make_color(0x18, 0x2F, 0x4C);
    video_color_t fg_primary = video_make_color(0xF2, 0xF4, 0xF8);
    video_color_t fg_accent = video_make_color(0xFF, 0xA3, 0x3C);
    for (size_t i = 0; i < pixel_count; ++i)
    {
        pixels[i] = bg;
    }

    int pen_x = margin_x;
    for (size_t idx = 0; idx < text_len; ++idx)
    {
        char ch = logo_text[idx];
        if (ch >= 'a' && ch <= 'z')
        {
            ch = (char)(ch - ('a' - 'A'));
        }

        uint8_t glyph[FONT_BASIC_HEIGHT_X2];
        font_basic_copy_glyph8x16((uint8_t)ch, glyph);
        video_color_t fg = (idx < 3) ? fg_primary : fg_accent;

        for (int row = 0; row < glyph_height; ++row)
        {
            for (int col = 0; col < glyph_width; ++col)
            {
                bool on = (glyph[row] & (1u << (7 - col))) != 0;
                if (!on)
                {
                    continue;
                }
                int px = pen_x + col;
                int py = margin_y + row;
                if (px < 0 || py < 0 || px >= width || py >= height)
                {
                    continue;
                }
                pixels[py * width + px] = fg;
            }
        }

        pen_x += glyph_width + spacing;
    }

    atk_widget_t *image = atk_widget_create(&ATK_IMAGE_CLASS);
    if (!image)
    {
        free(pixels);
        return false;
    }

    image->used = true;
    image->parent = NULL;
    image->x = ATK_MENU_BAR_LOGO_MARGIN_X;
    image->y = (state->menu_bar_height - height) / 2;
    if (image->y < 0)
    {
        image->y = 0;
    }

    if (!atk_image_set_pixels(image, pixels, width, height, width * (int)sizeof(video_color_t), true))
    {
        free(pixels);
        atk_widget_destroy(image);
        return false;
    }

    state->menu_logo = image;
    return true;
}

#ifdef KERNEL_BUILD
static void menu_action_shutdown(void *context)
{
    (void)context;
    static volatile bool shutdown_started = false;
    if (shutdown_started)
    {
        return;
    }
    shutdown_started = true;

    process_t *proc = process_create_kernel("shutdown",
                                            menu_shutdown_thread,
                                            NULL,
                                            PROCESS_DEFAULT_STACK_SIZE,
                                            -1);
    if (!proc)
    {
        /* Fall back to synchronous shutdown if we failed to spawn a worker. */
        menu_shutdown_thread(NULL);
    }
}

static void menu_shutdown_thread(void *arg)
{
    (void)arg;
    shell_output_t out;
    shell_output_init_console(&out);
    shell_cmd_shutdown(NULL, &out, "");
}
#endif

static void menu_action_welcome(void *context)
{
    atk_state_t *state = (atk_state_t *)context;
    if (!state)
    {
        menu_log("welcome: missing state");
        return;
    }

    menu_log("welcome: invoked");
    atk_widget_t *window = atk_window_create_at(state, video_screen_width() / 2, state->menu_bar_height + 120);
    if (!window)
    {
        menu_log("welcome: window creation failed");
        return;
    }

    atk_window_set_title_text(window, "Welcome to AlixOS");
    int padding = 20;
    int label_y = ATK_WINDOW_TITLE_HEIGHT + 12;
    atk_widget_t *label = atk_window_add_label(window,
                                               padding,
                                               label_y,
                                               window->width - padding * 2,
                                               window->height - label_y - padding);
    if (label)
    {
        atk_label_set_text(label,
                           "Thank you for trying AlixOS!\n\n"
                           "Networking now comes up automatically thanks to\n"
                           "the new startup scripts (dhclient igb0).\n"
                           "Use the top menu bar to find Help items like this.");
        menu_log("welcome: label set");
    }
    atk_window_bring_to_front(state, window);
    atk_window_mark_dirty(window);
    video_request_refresh_window(window);
    menu_log("welcome: window queued for redraw");
}

static int atk_menu_bar_measure_title(const char *title)
{
    int text_width = atk_font_text_width(title);
    if (text_width <= 0)
    {
        size_t len = title ? strlen(title) : 0;
        text_width = (int)len * ATK_FONT_WIDTH;
    }
    int width = text_width + ATK_MENU_BAR_TITLE_PADDING * 2;
    if (width < ATK_FONT_WIDTH * 3)
    {
        width = ATK_FONT_WIDTH * 3;
    }
    return width;
}

static int atk_menu_bar_height_pixels(const atk_state_t *state)
{
    if (!state)
    {
        return ATK_MENU_BAR_DEFAULT_HEIGHT;
    }
    if (state->menu_bar_height == 0)
    {
        return 0;
    }
    if (state->menu_bar_height < 0)
    {
        return ATK_MENU_BAR_DEFAULT_HEIGHT;
    }
    return state->menu_bar_height;
}

static void atk_menu_bar_mark_dirty(const atk_state_t *state)
{
    if (!state)
    {
        return;
    }
    int height = atk_menu_bar_height_pixels(state);
    if (height <= 0)
    {
        return;
    }
    atk_dirty_mark_rect(0, 0, video_screen_width(), height);
}

static void atk_menu_bar_mark_menu_area(const atk_widget_t *menu)
{
    if (!menu || !menu->used)
    {
        return;
    }
    atk_dirty_mark_rect(menu->x, menu->y, menu->width, menu->height);
}
