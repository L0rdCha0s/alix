#include "atk_menu_bar.h"

#include "atk/atk_image.h"
#include "atk/atk_label.h"
#include "atk/atk_menu.h"
#include "atk/atk_font.h"
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
#include "timer.h"
#endif

#define ATK_MENU_BAR_TITLE_PADDING 14
#define ATK_MENU_BAR_ENTRY_SPACING 8
#define ATK_MENU_BAR_LOGO_MARGIN_X 12
#define ATK_MENU_BAR_LOGO_MARGIN_Y 6
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
static void atk_menu_bar_clock_tick(void *context);
static bool g_clock_timer_registered = false;
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
    atk_dirty_mark_rect(0, 0, VIDEO_WIDTH, previous_height);
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
    if (g_clock_timer_registered)
    {
        return;
    }
    uint32_t interval = timer_frequency();
    if (interval == 0)
    {
        interval = 100;
    }
    if (timer_register_periodic(atk_menu_bar_clock_tick, NULL, interval))
    {
        g_clock_timer_registered = true;
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
                serial_printf("%s", "atk_menu_bar: entry count=");
                serial_printf("%016llX", (unsigned long long)(state->menu_entries.size));
                serial_printf("%s", "\r\n");
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

    video_draw_rect(0, 0, VIDEO_WIDTH, height, theme->menu_bar_face);
    video_draw_rect(0, height - 1, VIDEO_WIDTH, 1, theme->menu_dropdown_border);

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
                video_draw_rect(entry->x,
                                0,
                                entry->width,
                                height - 1,
                                theme->menu_bar_highlight);
                if (state->menu_logo && state->menu_logo->used)
                {
                    atk_image_draw(state, state->menu_logo);
                }
            }
            continue;
        }
        if (highlighted)
        {
            video_draw_rect(entry->x,
                            0,
                            entry->width,
                            height - 1,
                            theme->menu_bar_highlight);
        }
        video_color_t fg = highlighted ? theme->menu_dropdown_border : theme->menu_bar_text;
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
    char clock_text[16];
    timekeeping_format_time(clock_text, sizeof(clock_text));
    int clock_text_width = atk_font_text_width(clock_text);
    int clock_padding = 8;
    int clock_box_width = clock_text_width + clock_padding * 2;
    if (clock_box_width < ATK_MENU_BAR_CLOCK_RESERVE - ATK_MENU_BAR_ENTRY_SPACING)
    {
        clock_box_width = ATK_MENU_BAR_CLOCK_RESERVE - ATK_MENU_BAR_ENTRY_SPACING;
    }
    int clock_x = VIDEO_WIDTH - clock_box_width - ATK_MENU_BAR_ENTRY_SPACING;
    if (clock_x < 0)
    {
        clock_x = 0;
    }
    video_draw_rect(clock_x,
                    0,
                    clock_box_width,
                    height - 1,
                    theme->menu_bar_face);
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
        serial_printf("[menu_bar] event x=%016llX y=%016llX press=%016llX release=%016llX left=%016llX\r\n",
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
        serial_printf("[menu_bar] press entry: %s\r\n", hover_entry->title ? hover_entry->title : "(null)");
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
                if (menu_x + menu_width > VIDEO_WIDTH - 2)
                {
                    menu_x = VIDEO_WIDTH - menu_width - 2;
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
            serial_printf("%s", "[menu_bar] menu bounds x=");
            serial_printf("%016llX", (unsigned long long)((uint64_t)(int64_t)state->menu_open_entry->menu->x));
            serial_printf("%s", " y=");
            serial_printf("%016llX", (unsigned long long)((uint64_t)(int64_t)state->menu_open_entry->menu->y));
            serial_printf("%s", " w=");
            serial_printf("%016llX", (unsigned long long)((uint64_t)(int64_t)state->menu_open_entry->menu->width));
            serial_printf("%s", " h=");
            serial_printf("%016llX", (unsigned long long)((uint64_t)(int64_t)state->menu_open_entry->menu->height));
            serial_printf("%s", "\r\n");
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
    int max_right = VIDEO_WIDTH - ATK_MENU_BAR_CLOCK_RESERVE;
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
    atk_widget_t *window = atk_window_create_at(state, VIDEO_WIDTH / 2, state->menu_bar_height + 120);
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
                           "the new startup scripts (dhclient rtl0).\n"
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
    atk_dirty_mark_rect(0, 0, VIDEO_WIDTH, height);
}

static void atk_menu_bar_mark_menu_area(const atk_widget_t *menu)
{
    if (!menu || !menu->used)
    {
        return;
    }
    atk_dirty_mark_rect(menu->x, menu->y, menu->width, menu->height);
}

#ifndef ATK_NO_DESKTOP_APPS
static void atk_menu_bar_clock_tick(void *context)
{
    (void)context;
    atk_state_lock_init();
    uint64_t irq_state = atk_state_lock_acquire();
    atk_state_t *state = atk_state_get();
    int height = atk_menu_bar_height_pixels(state);
    if (height <= 0)
    {
        goto out;
    }
    atk_dirty_mark_rect(VIDEO_WIDTH - ATK_MENU_BAR_CLOCK_RESERVE, 0, ATK_MENU_BAR_CLOCK_RESERVE, height);
out:
    atk_state_lock_release(irq_state);
}
#endif
