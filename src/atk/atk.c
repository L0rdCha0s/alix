#include "atk.h"

#include <stddef.h>

#include "video.h"
#include "serial.h"

#include "atk_desktop.h"
#include "atk_internal.h"
#include "atk_menu_bar.h"
#include "atk_window.h"
#include "atk/atk_list_view.h"
#include "atk/atk_scrollbar.h"
#include "atk/atk_tabs.h"
#include "atk/atk_text_input.h"
#include "atk_event_debug.h"
#ifdef KERNEL_BUILD
#include "vfs.h"
#include "atk/util/png.h"
#endif
#ifndef KERNEL_BUILD
#include "atk/atk_terminal.h"
#endif
#include "user_atk_host.h"
#include "libc.h"

#ifndef ATK_NO_DESKTOP_APPS
#include "process.h"
#include "vfs.h"
#endif

#define ATK_MAX_BG_RECTS 64

typedef struct
{
    int x;
    int y;
    int width;
    int height;
} atk_bg_rect_t;

#if defined(KERNEL_BUILD) && ATK_DEBUG
#define ATK_MOUSE_LOG(...) serial_printf(__VA_ARGS__)
#else
#define ATK_MOUSE_LOG(...) ((void)0)
#endif

static void atk_apply_default_theme(atk_state_t *state);
static __attribute__((unused)) void action_exit_to_text(atk_widget_t *button, void *context);
static void atk_build_mouse_event(const atk_widget_t *widget,
                                  int cursor_x,
                                  int cursor_y,
                                  bool pressed_edge,
                                  bool released_edge,
                                  bool left_pressed,
                                  uint64_t event_id,
                                  atk_mouse_event_t *event);
static bool atk_dispatch_widget_mouse(atk_state_t *state,
                                      atk_widget_t *widget,
                                      int cursor_x,
                                      int cursor_y,
                                      bool pressed_edge,
                                      bool released_edge,
                                      bool left_pressed,
                                      const char *stage,
                                      uint64_t event_id,
                                      atk_mouse_event_result_t *result);
static void atk_clear_focus_widget(atk_state_t *state);
#ifndef ATK_NO_DESKTOP_APPS
static void action_open_task_manager(atk_widget_t *button, void *context);
static void action_open_atk_terminal(atk_widget_t *button, void *context);
static void action_open_atk_demo(atk_widget_t *button, void *context);
static void action_open_control_panel(atk_widget_t *button, void *context);
static void atk_schedule_user_launch(const char *launcher_name, const void *info);
static void atk_launch_user_binary(void *arg) __attribute__((noreturn));

typedef struct
{
    const char *path;
    const char *name;
} atk_user_launch_info_t;
#endif

#ifdef KERNEL_BUILD
typedef struct
{
    video_color_t *pixels;
    int width;
    int height;
    int stride_bytes;
    char path[256];
    bool loaded;
} atk_background_image_t;

static atk_background_image_t g_atk_background = { 0 };

static void atk_background_free(void)
{
    if (g_atk_background.pixels)
    {
        free(g_atk_background.pixels);
    }
    g_atk_background.pixels = NULL;
    g_atk_background.width = 0;
    g_atk_background.height = 0;
    g_atk_background.stride_bytes = 0;
    g_atk_background.path[0] = '\0';
    g_atk_background.loaded = false;
}

static void atk_background_clear(void)
{
    if (g_atk_background.loaded)
    {
        atk_background_free();
        atk_dirty_mark_all();
    }
}

static bool atk_background_load_path(const char *path)
{
    if (!path || *path == '\0')
    {
        return false;
    }

    vfs_node_t *node = vfs_resolve(vfs_root(), path);
    if (!node || !vfs_is_file(node))
    {
        return false;
    }
    size_t size = 0;
    const char *data = vfs_data(node, &size);
    if (!data || size == 0)
    {
        return false;
    }

    video_color_t *pixels = NULL;
    int w = 0, h = 0, stride = 0;
    int rc = png_decode_rgba32((const uint8_t *)data, size, &pixels, &w, &h, &stride);
    if (rc != 0 || !pixels)
    {
        return false;
    }

    atk_background_free();
    g_atk_background.pixels = pixels;
    g_atk_background.width = w;
    g_atk_background.height = h;
    g_atk_background.stride_bytes = stride;
    g_atk_background.loaded = true;
    size_t path_len = strlen(path);
    if (path_len >= sizeof(g_atk_background.path))
    {
        path_len = sizeof(g_atk_background.path) - 1;
    }
    memcpy(g_atk_background.path, path, path_len);
    g_atk_background.path[path_len] = '\0';
    return true;
}

static void atk_background_reload_if_needed(void)
{
    vfs_node_t *bgfile = vfs_resolve(vfs_root(), "/etc/display/background");
    if (!bgfile || !vfs_is_file(bgfile))
    {
        atk_background_clear();
        return;
    }

    size_t size = 0;
    const char *data = vfs_data(bgfile, &size);
    if (!data || size == 0)
    {
        atk_background_clear();
        return;
    }

    char path[256];
    size_t copy = (size < sizeof(path) - 1) ? size : (sizeof(path) - 1);
    memcpy(path, data, copy);
    path[copy] = '\0';

    while (copy > 0 && (path[copy - 1] == '\n' || path[copy - 1] == '\r' || path[copy - 1] == ' ' || path[copy - 1] == '\t'))
    {
        path[--copy] = '\0';
    }

    if (path[0] == '\0')
    {
        atk_background_clear();
        return;
    }

    if (g_atk_background.loaded && strcmp(path, g_atk_background.path) == 0)
    {
        return;
    }

    if (atk_background_load_path(path))
    {
        atk_dirty_mark_all();
    }
    else
    {
        atk_background_clear();
    }
}

static void atk_paint_background_region(const atk_state_t *state, int x, int y, int width, int height)
{
    if (!state || width <= 0 || height <= 0)
    {
        return;
    }

    bool have_wall = g_atk_background.loaded && g_atk_background.pixels;
    bool wall_covers_screen = have_wall &&
                              g_atk_background.width  >= VIDEO_WIDTH &&
                              g_atk_background.height >= VIDEO_HEIGHT;

    /* If the wallpaper covers the whole screen, avoid painting the solid
     * theme background first to prevent visible flashes during resize.
     * For partial wallpapers we still clear to the theme color so uncovered
     * areas stay deterministic. */
    if (!have_wall || !wall_covers_screen)
    {
        video_draw_rect(x, y, width, height, state->theme.background);
    }

    if (!have_wall)
    {
        return;
    }

    int dst_x0 = x < 0 ? 0 : x;
    int dst_y0 = y < 0 ? 0 : y;
    int dst_x1 = x + width;
    int dst_y1 = y + height;

    if (dst_x1 > VIDEO_WIDTH) dst_x1 = VIDEO_WIDTH;
    if (dst_y1 > VIDEO_HEIGHT) dst_y1 = VIDEO_HEIGHT;

    int src_x0 = dst_x0;
    int src_y0 = dst_y0;
    if (src_x0 >= g_atk_background.width || src_y0 >= g_atk_background.height)
    {
        return;
    }

    int copy_w = dst_x1 - dst_x0;
    int copy_h = dst_y1 - dst_y0;
    if (copy_w > g_atk_background.width - src_x0)
    {
        copy_w = g_atk_background.width - src_x0;
    }
    if (copy_h > g_atk_background.height - src_y0)
    {
        copy_h = g_atk_background.height - src_y0;
    }
    if (copy_w <= 0 || copy_h <= 0)
    {
        return;
    }

    const uint8_t *src_row = (const uint8_t *)g_atk_background.pixels +
                             (size_t)src_y0 * (size_t)g_atk_background.stride_bytes +
                             (size_t)src_x0 * sizeof(video_color_t);
    video_blit_rgba32(dst_x0,
                      dst_y0,
                      copy_w,
                      copy_h,
                      (const video_color_t *)src_row,
                      g_atk_background.stride_bytes,
                      true);
}
#else
static __attribute__((unused)) void atk_background_reload_if_needed(void) {}
static void atk_paint_background_region(const atk_state_t *state, int x, int y, int width, int height)
{
    if (!state || width <= 0 || height <= 0)
    {
        return;
    }
    video_draw_rect(x, y, width, height, state->theme.background);
}
#endif

static bool atk_rect_overlap(const atk_bg_rect_t *a, const atk_bg_rect_t *b)
{
    if (!a || !b || a->width <= 0 || a->height <= 0 || b->width <= 0 || b->height <= 0)
    {
        return false;
    }
    int ax1 = a->x + a->width;
    int ay1 = a->y + a->height;
    int bx1 = b->x + b->width;
    int by1 = b->y + b->height;
    return !(ax1 <= b->x || ay1 <= b->y || bx1 <= a->x || by1 <= a->y);
}

static int atk_rect_subtract(const atk_bg_rect_t *src,
                             const atk_bg_rect_t *mask,
                             atk_bg_rect_t *out,
                             int out_cap)
{
    if (!src || src->width <= 0 || src->height <= 0 || out_cap <= 0)
    {
        return 0;
    }
    if (!mask || mask->width <= 0 || mask->height <= 0 || !atk_rect_overlap(src, mask))
    {
        out[0] = *src;
        return 1;
    }

    int ox0 = src->x > mask->x ? src->x : mask->x;
    int oy0 = src->y > mask->y ? src->y : mask->y;
    int ox1 = (src->x + src->width) < (mask->x + mask->width) ? (src->x + src->width) : (mask->x + mask->width);
    int oy1 = (src->y + src->height) < (mask->y + mask->height) ? (src->y + src->height) : (mask->y + mask->height);

    int count = 0;

    /* Top strip */
    if (src->y < oy0 && count < out_cap)
    {
        out[count++] = (atk_bg_rect_t){ src->x, src->y, src->width, oy0 - src->y };
    }

    /* Bottom strip */
    int src_y1 = src->y + src->height;
    if (oy1 < src_y1 && count < out_cap)
    {
        out[count++] = (atk_bg_rect_t){ src->x, oy1, src->width, src_y1 - oy1 };
    }

    int mid_y = oy0;
    int mid_h = oy1 - oy0;
    if (mid_h > 0)
    {
        /* Left strip */
        if (src->x < ox0 && count < out_cap)
        {
            out[count++] = (atk_bg_rect_t){ src->x, mid_y, ox0 - src->x, mid_h };
        }
        /* Right strip */
        int src_x1 = src->x + src->width;
        if (ox1 < src_x1 && count < out_cap)
        {
            out[count++] = (atk_bg_rect_t){ ox1, mid_y, src_x1 - ox1, mid_h };
        }
    }

    return count;
}

static void atk_window_bounds(const atk_widget_t *window, atk_bg_rect_t *out)
{
    if (!window || !out)
    {
        return;
    }
    out->x = window->x - ATK_WINDOW_BORDER;
    out->y = window->y - ATK_WINDOW_BORDER;
    out->width = window->width + ATK_WINDOW_BORDER * 2;
    out->height = window->height + ATK_WINDOW_BORDER * 2;
}

static int atk_mask_background_regions(const atk_state_t *state,
                                       const atk_bg_rect_t *initial,
                                       atk_bg_rect_t *out_list,
                                       int out_cap)
{
    if (!initial || !out_list || out_cap <= 0)
    {
        return 0;
    }

    atk_bg_rect_t current[ATK_MAX_BG_RECTS];
    int current_count = 1;
    current[0] = *initial;

    /* Mask menu bar */
    int menu_h = atk_menu_bar_height(state);
    if (menu_h > 0)
    {
        atk_bg_rect_t mask = { 0, 0, VIDEO_WIDTH, menu_h };
        atk_bg_rect_t next[ATK_MAX_BG_RECTS];
        int next_count = 0;
        for (int i = 0; i < current_count && next_count < ATK_MAX_BG_RECTS; ++i)
        {
            next_count += atk_rect_subtract(&current[i],
                                            &mask,
                                            &next[next_count],
                                            ATK_MAX_BG_RECTS - next_count);
        }
        memcpy(current, next, (size_t)next_count * sizeof(atk_bg_rect_t));
        current_count = next_count;
    }

    /* Mask each window */
    if (state)
    {
        atk_guard_check((uint64_t *)&state->windows_guard_front, (uint64_t *)&state->windows_guard_back, "state->windows");
        ATK_LIST_FOR_EACH(node, &state->windows)
        {
            atk_widget_t *window = (atk_widget_t *)node->value;
            if (!window || !window->used)
            {
                continue;
            }
            atk_bg_rect_t mask;
            atk_window_bounds(window, &mask);

            atk_bg_rect_t next[ATK_MAX_BG_RECTS];
            int next_count = 0;
            for (int i = 0; i < current_count && next_count < ATK_MAX_BG_RECTS; ++i)
            {
                next_count += atk_rect_subtract(&current[i],
                                                &mask,
                                                &next[next_count],
                                                ATK_MAX_BG_RECTS - next_count);
            }
            memcpy(current, next, (size_t)next_count * sizeof(atk_bg_rect_t));
            current_count = next_count;
            if (current_count == 0)
            {
                break;
            }
        }
    }

    if (current_count > out_cap)
    {
        current_count = out_cap;
    }
    memcpy(out_list, current, (size_t)current_count * sizeof(atk_bg_rect_t));
    return current_count;
}

#define ATK_RESIZE_EDGE_LEFT   (1u << 0)
#define ATK_RESIZE_EDGE_TOP    (1u << 1)
#define ATK_RESIZE_EDGE_RIGHT  (1u << 2)
#define ATK_RESIZE_EDGE_BOTTOM (1u << 3)

static uint32_t atk_window_resize_edges_at(const atk_widget_t *window, int cursor_x, int cursor_y);
static bool atk_window_begin_resize(atk_state_t *state,
                                    atk_widget_t *window,
                                    uint32_t edges,
                                    int cursor_x,
                                    int cursor_y,
                                    atk_mouse_event_result_t *result);
static bool atk_window_resize_drag(atk_state_t *state, int cursor_x, int cursor_y);
static video_cursor_shape_t atk_cursor_shape_for_edges(uint32_t edges);
static void atk_update_cursor_shape(uint32_t edges);
static int g_mouse_dump_budget = 4;

static void atk_build_mouse_event(const atk_widget_t *widget,
                                  int cursor_x,
                                  int cursor_y,
                                  bool pressed_edge,
                                  bool released_edge,
                                  bool left_pressed,
                                  uint64_t event_id,
                                  atk_mouse_event_t *event)
{
    if (!event)
    {
        return;
    }

    int abs_x = 0;
    int abs_y = 0;
    if (widget)
    {
        atk_widget_absolute_position(widget, &abs_x, &abs_y);
    }

    int origin_x = abs_x - (widget ? widget->x : 0);
    int origin_y = abs_y - (widget ? widget->y : 0);

    event->cursor_x = cursor_x;
    event->cursor_y = cursor_y;
    event->origin_x = origin_x;
    event->origin_y = origin_y;
    event->local_x = cursor_x - abs_x;
    event->local_y = cursor_y - abs_y;
    event->pressed_edge = pressed_edge;
    event->released_edge = released_edge;
    event->left_pressed = left_pressed;
    event->id = event_id;
}

static bool atk_dispatch_widget_mouse(atk_state_t *state,
                                      atk_widget_t *widget,
                                      int cursor_x,
                                      int cursor_y,
                                      bool pressed_edge,
                                      bool released_edge,
                                      bool left_pressed,
                                      const char *stage,
                                      uint64_t event_id,
                                      atk_mouse_event_result_t *result)
{
    if (!widget || !widget->used)
    {
        return false;
    }

    atk_mouse_event_t event;
    atk_build_mouse_event(widget,
                          cursor_x,
                          cursor_y,
                          pressed_edge,
                          released_edge,
                          left_pressed,
                          event_id,
                          &event);
    atk_mouse_response_t response = atk_widget_dispatch_mouse(widget, &event);
    atk_event_debug_mouse_dispatch(event_id, stage, widget, &event, response);

    if (response & ATK_MOUSE_RESPONSE_CAPTURE)
    {
        atk_state_set_mouse_capture(state, widget);
    }
    if (response & ATK_MOUSE_RESPONSE_RELEASE)
    {
        atk_state_release_mouse_capture(state, widget);
    }
    if ((response & ATK_MOUSE_RESPONSE_REDRAW) && result)
    {
        result->redraw = true;
    }

    return (response & ATK_MOUSE_RESPONSE_HANDLED) != 0;
}

static void atk_clear_focus_widget(atk_state_t *state)
{
    if (!state)
    {
        return;
    }

    atk_widget_t *focus = atk_state_focus_widget(state);
    if (!focus)
    {
        return;
    }

    if (atk_widget_is_a(focus, &ATK_TEXT_INPUT_CLASS))
    {
        atk_text_input_focus(state, NULL);
    }
#ifndef KERNEL_BUILD
    else if (atk_widget_is_a(focus, &ATK_TERMINAL_CLASS))
    {
        atk_terminal_focus(state, NULL);
    }
#endif
    else
    {
        atk_state_set_focus_widget(state, NULL);
    }
}

void atk_init(void)
{
    atk_state_lock_init();
    uint64_t irq_state = atk_state_lock_acquire();
    atk_state_t *state = atk_state_get();
    atk_state_guard_init(state);
    atk_window_reset_all(state);
    atk_desktop_reset(state);
    atk_menu_bar_reset(state);
    atk_dirty_init(state);
    state->exit_requested = false;
    atk_state_lock_release(irq_state);
}

void atk_enter_mode(void)
{
    atk_state_lock_init();
    uint64_t irq_state = atk_state_lock_acquire();
    atk_state_t *state = atk_state_get();

    atk_apply_default_theme(state);
#if ATK_DEBUG
    atk_state_theme_log(state, "post default theme");
#endif

    atk_window_reset_all(state);
#if ATK_DEBUG
    atk_state_theme_log(state, "post window reset");
#endif
    atk_desktop_reset(state);
#if ATK_DEBUG
    atk_state_theme_log(state, "post desktop reset");
#endif
    atk_menu_bar_reset(state);
#if ATK_DEBUG
    atk_state_theme_log(state, "post menu bar reset");
#endif
    atk_menu_bar_build_default(state);
#if ATK_DEBUG
    atk_state_theme_log(state, "post menu bar build");
#endif
    atk_menu_bar_enable_clock_timer();
#if ATK_DEBUG
    atk_state_theme_log(state, "post menu bar timer");
#endif
    atk_dirty_mark_all();
#if ATK_DEBUG
    atk_state_theme_log(state, "post dirty mark");
#endif

#ifndef ATK_NO_DESKTOP_APPS
    atk_desktop_add_button(state,
                           240,
                           80,
                           88,
                           88,
                           "Tasks",
                           ATK_BUTTON_STYLE_TITLE_BELOW,
                           true,
                           action_open_task_manager,
                           state);

    atk_desktop_add_button(state,
                           340,
                           80,
                           88,
                           88,
                           "Terminal",
                           ATK_BUTTON_STYLE_TITLE_BELOW,
                           true,
                           action_open_atk_terminal,
                           state);

    atk_desktop_add_button(state,
                           440,
                           80,
                           88,
                           88,
                           "ATK Demo",
                           ATK_BUTTON_STYLE_TITLE_BELOW,
                           true,
                           action_open_atk_demo,
                           state);

    atk_desktop_add_button(state,
                           540,
                           80,
                           88,
                           88,
                           "Control Panel",
                           ATK_BUTTON_STYLE_TITLE_BELOW,
                           true,
                           action_open_control_panel,
                           state);
#else
    (void)action_exit_to_text;
#endif

    atk_state_lock_release(irq_state);
}

void atk_render(void)
{
    atk_state_lock_init();
    uint64_t irq_state = atk_state_lock_acquire();
    atk_state_t *state = atk_state_get();
    if (!state)
    {
        goto out;
    }

    if (!atk_state_theme_validate(state, "atk_render"))
    {
#ifdef KERNEL_BUILD
        serial_printf("%s", "[atk][theme] reapplying default theme\r\n");
#endif
        atk_apply_default_theme(state);
        atk_dirty_mark_all();
    }

#ifdef KERNEL_BUILD
    atk_background_reload_if_needed();
#endif

    atk_rect_t region;
    if (!atk_dirty_consume(&region))
    {
        goto out;
    }

    atk_bg_rect_t initial = { region.x, region.y, region.width, region.height };
    atk_bg_rect_t rects[ATK_MAX_BG_RECTS];
    int rect_count = atk_mask_background_regions(state, &initial, rects, ATK_MAX_BG_RECTS);
    for (int i = 0; i < rect_count; ++i)
    {
        atk_bg_rect_t *r = &rects[i];
        if (r->width > 0 && r->height > 0)
        {
            atk_paint_background_region(state, r->x, r->y, r->width, r->height);
        }
    }
    atk_desktop_draw_buttons(state, &region);
    atk_window_draw_all(state, &region);

    int menu_bottom = atk_menu_bar_height(state);
    if (menu_bottom > 0 && region.y < menu_bottom)
    {
        atk_menu_bar_draw(state);
    }

out:
    atk_state_lock_release(irq_state);
}

atk_mouse_event_result_t atk_handle_mouse_event(int cursor_x,
                                                int cursor_y,
                                                bool pressed_edge,
                                                bool released_edge,
                                                bool left_pressed)
{
    atk_state_lock_init();
    uint64_t irq_state = atk_state_lock_acquire();
    atk_state_t *state = atk_state_get();
    atk_mouse_event_result_t result = { .redraw = false, .exit_video = false };
    uint64_t event_id = atk_event_debug_next_id();
    atk_event_debug_mouse_begin(event_id, cursor_x, cursor_y, pressed_edge, released_edge, left_pressed);

    if (!atk_window_list_validate(state))
    {
        atk_window_list_dump(state, "mouse_event_corrupt");
        result.redraw = true;
        goto out;
    }
    if (g_mouse_dump_budget > 0)
    {
        atk_window_list_dump(state, "mouse_event");
        g_mouse_dump_budget--;
    }

    bool menu_redraw = false;
    bool menu_consumed = atk_menu_bar_handle_mouse(state,
                                                   cursor_x,
                                                   cursor_y,
                                                   pressed_edge,
                                                   released_edge,
                                                   left_pressed,
                                                   &menu_redraw);
    ATK_MOUSE_LOG("[atk][mouse] menu consumed=%d redraw=%d id=%016llX cursor=(%d,%d) pressed=%d released=%d left=%d\r\n",
                  menu_consumed ? 1 : 0,
                  menu_redraw ? 1 : 0,
                  (unsigned long long)event_id,
                  cursor_x,
                  cursor_y,
                  pressed_edge ? 1 : 0,
                  released_edge ? 1 : 0,
                  left_pressed ? 1 : 0);
    if (menu_redraw)
    {
        result.redraw = true;
    }
    if (menu_consumed)
    {
        goto out;
    }

    atk_widget_t *capture = atk_state_mouse_capture(state);
    if (capture && (!capture->used))
    {
        atk_state_release_mouse_capture(state, capture);
        capture = NULL;
    }

    bool capture_consumed = false;
    if (capture)
    {
        capture_consumed = atk_dispatch_widget_mouse(state,
                                                     capture,
                                                     cursor_x,
                                                     cursor_y,
                                                     pressed_edge,
                                                     released_edge,
                                                     left_pressed,
                                                     "capture",
                                                     event_id,
                                                     &result);
        ATK_MOUSE_LOG("[atk][mouse] capture cls=%s consumed=%d id=%016llX\r\n",
                      capture->cls ? capture->cls->name : "<none>",
                      capture_consumed ? 1 : 0,
                      (unsigned long long)event_id);
    }

    atk_widget_t *hover_resize_window = NULL;
    uint32_t hover_resize_edges = 0;
    ATK_LIST_FOR_EACH_REVERSE(resize_node, &state->windows)
    {
        atk_widget_t *win = (atk_widget_t *)resize_node->value;
        if (!win || !win->used)
        {
            continue;
        }
        if (!atk_window_supports_resize(win))
        {
            continue;
        }
        uint32_t edges = atk_window_resize_edges_at(win, cursor_x, cursor_y);
        if (edges == 0)
        {
            continue;
        }
        hover_resize_window = win;
        hover_resize_edges = edges;
        break;
    }

    if (!capture_consumed)
    {
        if (pressed_edge)
        {
            state->dragging_window = NULL;
            state->dragging_desktop_button = NULL;
            state->desktop_drag_moved = false;
            state->pressed_window_button_window = NULL;
            state->pressed_window_button = NULL;
            state->pressed_desktop_button = NULL;

            bool handled = false;

            if (hover_resize_window && hover_resize_edges)
            {
                handled = atk_window_begin_resize(state,
                                                  hover_resize_window,
                                                  hover_resize_edges,
                                                  cursor_x,
                                                  cursor_y,
                                                  &result);
            }

            ATK_LIST_FOR_EACH_REVERSE(win_node, &state->windows)
            {
                if (handled)
                {
                    break;
                }

                atk_widget_t *win = (atk_widget_t *)win_node->value;
                if (!win || !win->used)
                {
                    continue;
                }

                atk_widget_t *btn = atk_window_get_button_at(win, cursor_x, cursor_y);
                if (btn)
                {
                    atk_widget_t *prev_top = state->windows.tail ? (atk_widget_t *)state->windows.tail->value : NULL;
                    bool moved = atk_window_bring_to_front(state, win);
                    if (moved)
                    {
                        atk_window_mark_dirty(win);
                        if (prev_top && prev_top != win)
                        {
                            atk_window_mark_dirty(prev_top);
                        }
                        result.redraw = true;
                    }
                    state->pressed_window_button_window = win;
                    state->pressed_window_button = btn;
                    handled = true;
                }
            }

            if (!handled)
            {
                atk_widget_t *win = atk_window_title_hit_test(state, cursor_x, cursor_y);
                if (win && win->used)
                {
                    atk_widget_t *prev_top = state->windows.tail ? (atk_widget_t *)state->windows.tail->value : NULL;
                    bool moved = atk_window_bring_to_front(state, win);
                    if (moved)
                    {
                        atk_window_mark_dirty(win);
                        if (prev_top && prev_top != win)
                        {
                            atk_window_mark_dirty(prev_top);
                        }
                        result.redraw = true;
                    }
                    state->dragging_window = win;
                    state->drag_offset_x = cursor_x - win->x;
                    state->drag_offset_y = cursor_y - win->y;
                    handled = true;
                }
            }

            if (!handled)
            {
                atk_widget_t *win = atk_window_hit_test(state, cursor_x, cursor_y);
                if (win && win->used)
                {
                    atk_widget_t *prev_top = state->windows.tail ? (atk_widget_t *)state->windows.tail->value : NULL;
                    bool moved = atk_window_bring_to_front(state, win);
                    if (moved)
                    {
                        atk_window_mark_dirty(win);
                        if (prev_top && prev_top != win)
                        {
                            atk_window_mark_dirty(prev_top);
                        }
                        result.redraw = true;
                    }

                    bool consumed = false;
                    atk_widget_t *child = atk_window_widget_at(win, cursor_x, cursor_y);
                    if (child)
                    {
                        consumed = atk_dispatch_widget_mouse(state,
                                                             child,
                                                             cursor_x,
                                                             cursor_y,
                                                             pressed_edge,
                                                             released_edge,
                                                             left_pressed,
                                                             "child",
                                                             event_id,
                                                             &result);
                    }

                    if (!consumed && user_atk_window_is_remote(win))
                    {
                        user_atk_focus_window(win);
                        consumed = true;
                    }

                    if (!consumed)
                    {
                        atk_clear_focus_widget(state);
                    }

                    handled = true;
                }
            }

            if (!handled)
            {
                atk_widget_t *btn = atk_desktop_button_hit_test(state, cursor_x, cursor_y);
                if (btn && btn->used)
                {
                    state->pressed_desktop_button = btn;
                    if (atk_button_is_draggable(btn))
                    {
                        state->dragging_desktop_button = btn;
                        state->desktop_drag_offset_x = cursor_x - btn->x;
                        state->desktop_drag_offset_y = cursor_y - btn->y;
                        state->desktop_drag_moved = false;
                    }
                    atk_clear_focus_widget(state);
                    handled = true;
                }
            }

            if (!handled)
            {
                atk_clear_focus_widget(state);
            }
        }
        else if (released_edge)
        {
            if (state->resizing_window)
            {
                state->resizing_window = NULL;
                state->resize_edges = 0;
            }
            state->dragging_window = NULL;
            if (state->dragging_desktop_button)
            {
                state->dragging_desktop_button = NULL;
            }

            if (state->pressed_window_button_window && state->pressed_window_button)
            {
                atk_widget_t *win = state->pressed_window_button_window;
                atk_widget_t *btn = state->pressed_window_button;
                if (win->used && btn->used && atk_button_hit_test(btn, win->x, win->y, cursor_x, cursor_y))
                {
                    atk_button_invoke(btn);
                    result.redraw = true;
                }
            }
            state->pressed_window_button_window = NULL;
            state->pressed_window_button = NULL;

            if (state->pressed_desktop_button && state->pressed_desktop_button->used)
            {
                bool inside = atk_button_hit_test(state->pressed_desktop_button, 0, 0, cursor_x, cursor_y);
                if (!state->desktop_drag_moved && inside)
                {
                    atk_button_invoke(state->pressed_desktop_button);
                    result.redraw = true;
                }
            }
            state->pressed_desktop_button = NULL;
            state->desktop_drag_moved = false;
        }
    }

    if (left_pressed && state->resizing_window && state->resizing_window->used)
    {
        if (atk_window_resize_drag(state, cursor_x, cursor_y))
        {
            result.redraw = true;
        }
    }
    else if (left_pressed && state->dragging_window && state->dragging_window->used)
    {
        atk_widget_t *win = state->dragging_window;
        int old_x = win->x;
        int old_y = win->y;
        int old_width = win->width;
        int old_height = win->height;

        int new_x = cursor_x - state->drag_offset_x;
        int new_y = cursor_y - state->drag_offset_y;
        win->x = new_x;
        win->y = new_y;
        atk_window_ensure_inside(win);
        if (win->x != old_x || win->y != old_y)
        {
            atk_dirty_mark_rect(old_x - ATK_WINDOW_BORDER,
                                old_y - ATK_WINDOW_BORDER,
                                old_width + ATK_WINDOW_BORDER * 2,
                                old_height + ATK_WINDOW_BORDER * 2);
            atk_window_mark_dirty(win);
            result.redraw = true;
        }
    }

    if (left_pressed && state->dragging_desktop_button && state->dragging_desktop_button->used)
    {
        atk_widget_t *btn = state->dragging_desktop_button;
        int old_x = btn->x;
        int old_y = btn->y;
        int old_width = btn->width;
        int old_height = atk_button_effective_height(btn);

        int new_x = cursor_x - state->desktop_drag_offset_x;
        int new_y = cursor_y - state->desktop_drag_offset_y;

        if (new_x < 0) new_x = 0;
        if (new_y < 0) new_y = 0;
        int max_x = VIDEO_WIDTH - btn->width;
        int max_y = VIDEO_HEIGHT - atk_button_effective_height(btn);
        if (max_x < 0) max_x = 0;
        if (max_y < 0) max_y = 0;
        if (new_x > max_x) new_x = max_x;
        if (new_y > max_y) new_y = max_y;

        btn->x = new_x;
        btn->y = new_y;

        if (btn->x != old_x || btn->y != old_y)
        {
            state->desktop_drag_moved = true;
            atk_dirty_mark_rect(old_x, old_y, old_width, old_height);
            atk_dirty_mark_rect(btn->x, btn->y, btn->width, atk_button_effective_height(btn));
            result.redraw = true;
        }
    }

    atk_widget_t *hover_window = atk_window_hit_test(state, cursor_x, cursor_y);
    bool remote_handled = user_atk_route_mouse_event(hover_window,
                                                     cursor_x,
                                                     cursor_y,
                                                     pressed_edge,
                                                     released_edge,
                                                     left_pressed);
    if (pressed_edge || released_edge)
    {
        atk_event_debug_remote(event_id, hover_window, remote_handled);
    }
    if (pressed_edge && !remote_handled)
    {
        user_atk_focus_window(NULL);
    }

    uint32_t cursor_edges = 0;
    if (state->resizing_window && state->resize_edges)
    {
        cursor_edges = state->resize_edges;
    }
    else
    {
        cursor_edges = hover_resize_edges;
    }

    if (cursor_edges == 0)
    {
        atk_widget_t *cursor_widget = NULL;
        if (capture && capture->used)
        {
            cursor_widget = capture;
        }
        else if (hover_window)
        {
            cursor_widget = atk_window_widget_at(hover_window, cursor_x, cursor_y);
        }

        if (cursor_widget && cursor_widget->used && atk_widget_is_a(cursor_widget, &ATK_LIST_VIEW_CLASS))
        {
            int abs_x = 0;
            int abs_y = 0;
            atk_widget_absolute_position(cursor_widget, &abs_x, &abs_y);
            int local_x = cursor_x - abs_x;
            int local_y = cursor_y - abs_y;
            if (atk_list_view_is_over_separator(cursor_widget, local_x, local_y))
            {
                cursor_edges = ATK_RESIZE_EDGE_LEFT;
            }
        }
    }
    atk_update_cursor_shape(cursor_edges);

    if (state->exit_requested)
    {
        result.exit_video = true;
        state->exit_requested = false;
    }

out:
    atk_state_lock_release(irq_state);
    return result;
}

static void atk_apply_default_theme(atk_state_t *state)
{
    if (!state)
    {
        return;
    }

    atk_guard_check(&state->theme_guard_front, &state->theme_guard_back, "state->theme");
    state->theme.background = video_make_color(0x3B, 0x6E, 0xA5);
    state->theme.window_border = video_make_color(0x20, 0x20, 0x20);
    state->theme.window_title = video_make_color(0x30, 0x60, 0xA0);
    state->theme.window_title_text = video_make_color(0xFF, 0xFF, 0xFF);
    state->theme.window_body = video_make_color(0xF0, 0xF0, 0xF0);
    state->theme.button_face = video_make_color(0xE0, 0xE0, 0xE0);
    state->theme.button_border = video_make_color(0x40, 0x40, 0x40);
    state->theme.button_text = video_make_color(0x10, 0x10, 0x10);
    state->theme.desktop_icon_face = video_make_color(0x50, 0x90, 0xD0);
    state->theme.desktop_icon_text = state->theme.window_title_text;
    state->theme.menu_bar_face = video_make_color(0x15, 0x29, 0x43);
    state->theme.menu_bar_text = video_make_color(0xF0, 0xF4, 0xF9);
    state->theme.menu_bar_highlight = video_make_color(0x28, 0x45, 0x6B);
    state->theme.menu_dropdown_face = video_make_color(0xF6, 0xF6, 0xF6);
    state->theme.menu_dropdown_border = video_make_color(0x30, 0x30, 0x30);
    state->theme.menu_dropdown_text = video_make_color(0x20, 0x20, 0x20);
    state->theme.menu_dropdown_highlight = video_make_color(0x36, 0x58, 0x8A);
    atk_state_theme_commit(state);
#if ATK_DEBUG
    atk_state_theme_log(state, "default theme");
#endif
}

static void action_exit_to_text(atk_widget_t *button, void *context)
{
    (void)button;
    atk_state_t *state = (atk_state_t *)context;
    if (state)
    {
        state->exit_requested = true;
    }
}

atk_key_event_result_t atk_handle_key_char(char ch)
{
    atk_state_lock_init();
    uint64_t irq_state = atk_state_lock_acquire();
    atk_state_t *state = atk_state_get();
    atk_key_event_result_t result = { .redraw = false, .exit_video = false };

    if (!state)
    {
        goto out;
    }

    if (user_atk_route_key_event(ch))
    {
        goto out;
    }

    atk_widget_t *focus = atk_state_focus_widget(state);
    if (!focus || !focus->used)
    {
        goto out;
    }

    atk_key_response_t response = atk_widget_dispatch_key(focus, (int)ch, 0, 0);
    if (response & ATK_KEY_RESPONSE_REDRAW)
    {
        result.redraw = true;
    }

out:
    atk_state_lock_release(irq_state);
    return result;
}

#ifndef ATK_NO_DESKTOP_APPS
static const atk_user_launch_info_t g_atk_shell_launch = {
    .path = "/root/usr/bin/atk_shell.elf",
    .name = "atk_shell"
};

static const atk_user_launch_info_t g_atk_taskmgr_launch = {
    .path = "/usr/bin/atk_taskmgr.elf",
    .name = "atk_taskmgr"
};

static const atk_user_launch_info_t g_atk_demo_launch = {
    .path = "/usr/bin/atk_demo.elf",
    .name = "atk_demo"
};

static const atk_user_launch_info_t g_control_panel_launch = {
    .path = "/usr/bin/control_panel.elf",
    .name = "control_panel"
};
#endif

static uint32_t atk_window_resize_edges_at(const atk_widget_t *window, int cursor_x, int cursor_y)
{
    if (!window || !window->used)
    {
        return 0;
    }

    const atk_window_priv_t *priv = (const atk_window_priv_t *)atk_widget_priv(window, &ATK_WINDOW_CLASS);
    bool chrome_visible = priv ? priv->chrome_visible : true;
    int border = chrome_visible ? ATK_WINDOW_BORDER : 0;
    int margin = ATK_WINDOW_RESIZE_MARGIN;

    int left = window->x - border;
    int top = window->y - border;
    int right = left + window->width + border * 2;
    int bottom = top + window->height + border * 2;

    uint32_t edges = 0;

    if (cursor_x >= left - margin && cursor_x <= left + margin &&
        cursor_y >= top - margin && cursor_y <= bottom + margin)
    {
        edges |= ATK_RESIZE_EDGE_LEFT;
    }
    if (cursor_x >= right - margin && cursor_x <= right + margin &&
        cursor_y >= top - margin && cursor_y <= bottom + margin)
    {
        edges |= ATK_RESIZE_EDGE_RIGHT;
    }
    if (cursor_y >= top - margin && cursor_y <= top + margin &&
        cursor_x >= left - margin && cursor_x <= right + margin)
    {
        edges |= ATK_RESIZE_EDGE_TOP;
    }
    if (cursor_y >= bottom - margin && cursor_y <= bottom + margin &&
        cursor_x >= left - margin && cursor_x <= right + margin)
    {
        edges |= ATK_RESIZE_EDGE_BOTTOM;
    }

    if ((edges & (ATK_RESIZE_EDGE_LEFT | ATK_RESIZE_EDGE_RIGHT)) ==
        (ATK_RESIZE_EDGE_LEFT | ATK_RESIZE_EDGE_RIGHT))
    {
        edges &= ~(ATK_RESIZE_EDGE_LEFT | ATK_RESIZE_EDGE_RIGHT);
    }
    if ((edges & (ATK_RESIZE_EDGE_TOP | ATK_RESIZE_EDGE_BOTTOM)) ==
        (ATK_RESIZE_EDGE_TOP | ATK_RESIZE_EDGE_BOTTOM))
    {
        edges &= ~(ATK_RESIZE_EDGE_TOP | ATK_RESIZE_EDGE_BOTTOM);
    }

    return edges;
}

static bool atk_window_begin_resize(atk_state_t *state,
                                    atk_widget_t *window,
                                    uint32_t edges,
                                    int cursor_x,
                                    int cursor_y,
                                    atk_mouse_event_result_t *result)
{
    if (!state || !window || edges == 0)
    {
        return false;
    }

    atk_widget_t *prev_top = state->windows.tail ? (atk_widget_t *)state->windows.tail->value : NULL;
    bool moved = atk_window_bring_to_front(state, window);
    if (moved)
    {
        atk_window_mark_dirty(window);
        if (prev_top && prev_top != window)
        {
            atk_window_mark_dirty(prev_top);
        }
        if (result)
        {
            result->redraw = true;
        }
    }

    state->resizing_window = window;
    state->resize_edges = edges;
    state->resize_start_cursor_x = cursor_x;
    state->resize_start_cursor_y = cursor_y;
    state->resize_start_x = window->x;
    state->resize_start_y = window->y;
    state->resize_start_width = window->width;
    state->resize_start_height = window->height;
    state->dragging_window = NULL;
    return true;
}

static bool atk_window_resize_drag(atk_state_t *state, int cursor_x, int cursor_y)
{
    if (!state || !state->resizing_window || state->resize_edges == 0)
    {
        return false;
    }

    atk_widget_t *win = state->resizing_window;
    if (!win->used)
    {
        return false;
    }

    int old_left = win->x - ATK_WINDOW_BORDER;
    int old_top = win->y - ATK_WINDOW_BORDER;
    int old_width = win->width + ATK_WINDOW_BORDER * 2;
    int old_height = win->height + ATK_WINDOW_BORDER * 2;

    int new_x = state->resize_start_x;
    int new_y = state->resize_start_y;
    int new_width = state->resize_start_width;
    int new_height = state->resize_start_height;
    int delta_x = cursor_x - state->resize_start_cursor_x;
    int delta_y = cursor_y - state->resize_start_cursor_y;

    if (state->resize_edges & ATK_RESIZE_EDGE_LEFT)
    {
        new_width = state->resize_start_width - delta_x;
        if (new_width < ATK_WINDOW_MIN_WIDTH)
        {
            delta_x = state->resize_start_width - ATK_WINDOW_MIN_WIDTH;
            new_width = ATK_WINDOW_MIN_WIDTH;
        }
        new_x = state->resize_start_x + delta_x;
    }
    else if (state->resize_edges & ATK_RESIZE_EDGE_RIGHT)
    {
        new_width = state->resize_start_width + delta_x;
        if (new_width < ATK_WINDOW_MIN_WIDTH)
        {
            new_width = ATK_WINDOW_MIN_WIDTH;
        }
    }

    if (state->resize_edges & ATK_RESIZE_EDGE_TOP)
    {
        new_height = state->resize_start_height - delta_y;
        if (new_height < ATK_WINDOW_MIN_HEIGHT)
        {
            delta_y = state->resize_start_height - ATK_WINDOW_MIN_HEIGHT;
            new_height = ATK_WINDOW_MIN_HEIGHT;
        }
        new_y = state->resize_start_y + delta_y;
    }
    else if (state->resize_edges & ATK_RESIZE_EDGE_BOTTOM)
    {
        new_height = state->resize_start_height + delta_y;
        if (new_height < ATK_WINDOW_MIN_HEIGHT)
        {
            new_height = ATK_WINDOW_MIN_HEIGHT;
        }
    }

    if (new_width == win->width && new_height == win->height &&
        new_x == win->x && new_y == win->y)
    {
        return false;
    }

    win->x = new_x;
    win->y = new_y;
    win->width = new_width;
    win->height = new_height;
    atk_window_ensure_inside(win);

    atk_dirty_mark_rect(old_left, old_top, old_width, old_height);
    atk_dirty_mark_rect(win->x - ATK_WINDOW_BORDER,
                        win->y - ATK_WINDOW_BORDER,
                        win->width + ATK_WINDOW_BORDER * 2,
                        win->height + ATK_WINDOW_BORDER * 2);
    /* Force a full redraw during resize to keep terminal state consistent. */
    atk_dirty_mark_rect(0, 0, VIDEO_WIDTH, VIDEO_HEIGHT);
    atk_window_request_layout(win);
    return true;
}

static video_cursor_shape_t atk_cursor_shape_for_edges(uint32_t edges)
{
    if (edges == 0)
    {
        return VIDEO_CURSOR_ARROW;
    }

    bool left = (edges & ATK_RESIZE_EDGE_LEFT) != 0;
    bool right = (edges & ATK_RESIZE_EDGE_RIGHT) != 0;
    bool top = (edges & ATK_RESIZE_EDGE_TOP) != 0;
    bool bottom = (edges & ATK_RESIZE_EDGE_BOTTOM) != 0;

    if ((left && top) || (right && bottom))
    {
        return VIDEO_CURSOR_RESIZE_DIAG_NW_SE;
    }
    if ((right && top) || (left && bottom))
    {
        return VIDEO_CURSOR_RESIZE_DIAG_NE_SW;
    }
    if (left || right)
    {
        return VIDEO_CURSOR_RESIZE_H;
    }
    if (top || bottom)
    {
        return VIDEO_CURSOR_RESIZE_V;
    }
    return VIDEO_CURSOR_ARROW;
}

static void atk_update_cursor_shape(uint32_t edges)
{
    video_cursor_shape_t shape = atk_cursor_shape_for_edges(edges);
    video_cursor_set_shape(shape);
}

#ifndef ATK_NO_DESKTOP_APPS
static void action_open_task_manager(atk_widget_t *button, void *context)
{
    (void)button;
    (void)context;
    atk_schedule_user_launch("atk_taskmgr_launcher", &g_atk_taskmgr_launch);
}

static void action_open_atk_terminal(atk_widget_t *button, void *context)
{
    (void)button;
    (void)context;
    atk_schedule_user_launch("atk_terminal_launcher", &g_atk_shell_launch);
}

static void action_open_atk_demo(atk_widget_t *button, void *context)
{
    (void)button;
    (void)context;
    atk_schedule_user_launch("atk_demo_launcher", &g_atk_demo_launch);
}

static void action_open_control_panel(atk_widget_t *button, void *context)
{
    (void)button;
    (void)context;
    atk_schedule_user_launch("control_panel_launcher", &g_control_panel_launch);
}

static void atk_schedule_user_launch(const char *launcher_name, const void *info)
{
    process_t *launcher = process_create_kernel(launcher_name ? launcher_name : "atk_user_launcher",
                                                atk_launch_user_binary,
                                                (void *)info,
                                                0,
                                                -1);
    if (!launcher)
    {
        serial_printf("%s", "atk: failed to schedule user launcher\r\n");
    }
}

static void atk_launch_user_binary(void *arg)
{
    const atk_user_launch_info_t *info = (const atk_user_launch_info_t *)arg;
    const char *path = info ? info->path : NULL;
    const char *name = (info && info->name) ? info->name : "user_app";

    vfs_node_t *root = vfs_root();
    if (!root || !path)
    {
        serial_printf("%s", "atk: invalid user binary request\r\n");
        process_exit(1);
    }

    vfs_node_t *node = vfs_resolve(root, path);
    if (!node)
    {
        serial_printf("%s", "atk: binary not found\r\n");
        process_exit(1);
    }

    size_t size = 0;
    const uint8_t *data = (const uint8_t *)vfs_data(node, &size);
    if (!data || size == 0)
    {
        serial_printf("%s", "atk: binary empty\r\n");
        process_exit(1);
    }

    process_t *proc = process_create_user_elf_with_parent(name,
                                                          data,
                                                          size,
                                                          -1,
                                                          process_current(),
                                                          NULL,
                                                          0);
    if (!proc)
    {
        serial_printf("%s", "atk: failed to start user binary\r\n");
        process_exit(1);
    }

    process_join(proc, NULL);
    process_destroy(proc);
    process_exit(0);
}
#endif
