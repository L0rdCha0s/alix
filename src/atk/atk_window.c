#include "atk_window.h"

#include <stddef.h>
#include "libc.h"
#include "serial.h"
#include "video.h"
#include "atk/atk_image.h"
#include "atk/atk_label.h"
#include "atk/atk_scrollbar.h"
#include "atk/atk_list_view.h"
#include "atk/atk_tabs.h"
#include "atk/atk_text_input.h"
#ifndef KERNEL_BUILD
#include "atk/atk_terminal.h"
#endif
#include "atk/atk_font.h"
#ifdef KERNEL_BUILD
#include "user_atk_host.h"
#endif

/* Forward decl for compilers if video.h doesn't expose it (no harm if duplicated). */
static void atk_log(const char *msg);
static bool window_list_pointer_valid(const void *ptr);
static bool window_sanitize_list(atk_state_t *state);
static void format_window_title(char *buffer, size_t capacity, int id);
static void window_get_bounds(const atk_widget_t *window, int *x, int *y, int *width, int *height);
static atk_widget_t *window_add_button(atk_widget_t *window,
                                       const char *title,
                                       int rel_x,
                                       int rel_y,
                                       int width,
                                       int height,
                                       atk_button_style_t style,
                                       bool draggable,
                                       atk_button_action_t action,
                                       void *context);
static void action_window_close(atk_widget_t *button, void *context);
static void window_draw_internal(const atk_state_t *state, const atk_widget_t *window);
static void window_layout_close_button(atk_widget_t *window, atk_window_priv_t *priv);
static void window_layout_children(atk_widget_t *window, atk_window_priv_t *priv);
static void window_after_size_change(atk_widget_t *window);
static atk_window_priv_t *window_priv_mut(atk_widget_t *window);
static const atk_window_priv_t *window_priv(const atk_widget_t *window);
static void window_destroy(atk_widget_t *window);
static void window_destroy_value(void *value);
static void window_debug_dump_node(const atk_list_node_t *node, size_t index);

extern const atk_class_t ATK_BUTTON_CLASS;
static const atk_widget_vtable_t window_vtable = { 0 };
const atk_class_t ATK_WINDOW_CLASS = { "Window", &ATK_WIDGET_CLASS, &window_vtable, sizeof(atk_window_priv_t) };

void atk_window_reset_all(atk_state_t *state)
{
    if (!state)
    {
        return;
    }

    atk_guard_check(&state->windows_guard_front, &state->windows_guard_back, "state->windows");
    bool list_safe = window_sanitize_list(state);
    if (list_safe)
    {
        atk_list_clear(&state->windows, window_destroy_value);
    }
    atk_list_init(&state->windows);
    atk_guard_reset(&state->windows_guard_front, &state->windows_guard_back);

    state->next_window_id = 1;
    state->dragging_window = 0;
    state->drag_offset_x = 0;
    state->drag_offset_y = 0;
    state->resizing_window = NULL;
    state->resize_edges = 0;
    state->resize_start_cursor_x = 0;
    state->resize_start_cursor_y = 0;
    state->resize_start_x = 0;
    state->resize_start_y = 0;
    state->resize_start_width = 0;
    state->resize_start_height = 0;
    state->pressed_window_button_window = 0;
    state->pressed_window_button = 0;
    state->focus_widget = NULL;
    state->mouse_capture_widget = NULL;
}

static bool window_intersects_clip(const atk_widget_t *window, const atk_rect_t *clip)
{
    if (!clip || !window)
    {
        return true;
    }
    int x0 = window->x - ATK_WINDOW_BORDER;
    int y0 = window->y - ATK_WINDOW_BORDER;
    int x1 = x0 + window->width + ATK_WINDOW_BORDER * 2;
    int y1 = y0 + window->height + ATK_WINDOW_BORDER * 2;
    int clip_x1 = clip->x + clip->width;
    int clip_y1 = clip->y + clip->height;
    if (x1 <= clip->x || y1 <= clip->y || x0 >= clip_x1 || y0 >= clip_y1)
    {
        return false;
    }
    return true;
}

void atk_window_draw_all(const atk_state_t *state, const atk_rect_t *clip)
{
    if (!state)
    {
        return;
    }

    atk_guard_check((uint64_t *)&state->windows_guard_front, (uint64_t *)&state->windows_guard_back, "state->windows");
    ATK_LIST_FOR_EACH(node, &state->windows)
    {
        atk_widget_t *window = (atk_widget_t *)node->value;
        if (window && window->used)
        {
            if (!window_intersects_clip(window, clip))
            {
                continue;
            }
            window_draw_internal(state, window);
        }
    }
}

bool atk_window_bring_to_front(atk_state_t *state, atk_widget_t *window)
{
    if (!state || !window)
    {
        return false;
    }

    atk_guard_check(&state->windows_guard_front, &state->windows_guard_back, "state->windows");
    atk_window_priv_t *priv = window_priv_mut(window);
    if (!priv || !priv->list_node)
    {
        return false;
    }

    if (state->windows.tail == priv->list_node)
    {
        return false;
    }

    atk_list_move_to_back(&state->windows, priv->list_node);
    return true;
}

atk_widget_t *atk_window_hit_test(const atk_state_t *state, int x, int y)
{
    if (!state)
    {
        return 0;
    }

    atk_guard_check((uint64_t *)&state->windows_guard_front, (uint64_t *)&state->windows_guard_back, "state->windows");
    ATK_LIST_FOR_EACH_REVERSE(node, &state->windows)
    {
        atk_widget_t *window = (atk_widget_t *)node->value;
        if (!window || !window->used)
        {
            continue;
        }
        if (x >= window->x && x < window->x + window->width &&
            y >= window->y && y < window->y + window->height)
        {
            return window;
        }
    }
    return 0;
}

atk_widget_t *atk_window_title_hit_test(const atk_state_t *state, int x, int y)
{
    if (!state)
    {
        return 0;
    }

    atk_guard_check((uint64_t *)&state->windows_guard_front, (uint64_t *)&state->windows_guard_back, "state->windows");
    ATK_LIST_FOR_EACH_REVERSE(node, &state->windows)
    {
        atk_widget_t *window = (atk_widget_t *)node->value;
        if (!window || !window->used)
        {
            continue;
        }
        atk_window_priv_t *priv = window_priv_mut(window);
        if (!priv || !priv->chrome_visible)
        {
            continue;
        }
        if (x >= window->x && x < window->x + window->width &&
            y >= window->y && y < window->y + ATK_WINDOW_TITLE_HEIGHT)
        {
            return window;
        }
    }
    return 0;
}

atk_widget_t *atk_window_get_button_at(atk_widget_t *window, int px, int py)
{
    if (!window || !window->used)
    {
        return 0;
    }

    atk_window_priv_t *priv = window_priv_mut(window);
    if (!priv)
    {
        return 0;
    }
    if (!priv->chrome_visible)
    {
        return 0;
    }

    ATK_LIST_FOR_EACH_REVERSE(node, &priv->buttons)
    {
        atk_widget_t *btn = (atk_widget_t *)node->value;
        if (!btn || !btn->used)
        {
            continue;
        }
        if (atk_button_hit_test(btn, window->x, window->y, px, py))
        {
            return btn;
        }
    }
    return 0;
}

atk_widget_t *atk_window_widget_at(atk_widget_t *window, int px, int py)
{
    if (!window || !window->used)
    {
        return NULL;
    }
#ifdef KERNEL_BUILD
    if (user_atk_window_is_remote(window))
    {
        return NULL;
    }
#endif

    atk_window_priv_t *priv = window_priv_mut(window);
    if (!priv)
    {
        return NULL;
    }

    ATK_LIST_FOR_EACH_REVERSE(node, &priv->children)
    {
#ifndef KERNEL_BUILD
        if ((uintptr_t)node < ATK_USER_POINTER_MIN)
        {
            continue;
        }
#endif
        atk_widget_t *child = (atk_widget_t *)node->value;
        if (!child)
        {
            continue;
        }
#ifndef KERNEL_BUILD
        if ((uintptr_t)child < ATK_USER_POINTER_MIN)
        {
            continue;
        }
#endif
        if (!child->used)
        {
            continue;
        }
        if (atk_widget_is_a(child, &ATK_TAB_VIEW_CLASS))
        {
            if (!atk_tab_view_contains_point(child, px, py))
            {
                continue;
            }

            if (!atk_tab_view_point_in_tab_bar(child, px, py))
            {
                atk_widget_t *content = atk_tab_view_active_content(child);
                if (content && content->used)
                {
                    int cx = 0;
                    int cy = 0;
                    int cw = 0;
                    int ch = 0;
                    atk_widget_absolute_bounds(content, &cx, &cy, &cw, &ch);
                    if (px >= cx && px < cx + cw && py >= cy && py < cy + ch)
                    {
                        return content;
                    }
                }
            }

            return child;
        }

        if (atk_widget_hit_test(child, window->x, window->y, px, py))
        {
            return child;
        }
    }
    return NULL;
}

void atk_window_mark_dirty(const atk_widget_t *window)
{
    int x, y, w, h;
    window_get_bounds(window, &x, &y, &w, &h);
    if (w <= 0 || h <= 0)
    {
        return;
    }
    atk_dirty_mark_rect(x, y, w, h);
}

void atk_window_request_layout(atk_widget_t *window)
{
    if (!window)
    {
        return;
    }
#ifdef KERNEL_BUILD
    if (user_atk_window_is_remote(window))
    {
        serial_printf("[atk][layout] remote window=%p size=%dx%d pos=(%d,%d)\r\n",
                      (void *)window,
                      window->width,
                      window->height,
                      window->x,
                      window->y);
    }
#endif
    window_after_size_change(window);
    atk_window_mark_dirty(window);
}

void atk_window_ensure_inside(atk_widget_t *window)
{
    if (!window)
    {
        return;
    }

    if (window->width > VIDEO_WIDTH)
    {
        window->width = VIDEO_WIDTH;
    }
    if (window->height > VIDEO_HEIGHT)
    {
        window->height = VIDEO_HEIGHT;
    }

    int max_x = VIDEO_WIDTH - window->width;
    int max_y = VIDEO_HEIGHT - window->height;

    if (window->x < 0) window->x = 0;
    if (window->y < 0) window->y = 0;
    if (window->x > max_x) window->x = max_x;
    if (window->y > max_y) window->y = max_y;
}

bool atk_window_supports_resize(const atk_widget_t *window)
{
    if (!window || !window->used)
    {
        return false;
    }
#ifdef KERNEL_BUILD
    if (user_atk_window_is_remote(window) && !user_atk_window_is_resizable(window))
    {
        return false;
    }
#endif
    return true;
}

atk_widget_t *atk_window_create_at(atk_state_t *state, int x, int y)
{
    if (!state)
    {
        return 0;
    }

    atk_widget_t *window = atk_widget_create(&ATK_WINDOW_CLASS);
    if (!window)
    {
        atk_log("window_create_at: allocation failed");
        return 0;
    }

    atk_window_priv_t *priv = window_priv_mut(window);
    if (!priv)
    {
        atk_widget_destroy(window);
        return 0;
    }

    atk_list_init(&priv->buttons);
    priv->close_button = NULL;
    atk_list_init(&priv->children);
    atk_list_init(&priv->text_inputs);
    atk_list_init(&priv->terminals);
    atk_list_init(&priv->scrollbars);
    priv->list_node = 0;
    priv->user_context = NULL;
    priv->on_destroy = NULL;
    priv->chrome_visible = true;

    window->used = true;
    window->width = 600;
    window->height = 400;
    window->x = x - window->width / 2;
    window->y = y - ATK_WINDOW_TITLE_HEIGHT / 2;
    window->parent = 0;

    format_window_title(priv->title, sizeof(priv->title), state->next_window_id++);

    atk_window_ensure_inside(window);

    int btn_margin = 4;
    int btn_width = ATK_WINDOW_TITLE_HEIGHT - btn_margin * 2;
    if (btn_width < ATK_FONT_WIDTH + 4)
    {
        btn_width = ATK_FONT_WIDTH + 4;
    }
    int btn_height = ATK_WINDOW_TITLE_HEIGHT - btn_margin * 2;

    if (!window_add_button(window,
                           "X",
                           window->width - btn_width - btn_margin,
                           btn_margin,
                           btn_width,
                           btn_height,
                           ATK_BUTTON_STYLE_TITLE_INSIDE,
                           false,
                           action_window_close,
                           window))
    {
        window_destroy(window);
        atk_log("window_create_at: failed to add close button");
        return 0;
    }

    atk_list_node_t *node = atk_list_push_back(&state->windows, window);
    if (!node)
    {
        window_destroy(window);
        atk_log("window_create_at: failed to track window");
        return 0;
    }

    priv->list_node = node;

    return window;
}

void atk_window_close(atk_state_t *state, atk_widget_t *window)
{
    if (!state || !window)
    {
        return;
    }

    if (state->dragging_window == window)
    {
        state->dragging_window = 0;
    }

    if (state->pressed_window_button_window == window)
    {
        state->pressed_window_button_window = 0;
        state->pressed_window_button = 0;
    }

    atk_window_priv_t *priv = window_priv_mut(window);
    if (priv && priv->list_node)
    {
        atk_list_remove(&state->windows, priv->list_node);
        priv->list_node = 0;
    }

    atk_widget_t *focus = atk_state_focus_widget(state);
    if (focus && focus->parent == window)
    {
        atk_state_set_focus_widget(state, NULL);
    }

    if (priv && priv->on_destroy && priv->user_context)
    {
        priv->on_destroy(priv->user_context);
        priv->user_context = NULL;
    }

    int dirty_x = 0, dirty_y = 0, dirty_w = 0, dirty_h = 0;
    window_get_bounds(window, &dirty_x, &dirty_y, &dirty_w, &dirty_h);
    if (dirty_w > 0 && dirty_h > 0)
    {
        atk_dirty_mark_rect(dirty_x, dirty_y, dirty_w, dirty_h);
    }

    window_destroy(window);
}

const char *atk_window_title(const atk_widget_t *window)
{
    const atk_window_priv_t *priv = window_priv(window);
    if (!priv)
    {
        return "";
    }
    return priv->title;
}

void atk_window_set_title_text(atk_widget_t *window, const char *title)
{
    atk_window_priv_t *priv = window_priv_mut(window);
    if (!priv)
    {
        return;
    }

    size_t i = 0;
    if (title)
    {
        for (; title[i] != '\0' && i < sizeof(priv->title) - 1; ++i)
        {
            priv->title[i] = title[i];
        }
    }
    priv->title[i] = '\0';
    atk_window_mark_dirty(window);
}

void atk_window_set_context(atk_widget_t *window, void *context, void (*on_destroy)(void *context))
{
    atk_window_priv_t *priv = window_priv_mut(window);
    if (!priv)
    {
        return;
    }
    priv->user_context = context;
    priv->on_destroy = on_destroy;
}

void *atk_window_context(const atk_widget_t *window)
{
    const atk_window_priv_t *priv = window_priv(window);
    return priv ? priv->user_context : NULL;
}

bool atk_window_is_chrome_visible(const atk_widget_t *window)
{
    const atk_window_priv_t *priv = window_priv(window);
    return priv ? priv->chrome_visible : true;
}

void atk_window_set_chrome_visible(atk_widget_t *window, bool visible)
{
    atk_window_priv_t *priv = window_priv_mut(window);
    if (!priv || priv->chrome_visible == visible)
    {
        return;
    }

    if (!visible)
    {
        window->y -= ATK_WINDOW_TITLE_HEIGHT;
        window->height += ATK_WINDOW_TITLE_HEIGHT;
    }
    else
    {
        window->y += ATK_WINDOW_TITLE_HEIGHT;
        if (window->height > ATK_WINDOW_TITLE_HEIGHT)
        {
            window->height -= ATK_WINDOW_TITLE_HEIGHT;
        }
    }

    priv->chrome_visible = visible;
    window_after_size_change(window);
    atk_window_mark_dirty(window);
}

static void atk_log(const char *msg)
{
    serial_printf("%s", msg);
    serial_printf("%s", "\r\n");
}

static bool window_list_pointer_valid(const void *ptr)
{
    if (!ptr)
    {
        return true;
    }
    uintptr_t addr = (uintptr_t)ptr;
    uint64_t top = (uint64_t)addr >> 47;
    return (top == 0u) || (top == 0x1FFFFu);
}

static bool window_sanitize_list(atk_state_t *state)
{
    if (!state)
    {
        return true;
    }

    atk_list_t *list = &state->windows;
    atk_list_node_t *node = list->head;
    size_t guard = 0;
    const size_t guard_limit = 4096;
    bool corrupted = false;

    while (node)
    {
        if (!window_list_pointer_valid(node))
        {
            corrupted = true;
            break;
        }

        guard++;
        if (guard > guard_limit)
        {
            corrupted = true;
            break;
        }

        atk_list_node_t *next = node->next;
        if (next && !window_list_pointer_valid(next))
        {
            corrupted = true;
            break;
        }

        node = next;
    }

    if (corrupted)
    {
        serial_printf("%s", "atk: window list corrupted; resetting\r\n");
        list->head = NULL;
        list->tail = NULL;
        list->size = 0;
        return false;
    }

    if (list->tail && !window_list_pointer_valid(list->tail))
    {
        serial_printf("%s", "atk: window list tail corrupted; resetting\r\n");
        list->head = NULL;
        list->tail = NULL;
        list->size = 0;
        return false;
    }

    return true;
}

bool atk_window_list_validate(atk_state_t *state)
{
    return window_sanitize_list(state);
}

static void window_debug_dump_node(const atk_list_node_t *node, size_t index)
{
    const atk_widget_t *win = node ? (const atk_widget_t *)node->value : NULL;
    serial_printf("%s", "[atk][winlist] idx=");
    serial_printf("%016llX", (unsigned long long)index);
    serial_printf("%s", " node=0x");
    serial_printf("%016llX", (unsigned long long)((uint64_t)(uintptr_t)node));
    serial_printf("%s", " next=0x");
    serial_printf("%016llX", (unsigned long long)((uint64_t)(uintptr_t)(node ? node->next : NULL)));
    serial_printf("%s", " win=0x");
    serial_printf("%016llX", (unsigned long long)((uint64_t)(uintptr_t)win));
    if (win)
    {
        serial_printf("%s", " used=");
        serial_printf("%016llX", (unsigned long long)((uint64_t)win->used));
        serial_printf("%s", " x=");
        serial_printf("%016llX", (unsigned long long)((uint64_t)win->x));
        serial_printf("%s", " y=");
        serial_printf("%016llX", (unsigned long long)((uint64_t)win->y));
        serial_printf("%s", " w=");
        serial_printf("%016llX", (unsigned long long)((uint64_t)win->width));
        serial_printf("%s", " h=");
        serial_printf("%016llX", (unsigned long long)((uint64_t)win->height));
    }
    serial_printf("%s", "\r\n");
}

void atk_window_list_dump(atk_state_t *state, const char *label)
{
    serial_printf("%s", "[atk][winlist] dump label=");
    serial_printf("%s", label ? label : "?");
    serial_printf("%s", "\r\n");

    if (!state)
    {
        serial_printf("%s", "[atk][winlist] state null\r\n");
        return;
    }

    atk_list_t *list = &state->windows;
    serial_printf("%s", "[atk][winlist] head=0x");
    serial_printf("%016llX", (unsigned long long)((uint64_t)(uintptr_t)list->head));
    serial_printf("%s", " tail=0x");
    serial_printf("%016llX", (unsigned long long)((uint64_t)(uintptr_t)list->tail));
    serial_printf("%s", " size=");
    serial_printf("%016llX", (unsigned long long)((uint64_t)list->size));
    serial_printf("%s", "\r\n");

    const size_t max_nodes = 32;
    size_t idx = 0;
    for (atk_list_node_t *node = list->head; node && idx < max_nodes; node = node->next, ++idx)
    {
        window_debug_dump_node(node, idx);
    }
    if (idx >= max_nodes)
    {
        serial_printf("%s", "[atk][winlist] truncated\r\n");
    }
}

static void window_layout_close_button(atk_widget_t *window, atk_window_priv_t *priv)
{
    if (!window || !priv || !priv->close_button)
    {
        return;
    }

    atk_widget_t *btn = priv->close_button;
    if (!btn || !btn->used)
    {
        return;
    }

    int margin = 4;
    int target_x = window->width - margin - btn->width;
    if (target_x < margin)
    {
        target_x = margin;
    }
    btn->x = target_x;
}

static void window_layout_children(atk_widget_t *window, atk_window_priv_t *priv)
{
    if (!window || !priv)
    {
        return;
    }

    ATK_LIST_FOR_EACH(node, &priv->children)
    {
        if (!window_list_pointer_valid(node))
        {
            serial_printf("%s", "[atk][layout] invalid child node; skipping\r\n");
            continue;
        }
        atk_widget_t *child = (atk_widget_t *)node->value;
        if (!child || !child->used)
        {
            continue;
        }
        if (!atk_widget_validate(child, "window_layout_children child"))
        {
            serial_printf("%s", "[atk][layout] invalid child widget; skipping\r\n");
            continue;
        }

        atk_widget_apply_layout(child);

        if (atk_widget_is_a(child, &ATK_TAB_VIEW_CLASS))
        {
            atk_tab_view_relayout(child);
        }
        else if (atk_widget_is_a(child, &ATK_LIST_VIEW_CLASS))
        {
            atk_list_view_relayout(child);
        }
#ifndef KERNEL_BUILD
        else if (atk_widget_is_a(child, &ATK_TERMINAL_CLASS))
        {
            atk_terminal_handle_resize(child);
        }
#endif
    }
}

static void window_after_size_change(atk_widget_t *window)
{
    if (!window || !window->used)
    {
        return;
    }

    atk_window_priv_t *priv = window_priv_mut(window);
    if (!priv)
    {
        return;
    }

    if (priv->chrome_visible)
    {
        window_layout_close_button(window, priv);
    }

    window_layout_children(window, priv);

#ifdef KERNEL_BUILD
    if (user_atk_window_is_remote(window))
    {
        user_atk_window_resized(window);
    }
#endif
}

static void window_draw_internal(const atk_state_t *state, const atk_widget_t *window)
{
    if (!state || !window || !window->used)
    {
        return;
    }

#ifdef KERNEL_BUILD
    if (user_atk_window_is_remote(window))
    {
        serial_printf("[atk][draw] remote window=%p pos=(%d,%d) size=%dx%d\r\n",
                      (void *)window,
                      window->x,
                      window->y,
                      window->width,
                      window->height);
    }
#endif

    atk_state_theme_validate(state, "atk_window_draw");
    const atk_theme_t *theme = &state->theme;
    atk_window_priv_t *priv_mut = window_priv_mut((atk_widget_t *)window);
    const atk_window_priv_t *priv = (const atk_window_priv_t *)priv_mut;
    bool chrome_visible = priv ? priv->chrome_visible : true;

    if (chrome_visible)
    {
        window_layout_close_button((atk_widget_t *)window, priv_mut);

        video_draw_rect(window->x - ATK_WINDOW_BORDER,
                        window->y - ATK_WINDOW_BORDER,
                        window->width + ATK_WINDOW_BORDER * 2,
                        window->height + ATK_WINDOW_BORDER * 2,
                        theme->window_border);

        video_draw_rect(window->x,
                        window->y,
                        window->width,
                        window->height,
                        theme->window_body);

        video_draw_rect(window->x,
                        window->y,
                        window->width,
                        ATK_WINDOW_TITLE_HEIGHT,
                        theme->window_title);

        video_draw_rect_outline(window->x,
                                window->y,
                                window->width,
                                ATK_WINDOW_TITLE_HEIGHT,
                                theme->window_border);

        int title_baseline = atk_font_baseline_for_rect(window->y, ATK_WINDOW_TITLE_HEIGHT);
        atk_rect_t clip = { window->x, window->y, window->width, ATK_WINDOW_TITLE_HEIGHT };
        atk_font_draw_string_clipped(window->x + ATK_WINDOW_TITLE_PADDING_X,
                                     title_baseline,
                                     priv->title,
                                     theme->window_title_text,
                                     theme->window_title,
                                     &clip);

        video_draw_rect_outline(window->x,
                                window->y,
                                window->width,
                                window->height,
                                theme->window_border);
    }
    else
    {
        video_draw_rect(window->x,
                        window->y,
                        window->width,
                        window->height,
                        theme->window_body);
    }

    ATK_LIST_FOR_EACH(node, &priv->children)
    {
        atk_widget_t *child = (atk_widget_t *)node->value;
        if (!child || !child->used)
        {
            continue;
        }
        if (!chrome_visible && atk_widget_is_a(child, &ATK_BUTTON_CLASS))
        {
            continue;
        }

        atk_widget_draw_any(state, child);
    }
}

void atk_window_draw(atk_state_t *state, atk_widget_t *window)
{
    window_draw_internal(state, window);
}

void atk_window_draw_from(atk_state_t *state, atk_widget_t *start)
{
    if (!state || !start)
    {
        return;
    }

    atk_list_node_t *node = atk_list_find(&state->windows, start);
    if (!node)
    {
        return;
    }

    for (atk_list_node_t *n = node; n; n = n->next)
    {
        atk_widget_t *window = (atk_widget_t *)n->value;
        if (!window || !window->used)
        {
            continue;
        }
        atk_window_mark_dirty(window);
        window_draw_internal(state, window);
    }
}

bool atk_window_contains(const atk_state_t *state, const atk_widget_t *window)
{
    if (!state || !window)
    {
        return false;
    }
    return atk_list_find(&state->windows, window) != NULL;
}

bool atk_window_is_topmost(const atk_state_t *state, const atk_widget_t *window)
{
    if (!state || !window || !state->windows.tail)
    {
        return false;
    }
    return state->windows.tail->value == window;
}

static void format_window_title(char *buffer, size_t capacity, int id)
{
    if (!buffer || capacity == 0)
    {
        return;
    }
    const char prefix[] = "Window ";
    size_t pos = 0;
    for (size_t i = 0; i < sizeof(prefix) - 1 && pos < capacity - 1; ++i)
    {
        buffer[pos++] = prefix[i];
    }

    char digits[16];
    size_t digit_count = 0;
    int value = id;
    if (value <= 0)
    {
        digits[digit_count++] = '0';
    }
    else
    {
        while (value > 0 && digit_count < sizeof(digits))
        {
            digits[digit_count++] = (char)('0' + (value % 10));
            value /= 10;
        }
    }

    while (digit_count > 0 && pos < capacity - 1)
    {
        buffer[pos++] = digits[--digit_count];
    }
    buffer[pos] = '\0';
}

static void window_get_bounds(const atk_widget_t *window, int *x, int *y, int *width, int *height)
{
    if (!window || !window->used)
    {
        if (x) *x = 0;
        if (y) *y = 0;
        if (width) *width = 0;
        if (height) *height = 0;
        return;
    }

    const atk_window_priv_t *priv = window_priv(window);
    bool chrome_visible = priv ? priv->chrome_visible : true;

    int bx, by, bw, bh;
    if (chrome_visible)
    {
        bx = window->x - ATK_WINDOW_BORDER;
        by = window->y - ATK_WINDOW_BORDER;
        bw = window->width + ATK_WINDOW_BORDER * 2;
        bh = window->height + ATK_WINDOW_BORDER * 2;
    }
    else
    {
        bx = window->x;
        by = window->y;
        bw = window->width;
        bh = window->height;
    }

    if (x) *x = bx;
    if (y) *y = by;
    if (width) *width = bw;
    if (height) *height = bh;
}

static atk_widget_t *window_add_button(atk_widget_t *window,
                                       const char *title,
                                       int rel_x,
                                       int rel_y,
                                       int width,
                                       int height,
                                       atk_button_style_t style,
                                       bool draggable,
                                       atk_button_action_t action,
                                       void *context)
{
    if (!window)
    {
        return 0;
    }

    atk_window_priv_t *priv = window_priv_mut(window);
    if (!priv)
    {
        return 0;
    }

    atk_widget_t *btn = atk_widget_create(&ATK_BUTTON_CLASS);
    if (!btn)
    {
        return 0;
    }

    btn->x = rel_x;
    btn->y = rel_y;
    btn->width = width;
    btn->height = height;
    btn->parent = window;

    atk_button_configure(btn,
                         title,
                         style,
                         draggable,
                         false,
                         action,
                         context);
    atk_list_node_t *child_node = atk_list_push_back(&priv->children, btn);
    if (!child_node)
    {
        atk_widget_destroy(btn);
        return 0;
    }

    atk_list_node_t *button_node = atk_list_push_back(&priv->buttons, btn);
    if (!button_node)
    {
        atk_list_remove(&priv->children, child_node);
        atk_widget_destroy(btn);
        return 0;
    }

    atk_button_priv_t *btn_priv = (atk_button_priv_t *)atk_widget_priv(btn, &ATK_BUTTON_CLASS);
    if (btn_priv)
    {
        btn_priv->list_node = button_node;
    }

    if (action == action_window_close)
    {
        priv->close_button = btn;
    }

    return btn;
}

atk_widget_t *atk_window_add_button(atk_widget_t *window,
                                    const char *title,
                                    int rel_x,
                                    int rel_y,
                                    int width,
                                    int height,
                                    atk_button_style_t style,
                                    bool draggable,
                                    atk_button_action_t action,
                                    void *context)
{
    return window_add_button(window, title, rel_x, rel_y, width, height, style, draggable, action, context);
}

static void action_window_close(atk_widget_t *button, void *context)
{
    (void)button;
    atk_widget_t *window = (atk_widget_t *)context;
    atk_state_t *state = atk_state_get();
    atk_window_close(state, window);
}

static atk_window_priv_t *window_priv_mut(atk_widget_t *window)
{
    if (!window)
    {
        return 0;
    }
    return (atk_window_priv_t *)atk_widget_priv(window, &ATK_WINDOW_CLASS);
}

static const atk_window_priv_t *window_priv(const atk_widget_t *window)
{
    if (!window)
    {
        return 0;
    }
    return (const atk_window_priv_t *)atk_widget_priv(window, &ATK_WINDOW_CLASS);
}

static void window_child_destroy(void *value)
{
    atk_widget_t *widget = (atk_widget_t *)value;
    if (!widget)
    {
        return;
    }
    atk_widget_destroy_any(widget);
}

static void window_destroy(atk_widget_t *window)
{
    if (!window)
    {
        return;
    }

    atk_window_priv_t *priv = window_priv_mut(window);
    if (priv)
    {
        atk_list_clear(&priv->children, window_child_destroy);
        atk_list_clear(&priv->buttons, NULL);
        atk_list_clear(&priv->text_inputs, NULL);
        atk_list_clear(&priv->terminals, NULL);
        atk_list_clear(&priv->scrollbars, NULL);
        priv->list_node = 0;
        priv->user_context = NULL;
        priv->on_destroy = NULL;
        priv->close_button = NULL;
    }

    atk_widget_destroy(window);
}

static void window_destroy_value(void *value)
{
    window_destroy((atk_widget_t *)value);
}
