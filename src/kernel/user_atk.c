#include "user_atk_host.h"

#include "atk_internal.h"
#include "atk_window.h"
#include "atk/atk_image.h"
#include "heap.h"
#include "libc.h"
#include "process.h"
#include "serial.h"
#include "video.h"

#ifndef USER_ATK_DEBUG
#define USER_ATK_DEBUG 0
#endif

typedef struct user_atk_window
{
    uint32_t handle;
    process_t *owner;
    atk_widget_t *window;
    atk_widget_t *image;
    uint16_t *pixels;
    size_t pixel_bytes;
    int content_width;
    int content_height;
    int content_offset_x;
    int content_offset_y;
    int stride_bytes;
    bool closed;
    bool destroying;
    user_atk_event_t events[USER_ATK_EVENT_QUEUE_MAX];
    size_t event_head;
    size_t event_tail;
    size_t event_count;
    wait_queue_t event_waiters;
    struct user_atk_window *next;
    struct user_atk_window *prev;
} user_atk_window_t;

static user_atk_window_t *g_windows_head = NULL;
static user_atk_window_t *g_focus_window = NULL;
static user_atk_window_t *g_capture_window = NULL;
static process_t *g_focus_priority_owner = NULL;
static process_t *g_capture_priority_owner = NULL;
static uint32_t g_next_handle = 1;

#if USER_ATK_DEBUG
static void user_atk_log(const char *msg, uint64_t value)
{
    serial_write_string("[user_atk] ");
    serial_write_string(msg);
    serial_write_string("0x");
    serial_write_hex64(value);
    serial_write_string("\r\n");
}

static void user_atk_log_pair(const char *msg, uint64_t a, uint64_t b)
{
    serial_write_string("[user_atk] ");
    serial_write_string(msg);
    serial_write_string(" a=0x");
    serial_write_hex64(a);
    serial_write_string(" b=0x");
    serial_write_hex64(b);
    serial_write_string("\r\n");
}
#else
static void user_atk_log(const char *msg, uint64_t value)
{
    (void)msg;
    (void)value;
}
#define user_atk_log_pair(msg, a, b) (void)0
#endif

static user_atk_window_t *user_atk_from_window(const atk_widget_t *window);
static user_atk_window_t *user_atk_find(uint32_t handle, process_t *owner);
static void user_atk_insert(user_atk_window_t *win);
static void user_atk_remove(user_atk_window_t *win, bool closing_kernel);
static void user_atk_window_on_destroy(void *context);
static void user_atk_queue_event(user_atk_window_t *win, const user_atk_event_t *event);
static bool user_atk_pop_event(user_atk_window_t *win, user_atk_event_t *out_event);
static void user_atk_send_close_event(user_atk_window_t *win);
static void user_atk_apply_priorities(void);
static bool user_atk_event_queue_empty(void *context);
static bool user_atk_try_coalesce_mouse(user_atk_window_t *win, const user_atk_event_t *event);

void user_atk_init(void)
{
    g_windows_head = NULL;
    g_focus_window = NULL;
    g_capture_window = NULL;
    if (g_focus_priority_owner)
    {
        process_clear_priority_override(g_focus_priority_owner);
        g_focus_priority_owner = NULL;
    }
    if (g_capture_priority_owner)
    {
        process_clear_priority_override(g_capture_priority_owner);
        g_capture_priority_owner = NULL;
    }
    g_next_handle = 1;
}

static user_atk_window_t *user_atk_from_window(const atk_widget_t *window)
{
    if (!window)
    {
        return NULL;
    }
    return (user_atk_window_t *)atk_window_context(window);
}

bool user_atk_window_is_remote(const atk_widget_t *window)
{
    return user_atk_from_window(window) != NULL;
}

void user_atk_focus_window(const atk_widget_t *window)
{
    user_atk_window_t *target = user_atk_from_window(window);
    if (target && target->closed)
    {
        target = NULL;
    }
    if (g_focus_window == target)
    {
        return;
    }
    g_focus_window = target;
    user_atk_apply_priorities();
}

bool user_atk_route_mouse_event(const atk_widget_t *hover_window,
                                int cursor_x,
                                int cursor_y,
                                bool pressed_edge,
                                bool released_edge,
                                bool left_pressed)
{
    user_atk_window_t *previous_capture = g_capture_window;
    user_atk_window_t *target = g_capture_window;
    if (!target)
    {
        target = user_atk_from_window(hover_window);
    }
#if USER_ATK_DEBUG
    user_atk_log_pair("route_mouse hover", (uintptr_t)hover_window, (uintptr_t)(target ? target->window : NULL));
#endif
    if (!target || target->closed || !target->window)
    {
        return false;
    }

    int win_x = target->window->x + target->content_offset_x;
    int win_y = target->window->y + target->content_offset_y;

    int rel_x = cursor_x - win_x;
    int rel_y = cursor_y - win_y;

    bool inside = (rel_x >= 0 && rel_y >= 0 &&
                   rel_x < target->content_width &&
                   rel_y < target->content_height);

    if (!inside && !g_capture_window)
    {
#if USER_ATK_DEBUG
        uint64_t coord = ((uint64_t)(uint32_t)rel_x << 32) | (uint32_t)(rel_y & 0xFFFFFFFFu);
        user_atk_log_pair("route_mouse outside", coord, (uint64_t)target->handle);
#endif
        return false;
    }

    user_atk_event_t event = {
        .type = USER_ATK_EVENT_MOUSE,
        .flags = 0,
        .x = rel_x,
        .y = rel_y,
        .data0 = 0,
        .data1 = 0,
    };

    if (left_pressed)
    {
        event.flags |= USER_ATK_MOUSE_FLAG_LEFT;
    }
    if (pressed_edge)
    {
        event.flags |= USER_ATK_MOUSE_FLAG_PRESS;
        g_capture_window = target;
#if USER_ATK_DEBUG
        user_atk_log_pair("capture begin", target->handle, (uint64_t)event.flags);
#endif
    }
    if (released_edge)
    {
        event.flags |= USER_ATK_MOUSE_FLAG_RELEASE;
        if (g_capture_window == target && !left_pressed)
        {
            g_capture_window = NULL;
#if USER_ATK_DEBUG
            user_atk_log_pair("capture end", target->handle, (uint64_t)event.flags);
#endif
        }
    }

#if USER_ATK_DEBUG
    uint64_t coord = ((uint64_t)(uint32_t)rel_x << 32) | (uint32_t)(rel_y & 0xFFFFFFFFu);
    user_atk_log_pair("queue mouse", coord, (uint64_t)event.flags);
#endif
    user_atk_queue_event(target, &event);
    if (previous_capture != g_capture_window)
    {
        user_atk_apply_priorities();
    }
    return true;
}

bool user_atk_route_key_event(char ch)
{
    if (!g_focus_window || g_focus_window->closed)
    {
        return false;
    }
#if USER_ATK_DEBUG
    user_atk_log_pair("route_key", (uint64_t)(uint8_t)ch, g_focus_window->handle);
#endif

    user_atk_event_t event = {
        .type = USER_ATK_EVENT_KEY,
        .flags = 0,
        .x = 0,
        .y = 0,
        .data0 = (uint8_t)ch,
        .data1 = 0,
    };
    user_atk_queue_event(g_focus_window, &event);
    return true;
}

static void user_atk_window_on_destroy(void *context)
{
    user_atk_window_t *win = (user_atk_window_t *)context;
    if (!win)
    {
        return;
    }

    win->window = NULL;
    win->image = NULL;
    win->pixels = NULL;
    win->closed = true;
    if (g_focus_window == win)
    {
        g_focus_window = NULL;
    }
    if (g_capture_window == win)
    {
        g_capture_window = NULL;
    }
    wait_queue_wake_all(&win->event_waiters);
    user_atk_apply_priorities();
    user_atk_send_close_event(win);
}

static void user_atk_insert(user_atk_window_t *win)
{
    win->prev = NULL;
    win->next = g_windows_head;
    if (g_windows_head)
    {
        g_windows_head->prev = win;
    }
    g_windows_head = win;
}

static void user_atk_remove(user_atk_window_t *win, bool closing_kernel)
{
    if (!win)
    {
        return;
    }

    if (win->prev)
    {
        win->prev->next = win->next;
    }
    else
    {
        g_windows_head = win->next;
    }
    if (win->next)
    {
        win->next->prev = win->prev;
    }
    win->next = NULL;
    win->prev = NULL;

    if (!closing_kernel && win->window)
    {
        win->destroying = true;
        atk_window_close(atk_state_get(), win->window);
        win->destroying = false;
    }

    if (g_focus_window == win)
    {
        g_focus_window = NULL;
    }
    if (g_capture_window == win)
    {
        g_capture_window = NULL;
    }
    wait_queue_wake_all(&win->event_waiters);
    user_atk_apply_priorities();
    free(win);
}

static user_atk_window_t *user_atk_find(uint32_t handle, process_t *owner)
{
    for (user_atk_window_t *win = g_windows_head; win; win = win->next)
    {
        if (win->handle == handle && win->owner == owner)
        {
            return win;
        }
    }
    return NULL;
}

int64_t user_atk_sys_create(const user_atk_window_desc_t *desc_user)
{
    if (!desc_user)
    {
        return -1;
    }

    user_atk_window_desc_t desc;
    memcpy(&desc, desc_user, sizeof(desc));

    if (desc.width == 0 || desc.height == 0)
    {
        return -1;
    }
    if (desc.width > VIDEO_WIDTH)
    {
        desc.width = VIDEO_WIDTH;
    }
    if (desc.height > VIDEO_HEIGHT)
    {
        desc.height = VIDEO_HEIGHT;
    }
    desc.title[USER_ATK_TITLE_MAX - 1] = '\0';

    atk_state_t *state = atk_state_get();
    atk_widget_t *window = atk_window_create_at(state, VIDEO_WIDTH / 2, VIDEO_HEIGHT / 2);
    if (!window)
    {
        return -1;
    }

    const int margin = 8;
    int content_offset_x = margin;
    int content_offset_y = ATK_WINDOW_TITLE_HEIGHT + margin;
    window->width = desc.width + margin * 2;
    window->height = desc.height + margin * 2 + ATK_WINDOW_TITLE_HEIGHT;
    atk_window_ensure_inside(window);

    if (desc.title[0] != '\0')
    {
        atk_window_set_title_text(window, desc.title);
    }

    atk_widget_t *image = atk_window_add_image(window, content_offset_x, content_offset_y);
    if (!image)
    {
        atk_window_close(state, window);
        return -1;
    }

    size_t pixel_bytes = (size_t)desc.width * (size_t)desc.height * sizeof(uint16_t);
    uint16_t *pixels = (uint16_t *)malloc(pixel_bytes);
    if (!pixels)
    {
        atk_window_close(state, window);
        return -1;
    }
    memset(pixels, 0, pixel_bytes);
    user_atk_log("alloc pixels=", (uintptr_t)pixels);
    user_atk_log("alloc bytes=", pixel_bytes);

    if (!atk_image_set_pixels(image, pixels, desc.width, desc.height, desc.width * (int)sizeof(uint16_t), true))
    {
        free(pixels);
        atk_window_close(state, window);
        return -1;
    }

    user_atk_window_t *win = (user_atk_window_t *)calloc(1, sizeof(user_atk_window_t));
    if (!win)
    {
        atk_window_close(state, window);
        return -1;
    }

    win->handle = g_next_handle++;
    win->owner = process_current();
    win->window = window;
    win->image = image;
    win->pixels = atk_image_pixels(image);
    win->pixel_bytes = pixel_bytes;
    win->content_width = desc.width;
    win->content_height = desc.height;
    win->content_offset_x = content_offset_x;
    win->content_offset_y = content_offset_y;
    win->stride_bytes = desc.width * (int)sizeof(uint16_t);
    win->closed = false;
    win->destroying = false;
    win->event_head = 0;
    win->event_tail = 0;
    win->event_count = 0;
    wait_queue_init(&win->event_waiters);

    atk_window_set_context(window, win, user_atk_window_on_destroy);
    user_atk_insert(win);

    atk_window_mark_dirty(window);
    video_request_refresh_window(window);
    video_pump_events();
    user_atk_log("create handle=", win->handle);
    user_atk_focus_window(window);
    return (int64_t)win->handle;
}

int64_t user_atk_sys_present(uint32_t handle, const uint16_t *pixels, size_t byte_len)
{
    if (!pixels)
    {
        return -1;
    }
    user_atk_log("present handle=", handle);
    user_atk_log("present user ptr=", (uintptr_t)pixels);
    user_atk_log("present bytes=", byte_len);
    user_atk_window_t *win = user_atk_find(handle, process_current());
    if (!win || win->closed || !win->pixels)
    {
        return -1;
    }

    if (byte_len != win->pixel_bytes)
    {
        return -1;
    }

    memcpy(win->pixels, pixels, byte_len);
    user_atk_log("present dst ptr=", (uintptr_t)win->pixels);
    if (win->window)
    {
        atk_window_mark_dirty(win->window);
        video_request_refresh_window(win->window);
    }
    else
    {
        video_request_refresh();
    }
    video_pump_events();
    return 0;
}

int64_t user_atk_sys_poll_event(uint32_t handle, user_atk_event_t *event_out, uint32_t flags)
{
    if (!event_out)
    {
        return -1;
    }
    user_atk_window_t *win = user_atk_find(handle, process_current());
    if (!win)
    {
        return -1;
    }

    bool block = (flags & USER_ATK_POLL_FLAG_BLOCK) != 0;

    user_atk_event_t event = { 0 };
    while (!user_atk_pop_event(win, &event))
    {
        if (!block || win->closed)
        {
            memset(event_out, 0, sizeof(*event_out));
#if USER_ATK_DEBUG
            user_atk_log_pair("sys_poll_event empty", handle, flags);
#endif
            return 0;
        }
        wait_queue_wait(&win->event_waiters, user_atk_event_queue_empty, win);
    }

    *event_out = event;
#if USER_ATK_DEBUG
    user_atk_log_pair("sys_poll_event", handle, event_out->type);
#endif
    return 1;
}

int64_t user_atk_sys_close(uint32_t handle)
{
    user_atk_log("close handle=", handle);
    user_atk_window_t *win = user_atk_find(handle, process_current());
    if (!win)
    {
        return -1;
    }

    user_atk_remove(win, false);
    return 0;
}

void user_atk_on_process_destroy(process_t *process)
{
    user_atk_window_t *win = g_windows_head;
    while (win)
    {
        user_atk_window_t *next = win->next;
        if (win->owner == process)
        {
            user_atk_remove(win, false);
        }
        win = next;
    }
}

static void user_atk_queue_event(user_atk_window_t *win, const user_atk_event_t *event)
{
    if (!win || !event)
    {
        return;
    }
#if USER_ATK_DEBUG
    user_atk_log_pair("enqueue event", win->handle, event->type);
    if (event->type == USER_ATK_EVENT_MOUSE)
    {
        uint64_t coord = ((uint64_t)(uint32_t)event->x << 32) | (uint32_t)(event->y & 0xFFFFFFFFu);
        user_atk_log_pair("enqueue mouse", coord, event->flags);
    }
#endif

    if (user_atk_try_coalesce_mouse(win, event))
    {
#if USER_ATK_DEBUG
        user_atk_log_pair("coalesce mouse", win->handle, event->flags);
#endif
        return;
    }

    win->events[win->event_tail] = *event;
    win->event_tail = (win->event_tail + 1) % USER_ATK_EVENT_QUEUE_MAX;
    if (win->event_count == USER_ATK_EVENT_QUEUE_MAX)
    {
        win->event_head = (win->event_head + 1) % USER_ATK_EVENT_QUEUE_MAX;
        win->event_count--;
    }
    win->event_count++;
    wait_queue_wake_one(&win->event_waiters);
}

static bool user_atk_pop_event(user_atk_window_t *win, user_atk_event_t *out_event)
{
    if (!win || win->event_count == 0)
    {
        return false;
    }
    if (out_event)
    {
        *out_event = win->events[win->event_head];
    }
#if USER_ATK_DEBUG
    if (out_event)
    {
        user_atk_log_pair("dequeue event", win->handle, out_event->type);
    }
#endif
    win->event_head = (win->event_head + 1) % USER_ATK_EVENT_QUEUE_MAX;
    win->event_count--;
    return true;
}

static void user_atk_send_close_event(user_atk_window_t *win)
{
    if (!win)
    {
        return;
    }
    user_atk_event_t event = {
        .type = USER_ATK_EVENT_CLOSE,
        .flags = 0,
        .x = 0,
        .y = 0,
        .data0 = 0,
        .data1 = 0,
    };
    user_atk_queue_event(win, &event);
}

static bool user_atk_event_queue_empty(void *context)
{
    user_atk_window_t *win = (user_atk_window_t *)context;
    if (!win)
    {
        return false;
    }
    return (win->event_count == 0) && !win->closed;
}

static bool user_atk_try_coalesce_mouse(user_atk_window_t *win, const user_atk_event_t *event)
{
    if (!win || !event)
    {
        return false;
    }
    if (event->type != USER_ATK_EVENT_MOUSE)
    {
        return false;
    }

    const uint32_t edge_mask = USER_ATK_MOUSE_FLAG_PRESS | USER_ATK_MOUSE_FLAG_RELEASE;
    if ((event->flags & edge_mask) != 0)
    {
        return false;
    }
    if (win->event_count == 0)
    {
        return false;
    }

    size_t last_index = (win->event_tail == 0) ? (USER_ATK_EVENT_QUEUE_MAX - 1) : (win->event_tail - 1);
    user_atk_event_t *last = &win->events[last_index];
    if (last->type != USER_ATK_EVENT_MOUSE)
    {
        return false;
    }
    if ((last->flags & edge_mask) != 0)
    {
        return false;
    }

    last->x = event->x;
    last->y = event->y;
    last->flags = event->flags;
    return true;
}

static void user_atk_apply_priorities(void)
{
    process_t *focus_owner = (g_focus_window && !g_focus_window->closed) ? g_focus_window->owner : NULL;
    process_t *capture_owner = (g_capture_window && !g_capture_window->closed) ? g_capture_window->owner : NULL;

    if (g_capture_priority_owner && g_capture_priority_owner != capture_owner)
    {
        if (g_capture_priority_owner == focus_owner)
        {
            process_set_priority_override(g_capture_priority_owner, THREAD_PRIORITY_HIGH);
            g_focus_priority_owner = g_capture_priority_owner;
        }
        else
        {
            process_clear_priority_override(g_capture_priority_owner);
        }
        g_capture_priority_owner = NULL;
    }

    if (g_focus_priority_owner &&
        g_focus_priority_owner != focus_owner &&
        g_focus_priority_owner != capture_owner)
    {
        process_clear_priority_override(g_focus_priority_owner);
        g_focus_priority_owner = NULL;
    }

    if (capture_owner)
    {
        process_set_priority_override(capture_owner, THREAD_PRIORITY_UI);
        g_capture_priority_owner = capture_owner;
    }

    if (focus_owner)
    {
        if (focus_owner == capture_owner)
        {
            g_focus_priority_owner = focus_owner;
        }
        else
        {
            process_set_priority_override(focus_owner, THREAD_PRIORITY_HIGH);
            g_focus_priority_owner = focus_owner;
        }
    }
    else if (!capture_owner && g_focus_priority_owner)
    {
        process_clear_priority_override(g_focus_priority_owner);
        g_focus_priority_owner = NULL;
    }

    if (!capture_owner)
    {
        g_capture_priority_owner = NULL;
    }
}
