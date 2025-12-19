#include "user_atk_host.h"

#include "atk_internal.h"
#include "atk_window.h"
#include "atk/atk_image.h"
#include "heap.h"
#include "libc.h"
#include "process.h"
#include "serial.h"
#include "spinlock.h"
#include "video.h"
#include "user_copy.h"

#ifndef USER_ATK_DEBUG
#define USER_ATK_DEBUG 0
#endif

typedef struct user_atk_window
{
    uint32_t handle;
    uint32_t flags;
    uint32_t refcount;
    process_t *owner;
    atk_widget_t *window;
    atk_widget_t *image;
    video_color_t *pixels;
    video_color_t *back_pixels;
    size_t pixel_bytes;
    int content_width;
    int content_height;
    int content_offset_x;
    int content_offset_y;
    int stride_bytes;
    bool closed;
    bool destroying;
    spinlock_t pixel_lock;
    user_atk_event_t events[USER_ATK_EVENT_QUEUE_MAX];
    size_t event_head;
    size_t event_tail;
    size_t event_count;
    spinlock_t event_lock;
    wait_queue_t event_waiters;
    struct user_atk_window *next;
    struct user_atk_window *prev;
} user_atk_window_t;

static user_atk_window_t *g_windows_head = NULL;
static user_atk_window_t *g_focus_window = NULL;
static user_atk_window_t *g_capture_window = NULL;
static bool g_capture_forced = false;
static bool g_capture_relative = false;
static process_t *g_focus_priority_owner = NULL;
static process_t *g_capture_priority_owner = NULL;
static uint32_t g_next_handle = 1;

#define USER_ATK_PRESENT_SAMPLE_WORDS 8u

#if USER_ATK_DEBUG
static void user_atk_present_log_summary(uint32_t handle,
                                         size_t expected_bytes,
                                         size_t actual_bytes,
                                         const video_color_t *src_pixels,
                                         const video_color_t *dst_pixels)
{
    serial_printf("[user_atk][present] handle=0x%016llX expected=0x%016llX actual=0x%016llX user=0x%016llX dst=0x%016llX\r\n",
                  (unsigned long long)((uint64_t)handle),
                  (unsigned long long)((uint64_t)expected_bytes),
                  (unsigned long long)((uint64_t)actual_bytes),
                  (unsigned long long)((uint64_t)(uintptr_t)src_pixels),
                  (unsigned long long)((uint64_t)(uintptr_t)dst_pixels));
}

static void user_atk_present_log_mismatch(uint32_t handle, size_t expected_bytes, size_t actual_bytes)
{
    serial_printf("[user_atk][present] length_mismatch handle=0x%016llX expected=0x%016llX actual=0x%016llX\r\n",
                  (unsigned long long)((uint64_t)handle),
                  (unsigned long long)((uint64_t)expected_bytes),
                  (unsigned long long)((uint64_t)actual_bytes));
}
#endif

#if USER_ATK_DEBUG
static void user_atk_log(const char *msg, uint64_t value)
{
    serial_printf("[user_atk] %s0x%016llX\r\n",
                  msg ? msg : "",
                  (unsigned long long)value);
}

static void user_atk_log_pair(const char *msg, uint64_t a, uint64_t b)
{
    serial_printf("[user_atk] %s a=0x%016llX b=0x%016llX\r\n",
                  msg ? msg : "",
                  (unsigned long long)a,
                  (unsigned long long)b);
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
static bool user_atk_event_ready(void *context);
static bool user_atk_try_coalesce_mouse(user_atk_window_t *win, const user_atk_event_t *event);
static void user_atk_queue_resize_event(user_atk_window_t *win, uint32_t width, uint32_t height);
static void user_atk_queue_key_sequence(user_atk_window_t *win,
                                        const keyboard_event_t *src,
                                        const char *seq,
                                        size_t len);

static spinlock_t g_windows_lock;

static inline void user_atk_windows_lock(void)
{
    spinlock_lock(&g_windows_lock);
}

static inline void user_atk_windows_unlock(void)
{
    spinlock_unlock(&g_windows_lock);
}

void user_atk_init(void)
{
    g_windows_head = NULL;
    g_focus_window = NULL;
    g_capture_window = NULL;
    g_capture_forced = false;
    g_capture_relative = false;
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
    spinlock_init(&g_windows_lock);
    g_next_handle = 1;
}

static void user_atk_window_retain(user_atk_window_t *win)
{
    if (!win)
    {
        return;
    }
    __atomic_fetch_add(&win->refcount, 1u, __ATOMIC_SEQ_CST);
}

static void user_atk_window_release(user_atk_window_t *win)
{
    if (!win)
    {
        return;
    }
    uint32_t prev = __atomic_fetch_sub(&win->refcount, 1u, __ATOMIC_SEQ_CST);
    if (prev == 0)
    {
        __atomic_fetch_add(&win->refcount, 1u, __ATOMIC_SEQ_CST);
        return;
    }
    if (prev == 1)
    {
        free(win);
    }
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

bool user_atk_window_is_resizable(const atk_widget_t *window)
{
    user_atk_window_t *win = user_atk_from_window(window);
    if (!win)
    {
        return false;
    }
    return (win->flags & USER_ATK_WINDOW_FLAG_RESIZABLE) != 0;
}

void user_atk_window_resized(const atk_widget_t *window)
{
    user_atk_window_t *win = user_atk_from_window(window);
    if (!win || (win->flags & USER_ATK_WINDOW_FLAG_RESIZABLE) == 0)
    {
        return;
    }
    if (!win->image || !win->window)
    {
        return;
    }

    atk_widget_t *image = win->image;

    int new_off_x = image->x;
    int new_off_y = image->y;
    int new_width = image->width;
    int new_height = image->height;
    if (new_width < 1) new_width = 1;
    if (new_height < 1) new_height = 1;

    bool size_changed = (new_width != win->content_width) || (new_height != win->content_height);
    bool offset_changed = (win->content_offset_x != new_off_x) || (win->content_offset_y != new_off_y);

    if (!size_changed && !offset_changed)
    {
        return;
    }

    serial_printf("[user_atk][resize] handle=0x%016llX old=%dx%d off=(%d,%d) new=%dx%d off=(%d,%d)\r\n",
                  (unsigned long long)win->handle,
                  win->content_width,
                  win->content_height,
                  win->content_offset_x,
                  win->content_offset_y,
                  new_width,
                  new_height,
                  new_off_x,
                  new_off_y);

    spinlock_lock(&win->pixel_lock);
    serial_printf("[user_atk][resize] handle=0x%016llX pixels=0x%016llX bytes=0x%016llX stride=%d content=%dx%d\r\n",
                  (unsigned long long)win->handle,
                  (unsigned long long)(uintptr_t)win->pixels,
                  (unsigned long long)win->pixel_bytes,
                  win->stride_bytes,
                  win->content_width,
                  win->content_height);
    if (size_changed)
    {
        size_t new_bytes = (size_t)new_width * (size_t)new_height * sizeof(video_color_t);
        video_color_t *front = (video_color_t *)malloc(new_bytes);
        if (!front)
        {
            spinlock_unlock(&win->pixel_lock);
            image->width = win->content_width;
            image->height = win->content_height;
            return;
        }
        video_color_t *back = (video_color_t *)malloc(new_bytes);
        if (!back)
        {
            free(front);
            spinlock_unlock(&win->pixel_lock);
            image->width = win->content_width;
            image->height = win->content_height;
            return;
        }
        memset(front, 0, new_bytes);
        memset(back, 0, new_bytes);

        if (win->pixels && win->content_width > 0 && win->content_height > 0)
        {
            int copy_w = (new_width < win->content_width) ? new_width : win->content_width;
            int copy_h = (new_height < win->content_height) ? new_height : win->content_height;
            for (int row = 0; row < copy_h; ++row)
            {
                size_t dst_offset = (size_t)row * (size_t)new_width * sizeof(video_color_t);
                size_t src_offset = (size_t)row * (size_t)win->stride_bytes;
                memcpy((uint8_t *)front + dst_offset,
                       (const uint8_t *)win->pixels + src_offset,
                       (size_t)copy_w * sizeof(video_color_t));
            }
        }

        if (!atk_image_set_pixels(image,
                                  front,
                                  new_width,
                                  new_height,
                                  new_width * (int)sizeof(video_color_t),
                                  false))
        {
            free(back);
            free(front);
            image->width = win->content_width;
            image->height = win->content_height;
            spinlock_unlock(&win->pixel_lock);
            return;
        }

        video_color_t *old_front = win->pixels;
        video_color_t *old_back = win->back_pixels;
        win->pixels = atk_image_pixels(image);
        win->back_pixels = back;
        win->pixel_bytes = new_bytes;
        win->stride_bytes = new_width * (int)sizeof(video_color_t);
        win->content_width = new_width;
        win->content_height = new_height;
        spinlock_unlock(&win->pixel_lock);
        if (old_front)
        {
            free(old_front);
        }
        if (old_back)
        {
            free(old_back);
        }
        spinlock_lock(&win->pixel_lock);
    }

    /* Refresh layout margins so anchor-based layout keeps using correct geometry. */
    image->layout_margin_left = new_off_x;
    image->layout_margin_top = new_off_y;
    image->layout_margin_right = win->window->width - (new_off_x + new_width);
    image->layout_margin_bottom = win->window->height - (new_off_y + new_height);
    if (image->layout_margin_right < 0) image->layout_margin_right = 0;
    if (image->layout_margin_bottom < 0) image->layout_margin_bottom = 0;

    win->content_offset_x = new_off_x;
    win->content_offset_y = new_off_y;
    spinlock_unlock(&win->pixel_lock);

    user_atk_queue_resize_event(win, (uint32_t)win->content_width, (uint32_t)win->content_height);
    atk_window_mark_dirty(win->window);
    video_request_refresh_window(win->window);
}

void user_atk_focus_window(const atk_widget_t *window)
{
    user_atk_window_t *target = user_atk_from_window(window);
    if (target && target->closed)
    {
        target = NULL;
    }
    user_atk_windows_lock();
    if (g_focus_window != target)
    {
        g_focus_window = target;
    }
    user_atk_windows_unlock();
    user_atk_apply_priorities();
}

bool user_atk_capture_relative_active(void)
{
    user_atk_window_t *win = __atomic_load_n(&g_capture_window, __ATOMIC_ACQUIRE);
    bool forced = __atomic_load_n(&g_capture_forced, __ATOMIC_ACQUIRE);
    bool relative = __atomic_load_n(&g_capture_relative, __ATOMIC_ACQUIRE);
    return win && forced && relative;
}

bool user_atk_route_mouse_event(const atk_widget_t *hover_window,
                                int dx,
                                int dy,
                                int cursor_x,
                                int cursor_y,
                                bool pressed_edge,
                                bool released_edge,
                                bool left_pressed)
{
    user_atk_windows_lock();
    user_atk_window_t *previous_capture = g_capture_window;
    bool forced_capture = g_capture_forced;
    bool relative_capture = g_capture_relative;
    if (previous_capture)
    {
        user_atk_window_retain(previous_capture);
    }
    user_atk_windows_unlock();

    user_atk_window_t *hover_target = user_atk_from_window(hover_window);
    bool dropped_forced_capture = false;
    if (forced_capture && previous_capture && pressed_edge && hover_target != previous_capture)
    {
        user_atk_windows_lock();
        if (g_capture_window == previous_capture && g_capture_forced)
        {
            g_capture_window = NULL;
            g_capture_forced = false;
            g_capture_relative = false;
            dropped_forced_capture = true;
        }
        user_atk_windows_unlock();
    }
    if (dropped_forced_capture)
    {
        forced_capture = false;
        relative_capture = false;
    }

    user_atk_window_t *target = NULL;
    if (!dropped_forced_capture && previous_capture)
    {
        target = previous_capture;
        /* target is already retained via previous_capture */
    }
    else
    {
        target = hover_target;
        if (target)
        {
            user_atk_window_retain(target);
        }
    }
#if USER_ATK_DEBUG
    user_atk_log_pair("route_mouse hover", (uintptr_t)hover_window, (uintptr_t)(target ? target->window : NULL));
#endif
    if (!target || target->closed || !target->window)
    {
        if (target && target != previous_capture)
        {
            user_atk_window_release(target);
        }
        if (previous_capture)
        {
            user_atk_window_release(previous_capture);
        }
        return false;
    }

    int win_x = target->window->x + target->content_offset_x;
    int win_y = target->window->y + target->content_offset_y;

    int rel_x = cursor_x - win_x;
    int rel_y = cursor_y - win_y;

    bool inside = (rel_x >= 0 && rel_y >= 0 &&
                   rel_x < target->content_width &&
                   rel_y < target->content_height);

    if (!inside && target != previous_capture)
    {
#if USER_ATK_DEBUG
        uint64_t coord = ((uint64_t)(uint32_t)rel_x << 32) | (uint32_t)(rel_y & 0xFFFFFFFFu);
        user_atk_log_pair("route_mouse outside", coord, (uint64_t)target->handle);
#endif
        if (target && target != previous_capture)
        {
            user_atk_window_release(target);
        }
        if (previous_capture)
        {
            user_atk_window_release(previous_capture);
        }
        return false;
    }

    user_atk_event_t event = {
        .type = USER_ATK_EVENT_MOUSE,
        .flags = 0,
        .x = rel_x,
        .y = rel_y,
        .data0 = (uint32_t)dx,
        .data1 = (uint32_t)dy,
    };

    if (left_pressed)
    {
        event.flags |= USER_ATK_MOUSE_FLAG_LEFT;
    }
    if (pressed_edge)
    {
        event.flags |= USER_ATK_MOUSE_FLAG_PRESS;
        if (!forced_capture)
        {
            user_atk_windows_lock();
            g_capture_window = target;
            g_capture_relative = false;
            user_atk_windows_unlock();
        }
#if USER_ATK_DEBUG
        user_atk_log_pair("capture begin", target->handle, (uint64_t)event.flags);
#endif
    }
    if (released_edge)
    {
        event.flags |= USER_ATK_MOUSE_FLAG_RELEASE;
        if (!forced_capture)
        {
            user_atk_windows_lock();
            if (g_capture_window == target && !left_pressed)
            {
                g_capture_window = NULL;
            }
            g_capture_relative = false;
#if USER_ATK_DEBUG
            user_atk_log_pair("capture end", target->handle, (uint64_t)event.flags);
#endif
            user_atk_windows_unlock();
        }
    }

    if (forced_capture && relative_capture)
    {
        event.flags |= USER_ATK_MOUSE_FLAG_RELATIVE;
    }

#if USER_ATK_DEBUG
    uint64_t coord = ((uint64_t)(uint32_t)rel_x << 32) | (uint32_t)(rel_y & 0xFFFFFFFFu);
    user_atk_log_pair("queue mouse", coord, (uint64_t)event.flags);
#endif
    user_atk_queue_event(target, &event);
    user_atk_windows_lock();
    bool capture_changed = (previous_capture != g_capture_window);
    user_atk_windows_unlock();
    if (capture_changed)
    {
        user_atk_apply_priorities();
    }
    if (target && target != previous_capture)
    {
        user_atk_window_release(target);
    }
    if (previous_capture)
    {
        user_atk_window_release(previous_capture);
    }
    return true;
}

bool user_atk_route_key_event(const keyboard_event_t *key_event)
{
    if (!key_event)
    {
        return false;
    }
    user_atk_windows_lock();
    user_atk_window_t *focus = g_focus_window;
    if (focus && focus->closed)
    {
        focus = NULL;
        g_focus_window = NULL;
    }
    if (focus)
    {
        user_atk_window_retain(focus);
    }
    user_atk_windows_unlock();
    if (!focus)
    {
        return false;
    }
#if USER_ATK_DEBUG
    user_atk_log_pair("route_key", (uint64_t)(uint8_t)key_event->ch, focus->handle);
#endif

    /* Translate extended arrow keys into ANSI escape sequences so text UI can consume them. */
    if (key_event->extended && !key_event->released && key_event->ch == 0)
    {
        const char *seq = NULL;
        size_t seq_len = 0;
        switch (key_event->scancode)
        {
            case 0x48: seq = "\x1B[A"; seq_len = 3; break; /* Up */
            case 0x50: seq = "\x1B[B"; seq_len = 3; break; /* Down */
            case 0x4B: seq = "\x1B[D"; seq_len = 3; break; /* Left */
            case 0x4D: seq = "\x1B[C"; seq_len = 3; break; /* Right */
            default:
                break;
        }
        if (seq && seq_len > 0)
        {
            user_atk_queue_key_sequence(focus, key_event, seq, seq_len);
            user_atk_window_release(focus);
            return true;
        }
    }

    user_atk_event_t event = {
        .type = USER_ATK_EVENT_KEY,
        .flags = 0,
        .x = 0,
        .y = 0,
        .data0 = (uint8_t)key_event->ch,
        .data1 = (uint32_t)key_event->scancode,
    };
    if (key_event->released)
    {
        event.flags |= USER_ATK_KEY_FLAG_RELEASE;
    }
    if (key_event->extended)
    {
        event.flags |= USER_ATK_KEY_FLAG_EXTENDED;
    }
    if (key_event->repeat)
    {
        event.flags |= USER_ATK_KEY_FLAG_REPEAT;
    }
    user_atk_queue_event(focus, &event);
    user_atk_window_release(focus);
    return true;
}

static void user_atk_queue_key_sequence(user_atk_window_t *win,
                                        const keyboard_event_t *src,
                                        const char *seq,
                                        size_t len)
{
    if (!win || !seq || len == 0)
    {
        return;
    }
    for (size_t i = 0; i < len; ++i)
    {
        user_atk_event_t ev = {
            .type = USER_ATK_EVENT_KEY,
            .flags = 0,
            .x = 0,
            .y = 0,
            .data0 = (uint8_t)seq[i],
            .data1 = src ? (uint32_t)src->scancode : 0,
        };
        if (src)
        {
            if (src->extended)
            {
                ev.flags |= USER_ATK_KEY_FLAG_EXTENDED;
            }
            if (src->repeat)
            {
                ev.flags |= USER_ATK_KEY_FLAG_REPEAT;
            }
        }
        user_atk_queue_event(win, &ev);
    }
}

static void user_atk_window_on_destroy(void *context)
{
    user_atk_window_t *win = (user_atk_window_t *)context;
    if (!win)
    {
        return;
    }

    bool send_close_event = !win->destroying;
    video_color_t *front_pixels = NULL;
    video_color_t *back_pixels = NULL;
    user_atk_windows_lock();
    win->window = NULL;
    win->image = NULL;
    spinlock_lock(&win->pixel_lock);
    front_pixels = win->pixels;
    back_pixels = win->back_pixels;
    win->pixels = NULL;
    win->back_pixels = NULL;
    win->pixel_bytes = 0;
    win->closed = true;
    spinlock_unlock(&win->pixel_lock);
    if (g_focus_window == win)
    {
        g_focus_window = NULL;
    }
    if (g_capture_window == win)
    {
        g_capture_window = NULL;
        g_capture_forced = false;
        g_capture_relative = false;
    }
    user_atk_windows_unlock();
    if (front_pixels)
    {
        free(front_pixels);
    }
    if (back_pixels)
    {
        free(back_pixels);
    }
    wait_queue_wake_all(&win->event_waiters);
    user_atk_apply_priorities();
    if (send_close_event)
    {
        user_atk_send_close_event(win);
    }
}

static void user_atk_insert(user_atk_window_t *win)
{
    user_atk_windows_lock();
    win->prev = NULL;
    win->next = g_windows_head;
    if (g_windows_head)
    {
        g_windows_head->prev = win;
    }
    g_windows_head = win;
    user_atk_windows_unlock();
}

static void user_atk_remove(user_atk_window_t *win, bool closing_kernel)
{
    if (!win)
    {
        return;
    }
    (void)closing_kernel;

    atk_state_lock_init();
    uint64_t irq_state = atk_state_lock_acquire();
    user_atk_windows_lock();
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

    if (g_focus_window == win)
    {
        g_focus_window = NULL;
    }
    if (g_capture_window == win)
    {
        g_capture_window = NULL;
        g_capture_forced = false;
        g_capture_relative = false;
    }
    user_atk_windows_unlock();

    if (win->window)
    {
        win->destroying = true;
        atk_window_close(atk_state_get(), win->window);
        win->destroying = false;
        atk_dirty_mark_all();
        video_request_refresh();
    }
    atk_state_lock_release(irq_state);

    wait_queue_wake_all(&win->event_waiters);
    user_atk_apply_priorities();
    user_atk_window_release(win);
}

static user_atk_window_t *user_atk_find(uint32_t handle, process_t *owner)
{
    user_atk_windows_lock();
    for (user_atk_window_t *win = g_windows_head; win; win = win->next)
    {
        if (win->handle == handle && win->owner == owner)
        {
            user_atk_window_retain(win);
            user_atk_windows_unlock();
            return win;
        }
    }
    user_atk_windows_unlock();
    return NULL;
}

int64_t user_atk_sys_create(const user_atk_window_desc_t *desc_user)
{
    if (!desc_user)
    {
        return -1;
    }
    user_atk_window_desc_t desc = { 0 };
    if (!user_copy_from_user(&desc, desc_user, sizeof(desc)))
    {
        return -1;
    }

    if (desc.width == 0 || desc.height == 0)
    {
        return -1;
    }
    /* Validate extremely large requests to avoid overflow, but do not tie to screen size. */
    if (desc.width > 16384 || desc.height > 16384)
    {
        return -1;
    }
    desc.title[USER_ATK_TITLE_MAX - 1] = '\0';

    size_t pixel_bytes = (size_t)desc.width * (size_t)desc.height * sizeof(video_color_t);
    video_color_t *front = (video_color_t *)malloc(pixel_bytes);
    if (!front)
    {
        return -1;
    }
    video_color_t *back = (video_color_t *)malloc(pixel_bytes);
    if (!back)
    {
        free(front);
        return -1;
    }
    memset(front, 0, pixel_bytes);
    memset(back, 0, pixel_bytes);

    user_atk_window_t *win = (user_atk_window_t *)calloc(1, sizeof(user_atk_window_t));
    if (!win)
    {
        free(back);
        free(front);
        return -1;
    }

    atk_state_lock_init();
    uint64_t irq_state = atk_state_lock_acquire();
    atk_state_t *state = atk_state_get();
    int screen_w = video_screen_width();
    int screen_h = video_screen_height();
    atk_widget_t *window = atk_window_create_at(state, screen_w / 2, screen_h / 2);
    if (!window)
    {
        atk_state_lock_release(irq_state);
        free(win);
        free(back);
        free(front);
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
        atk_state_lock_release(irq_state);
        free(win);
        free(back);
        free(front);
        return -1;
    }

    user_atk_log("alloc pixels=", (uintptr_t)front);
    user_atk_log("alloc bytes=", pixel_bytes);

    if (!atk_image_set_pixels(image,
                              front,
                              desc.width,
                              desc.height,
                              desc.width * (int)sizeof(video_color_t),
                              false))
    {
        atk_window_close(state, window);
        atk_state_lock_release(irq_state);
        free(win);
        free(back);
        free(front);
        return -1;
    }

    atk_widget_set_layout(image,
                          ATK_WIDGET_ANCHOR_LEFT |
                          ATK_WIDGET_ANCHOR_TOP |
                          ATK_WIDGET_ANCHOR_RIGHT |
                          ATK_WIDGET_ANCHOR_BOTTOM);

    win->handle = g_next_handle++;
    win->flags = desc.flags & USER_ATK_WINDOW_FLAG_RESIZABLE;
    win->refcount = 1;
    win->owner = process_current();
    win->window = window;
    win->image = image;
    win->pixels = atk_image_pixels(image);
    win->back_pixels = back;
    win->pixel_bytes = pixel_bytes;
    win->content_width = desc.width;
    win->content_height = desc.height;
    win->content_offset_x = content_offset_x;
    win->content_offset_y = content_offset_y;
    win->stride_bytes = desc.width * (int)sizeof(video_color_t);
    win->closed = false;
    win->destroying = false;
    spinlock_init(&win->pixel_lock);
    win->event_head = 0;
    win->event_tail = 0;
    win->event_count = 0;
    spinlock_init(&win->event_lock);
    wait_queue_init(&win->event_waiters);

    atk_window_set_context(window, win, user_atk_window_on_destroy);
    user_atk_insert(win);

    atk_window_mark_dirty(window);
    video_request_refresh_window(window);
    user_atk_log("create handle=", win->handle);
    user_atk_focus_window(window);
    atk_state_lock_release(irq_state);
    return (int64_t)win->handle;
}

int64_t user_atk_sys_present(uint32_t handle, const video_color_t *pixels, size_t byte_len)
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
        if (win)
        {
            user_atk_window_release(win);
        }
        return -1;
    }

    spinlock_lock(&win->pixel_lock);
    if (win->closed || !win->pixels)
    {
        spinlock_unlock(&win->pixel_lock);
        user_atk_window_release(win);
        return -1;
    }

#if USER_ATK_DEBUG
    serial_printf("[user_atk][present] handle=0x%016llX bytes=0x%016llX expected=0x%016llX content=%dx%d stride=%d dst=0x%016llX\r\n",
                  (unsigned long long)((uint64_t)handle),
                  (unsigned long long)((uint64_t)byte_len),
                  (unsigned long long)((uint64_t)win->pixel_bytes),
                  win->content_width,
                  win->content_height,
                  win->stride_bytes,
                  (unsigned long long)((uint64_t)(uintptr_t)win->pixels));
#endif


    size_t expected_bytes = win->pixel_bytes;
    size_t copy_bytes = expected_bytes;
    if (byte_len != expected_bytes)
    {
#if USER_ATK_DEBUG
        user_atk_present_log_summary(handle, expected_bytes, byte_len, pixels, win->pixels);
        user_atk_present_log_mismatch(handle, expected_bytes, byte_len);
#endif
        if (byte_len < copy_bytes)
        {
            copy_bytes = byte_len;
        }
    }

    video_color_t *dst = win->back_pixels ? win->back_pixels : win->pixels;
    if (copy_bytes > 0 && !user_copy_from_user(dst, pixels, copy_bytes))
    {
        spinlock_unlock(&win->pixel_lock);
        user_atk_window_release(win);
        return -1;
    }
    if (copy_bytes < expected_bytes)
    {
        size_t remaining = expected_bytes - copy_bytes;
        memset((uint8_t *)dst + copy_bytes, 0, remaining);
    }

    if (win->back_pixels)
    {
        video_color_t *new_front = win->back_pixels;
        win->back_pixels = win->pixels;
        win->pixels = new_front;
    }
    spinlock_unlock(&win->pixel_lock);
    user_atk_log("present dst ptr=", (uintptr_t)win->pixels);
    if (win->window)
    {
        atk_state_lock_init();
        uint64_t irq_state = atk_state_lock_acquire();
        if (win->image && win->pixels)
        {
            atk_image_set_pixels(win->image,
                                 win->pixels,
                                 win->content_width,
                                 win->content_height,
                                 win->stride_bytes,
                                 false);
        }
        atk_window_mark_dirty(win->window);
        video_request_refresh_window(win->window);
        atk_state_lock_release(irq_state);
    }
    else
    {
        video_request_refresh();
    }
    user_atk_window_release(win);
    return 0;
}

int64_t user_atk_sys_poll_event(uint32_t handle, user_atk_event_t *event_out, uint32_t flags)
{
    if (!event_out)
    {
        return -1;
    }
    if (!user_ptr_range_valid(event_out, sizeof(*event_out)))
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
            user_atk_event_t zero = { 0 };
            user_copy_to_user(event_out, &zero, sizeof(zero));
// #if USER_ATK_DEBUG
//             user_atk_log_pair("sys_poll_event empty", handle, flags);
// #endif
            user_atk_window_release(win);
            return 0;
        }
        wait_queue_wait(&win->event_waiters, user_atk_event_ready, win);
    }

    if (!user_copy_to_user(event_out, &event, sizeof(event)))
    {
        user_atk_window_release(win);
        return -1;
    }
#if USER_ATK_DEBUG
    user_atk_log_pair("sys_poll_event", handle, event.type);
#endif
    user_atk_window_release(win);
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
    user_atk_window_release(win);
    return 0;
}

int64_t user_atk_sys_capture(uint32_t handle, uint32_t flags)
{
    user_atk_window_t *win = user_atk_find(handle, process_current());
    if (!win)
    {
        return -1;
    }

    bool enable = (flags & USER_ATK_CAPTURE_ENABLE) != 0;
    bool relative = (flags & USER_ATK_CAPTURE_RELATIVE) != 0;

    user_atk_windows_lock();
    if (enable)
    {
        g_capture_window = win;
        g_capture_forced = true;
        g_capture_relative = relative;
    }
    else if (g_capture_window == win && g_capture_forced)
    {
        g_capture_window = NULL;
        g_capture_forced = false;
        g_capture_relative = false;
    }
    user_atk_windows_unlock();
    user_atk_apply_priorities();
    user_atk_window_release(win);
    return 0;
}

void user_atk_on_process_destroy(process_t *process)
{
    if (!process)
    {
        return;
    }

    while (1)
    {
        user_atk_windows_lock();
        user_atk_window_t *target = NULL;
        for (user_atk_window_t *win = g_windows_head; win; win = win->next)
        {
            if (win->owner == process)
            {
                user_atk_window_retain(win);
                target = win;
                break;
            }
        }
        user_atk_windows_unlock();

        if (!target)
        {
            break;
        }

        user_atk_remove(target, false);
        user_atk_window_release(target);
    }
}

static void user_atk_queue_resize_event(user_atk_window_t *win, uint32_t width, uint32_t height)
{
    if (!win)
    {
        return;
    }

    user_atk_event_t event = {
        .type = USER_ATK_EVENT_RESIZE,
        .flags = 0,
        .x = 0,
        .y = 0,
        .data0 = width,
        .data1 = height
    };
    user_atk_queue_event(win, &event);
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

    spinlock_lock(&win->event_lock);

    if (user_atk_try_coalesce_mouse(win, event))
    {
#if USER_ATK_DEBUG
        user_atk_log_pair("coalesce mouse", win->handle, event->flags);
#endif
        spinlock_unlock(&win->event_lock);
        return;
    }

    if (event->type == USER_ATK_EVENT_RESIZE && win->event_count > 0)
    {
        size_t last = (win->event_tail + USER_ATK_EVENT_QUEUE_MAX - 1) % USER_ATK_EVENT_QUEUE_MAX;
        if (win->events[last].type == USER_ATK_EVENT_RESIZE)
        {
            win->events[last] = *event;
            spinlock_unlock(&win->event_lock);
            wait_queue_wake_one(&win->event_waiters);
            return;
        }
    }

    win->events[win->event_tail] = *event;
    win->event_tail = (win->event_tail + 1) % USER_ATK_EVENT_QUEUE_MAX;
    if (win->event_count == USER_ATK_EVENT_QUEUE_MAX)
    {
        win->event_head = (win->event_head + 1) % USER_ATK_EVENT_QUEUE_MAX;
        win->event_count--;
    }
    win->event_count++;
    spinlock_unlock(&win->event_lock);
    wait_queue_wake_one(&win->event_waiters);
}

static bool user_atk_pop_event(user_atk_window_t *win, user_atk_event_t *out_event)
{
    if (!win)
    {
        return false;
    }

    spinlock_lock(&win->event_lock);
    if (win->event_count == 0)
    {
        spinlock_unlock(&win->event_lock);
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
    spinlock_unlock(&win->event_lock);
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

static bool user_atk_event_ready(void *context)
{
    user_atk_window_t *win = (user_atk_window_t *)context;
    if (!win)
    {
        return false;
    }
    spinlock_lock(&win->event_lock);
    bool ready = (win->event_count > 0);
    spinlock_unlock(&win->event_lock);
    return ready;
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
    uint32_t relative_mask = USER_ATK_MOUSE_FLAG_RELATIVE;
    if ((event->flags & relative_mask) != (last->flags & relative_mask))
    {
        return false;
    }

    last->x = event->x;
    last->y = event->y;
    last->flags = event->flags;
    int32_t accum_dx = (int32_t)last->data0 + (int32_t)event->data0;
    int32_t accum_dy = (int32_t)last->data1 + (int32_t)event->data1;
    last->data0 = (uint32_t)accum_dx;
    last->data1 = (uint32_t)accum_dy;
    return true;
}

static void user_atk_apply_priorities(void)
{
    user_atk_windows_lock();
    if (g_focus_window && g_focus_window->closed)
    {
        g_focus_window = NULL;
    }
    if (g_capture_window && g_capture_window->closed)
    {
        g_capture_window = NULL;
    }

    process_t *focus_owner = g_focus_window ? g_focus_window->owner : NULL;
    process_t *capture_owner = g_capture_window ? g_capture_window->owner : NULL;

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
    user_atk_windows_unlock();
}
