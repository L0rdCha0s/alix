#include "atk_user.h"

#include "libc.h"
#include "usyscall.h"
#include "video_surface.h"
#include "serial.h"

#ifndef ATK_USER_TRACE
#define ATK_USER_TRACE 0
#endif

static bool atk_user_window_open_internal(atk_user_window_t *win,
                                          const char *title,
                                          uint32_t width,
                                          uint32_t height,
                                          uint32_t flags);
static void atk_user_handle_resize_event(atk_user_window_t *win, const user_atk_event_t *event);

#if ATK_USER_TRACE
static void atk_user_trace(const char *msg, uint64_t a, uint64_t b)
{
    serial_printf("%s", "[atk_user] ");
    serial_printf("%s", msg);
    serial_printf("%s", " a=0x");
    serial_printf("%016llX", (unsigned long long)(a));
    serial_printf("%s", " b=0x");
    serial_printf("%016llX", (unsigned long long)(b));
    serial_printf("%s", "\r\n");
}
#else
#define atk_user_trace(msg, a, b) (void)0
#endif

static bool atk_user_present_common(const atk_user_window_t *win, bool force_present)
{
    if (!win || win->handle == 0 || !win->buffer)
    {
        return false;
    }

    bool dirty = video_surface_consume_dirty();
    if (win->track_dirty && !force_present && !dirty)
    {
        atk_user_trace("present_skip", win->handle, 0);
        return true;
    }

    atk_user_trace(force_present ? "present_force" : "present", win->handle, win->buffer_bytes);
    bool ok = (sys_ui_present(win->handle, win->buffer, win->buffer_bytes) == 0);
    if (!ok && dirty)
    {
        video_surface_force_dirty();
    }
    return ok;
}

bool atk_user_window_open(atk_user_window_t *win, const char *title, uint32_t width, uint32_t height)
{
    return atk_user_window_open_with_flags(win, title, width, height, 0);
}

bool atk_user_window_open_with_flags(atk_user_window_t *win,
                                     const char *title,
                                     uint32_t width,
                                     uint32_t height,
                                     uint32_t flags)
{
    return atk_user_window_open_internal(win, title, width, height, flags);
}

bool atk_user_present(const atk_user_window_t *win)
{
    return atk_user_present_common(win, false);
}

bool atk_user_present_force(const atk_user_window_t *win)
{
    return atk_user_present_common(win, true);
}

void atk_user_enable_dirty_tracking(atk_user_window_t *win, bool enable)
{
    if (!win)
    {
        return;
    }
    win->track_dirty = enable;
    video_surface_set_tracking(enable);
    if (enable)
    {
        video_surface_force_dirty();
    }
}

bool atk_user_wait_event(atk_user_window_t *win, user_atk_event_t *event)
{
    if (!win || !event)
    {
        return false;
    }
    bool ok = sys_ui_poll_event(win->handle, event, USER_ATK_POLL_FLAG_BLOCK) == 1;
#if ATK_USER_TRACE
    if (ok)
    {
        atk_user_trace("wait_event type", event->type, ((uint64_t)(uint32_t)event->x << 32) | (uint32_t)(event->y & 0xFFFFFFFFu));
    }
    else
    {
        atk_user_trace("wait_event empty", win->handle, 0);
    }
#endif
    if (ok && event->type == USER_ATK_EVENT_RESIZE)
    {
        atk_user_handle_resize_event(win, event);
    }
    return ok;
}

bool atk_user_poll_event(atk_user_window_t *win, user_atk_event_t *event)
{
    if (!win || !event)
    {
        return false;
    }
    bool ok = sys_ui_poll_event(win->handle, event, 0u) == 1;
#if ATK_USER_TRACE
    if (ok)
    {
        atk_user_trace("poll_event type", event->type, ((uint64_t)(uint32_t)event->x << 32) | (uint32_t)(event->y & 0xFFFFFFFFu));
    }
#endif
    if (ok && event->type == USER_ATK_EVENT_RESIZE)
    {
        atk_user_handle_resize_event(win, event);
    }
    return ok;
}

void atk_user_close(atk_user_window_t *win)
{
    if (!win)
    {
        return;
    }
    if (win->handle)
    {
        sys_ui_close(win->handle);
        win->handle = 0;
    }
    if (win->buffer)
    {
        video_surface_detach();
        free(win->buffer);
        win->buffer = NULL;
    }
    win->buffer_bytes = 0;
    win->width = 0;
    win->height = 0;
    win->track_dirty = false;
}

static bool atk_user_window_open_internal(atk_user_window_t *win,
                                          const char *title,
                                          uint32_t width,
                                          uint32_t height,
                                          uint32_t flags)
{
    if (!win || width == 0 || height == 0)
    {
        return false;
    }

    user_atk_window_desc_t desc = {
        .width = width,
        .height = height,
        .flags = flags,
    };
    if (title)
    {
        size_t len = strlen(title);
        if (len >= USER_ATK_TITLE_MAX)
        {
            len = USER_ATK_TITLE_MAX - 1;
        }
        memcpy(desc.title, title, len);
        desc.title[len] = '\0';
    }

    int handle = sys_ui_create(&desc);
    if (handle < 0)
    {
        return false;
    }

    size_t bytes = (size_t)width * (size_t)height * sizeof(video_color_t);
    video_color_t *buffer = (video_color_t *)malloc(bytes);
    if (!buffer)
    {
        sys_ui_close((uint32_t)handle);
        return false;
    }
    memset(buffer, 0, bytes);

    win->handle = (uint32_t)handle;
    win->buffer = buffer;
    win->buffer_bytes = bytes;
    win->width = width;
    win->height = height;
    win->track_dirty = false;

    video_surface_attach(buffer, width, height);
    video_surface_set_tracking(false);
    atk_user_trace("window_open handle", win->handle, (uintptr_t)buffer);
    return true;
}

static void atk_user_handle_resize_event(atk_user_window_t *win, const user_atk_event_t *event)
{
    if (!win || !event || event->type != USER_ATK_EVENT_RESIZE)
    {
        return;
    }
    uint32_t width = event->data0;
    uint32_t height = event->data1;
    if (width == 0 || height == 0)
    {
        return;
    }

    size_t bytes = (size_t)width * (size_t)height * sizeof(video_color_t);
    video_color_t *buffer = (video_color_t *)realloc(win->buffer, bytes);
    if (!buffer)
    {
        buffer = (video_color_t *)malloc(bytes);
        if (!buffer)
        {
            return;
        }
        if (win->buffer)
        {
            size_t copy = win->buffer_bytes < bytes ? win->buffer_bytes : bytes;
            memcpy(buffer, win->buffer, copy);
            free(win->buffer);
        }
    }
    memset(buffer, 0, bytes);

    video_surface_detach();
    win->buffer = buffer;
    win->buffer_bytes = bytes;
    win->width = width;
    win->height = height;
    video_surface_attach(buffer, width, height);
    video_surface_set_tracking(win->track_dirty);
    video_surface_force_dirty();
    atk_user_trace("window_resize handle", win->handle, ((uint64_t)width << 32) | height);
}
