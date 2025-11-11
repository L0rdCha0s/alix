#include "atk_user.h"

#include "libc.h"
#include "usyscall.h"
#include "video_surface.h"
#include "serial.h"

#ifndef ATK_USER_TRACE
#define ATK_USER_TRACE 0
#endif

#if ATK_USER_TRACE
static void atk_user_trace(const char *msg, uint64_t a, uint64_t b)
{
    serial_write_string("[atk_user] ");
    serial_write_string(msg);
    serial_write_string(" a=0x");
    serial_write_hex64(a);
    serial_write_string(" b=0x");
    serial_write_hex64(b);
    serial_write_string("\r\n");
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
    if (!force_present && !dirty)
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
    if (!win || width == 0 || height == 0)
    {
        return false;
    }

    user_atk_window_desc_t desc = {
        .width = width,
        .height = height,
        .flags = 0,
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

    size_t bytes = (size_t)width * (size_t)height * sizeof(uint16_t);
    uint16_t *buffer = (uint16_t *)malloc(bytes);
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

    video_surface_attach(buffer, width, height);
    atk_user_trace("window_open handle", win->handle, (uintptr_t)buffer);
    return true;
}

bool atk_user_present(const atk_user_window_t *win)
{
    return atk_user_present_common(win, false);
}

bool atk_user_present_force(const atk_user_window_t *win)
{
    return atk_user_present_common(win, true);
}

bool atk_user_wait_event(const atk_user_window_t *win, user_atk_event_t *event)
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
    return ok;
}

bool atk_user_poll_event(const atk_user_window_t *win, user_atk_event_t *event)
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
}
