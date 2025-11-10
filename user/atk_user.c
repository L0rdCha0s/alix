#include "atk_user.h"

#include "libc.h"
#include "usyscall.h"
#include "video_surface.h"

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
    return true;
}

bool atk_user_present(const atk_user_window_t *win)
{
    if (!win || win->handle == 0 || !win->buffer)
    {
        return false;
    }
    return sys_ui_present(win->handle, win->buffer, win->buffer_bytes) == 0;
}

bool atk_user_wait_event(const atk_user_window_t *win, user_atk_event_t *event)
{
    if (!win || !event)
    {
        return false;
    }
    return sys_ui_poll_event(win->handle, event, USER_ATK_POLL_FLAG_BLOCK) == 1;
}

bool atk_user_poll_event(const atk_user_window_t *win, user_atk_event_t *event)
{
    if (!win || !event)
    {
        return false;
    }
    return sys_ui_poll_event(win->handle, event, 0u) == 1;
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
