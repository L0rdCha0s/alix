#include "user_atk_host.h"

#include "atk/object.h"

void user_atk_init(void) {}
void user_atk_on_process_destroy(struct process *process)
{
    (void)process;
}

bool user_atk_window_is_remote(const atk_widget_t *window)
{
    (void)window;
    return false;
}

bool user_atk_window_is_resizable(const atk_widget_t *window)
{
    (void)window;
    return false;
}

void user_atk_focus_window(const atk_widget_t *window)
{
    (void)window;
}

bool user_atk_route_mouse_event(const atk_widget_t *hover_window,
                                int cursor_x,
                                int cursor_y,
                                bool pressed_edge,
                                bool released_edge,
                                bool left_pressed)
{
    (void)hover_window;
    (void)cursor_x;
    (void)cursor_y;
    (void)pressed_edge;
    (void)released_edge;
    (void)left_pressed;
    return false;
}

bool user_atk_route_key_event(char ch)
{
    (void)ch;
    return false;
}

void user_atk_window_resized(const atk_widget_t *window)
{
    (void)window;
}

int64_t user_atk_sys_create(const user_atk_window_desc_t *desc)
{
    (void)desc;
    return -1;
}

int64_t user_atk_sys_present(uint32_t handle, const video_color_t *pixels, size_t byte_len)
{
    (void)handle;
    (void)pixels;
    (void)byte_len;
    return -1;
}

int64_t user_atk_sys_poll_event(uint32_t handle, user_atk_event_t *event_out, uint32_t flags)
{
    (void)handle;
    (void)event_out;
    (void)flags;
    return -1;
}

int64_t user_atk_sys_close(uint32_t handle)
{
    (void)handle;
    return -1;
}
