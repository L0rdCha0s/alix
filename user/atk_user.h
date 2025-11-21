#ifndef USER_ATK_USER_H
#define USER_ATK_USER_H

#include "types.h"
#include "user_atk_defs.h"
#include "video.h"
#include <stdbool.h>

typedef struct
{
    uint32_t handle;
    video_color_t *buffer;
    size_t buffer_bytes;
    uint32_t width;
    uint32_t height;
    bool track_dirty;
} atk_user_window_t;

bool atk_user_window_open(atk_user_window_t *win, const char *title, uint32_t width, uint32_t height);
bool atk_user_window_open_with_flags(atk_user_window_t *win,
                                     const char *title,
                                     uint32_t width,
                                     uint32_t height,
                                     uint32_t flags);
bool atk_user_present(const atk_user_window_t *win);
bool atk_user_present_force(const atk_user_window_t *win);
void atk_user_enable_dirty_tracking(atk_user_window_t *win, bool enable);
bool atk_user_wait_event(atk_user_window_t *win, user_atk_event_t *event);
bool atk_user_poll_event(atk_user_window_t *win, user_atk_event_t *event);
void atk_user_close(atk_user_window_t *win);

#endif /* USER_ATK_USER_H */
