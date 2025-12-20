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

/*
 * Create a remote ATK window owned by the calling process.
 *
 * On success this allocates a RGB565 pixel buffer (`win->buffer`) sized
 * `width × height`, attaches it as the active userland video surface, and fills
 * out `win` with the kernel-provided window handle and dimensions.
 */
bool atk_user_window_open(atk_user_window_t *win, const char *title, uint32_t width, uint32_t height);

/*
 * Create a remote ATK window with explicit `flags`.
 *
 * `flags` are passed through to the kernel's `SYSCALL_UI_CREATE` path.
 */
bool atk_user_window_open_with_flags(atk_user_window_t *win,
                                     const char *title,
                                     uint32_t width,
                                     uint32_t height,
                                     uint32_t flags);

/*
 * Present the current pixel buffer to the kernel window.
 *
 * When dirty tracking is enabled via `atk_user_enable_dirty_tracking()`, this is
 * a no-op if no pixels were marked dirty since the last present.
 */
bool atk_user_present(const atk_user_window_t *win);

/*
 * Present the current pixel buffer to the kernel window, even if no dirty pixels
 * were reported.
 */
bool atk_user_present_force(const atk_user_window_t *win);

/*
 * Enable or disable userland dirty tracking for `win`.
 *
 * When enabled, ATK/video surface drawing marks a dirty bit that allows
 * `atk_user_present()` to skip redundant uploads. Enabling forces an initial
 * dirty mark so the next present uploads the whole buffer once.
 */
void atk_user_enable_dirty_tracking(atk_user_window_t *win, bool enable);

/*
 * Block until an event is available for `win`.
 *
 * Returns true and fills `event` on success. `USER_ATK_EVENT_RESIZE` is handled
 * internally by reallocating `win->buffer` and re-attaching the video surface
 * before returning the event to the caller.
 */
bool atk_user_wait_event(atk_user_window_t *win, user_atk_event_t *event);

/*
 * Block until an event is available for `win` or `timeout_ms` elapses.
 *
 * Returns true when an event was dequeued; returns false on timeout or error.
 */
bool atk_user_wait_event_timeout(atk_user_window_t *win, user_atk_event_t *event, uint32_t timeout_ms);

/*
 * Poll for the next event without blocking.
 *
 * Returns true and fills `event` when an event was dequeued; returns false when
 * the queue is empty (or on error).
 */
bool atk_user_poll_event(atk_user_window_t *win, user_atk_event_t *event);

/*
 * Close a remote window and release its backing buffer.
 *
 * Safe to call multiple times. This also detaches the userland video surface if
 * it is currently bound to `win`.
 */
void atk_user_close(atk_user_window_t *win);

/*
 * Request or release mouse capture for a window.
 *
 * When `relative` is true and capture is enabled, mouse events include
 * raw deltas via USER_ATK_MOUSE_FLAG_RELATIVE.
 */
bool atk_user_set_mouse_capture(atk_user_window_t *win, bool enable, bool relative);

#endif /* USER_ATK_USER_H */
