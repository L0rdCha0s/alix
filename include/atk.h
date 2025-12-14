#ifndef ATK_H
#define ATK_H

#include "types.h"

/*
 * Result from `atk_handle_mouse_event()`.
 *
 * - `redraw`: ATK mutated visual state; caller should schedule a render/flush.
 * - `exit_video`: ATK requested leaving video mode (kernel video shell only).
 */
typedef struct
{
    bool redraw;
    bool exit_video;
} atk_mouse_event_result_t;

/*
 * Result from `atk_handle_key_char()`.
 *
 * - `redraw`: ATK mutated visual state; caller should schedule a render/flush.
 * - `exit_video`: ATK requested leaving video mode (kernel video shell only).
 */
typedef struct
{
    bool redraw;
    bool exit_video;
} atk_key_event_result_t;

/*
 * Initialize ATK global state.
 *
 * Call once during boot before any other ATK API. This sets up internal state,
 * widget classes, and desktop defaults.
 */
void atk_init(void);

/*
 * Enter ATK "video mode".
 *
 * This resets per-session UI state (desktop/menu/windows) and marks the whole
 * scene dirty. Typical kernel usage is:
 *   `atk_enter_mode(); atk_render(); video_flush_dirty();`
 */
void atk_enter_mode(void);

/*
 * Render the current dirty region into the backing surface (backbuffer).
 *
 * ATK uses a "dirty rect" model; if nothing is dirty, this is a no-op. Callers
 * are responsible for flushing the backbuffer to the real framebuffer (kernel)
 * or presenting it to the host window (userland).
 */
void atk_render(void);

/*
 * Feed an absolute mouse event into ATK.
 *
 * Coordinates are in screen space. `pressed_edge`/`released_edge` indicate
 * button transitions for the current frame; `left_pressed` is the current state.
 * ATK handles window chrome, menu bar interactions, mouse capture, and widget
 * dispatch. If `result.redraw` is true, call `atk_render()` then present/flush.
 */
atk_mouse_event_result_t atk_handle_mouse_event(int cursor_x, int cursor_y, bool pressed_edge, bool released_edge, bool left_pressed);

/*
 * Feed a typed character into ATK.
 *
 * This is intended for text input and simple UI shortcuts. If `result.redraw`
 * is true, call `atk_render()` then present/flush.
 */
atk_key_event_result_t atk_handle_key_char(char ch);

/*
 * Query whether ATK is currently in a window-drag operation.
 *
 * Used by the kernel video driver to avoid fighting the drag compositor path.
 */
bool atk_drag_active(void);

#endif
