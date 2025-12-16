#ifndef ATK_TERMINAL_H
#define ATK_TERMINAL_H

#include "atk/object.h"

#ifdef __cplusplus
extern "C" {
#endif

struct atk_state;

typedef void (*atk_terminal_submit_t)(atk_widget_t *terminal, void *context, const char *line);
typedef bool (*atk_terminal_control_t)(atk_widget_t *terminal, void *context, char control);

#define ATK_TERMINAL_SCROLLBAR_WIDTH 14

/*
 * Create a terminal widget as a child of `window`.
 *
 * The terminal provides a scrollback view plus a single-line input prompt. It
 * is primarily used by userland ATK apps (e.g., the graphical shell).
 */
atk_widget_t *atk_window_add_terminal(atk_widget_t *window, int x, int y, int width, int height);

/* Clear scrollback and input state, returning the terminal to an empty prompt. */
void atk_terminal_reset(atk_widget_t *terminal);

/* Append `len` bytes of text to the scrollback buffer and mark the widget dirty. */
void atk_terminal_write(atk_widget_t *terminal, const char *data, size_t len);

/*
 * Handle a typed character for terminal input.
 *
 * Returns true if the terminal state changed and needs a redraw.
 */
bool atk_terminal_handle_char(atk_widget_t *terminal, char ch);

/*
 * Set a callback invoked when the user submits a line (Enter).
 *
 * The callback is invoked from the ATK event path; keep it fast.
 */
void atk_terminal_set_submit_handler(atk_widget_t *terminal, atk_terminal_submit_t handler, void *context);

/*
 * Set a callback invoked for control characters (e.g., Ctrl+C).
 *
 * Return true from the callback to indicate the control was consumed.
 */
void atk_terminal_set_control_handler(atk_widget_t *terminal, atk_terminal_control_t handler, void *context);

/* Clear the current input line without affecting scrollback. */
void atk_terminal_clear_input(atk_widget_t *terminal);

/*
 * Copy the current input line into `buffer`.
 *
 * Returns the number of bytes written (excluding the terminating NUL). If
 * `cursor_out` is non-NULL, it receives the current cursor position.
 */
size_t atk_terminal_get_input(const atk_widget_t *terminal, char *buffer, size_t capacity, size_t *cursor_out);

/*
 * Replace the current input line and cursor position.
 *
 * `cursor` is clamped to the new string length.
 */
void atk_terminal_set_input(atk_widget_t *terminal, const char *text, size_t cursor);

/*
 * Focus this terminal, making it eligible to receive key events.
 *
 * This updates `state->focus_widget` and marks the widget dirty as needed.
 */
void atk_terminal_focus(struct atk_state *state, atk_widget_t *terminal);

/* Return true if `terminal` is the currently focused widget. */
bool atk_terminal_is_focused(const struct atk_state *state, const atk_widget_t *terminal);

/* Mark the terminal area dirty without mutating terminal state. */
void atk_terminal_mark_dirty(atk_widget_t *terminal);

/* Return terminal grid dimensions (rows/cols) derived from pixel size and font metrics. */
void atk_terminal_get_dimensions(const atk_widget_t *terminal, int *rows, int *cols);

/* Draw the terminal into the current backbuffer. */
void atk_terminal_draw(const struct atk_state *state, const atk_widget_t *terminal);

/* Destroy resources owned by the terminal widget. */
void atk_terminal_destroy(atk_widget_t *terminal);
#ifndef KERNEL_BUILD
/*
 * Handle resize/layout changes for a terminal embedded in a userland window.
 *
 * This recalculates internal buffers based on the current widget size.
 */
bool atk_terminal_handle_resize(atk_widget_t *terminal);
#endif

extern const atk_class_t ATK_TERMINAL_CLASS;

#ifdef __cplusplus
}
#endif

#endif
