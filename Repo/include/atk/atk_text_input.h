#ifndef ATK_TEXT_INPUT_H
#define ATK_TEXT_INPUT_H

#include "atk/object.h"
#include "types.h"

struct atk_state;

typedef void (*atk_text_input_submit_t)(atk_widget_t *input, void *context);

/*
 * Create a single-line text input widget as a child of `window`.
 *
 * Height is derived from the current font line height. The input registers
 * itself with the window so focus traversal and dispatch can find it.
 */
atk_widget_t *atk_window_add_text_input(atk_widget_t *window, int x, int y, int width);

/*
 * Set a callback invoked when the user submits (presses Enter).
 *
 * The callback is invoked from the ATK event path; keep it fast.
 */
void atk_text_input_set_submit_handler(atk_widget_t *input, atk_text_input_submit_t handler, void *context);

/* Return the current input text buffer (always non-NULL). */
const char *atk_text_input_text(const atk_widget_t *input);

/* Clear the input text and mark the widget area dirty. */
void atk_text_input_clear(atk_widget_t *input);

/* Replace the input text and mark the widget area dirty. */
void atk_text_input_set_text(atk_widget_t *input, const char *text);

/*
 * Hit test a text input against an absolute point.
 *
 * `origin_x`/`origin_y` are the absolute parent origin.
 */
bool atk_text_input_hit_test(const atk_widget_t *input, int origin_x, int origin_y, int px, int py);

/* Return whether this input is currently focused. */
bool atk_text_input_is_focused(const atk_widget_t *input);

/*
 * Focus this text input.
 *
 * This updates `state->focus_widget`, clears focus from any previously focused
 * text input, and marks affected widgets dirty.
 */
void atk_text_input_focus(struct atk_state *state, atk_widget_t *input);

/* Clear focus from this text input (equivalent to focusing NULL). */
void atk_text_input_blur(struct atk_state *state, atk_widget_t *input);

/* Mark the widget dirty without mutating text/focus state. */
void atk_text_input_request_redraw(atk_widget_t *input);

typedef enum
{
    ATK_TEXT_INPUT_EVENT_NONE = 0,
    ATK_TEXT_INPUT_EVENT_CHANGED = 1,
    ATK_TEXT_INPUT_EVENT_SUBMIT = 2
} atk_text_input_event_t;

/*
 * Handle a typed character for a focused text input.
 *
 * Returns an event describing whether text changed or a submit occurred. This
 * function updates the widget state and marks it dirty when needed.
 */
atk_text_input_event_t atk_text_input_handle_char(atk_widget_t *input, char ch);

/* Draw the text input widget into the current backbuffer. */
void atk_text_input_draw(const struct atk_state *state, const atk_widget_t *input);

/* Destroy resources owned by the text input (text buffer). */
void atk_text_input_destroy(atk_widget_t *input);

#endif
