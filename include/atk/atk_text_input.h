#ifndef ATK_TEXT_INPUT_H
#define ATK_TEXT_INPUT_H

#include "atk/object.h"
#include "types.h"

struct atk_state;

typedef void (*atk_text_input_submit_t)(atk_widget_t *input, void *context);

atk_widget_t *atk_window_add_text_input(atk_widget_t *window, int x, int y, int width);
void atk_text_input_set_submit_handler(atk_widget_t *input, atk_text_input_submit_t handler, void *context);
const char *atk_text_input_text(const atk_widget_t *input);
void atk_text_input_clear(atk_widget_t *input);
bool atk_text_input_hit_test(const atk_widget_t *input, int origin_x, int origin_y, int px, int py);
bool atk_text_input_is_focused(const atk_widget_t *input);
void atk_text_input_focus(struct atk_state *state, atk_widget_t *input);
void atk_text_input_blur(struct atk_state *state, atk_widget_t *input);
void atk_text_input_request_redraw(atk_widget_t *input);

typedef enum
{
    ATK_TEXT_INPUT_EVENT_NONE = 0,
    ATK_TEXT_INPUT_EVENT_CHANGED = 1,
    ATK_TEXT_INPUT_EVENT_SUBMIT = 2
} atk_text_input_event_t;

atk_text_input_event_t atk_text_input_handle_char(atk_widget_t *input, char ch);
void atk_text_input_draw(const struct atk_state *state, const atk_widget_t *input);
void atk_text_input_destroy(atk_widget_t *input);

#endif
