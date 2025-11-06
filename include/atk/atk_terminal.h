#ifndef ATK_TERMINAL_H
#define ATK_TERMINAL_H

#include "atk/object.h"

#ifdef __cplusplus
extern "C" {
#endif

struct atk_state;

typedef void (*atk_terminal_submit_t)(atk_widget_t *terminal, void *context, const char *line);

atk_widget_t *atk_window_add_terminal(atk_widget_t *window, int x, int y, int width, int height);
void atk_terminal_reset(atk_widget_t *terminal);
void atk_terminal_write(atk_widget_t *terminal, const char *data, size_t len);
bool atk_terminal_handle_char(atk_widget_t *terminal, char ch);
void atk_terminal_set_submit_handler(atk_widget_t *terminal, atk_terminal_submit_t handler, void *context);
void atk_terminal_focus(struct atk_state *state, atk_widget_t *terminal);
bool atk_terminal_is_focused(const struct atk_state *state, const atk_widget_t *terminal);
void atk_terminal_mark_dirty(atk_widget_t *terminal);
void atk_terminal_get_dimensions(const atk_widget_t *terminal, int *rows, int *cols);
void atk_terminal_draw(const struct atk_state *state, const atk_widget_t *terminal);
void atk_terminal_destroy(atk_widget_t *terminal);

extern const atk_class_t ATK_TERMINAL_CLASS;

#ifdef __cplusplus
}
#endif

#endif
