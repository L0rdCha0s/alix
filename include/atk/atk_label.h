#ifndef ATK_LABEL_H
#define ATK_LABEL_H

#include "atk/object.h"
#include "types.h"
#include <stddef.h>

struct atk_state;

atk_widget_t *atk_window_add_label(atk_widget_t *window, int x, int y, int width, int height);
void atk_label_set_text(atk_widget_t *label, const char *text);
void atk_label_append_text(atk_widget_t *label, const char *text);
const char *atk_label_text(const atk_widget_t *label);
void atk_label_scroll_to_line(atk_widget_t *label, size_t line);
void atk_label_scroll_to_bottom(atk_widget_t *label);
void atk_label_draw(const struct atk_state *state, const atk_widget_t *label);
void atk_label_destroy(atk_widget_t *label);

#endif
