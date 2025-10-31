#ifndef ATK_BUTTON_H
#define ATK_BUTTON_H

#include "atk_internal.h"

void atk_button_configure(atk_widget_t *widget,
                          const char *title,
                          atk_button_style_t style,
                          bool draggable,
                          bool absolute,
                          atk_button_action_t action,
                          void *context);
int atk_button_effective_height(const atk_widget_t *widget);
bool atk_button_hit_test(const atk_widget_t *widget, int origin_x, int origin_y, int px, int py);
void atk_button_draw(const atk_state_t *state, const atk_widget_t *widget, int origin_x, int origin_y);
const char *atk_button_title(const atk_widget_t *widget);
bool atk_button_is_draggable(const atk_widget_t *widget);
bool atk_button_is_absolute(const atk_widget_t *widget);
void atk_button_invoke(atk_widget_t *widget);

#endif
