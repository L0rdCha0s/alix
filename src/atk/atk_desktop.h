#ifndef ATK_DESKTOP_H
#define ATK_DESKTOP_H

#include "atk_button.h"

void atk_desktop_reset(atk_state_t *state);
void atk_desktop_draw_buttons(const atk_state_t *state);
atk_widget_t *atk_desktop_add_button(atk_state_t *state,
                                     int x,
                                     int y,
                                     int width,
                                     int height,
                                     const char *title,
                                     atk_button_style_t style,
                                     bool draggable,
                                     atk_button_action_t action,
                                     void *context);
atk_widget_t *atk_desktop_button_hit_test(const atk_state_t *state, int px, int py);

#endif
