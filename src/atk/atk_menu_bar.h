#ifndef ATK_MENU_BAR_H
#define ATK_MENU_BAR_H

#include "atk_internal.h"

void atk_menu_bar_reset(atk_state_t *state);
void atk_menu_bar_build_default(atk_state_t *state);
void atk_menu_bar_enable_clock_timer(void);
void atk_menu_bar_draw(const atk_state_t *state);
bool atk_menu_bar_handle_mouse(atk_state_t *state,
                               int cursor_x,
                               int cursor_y,
                               bool pressed_edge,
                               bool released_edge,
                               bool left_pressed,
                               bool *redraw_out);

#endif
