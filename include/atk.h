#ifndef ATK_H
#define ATK_H

#include "types.h"

typedef struct
{
    bool redraw;
    bool exit_video;
} atk_mouse_event_result_t;

typedef struct
{
    bool redraw;
    bool exit_video;
} atk_key_event_result_t;

void atk_init(void);
void atk_enter_mode(void);
void atk_render(void);
atk_mouse_event_result_t atk_handle_mouse_event(int cursor_x, int cursor_y, bool pressed_edge, bool released_edge, bool left_pressed);
atk_key_event_result_t atk_handle_key_char(char ch);

#endif
