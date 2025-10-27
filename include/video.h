#ifndef VIDEO_H
#define VIDEO_H

#include "types.h"

void video_init(void);
bool video_enter_mode(void);
void video_run_loop(void);
void video_exit_mode(void);
void video_on_mouse_event(int dx, int dy, bool left_pressed);

#endif
