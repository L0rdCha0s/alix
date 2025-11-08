#ifndef VIDEO_H
#define VIDEO_H

#include "types.h"

#ifndef VIDEO_WIDTH
#define VIDEO_WIDTH  1280
#endif
#ifndef VIDEO_HEIGHT
#define VIDEO_HEIGHT 1024
#endif

struct atk_widget;

void video_init(void);
bool video_enter_mode(void);
void video_run_loop(void);
void video_exit_mode(void);
void video_on_mouse_event(int dx, int dy, bool left_pressed);

uint16_t video_make_color(uint8_t r, uint8_t g, uint8_t b);
void video_fill(uint16_t color);
void video_draw_rect(int x, int y, int width, int height, uint16_t color);
void video_draw_rect_outline(int x, int y, int width, int height, uint16_t color);
void video_draw_text(int x, int y, const char *text, uint16_t fg, uint16_t bg);
void video_draw_text_clipped(int x, int y, int width, int height,
                             const char *text, uint16_t fg, uint16_t bg);
void video_invalidate_rect(int x, int y, int width, int height);
void video_invalidate_all(void);
void video_blit_rgb565(int x, int y, int width, int height, const uint16_t *pixels, int stride_bytes);
bool video_is_active(void);
void video_request_refresh(void);
void video_request_refresh_window(struct atk_widget *window);
void video_pump_events(void);


#endif
