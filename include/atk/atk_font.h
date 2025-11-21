#ifndef ATK_FONT_H
#define ATK_FONT_H

#include "types.h"
#include "video.h"

typedef struct atk_rect atk_rect_t;

bool atk_font_available(void);
int atk_font_text_width(const char *text);
int atk_font_baseline_for_rect(int top, int height);
int atk_font_line_height(void);
void atk_font_draw_string(int x, int baseline_y, const char *text, video_color_t fg, video_color_t bg);
void atk_font_draw_string_clipped(int x,
                                  int baseline_y,
                                  const char *text,
                                  video_color_t fg,
                                  video_color_t bg,
                                  const atk_rect_t *clip);

#endif
