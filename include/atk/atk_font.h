#ifndef ATK_FONT_H
#define ATK_FONT_H

#include "types.h"
#include "video.h"

typedef struct atk_rect atk_rect_t;

/*
 * Return true if a font is available for ATK text rendering.
 *
 * In kernel builds this typically reflects whether the TTF/font system was
 * initialized successfully.
 */
bool atk_font_available(void);

/* Return the pixel width of a UTF-8 string when drawn with the current font. */
int atk_font_text_width(const char *text);

/*
 * Compute a baseline Y coordinate for drawing text inside a rectangle.
 *
 * `top`/`height` describe the rectangle. The returned baseline is suitable for
 * `atk_font_draw_string*`.
 */
int atk_font_baseline_for_rect(int top, int height);

/* Return the pixel height of a single line of text. */
int atk_font_line_height(void);

/*
 * Draw a string at (x, baseline_y).
 *
 * `fg` and `bg` are colors used by the renderer; background is used for any
 * glyph blending/clipping behavior.
 */
void atk_font_draw_string(int x, int baseline_y, const char *text, video_color_t fg, video_color_t bg);

/*
 * Draw a string clipped to `clip`.
 *
 * This is the preferred API for drawing inside widgets to avoid overdraw
 * outside bounds.
 */
void atk_font_draw_string_clipped(int x,
                                  int baseline_y,
                                  const char *text,
                                  video_color_t fg,
                                  video_color_t bg,
                                  const atk_rect_t *clip);

#endif
