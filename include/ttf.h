#ifndef TTF_H
#define TTF_H

#include "types.h"

typedef struct ttf_font
{
    void *impl;
} ttf_font_t;

typedef struct
{
    int ascent;
    int descent;
    int line_gap;
} ttf_font_metrics_t;

typedef struct
{
    int width;
    int height;
    int stride;
    int offset_x;
    int offset_y;
    uint8_t *pixels;
} ttf_bitmap_t;

typedef struct
{
    int advance;
    int bearing_x;
    int bearing_y;
    int width;
    int height;
} ttf_glyph_metrics_t;

bool ttf_font_load(ttf_font_t *font, const uint8_t *data, size_t size);
void ttf_font_unload(ttf_font_t *font);

bool ttf_font_metrics(const ttf_font_t *font, int pixel_height, ttf_font_metrics_t *out_metrics);
uint16_t ttf_font_lookup_glyph(const ttf_font_t *font, uint32_t codepoint);

bool ttf_font_render_glyph_bitmap(const ttf_font_t *font,
                                  uint32_t codepoint,
                                  int pixel_height,
                                  ttf_bitmap_t *out_bitmap,
                                  ttf_glyph_metrics_t *out_metrics);

void ttf_bitmap_destroy(ttf_bitmap_t *bitmap);

#endif /* TTF_H */
