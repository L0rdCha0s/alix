#ifndef ATK_LAYOUT_H
#define ATK_LAYOUT_H

#include "types.h"

typedef struct
{
    int x;
    int y;
    int width;
    int height;
    int padding_left;
    int padding_top;
    int padding_right;
    int padding_bottom;
} atk_layout_t;

typedef struct
{
    int x;
    int y;
    int width;
    int height;
} atk_layout_region_t;

static inline atk_layout_region_t atk_layout_region_make(int x, int y, int width, int height)
{
    atk_layout_region_t region = { x, y, width, height };
    return region;
}

void atk_layout_init(atk_layout_t *layout, int x, int y, int width, int height);
void atk_layout_set_padding(atk_layout_t *layout, int left, int top, int right, int bottom);
atk_layout_region_t atk_layout_take_top(atk_layout_t *layout, int height, int spacing);
atk_layout_region_t atk_layout_take_bottom(atk_layout_t *layout, int height, int spacing);
atk_layout_region_t atk_layout_content(const atk_layout_t *layout);

#endif
