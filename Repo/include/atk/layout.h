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

/*
 * Construct a region in layout coordinates.
 *
 * This is a convenience helper for `atk_layout_*` APIs and callers that want to
 * store or return simple rectangles.
 */
static inline atk_layout_region_t atk_layout_region_make(int x, int y, int width, int height)
{
    atk_layout_region_t region = { x, y, width, height };
    return region;
}

/*
 * Initialize a layout cursor at (x,y) with a fixed outer size.
 *
 * `atk_layout_take_top()` / `atk_layout_take_bottom()` carve regions out of the
 * inner area and advance padding to avoid overlaps.
 */
void atk_layout_init(atk_layout_t *layout, int x, int y, int width, int height);

/*
 * Set outer padding for the layout.
 *
 * Padding shrinks the "content" area returned by `atk_layout_content()` and
 * affects where subsequent `take_*` calls allocate regions.
 */
void atk_layout_set_padding(atk_layout_t *layout, int left, int top, int right, int bottom);

/*
 * Allocate a region from the top edge of the remaining content.
 *
 * - `height` is clamped to the remaining inner height.
 * - `spacing` (if > 0) is added below the returned region.
 */
atk_layout_region_t atk_layout_take_top(atk_layout_t *layout, int height, int spacing);

/*
 * Allocate a region from the bottom edge of the remaining content.
 *
 * - `height` is clamped to the remaining inner height.
 * - `spacing` (if > 0) is added above the returned region.
 */
atk_layout_region_t atk_layout_take_bottom(atk_layout_t *layout, int height, int spacing);

/*
 * Return the remaining inner region after padding and any `take_*` calls.
 *
 * This does not mutate the layout, so it can be called multiple times.
 */
atk_layout_region_t atk_layout_content(const atk_layout_t *layout);

#endif
