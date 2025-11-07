#include "atk/layout.h"

#include <stddef.h>

static void layout_clamp_region(atk_layout_region_t *region)
{
    if (!region)
    {
        return;
    }
    if (region->width < 0)
    {
        region->width = 0;
    }
    if (region->height < 0)
    {
        region->height = 0;
    }
}

void atk_layout_init(atk_layout_t *layout, int x, int y, int width, int height)
{
    if (!layout)
    {
        return;
    }
    layout->x = x;
    layout->y = y;
    layout->width = width;
    layout->height = height;
    layout->padding_left = 0;
    layout->padding_top = 0;
    layout->padding_right = 0;
    layout->padding_bottom = 0;
}

void atk_layout_set_padding(atk_layout_t *layout, int left, int top, int right, int bottom)
{
    if (!layout)
    {
        return;
    }
    layout->padding_left = left;
    layout->padding_top = top;
    layout->padding_right = right;
    layout->padding_bottom = bottom;
}

static atk_layout_region_t layout_inner_bounds(const atk_layout_t *layout)
{
    if (!layout)
    {
        return atk_layout_region_make(0, 0, 0, 0);
    }
    int inner_x = layout->x + layout->padding_left;
    int inner_y = layout->y + layout->padding_top;
    int inner_w = layout->width - (layout->padding_left + layout->padding_right);
    int inner_h = layout->height - (layout->padding_top + layout->padding_bottom);
    if (inner_w < 0) inner_w = 0;
    if (inner_h < 0) inner_h = 0;
    return atk_layout_region_make(inner_x, inner_y, inner_w, inner_h);
}

atk_layout_region_t atk_layout_take_top(atk_layout_t *layout, int height, int spacing)
{
    if (!layout || height <= 0)
    {
        return atk_layout_region_make(0, 0, 0, 0);
    }

    atk_layout_region_t inner = layout_inner_bounds(layout);
    if (height > inner.height)
    {
        height = inner.height;
    }

    atk_layout_region_t region = atk_layout_region_make(inner.x, inner.y, inner.width, height);
    layout->padding_top += height + (spacing > 0 ? spacing : 0);
    layout_clamp_region(&region);
    return region;
}

atk_layout_region_t atk_layout_take_bottom(atk_layout_t *layout, int height, int spacing)
{
    if (!layout || height <= 0)
    {
        return atk_layout_region_make(0, 0, 0, 0);
    }

    atk_layout_region_t inner = layout_inner_bounds(layout);
    if (height > inner.height)
    {
        height = inner.height;
    }

    int y = inner.y + inner.height - height;
    atk_layout_region_t region = atk_layout_region_make(inner.x, y, inner.width, height);
    layout->padding_bottom += height + (spacing > 0 ? spacing : 0);
    layout_clamp_region(&region);
    return region;
}

atk_layout_region_t atk_layout_content(const atk_layout_t *layout)
{
    atk_layout_region_t region = layout_inner_bounds(layout);
    layout_clamp_region(&region);
    return region;
}
