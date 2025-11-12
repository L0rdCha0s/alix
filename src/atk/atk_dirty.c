#include "atk_internal.h"

#include "video.h"

static void atk_dirty_expand(atk_state_t *state, int x0, int y0, int x1, int y1)
{
    if (!state)
    {
        return;
    }
    if (!state->dirty_active)
    {
        state->dirty_active = true;
        state->dirty_x0 = x0;
        state->dirty_y0 = y0;
        state->dirty_x1 = x1;
        state->dirty_y1 = y1;
        return;
    }
    if (x0 < state->dirty_x0) state->dirty_x0 = x0;
    if (y0 < state->dirty_y0) state->dirty_y0 = y0;
    if (x1 > state->dirty_x1) state->dirty_x1 = x1;
    if (y1 > state->dirty_y1) state->dirty_y1 = y1;
}

void atk_dirty_init(atk_state_t *state)
{
    if (!state)
    {
        return;
    }
    state->dirty_full = true;
    state->dirty_active = false;
    state->dirty_x0 = 0;
    state->dirty_y0 = 0;
    state->dirty_x1 = VIDEO_WIDTH;
    state->dirty_y1 = VIDEO_HEIGHT;
    video_invalidate_all();
}

void atk_dirty_mark_rect(int x, int y, int width, int height)
{
    if (width <= 0 || height <= 0)
    {
        return;
    }

    int x0 = x;
    int y0 = y;
    int x1 = x + width;
    int y1 = y + height;

    if (x1 <= 0 || y1 <= 0 || x0 >= VIDEO_WIDTH || y0 >= VIDEO_HEIGHT)
    {
        return;
    }

    if (x0 < 0) x0 = 0;
    if (y0 < 0) y0 = 0;
    if (x1 > VIDEO_WIDTH) x1 = VIDEO_WIDTH;
    if (y1 > VIDEO_HEIGHT) y1 = VIDEO_HEIGHT;

    video_invalidate_rect(x0, y0, x1 - x0, y1 - y0);

    atk_state_t *state = atk_state_get();
    if (!state)
    {
        return;
    }
    if (state->dirty_full)
    {
        return;
    }
    atk_dirty_expand(state, x0, y0, x1, y1);
}

void atk_dirty_mark_all(void)
{
    atk_state_t *state = atk_state_get();
    if (!state)
    {
        return;
    }
#if ATK_DEBUG
    atk_state_theme_log(state, "dirty mark start");
#endif
    state->dirty_full = true;
    state->dirty_active = false;
    state->dirty_x0 = 0;
    state->dirty_y0 = 0;
    state->dirty_x1 = VIDEO_WIDTH;
    state->dirty_y1 = VIDEO_HEIGHT;
#if ATK_DEBUG
    atk_state_theme_log(state, "dirty mark pre invalidate");
#endif
    video_invalidate_all();
#if ATK_DEBUG
    atk_state_theme_log(state, "dirty mark post invalidate");
#endif
}

bool atk_dirty_consume(atk_rect_t *out)
{
    atk_state_t *state = atk_state_get();
    if (!state)
    {
        return false;
    }

    if (state->dirty_full)
    {
        if (out)
        {
            out->x = 0;
            out->y = 0;
            out->width = VIDEO_WIDTH;
            out->height = VIDEO_HEIGHT;
        }
        state->dirty_full = false;
        state->dirty_active = false;
        return true;
    }

    if (!state->dirty_active)
    {
        return false;
    }

    int x0 = state->dirty_x0;
    int y0 = state->dirty_y0;
    int x1 = state->dirty_x1;
    int y1 = state->dirty_y1;

    state->dirty_active = false;

    if (x0 < 0) x0 = 0;
    if (y0 < 0) y0 = 0;
    if (x1 > VIDEO_WIDTH) x1 = VIDEO_WIDTH;
    if (y1 > VIDEO_HEIGHT) y1 = VIDEO_HEIGHT;

    if (x1 <= x0 || y1 <= y0)
    {
        return false;
    }

    if (out)
    {
        out->x = x0;
        out->y = y0;
        out->width = x1 - x0;
        out->height = y1 - y0;
    }
    return true;
}
