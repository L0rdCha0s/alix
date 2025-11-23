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
    state->dirty_x1 = video_screen_width();
    state->dirty_y1 = video_screen_height();
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

    int screen_w = video_screen_width();
    int screen_h = video_screen_height();
    if (x1 <= 0 || y1 <= 0 || x0 >= screen_w || y0 >= screen_h)
    {
        return;
    }

    if (x0 < 0) x0 = 0;
    if (y0 < 0) y0 = 0;
    if (x1 > screen_w) x1 = screen_w;
    if (y1 > screen_h) y1 = screen_h;

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
    state->dirty_x1 = video_screen_width();
    state->dirty_y1 = video_screen_height();
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
            out->width = video_screen_width();
            out->height = video_screen_height();
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
    int screen_w = video_screen_width();
    int screen_h = video_screen_height();
    if (x1 > screen_w) x1 = screen_w;
    if (y1 > screen_h) y1 = screen_h;

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
