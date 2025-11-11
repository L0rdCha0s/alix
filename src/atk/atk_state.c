#include "atk_internal.h"

atk_state_t *atk_state_get(void)
{
    static atk_state_t state;
    return &state;
}

atk_widget_t *atk_state_mouse_capture(const atk_state_t *state)
{
    return state ? state->mouse_capture_widget : NULL;
}

void atk_state_set_mouse_capture(atk_state_t *state, atk_widget_t *widget)
{
    if (!state)
    {
        return;
    }
    state->mouse_capture_widget = widget;
}

void atk_state_release_mouse_capture(atk_state_t *state, const atk_widget_t *widget)
{
    if (!state)
    {
        return;
    }
    if (!widget || state->mouse_capture_widget == widget)
    {
        state->mouse_capture_widget = NULL;
    }
}

atk_widget_t *atk_state_focus_widget(const atk_state_t *state)
{
    return state ? state->focus_widget : NULL;
}

void atk_state_set_focus_widget(atk_state_t *state, atk_widget_t *widget)
{
    if (!state)
    {
        return;
    }
    state->focus_widget = widget;
}
