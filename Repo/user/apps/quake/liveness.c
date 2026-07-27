#include "liveness.h"

void quake_liveness_init(quake_liveness_t *state, bool enabled)
{
    if (!state)
    {
        return;
    }

    *state = (quake_liveness_t){0};
    state->enabled = enabled;
}

void quake_liveness_record_present(quake_liveness_t *state, bool succeeded)
{
    if (!state || !state->enabled)
    {
        return;
    }

    state->frame_count++;
    if (succeeded)
    {
        state->present_success_count++;
    }
    else
    {
        state->present_failure_count++;
    }
}

void quake_liveness_record_input(quake_liveness_t *state,
                                 quake_liveness_input_kind_t kind)
{
    if (!state || !state->enabled)
    {
        return;
    }

    state->input_event_count++;
    if (kind == QUAKE_LIVENESS_INPUT_KEY)
    {
        state->key_event_count++;
    }
    else if (kind == QUAKE_LIVENESS_INPUT_MOUSE)
    {
        state->mouse_event_count++;
    }
}

bool quake_liveness_report_due(quake_liveness_t *state, uint64_t now_ms)
{
    if (!state || !state->enabled)
    {
        return false;
    }

    if (!state->report_clock_started || now_ms < state->last_report_ms)
    {
        state->report_clock_started = true;
        state->last_report_ms = now_ms;
        return false;
    }

    if (now_ms - state->last_report_ms < QUAKE_LIVENESS_INTERVAL_MS)
    {
        return false;
    }

    state->last_report_ms = now_ms;
    return true;
}

uint32_t quake_liveness_hash_source(const uint8_t *pixels, size_t pixel_count)
{
    if (!pixels)
    {
        return 0;
    }

    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < pixel_count; ++i)
    {
        hash ^= pixels[i];
        hash *= 16777619u;
    }
    return hash;
}
