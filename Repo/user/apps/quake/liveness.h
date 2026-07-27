#ifndef QUAKE_LIVENESS_H
#define QUAKE_LIVENESS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum
{
    QUAKE_LIVENESS_INTERVAL_MS = 500,
};

typedef enum
{
    QUAKE_LIVENESS_INPUT_OTHER = 0,
    QUAKE_LIVENESS_INPUT_KEY,
    QUAKE_LIVENESS_INPUT_MOUSE,
} quake_liveness_input_kind_t;

typedef struct
{
    bool enabled;
    bool report_clock_started;
    uint64_t last_report_ms;
    uint64_t frame_count;
    uint64_t present_success_count;
    uint64_t present_failure_count;
    uint64_t input_event_count;
    uint64_t key_event_count;
    uint64_t mouse_event_count;
} quake_liveness_t;

void quake_liveness_init(quake_liveness_t *state, bool enabled);
void quake_liveness_record_present(quake_liveness_t *state, bool succeeded);
void quake_liveness_record_input(quake_liveness_t *state,
                                 quake_liveness_input_kind_t kind);
bool quake_liveness_report_due(quake_liveness_t *state, uint64_t now_ms);
uint32_t quake_liveness_hash_source(const uint8_t *pixels, size_t pixel_count);

#endif /* QUAKE_LIVENESS_H */
