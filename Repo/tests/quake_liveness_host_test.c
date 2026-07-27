#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "liveness.h"

static bool test_disabled_is_inert(void)
{
    quake_liveness_t state;
    quake_liveness_init(&state, false);
    quake_liveness_record_present(&state, true);
    quake_liveness_record_present(&state, false);
    quake_liveness_record_input(&state, QUAKE_LIVENESS_INPUT_KEY);

    return !state.enabled &&
           state.frame_count == 0 &&
           state.present_success_count == 0 &&
           state.present_failure_count == 0 &&
           state.input_event_count == 0 &&
           !quake_liveness_report_due(&state, 1000);
}

static bool test_present_and_input_totals(void)
{
    quake_liveness_t state;
    quake_liveness_init(&state, true);
    quake_liveness_record_present(&state, true);
    quake_liveness_record_present(&state, false);
    quake_liveness_record_present(&state, true);
    quake_liveness_record_input(&state, QUAKE_LIVENESS_INPUT_KEY);
    quake_liveness_record_input(&state, QUAKE_LIVENESS_INPUT_MOUSE);
    quake_liveness_record_input(&state, QUAKE_LIVENESS_INPUT_OTHER);

    return state.frame_count == 3 &&
           state.present_success_count == 2 &&
           state.present_failure_count == 1 &&
           state.input_event_count == 3 &&
           state.key_event_count == 1 &&
           state.mouse_event_count == 1;
}

static bool test_report_interval(void)
{
    quake_liveness_t state;
    quake_liveness_init(&state, true);

    return !quake_liveness_report_due(&state, 1000) &&
           !quake_liveness_report_due(&state, 1499) &&
           quake_liveness_report_due(&state, 1500) &&
           !quake_liveness_report_due(&state, 1999) &&
           quake_liveness_report_due(&state, 2000);
}

static bool test_source_hash_changes(void)
{
    uint8_t pixels[] = {0, 1, 2, 3};
    uint32_t initial = quake_liveness_hash_source(pixels, sizeof(pixels));
    pixels[2] = 4;
    return initial != 0 &&
           initial != quake_liveness_hash_source(pixels, sizeof(pixels)) &&
           quake_liveness_hash_source(NULL, 4) == 0;
}

int main(void)
{
    struct
    {
        const char *name;
        bool (*run)(void);
    } tests[] = {
        {"disabled-is-inert", test_disabled_is_inert},
        {"present-and-input-totals", test_present_and_input_totals},
        {"report-interval", test_report_interval},
        {"source-hash-changes", test_source_hash_changes},
    };

    int failures = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i)
    {
        if (!tests[i].run())
        {
            fprintf(stderr, "FAIL: %s\n", tests[i].name);
            failures++;
        }
    }

    if (failures == 0)
    {
        printf("quake_liveness_host_test: success\n");
    }
    return failures == 0 ? 0 : 1;
}
