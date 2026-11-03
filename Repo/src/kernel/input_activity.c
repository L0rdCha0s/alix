#include "input_activity.h"
#include "timer.h"
#include <stdint.h>

static uint64_t last_input_millis;

void input_activity_record(void)
{
    uint64_t now = timer_monotonic_millis();
    uint64_t previous = __atomic_load_n(&last_input_millis, __ATOMIC_RELAXED);
    while (previous < now &&
           !__atomic_compare_exchange_n(&last_input_millis, &previous, now, false,
                                         __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {}
}

uint32_t input_activity_idle_millis(void)
{
    uint64_t now = timer_monotonic_millis();
    uint64_t previous = __atomic_load_n(&last_input_millis, __ATOMIC_ACQUIRE);
    uint64_t elapsed = now >= previous ? now - previous : 0;
    return elapsed > UINT32_MAX ? UINT32_MAX : (uint32_t)elapsed;
}
