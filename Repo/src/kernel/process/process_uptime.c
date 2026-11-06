#include "process_internal.h"

/* Convert elapsed clock units rather than an absolute nanosecond timestamp. */
static uint64_t process_uptime_ticks_to_ns(uint64_t ticks, uint32_t frequency)
{
    if (frequency == 0) return 0;
    const uint64_t maximum = UINT64_MAX;
    uint64_t seconds = ticks / frequency;
    uint64_t fraction = ((ticks % frequency) * 1000000000ULL) / frequency;
    if (seconds > maximum / 1000000000ULL) return maximum;
    uint64_t whole = seconds * 1000000000ULL;
    return fraction > maximum - whole ? maximum : whole + fraction;
}

uint64_t process_current_uptime_ns(void)
{
    /* A running thread owns its process. Pin the CPU across the current-owner
     * snapshot so migration/exit cannot change that ownership mid-read. Only
     * scalar values survive the guard; no process/stack pointer escapes. */
    spinlock_preempt_disable();
    process_t *process = current_process_local();
    uint64_t start = process ? process->started_monotonic_millis : 0;
    uint64_t now = timer_monotonic_millis();
    bool valid = process != NULL && now >= start;
    spinlock_preempt_enable();
    return valid ? process_uptime_ticks_to_ns(now - start, 1000) : 0;
}
