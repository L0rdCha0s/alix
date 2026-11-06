#ifndef TIMER_H
#define TIMER_H

#include "types.h"

typedef void (*timer_callback_t)(void *context);

void timer_init(uint32_t frequency_hz);
bool timer_early_delay_us(uint32_t microseconds);
void timer_on_tick(void);
uint64_t timer_ticks(void);
uint64_t timer_monotonic_millis(void);
uint64_t timer_monotonic_resolution_ns(void);
uint64_t timer_deadline_after_millis(uint64_t milliseconds);
uint32_t timer_frequency(void);
bool timer_register_periodic(timer_callback_t callback, void *context, uint32_t interval_ticks);
bool timer_unregister(timer_callback_t callback, void *context);

#endif
