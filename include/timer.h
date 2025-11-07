#ifndef TIMER_H
#define TIMER_H

#include "types.h"

typedef void (*timer_callback_t)(void *context);

void timer_init(uint32_t frequency_hz);
void timer_on_tick(void);
uint64_t timer_ticks(void);
uint32_t timer_frequency(void);
bool timer_register_periodic(timer_callback_t callback, void *context, uint32_t interval_ticks);
bool timer_unregister(timer_callback_t callback, void *context);

#endif
