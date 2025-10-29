#ifndef TIMER_H
#define TIMER_H

#include "types.h"

void timer_init(uint32_t frequency_hz);
void timer_on_tick(void);
uint64_t timer_ticks(void);
uint32_t timer_frequency(void);

#endif
