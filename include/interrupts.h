#ifndef INTERRUPTS_H
#define INTERRUPTS_H

#include "types.h"

void interrupts_init(void);
void interrupts_enable(void);
void interrupts_enable_irq(uint8_t irq);

#endif
