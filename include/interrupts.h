#ifndef INTERRUPTS_H
#define INTERRUPTS_H

#include "types.h"

typedef struct interrupt_frame
{
    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
    uint64_t rsp;
    uint64_t ss;
} interrupt_frame_t;

void interrupts_init(void);
void interrupts_enable(void);
void interrupts_enable_irq(uint8_t irq);

#endif
