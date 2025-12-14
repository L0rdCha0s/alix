#ifndef INTERRUPTS_H
#define INTERRUPTS_H

#include "types.h"

/* IRQ callback registration (PIC IRQ lines 0-15). */
#define INTERRUPTS_IRQ_COUNT 16

typedef struct interrupt_frame
{
    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
    uint64_t rsp;
    uint64_t ss;
} interrupt_frame_t;

typedef void (*irq_handler_t)(uint8_t irq, interrupt_frame_t *frame, void *context);

void interrupts_init(void);
void interrupts_enable(void);
void interrupts_enable_irq(uint8_t irq);
bool interrupts_register_irq_handler(uint8_t irq, irq_handler_t handler, void *context);

#endif
