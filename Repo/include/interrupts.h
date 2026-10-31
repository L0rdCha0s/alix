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

/* Layout shared with exception_entry.S. Unlike compiler interrupt prologues,
 * this stable frame exposes every GPR for native fault delivery and return. */
typedef struct exception_frame
{
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rsi, rdi, rbp, rdx, rcx, rbx, rax;
    uint64_t vector, error_code;
    interrupt_frame_t cpu;
} exception_frame_t;

void exception_dispatch(exception_frame_t *frame);

typedef void (*irq_handler_t)(uint8_t irq, interrupt_frame_t *frame, void *context);

void interrupts_init(void);
void interrupts_enable(void);
void interrupts_enable_irq(uint8_t irq);
bool interrupts_register_irq_handler(uint8_t irq, irq_handler_t handler, void *context);

#endif
