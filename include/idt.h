#ifndef IDT_H
#define IDT_H

#include "types.h"

void idt_init(void);
void idt_set_gate(uint8_t vector, void (*handler)(void));
void idt_load(void);

#endif
