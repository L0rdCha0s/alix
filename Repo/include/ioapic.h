#ifndef IOAPIC_H
#define IOAPIC_H
#include "types.h"
void ioapic_init(void);
bool ioapic_enable_isa_irq(uint8_t irq);
#endif
