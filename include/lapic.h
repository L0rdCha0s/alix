#ifndef LAPIC_H
#define LAPIC_H

#include "types.h"

bool lapic_init(void);
uint32_t lapic_get_id(void);
void lapic_enable(void);
void lapic_eoi(void);
void lapic_send_ipi(uint32_t apic_id, uint8_t vector);
void lapic_send_init(uint32_t apic_id);
void lapic_send_startup(uint32_t apic_id, uint8_t vector);
void lapic_broadcast_ipi(uint8_t vector, bool include_self);
void lapic_set_tpr(uint8_t value);

#endif /* LAPIC_H */
