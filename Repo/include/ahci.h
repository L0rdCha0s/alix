#ifndef AHCI_H
#define AHCI_H

#include "types.h"

void ahci_init(void);
void ahci_on_irq(void);
void ahci_interrupts_activate(void);
void ahci_set_interrupt_mode(bool enable);

#endif /* AHCI_H */
