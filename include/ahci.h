#ifndef AHCI_H
#define AHCI_H

void ahci_init(void);
void ahci_on_irq(void);
void ahci_interrupts_activate(void);

#endif /* AHCI_H */
