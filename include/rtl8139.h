#ifndef RTL8139_H
#define RTL8139_H

#include "types.h"

void rtl8139_init(void);
void rtl8139_on_irq(void);
void rtl8139_poll(void);
bool rtl8139_is_present(void);
bool rtl8139_get_mac(uint8_t mac_out[6]);

#endif
