#ifndef IGB_H
#define IGB_H

#include "types.h"

void igb_init(void);
void igb_on_irq(void);
void igb_poll(void);
bool igb_is_present(void);
bool igb_get_mac(uint8_t mac_out[6]);

#endif
