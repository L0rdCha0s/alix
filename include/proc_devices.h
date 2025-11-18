#ifndef PROC_DEVICES_H
#define PROC_DEVICES_H

#include "types.h"
#include "block.h"
#include "net/interface.h"

void proc_devices_init(void);
void proc_devices_refresh_all(void);
void proc_devices_on_block_registered(block_device_t *device);
void proc_devices_on_net_registered(net_interface_t *iface);

#endif
