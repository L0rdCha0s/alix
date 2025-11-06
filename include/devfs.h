#ifndef DEVFS_H
#define DEVFS_H

#include "block.h"

void devfs_init(void);
void devfs_register_block_device(block_device_t *device);
void devfs_register_block_devices(void);

#endif
