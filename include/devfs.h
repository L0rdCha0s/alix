#ifndef DEVFS_H
#define DEVFS_H

#include "block.h"
#include "vfs.h"

void devfs_init(void);
void devfs_register_block_device(block_device_t *device);
void devfs_register_block_devices(void);
bool devfs_register_file(const char *name,
                         vfs_read_cb_t read_cb,
                         vfs_write_cb_t write_cb,
                         void *context);

#endif
