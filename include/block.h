#ifndef BLOCK_H
#define BLOCK_H

#include "types.h"

typedef struct block_device block_device_t;

typedef bool (*block_device_read_fn)(block_device_t *device, uint64_t lba, uint32_t count, void *buffer);
typedef bool (*block_device_write_fn)(block_device_t *device, uint64_t lba, uint32_t count, const void *buffer);

struct block_device
{
    char name[16];
    uint32_t sector_size;
    uint64_t sector_count;
    void *driver_data;
    block_device_read_fn read;
    block_device_write_fn write;
    block_device_t *next;
};

void block_init(void);
block_device_t *block_register(const char *name,
                               uint32_t sector_size,
                               uint64_t sector_count,
                               block_device_read_fn read,
                               block_device_write_fn write,
                               void *driver_data);
block_device_t *block_first(void);
block_device_t *block_next(block_device_t *device);
block_device_t *block_find(const char *name);
bool block_read(block_device_t *device, uint64_t lba, uint32_t count, void *buffer);
bool block_write(block_device_t *device, uint64_t lba, uint32_t count, const void *buffer);

#endif
