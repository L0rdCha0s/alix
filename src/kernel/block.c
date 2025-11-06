#include "block.h"
#include "libc.h"

static block_device_t *g_block_devices_head = NULL;
static block_device_t *g_block_devices_tail = NULL;

void block_init(void)
{
    g_block_devices_head = NULL;
    g_block_devices_tail = NULL;
}

static void block_copy_name(block_device_t *device, const char *name)
{
    if (!device)
    {
        return;
    }
    device->name[0] = '\0';
    if (!name)
    {
        return;
    }
    size_t len = strlen(name);
    if (len >= sizeof(device->name))
    {
        len = sizeof(device->name) - 1;
    }
    memcpy(device->name, name, len);
    device->name[len] = '\0';
}

block_device_t *block_register(const char *name,
                               uint32_t sector_size,
                               uint64_t sector_count,
                               block_device_read_fn read,
                               block_device_write_fn write,
                               void *driver_data)
{
    if (sector_size == 0 || sector_count == 0 || !read)
    {
        return NULL;
    }

    block_device_t *device = (block_device_t *)malloc(sizeof(block_device_t));
    if (!device)
    {
        return NULL;
    }

    memset(device, 0, sizeof(block_device_t));
    block_copy_name(device, name ? name : "disk");
    device->sector_size = sector_size;
    device->sector_count = sector_count;
    device->driver_data = driver_data;
    device->read = read;
    device->write = write;
    device->next = NULL;

    if (!g_block_devices_head)
    {
        g_block_devices_head = device;
        g_block_devices_tail = device;
    }
    else
    {
        g_block_devices_tail->next = device;
        g_block_devices_tail = device;
    }

    return device;
}

block_device_t *block_first(void)
{
    return g_block_devices_head;
}

block_device_t *block_next(block_device_t *device)
{
    return device ? device->next : NULL;
}

block_device_t *block_find(const char *name)
{
    if (!name)
    {
        return NULL;
    }
    for (block_device_t *dev = g_block_devices_head; dev; dev = dev->next)
    {
        if (strcmp(dev->name, name) == 0)
        {
            return dev;
        }
    }
    return NULL;
}

bool block_read(block_device_t *device, uint64_t lba, uint32_t count, void *buffer)
{
    if (!device || !buffer || count == 0 || !device->read)
    {
        return false;
    }
    if (lba >= device->sector_count || (lba + count) > device->sector_count)
    {
        return false;
    }
    return device->read(device, lba, count, buffer);
}

bool block_write(block_device_t *device, uint64_t lba, uint32_t count, const void *buffer)
{
    if (!device || !buffer || count == 0 || !device->write)
    {
        return false;
    }
    if (lba >= device->sector_count || (lba + count) > device->sector_count)
    {
        return false;
    }
    return device->write(device, lba, count, buffer);
}
