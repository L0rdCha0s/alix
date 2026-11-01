#include "block.h"
#include "libc.h"
#include "spinlock.h"

/*
 * src/kernel/block.c
 *
 * Block device registry and common read/write/flush wrappers.
 *
 * Drivers register `block_device_t` instances via `block_register`, and higher
 * layers (VFS, filesystems) enumerate or look them up by name.
 *
 * See docs/kernel/vfs.md and docs/kernel/source_map.md.
 */

static block_device_t *g_block_devices_head = NULL;
static block_device_t *g_block_devices_tail = NULL;
static spinlock_t g_registry_lock;

/*
 * Initialise the global block device list.
 */
void block_init(void)
{
    spinlock_init(&g_registry_lock);
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

/*
 * Register a new block device.
 *
 * The driver provides sector geometry and callbacks. The returned pointer is
 * owned by the registry for the lifetime of the kernel.
 */
block_device_t *block_register(const char *name,
                               uint32_t sector_size,
                               uint64_t sector_count,
                               block_device_read_fn read,
                               block_device_write_fn write,
                               block_device_flush_fn flush,
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
    device->flush = flush;
    device->next = NULL;

    uint64_t flags = spinlock_lock_irqsave(&g_registry_lock);
    if (!g_block_devices_head)
    {
        __atomic_store_n(&g_block_devices_head, device, __ATOMIC_RELEASE);
        g_block_devices_tail = device;
    }
    else
    {
        __atomic_store_n(&g_block_devices_tail->next, device, __ATOMIC_RELEASE);
        g_block_devices_tail = device;
    }
    spinlock_unlock_irqrestore(&g_registry_lock, flags);

    return device;
}

block_device_t *block_first(void)
{
    return __atomic_load_n(&g_block_devices_head, __ATOMIC_ACQUIRE);
}

block_device_t *block_next(block_device_t *device)
{
    return device ? __atomic_load_n(&device->next, __ATOMIC_ACQUIRE) : NULL;
}

block_device_t *block_find(const char *name)
{
    if (!name)
    {
        return NULL;
    }
    for (block_device_t *dev = block_first(); dev; dev = block_next(dev))
    {
        if (strcmp(dev->name, name) == 0)
        {
            return dev;
        }
    }
    return NULL;
}

/*
 * Read `count` sectors starting at LBA `lba` into `buffer`.
 */
bool block_read(block_device_t *device, uint64_t lba, uint32_t count, void *buffer)
{
    if (!device || !buffer || count == 0 || !device->read)
    {
        return false;
    }
    if (lba >= device->sector_count || count > device->sector_count - lba)
    {
        return false;
    }
    return device->read(device, lba, count, buffer);
}

/*
 * Write `count` sectors starting at LBA `lba` from `buffer`.
 */
bool block_write(block_device_t *device, uint64_t lba, uint32_t count, const void *buffer)
{
    if (!device || !buffer || count == 0 || !device->write)
    {
        return false;
    }
    if (lba >= device->sector_count || count > device->sector_count - lba)
    {
        return false;
    }
    return device->write(device, lba, count, buffer);
}

/*
 * Flush outstanding writes for a block device (if supported).
 */
bool block_flush(block_device_t *device)
{
    if (!device)
    {
        return false;
    }
    if (!device->flush)
    {
        return true;
    }
    return device->flush(device);
}
