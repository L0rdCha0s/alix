#include "devfs.h"
#include "vfs.h"

static vfs_node_t *g_dev_root = NULL;

static vfs_node_t *devfs_root_node(void)
{
    if (g_dev_root && vfs_is_dir(g_dev_root))
    {
        return g_dev_root;
    }

    vfs_node_t *root = vfs_root();
    if (!root)
    {
        return NULL;
    }

    vfs_node_t *dev = vfs_resolve(root, "/dev");
    if (!dev)
    {
        dev = vfs_mkdir(root, "/dev");
    }
    if (dev && vfs_is_dir(dev))
    {
        g_dev_root = dev;
    }
    return g_dev_root;
}

void devfs_init(void)
{
    (void)devfs_root_node();
}

void devfs_register_block_device(block_device_t *device)
{
    if (!device)
    {
        return;
    }
    vfs_node_t *dev_dir = devfs_root_node();
    if (!dev_dir)
    {
        return;
    }
    if (!device->name[0])
    {
        return;
    }
    vfs_add_block_device(dev_dir, device->name, device);
}

void devfs_register_block_devices(void)
{
    vfs_node_t *dev_dir = devfs_root_node();
    if (!dev_dir)
    {
        return;
    }
    for (block_device_t *device = block_first(); device; device = block_next(device))
    {
        if (device->name[0])
        {
            vfs_add_block_device(dev_dir, device->name, device);
        }
    }
}
