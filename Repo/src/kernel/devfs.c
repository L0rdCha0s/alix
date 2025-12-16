#include "devfs.h"
#include "vfs.h"

/*
 * src/kernel/devfs.c
 *
 * Minimal devfs implementation layered on the VFS:
 * - Ensures `/dev` exists.
 * - Publishes block devices as `VFS_NODE_BLOCK` children under `/dev`.
 * - Supports callback-backed pseudo-files under `/dev` via `vfs_set_file_callbacks`.
 *
 * See docs/kernel/vfs.md.
 */

static vfs_node_t *g_dev_root = NULL;

static void devfs_set_mutable(bool allow)
{
    if (g_dev_root)
    {
        vfs_set_subtree_mutable(g_dev_root, allow);
    }
}

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

/*
 * Register a single block device as `/dev/<device->name>`.
 */
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
    devfs_set_mutable(true);
    if (!device->name[0])
    {
        devfs_set_mutable(false);
        return;
    }
    vfs_add_block_device(dev_dir, device->name, device);
    devfs_set_mutable(false);
}

/*
 * Register all currently-known block devices under `/dev`.
 */
void devfs_register_block_devices(void)
{
    vfs_node_t *dev_dir = devfs_root_node();
    if (!dev_dir)
    {
        return;
    }
    devfs_set_mutable(true);
    for (block_device_t *device = block_first(); device; device = block_next(device))
    {
        if (device->name[0])
        {
            vfs_add_block_device(dev_dir, device->name, device);
        }
    }
    devfs_set_mutable(false);
}

/*
 * Create a callback-backed file under `/dev`.
 */
bool devfs_register_file(const char *name,
                         vfs_read_cb_t read_cb,
                         vfs_write_cb_t write_cb,
                         void *context)
{
    if (!name || name[0] == '\0')
    {
        return false;
    }
    vfs_node_t *dev_dir = devfs_root_node();
    if (!dev_dir)
    {
        return false;
    }

    devfs_set_mutable(true);
    vfs_node_t *node = vfs_open_file(dev_dir, name, true, true);
    bool ok = false;
    if (node)
    {
        ok = vfs_set_file_callbacks(node, read_cb, write_cb, context);
    }
    devfs_set_mutable(false);
    return ok;
}
