#include "alixfs.h"
#include "vfs_internal.h"
#include "heap.h"
#include "libc.h"
#include "serial.h"
#include <stdint.h>

#define ALIXFS2_MAGIC   "ALIXFS2"
#define ALIXFS2_VERSION 2u
#define ALIXFS2_MAX_FREE_CHUNKS 128u
#define ALIXFS2_DEFAULT_NODE_CAPACITY 4096u

typedef struct __attribute__((packed))
{
    uint64_t offset;
    uint64_t length;
} alixfs2_free_chunk_t;

typedef struct __attribute__((packed))
{
    char     magic[8];
    uint32_t version;
    uint32_t node_capacity;
    uint32_t node_count;
    uint32_t root_id;
    uint32_t free_chunk_count;
    uint64_t data_region_offset;
    uint64_t data_region_size;
    alixfs2_free_chunk_t free_chunks[ALIXFS2_MAX_FREE_CHUNKS];
    uint8_t reserved[256];
} alixfs2_header_t;

typedef struct __attribute__((packed))
{
    uint64_t offset;
    uint32_t length;
    uint32_t capacity;
} alixfs2_chunk_entry_t;

typedef struct __attribute__((packed))
{
    uint32_t id;
    uint32_t parent_id;
    uint32_t type;
    uint32_t name_len;
    uint32_t data_len;
} alixfs_node_disk_t;

struct alixfs_mount
{
    block_device_t *device;
    size_t sector_size;
    size_t header_span;
    uint64_t node_table_offset;
    alixfs2_header_t header;
    alixfs2_chunk_entry_t *chunks;
    size_t chunk_table_bytes;
    uint8_t *chunk_dirty_bitmap;
    size_t chunk_dirty_capacity;
    uint32_t free_node_hint;
    bool header_dirty;
};

static size_t alixfs_align_size(size_t value, size_t align)
{
    if (align == 0)
    {
        return value;
    }
    size_t mask = align - 1;
    return (value + mask) & ~mask;
}

static uint64_t alixfs_align_u64(uint64_t value, uint64_t align)
{
    if (align == 0)
    {
        return value;
    }
    uint64_t mask = align - 1;
    return (value + mask) & ~mask;
}

static bool alixfs_device_io(block_device_t *device,
                             size_t sector_size,
                             uint64_t offset,
                             void *buffer,
                             size_t len,
                             bool write)
{
    if (!device || !buffer || len == 0)
    {
        return true;
    }
    if (sector_size == 0)
    {
        sector_size = 512;
    }
    uint64_t sector = offset / sector_size;
    size_t sector_offset = (size_t)(offset % sector_size);
    uint8_t *scratch = NULL;
    uint8_t *dst = (uint8_t *)buffer;
    const uint8_t *src = (const uint8_t *)buffer;
    size_t remaining = len;

    if (sector_offset != 0 || (remaining % sector_size) != 0)
    {
        scratch = (uint8_t *)malloc(sector_size);
        if (!scratch)
        {
            return false;
        }
    }

    if (sector_offset != 0)
    {
        if (!block_read(device, sector, 1, scratch))
        {
            free(scratch);
            return false;
        }
        size_t chunk = sector_size - sector_offset;
        if (chunk > remaining)
        {
            chunk = remaining;
        }
        if (write)
        {
            memcpy(scratch + sector_offset, src, chunk);
            if (!block_write(device, sector, 1, scratch))
            {
                free(scratch);
                return false;
            }
            src += chunk;
        }
        else
        {
            memcpy(dst, scratch + sector_offset, chunk);
            dst += chunk;
        }
        remaining -= chunk;
        sector += 1;
        sector_offset = 0;
    }

    while (remaining >= sector_size)
    {
        uint32_t count = (uint32_t)(remaining / sector_size);
        if (write)
        {
            if (!block_write(device, sector, count, src))
            {
                free(scratch);
                return false;
            }
            src += (size_t)count * sector_size;
        }
        else
        {
            if (!block_read(device, sector, count, dst))
            {
                free(scratch);
                return false;
            }
            dst += (size_t)count * sector_size;
        }
        remaining -= (size_t)count * sector_size;
        sector += count;
    }

    if (remaining > 0)
    {
        if (!scratch)
        {
            scratch = (uint8_t *)malloc(sector_size);
            if (!scratch)
            {
                return false;
            }
        }
        if (!block_read(device, sector, 1, scratch))
        {
            free(scratch);
            return false;
        }
        if (write)
        {
            memcpy(scratch, src, remaining);
            if (!block_write(device, sector, 1, scratch))
            {
                free(scratch);
                return false;
            }
        }
        else
        {
            memcpy(dst, scratch, remaining);
        }
    }

    if (scratch)
    {
        free(scratch);
    }
    return true;
}

static bool alixfs_device_read(block_device_t *device,
                               size_t sector_size,
                               uint64_t offset,
                               void *buffer,
                               size_t len)
{
    return alixfs_device_io(device, sector_size, offset, buffer, len, false);
}

static bool alixfs_device_write(block_device_t *device,
                                size_t sector_size,
                                uint64_t offset,
                                const void *buffer,
                                size_t len)
{
    return alixfs_device_io(device, sector_size, offset, (void *)buffer, len, true);
}

static inline void alixfs_mark_chunk_dirty(alixfs_mount_t *fs, uint32_t id)
{
    if (!fs || !fs->chunk_dirty_bitmap || id >= fs->header.node_capacity)
    {
        return;
    }
    fs->chunk_dirty_bitmap[id / 8] |= (uint8_t)(1u << (id % 8));
}

static inline void alixfs_clear_chunk_dirty(alixfs_mount_t *fs, uint32_t id)
{
    if (!fs || !fs->chunk_dirty_bitmap || id >= fs->header.node_capacity)
    {
        return;
    }
    fs->chunk_dirty_bitmap[id / 8] &= (uint8_t)~(1u << (id % 8));
}

static bool alixfs_chunk_allocate(alixfs_mount_t *fs,
                                  size_t need,
                                  uint64_t *offset,
                                  uint32_t *capacity)
{
    if (!fs || !offset || !capacity)
    {
        return false;
    }
    size_t aligned = alixfs_align_size(need, fs->sector_size);
    for (uint32_t i = 0; i < fs->header.free_chunk_count; ++i)
    {
        alixfs2_free_chunk_t *chunk = &fs->header.free_chunks[i];
        if (chunk->length >= aligned)
        {
            *offset = chunk->offset;
            *capacity = (uint32_t)aligned;
            chunk->offset += aligned;
            chunk->length -= aligned;
            if (chunk->length == 0 && i + 1 < fs->header.free_chunk_count)
            {
                memmove(&fs->header.free_chunks[i],
                        &fs->header.free_chunks[i + 1],
                        (fs->header.free_chunk_count - i - 1) * sizeof(alixfs2_free_chunk_t));
                fs->header.free_chunk_count--;
            }
            fs->header_dirty = true;
            return true;
        }
    }
    uint64_t start = fs->header.data_region_offset + fs->header.data_region_size;
    uint64_t bytes = (uint64_t)fs->device->sector_count * fs->sector_size;
    if (start + aligned > bytes)
    {
        return false;
    }
    *offset = start;
    *capacity = (uint32_t)aligned;
    fs->header.data_region_size += aligned;
    fs->header_dirty = true;
    return true;
}

static void alixfs_chunk_release(alixfs_mount_t *fs, uint64_t offset, uint32_t length)
{
    if (!fs || length == 0)
    {
        return;
    }
    uint64_t aligned_len = alixfs_align_u64(length, fs->sector_size);
    for (uint32_t i = 0; i < fs->header.free_chunk_count; ++i)
    {
        alixfs2_free_chunk_t *chunk = &fs->header.free_chunks[i];
        uint64_t end = chunk->offset + chunk->length;
        if (end == offset)
        {
            chunk->length += aligned_len;
            fs->header_dirty = true;
            return;
        }
        if (offset + aligned_len == chunk->offset)
        {
            chunk->offset = offset;
            chunk->length += aligned_len;
            fs->header_dirty = true;
            return;
        }
    }
    if (fs->header.free_chunk_count < ALIXFS2_MAX_FREE_CHUNKS)
    {
        alixfs2_free_chunk_t *chunk = &fs->header.free_chunks[fs->header.free_chunk_count++];
        chunk->offset = offset;
        chunk->length = aligned_len;
        fs->header_dirty = true;
    }
}

static vfs_node_t *alixfs_new_node(vfs_node_type_t type)
{
    vfs_node_t *node = (vfs_node_t *)calloc(1, sizeof(vfs_node_t));
    if (!node)
    {
        return NULL;
    }
    node->type = type;
    node->disk_id = UINT32_MAX;
    node->allow_mutation = true;
    node->refcount = 1;
    node->pending_dirty_bytes = 0;
    spinlock_init(&node->data_lock);
    return node;
}

static bool alixfs_ensure_capacity(vfs_node_t *node, size_t need)
{
    if (!node || node->type != VFS_NODE_FILE)
    {
        return false;
    }
    size_t req = need + 1;
    if (node->capacity >= req)
    {
        return true;
    }
    size_t new_cap = (node->capacity == 0) ? 64 : node->capacity;
    while (new_cap < req)
    {
        size_t next = new_cap << 1;
        if (next <= new_cap)
        {
            new_cap = req;
            break;
        }
        new_cap = next;
        if (new_cap < req)
        {
            new_cap = req;
        }
    }
    char *nbuf = (char *)realloc(node->data, new_cap);
    if (!nbuf)
    {
        return false;
    }
    node->data = nbuf;
    node->capacity = new_cap;
    if (node->size + 1 <= node->capacity)
    {
        node->data[node->size] = '\0';
    }
    return true;
}

static bool alixfs_assign_node_id(alixfs_mount_t *fs, vfs_node_t *node)
{
    if (!fs || !node)
    {
        return false;
    }
    if (node->disk_id != UINT32_MAX)
    {
        return true;
    }
    for (uint32_t i = fs->free_node_hint; i < fs->header.node_capacity; ++i)
    {
        if (fs->chunks[i].capacity == 0)
        {
            node->disk_id = i;
            fs->free_node_hint = i + 1;
            fs->header.node_count++;
            fs->header_dirty = true;
            return true;
        }
    }
    for (uint32_t i = 0; i < fs->free_node_hint; ++i)
    {
        if (fs->chunks[i].capacity == 0)
        {
            node->disk_id = i;
            fs->free_node_hint = i + 1;
            fs->header.node_count++;
            fs->header_dirty = true;
            return true;
        }
    }
    return false;
}

static bool alixfs_serialize_node(vfs_node_t *node,
                                  uint8_t **out_buf,
                                  size_t *out_len)
{
    if (!node || !out_buf || !out_len || node->disk_id == UINT32_MAX)
    {
        return false;
    }
    size_t name_len = (node->name) ? strlen(node->name) : 0;
    size_t data_len = 0;
    if (node->type == VFS_NODE_FILE || node->type == VFS_NODE_SYMLINK)
    {
        data_len = node->size;
    }
    size_t total = sizeof(alixfs_node_disk_t) + name_len + data_len;
    uint8_t *buffer = (uint8_t *)malloc(total);
    if (!buffer)
    {
        return false;
    }
    alixfs_node_disk_t disk = {
        .id = node->disk_id,
        .parent_id = node->parent ? node->parent->disk_id : 0xFFFFFFFFu,
        .type = node->type,
        .name_len = (uint32_t)name_len,
        .data_len = (uint32_t)data_len
    };
    memcpy(buffer, &disk, sizeof(disk));
    size_t offset = sizeof(disk);
    if (name_len > 0)
    {
        memcpy(buffer + offset, node->name, name_len);
        offset += name_len;
    }
    if (data_len > 0 && node->data)
    {
        memcpy(buffer + offset, node->data, data_len);
    }
    *out_buf = buffer;
    *out_len = total;
    return true;
}

static bool alixfs_write_node(alixfs_mount_t *fs, vfs_node_t *node)
{
    if (!fs || !node)
    {
        return true;
    }
    if (!alixfs_assign_node_id(fs, node))
    {
        return false;
    }
    uint8_t *payload = NULL;
    size_t payload_len = 0;
    if (!alixfs_serialize_node(node, &payload, &payload_len))
    {
        return false;
    }
    alixfs2_chunk_entry_t *entry = &fs->chunks[node->disk_id];
    size_t aligned = alixfs_align_size(payload_len, fs->sector_size);
    if (entry->capacity < aligned)
    {
        if (entry->capacity > 0)
        {
            alixfs_chunk_release(fs, entry->offset, entry->capacity);
        }
        uint64_t new_offset = 0;
        uint32_t new_cap = 0;
        if (!alixfs_chunk_allocate(fs, aligned, &new_offset, &new_cap))
        {
            free(payload);
            return false;
        }
        entry->offset = new_offset;
        entry->capacity = new_cap;
    }
    if (!alixfs_device_write(fs->device,
                              fs->sector_size,
                              entry->offset,
                              payload,
                              payload_len))
    {
        free(payload);
        return false;
    }
    entry->length = (uint32_t)payload_len;
    alixfs_mark_chunk_dirty(fs, node->disk_id);
    node->dirty = false;
    node->disk_data_dirty = false;
    node->disk_meta_dirty = false;
    node->disk_name_dirty = false;
    size_t consumed = node->pending_dirty_bytes;
    node->pending_dirty_bytes = 0;
    if (node->mount && consumed > 0)
    {
        vfs_mount_t *mount = node->mount;
        spinlock_lock(&mount->dirty_lock);
        if (mount->dirty_bytes > consumed)
        {
            mount->dirty_bytes -= consumed;
        }
        else
        {
            mount->dirty_bytes = 0;
        }
        spinlock_unlock(&mount->dirty_lock);
    }
    free(payload);
    return true;
}

static bool alixfs_flush_chunk_table(alixfs_mount_t *fs)
{
    if (!fs || !fs->chunk_dirty_bitmap)
    {
        return true;
    }
    for (uint32_t id = 0; id < fs->header.node_capacity; ++id)
    {
        if (!((fs->chunk_dirty_bitmap[id / 8] >> (id % 8)) & 1u))
        {
            continue;
        }
        uint64_t offset = fs->node_table_offset + (uint64_t)id * sizeof(alixfs2_chunk_entry_t);
        if (!alixfs_device_write(fs->device,
                                  fs->sector_size,
                                  offset,
                                  &fs->chunks[id],
                                  sizeof(alixfs2_chunk_entry_t)))
        {
            return false;
        }
        alixfs_clear_chunk_dirty(fs, id);
    }
    return true;
}

static bool alixfs_flush_header(alixfs_mount_t *fs)
{
    if (!fs || !fs->header_dirty)
    {
        return true;
    }
    size_t span = fs->header_span;
    uint8_t *buffer = (uint8_t *)calloc(1, span);
    if (!buffer)
    {
        return false;
    }
    memcpy(buffer, &fs->header, sizeof(fs->header));
    bool ok = alixfs_device_write(fs->device, fs->sector_size, 0, buffer, span);
    free(buffer);
    if (ok)
    {
        fs->header_dirty = false;
    }
    return ok;
}

static bool alixfs_flush_subtree(alixfs_mount_t *fs,
                                 vfs_node_t *node,
                                 vfs_mount_t *mount,
                                 bool force_all)
{
    if (!node)
    {
        return true;
    }
    bool dirty = false;
    if (node->mount == mount)
    {
        spinlock_lock(&node->data_lock);
        dirty = force_all;
        if (!dirty)
        {
            dirty = node->disk_meta_dirty || node->disk_data_dirty || node->disk_name_dirty;
        }
        if (dirty)
        {
            if (!alixfs_write_node(fs, node))
            {
                spinlock_unlock(&node->data_lock);
                return false;
            }
        }
        spinlock_unlock(&node->data_lock);
    }
    for (vfs_node_t *child = node->first_child; child; child = child->next_sibling)
    {
        if (!alixfs_flush_subtree(fs, child, mount, force_all))
        {
            return false;
        }
    }
    return true;
}

alixfs_mount_t *alixfs_mount_create(block_device_t *device)
{
    if (!device)
    {
        return NULL;
    }
    alixfs_mount_t *fs = (alixfs_mount_t *)calloc(1, sizeof(alixfs_mount_t));
    if (!fs)
    {
        return NULL;
    }
    fs->device = device;
    fs->sector_size = (device->sector_size) ? device->sector_size : 512;
    fs->header_span = alixfs_align_size(sizeof(alixfs2_header_t), fs->sector_size);
    fs->node_table_offset = fs->header_span;
    return fs;
}

void alixfs_mount_destroy(alixfs_mount_t *fs)
{
    if (!fs)
    {
        return;
    }
    free(fs->chunks);
    free(fs->chunk_dirty_bitmap);
    free(fs);
}

static bool alixfs_load_chunk_table(alixfs_mount_t *fs)
{
    if (!fs)
    {
        return false;
    }
    fs->chunk_table_bytes = (size_t)fs->header.node_capacity * sizeof(alixfs2_chunk_entry_t);
    size_t span = alixfs_align_size(fs->chunk_table_bytes, fs->sector_size);
    fs->chunks = (alixfs2_chunk_entry_t *)calloc(fs->header.node_capacity, sizeof(alixfs2_chunk_entry_t));
    if (!fs->chunks)
    {
        return false;
    }
    uint8_t *buffer = (uint8_t *)malloc(span);
    if (!buffer)
    {
        return false;
    }
    if (!alixfs_device_read(fs->device,
                             fs->sector_size,
                             fs->node_table_offset,
                             buffer,
                             fs->chunk_table_bytes))
    {
        free(buffer);
        return false;
    }
    memcpy(fs->chunks, buffer, fs->chunk_table_bytes);
    free(buffer);
    size_t bitmap_bytes = (fs->header.node_capacity + 7) / 8;
    fs->chunk_dirty_bitmap = (uint8_t *)calloc(1, bitmap_bytes);
    if (!fs->chunk_dirty_bitmap)
    {
        return false;
    }
    fs->chunk_dirty_capacity = bitmap_bytes;
    return true;
}

bool alixfs_mount_load(alixfs_mount_t *fs, vfs_mount_t *mount)
{
    if (!fs || !mount || !mount->mount_point)
    {
        return false;
    }
    if (!alixfs_device_read(fs->device, fs->sector_size, 0, &fs->header, sizeof(fs->header)))
    {
        return false;
    }
    if (memcmp(fs->header.magic, ALIXFS2_MAGIC, sizeof(fs->header.magic)) != 0 ||
        fs->header.version != ALIXFS2_VERSION ||
        fs->header.node_capacity == 0)
    {
        return false;
    }
    fs->node_table_offset = fs->header_span;
    if (!alixfs_load_chunk_table(fs))
    {
        return false;
    }
    vfs_node_t **nodes = (vfs_node_t **)calloc(fs->header.node_capacity, sizeof(vfs_node_t *));
    if (!nodes)
    {
        return false;
    }
    nodes[fs->header.root_id] = mount->mount_point;
    vfs_node_t *mount_root = mount->mount_point;
    spinlock_lock(&mount_root->data_lock);
    mount_root->disk_id = fs->header.root_id;
    mount_root->mount = mount;
    mount_root->allow_mutation = true;
    mount_root->first_child = NULL;
    mount_root->dirty = false;
    mount_root->disk_meta_dirty = false;
    mount_root->disk_data_dirty = false;
    mount_root->disk_name_dirty = false;
    mount_root->pending_dirty_bytes = 0;
    spinlock_unlock(&mount_root->data_lock);

    for (uint32_t id = 0; id < fs->header.node_capacity; ++id)
    {
        alixfs2_chunk_entry_t *entry = &fs->chunks[id];
        if (entry->capacity == 0 || entry->length < sizeof(alixfs_node_disk_t))
        {
            continue;
        }
        uint8_t *buffer = (uint8_t *)malloc(entry->length);
        if (!buffer)
        {
            free(nodes);
            return false;
        }
        if (!alixfs_device_read(fs->device,
                                 fs->sector_size,
                                 entry->offset,
                                 buffer,
                                 entry->length))
        {
            free(buffer);
            free(nodes);
            return false;
        }
        alixfs_node_disk_t disk;
        memcpy(&disk, buffer, sizeof(disk));
        if (disk.id != id)
        {
            free(buffer);
            continue;
        }
        vfs_node_t *node = nodes[id];
        if (!node)
        {
            node = alixfs_new_node((vfs_node_type_t)disk.type);
            if (!node)
            {
                free(buffer);
                free(nodes);
                return false;
            }
            nodes[id] = node;
        }
        spinlock_lock(&node->data_lock);
        node->disk_id = id;
        node->mount = mount;
        node->allow_mutation = true;
        size_t offset = sizeof(disk);
        if (disk.name_len > 0)
        {
            char *name = (char *)malloc(disk.name_len + 1);
            if (!name)
            {
                spinlock_unlock(&node->data_lock);
                free(buffer);
                free(nodes);
                return false;
            }
            memcpy(name, buffer + offset, disk.name_len);
            name[disk.name_len] = '\0';
            if (node->name)
            {
                free(node->name);
            }
            node->name = name;
            offset += disk.name_len;
        }
        if ((node->type == VFS_NODE_FILE || node->type == VFS_NODE_SYMLINK) && disk.data_len > 0)
        {
            if (!alixfs_ensure_capacity(node, disk.data_len))
            {
                spinlock_unlock(&node->data_lock);
                free(buffer);
                free(nodes);
                return false;
            }
            memcpy(node->data, buffer + offset, disk.data_len);
            node->size = disk.data_len;
            node->data[disk.data_len] = '\0';
        }
        else if (node->data)
        {
            node->data[0] = '\0';
            node->size = 0;
        }
        node->pending_dirty_bytes = 0;
        node->dirty = false;
        node->disk_data_dirty = false;
        node->disk_meta_dirty = false;
        node->disk_name_dirty = false;
        spinlock_unlock(&node->data_lock);
        free(buffer);
    }

    for (uint32_t id = 0; id < fs->header.node_capacity; ++id)
    {
        vfs_node_t *node = nodes[id];
        if (!node || id == fs->header.root_id)
        {
            continue;
        }
        alixfs2_chunk_entry_t *entry = &fs->chunks[id];
        if (entry->capacity == 0)
        {
            continue;
        }
        uint8_t *buffer = (uint8_t *)malloc(entry->length);
        if (!buffer)
        {
            free(nodes);
            return false;
        }
        if (!alixfs_device_read(fs->device,
                                 fs->sector_size,
                                 entry->offset,
                                 buffer,
                                 entry->length))
        {
            free(buffer);
            free(nodes);
            return false;
        }
        alixfs_node_disk_t disk;
        memcpy(&disk, buffer, sizeof(disk));
        free(buffer);
        if (disk.parent_id >= fs->header.node_capacity)
        {
            continue;
        }
        vfs_node_t *parent = nodes[disk.parent_id];
        if (!parent)
        {
            continue;
        }
        node->parent = parent;
        node->next_sibling = parent->first_child;
        parent->first_child = node;
    }

    free(nodes);
    return true;
}

bool alixfs_mount_flush_nodes(alixfs_mount_t *fs,
                              vfs_node_t *root,
                              vfs_mount_t *mount,
                              bool force_all)
{
    if (!fs || !root)
    {
        return true;
    }
    return alixfs_flush_subtree(fs, root, mount, force_all);
}

bool alixfs_mount_flush_single(alixfs_mount_t *fs,
                               vfs_node_t *node,
                               vfs_mount_t *mount)
{
    (void)mount;
    if (!node)
    {
        return true;
    }
    spinlock_lock(&node->data_lock);
    bool ok = alixfs_write_node(fs, node);
    spinlock_unlock(&node->data_lock);
    return ok;
}

bool alixfs_mount_commit(alixfs_mount_t *fs)
{
    if (!fs)
    {
        return true;
    }
    if (!alixfs_flush_chunk_table(fs))
    {
        return false;
    }
    return alixfs_flush_header(fs);
}

void alixfs_mount_release_node(alixfs_mount_t *fs, vfs_node_t *node)
{
    if (!fs || !node || node->disk_id == UINT32_MAX)
    {
        return;
    }
    alixfs2_chunk_entry_t *entry = &fs->chunks[node->disk_id];
    if (entry->capacity > 0)
    {
        alixfs_chunk_release(fs, entry->offset, entry->capacity);
    }
    memset(entry, 0, sizeof(*entry));
    alixfs_mark_chunk_dirty(fs, node->disk_id);
    node->disk_id = UINT32_MAX;
    node->disk_meta_dirty = false;
    node->disk_data_dirty = false;
    node->disk_name_dirty = false;
    if (fs->header.node_count > 0)
    {
        fs->header.node_count--;
    }
    fs->header_dirty = true;
}

bool alixfs_mount_format(block_device_t *device)
{
    if (!device)
    {
        return false;
    }
    size_t sector_size = (device->sector_size) ? device->sector_size : 512;
    alixfs2_header_t header;
    memset(&header, 0, sizeof(header));
    memcpy(header.magic, ALIXFS2_MAGIC, sizeof(header.magic));
    header.version = ALIXFS2_VERSION;
    header.node_capacity = ALIXFS2_DEFAULT_NODE_CAPACITY;
    header.node_count = 1;
    header.root_id = 0;
    size_t header_span = alixfs_align_size(sizeof(header), sector_size);
    size_t table_bytes = header.node_capacity * sizeof(alixfs2_chunk_entry_t);
    size_t table_span = alixfs_align_size(table_bytes, sector_size);
    header.data_region_offset = header_span + table_span;
    header.data_region_size = 0;

    uint8_t *header_buf = (uint8_t *)calloc(1, header_span);
    uint8_t *table_buf = (uint8_t *)calloc(1, table_span);
    if (!header_buf || !table_buf)
    {
        free(header_buf);
        free(table_buf);
        return false;
    }
    memcpy(header_buf, &header, sizeof(header));
    if (!alixfs_device_write(device, sector_size, 0, header_buf, header_span))
    {
        free(header_buf);
        free(table_buf);
        return false;
    }
    free(header_buf);
    if (!alixfs_device_write(device, sector_size, header_span, table_buf, table_span))
    {
        free(table_buf);
        return false;
    }
    free(table_buf);

    vfs_node_t root_stub;
    memset(&root_stub, 0, sizeof(root_stub));
    root_stub.type = VFS_NODE_DIR;
    root_stub.disk_id = 0;
    uint8_t *payload = NULL;
    size_t payload_len = 0;
    if (!alixfs_serialize_node(&root_stub, &payload, &payload_len))
    {
        return false;
    }
    uint32_t capacity = (uint32_t)alixfs_align_size(payload_len, sector_size);
    header.data_region_size = capacity;
    alixfs2_chunk_entry_t entry = {
        .offset = header.data_region_offset,
        .length = (uint32_t)payload_len,
        .capacity = capacity
    };
    bool ok = alixfs_device_write(device, sector_size, entry.offset, payload, payload_len);
    free(payload);
    if (!ok)
    {
        return false;
    }
    ok = alixfs_device_write(device,
                              sector_size,
                              header_span,
                              &entry,
                              sizeof(entry));
    if (!ok)
    {
        return false;
    }
    header_buf = (uint8_t *)calloc(1, header_span);
    if (!header_buf)
    {
        return false;
    }
    memcpy(header_buf, &header, sizeof(header));
    ok = alixfs_device_write(device, sector_size, 0, header_buf, header_span);
    free(header_buf);
    return ok;
}

void alixfs_mount_snapshot(const alixfs_mount_t *fs, bool *header_dirty)
{
    if (!fs || !header_dirty)
    {
        return;
    }
    *header_dirty = fs->header_dirty;
}
