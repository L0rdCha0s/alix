#include "alixfs.h"
#include "vfs_internal.h"
#include "vfs_mapping.h"
#include "heap.h"
#include "libc.h"
#include "serial.h"
#include <stdint.h>

/*
 * src/kernel/alixfs.c
 *
 * AlixFS2 on-disk filesystem backend for the VFS mount layer.
 *
 * This file implements reading/writing VFS nodes to a block device:
 * - a small fixed-size header (`alixfs2_header_t`)
 * - a chunk table mapping node IDs to data offsets/lengths
 * - per-node on-disk records for type/name/data
 *
 * The VFS orchestrates mount/writeback policy; this backend focuses on on-disk
 * persistence. See docs/kernel/vfs.md.
 */

#define ALIXFS2_MAGIC   "ALIXFS2"
#define ALIXFS2_VERSION 4u
#define ALIXFS2_VERSION_OWNERSHIP 3u
#define ALIXFS2_VERSION_LEGACY 2u
#define ALIXFS2_MAX_FREE_CHUNKS 128u
#define ALIXFS2_DEFAULT_NODE_CAPACITY 4096u

/*
 * On-disk structures (packed).
 *
 * Layout:
 * - Header at offset 0 (sector-aligned span, see `header_span`)
 * - Chunk table at offset `header_span` (node_capacity entries)
 * - Data region at offset `header.data_region_offset`
 *
 * The chunk table maps node IDs → payload chunks. Each payload chunk stores a
 * node header + name + data (for files/symlinks).
 *
 * See docs/kernel/alixfs.md for the full format description.
 */
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
} alixfs_node_disk_v2_t;

typedef struct __attribute__((packed))
{
    uint32_t id;
    uint32_t parent_id;
    uint32_t type;
    uint32_t name_len;
    uint32_t data_len;
    uint32_t uid;
    uint32_t gid;
} alixfs_node_disk_v3_t;

typedef struct __attribute__((packed))
{
    uint32_t id;
    uint32_t parent_id;
    uint32_t type;
    uint32_t name_len;
    uint32_t data_len;
    uint32_t uid;
    uint32_t gid;
    uint64_t atime;
    uint64_t mtime;
    uint64_t ctime;
} alixfs_node_disk_v4_t;

/* Optional versioned tail after name/data. Older records end before this
 * extension; existing header and file-data offsets remain unchanged. */
#define ALIXFS_MODE_MAGIC UINT64_C(0x45444f4d58494c41)
typedef struct __attribute__((packed))
{
    uint64_t magic;
    uint32_t version, permissions;
} alixfs_mode_disk_t;
_Static_assert(sizeof(alixfs_mode_disk_t) == 16, "AlixFS mode extension ABI");

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

bool alixfs_mount_supports_ownership(const alixfs_mount_t *fs)
{
    return fs && fs->header.version >= ALIXFS2_VERSION_OWNERSHIP;
}

static bool alixfs_version_has_ownership(uint32_t version)
{
    return version >= ALIXFS2_VERSION_OWNERSHIP;
}

static size_t alixfs_node_disk_header_size(uint32_t version)
{
    if (version >= ALIXFS2_VERSION)
    {
        return sizeof(alixfs_node_disk_v4_t);
    }
    if (alixfs_version_has_ownership(version))
    {
        return sizeof(alixfs_node_disk_v3_t);
    }
    return sizeof(alixfs_node_disk_v2_t);
}

static bool alixfs_device_io(block_device_t *device,
                             size_t sector_size,
                             uint64_t offset,
                             void *buffer,
                             size_t len,
                             bool write)
{
    /*
     * Byte-granular IO on top of sector-based block IO.
     *
     * If the request is not sector-aligned, this uses a scratch buffer and
     * read-modify-write for partial-sector updates.
     */
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
    /*
     * Allocate a sector-aligned payload chunk.
     *
     * Allocation order:
     *  1) first-fit from `header.free_chunks[]`
     *  2) extend the data-region high-water mark (`data_region_size`)
     */
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
    /*
     * Return a payload chunk to the on-disk free list.
     *
     * This attempts to coalesce with an adjacent free chunk; otherwise it
     * appends a new entry if the free list isn't full.
     */
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
    node->uid = VFS_UID_ROOT;
    node->gid = VFS_GID_ROOT;
    node->permissions = type == VFS_NODE_FILE ? 0666u : type == VFS_NODE_BLOCK ? 0600u : 0777u;
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
    /*
     * Assign a persistent node ID (chunk table index) if missing.
     *
     * A node ID is considered free when `chunks[id].capacity == 0`.
     */
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

static size_t alixfs_node_name_length(const vfs_node_t *node)
{
    /* A filesystem root has no name inside its own filesystem. The mount
     * point's name belongs to the containing tree and can differ next boot. */
    if (node->mount && node->mount->mount_point == node) return 0;
    return node->name ? strlen(node->name) : 0;
}

static bool alixfs_serialize_node(vfs_node_t *node,
                                  uint32_t version,
                                  bool metadata_only,
                                  uint8_t **out_buf,
                                  size_t *out_len)
{
    /*
     * Serialize a VFS node into the on-disk payload format:
     *   [alixfs_node_disk_v*][name bytes][data bytes][mode extension]
     *
     * - `name_len` does not include a NUL terminator.
     * - `data_len` is `node->size` for files/symlinks, 0 otherwise.
     */
    if (!node || !out_buf || !out_len || node->disk_id == UINT32_MAX)
    {
        return false;
    }
    size_t name_len = alixfs_node_name_length(node);
    uint32_t parent_id = node->parent && node->parent->mount == node->mount ?
                             node->parent->disk_id : UINT32_MAX;
    size_t data_len = 0;
    if (node->type == VFS_NODE_FILE || node->type == VFS_NODE_SYMLINK)
    {
        data_len = node->size;
    }
    size_t header_size = alixfs_node_disk_header_size(version);
    size_t total, full_size;
    if (__builtin_add_overflow(header_size, name_len, &full_size) ||
        __builtin_add_overflow(full_size, data_len, &full_size) ||
        __builtin_add_overflow(full_size, sizeof(alixfs_mode_disk_t), &full_size) || full_size > UINT32_MAX)
        return false;
    total = metadata_only ? header_size + name_len + sizeof(alixfs_mode_disk_t) : full_size;
    uint8_t *buffer = (uint8_t *)malloc(total);
    if (!buffer)
    {
        return false;
    }
    size_t offset = 0;
    if (version >= ALIXFS2_VERSION)
    {
        alixfs_node_disk_v4_t disk = {
            .id = node->disk_id,
            .parent_id = parent_id,
            .type = node->type,
            .name_len = (uint32_t)name_len,
            .data_len = (uint32_t)data_len,
            .uid = node->uid,
            .gid = node->gid,
            .atime = node->atime,
            .mtime = node->mtime,
            .ctime = node->ctime
        };
        memcpy(buffer, &disk, sizeof(disk));
        offset = sizeof(disk);
    }
    else if (alixfs_version_has_ownership(version))
    {
        alixfs_node_disk_v3_t disk = {
            .id = node->disk_id,
            .parent_id = parent_id,
            .type = node->type,
            .name_len = (uint32_t)name_len,
            .data_len = (uint32_t)data_len,
            .uid = node->uid,
            .gid = node->gid
        };
        memcpy(buffer, &disk, sizeof(disk));
        offset = sizeof(disk);
    }
    else
    {
        alixfs_node_disk_v2_t disk = {
            .id = node->disk_id,
            .parent_id = parent_id,
            .type = node->type,
            .name_len = (uint32_t)name_len,
            .data_len = (uint32_t)data_len
        };
        memcpy(buffer, &disk, sizeof(disk));
        offset = sizeof(disk);
    }
    if (name_len > 0)
    {
        memcpy(buffer + offset, node->name, name_len);
        offset += name_len;
    }
    if (!metadata_only && data_len > 0 && node->data)
    {
        memcpy(buffer + offset, node->data, data_len);
    }
    if (!metadata_only) offset += data_len;
    alixfs_mode_disk_t *mode = (void *)(buffer + offset);
    *mode = (alixfs_mode_disk_t){ .magic = ALIXFS_MODE_MAGIC, .version = 1, .permissions = node->permissions & 0777u };
    *out_buf = buffer;
    *out_len = total;
    return true;
}

static bool alixfs_write_node(alixfs_mount_t *fs, vfs_node_t *node, bool force_all)
{
    /*
     * Write a single node payload to disk and update the in-memory chunk entry.
     *
     * The chunk table and header are not written here; VFS calls
     * `alixfs_mount_commit` after flushing nodes to persist metadata updates.
     */
    if (!fs || !node)
    {
        return true;
    }

    uint8_t *payload = NULL;
    size_t payload_len = 0;
    uint32_t node_id = UINT32_MAX;
    uint64_t dirty_seq = 0;
    size_t pending_bytes = 0;
    bool metadata_only = false;

    spinlock_lock(&node->data_lock);
    vfs_mapping_pull_locked(node);
    bool dirty = force_all;
    if (!dirty)
    {
        dirty = node->disk_meta_dirty || node->disk_data_dirty || node->disk_name_dirty;
        if (!dirty && node->disk_id == UINT32_MAX)
        {
            dirty = true;
        }
    }
    if (!dirty)
    {
        spinlock_unlock(&node->data_lock);
        return true;
    }

    dirty_seq = node->dirty_seq;
    pending_bytes = node->pending_dirty_bytes;
    if (!alixfs_assign_node_id(fs, node))
    {
        spinlock_unlock(&node->data_lock);
        return false;
    }
    node_id = node->disk_id;
    alixfs2_chunk_entry_t *entry = &fs->chunks[node_id];
    size_t name_len = alixfs_node_name_length(node);
    size_t data_len = (node->type == VFS_NODE_FILE || node->type == VFS_NODE_SYMLINK)
        ? node->size : 0;
    size_t stored_len;
    if (__builtin_add_overflow(alixfs_node_disk_header_size(fs->header.version), name_len, &stored_len) ||
        __builtin_add_overflow(stored_len, data_len, &stored_len) ||
        __builtin_add_overflow(stored_len, sizeof(alixfs_mode_disk_t), &stored_len) || stored_len > UINT32_MAX)
    { spinlock_unlock(&node->data_lock); return false; }
    /* Timestamp/ownership changes must not copy and rewrite an unchanged file. */
    metadata_only = !force_all && !node->disk_data_dirty && !node->disk_name_dirty &&
        entry->capacity > 0 && entry->length == stored_len;

    if (!alixfs_serialize_node(node, fs->header.version, metadata_only, &payload, &payload_len))
    {
        spinlock_unlock(&node->data_lock);
        return false;
    }
    spinlock_unlock(&node->data_lock);

    size_t aligned = alixfs_align_size(stored_len, fs->sector_size);
    uint64_t next_offset = entry->offset;
    uint32_t next_capacity = entry->capacity;
    bool relocated = false;
    if (entry->capacity < aligned)
    {
        if (!alixfs_chunk_allocate(fs, aligned, &next_offset, &next_capacity))
        {
            free(payload);
            return false;
        }
        relocated = true;
    }
    if (!alixfs_device_write(fs->device,
                              fs->sector_size,
                              next_offset,
                              payload,
                              metadata_only ? payload_len - sizeof(alixfs_mode_disk_t) : payload_len) ||
        (metadata_only && !alixfs_device_write(fs->device, fs->sector_size,
            next_offset + stored_len - sizeof(alixfs_mode_disk_t),
            payload + payload_len - sizeof(alixfs_mode_disk_t), sizeof(alixfs_mode_disk_t))))
    {
        if (relocated)
        {
            alixfs_chunk_release(fs, next_offset, next_capacity);
        }
        free(payload);
        return false;
    }
    if (relocated)
    {
        alixfs_chunk_release(fs, entry->offset, entry->capacity);
        entry->offset = next_offset;
        entry->capacity = next_capacity;
    }
    if (relocated || entry->length != stored_len)
    {
        entry->length = (uint32_t)stored_len;
        alixfs_mark_chunk_dirty(fs, node_id);
    }

    spinlock_lock(&node->data_lock);
    if (node->dirty_seq == dirty_seq)
    {
        node->dirty = false;
        node->disk_data_dirty = false;
        node->disk_meta_dirty = false;
        node->disk_name_dirty = false;
        node->pending_dirty_bytes = 0;
    }
    else if (pending_bytes > 0)
    {
        if (node->pending_dirty_bytes > pending_bytes)
        {
            node->pending_dirty_bytes -= pending_bytes;
        }
        else
        {
            node->pending_dirty_bytes = 0;
        }
    }
    spinlock_unlock(&node->data_lock);

    if (node->mount && pending_bytes > 0)
    {
        vfs_mount_t *mount = node->mount;
        spinlock_lock(&mount->dirty_lock);
        if (mount->dirty_bytes > pending_bytes)
        {
            mount->dirty_bytes -= pending_bytes;
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
    /*
     * Persist modified chunk table entries.
     *
     * Entries are tracked by a per-ID dirty bitmap so we can write only the
     * changed entries rather than rewriting the full table.
     */
    if (!fs || !fs->chunk_dirty_bitmap)
    {
        return true;
    }
    for (size_t offset = 0; offset < fs->chunk_table_bytes; offset += fs->sector_size)
    {
        size_t bytes = fs->chunk_table_bytes - offset;
        if (bytes > fs->sector_size)
        {
            bytes = fs->sector_size;
        }
        uint32_t first = (uint32_t)(offset / sizeof(alixfs2_chunk_entry_t));
        uint32_t end = (uint32_t)((offset + bytes) / sizeof(alixfs2_chunk_entry_t));
        bool dirty = false;
        for (uint32_t id = first; id < end; ++id)
        {
            dirty |= ((fs->chunk_dirty_bitmap[id / 8] >> (id % 8)) & 1u) != 0;
        }
        if (!dirty)
        {
            continue;
        }
        /* The complete table is resident: write each dirty sector once, without
         * a read/modify/write for each of its 32 individual chunk entries. */
        if (!alixfs_device_write(fs->device,
                                  fs->sector_size,
                                  fs->node_table_offset + offset,
                                  (uint8_t *)fs->chunks + offset,
                                  bytes))
        {
            return false;
        }
        for (uint32_t id = first; id < end; ++id)
        {
            alixfs_clear_chunk_dirty(fs, id);
        }
    }
    return true;
}

static bool alixfs_flush_header(alixfs_mount_t *fs)
{
    /*
     * Persist the on-disk header.
     *
     * The header includes the free list and data-region bookkeeping.
     */
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
    /*
     * Recursive flush for a mounted subtree.
     *
     * Only nodes that belong to the specific mount are flushed (so mount points
     * embedded under the tree are not traversed across device boundaries).
     */
    if (!node)
    {
        return true;
    }
    bool dirty = false;
    if (node->mount == mount)
    {
        dirty = force_all;
        if (!dirty)
        {
            spinlock_lock(&node->data_lock);
            dirty = node->disk_meta_dirty || node->disk_data_dirty || node->disk_name_dirty;
            if (!dirty && node->disk_id == UINT32_MAX)
            {
                dirty = true;
            }
            spinlock_unlock(&node->data_lock);
        }
        if (dirty && !alixfs_write_node(fs, node, force_all))
        {
            return false;
        }
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

/*
 * Create an AlixFS mount backend for a block device.
 *
 * This allocates in-memory tracking state; it does not read the disk until
 * `alixfs_mount_load` is called.
 */
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

/*
 * Destroy an AlixFS mount backend and free all associated in-memory state.
 */
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
    /*
     * Load the on-disk chunk table into memory and initialise the chunk dirty bitmap.
     */
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

/* Mount-only scratch stays on the heap, never on a process/DMA stack. Small
 * adjacent records share a bounded read-ahead window; large file payloads go
 * directly to their destination. Remember parent IDs from that first read so
 * linking the tree does not read every complete file a second time. */
#define ALIXFS_MOUNT_READ_AHEAD (64u * 1024u)
typedef struct
{
    vfs_node_t *node;
    uint32_t parent_id;
} alixfs_load_node_t;

typedef struct
{
    uint64_t offset;
    size_t length;
    uint8_t data[ALIXFS_MOUNT_READ_AHEAD];
    alixfs_load_node_t nodes[];
} alixfs_load_state_t;

static bool alixfs_mount_read(alixfs_mount_t *fs, alixfs_load_state_t *load,
                              uint64_t offset, void *buffer, size_t length)
{
    if (offset >= load->offset && offset - load->offset <= load->length &&
        length <= load->length - (size_t)(offset - load->offset))
    {
        memcpy(buffer, load->data + (size_t)(offset - load->offset), length);
        return true;
    }

    size_t sector_size = fs->sector_size;
    uint64_t device_bytes;
    if (!sector_size || sector_size > sizeof(load->data) ||
        __builtin_mul_overflow(fs->device->sector_count, (uint64_t)sector_size, &device_bytes))
    {
        return alixfs_device_read(fs->device, sector_size, offset, buffer, length);
    }
    uint64_t start = offset - offset % sector_size;
    size_t prefix = (size_t)(offset - start);
    size_t span = sizeof(load->data) / sector_size * sector_size;
    if (length > span - prefix)
    {
        return alixfs_device_read(fs->device, sector_size, offset, buffer, length);
    }
    if (start >= device_bytes || length > device_bytes - offset)
    {
        return false;
    }
    if (span > device_bytes - start) span = (size_t)(device_bytes - start);
    load->length = 0;
    if (!alixfs_device_read(fs->device, sector_size, start, load->data, span))
    {
        /* Read-ahead is speculative: an error beyond the requested record
         * must not make a previously readable filesystem fail to mount. */
        return alixfs_device_read(fs->device, sector_size, offset, buffer, length);
    }
    load->offset = start;
    load->length = span;
    memcpy(buffer, load->data + prefix, length);
    return true;
}

/*
 * Load filesystem metadata from disk and populate the mounted VFS subtree.
 *
 * - Reads the header and chunk table.
 * - Walks the node table and creates VFS nodes under `mount->mount_point`.
 * - Assigns persistent disk IDs for nodes to support later writeback.
 */
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
    uint32_t version = fs->header.version;
    if (memcmp(fs->header.magic, ALIXFS2_MAGIC, sizeof(fs->header.magic)) != 0 ||
        (version != ALIXFS2_VERSION &&
         version != ALIXFS2_VERSION_OWNERSHIP &&
         version != ALIXFS2_VERSION_LEGACY) ||
        fs->header.node_capacity == 0 || fs->header.root_id >= fs->header.node_capacity)
    {
        return false;
    }
    bool has_ownership = alixfs_version_has_ownership(version);
    bool has_times = (version >= ALIXFS2_VERSION);
    size_t node_header_size = alixfs_node_disk_header_size(version);
    fs->node_table_offset = fs->header_span;
    if (!alixfs_load_chunk_table(fs))
    {
        return false;
    }
    size_t nodes_bytes;
    if (__builtin_mul_overflow((size_t)fs->header.node_capacity, sizeof(alixfs_load_node_t), &nodes_bytes) ||
        nodes_bytes > SIZE_MAX - sizeof(alixfs_load_state_t))
    {
        return false;
    }
    alixfs_load_state_t *load = calloc(1, sizeof(*load) + nodes_bytes);
    if (!load) return false;
    load->nodes[fs->header.root_id].node = mount->mount_point;
    vfs_node_t *mount_root = mount->mount_point;
    spinlock_lock(&mount_root->data_lock);
    mount_root->disk_id = fs->header.root_id;
    mount_root->mount = mount;
    mount_root->allow_mutation = true;
    mount_root->uid = VFS_UID_ROOT;
    mount_root->gid = VFS_GID_ROOT;
    mount_root->permissions = 0777u;
    mount_root->atime = 0;
    mount_root->mtime = 0;
    mount_root->ctime = 0;
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
        if (entry->capacity == 0 || entry->length < node_header_size)
        {
            continue;
        }
        uint8_t *buffer = (uint8_t *)malloc(entry->length);
        if (!buffer)
        {
            free(load);
            return false;
        }
        if (!alixfs_mount_read(fs, load, entry->offset, buffer, entry->length))
        {
            free(buffer);
            free(load);
            return false;
        }
        alixfs_node_disk_v2_t disk_common;
        uint32_t node_uid = VFS_UID_ROOT;
        uint32_t node_gid = VFS_GID_ROOT;
        uint64_t node_atime = 0;
        uint64_t node_mtime = 0;
        uint64_t node_ctime = 0;
        if (has_times)
        {
            alixfs_node_disk_v4_t disk;
            memcpy(&disk, buffer, sizeof(disk));
            disk_common.id = disk.id;
            disk_common.parent_id = disk.parent_id;
            disk_common.type = disk.type;
            disk_common.name_len = disk.name_len;
            disk_common.data_len = disk.data_len;
            node_uid = disk.uid;
            node_gid = disk.gid;
            node_atime = disk.atime;
            node_mtime = disk.mtime;
            node_ctime = disk.ctime;
        }
        else if (has_ownership)
        {
            alixfs_node_disk_v3_t disk;
            memcpy(&disk, buffer, sizeof(disk));
            disk_common.id = disk.id;
            disk_common.parent_id = disk.parent_id;
            disk_common.type = disk.type;
            disk_common.name_len = disk.name_len;
            disk_common.data_len = disk.data_len;
            node_uid = disk.uid;
            node_gid = disk.gid;
        }
        else
        {
            memcpy(&disk_common, buffer, sizeof(disk_common));
        }
        if (disk_common.id != id)
        {
            free(buffer);
            continue;
        }
        size_t content_end;
        if (__builtin_add_overflow(node_header_size, (size_t)disk_common.name_len, &content_end) ||
            __builtin_add_overflow(content_end, (size_t)disk_common.data_len, &content_end) || content_end > entry->length)
        { free(buffer); free(load); return false; }
        uint32_t permissions = disk_common.type == VFS_NODE_FILE ? 0666u :
                               disk_common.type == VFS_NODE_BLOCK ? 0600u : 0777u;
        if (entry->length != content_end)
        {
            if (entry->length - content_end != sizeof(alixfs_mode_disk_t))
            { free(buffer); free(load); return false; }
            const alixfs_mode_disk_t *mode = (const void *)(buffer + content_end);
            if (mode->magic != ALIXFS_MODE_MAGIC || mode->version != 1 || (mode->permissions & ~0777u))
            { free(buffer); free(load); return false; }
            permissions = mode->permissions;
        }
        vfs_node_t *node = load->nodes[id].node;
        if (!node)
        {
            node = alixfs_new_node((vfs_node_type_t)disk_common.type);
            if (!node)
            {
                free(buffer);
                free(load);
                return false;
            }
            load->nodes[id].node = node;
        }
        load->nodes[id].parent_id = disk_common.parent_id;
        spinlock_lock(&node->data_lock);
        node->disk_id = id;
        node->mount = mount;
        node->allow_mutation = true;
        node->uid = node_uid;
        node->gid = node_gid;
        node->permissions = permissions;
        node->atime = node_atime;
        node->mtime = node_mtime;
        node->ctime = node_ctime;
        size_t offset = node_header_size;
        if (disk_common.name_len > 0 && id != fs->header.root_id)
        {
            char *name = (char *)malloc(disk_common.name_len + 1);
            if (!name)
            {
                spinlock_unlock(&node->data_lock);
                free(buffer);
                free(load);
                return false;
            }
            memcpy(name, buffer + offset, disk_common.name_len);
            name[disk_common.name_len] = '\0';
            if (node->name)
            {
                free(node->name);
            }
            node->name = name;
        }
        /* Old disks may contain the former mount-point spelling. Retain the
         * caller's mount point name, but always skip those on-disk bytes. */
        offset += disk_common.name_len;
        if ((node->type == VFS_NODE_FILE || node->type == VFS_NODE_SYMLINK) &&
            disk_common.data_len > 0)
        {
            if (!alixfs_ensure_capacity(node, disk_common.data_len))
            {
                spinlock_unlock(&node->data_lock);
                free(buffer);
                free(load);
                return false;
            }
            memcpy(node->data, buffer + offset, disk_common.data_len);
            node->size = disk_common.data_len;
            node->data[disk_common.data_len] = '\0';
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
        vfs_node_t *node = load->nodes[id].node;
        if (!node || id == fs->header.root_id)
        {
            continue;
        }
        uint32_t parent_id = load->nodes[id].parent_id;
        if (parent_id >= fs->header.node_capacity)
        {
            continue;
        }
        vfs_node_t *parent = load->nodes[parent_id].node;
        if (!parent)
        {
            continue;
        }
        node->parent = parent;
        node->next_sibling = parent->first_child;
        parent->first_child = node;
    }

    free(load);
    return true;
}

/*
 * Flush an entire subtree of VFS nodes to disk.
 *
 * This is called by VFS mount writeback when syncing a mounted filesystem.
 */
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

/*
 * Flush a single VFS node to disk.
 *
 * Used for targeted writeback (`vfs_flush_node`) and as a building block for
 * subtree flush.
 */
bool alixfs_mount_flush_single(alixfs_mount_t *fs,
                               vfs_node_t *node,
                               vfs_mount_t *mount,
                               bool force_all)
{
    (void)mount;
    if (!node)
    {
        return true;
    }
    bool ok = alixfs_write_node(fs, node, force_all);
    return ok;
}

/*
 * Commit filesystem metadata updates to disk (header + chunk table).
 */
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

/*
 * Release persistent storage associated with a node when it is deleted.
 *
 * Called by VFS when a mounted node is being freed and should be removed from
 * the on-disk chunk table/free lists.
 */
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

/*
 * Format a block device as a new AlixFS2 filesystem.
 */
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
    root_stub.uid = VFS_UID_ROOT;
    root_stub.gid = VFS_GID_ROOT;
    uint8_t *payload = NULL;
    size_t payload_len = 0;
    if (!alixfs_serialize_node(&root_stub, header.version, false, &payload, &payload_len))
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

/*
 * Snapshot lightweight mount state for callers that want to surface health.
 *
 * Currently exposes whether the in-memory header is dirty (useful for VFS
 * deciding if a full sync is still needed).
 */
void alixfs_mount_snapshot(const alixfs_mount_t *fs, bool *header_dirty)
{
    if (!fs || !header_dirty)
    {
        return;
    }
    *header_dirty = fs->header_dirty;
}

bool alixfs_mount_supports_times(const alixfs_mount_t *fs)
{
    if (!fs)
    {
        return false;
    }
    return fs->header.version >= ALIXFS2_VERSION;
}
