#include "vfs_mapping.h"
#include "vfs_internal.h"
#include "physmem.h"
#include "heap.h"
#include "libc.h"
#include "errno.h"
#include "timekeeping.h"
#include "user_memory.h"

#define FILE_PAGE 4096u
/* Cached shared pages are stable until every mapping descriptor has retired.
 * VM references survive leaf removal until the TLB journal has completed. */
typedef struct vfs_mapped_page {
    size_t offset;
    paddr_t physical;
    struct vfs_mapped_page *next;
} vfs_mapped_page_t;
struct vfs_file_mapping {
    vfs_node_t *node;
    fd_description_t *owner; /* registry borrowed; unlink before owner is freed */
    size_t count;
    bool shared;
    bool writable;
    size_t offset;
    paddr_t *pages;
    struct vfs_file_mapping *next;
};

void vfs_mapping_pull_locked(vfs_node_t *node)
{
    /* Read-only library mappings cannot dirty their file. In particular,
     * retaining a node or reading one byte must not compare a whole DSO. */
    if (!node->mapped_writers) return;
    bool changed = false;
    for (vfs_mapped_page_t *p = node->mapped_pages; p; p = p->next) {
        if (p->offset >= node->size) continue;
        size_t n = node->size - p->offset;
        if (n > FILE_PAGE) n = FILE_PAGE;
        void *source = phys_to_virt(p->physical);
        if (memcmp(node->data + p->offset, source, n)) {
            memcpy(node->data + p->offset, source, n);
            changed = true;
        }
    }
    if (!changed) return;
    node->dirty = node->disk_data_dirty = true;
    ++node->dirty_seq;
    node->mtime = node->ctime = timekeeping_now_seconds();
    vfs_queue_dirty_node(node);
}

void vfs_mapping_push_locked(vfs_node_t *node, size_t offset, size_t count)
{
    for (vfs_mapped_page_t *p = node->mapped_pages; p; p = p->next) {
        size_t low = p->offset > offset ? p->offset : offset;
        size_t high = p->offset + FILE_PAGE < offset + count ? p->offset + FILE_PAGE : offset + count;
        if (high > low) memcpy((char *)phys_to_virt(p->physical) + low - p->offset,
                              node->data + low, high - low);
    }
}

bool vfs_mapping_busy_locked(vfs_node_t *node)
{
    for (vfs_file_mapping_t *m = node->mappings; m; m = m->next)
        if (fd_description_referenced(m->owner)) return true;
    return false;
}

void vfs_mapping_destroy_locked(vfs_node_t *node)
{
    if (node->mapped_pages && node->mount) {
        spinlock_lock(&node->mount->dirty_lock);
        --node->mount->mapped_files;
        spinlock_unlock(&node->mount->dirty_lock);
    }
    while (node->mapped_pages) {
        vfs_mapped_page_t *p = node->mapped_pages;
        node->mapped_pages = p->next;
        user_memory_free_page(p->physical);
        free(p);
    }
    free(node->mapped_page_index);
    node->mapped_page_index = NULL;
    node->mapped_page_capacity = 0;
}

/* Node data_lock held. All source bytes are already resident in the VFS;
 * this is also safe in a user fault with interrupts disabled: no storage wait,
 * user address, process stack, or cross-thread request is involved. */
static paddr_t vfs_mapping_shared_page_locked(vfs_node_t *node, size_t at)
{
    size_t slot = at / FILE_PAGE;
    if (slot >= node->mapped_page_capacity || at >= node->size) return 0;
    vfs_mapped_page_t *p = node->mapped_page_index[slot];
    if (p) return p->physical;
    p = calloc(1, sizeof(*p));
    if (!p) return 0;
    if (!user_memory_alloc_page(&p->physical)) { free(p); return 0; }
    size_t n = node->size - at;
    if (n > FILE_PAGE) n = FILE_PAGE;
    void *data = phys_to_virt(p->physical);
    memcpy(data, node->data + at, n);
    if (n < FILE_PAGE) memset((char *)data + n, 0, FILE_PAGE - n);
    p->offset = at;
    if (!node->mapped_pages && node->mount) {
        spinlock_lock(&node->mount->dirty_lock);
        ++node->mount->mapped_files;
        spinlock_unlock(&node->mount->dirty_lock);
    }
    p->next = node->mapped_pages;
    node->mapped_pages = p;
    node->mapped_page_index[slot] = p;
    return p->physical;
}

int vfs_mapping_create_access(vfs_node_t *node, uint64_t offset, size_t length,
                       bool shared, bool writable, fd_description_t *owner, vfs_file_mapping_t **out)
{
    *out = NULL;
    if (!node || !owner || !length || (offset & (FILE_PAGE-1)) ||
        (length & (FILE_PAGE-1)) || offset > INT64_MAX || length > INT64_MAX-offset) return -EINVAL;
    vfs_file_mapping_t *m = calloc(1, sizeof(*m));
    if (!m) return -ENOMEM;
    m->count = length / FILE_PAGE; m->shared = shared; m->owner = owner;
    m->writable = shared && writable; m->offset = (size_t)offset;
    m->pages = calloc(m->count, sizeof(*m->pages));
    if (!m->pages) { free(m); return -ENOMEM; }
    vfs_node_retain(node);
    m->node = node;
    spinlock_lock(&node->data_lock);
    vfs_mapping_pull_locked(node);
    int error = node->type != VFS_NODE_FILE || node->read_cb || node->write_cb ? -ENOTSUP :
        offset >= node->size || length - FILE_PAGE >= node->size - offset ? -ENXIO : 0;
    if (!error && shared) {
        size_t required = ((size_t)offset + length) / FILE_PAGE;
        if (required > node->mapped_page_capacity) {
            size_t capacity = node->mapped_page_capacity ? node->mapped_page_capacity : 16;
            while (capacity < required && capacity <= SIZE_MAX / 2) capacity *= 2;
            if (capacity < required || capacity > SIZE_MAX / sizeof(*node->mapped_page_index)) error = -ENOMEM;
            else {
                vfs_mapped_page_t **index = realloc(node->mapped_page_index, capacity * sizeof(*index));
                if (!index) error = -ENOMEM;
                else {
                    memset(index + node->mapped_page_capacity, 0,
                           (capacity - node->mapped_page_capacity) * sizeof(*index));
                    node->mapped_page_index = index;
                    node->mapped_page_capacity = capacity;
                }
            }
        }
    }
    for (size_t i = 0; !error && i < m->count; ++i) {
        size_t at = (size_t)offset + i * FILE_PAGE;
        if (shared) {
            /* Immutable mappings populate a cache page on first access. */
            if (!writable) continue;
            m->pages[i] = vfs_mapping_shared_page_locked(node, at);
            if (!m->pages[i]) error = -ENOMEM;
            continue;
        }
        paddr_t physical = 0;
        if (!user_memory_alloc_page(&physical)) { error = -ENOMEM; break; }
        size_t n = node->size - at;
        if (n > FILE_PAGE) n = FILE_PAGE;
        memset(phys_to_virt(physical), 0, FILE_PAGE);
        memcpy(phys_to_virt(physical), node->data + at, n);
        m->pages[i] = physical;
    }
    if (!error) {
        m->next = node->mappings; node->mappings = m;
        if (m->writable && node->mapped_writers++ == 0 && node->mount) {
            spinlock_lock(&node->mount->dirty_lock);
            node->mapped_writer_next = node->mount->mapped_writer_head;
            node->mount->mapped_writer_head = node;
            spinlock_unlock(&node->mount->dirty_lock);
        }
    }
    else if (!node->mappings) vfs_mapping_destroy_locked(node);
    spinlock_unlock(&node->data_lock);
    if (error) {
        if (!shared) for (size_t i = 0; i < m->count; ++i)
            if (m->pages[i]) user_memory_free_page(m->pages[i]);
        vfs_node_release_owned(node); free(m->pages); free(m);
    } else *out = m;
    return error;
}

int vfs_mapping_create(vfs_node_t *node, uint64_t offset, size_t length,
                       bool shared, fd_description_t *owner, vfs_file_mapping_t **out)
{ return vfs_mapping_create_access(node, offset, length, shared, true, owner, out); }

void vfs_mapping_release(vfs_file_mapping_t *m)
{
    if (!m) return;
    vfs_node_t *node = m->node;
    spinlock_lock(&node->data_lock);
    vfs_mapping_pull_locked(node);
    if (m->writable && --node->mapped_writers == 0 && node->mount) {
        spinlock_lock(&node->mount->dirty_lock);
        vfs_node_t **link = &node->mount->mapped_writer_head;
        while (*link && *link != node) link = &(*link)->mapped_writer_next;
        if (*link) *link = node->mapped_writer_next;
        node->mapped_writer_next = NULL;
        spinlock_unlock(&node->mount->dirty_lock);
    }
    vfs_file_mapping_t **link = &node->mappings;
    while (*link && *link != m) link = &(*link)->next;
    if (*link) *link = m->next;
    if (!node->mappings) vfs_mapping_destroy_locked(node);
    spinlock_unlock(&node->data_lock);
    if (!m->shared) for (size_t i = 0; i < m->count; ++i) user_memory_free_page(m->pages[i]);
    vfs_node_release_owned(node); free(m->pages); free(m);
}
paddr_t vfs_mapping_page(const vfs_file_mapping_t *m, size_t index)
{
    if (!m || index >= m->count) return 0;
    if (!m->shared) return m->pages[index];
    spinlock_lock(&m->node->data_lock);
    paddr_t page = m->pages[index];
    if (!page) {
        page = vfs_mapping_shared_page_locked(m->node, m->offset + index * FILE_PAGE);
        m->pages[index] = page;
    }
    spinlock_unlock(&m->node->data_lock);
    return page;
}
int vfs_mapping_sync(vfs_file_mapping_t *m)
{
    if (!m || !m->shared) return 0;
    spinlock_lock(&m->node->data_lock);
    vfs_mapping_pull_locked(m->node);
    spinlock_unlock(&m->node->data_lock);
    return vfs_flush_node(m->node) ? 0 : -EIO;
}
