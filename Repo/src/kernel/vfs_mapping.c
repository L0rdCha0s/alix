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
    paddr_t *pages;
    struct vfs_file_mapping *next;
};

void vfs_mapping_pull_locked(vfs_node_t *node)
{
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
    if (node->mount) {
        spinlock_lock(&node->mount->dirty_lock);
        node->mount->dirty = true;
        ++node->mount->dirty_seq;
        spinlock_unlock(&node->mount->dirty_lock);
    }
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
}

int vfs_mapping_create(vfs_node_t *node, uint64_t offset, size_t length,
                       bool shared, fd_description_t *owner, vfs_file_mapping_t **out)
{
    *out = NULL;
    if (!node || !owner || !length || (offset & (FILE_PAGE-1)) ||
        (length & (FILE_PAGE-1)) || offset > INT64_MAX || length > INT64_MAX-offset) return -EINVAL;
    vfs_file_mapping_t *m = calloc(1, sizeof(*m));
    if (!m) return -ENOMEM;
    m->count = length / FILE_PAGE; m->shared = shared; m->owner = owner;
    m->pages = calloc(m->count, sizeof(*m->pages));
    if (!m->pages) { free(m); return -ENOMEM; }
    vfs_node_retain(node);
    m->node = node;
    spinlock_lock(&node->data_lock);
    vfs_mapping_pull_locked(node);
    int error = node->type != VFS_NODE_FILE || node->read_cb || node->write_cb ? -ENOTSUP :
        offset >= node->size || length - FILE_PAGE >= node->size - offset ? -ENXIO : 0;
    for (size_t i = 0; !error && i < m->count; ++i) {
        size_t at = (size_t)offset + i * FILE_PAGE;
        vfs_mapped_page_t *p = node->mapped_pages;
        if (shared) while (p && p->offset != at) p = p->next;
        else p = NULL;
        if (p) { m->pages[i] = p->physical; continue; }
        paddr_t physical = 0;
        if (!user_memory_alloc_page(&physical)) { error = -ENOMEM; break; }
        size_t n = node->size - at;
        if (n > FILE_PAGE) n = FILE_PAGE;
        memset(phys_to_virt(physical), 0, FILE_PAGE);
        memcpy(phys_to_virt(physical), node->data + at, n);
        if (shared) {
            p = calloc(1, sizeof(*p));
            if (!p) { user_memory_free_page(physical); error = -ENOMEM; break; }
            p->offset = at; p->physical = physical; p->next = node->mapped_pages;
            if (!node->mapped_pages && node->mount) {
                spinlock_lock(&node->mount->dirty_lock);
                ++node->mount->mapped_files;
                spinlock_unlock(&node->mount->dirty_lock);
            }
            node->mapped_pages = p;
        }
        m->pages[i] = physical;
    }
    if (!error) { m->next = node->mappings; node->mappings = m; }
    else if (!node->mappings) vfs_mapping_destroy_locked(node);
    spinlock_unlock(&node->data_lock);
    if (error) {
        if (!shared) for (size_t i = 0; i < m->count; ++i)
            if (m->pages[i]) user_memory_free_page(m->pages[i]);
        vfs_node_release_owned(node); free(m->pages); free(m);
    } else *out = m;
    return error;
}

void vfs_mapping_release(vfs_file_mapping_t *m)
{
    if (!m) return;
    vfs_node_t *node = m->node;
    spinlock_lock(&node->data_lock);
    vfs_mapping_pull_locked(node);
    vfs_file_mapping_t **link = &node->mappings;
    while (*link && *link != m) link = &(*link)->next;
    if (*link) *link = m->next;
    if (!node->mappings) vfs_mapping_destroy_locked(node);
    spinlock_unlock(&node->data_lock);
    if (!m->shared) for (size_t i = 0; i < m->count; ++i) user_memory_free_page(m->pages[i]);
    vfs_node_release_owned(node); free(m->pages); free(m);
}
paddr_t vfs_mapping_page(const vfs_file_mapping_t *m, size_t index)
{ return m && index < m->count ? m->pages[index] : 0; }
int vfs_mapping_sync(vfs_file_mapping_t *m)
{
    if (!m || !m->shared) return 0;
    spinlock_lock(&m->node->data_lock);
    vfs_mapping_pull_locked(m->node);
    spinlock_unlock(&m->node->data_lock);
    return vfs_flush_node(m->node) ? 0 : -EIO;
}
