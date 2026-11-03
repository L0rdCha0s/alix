#ifndef PAGING_H
#define PAGING_H

#include "types.h"
#include "spinlock.h"

typedef struct paging_extra_page
{
    void *raw;
    void *aligned;
    struct paging_extra_page *next;
} paging_extra_page_t;

typedef struct paging_space
{
    uintptr_t cr3;
    void *allocation_base;
    size_t allocation_size;
    void *tables_base;
    paging_extra_page_t *extra_pages;
    size_t extra_page_count;
    uint32_t active_cpu_mask;
    uint64_t resident_user_pages, peak_resident_user_pages;
    spinlock_t lock;
    bool lock_inited;
} paging_space_t;

/* Value-only token: no requesting thread's stack is retained by another CPU. */
typedef struct paging_tlb_ticket
{
    uint64_t generation;
    uint32_t cpu_mask;
} paging_tlb_ticket_t;

void paging_init(void);
bool paging_clone_kernel_space(paging_space_t *space);
bool paging_share_kernel_space(paging_space_t *space);
void paging_destroy_space(paging_space_t *space);
uintptr_t paging_kernel_cr3(void);
bool paging_map_user_page(paging_space_t *space,
                          uintptr_t virtual_addr,
                          uintptr_t physical_addr,
                          bool writable,
                          bool executable);
bool paging_map_user_range(paging_space_t *space,
                           uintptr_t virtual_addr,
                           uintptr_t physical_addr,
                           size_t length,
                           bool writable,
                           bool executable);
bool paging_unmap_user_page(paging_space_t *space,
                            uintptr_t virtual_addr);
/* Prepare all page tables before a VM transaction changes any leaf entry.
 * The write helper never allocates or broadcasts; caller flushes after commit. */
bool paging_prepare_user_range(paging_space_t *space, uintptr_t address, size_t length);
bool paging_write_prepared_user_page(paging_space_t *space, uintptr_t address,
                                     paddr_t physical, bool present, bool writable,
                                     bool executable);
bool paging_map_kernel_ioremap_range(uintptr_t virtual_addr,
                                     paddr_t physical_addr,
                                     size_t length,
                                     bool cache_disable);
bool paging_set_kernel_range_writable(uintptr_t virtual_addr,
                                      size_t length,
                                      bool writable);
bool paging_set_kernel_range_writable_force(uintptr_t virtual_addr,
                                            size_t length,
                                            bool writable);
void paging_flush_space_tlb(paging_space_t *space);
paging_tlb_ticket_t paging_request_tlb_flush(paging_space_t *space);
bool paging_tlb_flush_complete(paging_tlb_ticket_t ticket);
void paging_flush_global_tlb(void);
void paging_handle_remote_tlb_flush(void);
/* AP bring-up uses its resolved index before smp_current_cpu_index is valid. */
void paging_initialize_cpu_tlb(uint32_t cpu_index);
void paging_user_residency(paging_space_t *space, uint64_t *current, uint64_t *peak);
void paging_set_clone_trace(bool enable);
bool paging_global_lock_held_by_current_cpu(void);

#endif
