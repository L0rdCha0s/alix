#ifndef PAGING_H
#define PAGING_H

#include "types.h"

#define PAGING_MAX_EXTRA_PAGES 64

typedef struct paging_extra_page
{
    void *raw;
    void *aligned;
} paging_extra_page_t;

typedef struct paging_space
{
    uintptr_t cr3;
    void *allocation_base;
    size_t allocation_size;
    void *tables_base;
    paging_extra_page_t extra_pages[PAGING_MAX_EXTRA_PAGES];
    size_t extra_page_count;
} paging_space_t;

void paging_init(void);
bool paging_clone_kernel_space(paging_space_t *space);
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

#endif
