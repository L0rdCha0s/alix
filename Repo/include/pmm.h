#ifndef PMM_H
#define PMM_H

#include "types.h"

typedef enum
{
    PMM_ALLOC_ANY = 0,
    PMM_ALLOC_DMA32 = 1
} pmm_alloc_flags_t;

void pmm_init(void);
bool pmm_is_ready(void);

bool pmm_alloc_range(size_t bytes,
                     size_t alignment,
                     pmm_alloc_flags_t flags,
                     paddr_t *out_base);
bool pmm_alloc_page(pmm_alloc_flags_t flags, paddr_t *out_base);

void pmm_free_range(paddr_t base, size_t bytes);
void pmm_free_page(paddr_t base);

void pmm_reserve_range(paddr_t base, size_t bytes);
size_t pmm_available_bytes(void);

#endif /* PMM_H */
