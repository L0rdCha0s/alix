#ifndef PAGING_H
#define PAGING_H

#include "types.h"
#include <stdbool.h>

typedef struct paging_space
{
    uintptr_t cr3;
    void *allocation_base;
    size_t allocation_size;
    void *tables_base;
} paging_space_t;

void paging_init(void);
bool paging_clone_kernel_space(paging_space_t *space);
void paging_destroy_space(paging_space_t *space);
uintptr_t paging_kernel_cr3(void);

#endif
