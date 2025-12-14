#ifndef USER_MEMORY_H
#define USER_MEMORY_H

#include "types.h"

void user_memory_init(void);
paddr_t user_memory_alloc(size_t bytes);
void user_memory_free(paddr_t addr, size_t bytes);
size_t user_memory_available(void);
bool user_memory_alloc_page(paddr_t *phys_out);
void user_memory_free_page(paddr_t phys);

#endif /* USER_MEMORY_H */
