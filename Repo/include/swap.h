#ifndef ALIX_SWAP_H
#define ALIX_SWAP_H
#include "types.h"
#define USER_PAGE_SWAPPED ((paddr_t)4)
#define USER_PAGE_BUSY ((paddr_t)8)
bool swap_discover(void);
bool swap_available(void);
paddr_t swap_store(paddr_t physical);
bool swap_load(paddr_t token, paddr_t physical);
bool swap_retain(paddr_t token);
void swap_release(paddr_t token);
size_t swap_used_pages(void);
#endif
