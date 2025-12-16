#ifndef IOREMAP_H
#define IOREMAP_H

#include "types.h"

#include <stddef.h>

void ioremap_init(void);
void *ioremap(paddr_t physical_addr, size_t length);
void *ioremap_cached(paddr_t physical_addr, size_t length);

#endif /* IOREMAP_H */
