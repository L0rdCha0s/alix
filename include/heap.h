#ifndef HEAP_H
#define HEAP_H

#include "types.h"

void heap_init(void);

void *malloc(size_t size);
void free(void *ptr);
void *calloc(size_t count, size_t size);
void *realloc(void *ptr, size_t size);

#endif
