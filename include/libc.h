#ifndef LIBC_H
#define LIBC_H

#include "types.h"

void *memset(void *dst, int value, size_t count);
void *memmove(void *dst, const void *src, size_t count);
size_t strlen(const char *str);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, size_t n);

#endif
