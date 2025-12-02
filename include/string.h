#ifndef STRING_H
#define STRING_H

#ifdef TTF_HOST_BUILD
#include_next <string.h>
#else
#include "types.h"

void *memcpy(void *dst, const void *src, size_t count);
void *memmove(void *dst, const void *src, size_t count);
void *memset(void *dst, int value, size_t count);
int memcmp(const void *a, const void *b, size_t count);
size_t strlen(const char *str);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, size_t n);
char *strcpy(char *dst, const char *src);
char *strncpy(char *dst, const char *src, size_t n);
char *strcat(char *dst, const char *src);
char *strchr(const char *str, int ch);
char *strrchr(const char *str, int ch);
int strcasecmp(const char *a, const char *b);
int strncasecmp(const char *a, const char *b, size_t n);
#endif

#endif
