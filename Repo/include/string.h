#ifndef STRING_H
#define STRING_H

#ifdef TTF_HOST_BUILD
#include_next <string.h>
#else
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

void *memcpy(void *dst, const void *src, size_t count);
void *memmove(void *dst, const void *src, size_t count);
void *memset(void *dst, int value, size_t count);
int memcmp(const void *a, const void *b, size_t count);
void *memchr(const void *src, int ch, size_t count);
size_t strlen(const char *str);
size_t strnlen(const char *str, size_t maximum);
char *strdup(const char *str);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, size_t n);
char *strcpy(char *dst, const char *src);
char *strncpy(char *dst, const char *src, size_t n);
char *strcat(char *dst, const char *src);
char *strncat(char *dst, const char *src, size_t n);
int strcoll(const char *left, const char *right);
size_t strxfrm(char *destination, const char *source, size_t size);
char *strchr(const char *str, int ch);
char *strrchr(const char *str, int ch);
char *strstr(const char *haystack, const char *needle);
int strcasecmp(const char *a, const char *b);
int strncasecmp(const char *a, const char *b, size_t n);
char *strerror(int errnum);
int strerror_r(int errnum, char *buffer, size_t capacity);
#ifdef __cplusplus
}
#endif
#endif

#endif
