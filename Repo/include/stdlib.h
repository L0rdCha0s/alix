#ifndef STDLIB_H
#define STDLIB_H

#ifdef TTF_HOST_BUILD
#include_next <stdlib.h>
#else
#include "types.h"
#include <stddef.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define RAND_MAX 32767
/* Both installed locales (C and POSIX) use single-byte ASCII conversion. */
#define MB_CUR_MAX ((size_t)1)
typedef struct { int quot, rem; } div_t;
typedef struct { long quot, rem; } ldiv_t;
typedef struct { long long quot, rem; } lldiv_t;

#ifdef __cplusplus
extern "C" {
#endif

void *malloc(size_t size);
void *calloc(size_t count, size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);
int mblen(const char *text, size_t length);
int mbtowc(wchar_t *output, const char *text, size_t length);
int wctomb(char *output, wchar_t value);
size_t mbstowcs(wchar_t *output, const char *text, size_t capacity);
size_t wcstombs(char *output, const wchar_t *text, size_t capacity);
void *aligned_alloc(size_t alignment, size_t size);
int posix_memalign(void **result, size_t alignment, size_t size);
int abs(int value);
long labs(long value);
long long llabs(long long value);
div_t div(int numerator, int denominator);
ldiv_t ldiv(long numerator, long denominator);
lldiv_t lldiv(long long numerator, long long denominator);
int atoi(const char *str);
long atol(const char *str);
long long atoll(const char *str);
double atof(const char *str);
long strtol(const char *str, char **end, int base);
long long strtoll(const char *str, char **end, int base);
unsigned long strtoul(const char *str, char **end, int base);
unsigned long long strtoull(const char *str, char **end, int base);
float strtof(const char *str, char **end);
double strtod(const char *str, char **end);
long double strtold(const char *str, char **end);
int rand(void);
void srand(unsigned int seed);
int setenv(const char *name, const char *value, int overwrite);
int unsetenv(const char *name);
char *getenv(const char *name);
int system(const char *command);
void exit(int status);
void abort(void) __attribute__((noreturn));
void _Exit(int status) __attribute__((noreturn));
int atexit(void (*function)(void));
int at_quick_exit(void (*function)(void));
void quick_exit(int status) __attribute__((noreturn));
void *bsearch(const void *key, const void *base, size_t count, size_t width,
              int (*compare)(const void *, const void *));
void qsort(void *base, size_t count, size_t width,
            int (*compare)(const void *, const void *));
#ifdef __cplusplus
}
#endif
#endif

#endif
