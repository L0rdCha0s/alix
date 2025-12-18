#ifndef STDLIB_H
#define STDLIB_H

#ifdef TTF_HOST_BUILD
#include_next <stdlib.h>
#else
#include "types.h"

void *malloc(size_t size);
void *calloc(size_t count, size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);
int abs(int value);
int atoi(const char *str);
double atof(const char *str);
int rand(void);
void srand(unsigned int seed);
int setenv(const char *name, const char *value, int overwrite);
int unsetenv(const char *name);
char *getenv(const char *name);
void exit(int status);
#endif

#endif
