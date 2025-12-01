#ifndef LIMITS_H
#define LIMITS_H

#ifdef TTF_HOST_BUILD
#include_next <limits.h>
#else
#define CHAR_BIT 8
#define INT_MAX 2147483647
#define INT_MIN (-INT_MAX - 1)
#define UINT_MAX 0xFFFFFFFFu
#define LONG_MAX 0x7fffffffffffffffL
#define LONG_MIN (-LONG_MAX - 1L)
#define ULONG_MAX 0xFFFFFFFFFFFFFFFFuL
#endif

#endif
