#ifndef LIMITS_H
#define LIMITS_H

#ifdef TTF_HOST_BUILD
#include_next <limits.h>
#else
#define CHAR_BIT 8
#define SCHAR_MIN (-128)
#define SCHAR_MAX 127
#define UCHAR_MAX 255
#if __CHAR_UNSIGNED__
#define CHAR_MIN 0
#define CHAR_MAX UCHAR_MAX
#else
#define CHAR_MIN SCHAR_MIN
#define CHAR_MAX SCHAR_MAX
#endif
#define SHRT_MIN (-32768)
#define SHRT_MAX 32767
#define USHRT_MAX 65535
#define LLONG_MAX 0x7fffffffffffffffLL
#define LLONG_MIN (-LLONG_MAX - 1LL)
#define ULLONG_MAX 0xffffffffffffffffULL
#define MB_LEN_MAX 1
/* Maximum native VFS path buffer size, including the terminating NUL. */
#define PATH_MAX 4096
#define INT_MAX 2147483647
#define INT_MIN (-INT_MAX - 1)
#define UINT_MAX 0xFFFFFFFFu
#define LONG_MAX 0x7fffffffffffffffL
#define LONG_MIN (-LONG_MAX - 1L)
#define ULONG_MAX 0xFFFFFFFFFFFFFFFFuL
#endif

#endif
