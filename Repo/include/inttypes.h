#ifndef ALIX_INTTYPES_H
#define ALIX_INTTYPES_H

#ifdef TTF_HOST_BUILD
#include_next <inttypes.h>
#else
#include <stdint.h>
#include <stddef.h>

#if __INTMAX_WIDTH__ != 64 || __INTPTR_WIDTH__ != 64 || __SIZEOF_LONG__ != 8
#error "Alix inttypes requires the native LP64 ABI"
#endif

#define _ALIX_INTFMT_8 "hh"
#define _ALIX_INTFMT_16 "h"
#define _ALIX_INTFMT_32 ""
#define _ALIX_INTFMT_64 "l"

/* printf promotes narrow integer values to int; scanf preserves pointer width. */
#define _ALIX_PRINT_FMT_8 ""
#define _ALIX_PRINT_FMT_16 ""
#define _ALIX_PRINT_FMT_32 ""
#define _ALIX_PRINT_FMT_64 "l"

/* FAST types differ between the native GCC and Clang compilers. */
#if __INT_FAST8_WIDTH__ == 8
#define _ALIX_INTFMT_FAST8 _ALIX_INTFMT_8
#define _ALIX_PRINT_FMT_FAST8 _ALIX_PRINT_FMT_8
#elif __INT_FAST8_WIDTH__ == 16
#define _ALIX_INTFMT_FAST8 _ALIX_INTFMT_16
#define _ALIX_PRINT_FMT_FAST8 _ALIX_PRINT_FMT_16
#elif __INT_FAST8_WIDTH__ == 32
#define _ALIX_INTFMT_FAST8 _ALIX_INTFMT_32
#define _ALIX_PRINT_FMT_FAST8 _ALIX_PRINT_FMT_32
#elif __INT_FAST8_WIDTH__ == 64
#define _ALIX_INTFMT_FAST8 _ALIX_INTFMT_64
#define _ALIX_PRINT_FMT_FAST8 _ALIX_PRINT_FMT_64
#else
#error "Unsupported native int_fast8_t width"
#endif

/* FAST types differ between the native GCC and Clang compilers. */
#if __INT_FAST16_WIDTH__ == 8
#define _ALIX_INTFMT_FAST16 _ALIX_INTFMT_8
#define _ALIX_PRINT_FMT_FAST16 _ALIX_PRINT_FMT_8
#elif __INT_FAST16_WIDTH__ == 16
#define _ALIX_INTFMT_FAST16 _ALIX_INTFMT_16
#define _ALIX_PRINT_FMT_FAST16 _ALIX_PRINT_FMT_16
#elif __INT_FAST16_WIDTH__ == 32
#define _ALIX_INTFMT_FAST16 _ALIX_INTFMT_32
#define _ALIX_PRINT_FMT_FAST16 _ALIX_PRINT_FMT_32
#elif __INT_FAST16_WIDTH__ == 64
#define _ALIX_INTFMT_FAST16 _ALIX_INTFMT_64
#define _ALIX_PRINT_FMT_FAST16 _ALIX_PRINT_FMT_64
#else
#error "Unsupported native int_fast16_t width"
#endif

/* FAST types differ between the native GCC and Clang compilers. */
#if __INT_FAST32_WIDTH__ == 8
#define _ALIX_INTFMT_FAST32 _ALIX_INTFMT_8
#define _ALIX_PRINT_FMT_FAST32 _ALIX_PRINT_FMT_8
#elif __INT_FAST32_WIDTH__ == 16
#define _ALIX_INTFMT_FAST32 _ALIX_INTFMT_16
#define _ALIX_PRINT_FMT_FAST32 _ALIX_PRINT_FMT_16
#elif __INT_FAST32_WIDTH__ == 32
#define _ALIX_INTFMT_FAST32 _ALIX_INTFMT_32
#define _ALIX_PRINT_FMT_FAST32 _ALIX_PRINT_FMT_32
#elif __INT_FAST32_WIDTH__ == 64
#define _ALIX_INTFMT_FAST32 _ALIX_INTFMT_64
#define _ALIX_PRINT_FMT_FAST32 _ALIX_PRINT_FMT_64
#else
#error "Unsupported native int_fast32_t width"
#endif

/* FAST types differ between the native GCC and Clang compilers. */
#if __INT_FAST64_WIDTH__ == 8
#define _ALIX_INTFMT_FAST64 _ALIX_INTFMT_8
#define _ALIX_PRINT_FMT_FAST64 _ALIX_PRINT_FMT_8
#elif __INT_FAST64_WIDTH__ == 16
#define _ALIX_INTFMT_FAST64 _ALIX_INTFMT_16
#define _ALIX_PRINT_FMT_FAST64 _ALIX_PRINT_FMT_16
#elif __INT_FAST64_WIDTH__ == 32
#define _ALIX_INTFMT_FAST64 _ALIX_INTFMT_32
#define _ALIX_PRINT_FMT_FAST64 _ALIX_PRINT_FMT_32
#elif __INT_FAST64_WIDTH__ == 64
#define _ALIX_INTFMT_FAST64 _ALIX_INTFMT_64
#define _ALIX_PRINT_FMT_FAST64 _ALIX_PRINT_FMT_64
#else
#error "Unsupported native int_fast64_t width"
#endif

/* Exact-width integer formats. */
#define PRId8 _ALIX_PRINT_FMT_8 "d"
#define PRIi8 _ALIX_PRINT_FMT_8 "i"
#define PRIo8 _ALIX_PRINT_FMT_8 "o"
#define PRIu8 _ALIX_PRINT_FMT_8 "u"
#define PRIx8 _ALIX_PRINT_FMT_8 "x"
#define PRIX8 _ALIX_PRINT_FMT_8 "X"
#define SCNd8 _ALIX_INTFMT_8 "d"
#define SCNi8 _ALIX_INTFMT_8 "i"
#define SCNo8 _ALIX_INTFMT_8 "o"
#define SCNu8 _ALIX_INTFMT_8 "u"
#define SCNx8 _ALIX_INTFMT_8 "x"
#define PRId16 _ALIX_PRINT_FMT_16 "d"
#define PRIi16 _ALIX_PRINT_FMT_16 "i"
#define PRIo16 _ALIX_PRINT_FMT_16 "o"
#define PRIu16 _ALIX_PRINT_FMT_16 "u"
#define PRIx16 _ALIX_PRINT_FMT_16 "x"
#define PRIX16 _ALIX_PRINT_FMT_16 "X"
#define SCNd16 _ALIX_INTFMT_16 "d"
#define SCNi16 _ALIX_INTFMT_16 "i"
#define SCNo16 _ALIX_INTFMT_16 "o"
#define SCNu16 _ALIX_INTFMT_16 "u"
#define SCNx16 _ALIX_INTFMT_16 "x"
#define PRId32 _ALIX_PRINT_FMT_32 "d"
#define PRIi32 _ALIX_PRINT_FMT_32 "i"
#define PRIo32 _ALIX_PRINT_FMT_32 "o"
#define PRIu32 _ALIX_PRINT_FMT_32 "u"
#define PRIx32 _ALIX_PRINT_FMT_32 "x"
#define PRIX32 _ALIX_PRINT_FMT_32 "X"
#define SCNd32 _ALIX_INTFMT_32 "d"
#define SCNi32 _ALIX_INTFMT_32 "i"
#define SCNo32 _ALIX_INTFMT_32 "o"
#define SCNu32 _ALIX_INTFMT_32 "u"
#define SCNx32 _ALIX_INTFMT_32 "x"
#define PRId64 _ALIX_PRINT_FMT_64 "d"
#define PRIi64 _ALIX_PRINT_FMT_64 "i"
#define PRIo64 _ALIX_PRINT_FMT_64 "o"
#define PRIu64 _ALIX_PRINT_FMT_64 "u"
#define PRIx64 _ALIX_PRINT_FMT_64 "x"
#define PRIX64 _ALIX_PRINT_FMT_64 "X"
#define SCNd64 _ALIX_INTFMT_64 "d"
#define SCNi64 _ALIX_INTFMT_64 "i"
#define SCNo64 _ALIX_INTFMT_64 "o"
#define SCNu64 _ALIX_INTFMT_64 "u"
#define SCNx64 _ALIX_INTFMT_64 "x"

/* LEAST integer formats. */
#define PRIdLEAST8 _ALIX_PRINT_FMT_8 "d"
#define PRIiLEAST8 _ALIX_PRINT_FMT_8 "i"
#define PRIoLEAST8 _ALIX_PRINT_FMT_8 "o"
#define PRIuLEAST8 _ALIX_PRINT_FMT_8 "u"
#define PRIxLEAST8 _ALIX_PRINT_FMT_8 "x"
#define PRIXLEAST8 _ALIX_PRINT_FMT_8 "X"
#define SCNdLEAST8 _ALIX_INTFMT_8 "d"
#define SCNiLEAST8 _ALIX_INTFMT_8 "i"
#define SCNoLEAST8 _ALIX_INTFMT_8 "o"
#define SCNuLEAST8 _ALIX_INTFMT_8 "u"
#define SCNxLEAST8 _ALIX_INTFMT_8 "x"
#define PRIdLEAST16 _ALIX_PRINT_FMT_16 "d"
#define PRIiLEAST16 _ALIX_PRINT_FMT_16 "i"
#define PRIoLEAST16 _ALIX_PRINT_FMT_16 "o"
#define PRIuLEAST16 _ALIX_PRINT_FMT_16 "u"
#define PRIxLEAST16 _ALIX_PRINT_FMT_16 "x"
#define PRIXLEAST16 _ALIX_PRINT_FMT_16 "X"
#define SCNdLEAST16 _ALIX_INTFMT_16 "d"
#define SCNiLEAST16 _ALIX_INTFMT_16 "i"
#define SCNoLEAST16 _ALIX_INTFMT_16 "o"
#define SCNuLEAST16 _ALIX_INTFMT_16 "u"
#define SCNxLEAST16 _ALIX_INTFMT_16 "x"
#define PRIdLEAST32 _ALIX_PRINT_FMT_32 "d"
#define PRIiLEAST32 _ALIX_PRINT_FMT_32 "i"
#define PRIoLEAST32 _ALIX_PRINT_FMT_32 "o"
#define PRIuLEAST32 _ALIX_PRINT_FMT_32 "u"
#define PRIxLEAST32 _ALIX_PRINT_FMT_32 "x"
#define PRIXLEAST32 _ALIX_PRINT_FMT_32 "X"
#define SCNdLEAST32 _ALIX_INTFMT_32 "d"
#define SCNiLEAST32 _ALIX_INTFMT_32 "i"
#define SCNoLEAST32 _ALIX_INTFMT_32 "o"
#define SCNuLEAST32 _ALIX_INTFMT_32 "u"
#define SCNxLEAST32 _ALIX_INTFMT_32 "x"
#define PRIdLEAST64 _ALIX_PRINT_FMT_64 "d"
#define PRIiLEAST64 _ALIX_PRINT_FMT_64 "i"
#define PRIoLEAST64 _ALIX_PRINT_FMT_64 "o"
#define PRIuLEAST64 _ALIX_PRINT_FMT_64 "u"
#define PRIxLEAST64 _ALIX_PRINT_FMT_64 "x"
#define PRIXLEAST64 _ALIX_PRINT_FMT_64 "X"
#define SCNdLEAST64 _ALIX_INTFMT_64 "d"
#define SCNiLEAST64 _ALIX_INTFMT_64 "i"
#define SCNoLEAST64 _ALIX_INTFMT_64 "o"
#define SCNuLEAST64 _ALIX_INTFMT_64 "u"
#define SCNxLEAST64 _ALIX_INTFMT_64 "x"

/* FAST integer formats. */
#define PRIdFAST8 _ALIX_PRINT_FMT_FAST8 "d"
#define PRIiFAST8 _ALIX_PRINT_FMT_FAST8 "i"
#define PRIoFAST8 _ALIX_PRINT_FMT_FAST8 "o"
#define PRIuFAST8 _ALIX_PRINT_FMT_FAST8 "u"
#define PRIxFAST8 _ALIX_PRINT_FMT_FAST8 "x"
#define PRIXFAST8 _ALIX_PRINT_FMT_FAST8 "X"
#define SCNdFAST8 _ALIX_INTFMT_FAST8 "d"
#define SCNiFAST8 _ALIX_INTFMT_FAST8 "i"
#define SCNoFAST8 _ALIX_INTFMT_FAST8 "o"
#define SCNuFAST8 _ALIX_INTFMT_FAST8 "u"
#define SCNxFAST8 _ALIX_INTFMT_FAST8 "x"
#define PRIdFAST16 _ALIX_PRINT_FMT_FAST16 "d"
#define PRIiFAST16 _ALIX_PRINT_FMT_FAST16 "i"
#define PRIoFAST16 _ALIX_PRINT_FMT_FAST16 "o"
#define PRIuFAST16 _ALIX_PRINT_FMT_FAST16 "u"
#define PRIxFAST16 _ALIX_PRINT_FMT_FAST16 "x"
#define PRIXFAST16 _ALIX_PRINT_FMT_FAST16 "X"
#define SCNdFAST16 _ALIX_INTFMT_FAST16 "d"
#define SCNiFAST16 _ALIX_INTFMT_FAST16 "i"
#define SCNoFAST16 _ALIX_INTFMT_FAST16 "o"
#define SCNuFAST16 _ALIX_INTFMT_FAST16 "u"
#define SCNxFAST16 _ALIX_INTFMT_FAST16 "x"
#define PRIdFAST32 _ALIX_PRINT_FMT_FAST32 "d"
#define PRIiFAST32 _ALIX_PRINT_FMT_FAST32 "i"
#define PRIoFAST32 _ALIX_PRINT_FMT_FAST32 "o"
#define PRIuFAST32 _ALIX_PRINT_FMT_FAST32 "u"
#define PRIxFAST32 _ALIX_PRINT_FMT_FAST32 "x"
#define PRIXFAST32 _ALIX_PRINT_FMT_FAST32 "X"
#define SCNdFAST32 _ALIX_INTFMT_FAST32 "d"
#define SCNiFAST32 _ALIX_INTFMT_FAST32 "i"
#define SCNoFAST32 _ALIX_INTFMT_FAST32 "o"
#define SCNuFAST32 _ALIX_INTFMT_FAST32 "u"
#define SCNxFAST32 _ALIX_INTFMT_FAST32 "x"
#define PRIdFAST64 _ALIX_PRINT_FMT_FAST64 "d"
#define PRIiFAST64 _ALIX_PRINT_FMT_FAST64 "i"
#define PRIoFAST64 _ALIX_PRINT_FMT_FAST64 "o"
#define PRIuFAST64 _ALIX_PRINT_FMT_FAST64 "u"
#define PRIxFAST64 _ALIX_PRINT_FMT_FAST64 "x"
#define PRIXFAST64 _ALIX_PRINT_FMT_FAST64 "X"
#define SCNdFAST64 _ALIX_INTFMT_FAST64 "d"
#define SCNiFAST64 _ALIX_INTFMT_FAST64 "i"
#define SCNoFAST64 _ALIX_INTFMT_FAST64 "o"
#define SCNuFAST64 _ALIX_INTFMT_FAST64 "u"
#define SCNxFAST64 _ALIX_INTFMT_FAST64 "x"

#define PRIdMAX "ld"
#define PRIiMAX "li"
#define PRIoMAX "lo"
#define PRIuMAX "lu"
#define PRIxMAX "lx"
#define PRIXMAX "lX"
#define SCNdMAX "ld"
#define SCNiMAX "li"
#define SCNoMAX "lo"
#define SCNuMAX "lu"
#define SCNxMAX "lx"

#define PRIdPTR "ld"
#define PRIiPTR "li"
#define PRIoPTR "lo"
#define PRIuPTR "lu"
#define PRIxPTR "lx"
#define PRIXPTR "lX"
#define SCNdPTR "ld"
#define SCNiPTR "li"
#define SCNoPTR "lo"
#define SCNuPTR "lu"
#define SCNxPTR "lx"

typedef struct { intmax_t quot, rem; } imaxdiv_t;

#ifdef __cplusplus
extern "C" {
#endif
intmax_t imaxabs(intmax_t value);
imaxdiv_t imaxdiv(intmax_t numerator, intmax_t denominator);
intmax_t strtoimax(const char *text, char **end, int base);
uintmax_t strtoumax(const char *text, char **end, int base);
intmax_t wcstoimax(const wchar_t *text, wchar_t **end, int base);
uintmax_t wcstoumax(const wchar_t *text, wchar_t **end, int base);
#ifdef __cplusplus
}
#endif
#endif
#endif
