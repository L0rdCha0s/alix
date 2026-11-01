#ifndef ALIX_UCHAR_H
#define ALIX_UCHAR_H
#include <stdint.h>
#include "wchar.h"
#ifndef __cplusplus
typedef uint_least16_t char16_t;
typedef uint_least32_t char32_t;
#endif
#ifdef __cplusplus
extern "C" {
#endif
size_t mbrtoc16(char16_t *, const char *, size_t, mbstate_t *);
size_t c16rtomb(char *, char16_t, mbstate_t *);
size_t mbrtoc32(char32_t *, const char *, size_t, mbstate_t *);
size_t c32rtomb(char *, char32_t, mbstate_t *);
#ifdef __cplusplus
}
#endif
#endif
