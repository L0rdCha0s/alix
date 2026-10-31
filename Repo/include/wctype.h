#ifndef ALIX_WCTYPE_H
#define ALIX_WCTYPE_H
#ifdef TTF_HOST_BUILD
#include_next <wctype.h>
#else
#include "wchar.h"
typedef uint32_t wctype_t;
typedef uint32_t wctrans_t;
#ifdef __cplusplus
extern "C" {
#endif
int iswalnum(wint_t);
int iswalpha(wint_t);
int iswblank(wint_t);
int iswcntrl(wint_t);
int iswdigit(wint_t);
int iswgraph(wint_t);
int iswlower(wint_t);
int iswprint(wint_t);
int iswpunct(wint_t);
int iswspace(wint_t);
int iswupper(wint_t);
int iswxdigit(wint_t);
wint_t towlower(wint_t);
wint_t towupper(wint_t);
wctype_t wctype(const char *);
int iswctype(wint_t, wctype_t);
wctrans_t wctrans(const char *);
wint_t towctrans(wint_t, wctrans_t);
#ifdef __cplusplus
}
#endif
#endif
#endif
