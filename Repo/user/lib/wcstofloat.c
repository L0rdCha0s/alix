#include "wchar.h"
#include "stdlib.h"
#include "errno.h"

/* Linked with the real narrow floating parser in libalix-cxx-support.a, not
 * the unconditional C runtime, because the parser is an optional dependency. */
extern char *__alix_wide_ascii_prefix(const wchar_t *text);

#define WIDE_FLOAT(function,type,narrow) \
type function(const wchar_t *text,wchar_t **end) \
{ \
    if(end) *end=(wchar_t *)text; \
    char *copy=__alix_wide_ascii_prefix(text); if(!copy) return 0; \
    char *stopped=copy; type result=narrow(copy,&stopped); \
    if(end) *end=(wchar_t *)text+(stopped-copy); \
    int error=errno; free(copy); errno=error; return result; \
}
WIDE_FLOAT(wcstof,float,strtof)
WIDE_FLOAT(wcstod,double,strtod)
WIDE_FLOAT(wcstold,long double,strtold)
#undef WIDE_FLOAT
