#include "inttypes.h"
#include "stdlib.h"
#include "wchar.h"

_Static_assert(sizeof(intmax_t) == sizeof(long), "native intmax_t must match long");

intmax_t imaxabs(intmax_t value)
{
    return value < 0 ? -value : value;
}

imaxdiv_t imaxdiv(intmax_t numerator, intmax_t denominator)
{
    imaxdiv_t result = { numerator / denominator, numerator % denominator };
    return result;
}

intmax_t strtoimax(const char *text, char **end, int base)
{
    return strtol(text, end, base);
}

uintmax_t strtoumax(const char *text, char **end, int base)
{
    return strtoul(text, end, base);
}

intmax_t wcstoimax(const wchar_t *text, wchar_t **end, int base)
{
    return wcstol(text, end, base);
}

uintmax_t wcstoumax(const wchar_t *text, wchar_t **end, int base)
{
    return wcstoul(text, end, base);
}
