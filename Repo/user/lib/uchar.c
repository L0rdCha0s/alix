#include "uchar.h"
#include "errno.h"

/* Both installed locales are stateless ASCII. Every representable character
 * therefore maps to exactly one UTF-16 or UTF-32 code unit. */
size_t mbrtoc16(char16_t *output, const char *text, size_t length, mbstate_t *state)
{
    static _Thread_local mbstate_t internal;
    wchar_t value;
    size_t result = mbrtowc(&value, text, length, state ? state : &internal);
    if (output && text && result != (size_t)-1 && result != (size_t)-2) *output = (char16_t)value;
    return result;
}
size_t mbrtoc32(char32_t *output, const char *text, size_t length, mbstate_t *state)
{
    static _Thread_local mbstate_t internal;
    wchar_t value;
    size_t result = mbrtowc(&value, text, length, state ? state : &internal);
    if (output && text && result != (size_t)-1 && result != (size_t)-2) *output = (char32_t)value;
    return result;
}
size_t c16rtomb(char *output, char16_t value, mbstate_t *state)
{
    static _Thread_local mbstate_t internal;
    return wcrtomb(output, value, state ? state : &internal);
}
size_t c32rtomb(char *output, char32_t value, mbstate_t *state)
{
    static _Thread_local mbstate_t internal;
    if (output && value > 127) { errno = EILSEQ; return (size_t)-1; }
    return wcrtomb(output, (wchar_t)value, state ? state : &internal);
}
