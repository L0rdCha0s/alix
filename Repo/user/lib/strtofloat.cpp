/* Alix C conversion entry points backed by LLVM libc's correctly-rounded
 * parser. The implementation uses LLVM's freestanding support templates;
 * it does not call back into libc++ or the browser's JavaScript engine. */
#include "errno.h"
#include "stdlib.h"
#include "src/__support/str_to_float.h"

template <class Float>
static Float convert(const char *text, char **end)
{
    if (!text)
    {
        if (end) *end = nullptr;
        errno = EINVAL;
        return 0;
    }
    auto result = LIBC_NAMESPACE::internal::strtofloatingpoint<Float>(text);
    if (result.has_error()) errno = result.error;
    if (end) *end = const_cast<char *>(text + result.parsed_len);
    return result.value;
}

extern "C" float strtof(const char *text, char **end) { return convert<float>(text, end); }
extern "C" double strtod(const char *text, char **end) { return convert<double>(text, end); }
extern "C" long double strtold(const char *text, char **end) { return convert<long double>(text, end); }
