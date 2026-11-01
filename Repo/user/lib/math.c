/* Native frexpl ABI helper. Other real/complex functions are built from
 * the pinned portable sources in libc_runtime.mk. */
#include "math.h"
#include <float.h>
#include <stdint.h>

long double frexpl(long double value, int *exponent)
{
    *exponent = 0;
#if LDBL_MANT_DIG == 64 && LDBL_MAX_EXP == 16384
    _Static_assert(sizeof(long double) == 16, "Alix x87 extended ABI");
    union { long double value; struct { uint64_t fraction; uint16_t sign_exponent; } bits; } number = {value};
    unsigned field = number.bits.sign_exponent & 0x7fffu;
    if (field == 0x7fffu || (field == 0 && !number.bits.fraction)) return value;
    int adjustment = 0;
    if (field == 0)
    {
        number.value = value * 0x1p64L;
        field = number.bits.sign_exponent & 0x7fffu;
        adjustment = -64;
    }
    *exponent = (int)field - 16382 + adjustment;
    number.bits.sign_exponent = (number.bits.sign_exponent & 0x8000u) | 0x3ffeu;
    return number.value;
#elif LDBL_MANT_DIG == 53 && LDBL_MAX_EXP == 1024
    _Static_assert(sizeof(long double) == 8, "binary64 long-double ABI");
    union { long double value; uint64_t bits; } number = {value};
    unsigned field = (unsigned)(number.bits >> 52) & 0x7ffu;
    if (field == 0x7ffu || (number.bits << 1) == 0) return value;
    int adjustment = 0;
    if (field == 0)
    {
        number.value = value * 0x1p64L;
        field = (unsigned)(number.bits >> 52) & 0x7ffu;
        adjustment = -64;
    }
    *exponent = (int)field - 1022 + adjustment;
    number.bits = (number.bits & UINT64_C(0x800fffffffffffff)) | UINT64_C(0x3fe0000000000000);
    return number.value;
#else
#error Unsupported long-double representation
#endif
}
