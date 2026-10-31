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

static inline double alix_x87_sin(double x)
{
    double out;
    __asm__ volatile(
        "fldl %1\n"
        "fsin\n"
        "fstpl %0\n"
        : "=m"(out)
        : "m"(x)
        : "st");
    return out;
}

static inline double alix_x87_cos(double x)
{
    double out;
    __asm__ volatile(
        "fldl %1\n"
        "fcos\n"
        "fstpl %0\n"
        : "=m"(out)
        : "m"(x)
        : "st");
    return out;
}

static inline double alix_x87_sqrt(double x)
{
    double out;
    __asm__ volatile(
        "fldl %1\n"
        "fsqrt\n"
        "fstpl %0\n"
        : "=m"(out)
        : "m"(x)
        : "st");
    return out;
}

static inline double alix_x87_atan2(double y, double x)
{
    double out;
    __asm__ volatile(
        "fldl %2\n"  // y
        "fldl %1\n"  // x
        "fpatan\n"
        "fstpl %0\n"
        : "=m"(out)
        : "m"(x), "m"(y)
        : "st");
    return out;
}

double sin(double x)
{
    return alix_x87_sin(x);
}

double cos(double x)
{
    return alix_x87_cos(x);
}

double tan(double x)
{
    double c = alix_x87_cos(x);
    if (c == 0.0)
    {
        return 0.0;
    }
    return alix_x87_sin(x) / c;
}

double sqrt(double x)
{
    return alix_x87_sqrt(x);
}

double atan2(double y, double x)
{
    return alix_x87_atan2(y, x);
}

float atan2f(float y, float x)
{
    float out;
    __asm__ volatile(
        "flds %2\n"
        "flds %1\n"
        "fpatan\n"
        "fstps %0\n"
        : "=m"(out)
        : "m"(x), "m"(y)
        : "st");
    return out;
}

long double atan2l(long double y, long double x)
{
    long double out;
    /* Keep both operands and the result in the native x87 extended format. */
    __asm__ volatile(
        "fldt %2\n"
        "fldt %1\n"
        "fpatan\n"
        "fstpt %0\n"
        : "=m"(out)
        : "m"(x), "m"(y)
        : "st");
    return out;
}

double atan(double x)
{
    return alix_x87_atan2(x, 1.0);
}

double floor(double x)
{
    int64_t i = (int64_t)x;
    double di = (double)i;
    if (di > x)
    {
        i -= 1;
    }
    return (double)i;
}

double ceil(double x)
{
    int64_t i = (int64_t)x;
    double di = (double)i;
    if (di < x)
    {
        i += 1;
    }
    return (double)i;
}

double fabs(double x)
{
    return x < 0.0 ? -x : x;
}

double pow(double x, double y)
{
    if (x <= 0.0)
    {
        return 0.0;
    }

    double out;
    __asm__ volatile(
        "fldl %2\n"                /* y */
        "fldl %1\n"                /* x */
        "fyl2x\n"                  /* t = y * log2(x) */
        "fld %%st(0)\n"            /* dup t */
        "frndint\n"                /* i = round(t) */
        "fxch %%st(1)\n"           /* st0=t, st1=i */
        "fsub %%st(1), %%st(0)\n"  /* f = t - i */
        "f2xm1\n"                  /* 2^f - 1 */
        "fld1\n"
        "faddp\n"                  /* 2^f */
        "fscale\n"                 /* 2^t */
        "fstp %%st(1)\n"           /* pop i */
        "fstpl %0\n"
        : "=m"(out)
        : "m"(x), "m"(y)
        : "st");
    return out;
}
