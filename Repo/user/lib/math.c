#include "math.h"

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
