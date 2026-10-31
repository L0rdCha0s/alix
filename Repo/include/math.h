#ifndef MATH_H
#define MATH_H

#include "types.h"
#include <float.h>

/* Match the compiler's actual expression-evaluation format. */
#if FLT_EVAL_METHOD == 0
typedef float float_t;
typedef double double_t;
#elif FLT_EVAL_METHOD == 1
typedef double float_t;
typedef double double_t;
#elif FLT_EVAL_METHOD == 2
typedef long double float_t;
typedef long double double_t;
#else
#error "Unsupported floating-point evaluation format for Alix math.h"
#endif

#define FP_NAN 0
#define FP_INFINITE 1
#define FP_ZERO 2
#define FP_SUBNORMAL 3
#define FP_NORMAL 4
#define HUGE_VAL (__builtin_huge_val())
#define HUGE_VALF (__builtin_huge_valf())
#define HUGE_VALL (__builtin_huge_vall())
#define INFINITY (__builtin_inff())
#define NAN (__builtin_nanf(""))
#define fpclassify(x) __builtin_fpclassify(FP_NAN, FP_INFINITE, FP_NORMAL, FP_SUBNORMAL, FP_ZERO, (x))
#define isfinite(x) __builtin_isfinite(x)
#define isinf(x) __builtin_isinf(x)
#define isnan(x) __builtin_isnan(x)
#define isnormal(x) __builtin_isnormal(x)
#define signbit(x) __builtin_signbit(x)
#define isgreater(x,y) __builtin_isgreater((x),(y))
#define isgreaterequal(x,y) __builtin_isgreaterequal((x),(y))
#define isless(x,y) __builtin_isless((x),(y))
#define islessequal(x,y) __builtin_islessequal((x),(y))
#define islessgreater(x,y) __builtin_islessgreater((x),(y))
#define isunordered(x,y) __builtin_isunordered((x),(y))

#ifdef __cplusplus
extern "C" {
#endif

/* X/Open constants, rounded directly to binary64. In particular SQRT1_2
 * is not computed from an already-rounded double-precision square root. */
#define M_E        0x1.5bf0a8b145769p+1
#define M_LOG2E    0x1.71547652b82fep+0
#define M_LOG10E   0x1.bcb7b1526e50ep-2
#define M_LN2      0x1.62e42fefa39efp-1
#define M_LN10     0x1.26bb1bbb55516p+1
#define M_PI       0x1.921fb54442d18p+1
#define M_PI_2     0x1.921fb54442d18p+0
#define M_PI_4     0x1.921fb54442d18p-1
#define M_1_PI     0x1.45f306dc9c883p-2
#define M_2_PI     0x1.45f306dc9c883p-1
#define M_2_SQRTPI 0x1.20dd750429b6dp+0
#define M_SQRT2    0x1.6a09e667f3bcdp+0
#define M_SQRT1_2  0x1.6a09e667f3bcdp-1
#define PI         0x1.921fb54442d18p+1

double atan(double x);
double atan2(double y, double x);
float atan2f(float y, float x);
long double atan2l(long double y, long double x);
long double frexpl(long double value, int *exponent);
double sin(double x);
double cos(double x);
double tan(double x);
double sqrt(double x);
double floor(double x);
double ceil(double x);
double fabs(double x);
double pow(double x, double y);
float nearbyintf(float value);
double nearbyint(double value);
long double nearbyintl(long double value);
float sqrtf(float value);
float fabsf(float value);
long double fabsl(long double value);
float scalbnf(float value, int exponent);

#ifdef __cplusplus
}
#endif

#endif /* MATH_H */
