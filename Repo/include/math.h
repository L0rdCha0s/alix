#ifndef MATH_H
#define MATH_H

#include "types.h"

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

#define M_PI 3.14159265358979323846
#define PI   3.14159265358979323846

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

#ifdef __cplusplus
}
#endif

#endif /* MATH_H */
