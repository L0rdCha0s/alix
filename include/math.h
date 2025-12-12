#ifndef MATH_H
#define MATH_H

#include "types.h"

#define M_PI 3.14159265358979323846
#define PI   3.14159265358979323846

static inline double atan(double x)
{
    return __builtin_atan(x);
}

#endif /* MATH_H */
