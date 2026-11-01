#include "math.h"
#include "errno.h"
#include <float.h>

extern float __alix_sqrtf(float);
extern float __alix_scalbnf(float, int);

/* Preserve the existing native POSIX errno contract on these entry points.
 * The portable library otherwise advertises C's MATH_ERREXCEPT model. */
float sqrtf(float value)
{
    if (value < 0) errno = EDOM;
    return __alix_sqrtf(value);
}

float scalbnf(float value, int exponent)
{
    float result = __alix_scalbnf(value, exponent);
    if (!isfinite(value) || value == 0) return result;
    if (exponent > 512 || exponent < -512) errno = ERANGE;
    else
    {
        long double exact = scalbnl((long double)value, exponent);
        if (fabsl(exact) > FLT_MAX || (fabsl(exact) < FLT_MIN && (long double)result != exact)) errno = ERANGE;
    }
    return result;
}
