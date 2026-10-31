/* Alix libm entry points backed by pinned LLVM libc support templates.
 * Private LLVM fenv definitions never cross the native C ABI. */
#ifdef __ALIX__
#define LIBC_FULL_BUILD 1
#endif
#define LIBC_ERRNO_MODE 6 /* LLVM's documented system-inline errno backend. */
#include "src/__support/FPUtil/BasicOperations.h"
#include "src/__support/FPUtil/ManipulationFunctions.h"
#include "src/__support/FPUtil/sqrt.h"

#pragma STDC FENV_ACCESS ON

namespace fp = LIBC_NAMESPACE::fputil;

extern "C" float fabsf(float value) { return fp::abs(value); }
extern "C" long double fabsl(long double value) { return fp::abs(value); }

extern "C" float sqrtf(float value)
{
    fp::FPBits<float> bits(value);
    /* LLVM's hardware sqrt specialization supplies the IEEE result/flags;
     * the native POSIX entry point also reports its domain error in errno. */
    if (bits.is_neg() && !bits.is_zero() && !bits.is_nan()) errno = EDOM;
    return fp::sqrt<float>(value);
}

extern "C" float scalbnf(float value, int exponent)
{
    using Bits = fp::FPBits<float>;
    Bits bits(value);
    if (bits.is_signaling_nan()) return value + value;
    if (bits.is_inf_or_nan() || bits.is_zero() || exponent == 0) return value;

    /* Feed LLVM's general correctly-rounded path a bounded exponent. Beyond
     * this bound even min-subnormal/max-finite inputs overflow/underflow, so
     * clamping preserves every rounding-mode result. It avoids the upstream
     * extreme-exponent shortcut's arithmetic mode probe and lets the actual
     * arithmetic generate overflow/underflow plus inexact, even when directed
     * rounding returns a finite endpoint. */
    constexpr int limit = Bits::MAX_BIASED_EXPONENT + Bits::FRACTION_LEN + 1;
    int bounded = exponent > limit ? limit : (exponent < -limit ? -limit : exponent);
    fp::NormalFloat<float> normalized(bits);
    if (normalized.exponent + bounded > Bits::EXP_BIAS) errno = ERANGE;
    float result = fp::ldexp(value, bounded);
    Bits result_bits(result);
    /* The POSIX wrapper reports inexact tiny results even on hosts whose
     * math_errhandling only advertises exceptions. Exact subnormals retain
     * errno; normalizing both values lets us test lost precision without
     * touching pre-existing hardware exception flags. */
    if (result_bits.is_zero()) errno = ERANGE;
    else if (result_bits.is_subnormal())
    {
        fp::NormalFloat<float> rounded(result_bits);
        if (rounded.exponent != normalized.exponent + bounded ||
            rounded.mantissa != normalized.mantissa) errno = ERANGE;
    }
    return result;
}
