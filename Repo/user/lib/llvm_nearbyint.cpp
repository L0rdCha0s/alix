/* Native libm entry points using the pinned LLVM libc rounding implementation.
 * Keep the arithmetic itself upstream; Alix supplies its real hardware rounding
 * mode. LLVM's generic quick_get_round() probes with inexact FP arithmetic,
 * which is unsuitable for nearbyint's requirement not to raise FE_INEXACT. */
/* This translation unit uses LLVM's private full-build support definitions;
 * no LLVM fenv_t or exception-bit encoding crosses the native libc boundary.
 * fegetround's scalar rounding constants have the same x86 values. */
#ifdef __ALIX__
#define LIBC_FULL_BUILD 1
#endif
#include "src/__support/FPUtil/NearestIntegerOperations.h"

extern "C" int fegetround(void);
#ifdef __ALIX__
static_assert(FE_TONEAREST == 0 && FE_DOWNWARD == 0x400 &&
              FE_UPWARD == 0x800 && FE_TOWARDZERO == 0xc00);
#endif

#pragma STDC FENV_ACCESS ON

template <class Float>
static Float nearby_integer(Float value)
{
    using Bits = LIBC_NAMESPACE::fputil::FPBits<Float>;
    /* Quiet a signaling NaN with the hardware's normal invalid exception.
     * The upstream bit-rounding helper deliberately returns NaNs unchanged. */
    if (Bits(value).is_signaling_nan()) return value + value;
    int mode;
    switch (fegetround())
    {
        case FE_DOWNWARD: mode = FP_INT_DOWNWARD; break;
        case FE_UPWARD: mode = FP_INT_UPWARD; break;
        case FE_TOWARDZERO: mode = FP_INT_TOWARDZERO; break;
        default: mode = FP_INT_TONEAREST; break;
    }
    return LIBC_NAMESPACE::fputil::round_using_specific_rounding_mode(value, mode);
}

extern "C" float nearbyintf(float value) { return nearby_integer(value); }
extern "C" double nearbyint(double value) { return nearby_integer(value); }
extern "C" long double nearbyintl(long double value) { return nearby_integer(value); }
