#include "math.h"
#include "fenv.h"
#include "errno.h"
#include "serial.h"
#include "string.h"
#include <stdint.h>
#include <limits.h>

#pragma STDC FENV_ACCESS ON
#define CHECK(c, label) do { if (!(c)) { serial_printf("MATH_SUPPORT_TEST: FAIL %s mode=%u case=%u\n", label, mode, index); return 1; } } while (0)

static unsigned flags(void)
{
    uint16_t status; uint32_t mxcsr;
    __asm__ volatile ("fnstsw %0; stmxcsr %1" : "=m"(status), "=m"(mxcsr));
    return (status | mxcsr) & FE_ALL_EXCEPT;
}
static void clear_flags(void)
{
    uint32_t mxcsr;
    __asm__ volatile ("fnclex; stmxcsr %0" : "=m"(mxcsr));
    mxcsr &= ~0x3fu;
    __asm__ volatile ("ldmxcsr %0" :: "m"(mxcsr) : "memory");
}
static float reference_scale(float value, int exponent)
{
    float result;
    __asm__ volatile ("fildl %2; flds %1; fscale; fstp %%st(1); fstps %0"
                      : "=m"(result) : "m"(value), "m"(exponent) : "st", "st(1)");
    return result;
}
static uint64_t state = UINT64_C(0xcd3214ac12ef3456);
static uint32_t random_bits(void)
{
    state ^= state << 13; state ^= state >> 7; state ^= state << 17;
    return (uint32_t)state;
}

int main(void)
{
    unsigned mode = 0, index = 0, cases = 0;
    const int modes[] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };
    CHECK(sizeof(float_t) == sizeof(float) && sizeof(double_t) == sizeof(double), "evaluation types");
    for (mode = 0; mode < 4; ++mode)
    {
        CHECK(fesetround(modes[mode]) == 0, "set rounding");
        for (index = 0; index < 10000; ++index)
        {
            uint32_t bits = random_bits(); int exponent = (int)(random_bits() % 701) - 350;
            float value; memcpy(&value, &bits, sizeof(value));
            if (!isfinite(value)) continue;
            clear_flags(); float expected = reference_scale(value, exponent);
            unsigned expected_flags = flags();
            clear_flags(); errno = 123; float actual = scalbnf(value, exponent);
            CHECK(memcmp(&actual, &expected, sizeof(actual)) == 0, "scaling result");
            CHECK(flags() == expected_flags, "scaling exception flags");
            CHECK(errno == 123 || errno == ERANGE, "range errno");
            clear_flags(); float absolute = fabsf(value);
            uint32_t positive; memcpy(&positive, &absolute, sizeof(positive));
            CHECK(positive == (bits & 0x7fffffffu) && flags() == 0, "absolute bits");
            ++cases;
        }
        clear_flags(); errno = 0; (void)scalbnf(1, INT_MAX);
        CHECK(errno == ERANGE && flags() == (FE_OVERFLOW | FE_INEXACT), "extreme overflow");
        clear_flags(); errno = 0; (void)scalbnf(-1, INT_MIN);
        CHECK(errno == ERANGE && flags() == (FE_UNDERFLOW | FE_INEXACT), "extreme underflow");
        clear_flags(); errno = 123;
        CHECK(scalbnf(0x1p-126f, -1) == 0x1p-127f && errno == 123 && flags() == 0, "exact subnormal");
        clear_flags(); errno = 123;
        float root = sqrtf(2);
        CHECK(root == (modes[mode] == FE_UPWARD ? 0x1.6a09e8p+0f : 0x1.6a09e6p+0f), "sqrt rounding");
        CHECK(flags() == FE_INEXACT && errno == 123, "sqrt flags");
        clear_flags();
        CHECK(sqrtf(4) == 2 && flags() == 0, "exact sqrt");
    }
    CHECK(fesetround(FE_TONEAREST) == 0, "restore rounding");
    clear_flags(); errno = 0;
    CHECK(isnan(sqrtf(-1)) && flags() == FE_INVALID && errno == EDOM, "sqrt domain");
    clear_flags(); errno = 123;
    CHECK(signbit(sqrtf(-0.0f)) && !signbit(fabsf(-0.0f)) && flags() == 0, "signed zero");
    CHECK(fabsl(-1.0L - 0x1p-60L) == 1.0L + 0x1p-60L &&
          fabsl(-0x1p-12000L) == 0x1p-12000L &&
          fabsl(-0x1p12000L) == 0x1p12000L && flags() == 0, "extended abs");
    uint32_t bits = 0x7f800001; float snan; memcpy(&snan, &bits, sizeof(snan));
    clear_flags(); CHECK(isnan(scalbnf(snan, 0)) && flags() == FE_INVALID, "signaling NaN");
    clear_flags();
    serial_printf("MATH_SUPPORT_TEST: PASS cases=%u rounding=4 extended80=1 range_errno=1 flags=1\n", cases);
    return 0;
}
