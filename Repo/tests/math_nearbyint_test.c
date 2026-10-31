#include "math.h"
#include "fenv.h"
#include "serial.h"
#include "string.h"
#include <float.h>
#include <stdint.h>

#pragma STDC FENV_ACCESS ON

#define CHECK(condition, label) do { if (!(condition)) { \
    serial_printf("MATH_NEARBYINT_TEST: FAIL %s case=%u mode=%u\n", label, index, mode); return 1; } } while (0)

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

static void seed_flags(unsigned bits)
{
    uint32_t mxcsr;
    __asm__ volatile ("stmxcsr %0" : "=m"(mxcsr));
    mxcsr |= bits;
    __asm__ volatile ("ldmxcsr %0" :: "m"(mxcsr) : "memory");
}

static long double reference(long double value)
{
    long double result;
    __asm__ volatile ("fldt %1; frndint; fstpt %0" : "=m"(result) : "m"(value) : "st");
    return result;
}

static uint64_t state = UINT64_C(0xc51293a2db492ab1);
static uint64_t random_bits(void)
{
    state ^= state << 13; state ^= state >> 7; state ^= state << 17;
    return state;
}

int main(void)
{
    unsigned index = 0, mode = 0, cases = 0;
    const int modes[] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };
    const long double edges[] = {
        0.0L, -0.0L, 0.25L, -0.25L, 0.5L, -0.5L, 1.5L, -1.5L,
        2.5L, -2.5L, 3.5L, -3.5L, 0x1p-16445L, -0x1p-16445L,
        0x1p-12000L, -0x1p-12000L, 0x1p12000L, -0x1p12000L,
        0x1.000000000000001p62L, -0x1.000000000000001p62L,
        0x1.000000000000003p62L, -0x1.000000000000003p62L,
        0x1.fffffffffffffffep62L, -0x1.fffffffffffffffep62L,
        HUGE_VALL, -HUGE_VALL
    };
    CHECK(LDBL_MANT_DIG == 64 && sizeof(long double) == 16, "extended ABI");
    for (mode = 0; mode < 4; ++mode)
    {
        CHECK(fesetround(modes[mode]) == 0, "set rounding");
        for (index = 0; index < sizeof(edges) / sizeof(edges[0]); ++index)
        {
            long double expected = reference(edges[index]);
            clear_flags(); seed_flags(FE_DIVBYZERO);
            long double actual = nearbyintl(edges[index]);
            CHECK(flags() == FE_DIVBYZERO, "extended no inexact");
            CHECK(actual == expected && !!signbit(actual) == !!signbit(expected), "extended value");
            CHECK(fegetround() == modes[mode], "mode preserved");
            ++cases;
        }
        for (index = 0; index < 8192; ++index)
        {
            uint64_t bits = random_bits();
            uint32_t small = (uint32_t)random_bits();
            double value; float fvalue;
            memcpy(&value, &bits, sizeof(value)); memcpy(&fvalue, &small, sizeof(fvalue));
            if (!isfinite(value) || !isfinite(fvalue)) continue;
            double expected = (double)reference(value);
            float fexpected = (float)reference(fvalue);
            clear_flags(); seed_flags(FE_DIVBYZERO);
            double actual = nearbyint(value); float factual = nearbyintf(fvalue);
            CHECK(flags() == FE_DIVBYZERO, "binary32/64 no inexact");
            CHECK(memcmp(&actual, &expected, sizeof(actual)) == 0 &&
                  memcmp(&factual, &fexpected, sizeof(factual)) == 0, "binary32/64 value");
            ++cases;
        }
    }
    CHECK(fesetround(FE_TONEAREST) == 0, "restore rounding");
    uint64_t bits = UINT64_C(0x7ff0000000000001); double snan;
    memcpy(&snan, &bits, sizeof(snan)); clear_flags();
    double quiet = nearbyint(snan);
    CHECK(flags() == FE_INVALID && isnan(quiet), "double signaling NaN");
    memcpy(&bits, &quiet, sizeof(bits)); CHECK(bits & UINT64_C(0x8000000000000), "double quiet bit");
    uint32_t small = 0x7f800001; float fsnan;
    memcpy(&fsnan, &small, sizeof(fsnan)); clear_flags();
    float fquiet = nearbyintf(fsnan);
    CHECK(flags() == FE_INVALID && isnan(fquiet), "float signaling NaN");
    struct { uint64_t mantissa; uint16_t exponent; uint16_t padding[3]; } lbits =
        { UINT64_C(0x8000000000000001), 0x7fff, { 0, 0, 0 } };
    long double lsnan; memcpy(&lsnan, &lbits, sizeof(lsnan)); clear_flags();
    long double lquiet = nearbyintl(lsnan);
    CHECK(flags() == FE_INVALID && isnan(lquiet), "extended signaling NaN");
    memcpy(&lbits, &lquiet, sizeof(lbits)); CHECK(lbits.mantissa & UINT64_C(0x4000000000000000), "extended quiet bit");
    clear_flags(); seed_flags(FE_INEXACT | FE_DIVBYZERO);
    CHECK(nearbyint(1.25) == 1.0 && nearbyintf(-1.25f) == -1.0f && nearbyintl(2.5L) == 2.0L, "seeded result");
    CHECK(flags() == (FE_INEXACT | FE_DIVBYZERO), "preexisting inexact preserved");
    clear_flags();
    serial_printf("MATH_NEARBYINT_TEST: PASS cases=%u rounding=4 extended80=1 flags=preserved signaling_nan=1\n", cases);
    return 0;
}
