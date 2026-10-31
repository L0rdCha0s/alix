#include "math.h"
#include "serial.h"
#include <float.h>

static const long double pi = 3.141592653589793238462643383279502884L;

static bool close_long(long double actual, long double expected)
{
    long double difference = actual - expected;
    if (difference < 0) difference = -difference;
    return difference <= 4 * LDBL_EPSILON;
}

static bool close_float(float actual, float expected)
{
    float difference = actual - expected;
    if (difference < 0) difference = -difference;
    return difference <= 4 * FLT_EPSILON;
}

#define CHECK(condition, label) do { if (!(condition)) { \
    serial_printf("MATH_ATAN2_TEST: FAIL %s\n", label); return 1; } } while (0)

int main(void)
{
    CHECK(LDBL_MANT_DIG == 64 && sizeof(long double) == 16, "native extended ABI");
    CHECK(atan2f(0.0f, 1.0f) == 0 && !signbit(atan2f(0.0f, 1.0f)) &&
          atan2f(-0.0f, 1.0f) == 0 && signbit(atan2f(-0.0f, 1.0f)), "float signed zero");
    CHECK(atan2l(0.0L, 1.0L) == 0 && !signbit(atan2l(0.0L, 1.0L)) &&
          atan2l(-0.0L, 1.0L) == 0 && signbit(atan2l(-0.0L, 1.0L)), "extended signed zero");
    CHECK(close_float(atan2f(0.0f, -1.0f), (float)pi) &&
          close_float(atan2f(-0.0f, -1.0f), (float)-pi) &&
          close_long(atan2l(0.0L, -1.0L), pi) &&
          close_long(atan2l(-0.0L, -1.0L), -pi), "negative axis");
    CHECK(close_float(atan2f(1, 0), (float)(pi / 2)) &&
          close_float(atan2f(-1, 0), (float)(-pi / 2)) &&
          close_long(atan2l(1, 0), pi / 2) && close_long(atan2l(-1, 0), -pi / 2), "vertical axis");
    CHECK(close_float(atan2f(1, 1), (float)(pi / 4)) &&
          close_float(atan2f(1, -1), (float)(3 * pi / 4)) &&
          close_float(atan2f(-1, -1), (float)(-3 * pi / 4)) &&
          close_long(atan2l(1, 1), pi / 4) && close_long(atan2l(1, -1), 3 * pi / 4) &&
          close_long(atan2l(-1, -1), -3 * pi / 4), "quadrants");
    CHECK(isnan(atan2f(NAN, 1)) && isnan(atan2f(1, NAN)) &&
          isnan(atan2l(NAN, 1)) && isnan(atan2l(1, NAN)), "NaN propagation");
    CHECK(close_float(atan2f(INFINITY, INFINITY), (float)(pi / 4)) &&
          close_float(atan2f(-INFINITY, -INFINITY), (float)(-3 * pi / 4)) &&
          close_long(atan2l(HUGE_VALL, HUGE_VALL), pi / 4) &&
          close_long(atan2l(-HUGE_VALL, -HUGE_VALL), -3 * pi / 4), "infinities");
    CHECK(atan2l(1.0L + 0x1p-60L, 1.0L) > atan2l(1.0L, 1.0L), "extended precision retained");
    CHECK(close_long(atan2l(0x1p-12000L, 0x1p-12000L), pi / 4) &&
          close_long(atan2l(0x1p12000L, 0x1p12001L), atan2l(1, 2)), "extended exponent retained");
    serial_printf("MATH_ATAN2_TEST: PASS signed_zero=1 special=1 extended_precision=1\n");
    return 0;
}
