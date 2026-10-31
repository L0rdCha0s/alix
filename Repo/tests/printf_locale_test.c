#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "locale.h"
#include "math.h"
#include "fenv.h"
#include "errno.h"
#include "serial.h"
#include "sys/mman.h"
#include <limits.h>
#include <float.h>

#define CHECK(condition, label) do { if (!(condition)) { \
    serial_printf("PRINTF_LOCALE_TEST: FAIL %s\n", label); return 1; } } while (0)

int main(void)
{
    char *text = malloc(8192);
    CHECK(text, "buffer");
    CHECK(snprintf(text, 8192, "%+.2f|%#.0e|%.6g|%a", 1.25, 12.5, 12.5, 12.5) == 26 &&
          !strcmp(text, "+1.25|1.e+01|12.5|0x1.9p+3"), "float forms");
    CHECK(snprintf(text, 8192, "%#08x|%#.3o|%+05d|%hhd", 42u, 1u, 42, 255) == 21 &&
          !strcmp(text, "0x00002a|001|+0042|-1"), "integer forms");
    CHECK(snprintf(text, 8192, "%.20Lg", 1.0L + 0x1p-60L) > 0 &&
          !strcmp(text, "1.0000000000000000009"), "extended precision");
    CHECK(snprintf(text, 8192, "%La", 0x1p12000L) > 0 &&
          !strcmp(text, "0x1p+12000"), "extended exponent");
    CHECK(snprintf(text, 8192, "%La", 0x1p-16445L) > 0 &&
          !strcmp(text, "0x1p-16445"), "extended subnormal");
    int exponent = 0;
    CHECK(frexpl(0x1p-16445L, &exponent) == 0.5L && exponent == -16444,
          "subnormal frexpl");
    CHECK(snprintf(text, 8192, "%.0Lf", LDBL_MAX) == 4933 && strlen(text) == 4933,
          "full extended decimal exponent");
    const int modes[] = {FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO};
    const char *expected[] = {"0.2|-0.2", "0.2|-0.3", "0.3|-0.2", "0.2|-0.2"};
    for (unsigned i = 0; i < 4; ++i)
    {
        CHECK(fesetround(modes[i]) == 0 && snprintf(text, 8192, "%.1Lf|%.1Lf", 0.25L, -0.25L) == 8 &&
              !strcmp(text, expected[i]), "rounding mode");
    }
    CHECK(fesetround(FE_TONEAREST) == 0, "rounding restore");
    CHECK(snprintf(text, 8192, "%-023.0f", 0.0) == 23 &&
          !strcmp(text, "0                      "), "left alignment overrides zero padding");
    CHECK(snprintf(NULL, 0, "%*d", INT_MAX, 1) == INT_MAX, "large width counting");
    CHECK(snprintf(NULL, 0, "x%*d", INT_MAX, 1) == -1 && errno == EOVERFLOW, "count overflow");
    CHECK(snprintf(NULL, 0, "%.*f", INT_MAX, 1.0) == -1 && errno == EOVERFLOW, "precision overflow");
    CHECK(snprintf(text, 8192, "%.*g", INT_MAX, 1.0) == 1 && !strcmp(text, "1"),
          "large general precision");
    CHECK(snprintf(text, 8192, "%.*g", INT_MAX, 0.0001) > 0 &&
          !strcmp(text, "0.000100000000000000004792173602385929598312941379845142364501953125"),
          "large general precision with negative exponent");
    unsigned char *pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(pages != MAP_FAILED && mprotect(pages + 4096, 4096, PROT_NONE) == 0, "string guard");
    memcpy(pages + 4093, "abc", 3);
    CHECK(snprintf(text, 8192, "%.3s", (char *)pages + 4093) == 3 && !strcmp(text, "abc"),
          "bounded string read");
    CHECK(munmap(pages, 8192) == 0, "guard cleanup");
    char *allocated = NULL;
    int count = -1;
    int allocated_count = asprintf(&allocated, "%#.4a %+.6g%n", 1.25, 12.5, &count);
    CHECK(allocated_count == count && allocated &&
          !strcmp(allocated, "0x1.4000p+0 +12.5"), "allocated formatting");
    free(allocated);
    locale_t first = newlocale(LC_ALL_MASK, "C", NULL);
    locale_t second = duplocale(first);
    CHECK(first && second && first != second, "locale ownership");
    CHECK(uselocale(first) == LC_GLOBAL_LOCALE && uselocale(second) == first &&
          uselocale(NULL) == second, "locale selection");
    CHECK(!newlocale(LC_ALL_MASK, "unavailable", first) && errno == ENOENT &&
          newlocale(LC_TIME_MASK, "POSIX", first) == first, "locale failure preserves base");
    CHECK(uselocale(LC_GLOBAL_LOCALE) == second, "locale restore");
    freelocale(first); freelocale(second); free(text);
    serial_printf("PRINTF_LOCALE_TEST: PASS extended80=1 rounding=4 guarded_string=1 locale=1\n");
    return 0;
}
