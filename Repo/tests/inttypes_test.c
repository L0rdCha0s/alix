#include "inttypes.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include "wchar.h"
#include "errno.h"
#include "serial.h"

#define CHECK(condition, label) do { if (!(condition)) { \
    serial_printf("INTTYPES_TEST: FAIL %s\n", label); return 1; } } while (0)

int main(void)
{
    char *buffer = malloc(192);
    CHECK(buffer != NULL, "buffer allocation");
    CHECK(snprintf(buffer, 192, "%" PRId64 "|%" PRIuMAX "|%" PRIxPTR,
                   (int64_t)INT64_MIN, (uintmax_t)UINTMAX_MAX, (uintptr_t)0x100000000ULL) > 0 &&
          strcmp(buffer, "-9223372036854775808|18446744073709551615|100000000") == 0,
          "64-bit format ABI");
    CHECK(snprintf(buffer, 192, "%" PRId8 "|%" PRIu16 "|%" PRIxFAST8,
                   (int8_t)-127, (uint16_t)65535, (uint_fast8_t)0xab) > 0 &&
          strcmp(buffer, "-127|65535|ab") == 0, "promoted integer formats");
    char *end = NULL;
    errno = 0;
    CHECK(strtoimax(" -0x8000000000000000tail", &end, 0) == INTMAX_MIN &&
          strcmp(end, "tail") == 0 && errno == 0, "signed maximum-width parse");
    CHECK(strtoumax("18446744073709551615!", &end, 10) == UINTMAX_MAX && *end == '!',
          "unsigned maximum-width parse");
    errno = 0;
    CHECK(strtoumax("18446744073709551616", &end, 10) == UINTMAX_MAX &&
          *end == '\0' && errno == ERANGE, "integer overflow propagation");
    wchar_t *wide_end = NULL;
    errno = 0;
    CHECK(wcstoimax(L"-9223372036854775808?", &wide_end, 10) == INTMAX_MIN &&
          *wide_end == L'?' && errno == 0, "wide signed parse");
    CHECK(wcstoumax(L"0xffffffffffffffff;", &wide_end, 0) == UINTMAX_MAX && *wide_end == L';',
          "wide unsigned parse");
    imaxdiv_t division = imaxdiv(-17, 5);
    CHECK(division.quot == -3 && division.rem == -2 && imaxabs(-17) == 17,
          "signed division and absolute value");
    free(buffer);
    serial_printf("INTTYPES_TEST: PASS format64=1 promoted=1 narrow=1 wide16=1\n");
    return 0;
}
