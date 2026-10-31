#include <iomanip>
#include <iostream>
#include <limits>
#include <locale>
#include <sstream>
#include <string>

#include "wctype.h"
#include "wchar.h"
#include "serial.h"

extern "C" int alix_cxx_wide_mask_matches(wint_t, unsigned long);

static unsigned long character_mask(wint_t value)
{
    unsigned long mask = 0;
    if (iswspace(value)) mask |= std::ctype_base::space;
    if (iswprint(value)) mask |= std::ctype_base::print;
    if (iswcntrl(value)) mask |= std::ctype_base::cntrl;
    if (iswupper(value)) mask |= std::ctype_base::upper;
    if (iswlower(value)) mask |= std::ctype_base::lower;
    if (iswalpha(value)) mask |= std::ctype_base::alpha;
    if (iswdigit(value)) mask |= std::ctype_base::digit;
    if (iswpunct(value)) mask |= std::ctype_base::punct;
    if (iswxdigit(value)) mask |= std::ctype_base::xdigit;
    if (iswblank(value)) mask |= std::ctype_base::blank;
    return mask;
}

#define CHECK(condition, label) do { if (!(condition)) { \
    serial_printf("CXX_WIDE_TEST: FAIL %s\n", label); return 1; } } while (0)

int main()
{
    CHECK(sizeof(wchar_t) == 2, "native wchar ABI");
    const std::locale classic = std::locale::classic();
    const std::locale named("POSIX");
    const auto& classic_type = std::use_facet<std::ctype<wchar_t>>(classic);
    const auto& named_type = std::use_facet<std::ctype<wchar_t>>(named);
    for (unsigned value = 0; value < 128; ++value)
    {
        unsigned long expected = character_mask(value);
        for (unsigned long mask = 0; mask < 1024; ++mask)
        {
            bool match = (expected & mask) != 0;
            CHECK(classic_type.is(mask, static_cast<wchar_t>(value)) == match &&
                  named_type.is(mask, static_cast<wchar_t>(value)) == match &&
                  (alix_cxx_wide_mask_matches(value, mask) != 0) == match,
                  "wide class mask combinations");
        }
    }
    for (unsigned long mask = 0; mask < 1024; ++mask)
        CHECK(!classic_type.is(mask, static_cast<wchar_t>(0xffff)) &&
              !named_type.is(mask, static_cast<wchar_t>(0xffff)) &&
              !alix_cxx_wide_mask_matches(0xffff, mask) && !alix_cxx_wide_mask_matches(WEOF, mask),
              "non-ASCII and WEOF classes");
    CHECK(classic_type.tolower(L'Z') == L'z' && named_type.toupper(L'a') == L'A' &&
          classic_type.narrow(static_cast<wchar_t>(0xffff), '?') == '?', "C wide character conversion");
    std::wstring text = L"Alix ";
    text += L"wide";
    CHECK(text == L"Alix wide" && text.find(L"wide") == 5 && text.substr(0, 4) == L"Alix", "wide string operations");
    const std::wstring high{static_cast<wchar_t>(0x100)}, low{static_cast<wchar_t>(0xff)};
    CHECK(high.compare(low) > 0, "wide element comparison");
    const std::wstring utf16{static_cast<wchar_t>(0xd83d), static_cast<wchar_t>(0xde00)};
    CHECK(utf16.size() == 2 && std::wstring(utf16) == utf16, "UTF-16 code unit storage");
    std::wostringstream output;
    output << L"wide " << 42 << L' ' << std::fixed << std::setprecision(2) << 1.25;
    CHECK(output.str() == L"wide 42 1.25", "wide stream formatting");
    std::wistringstream input(output.str());
    std::wstring word;
    int integer = 0;
    double floating = 0;
    input >> word >> integer >> floating;
    CHECK(!input.fail() && word == L"wide" && integer == 42 && floating == 1.25, "wide stream parsing");
    CHECK(std::to_wstring(0x100000000LL) == L"4294967296", "wide integer formatting");
    size_t stopped = 0;
    const std::wstring integer_text = L" -9223372036854775808tail";
    CHECK(std::stoll(integer_text, &stopped) == std::numeric_limits<long long>::min() &&
          integer_text.substr(stopped) == L"tail", "wide numeric end pointer");
    const long double precise = 1.0L + 0x1p-60L;
    std::wostringstream extended;
    extended << std::setprecision(std::numeric_limits<long double>::max_digits10) << precise;
    CHECK(std::stold(extended.str()) == precise, "wide 80-bit roundtrip");
    std::wcout << L"CXX_WIDE_TEST: wcout PASS" << std::endl;
    CHECK(!std::wcout.fail(), "native wide standard output");
    serial_printf("CXX_WIDE_TEST: PASS wchar_bits=16 masks=133120 extended80=1\n");
    return 0;
}
