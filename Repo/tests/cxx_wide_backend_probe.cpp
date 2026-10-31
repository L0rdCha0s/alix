#define _LIBCPP_BUILDING_LIBRARY 1
#include <locale>

static_assert(std::ctype_base::space == (1UL << 0));
static_assert(std::ctype_base::print == (1UL << 1));
static_assert(std::ctype_base::cntrl == (1UL << 2));
static_assert(std::ctype_base::upper == (1UL << 3));
static_assert(std::ctype_base::lower == (1UL << 4));
static_assert(std::ctype_base::alpha == (1UL << 5));
static_assert(std::ctype_base::digit == (1UL << 6));
static_assert(std::ctype_base::punct == (1UL << 7));
static_assert(std::ctype_base::xdigit == (1UL << 8));
static_assert(std::ctype_base::blank == (1UL << 9));

extern "C" int alix_cxx_wide_mask_matches(wint_t value, unsigned long mask)
{
    return std::__locale::__iswctype(value, mask, nullptr) != 0;
}
