#include "locale.h"
#include "limits.h"
#include "stdlib.h"
#include "string.h"

/* This is a real C/POSIX locale, not a promise of unimplemented named locales.
 * ICU supplies its own internationalization data independently of this libc. */
static char c_locale_name[] = "C";

static const char *locale_category_environment(int category)
{
    switch (category)
    {
        case LC_COLLATE: return "LC_COLLATE";
        case LC_CTYPE: return "LC_CTYPE";
        case LC_MONETARY: return "LC_MONETARY";
        case LC_NUMERIC: return "LC_NUMERIC";
        case LC_TIME: return "LC_TIME";
        case LC_MESSAGES: return "LC_MESSAGES";
        default: return NULL;
    }
}

static int locale_supported(const char *name)
{
    return strcmp(name, "C") == 0 || strcmp(name, "POSIX") == 0;
}

static int locale_environment_supported(int category)
{
    const char *name = getenv("LC_ALL");
    if (!name || !*name) name = getenv(locale_category_environment(category));
    if (!name || !*name) name = getenv("LANG");
    return !name || !*name || locale_supported(name);
}

/* Shared validation for independent locale objects. It never changes global
 * or thread selection. Unselected categories keep their C defaults. */
int __alix_locale_mask_supported(unsigned mask, const char *name)
{
    static const int categories[] = {
        LC_COLLATE, LC_CTYPE, LC_MONETARY, LC_NUMERIC, LC_TIME, LC_MESSAGES
    };
    for (unsigned i = 0; i < sizeof(categories) / sizeof(categories[0]); ++i)
    {
        if (!(mask & (1u << categories[i]))) continue;
        if (*name ? !locale_supported(name) : !locale_environment_supported(categories[i]))
            return 0;
    }
    return 1;
}

int strcoll(const char *left, const char *right)
{
    return strcmp(left, right);
}

size_t strxfrm(char *destination, const char *source, size_t size)
{
    size_t length = strlen(source);
    if (size)
    {
        size_t copied = length < size ? length : size;
        if (copied) memcpy(destination, source, copied);
        if (length < size) destination[length] = '\0';
    }
    return length;
}

char *setlocale(int category, const char *name)
{
    if (category != LC_ALL && !locale_category_environment(category)) return NULL;
    if (!name) return c_locale_name;
    if (*name) return locale_supported(name) ? c_locale_name : NULL;
    if (category == LC_ALL)
    {
        static const int categories[] = {
            LC_COLLATE, LC_CTYPE, LC_MONETARY, LC_NUMERIC, LC_TIME, LC_MESSAGES
        };
        for (unsigned i = 0; i < sizeof(categories) / sizeof(categories[0]); ++i)
        {
            if (!locale_environment_supported(categories[i])) return NULL;
        }
    }
    else if (!locale_environment_supported(category)) return NULL;
    /* The only installed selections are equivalent; no partial state update
     * is possible when LC_ALL environment resolution rejects a category. */
    return c_locale_name;
}

struct lconv *localeconv(void)
{
    /* Native x86-64 char is signed. The compiler macro also keeps host models
     * correct when their plain-char convention differs. */
#ifdef __CHAR_UNSIGNED__
#define LOCALE_CHAR_MAX (__SCHAR_MAX__ * 2 + 1)
#else
#define LOCALE_CHAR_MAX __SCHAR_MAX__
#endif
    static struct lconv convention = {
        .decimal_point = ".", .thousands_sep = "", .grouping = "",
        .int_curr_symbol = "", .currency_symbol = "", .mon_decimal_point = "",
        .mon_thousands_sep = "", .mon_grouping = "", .positive_sign = "", .negative_sign = "",
        .int_frac_digits = LOCALE_CHAR_MAX, .frac_digits = LOCALE_CHAR_MAX,
        .p_cs_precedes = LOCALE_CHAR_MAX, .p_sep_by_space = LOCALE_CHAR_MAX,
        .n_cs_precedes = LOCALE_CHAR_MAX, .n_sep_by_space = LOCALE_CHAR_MAX,
        .p_sign_posn = LOCALE_CHAR_MAX, .n_sign_posn = LOCALE_CHAR_MAX,
        .int_p_cs_precedes = LOCALE_CHAR_MAX, .int_p_sep_by_space = LOCALE_CHAR_MAX,
        .int_n_cs_precedes = LOCALE_CHAR_MAX, .int_n_sep_by_space = LOCALE_CHAR_MAX,
        .int_p_sign_posn = LOCALE_CHAR_MAX, .int_n_sign_posn = LOCALE_CHAR_MAX
    };
    return &convention;
#undef LOCALE_CHAR_MAX
}
