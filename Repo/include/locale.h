#ifndef ALIX_LOCALE_H
#define ALIX_LOCALE_H

#ifdef TTF_HOST_BUILD
#include_next <locale.h>
#else

#define LC_ALL 0
#define LC_COLLATE 1
#define LC_CTYPE 2
#define LC_MONETARY 3
#define LC_NUMERIC 4
#define LC_TIME 5
#define LC_MESSAGES 6

#define LC_COLLATE_MASK (1u << LC_COLLATE)
#define LC_CTYPE_MASK (1u << LC_CTYPE)
#define LC_MONETARY_MASK (1u << LC_MONETARY)
#define LC_NUMERIC_MASK (1u << LC_NUMERIC)
#define LC_TIME_MASK (1u << LC_TIME)
#define LC_MESSAGES_MASK (1u << LC_MESSAGES)
#define LC_ALL_MASK (LC_COLLATE_MASK | LC_CTYPE_MASK | LC_MONETARY_MASK | \
                     LC_NUMERIC_MASK | LC_TIME_MASK | LC_MESSAGES_MASK)

typedef struct alix_locale *locale_t;
#define LC_GLOBAL_LOCALE ((locale_t)-1)

struct lconv
{
    char *decimal_point, *thousands_sep, *grouping;
    char *int_curr_symbol, *currency_symbol, *mon_decimal_point;
    char *mon_thousands_sep, *mon_grouping, *positive_sign, *negative_sign;
    char int_frac_digits, frac_digits, p_cs_precedes, p_sep_by_space;
    char n_cs_precedes, n_sep_by_space, p_sign_posn, n_sign_posn;
    char int_p_cs_precedes, int_p_sep_by_space, int_n_cs_precedes;
    char int_n_sep_by_space, int_p_sign_posn, int_n_sign_posn;
};

#ifdef __cplusplus
extern "C" {
#endif
/* Only C and its POSIX alias are installed. Unsupported selections fail. */
char *setlocale(int category, const char *locale);
struct lconv *localeconv(void);
locale_t newlocale(int category_mask, const char *locale, locale_t base);
void freelocale(locale_t locale);
locale_t duplocale(locale_t locale);
locale_t uselocale(locale_t locale);
#ifdef __cplusplus
}
#endif
#endif
#endif
