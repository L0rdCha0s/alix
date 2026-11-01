#ifdef TTF_HOST_BUILD
#include_next <assert.h>
#else
#if !defined(__cplusplus) && __STDC_VERSION__ >= 201112L
#define static_assert _Static_assert
#endif
#ifndef ALIX_ASSERT_DECLARED
#define ALIX_ASSERT_DECLARED
#ifdef __cplusplus
extern "C" {
#endif
void __assert_fail(const char *expression, const char *file, unsigned line,
                   const char *function) __attribute__((noreturn));
#ifdef __cplusplus
}
#endif
#endif
#undef assert
#ifdef NDEBUG
#define assert(expression) ((void)0)
#else
#define assert(expression) ((expression) ? (void)0 : __assert_fail(#expression, __FILE__, __LINE__, __func__))
#endif
#endif
