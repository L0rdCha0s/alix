#ifndef ALIX_PRINTF_FLOAT_H
#define ALIX_PRINTF_FLOAT_H
#include <stddef.h>

#define ALIX_PRINTF_ALT (1u << ('#' - ' '))
#define ALIX_PRINTF_ZERO (1u << ('0' - ' '))
#define ALIX_PRINTF_LEFT (1u << ('-' - ' '))
#define ALIX_PRINTF_SPACE (1u << (' ' - ' '))
#define ALIX_PRINTF_PLUS (1u << ('+' - ' '))

/* Synchronous callbacks on the calling thread, never retained or published. */
typedef struct
{
    void *context;
    void (*write)(void *context, const char *bytes, size_t length);
    void (*pad)(void *context, char byte, int count);
} alix_printf_float_output_t;

int alix_printf_float(const alix_printf_float_output_t *output, long double value,
                      int width, int precision, unsigned flags, char conversion);
#endif
