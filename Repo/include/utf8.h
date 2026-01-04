#ifndef UTF8_H
#define UTF8_H

#include "types.h"

typedef struct
{
    uint32_t codepoint;
    uint8_t consumed;
    bool valid;
} utf8_decode_result_t;

/* Decode the next codepoint from a NUL-terminated UTF-8 string. */
utf8_decode_result_t utf8_decode_one(const char *s);

/* Decode the next codepoint from a UTF-8 buffer with explicit length. */
utf8_decode_result_t utf8_decode_one_len(const char *s, size_t len);

/* Encode one codepoint as UTF-8 into `out` (must have space for 4 bytes). */
size_t utf8_encode_one(uint32_t codepoint, char out[4]);

/*
 * Return the byte index of the start of the last codepoint in `s[0..len)`.
 *
 * If the trailing bytes are not a valid UTF-8 sequence, this returns `len - 1`
 * so callers can delete a single byte and retry.
 */
size_t utf8_prev_char_start(const char *s, size_t len);

#endif /* UTF8_H */
