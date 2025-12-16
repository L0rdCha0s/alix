#ifndef CRYPTO_BIGNUM_H
#define CRYPTO_BIGNUM_H

#include "types.h"

#define BIGNUM_MAX_WORDS 128

typedef struct
{
    uint32_t words[BIGNUM_MAX_WORDS];
    size_t length;
} bignum_t;

void bignum_init(bignum_t *num);
void bignum_from_bytes(bignum_t *num, const uint8_t *data, size_t len);
void bignum_from_uint(bignum_t *num, uint32_t value);
void bignum_copy(bignum_t *dst, const bignum_t *src);
int bignum_compare(const bignum_t *a, const bignum_t *b);
void bignum_sub(bignum_t *a, const bignum_t *b);
void bignum_mulmod(const bignum_t *a, const bignum_t *b, const bignum_t *mod, bignum_t *out);
void bignum_modexp(const bignum_t *base, const bignum_t *exp, const bignum_t *mod, bignum_t *out);
void bignum_to_bytes(const bignum_t *num, uint8_t *out, size_t out_len);

#endif
