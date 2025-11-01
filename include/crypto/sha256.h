#ifndef CRYPTO_SHA256_H
#define CRYPTO_SHA256_H

#include "types.h"

typedef struct
{
    uint32_t state[8];
    uint64_t bitcount;
    uint8_t buffer[64];
} sha256_ctx_t;

void sha256_init(sha256_ctx_t *ctx);
void sha256_update(sha256_ctx_t *ctx, const void *data, size_t len);
void sha256_final(sha256_ctx_t *ctx, uint8_t out[32]);
void sha256_digest(const void *data, size_t len, uint8_t out[32]);

#endif
