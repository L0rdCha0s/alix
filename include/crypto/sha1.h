#ifndef CRYPTO_SHA1_H
#define CRYPTO_SHA1_H

#include <stddef.h>
#include <stdint.h>

typedef struct
{
    uint32_t state[5];
    uint64_t bitcount;
    uint8_t buffer[64];
} sha1_ctx_t;

void sha1_init(sha1_ctx_t *ctx);
void sha1_update(sha1_ctx_t *ctx, const void *data, size_t len);
void sha1_final(sha1_ctx_t *ctx, uint8_t digest[20]);

#endif /* CRYPTO_SHA1_H */
