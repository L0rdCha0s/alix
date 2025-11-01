#include "crypto/hmac.h"

#include "crypto/sha256.h"
#include "libc.h"

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[32])
{
    uint8_t k_pad[64];
    uint8_t inner_hash[32];

    if (key_len > sizeof(k_pad))
    {
        sha256_digest(key, key_len, inner_hash);
        memcpy(k_pad, inner_hash, 32);
        memset(k_pad + 32, 0, sizeof(k_pad) - 32);
    }
    else
    {
        memcpy(k_pad, key, key_len);
        memset(k_pad + key_len, 0, sizeof(k_pad) - key_len);
    }

    for (size_t i = 0; i < sizeof(k_pad); ++i)
    {
        k_pad[i] ^= 0x36;
    }

    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, k_pad, sizeof(k_pad));
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, inner_hash);

    for (size_t i = 0; i < sizeof(k_pad); ++i)
    {
        k_pad[i] ^= 0x36 ^ 0x5C;
    }

    sha256_init(&ctx);
    sha256_update(&ctx, k_pad, sizeof(k_pad));
    sha256_update(&ctx, inner_hash, sizeof(inner_hash));
    sha256_final(&ctx, out);

    memset(k_pad, 0, sizeof(k_pad));
    memset(inner_hash, 0, sizeof(inner_hash));
}
