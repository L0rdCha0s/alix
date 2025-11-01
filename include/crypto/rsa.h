#ifndef CRYPTO_RSA_H
#define CRYPTO_RSA_H

#include "crypto/bignum.h"

typedef struct
{
    bignum_t modulus;
    bignum_t exponent;
} rsa_public_key_t;

typedef bool (*rsa_random_cb)(uint8_t *buffer, size_t length, void *ctx);

void rsa_public_key_init(rsa_public_key_t *key);
void rsa_public_key_set(rsa_public_key_t *key, const uint8_t *modulus, size_t modulus_len,
                        const uint8_t *exponent, size_t exponent_len);
size_t rsa_public_key_size(const rsa_public_key_t *key);
bool rsa_encrypt_pkcs1_v15(const rsa_public_key_t *key,
                           const uint8_t *message, size_t message_len,
                           uint8_t *out, size_t out_len,
                           rsa_random_cb random_cb, void *random_ctx);

#endif
