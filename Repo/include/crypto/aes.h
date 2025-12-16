#ifndef CRYPTO_AES_H
#define CRYPTO_AES_H

#include "types.h"

typedef struct
{
    uint32_t round_keys[44];
} aes128_enc_ctx_t;

typedef struct
{
    uint32_t round_keys[44];
} aes128_dec_ctx_t;

void aes128_init_encrypt(aes128_enc_ctx_t *ctx, const uint8_t key[16]);
void aes128_init_decrypt(aes128_dec_ctx_t *ctx, const uint8_t key[16]);
void aes128_encrypt_block(const aes128_enc_ctx_t *ctx, uint8_t block[16]);
void aes128_decrypt_block(const aes128_dec_ctx_t *ctx, uint8_t block[16]);

#endif
