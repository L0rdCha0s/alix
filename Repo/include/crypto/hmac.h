#ifndef CRYPTO_HMAC_H
#define CRYPTO_HMAC_H

#include "types.h"

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[32]);

#endif
