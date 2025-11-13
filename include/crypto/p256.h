#ifndef CRYPTO_P256_H
#define CRYPTO_P256_H

#include "types.h"

#define P256_POINT_SIZE 65
#define P256_SCALAR_SIZE 32

bool p256_is_valid_public(const uint8_t *point, size_t length);
bool p256_generate_public(const uint8_t scalar[P256_SCALAR_SIZE],
                          uint8_t out_point[P256_POINT_SIZE]);
bool p256_compute_shared(const uint8_t scalar[P256_SCALAR_SIZE],
                         const uint8_t *peer_point, size_t peer_len,
                         uint8_t out_secret[P256_SCALAR_SIZE]);
bool p256_scalar_is_valid(const uint8_t scalar[P256_SCALAR_SIZE]);

#endif
