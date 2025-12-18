#ifndef CRYPTO_P384_H
#define CRYPTO_P384_H

#include "types.h"

#define P384_POINT_SIZE 97
#define P384_SCALAR_SIZE 48

bool p384_is_valid_public(const uint8_t *point, size_t length);
bool p384_generate_public(const uint8_t scalar[P384_SCALAR_SIZE],
                          uint8_t out_point[P384_POINT_SIZE]);
bool p384_compute_shared(const uint8_t scalar[P384_SCALAR_SIZE],
                         const uint8_t *peer_point, size_t peer_len,
                         uint8_t out_secret[P384_SCALAR_SIZE]);
bool p384_scalar_is_valid(const uint8_t scalar[P384_SCALAR_SIZE]);
bool p384_ecdsa_verify(const uint8_t *public_point, size_t public_len,
                       const uint8_t hash[32],
                       const uint8_t r[P384_SCALAR_SIZE],
                       const uint8_t s[P384_SCALAR_SIZE]);

#endif
