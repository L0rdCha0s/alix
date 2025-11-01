#include "crypto/rsa.h"

#include "libc.h"

void rsa_public_key_init(rsa_public_key_t *key)
{
    bignum_init(&key->modulus);
    bignum_init(&key->exponent);
}

static size_t rsa_modulus_bytes(const rsa_public_key_t *key)
{
    if (key->modulus.length == 0)
    {
        return 0;
    }
    size_t bits = (key->modulus.length - 1) * 32;
    uint32_t last = key->modulus.words[key->modulus.length - 1];
    while (last != 0)
    {
        bits++;
        last >>= 1U;
    }
    size_t bytes = (bits + 7) / 8;
    return bytes;
}

void rsa_public_key_set(rsa_public_key_t *key, const uint8_t *modulus, size_t modulus_len,
                        const uint8_t *exponent, size_t exponent_len)
{
    bignum_from_bytes(&key->modulus, modulus, modulus_len);
    bignum_from_bytes(&key->exponent, exponent, exponent_len);
}

size_t rsa_public_key_size(const rsa_public_key_t *key)
{
    return rsa_modulus_bytes(key);
}

bool rsa_encrypt_pkcs1_v15(const rsa_public_key_t *key,
                           const uint8_t *message, size_t message_len,
                           uint8_t *out, size_t out_len,
                           rsa_random_cb random_cb, void *random_ctx)
{
    if (!key || !random_cb)
    {
        return false;
    }
    size_t k = rsa_modulus_bytes(key);
    if (out_len < k || k < 11 || message_len > k - 11)
    {
        return false;
    }

    uint8_t *em = (uint8_t *)malloc(k);
    if (!em)
    {
        return false;
    }

    em[0] = 0x00;
    em[1] = 0x02;
    size_t ps_len = k - message_len - 3;
    size_t idx = 2;
    while (ps_len > 0)
    {
        uint8_t byte = 0;
        if (!random_cb(&byte, 1, random_ctx))
        {
            free(em);
            return false;
        }
        if (byte == 0)
        {
            continue;
        }
        em[idx++] = byte;
        ps_len--;
    }
    em[idx++] = 0x00;
    memcpy(em + idx, message, message_len);

    bignum_t m;
    bignum_t c;
    bignum_from_bytes(&m, em, k);
    bignum_modexp(&m, &key->exponent, &key->modulus, &c);
    bignum_to_bytes(&c, out, k);

    memset(em, 0, k);
    free(em);
    return true;
}
