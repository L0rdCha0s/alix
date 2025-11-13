#include "crypto/rsa.h"

#include "crypto/sha256.h"
#include "libc.h"
#include "serial.h"

#ifndef RSA_DEBUG_LOG
#define RSA_DEBUG_LOG 1
#endif

#define RSA_EM_STACK_SIZE 512

#if RSA_DEBUG_LOG
static void rsa_log_msg(const char *msg)
{
    serial_write_string("[rsa] ");
    serial_write_string(msg);
    serial_write_string("\r\n");
}

static void rsa_log_value(const char *msg, uint64_t value)
{
    serial_write_string("[rsa] ");
    serial_write_string(msg);
    serial_write_string("0x");
    serial_write_hex64(value);
    serial_write_string("\r\n");
}

static void rsa_log_bytes(const char *label, const uint8_t *data, size_t len)
{
    static const char hex_digits[] = "0123456789abcdef";
    const size_t max_dump = 32;
    serial_write_string("[rsa] ");
    serial_write_string(label);
    serial_write_string(": ");
    if (!data || len == 0)
    {
        serial_write_string("<empty>\r\n");
        return;
    }
    size_t limit = (len < max_dump) ? len : max_dump;
    for (size_t i = 0; i < limit; ++i)
    {
        char buf[3];
        uint8_t byte = data[i];
        buf[0] = hex_digits[byte >> 4];
        buf[1] = hex_digits[byte & 0x0F];
        buf[2] = '\0';
        serial_write_string(buf);
    }
    if (len > limit)
    {
        serial_write_string("...");
    }
    serial_write_string("\r\n");
}
#else
static inline void rsa_log_msg(const char *msg) { (void)msg; }
static inline void rsa_log_value(const char *msg, uint64_t value) { (void)msg; (void)value; }
static inline void rsa_log_bytes(const char *label, const uint8_t *data, size_t len)
{
    (void)label;
    (void)data;
    (void)len;
}
#endif

static void rsa_zero_and_free(uint8_t *buf, size_t len, bool heap)
{
    if (!buf)
    {
        return;
    }
    if (len != 0)
    {
        memset(buf, 0, len);
    }
    if (heap)
    {
        free(buf);
    }
}

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

    uint8_t em_stack[RSA_EM_STACK_SIZE];
    uint8_t *em = em_stack;
    bool em_heap = false;
    if (k > sizeof(em_stack))
    {
        em = (uint8_t *)malloc(k);
        if (!em)
        {
            rsa_log_msg("encrypt: failed to allocate em buffer");
            return false;
        }
        em_heap = true;
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
            rsa_zero_and_free(em, k, em_heap);
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

    rsa_zero_and_free(em, k, em_heap);
    return true;
}

bool rsa_verify_pkcs1_v15_sha256(const rsa_public_key_t *key,
                                 const uint8_t *data, size_t data_len,
                                 const uint8_t *signature, size_t signature_len)
{
    if (!key || !data || !signature)
    {
        rsa_log_msg("verify: null input pointer");
        return false;
    }
    size_t k = rsa_modulus_bytes(key);
    if (k == 0 || signature_len != k)
    {
        rsa_log_msg("verify: modulus/signature length mismatch");
        rsa_log_value("modulus_bytes=", k);
        rsa_log_value("signature_len=", signature_len);
        return false;
    }
    rsa_log_msg("verify: PKCS#1 v1.5 SHA256");
    rsa_log_value("data_len=", data_len);
    rsa_log_value("modulus_bytes=", k);
    rsa_log_value("signature_len=", signature_len);

    bignum_t sig_bn;
    bignum_from_bytes(&sig_bn, signature, signature_len);
    bignum_t em_bn;
    bignum_modexp(&sig_bn, &key->exponent, &key->modulus, &em_bn);
    rsa_log_msg("verify: modular exponentiation complete");

    uint8_t em_stack[RSA_EM_STACK_SIZE];
    uint8_t *em = em_stack;
    bool em_heap = false;
    if (k > sizeof(em_stack))
    {
        em = (uint8_t *)malloc(k);
        if (!em)
        {
            rsa_log_msg("verify: failed to allocate em buffer");
            return false;
        }
        em_heap = true;
    }
    rsa_log_msg("verify: converting EM to bytes");
    memset(em, 0, k);
    bignum_to_bytes(&em_bn, em, k);
    rsa_log_bytes("EM first64", em, (k < 64) ? k : 64);

    if (k < 11 || em[0] != 0x00 || em[1] != 0x01)
    {
        rsa_log_msg("verify: invalid PKCS#1 header");
        rsa_log_bytes("EM head", em, k < 32 ? k : 32);
        rsa_zero_and_free(em, k, em_heap);
        return false;
    }
    size_t idx = 2;
    size_t pad_len = 0;
    while (idx < k && em[idx] == 0xFF)
    {
        idx++;
        pad_len++;
    }
    rsa_log_value("padding_len=", pad_len);
    if (idx < 10 || idx >= k || em[idx] != 0x00)
    {
        rsa_log_msg("verify: missing 0x00 separator after padding");
        rsa_zero_and_free(em, k, em_heap);
        return false;
    }
    idx++;
    rsa_log_value("digest_info_offset=", idx);

    static const uint8_t sha256_digest_info_prefix[] = {
        0x30, 0x31,
        0x30, 0x0d,
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00,
        0x04, 0x20
    };
    if (idx + sizeof(sha256_digest_info_prefix) + 32 != k)
    {
        rsa_log_msg("verify: digest info size mismatch");
        rsa_log_value("idx=", idx);
        rsa_log_value("k=", k);
        rsa_zero_and_free(em, k, em_heap);
        return false;
    }
    if (memcmp(em + idx, sha256_digest_info_prefix, sizeof(sha256_digest_info_prefix)) != 0)
    {
        rsa_log_msg("verify: digest info prefix mismatch");
        rsa_zero_and_free(em, k, em_heap);
        return false;
    }
    idx += sizeof(sha256_digest_info_prefix);

    uint8_t digest[32];
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, digest);

    bool ok = (memcmp(em + idx, digest, sizeof(digest)) == 0);
    if (!ok)
    {
        rsa_log_msg("verify: digest mismatch");
        rsa_log_bytes("expected", digest, sizeof(digest));
        rsa_log_bytes("from_signature", em + idx, sizeof(digest));
        rsa_log_bytes("signature_prefix", signature, signature_len < 32 ? signature_len : 32);
    }
    else
    {
        rsa_log_msg("verify: digest match");
    }

    memset(digest, 0, sizeof(digest));
    rsa_zero_and_free(em, k, em_heap);
    return ok;
}
