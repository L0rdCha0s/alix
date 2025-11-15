/*
 * Minimal TLS 1.2 client implementation supporting the
 * TLS_RSA_WITH_AES_128_CBC_SHA256 cipher suite.
 *
 * This code handles a narrow subset of TLS sufficient for
 * performing HTTPS GET requests against servers that still
 * allow RSA key exchange. Certificate chain validation is
 * not performed; the server certificate is only parsed to
 * extract its RSA public key. This exists solely to unblock
 * simple HTTPS downloads inside the Alix environment.
 */

#include "net/tls.h"

#include "crypto/hmac.h"
#include "crypto/p256.h"
#include "net/tls_asn1.h"
#include "timer.h"
#include "serial.h"
#include "libc.h"
#include "process.h"
#include <stddef.h>

#ifndef TLS_DEBUG_SIG
#define TLS_DEBUG_SIG 1
#endif

#define TLS_VERSION_MAJOR 0x03
#define TLS_VERSION_MINOR 0x03

#define TLS_CONTENT_CHANGE_CIPHER_SPEC 20
#define TLS_CONTENT_ALERT             21
#define TLS_CONTENT_HANDSHAKE         22
#define TLS_CONTENT_APPLICATION_DATA  23

#define TLS_HANDSHAKE_CLIENT_HELLO    1
#define TLS_HANDSHAKE_SERVER_HELLO    2
#define TLS_HANDSHAKE_CERTIFICATE     11
#define TLS_HANDSHAKE_SERVER_KEY_EXCHANGE 12
#define TLS_HANDSHAKE_SERVER_HELLO_DONE 14
#define TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE 16
#define TLS_HANDSHAKE_FINISHED        20

#define TLS_ALERT_LEVEL_WARNING       1
#define TLS_ALERT_LEVEL_FATAL         2
#define TLS_ALERT_CLOSE_NOTIFY        0

#define TLS_CIPHER_RSA_WITH_AES_128_CBC_SHA256    0x003C
#define TLS_CIPHER_ECDHE_RSA_WITH_AES_128_CBC_SHA256 0xC027
#define TLS_CIPHER_ECDHE_RSA_WITH_AES_128_GCM_SHA256 0xC02F

#define TLS_EXT_SERVER_NAME           0x0000
#define TLS_EXT_SUPPORTED_GROUPS      0x000A
#define TLS_EXT_EC_POINT_FORMATS      0x000B
#define TLS_EXT_SIGNATURE_ALGORITHMS  0x000D

#define TLS_NAMED_CURVE_SECP256R1     23

#define TLS_MAX_FRAGMENT              16384
#define TLS_MAC_SIZE                  32
#define TLS_BLOCK_SIZE                16
#define TLS_EXPLICIT_IV_SIZE          16
#define TLS_GCM_FIXED_IV_SIZE         4
#define TLS_GCM_EXPLICIT_IV_SIZE      8
#define TLS_GCM_TAG_SIZE              16
#define TLS_MAX_RECORD                (TLS_EXPLICIT_IV_SIZE + TLS_MAX_FRAGMENT + TLS_MAC_SIZE + TLS_BLOCK_SIZE + 5)
#define TLS_APPLICATION_CHUNK         1024

#define TLS_LABEL_MASTER_SECRET       "master secret"
#define TLS_LABEL_KEY_EXPANSION       "key expansion"
#define TLS_LABEL_CLIENT_FINISHED     "client finished"
#define TLS_LABEL_SERVER_FINISHED     "server finished"

static uint32_t g_tls_prng_state = 0xC3E4ED12U;

static bool tls_cipher_is_aead(uint16_t suite)
{
    return suite == TLS_CIPHER_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
}

static void tls_prng_mix(uint32_t value)
{
    if (value == 0)
    {
        value = 0xA5A5A5A5U;
    }
    g_tls_prng_state ^= value;
    g_tls_prng_state ^= g_tls_prng_state << 13;
    g_tls_prng_state ^= g_tls_prng_state >> 17;
    g_tls_prng_state ^= g_tls_prng_state << 5;
}

static void tls_prng_seed(void)
{
    uint64_t ticks = timer_ticks();
    tls_prng_mix((uint32_t)ticks);
    tls_prng_mix((uint32_t)(ticks >> 32));
    tls_prng_mix((uint32_t)(uintptr_t)&ticks);
}

static uint32_t tls_prng_next(void)
{
    tls_prng_seed();
    uint32_t x = g_tls_prng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_tls_prng_state = x;
    return x;
}

static bool tls_random_bytes(uint8_t *out, size_t len)
{
    if (!out)
    {
        return false;
    }
    uint32_t value = 0;
    int shift = 0;
    for (size_t i = 0; i < len; ++i)
    {
        if (shift == 0)
        {
            value = tls_prng_next();
            shift = 32;
        }
        out[i] = (uint8_t)value;
        value >>= 8;
        shift -= 8;
    }
    return true;
}

static bool tls_random_fill(uint8_t *buffer, size_t length, void *context)
{
    (void)context;
    return tls_random_bytes(buffer, length);
}

static void tls_log(const char *msg)
{
    serial_printf("%s", msg);
    serial_printf("%s", "\r\n");
}

static void tls_log_hex(const char *prefix, uint64_t value)
{
    serial_printf("%s", prefix);
    serial_printf("%016llX", (unsigned long long)(value));
    serial_printf("%s", "\r\n");
}

#if TLS_DEBUG_SIG
static void tls_log_hexdump(const char *label, const uint8_t *data, size_t len)
{
    static const char hex_digits[] = "0123456789abcdef";
    serial_printf("%s", label);
    serial_printf("%s", ": ");
    if (!data || len == 0)
    {
        serial_printf("%s", "<empty>\r\n");
        return;
    }
    for (size_t i = 0; i < len; ++i)
    {
        char buf[3];
        uint8_t byte = data[i];
        buf[0] = hex_digits[(byte >> 4) & 0x0F];
        buf[1] = hex_digits[byte & 0x0F];
        buf[2] = '\0';
        serial_printf("%s", buf);
    }
    serial_printf("%s", "\r\n");
}

static void tls_log_sha256_digest(const char *label, const uint8_t *data, size_t len)
{
    uint8_t digest[32];
    sha256_digest(data, len, digest);
    tls_log_hexdump(label, digest, sizeof(digest));
}
#else
static inline void tls_log_hexdump(const char *label, const uint8_t *data, size_t len)
{
    (void)label;
    (void)data;
    (void)len;
}

static inline void tls_log_sha256_digest(const char *label, const uint8_t *data, size_t len)
{
    (void)label;
    (void)data;
    (void)len;
}
#endif

#define TLS_FAIL(msg) do { tls_log(msg); return false; } while (0)

static void tls_handshake_hash_update(tls_session_t *session, const uint8_t *data, size_t len)
{
    sha256_update(&session->handshake_hash, data, len);
}

static void tls_serialize_uint24(uint8_t out[3], size_t value)
{
    out[0] = (uint8_t)((value >> 16) & 0xFF);
    out[1] = (uint8_t)((value >> 8) & 0xFF);
    out[2] = (uint8_t)(value & 0xFF);
}

static uint16_t tls_read_uint16(const uint8_t *data)
{
    return (uint16_t)((data[0] << 8) | data[1]);
}

static size_t tls_read_uint24(const uint8_t *data)
{
    return ((size_t)data[0] << 16) | ((size_t)data[1] << 8) | (size_t)data[2];
}

static void tls_serialize_seq(uint64_t seq, uint8_t out[8])
{
    for (int i = 7; i >= 0; --i)
    {
        out[i] = (uint8_t)(seq & 0xFF);
        seq >>= 8;
    }
}

static void tls_increment_seq(uint64_t *seq)
{
    (*seq)++;
}

static uint64_t tls_default_timeout_ticks(void)
{
    uint32_t freq = timer_frequency();
    if (freq == 0)
    {
        freq = 100;
    }
    return (uint64_t)freq * 15;
}

static bool tls_socket_read_exact(tls_session_t *session, uint8_t *out, size_t len, uint64_t timeout_ticks)
{
    if (!session || session->socket_fd < 0)
    {
        tls_log("TLS: socket read invalid session/fd");
        return false;
    }

    uint64_t start = timer_ticks();
    size_t remaining = len;
    while (remaining > 0)
    {
        if (net_tcp_socket_has_error(session->socket))
        {
            tls_log("TLS: socket read detected tcp error");
            return false;
        }

        ssize_t got = read(session->socket_fd, out, remaining);
        if (got < 0)
        {
            if (timer_ticks() - start >= timeout_ticks)
            {
                tls_log("TLS: socket read timeout waiting for data");
                return false;
            }
            continue;
        }
        if (got == 0)
        {
            if (net_tcp_socket_remote_closed(session->socket))
            {
                tls_log("TLS: socket read saw remote close");
                return false;
            }
            if (timer_ticks() - start >= timeout_ticks)
            {
                tls_log("TLS: socket read timeout while idle");
                return false;
            }
            continue;
        }

        out += got;
        remaining -= (size_t)got;
        start = timer_ticks();
        process_yield();
    }
    return true;
}

static bool tls_socket_write_all(tls_session_t *session, const uint8_t *data, size_t len, uint64_t timeout_ticks)
{
    if (!session || !session->socket || !data || len == 0)
    {
        tls_log("TLS: socket write invalid args");
        return false;
    }

    uint64_t start = timer_ticks();
    while (true)
    {
        if (net_tcp_socket_has_error(session->socket))
        {
            tls_log("TLS: socket has error during write");
            return false;
        }
        if (net_tcp_socket_remote_closed(session->socket))
        {
            tls_log("TLS: socket remote closed during write");
            return false;
        }
        if (net_tcp_socket_send(session->socket, data, len))
        {
            return true;
        }
        if (timer_ticks() - start >= timeout_ticks)
        {
            tls_log("TLS: socket write timeout");
            return false;
        }
        process_yield();
    }
}

static bool tls_write_record_plain(tls_session_t *session, uint8_t type, const uint8_t *data, size_t len)
{
    uint8_t header[5];
    header[0] = type;
    header[1] = TLS_VERSION_MAJOR;
    header[2] = TLS_VERSION_MINOR;
    header[3] = (uint8_t)((len >> 8) & 0xFF);
    header[4] = (uint8_t)(len & 0xFF);

    uint8_t record[5 + TLS_MAX_FRAGMENT];
    memcpy(record, header, 5);
    if (len > 0)
    {
        memcpy(record + 5, data, len);
    }
    return tls_socket_write_all(session, record, 5 + len, tls_default_timeout_ticks());
}

static bool tls_read_record_plain(tls_session_t *session, uint8_t *type, size_t *length, uint64_t timeout)
{
    uint8_t header[5];
    if (!tls_socket_read_exact(session, header, sizeof(header), timeout))
    {
        tls_log("TLS: failed to read record header (plain)");
        return false;
    }
    size_t len = ((size_t)header[3] << 8) | (size_t)header[4];
    if (len > sizeof(session->record_buffer))
    {
        tls_log("TLS: record length exceeds buffer (plain)");
        return false;
    }
    if (!tls_socket_read_exact(session, session->record_buffer, len, timeout))
    {
        tls_log("TLS: failed to read record body (plain)");
        return false;
    }
    if (type)
    {
        *type = header[0];
    }
    if (length)
    {
        *length = len;
    }
    return true;
}

static bool tls_prf(const uint8_t *secret, size_t secret_len,
                    const char *label, const uint8_t *seed, size_t seed_len,
                    uint8_t *out, size_t out_len)
{
    size_t label_len = strlen(label);
    size_t total_seed = label_len + seed_len;
    uint8_t label_seed[64 + 64];
    if (total_seed > sizeof(label_seed))
    {
        return false;
    }
    memcpy(label_seed, label, label_len);
    memcpy(label_seed + label_len, seed, seed_len);

    uint8_t a[32];
    hmac_sha256(secret, secret_len, label_seed, total_seed, a);

    size_t produced = 0;
    while (produced < out_len)
    {
        uint8_t buffer[32 + sizeof(label_seed)];
        memcpy(buffer, a, sizeof(a));
        memcpy(buffer + sizeof(a), label_seed, total_seed);

        uint8_t block[32];
        hmac_sha256(secret, secret_len, buffer, sizeof(a) + total_seed, block);

        size_t to_copy = out_len - produced;
        if (to_copy > sizeof(block))
        {
            to_copy = sizeof(block);
        }
        memcpy(out + produced, block, to_copy);
        produced += to_copy;

        hmac_sha256(secret, secret_len, a, sizeof(a), a);
    }

    memset(a, 0, sizeof(a));
    memset(label_seed, 0, sizeof(label_seed));
    return true;
}

static bool tls_compute_master_secret(tls_session_t *session,
                                      const uint8_t *pre_master,
                                      size_t pre_master_len)
{
    uint8_t seed[64];
    memcpy(seed, session->client_random, 32);
    memcpy(seed + 32, session->server_random, 32);
    bool ok = tls_prf(pre_master, pre_master_len, TLS_LABEL_MASTER_SECRET, seed, sizeof(seed),
                      session->master_secret, sizeof(session->master_secret));
#if TLS_DEBUG_SIG
    if (ok)
    {
        tls_log_hexdump("TLS: master secret", session->master_secret, sizeof(session->master_secret));
    }
#endif
    return ok;
}

static bool tls_compute_key_block(tls_session_t *session)
{
    uint8_t seed[64];
    memcpy(seed, session->server_random, 32);
    memcpy(seed + 32, session->client_random, 32);
#if TLS_DEBUG_SIG
    tls_log_hexdump("TLS: key block server_random", session->server_random, 32);
    tls_log_hexdump("TLS: key block client_random", session->client_random, 32);
#endif

    if (tls_cipher_is_aead(session->cipher_suite))
    {
        uint8_t key_block[16 + 16 + TLS_GCM_FIXED_IV_SIZE + TLS_GCM_FIXED_IV_SIZE];
        if (!tls_prf(session->master_secret, sizeof(session->master_secret),
                     TLS_LABEL_KEY_EXPANSION, seed, sizeof(seed),
                     key_block, sizeof(key_block)))
        {
            return false;
        }
        size_t offset = 0;
        memcpy(session->client_write_key, key_block + offset, 16);
        offset += 16;
        memcpy(session->server_write_key, key_block + offset, 16);
        offset += 16;
        memcpy(session->client_write_iv, key_block + offset, TLS_GCM_FIXED_IV_SIZE);
        offset += TLS_GCM_FIXED_IV_SIZE;
        memcpy(session->server_write_iv, key_block + offset, TLS_GCM_FIXED_IV_SIZE);

        memset(session->client_write_mac, 0, TLS_MAC_SIZE);
        memset(session->server_write_mac, 0, TLS_MAC_SIZE);

        aes128_init_encrypt(&session->client_enc, session->client_write_key);
        aes128_init_encrypt(&session->server_enc, session->server_write_key);

        uint8_t zero_block[16] = {0};
        memcpy(session->client_gcm_H, zero_block, sizeof(zero_block));
        aes128_encrypt_block(&session->client_enc, session->client_gcm_H);
        memset(zero_block, 0, sizeof(zero_block));
        memcpy(session->server_gcm_H, zero_block, sizeof(zero_block));
        aes128_encrypt_block(&session->server_enc, session->server_gcm_H);

        memset(key_block, 0, sizeof(key_block));
    }
    else
    {
        uint8_t key_block[128];
        if (!tls_prf(session->master_secret, sizeof(session->master_secret),
                     TLS_LABEL_KEY_EXPANSION, seed, sizeof(seed),
                     key_block, sizeof(key_block)))
        {
            return false;
        }

        size_t offset = 0;
        memcpy(session->client_write_mac, key_block + offset, TLS_MAC_SIZE);
        offset += TLS_MAC_SIZE;
        memcpy(session->server_write_mac, key_block + offset, TLS_MAC_SIZE);
        offset += TLS_MAC_SIZE;
        memcpy(session->client_write_key, key_block + offset, 16);
        offset += 16;
        memcpy(session->server_write_key, key_block + offset, 16);
        offset += 16;
        memcpy(session->client_write_iv, key_block + offset, TLS_BLOCK_SIZE);
        offset += TLS_BLOCK_SIZE;
        memcpy(session->server_write_iv, key_block + offset, TLS_BLOCK_SIZE);

        aes128_init_encrypt(&session->client_enc, session->client_write_key);
        aes128_init_encrypt(&session->server_enc, session->server_write_key);
        aes128_init_decrypt(&session->server_dec, session->server_write_key);
        memset(session->client_gcm_H, 0, sizeof(session->client_gcm_H));
        memset(session->server_gcm_H, 0, sizeof(session->server_gcm_H));
        memset(key_block, 0, sizeof(key_block));
    }
#if TLS_DEBUG_SIG
    tls_log_hexdump("TLS: client_write_key", session->client_write_key, sizeof(session->client_write_key));
    tls_log_hexdump("TLS: server_write_key", session->server_write_key, sizeof(session->server_write_key));
    size_t iv_len = tls_cipher_is_aead(session->cipher_suite) ? TLS_GCM_FIXED_IV_SIZE : TLS_BLOCK_SIZE;
    tls_log_hexdump("TLS: client_write_iv", session->client_write_iv, iv_len);
    tls_log_hexdump("TLS: server_write_iv", session->server_write_iv, iv_len);
#endif
    return true;
}

static void tls_xor_block(uint8_t *dst, const uint8_t *src)
{
    for (size_t i = 0; i < TLS_BLOCK_SIZE; ++i)
    {
        dst[i] ^= src[i];
    }
}

static void tls_cbc_encrypt(const aes128_enc_ctx_t *ctx, uint8_t *data, size_t len, const uint8_t *iv)
{
    uint8_t prev[TLS_BLOCK_SIZE];
    memcpy(prev, iv, TLS_BLOCK_SIZE);
    for (size_t offset = 0; offset < len; offset += TLS_BLOCK_SIZE)
    {
        tls_xor_block(data + offset, prev);
        aes128_encrypt_block(ctx, data + offset);
        memcpy(prev, data + offset, TLS_BLOCK_SIZE);
    }
}

static void tls_cbc_decrypt(const aes128_dec_ctx_t *ctx, uint8_t *data, size_t len, const uint8_t *iv)
{
    uint8_t prev[TLS_BLOCK_SIZE];
    memcpy(prev, iv, TLS_BLOCK_SIZE);
    for (size_t offset = 0; offset < len; offset += TLS_BLOCK_SIZE)
    {
        uint8_t current[TLS_BLOCK_SIZE];
        memcpy(current, data + offset, TLS_BLOCK_SIZE);
        aes128_decrypt_block(ctx, data + offset);
        tls_xor_block(data + offset, prev);
        memcpy(prev, current, TLS_BLOCK_SIZE);
    }
}

static void tls_build_additional_data(uint8_t out[13], uint64_t seq, uint8_t type, size_t length)
{
    tls_serialize_seq(seq, out);
    out[8] = type;
    out[9] = TLS_VERSION_MAJOR;
    out[10] = TLS_VERSION_MINOR;
    out[11] = (uint8_t)((length >> 8) & 0xFF);
    out[12] = (uint8_t)(length & 0xFF);
}

static bool tls_calculate_mac(uint8_t *mac_out,
                              const uint8_t *mac_key,
                              uint64_t seq,
                              uint8_t type,
                              size_t length,
                              const uint8_t *fragment)
{
    uint8_t mac_input[13 + TLS_MAX_FRAGMENT];
    tls_build_additional_data(mac_input, seq, type, length);
    memcpy(mac_input + 13, fragment, length);

    hmac_sha256(mac_key, TLS_MAC_SIZE, mac_input, 13 + length, mac_out);
    memset(mac_input, 0, sizeof(mac_input));
    return true;
}

static void gcm_mult(uint8_t out[16], const uint8_t x[16], const uint8_t h[16])
{
    uint8_t z[16] = {0};
    uint8_t v[16];
    memcpy(v, h, 16);

    for (int i = 0; i < 16; ++i)
    {
        uint8_t xi = x[i];
        for (int bit = 7; bit >= 0; --bit)
        {
            if ((xi >> bit) & 1U)
            {
                for (int j = 0; j < 16; ++j)
                {
                    z[j] ^= v[j];
                }
            }
            bool lsb = (v[15] & 1U) != 0;
            for (int j = 15; j > 0; --j)
            {
                v[j] = (uint8_t)((v[j] >> 1) | ((v[j - 1] & 1U) << 7));
            }
            v[0] >>= 1;
            if (lsb)
            {
                v[0] ^= 0xE1U;
            }
        }
    }

    memcpy(out, z, 16);
    memset(v, 0, sizeof(v));
}

static void ghash_accumulate(uint8_t y[16], const uint8_t h[16], const uint8_t *data, size_t len)
{
    uint8_t block[16];
    uint8_t tmp[16];
    while (len > 0)
    {
        size_t take = (len < 16) ? len : 16;
        memset(block, 0, sizeof(block));
        memcpy(block, data, take);
        for (int i = 0; i < 16; ++i)
        {
            block[i] ^= y[i];
        }
        gcm_mult(tmp, block, h);
        memcpy(y, tmp, 16);
        data += take;
        len -= take;
    }
    memset(block, 0, sizeof(block));
    memset(tmp, 0, sizeof(tmp));
}

static void gcm_add_length_block(uint8_t y[16], const uint8_t h[16], size_t aad_len, size_t text_len)
{
    uint8_t block[16];
    uint64_t aad_bits = (uint64_t)aad_len * 8U;
    uint64_t text_bits = (uint64_t)text_len * 8U;
    for (int i = 0; i < 8; ++i)
    {
        block[i] = (uint8_t)(aad_bits >> (56 - i * 8));
        block[8 + i] = (uint8_t)(text_bits >> (56 - i * 8));
    }
    for (int i = 0; i < 16; ++i)
    {
        block[i] ^= y[i];
    }
    gcm_mult(y, block, h);
    memset(block, 0, sizeof(block));
}

static void gcm_inc32(uint8_t counter[16])
{
    for (int i = 15; i >= 12; --i)
    {
        counter[i]++;
        if (counter[i] != 0)
        {
            break;
        }
    }
}

static void gcm_crypt(const aes128_enc_ctx_t *ctx,
                      const uint8_t *input,
                      uint8_t *output,
                      size_t len,
                      uint8_t counter[16])
{
    size_t offset = 0;
    while (offset < len)
    {
        gcm_inc32(counter);
        uint8_t stream[16];
        memcpy(stream, counter, sizeof(stream));
        aes128_encrypt_block(ctx, stream);
        size_t block = len - offset;
        if (block > 16)
        {
            block = 16;
        }
        for (size_t i = 0; i < block; ++i)
        {
            output[offset + i] = input[offset + i] ^ stream[i];
        }
        memset(stream, 0, sizeof(stream));
        offset += block;
    }
}

static void gcm_build_j0(const uint8_t *nonce, uint8_t out[16])
{
    memcpy(out, nonce, TLS_GCM_FIXED_IV_SIZE + TLS_GCM_EXPLICIT_IV_SIZE);
    out[12] = 0x00;
    out[13] = 0x00;
    out[14] = 0x00;
    out[15] = 0x01;
}

static void gcm_compute_tag(const aes128_enc_ctx_t *ctx,
                            const uint8_t H[16],
                            const uint8_t *nonce,
                            const uint8_t *aad,
                            size_t aad_len,
                            const uint8_t *ciphertext,
                            size_t cipher_len,
                            uint8_t out_tag[16])
{
    uint8_t y[16] = {0};
    if (aad_len > 0)
    {
        ghash_accumulate(y, H, aad, aad_len);
    }
    if (cipher_len > 0)
    {
        ghash_accumulate(y, H, ciphertext, cipher_len);
    }
    gcm_add_length_block(y, H, aad_len, cipher_len);

    uint8_t j0[16];
    gcm_build_j0(nonce, j0);
    aes128_encrypt_block(ctx, j0);
    for (int i = 0; i < 16; ++i)
    {
        out_tag[i] = j0[i] ^ y[i];
    }
    memset(j0, 0, sizeof(j0));
    memset(y, 0, sizeof(y));
}

static bool gcm_seal(const aes128_enc_ctx_t *ctx,
                     const uint8_t H[16],
                     const uint8_t *nonce,
                     const uint8_t *aad,
                     size_t aad_len,
                     const uint8_t *plaintext,
                     size_t plaintext_len,
                     uint8_t *ciphertext,
                     uint8_t tag[16])
{
    uint8_t j0[16];
    gcm_build_j0(nonce, j0);
    uint8_t counter[16];
    memcpy(counter, j0, sizeof(counter));
    gcm_crypt(ctx, plaintext, ciphertext, plaintext_len, counter);
    memset(counter, 0, sizeof(counter));
    gcm_compute_tag(ctx, H, nonce, aad, aad_len, ciphertext, plaintext_len, tag);
    memset(j0, 0, sizeof(j0));
    return true;
}

static bool gcm_open(const aes128_enc_ctx_t *ctx,
                     const uint8_t H[16],
                     const uint8_t *nonce,
                     const uint8_t *aad,
                     size_t aad_len,
                     const uint8_t *ciphertext,
                     size_t ciphertext_len,
                     const uint8_t tag[16],
                     uint8_t *plaintext)
{
    uint8_t expected[16];
    gcm_compute_tag(ctx, H, nonce, aad, aad_len, ciphertext, ciphertext_len, expected);
    bool match = (memcmp(expected, tag, 16) == 0);
    if (!match)
    {
        memset(expected, 0, sizeof(expected));
        return false;
    }
    uint8_t j0[16];
    gcm_build_j0(nonce, j0);
    uint8_t counter[16];
    memcpy(counter, j0, sizeof(counter));
    gcm_crypt(ctx, ciphertext, plaintext, ciphertext_len, counter);
    memset(counter, 0, sizeof(counter));
    memset(j0, 0, sizeof(j0));
    memset(expected, 0, sizeof(expected));
    return true;
}

static bool tls_encrypt_record_gcm(tls_session_t *session,
                                   uint8_t type,
                                   const uint8_t *data,
                                   size_t len,
                                   uint8_t *out,
                                   size_t *out_len)
{
    if (len > TLS_MAX_FRAGMENT)
    {
        return false;
    }

#if TLS_DEBUG_SIG
    tls_log_hex("TLS: GCM encrypt seq 0x", session->client_seq);
    tls_log_hexdump("TLS: GCM client_write_key", session->client_write_key, 16);
    tls_log_hexdump("TLS: GCM client_write_iv", session->client_write_iv, TLS_GCM_FIXED_IV_SIZE);
    tls_log_hexdump("TLS: GCM plaintext", data, len);
#endif

    uint8_t explicit_iv[TLS_GCM_EXPLICIT_IV_SIZE];
    tls_serialize_seq(session->client_seq, explicit_iv);

    uint8_t nonce[TLS_GCM_FIXED_IV_SIZE + TLS_GCM_EXPLICIT_IV_SIZE];
    memcpy(nonce, session->client_write_iv, TLS_GCM_FIXED_IV_SIZE);
    memcpy(nonce + TLS_GCM_FIXED_IV_SIZE, explicit_iv, TLS_GCM_EXPLICIT_IV_SIZE);

    uint8_t ciphertext[TLS_MAX_FRAGMENT];
    uint8_t tag[TLS_GCM_TAG_SIZE];
    uint8_t aad[13];
    tls_build_additional_data(aad, session->client_seq, type, len);
#if TLS_DEBUG_SIG
    tls_log_hexdump("TLS: GCM explicit_iv", explicit_iv, sizeof(explicit_iv));
    tls_log_hexdump("TLS: GCM nonce", nonce, sizeof(nonce));
    tls_log_hexdump("TLS: GCM AAD", aad, sizeof(aad));
#endif
    if (!gcm_seal(&session->client_enc, session->client_gcm_H,
                  nonce, aad, sizeof(aad),
                  data, len, ciphertext, tag))
    {
        memset(ciphertext, 0, sizeof(ciphertext));
        memset(tag, 0, sizeof(tag));
        memset(nonce, 0, sizeof(nonce));
        memset(aad, 0, sizeof(aad));
        memset(explicit_iv, 0, sizeof(explicit_iv));
        return false;
    }

#if TLS_DEBUG_SIG
    tls_log_hexdump("TLS: GCM ciphertext", ciphertext, len);
    tls_log_hexdump("TLS: GCM tag", tag, sizeof(tag));
#endif

    uint8_t header[5];
    size_t record_payload = TLS_GCM_EXPLICIT_IV_SIZE + len + TLS_GCM_TAG_SIZE;
    header[0] = type;
    header[1] = TLS_VERSION_MAJOR;
    header[2] = TLS_VERSION_MINOR;
    header[3] = (uint8_t)((record_payload >> 8) & 0xFF);
    header[4] = (uint8_t)(record_payload & 0xFF);

    memcpy(out, header, 5);
    memcpy(out + 5, explicit_iv, TLS_GCM_EXPLICIT_IV_SIZE);
    memcpy(out + 5 + TLS_GCM_EXPLICIT_IV_SIZE, ciphertext, len);
    memcpy(out + 5 + TLS_GCM_EXPLICIT_IV_SIZE + len, tag, TLS_GCM_TAG_SIZE);
    *out_len = 5 + record_payload;

    tls_increment_seq(&session->client_seq);

    memset(ciphertext, 0, sizeof(ciphertext));
    memset(tag, 0, sizeof(tag));
    memset(nonce, 0, sizeof(nonce));
    memset(aad, 0, sizeof(aad));
    memset(explicit_iv, 0, sizeof(explicit_iv));
    return true;
}

static bool tls_encrypt_record(tls_session_t *session,
                               uint8_t type,
                               const uint8_t *data,
                               size_t len,
                               uint8_t *out,
                               size_t *out_len)
{
    if (tls_cipher_is_aead(session->cipher_suite))
    {
        return tls_encrypt_record_gcm(session, type, data, len, out, out_len);
    }

    if (len > TLS_MAX_FRAGMENT)
    {
        return false;
    }

    uint8_t plaintext[TLS_MAX_FRAGMENT + TLS_MAC_SIZE + TLS_BLOCK_SIZE];
    memcpy(plaintext, data, len);

    uint8_t mac[TLS_MAC_SIZE];
    tls_calculate_mac(mac, session->client_write_mac, session->client_seq, type, len, data);
    memcpy(plaintext + len, mac, TLS_MAC_SIZE);
    size_t total = len + TLS_MAC_SIZE;

    size_t pad_len = TLS_BLOCK_SIZE - ((total + 1) % TLS_BLOCK_SIZE);
    if (pad_len == TLS_BLOCK_SIZE)
    {
        pad_len = 0;
    }
    for (size_t i = 0; i <= pad_len; ++i)
    {
        plaintext[total + i] = (uint8_t)pad_len;
    }
    total += pad_len + 1;

    uint8_t explicit_iv[TLS_EXPLICIT_IV_SIZE];
    tls_random_bytes(explicit_iv, sizeof(explicit_iv));

    uint8_t work[TLS_MAX_FRAGMENT + TLS_MAC_SIZE + TLS_BLOCK_SIZE];
    memcpy(work, plaintext, total);
    tls_cbc_encrypt(&session->client_enc, work, total, explicit_iv);

    uint8_t header[5];
    size_t record_payload = TLS_EXPLICIT_IV_SIZE + total;
    header[0] = type;
    header[1] = TLS_VERSION_MAJOR;
    header[2] = TLS_VERSION_MINOR;
    header[3] = (uint8_t)((record_payload >> 8) & 0xFF);
    header[4] = (uint8_t)(record_payload & 0xFF);

    memcpy(out, header, 5);
    memcpy(out + 5, explicit_iv, TLS_EXPLICIT_IV_SIZE);
    memcpy(out + 5 + TLS_EXPLICIT_IV_SIZE, work, total);
    *out_len = 5 + record_payload;

    tls_increment_seq(&session->client_seq);

    memset(plaintext, 0, sizeof(plaintext));
    memset(mac, 0, sizeof(mac));
    memset(work, 0, sizeof(work));
    return true;
}

static bool tls_decrypt_record_gcm(tls_session_t *session,
                                   uint8_t type,
                                   uint8_t *data,
                                   size_t *len)
{
    if (*len < TLS_GCM_EXPLICIT_IV_SIZE + TLS_GCM_TAG_SIZE)
    {
        return false;
    }

    size_t cipher_len = *len - TLS_GCM_EXPLICIT_IV_SIZE - TLS_GCM_TAG_SIZE;
    uint8_t *explicit_iv = data;
    uint8_t *ciphertext = data + TLS_GCM_EXPLICIT_IV_SIZE;
    uint8_t *tag = ciphertext + cipher_len;

    uint8_t nonce[TLS_GCM_FIXED_IV_SIZE + TLS_GCM_EXPLICIT_IV_SIZE];
    memcpy(nonce, session->server_write_iv, TLS_GCM_FIXED_IV_SIZE);
    memcpy(nonce + TLS_GCM_FIXED_IV_SIZE, explicit_iv, TLS_GCM_EXPLICIT_IV_SIZE);

    uint8_t aad[13];
    tls_build_additional_data(aad, session->server_seq, type, cipher_len);
    bool ok = gcm_open(&session->server_enc, session->server_gcm_H,
                       nonce, aad, sizeof(aad),
                       ciphertext, cipher_len, tag,
                       ciphertext);
    memset(nonce, 0, sizeof(nonce));
    memset(aad, 0, sizeof(aad));
    if (!ok)
    {
        return false;
    }

    memmove(data, ciphertext, cipher_len);
    *len = cipher_len;
    tls_increment_seq(&session->server_seq);
    return true;
}

static bool tls_decrypt_record(tls_session_t *session,
                               uint8_t type,
                               uint8_t *data,
                               size_t *len)
{
    if (tls_cipher_is_aead(session->cipher_suite))
    {
        return tls_decrypt_record_gcm(session, type, data, len);
    }

    if (*len < TLS_EXPLICIT_IV_SIZE || ((*len - TLS_EXPLICIT_IV_SIZE) % TLS_BLOCK_SIZE) != 0)
    {
        return false;
    }

    uint8_t *explicit_iv = data;
    uint8_t *ciphertext = data + TLS_EXPLICIT_IV_SIZE;
    size_t cipher_len = *len - TLS_EXPLICIT_IV_SIZE;

    uint8_t work[TLS_MAX_FRAGMENT + TLS_MAC_SIZE + TLS_BLOCK_SIZE];
    memcpy(work, ciphertext, cipher_len);
    tls_cbc_decrypt(&session->server_dec, work, cipher_len, explicit_iv);

    if (cipher_len == 0)
    {
        return false;
    }
    size_t pad_len = work[cipher_len - 1];
    if (pad_len + 1 > cipher_len)
    {
        return false;
    }
    for (size_t i = 0; i <= pad_len; ++i)
    {
        if (work[cipher_len - 1 - i] != pad_len)
        {
            return false;
        }
    }
    size_t total = cipher_len - pad_len - 1;
    if (total < TLS_MAC_SIZE)
    {
        return false;
    }
    size_t body_len = total - TLS_MAC_SIZE;

    uint8_t mac[TLS_MAC_SIZE];
    tls_calculate_mac(mac, session->server_write_mac, session->server_seq, type, body_len, work);
    if (memcmp(mac, work + body_len, TLS_MAC_SIZE) != 0)
    {
        memset(mac, 0, sizeof(mac));
        return false;
    }
    memcpy(data, work, body_len);
    *len = body_len;
    tls_increment_seq(&session->server_seq);

    memset(work, 0, sizeof(work));
    memset(mac, 0, sizeof(mac));
    return true;
}

static bool tls_read_record_encrypted(tls_session_t *session, uint8_t *type, size_t *length, uint64_t timeout)
{
    uint8_t header[5];
    if (!tls_socket_read_exact(session, header, sizeof(header), timeout))
    {
        tls_log("TLS: failed to read record header (enc)");
        return false;
    }
    size_t len = ((size_t)header[3] << 8) | (size_t)header[4];
    if (len > sizeof(session->record_buffer))
    {
        tls_log("TLS: record length exceeds buffer (enc)");
        return false;
    }
    if (!tls_socket_read_exact(session, session->record_buffer, len, timeout))
    {
        tls_log("TLS: failed to read record body (enc)");
        return false;
    }

    if (!tls_decrypt_record(session, header[0], session->record_buffer, &len))
    {
        return false;
    }

    if (type)
    {
        *type = header[0];
    }
    if (length)
    {
        *length = len;
    }
    return true;
}

static bool tls_parse_certificate_rsa(tls_session_t *session, const uint8_t *cert, size_t cert_len)
{
    asn1_reader_t reader;
    asn1_reader_t seq;
    asn1_reader_init(&reader, cert, cert_len);
    if (!asn1_enter(&reader, 0x30, &seq))
    {
        TLS_FAIL("TLS: certificate outer sequence missing");
    }

    asn1_reader_t tbs;
    if (!asn1_enter(&seq, 0x30, &tbs))
    {
        TLS_FAIL("TLS: certificate TBSCertificate missing");
    }

    uint8_t tag;
    const uint8_t *value;
    size_t value_len;

    if (!asn1_read_element(&tbs, &tag, &value, &value_len))
    {
        TLS_FAIL("TLS: certificate version read failed");
    }
    if (tag == 0xA0)
    {
        /* version */
        if (!asn1_read_element(&tbs, &tag, &value, &value_len))
        {
            TLS_FAIL("TLS: certificate serial missing");
        }
    }

    /* serialNumber */
    if (tag != 0x02)
    {
        TLS_FAIL("TLS: certificate serial has wrong tag");
    }
    if (!asn1_read_element(&tbs, &tag, &value, &value_len)) /* signature */
    {
        TLS_FAIL("TLS: certificate signature info missing");
    }
    if (!asn1_read_element(&tbs, &tag, &value, &value_len)) /* issuer */
    {
        TLS_FAIL("TLS: certificate issuer missing");
    }
    if (!asn1_read_element(&tbs, &tag, &value, &value_len)) /* validity */
    {
        TLS_FAIL("TLS: certificate validity missing");
    }
    if (!asn1_read_element(&tbs, &tag, &value, &value_len)) /* subject */
    {
        TLS_FAIL("TLS: certificate subject missing");
    }

    asn1_reader_t spki;
    if (!asn1_enter(&tbs, 0x30, &spki))
    {
        TLS_FAIL("TLS: subjectPublicKeyInfo missing");
    }

    if (!asn1_read_element(&spki, &tag, &value, &value_len)) /* algorithm */
    {
        TLS_FAIL("TLS: SPKI algorithm missing");
    }
    if (!asn1_read_element(&spki, &tag, &value, &value_len)) /* subjectPublicKey */
    {
        TLS_FAIL("TLS: SPKI key missing");
    }
    if (tag != 0x03 || value_len < 1 || value[0] != 0x00)
    {
        TLS_FAIL("TLS: SPKI bitstring invalid");
    }
    asn1_reader_t pk_reader;
    asn1_reader_init(&pk_reader, value + 1, value_len - 1);
    asn1_reader_t rsa_seq;
    if (!asn1_enter(&pk_reader, 0x30, &rsa_seq))
    {
        TLS_FAIL("TLS: RSA sequence missing");
    }
    const uint8_t *mod_ptr = NULL;
    size_t mod_len = 0;
    if (!asn1_read_element(&rsa_seq, &tag, &mod_ptr, &mod_len) || tag != 0x02)
    {
        TLS_FAIL("TLS: RSA modulus missing");
    }
    const uint8_t *exp_ptr = NULL;
    size_t exp_len = 0;
    if (!asn1_read_element(&rsa_seq, &tag, &exp_ptr, &exp_len) || tag != 0x02)
    {
        TLS_FAIL("TLS: RSA exponent missing");
    }

    if (mod_len > 0 && mod_ptr[0] == 0x00)
    {
        mod_ptr++;
        mod_len--;
    }
    if (exp_len > 0 && exp_ptr[0] == 0x00)
    {
        exp_ptr++;
        exp_len--;
    }

rsa_public_key_set(&session->server_key, mod_ptr, mod_len, exp_ptr, exp_len);
    return true;
}

static bool tls_process_server_key_exchange_ecdhe(tls_session_t *session,
                                                  const uint8_t *body,
                                                  size_t hs_len)
{
    if (!session || !body || hs_len < 8)
    {
        TLS_FAIL("TLS: invalid ServerKeyExchange data");
    }

    size_t cursor = 0;
    const uint8_t *params_start = body;
    if (body[cursor++] != 0x03)
    {
        TLS_FAIL("TLS: server curve type unsupported");
    }
    if (cursor + 2 > hs_len)
    {
        TLS_FAIL("TLS: missing curve id");
    }
    uint16_t named_curve = tls_read_uint16(body + cursor);
    cursor += 2;
    if (named_curve != TLS_NAMED_CURVE_SECP256R1)
    {
        TLS_FAIL("TLS: server advertised unsupported curve");
    }
    if (cursor >= hs_len)
    {
        TLS_FAIL("TLS: missing ECDHE public length");
    }
    uint8_t pub_len = body[cursor++];
    if (cursor + pub_len > hs_len)
    {
        TLS_FAIL("TLS: truncated ECDHE public key");
    }
    const uint8_t *pub = body + cursor;
    cursor += pub_len;
    size_t params_len = cursor;
#if TLS_DEBUG_SIG
    tls_log_hex("TLS: ECDHE pub_len 0x", pub_len);
    tls_log_hexdump("TLS: ECDHE pub", pub, pub_len);
#endif
#if TLS_DEBUG_SIG
    tls_log_hex("TLS: ECDHE params_len 0x", params_len);
#endif

    if (cursor + 2 > hs_len)
    {
        TLS_FAIL("TLS: missing signature scheme");
    }
    uint8_t hash_algo = body[cursor++];
    uint8_t sig_algo = body[cursor++];
#if TLS_DEBUG_SIG
    tls_log_hex("TLS: signature hash algo 0x", hash_algo);
    tls_log_hex("TLS: signature sig algo 0x", sig_algo);
#endif
    if (hash_algo != 0x04 || sig_algo != 0x01)
    {
        TLS_FAIL("TLS: server signature scheme unsupported");
    }
    if (cursor + 2 > hs_len)
    {
        TLS_FAIL("TLS: missing signature length");
    }
    uint16_t sig_len = tls_read_uint16(body + cursor);
    cursor += 2;
    if (cursor + sig_len > hs_len)
    {
        TLS_FAIL("TLS: truncated signature");
    }
    const uint8_t *signature = body + cursor;
#if TLS_DEBUG_SIG
    tls_log_hex("TLS: signature length 0x", sig_len);
    tls_log_hexdump("TLS: signature preview", signature, sig_len < 64 ? sig_len : 64);
#endif

    uint8_t signed_data[64 + 128];
    size_t signed_len = 0;
    memcpy(signed_data + signed_len, session->client_random, 32);
    signed_len += 32;
    memcpy(signed_data + signed_len, session->server_random, 32);
    signed_len += 32;
    if (params_len > sizeof(signed_data) - signed_len)
    {
        TLS_FAIL("TLS: signed params too large");
    }
    memcpy(signed_data + signed_len, params_start, params_len);
    signed_len += params_len;
#if TLS_DEBUG_SIG
    tls_log_hex("TLS: signed_data length 0x", signed_len);
    tls_log_hexdump("TLS: signed_data", signed_data, signed_len);
    tls_log_sha256_digest("TLS: digest client|server", signed_data, signed_len);

    sha256_ctx_t dbg_ctx;
    uint8_t dbg_digest[32];
    sha256_init(&dbg_ctx);
    sha256_update(&dbg_ctx, session->server_random, 32);
    sha256_update(&dbg_ctx, session->client_random, 32);
    sha256_update(&dbg_ctx, params_start, params_len);
    sha256_final(&dbg_ctx, dbg_digest);
    tls_log_hexdump("TLS: digest server|client", dbg_digest, sizeof(dbg_digest));

    uint8_t header_bytes[4];
    header_bytes[0] = TLS_HANDSHAKE_SERVER_KEY_EXCHANGE;
    header_bytes[1] = (uint8_t)((hs_len >> 16) & 0xFF);
    header_bytes[2] = (uint8_t)((hs_len >> 8) & 0xFF);
    header_bytes[3] = (uint8_t)(hs_len & 0xFF);

    sha256_init(&dbg_ctx);
    sha256_update(&dbg_ctx, session->client_random, 32);
    sha256_update(&dbg_ctx, session->server_random, 32);
    sha256_update(&dbg_ctx, header_bytes, sizeof(header_bytes));
    sha256_update(&dbg_ctx, body, hs_len);
    sha256_final(&dbg_ctx, dbg_digest);
    tls_log_hexdump("TLS: digest client|server|hdr", dbg_digest, sizeof(dbg_digest));
#endif

    if (!rsa_verify_pkcs1_v15_sha256(&session->server_key,
                                     signed_data, signed_len,
                                     signature, sig_len))
    {
        TLS_FAIL("TLS: ECDHE signature verification failed");
    }

    if (!p256_is_valid_public(pub, pub_len))
    {
        TLS_FAIL("TLS: server ECDHE key invalid");
    }
    memcpy(session->ecdhe_server_public, pub, pub_len);
    session->ecdhe_server_public_len = pub_len;
    session->ecdhe_named_curve = named_curve;
    session->ecdhe_server_params_ready = true;
    return true;
}

static bool tls_process_server_handshake(tls_session_t *session,
                                         const uint8_t *data,
                                         size_t len,
                                         bool *got_server_hello,
                                         bool *got_certificate,
                                         bool *got_server_key_exchange,
                                         bool *got_hello_done)
{
    size_t offset = 0;
    while (offset + 4 <= len)
    {
        uint8_t hs_type = data[offset];
        size_t hs_len = tls_read_uint24(data + offset + 1);
        if (offset + 4 + hs_len > len)
        {
            TLS_FAIL("TLS: handshake fragment length invalid");
        }
        tls_handshake_hash_update(session, data + offset, 4 + hs_len);
        const uint8_t *body = data + offset + 4;

        tls_log_hex("TLS: handshake message type 0x", hs_type);

        switch (hs_type)
        {
            case TLS_HANDSHAKE_SERVER_HELLO:
            {
                if (hs_len < 38)
                {
                    TLS_FAIL("TLS: server hello too short");
                }
                uint16_t version = tls_read_uint16(body);
                if (version != ((TLS_VERSION_MAJOR << 8) | TLS_VERSION_MINOR))
                {
                    TLS_FAIL("TLS: server version mismatch");
                }
                memcpy(session->server_random, body + 2, 32);
                uint8_t session_id_len = body[34];
                size_t cursor = 35 + session_id_len;
                if (cursor + 3 > hs_len)
                {
                    TLS_FAIL("TLS: server hello session id out of range");
                }
                uint16_t cipher = tls_read_uint16(body + cursor);
                cursor += 2;
                session->cipher_suite = cipher;
                session->ecdhe_client_keys_ready = false;
                session->ecdhe_server_params_ready = false;
                if (cipher == TLS_CIPHER_RSA_WITH_AES_128_CBC_SHA256)
                {
                    session->key_exchange = TLS_KEY_EXCHANGE_RSA;
                    if (got_server_key_exchange)
                    {
                        *got_server_key_exchange = true;
                    }
                }
                else if (cipher == TLS_CIPHER_ECDHE_RSA_WITH_AES_128_CBC_SHA256 ||
                         cipher == TLS_CIPHER_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
                {
                    session->key_exchange = TLS_KEY_EXCHANGE_ECDHE_RSA;
                    session->ecdhe_server_public_len = 0;
                    if (got_server_key_exchange)
                    {
                        *got_server_key_exchange = false;
                    }
                }
                else
                {
                    TLS_FAIL("TLS: server chose unsupported cipher");
                }
                uint8_t compression = body[cursor++];
                if (compression != 0)
                {
                    TLS_FAIL("TLS: server requires compression");
                }
                if (cursor + 2 <= hs_len)
                {
                    uint16_t ext_len = tls_read_uint16(body + cursor);
                    cursor += 2;
                    if (cursor + ext_len > hs_len)
                    {
                        TLS_FAIL("TLS: server hello extensions truncated");
                    }
                }
                *got_server_hello = true;
                break;
            }
            case TLS_HANDSHAKE_CERTIFICATE:
            {
                if (hs_len < 3)
                {
                    TLS_FAIL("TLS: certificate message too short");
                }
                size_t list_len = tls_read_uint24(body);
                if (list_len + 3 != hs_len)
                {
                    TLS_FAIL("TLS: certificate list length mismatch");
                }
                if (list_len < 3)
                {
                    TLS_FAIL("TLS: empty certificate list");
                }
                size_t cert_len = tls_read_uint24(body + 3);
                if (cert_len + 6 > hs_len)
                {
                    TLS_FAIL("TLS: certificate entry truncated");
                }
                const uint8_t *cert_ptr = body + 6;
                if (!tls_parse_certificate_rsa(session, cert_ptr, cert_len))
                {
                    TLS_FAIL("TLS: failed to parse RSA certificate");
                }
                *got_certificate = true;
                break;
            }
            case TLS_HANDSHAKE_SERVER_KEY_EXCHANGE:
            {
                if (session->key_exchange != TLS_KEY_EXCHANGE_ECDHE_RSA)
                {
                    TLS_FAIL("TLS: unexpected ServerKeyExchange");
                }
                if (!tls_process_server_key_exchange_ecdhe(session, body, hs_len))
                {
                    TLS_FAIL("TLS: failed to parse ServerKeyExchange");
                }
                if (got_server_key_exchange)
                {
                    *got_server_key_exchange = true;
                }
                break;
            }
            case TLS_HANDSHAKE_SERVER_HELLO_DONE:
            {
                *got_hello_done = true;
                break;
            }
            default:
                tls_log_hex("TLS: unhandled handshake type 0x", hs_type);
                break;
        }

        offset += 4 + hs_len;
    }
    return true;
}

static bool tls_send_client_hello(tls_session_t *session, const char *hostname)
{
    uint8_t random_bytes[32];
    if (!tls_random_bytes(random_bytes, sizeof(random_bytes)))
    {
        return false;
    }
    memcpy(session->client_random, random_bytes, sizeof(random_bytes));

    uint8_t body[512];
    size_t offset = 0;
    body[offset++] = TLS_VERSION_MAJOR;
    body[offset++] = TLS_VERSION_MINOR;
    memcpy(body + offset, random_bytes, sizeof(random_bytes));
    offset += sizeof(random_bytes);
    body[offset++] = 0x00; /* session id length */

    body[offset++] = 0x00;
    body[offset++] = 0x06;
    body[offset++] = (uint8_t)(TLS_CIPHER_ECDHE_RSA_WITH_AES_128_GCM_SHA256 >> 8);
    body[offset++] = (uint8_t)(TLS_CIPHER_ECDHE_RSA_WITH_AES_128_GCM_SHA256 & 0xFF);
    body[offset++] = (uint8_t)(TLS_CIPHER_ECDHE_RSA_WITH_AES_128_CBC_SHA256 >> 8);
    body[offset++] = (uint8_t)(TLS_CIPHER_ECDHE_RSA_WITH_AES_128_CBC_SHA256 & 0xFF);
    body[offset++] = (uint8_t)(TLS_CIPHER_RSA_WITH_AES_128_CBC_SHA256 >> 8);
    body[offset++] = (uint8_t)(TLS_CIPHER_RSA_WITH_AES_128_CBC_SHA256 & 0xFF);

    body[offset++] = 0x01;
    body[offset++] = 0x00; /* null compression */

    size_t ext_len_offset = offset;
    body[offset++] = 0x00;
    body[offset++] = 0x00;

    size_t extensions_len = 0;

    if (hostname && hostname[0] != '\0')
    {
        size_t host_len = strlen(hostname);
        size_t server_name_struct_len = 1 + 2 + host_len;
        size_t sni_payload_len = 2 + server_name_struct_len;
        size_t sni_total_len = 4 + sni_payload_len;

        body[offset++] = 0x00;
        body[offset++] = 0x00;
        body[offset++] = (uint8_t)(sni_payload_len >> 8);
        body[offset++] = (uint8_t)(sni_payload_len & 0xFF);
        body[offset++] = (uint8_t)(server_name_struct_len >> 8);
        body[offset++] = (uint8_t)(server_name_struct_len & 0xFF);
        body[offset++] = 0x00;
        body[offset++] = (uint8_t)(host_len >> 8);
        body[offset++] = (uint8_t)(host_len & 0xFF);
        memcpy(body + offset, hostname, host_len);
        offset += host_len;
        extensions_len += sni_total_len;
    }

    /* supported_groups: secp256r1 */
    {
        body[offset++] = 0x00;
        body[offset++] = 0x0A;
        body[offset++] = 0x00;
        body[offset++] = 0x04;
        body[offset++] = 0x00;
        body[offset++] = 0x02;
        body[offset++] = 0x00;
        body[offset++] = TLS_NAMED_CURVE_SECP256R1;
        extensions_len += 8;
    }

    /* ec_point_formats: uncompressed */
    {
        body[offset++] = 0x00;
        body[offset++] = 0x0B;
        body[offset++] = 0x00;
        body[offset++] = 0x02;
        body[offset++] = 0x01;
        body[offset++] = 0x00;
        extensions_len += 6;
    }

    /* signature_algorithms: sha256+rsa, sha1+rsa */
    {
        body[offset++] = 0x00;
        body[offset++] = 0x0D;
        body[offset++] = 0x00;
        body[offset++] = 0x06;
        body[offset++] = 0x00;
        body[offset++] = 0x04;
        body[offset++] = 0x04;
        body[offset++] = 0x01;
        body[offset++] = 0x02;
        body[offset++] = 0x01;
        extensions_len += 10;
    }

    body[ext_len_offset] = (uint8_t)(extensions_len >> 8);
    body[ext_len_offset + 1] = (uint8_t)(extensions_len & 0xFF);

    size_t body_len = offset;
    uint8_t handshake[4 + sizeof(body)];
    handshake[0] = TLS_HANDSHAKE_CLIENT_HELLO;
    tls_serialize_uint24(handshake + 1, body_len);
    memcpy(handshake + 4, body, body_len);

    tls_log("TLS: sending ClientHello");
    tls_handshake_hash_update(session, handshake, 4 + body_len);
    return tls_write_record_plain(session, TLS_CONTENT_HANDSHAKE, handshake, 4 + body_len);
}

static bool tls_send_client_key_exchange_rsa(tls_session_t *session,
                                             const uint8_t *encrypted,
                                             size_t encrypted_len)
{
    uint8_t body[2 + 512];
    body[0] = (uint8_t)(encrypted_len >> 8);
    body[1] = (uint8_t)(encrypted_len & 0xFF);
    memcpy(body + 2, encrypted, encrypted_len);

    size_t body_len = encrypted_len + 2;
    uint8_t handshake[4 + sizeof(body)];
    handshake[0] = TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE;
    tls_serialize_uint24(handshake + 1, body_len);
    memcpy(handshake + 4, body, body_len);

    tls_handshake_hash_update(session, handshake, 4 + body_len);
    return tls_write_record_plain(session, TLS_CONTENT_HANDSHAKE, handshake, 4 + body_len);
}

static bool tls_send_client_key_exchange_ecdhe(tls_session_t *session)
{
    if (!session || !session->ecdhe_client_keys_ready)
    {
        return false;
    }
    uint8_t body[1 + P256_POINT_SIZE];
    body[0] = (uint8_t)session->ecdhe_public_len;
    memcpy(body + 1, session->ecdhe_public, session->ecdhe_public_len);
    size_t body_len = 1 + session->ecdhe_public_len;

    uint8_t handshake[4 + sizeof(body)];
    handshake[0] = TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE;
    tls_serialize_uint24(handshake + 1, body_len);
    memcpy(handshake + 4, body, body_len);

    tls_handshake_hash_update(session, handshake, 4 + body_len);
    return tls_write_record_plain(session, TLS_CONTENT_HANDSHAKE, handshake, 4 + body_len);
}

static bool tls_generate_ecdhe_keypair(tls_session_t *session)
{
    if (!session || session->ecdhe_client_keys_ready)
    {
        return session && session->ecdhe_client_keys_ready;
    }

    uint8_t scalar[P256_SCALAR_SIZE];
    do
    {
        if (!tls_random_bytes(scalar, sizeof(scalar)))
        {
            return false;
        }
    } while (!p256_scalar_is_valid(scalar));

    memcpy(session->ecdhe_private, scalar, sizeof(scalar));
    memset(scalar, 0, sizeof(scalar));

    if (!p256_generate_public(session->ecdhe_private, session->ecdhe_public))
    {
        memset(session->ecdhe_private, 0, sizeof(session->ecdhe_private));
        return false;
    }
    session->ecdhe_public_len = P256_POINT_SIZE;
    session->ecdhe_client_keys_ready = true;
#if TLS_DEBUG_SIG
    tls_log_hexdump("TLS: ECDHE private", session->ecdhe_private, sizeof(session->ecdhe_private));
    tls_log_hexdump("TLS: ECDHE public", session->ecdhe_public, session->ecdhe_public_len);
#endif
    return true;
}

static bool tls_ecdhe_compute_shared_secret(tls_session_t *session,
                                            uint8_t out_secret[P256_SCALAR_SIZE])
{
    if (!session || !session->ecdhe_client_keys_ready || !session->ecdhe_server_params_ready)
    {
        return false;
    }
    bool ok = p256_compute_shared(session->ecdhe_private,
                                  session->ecdhe_server_public,
                                  session->ecdhe_server_public_len,
                                  out_secret);
#if TLS_DEBUG_SIG
    if (ok)
    {
        tls_log_hexdump("TLS: ECDHE shared secret", out_secret, P256_SCALAR_SIZE);
    }
#endif
    return ok;
}

static bool tls_send_change_cipher_spec(tls_session_t *session)
{
    uint8_t payload = 0x01;
    return tls_write_record_plain(session, TLS_CONTENT_CHANGE_CIPHER_SPEC, &payload, 1);
}

static bool tls_send_finished(tls_session_t *session, const char *label)
{
    sha256_ctx_t copy = session->handshake_hash;
    uint8_t digest[32];
    sha256_final(&copy, digest);

    uint8_t verify_data[12];
    if (!tls_prf(session->master_secret, sizeof(session->master_secret),
                 label, digest, sizeof(digest),
                 verify_data, sizeof(verify_data)))
    {
        return false;
    }
#if TLS_DEBUG_SIG
    tls_log_hexdump("TLS: Finished digest", digest, sizeof(digest));
    tls_log_hexdump("TLS: Finished verify_data", verify_data, sizeof(verify_data));
#endif

    uint8_t handshake[4 + sizeof(verify_data)];
    handshake[0] = TLS_HANDSHAKE_FINISHED;
    tls_serialize_uint24(handshake + 1, sizeof(verify_data));
    memcpy(handshake + 4, verify_data, sizeof(verify_data));

    size_t record_len = 0;
    uint8_t record[TLS_MAX_RECORD];
    if (!tls_encrypt_record(session, TLS_CONTENT_HANDSHAKE,
                            handshake, sizeof(handshake),
                            record, &record_len))
    {
        return false;
    }

    if (!tls_socket_write_all(session, record, record_len, tls_default_timeout_ticks()))
    {
        return false;
    }

    tls_handshake_hash_update(session, handshake, sizeof(handshake));
    memset(verify_data, 0, sizeof(verify_data));
    memset(record, 0, sizeof(record));
    return true;
}

static bool tls_expect_server_finished(tls_session_t *session)
{
    uint8_t type = 0;
    size_t len = 0;
    uint64_t timeout = tls_default_timeout_ticks();
    if (!tls_read_record_encrypted(session, &type, &len, timeout))
    {
        TLS_FAIL("TLS: failed reading encrypted record for Finished");
    }
    if (type != TLS_CONTENT_HANDSHAKE || len < 4 || session->record_buffer[0] != TLS_HANDSHAKE_FINISHED)
    {
        TLS_FAIL("TLS: expected Finished handshake");
    }

    size_t expected_len = tls_read_uint24(session->record_buffer + 1);
    if (expected_len != 12 || len != 4 + expected_len)
    {
        TLS_FAIL("TLS: Finished length mismatch");
    }

    sha256_ctx_t copy = session->handshake_hash;
    uint8_t digest[32];
    sha256_final(&copy, digest);

    uint8_t verify_expected[12];
    if (!tls_prf(session->master_secret, sizeof(session->master_secret),
                 TLS_LABEL_SERVER_FINISHED,
                 digest, sizeof(digest),
                 verify_expected, sizeof(verify_expected)))
    {
        TLS_FAIL("TLS: PRF for Finished failed");
    }

    if (memcmp(verify_expected, session->record_buffer + 4, 12) != 0)
    {
        TLS_FAIL("TLS: Finished verify mismatch");
    }

    tls_handshake_hash_update(session, session->record_buffer, len);
    memset(verify_expected, 0, sizeof(verify_expected));
    return true;
}

bool tls_session_init(tls_session_t *session, net_tcp_socket_t *socket)
{
    if (!session || !socket)
    {
        return false;
    }
    memset(session, 0, sizeof(*session));
    session->socket = socket;
    session->socket_fd = net_tcp_socket_fd(socket);
    if (session->socket_fd < 0)
    {
        return false;
    }
    sha256_init(&session->handshake_hash);
    rsa_public_key_init(&session->server_key);
    session->key_exchange = TLS_KEY_EXCHANGE_NONE;
    session->cipher_suite = 0;
    return true;
}

bool tls_session_handshake(tls_session_t *session, const char *hostname)
{
    if (!session || !session->socket)
    {
        tls_log("TLS: invalid session in handshake");
        return false;
    }

    tls_log("TLS: handshake start");

    if (!tls_send_client_hello(session, hostname))
    {
        tls_log("TLS: failed to send ClientHello");
        return false;
    }

    bool got_server_hello = false;
    bool got_certificate = false;
    bool got_server_key_exchange = false;
    bool got_hello_done = false;
    bool client_key_sent = false;
    bool waiting_encrypted = false;

    uint64_t timeout = tls_default_timeout_ticks();

    while (!session->handshake_complete)
    {
        uint8_t type = 0;
        size_t len = 0;
        bool ok = false;
        if (!waiting_encrypted)
        {
            ok = tls_read_record_plain(session, &type, &len, timeout);
            if (ok)
            {
                tls_log_hex("TLS: received plain record type 0x", type);
            }
        }
        else
        {
            ok = tls_read_record_encrypted(session, &type, &len, timeout);
            if (ok)
            {
                tls_log_hex("TLS: received encrypted record type 0x", type);
            }
        }
        if (!ok)
        {
            tls_log("TLS: failed to read TLS record");
            return false;
        }

        if (!waiting_encrypted)
        {
            if (type == TLS_CONTENT_ALERT)
            {
                if (len >= 2)
                {
                    tls_log_hex("TLS: alert level 0x", session->record_buffer[0]);
                    tls_log_hex("TLS: alert description 0x", session->record_buffer[1]);
                }
                else
                {
                    tls_log("TLS: alert message too short");
                }
                if (len < 2 || session->record_buffer[1] == TLS_ALERT_LEVEL_FATAL)
                {
                    return false;
                }
                if (session->record_buffer[0] == TLS_ALERT_CLOSE_NOTIFY)
                {
                    return false;
                }
                continue;
            }
            if (type == TLS_CONTENT_HANDSHAKE)
            {
                if (!tls_process_server_handshake(session, session->record_buffer, len,
                                                  &got_server_hello, &got_certificate,
                                                  &got_server_key_exchange, &got_hello_done))
                {
                    tls_log("TLS: error processing server handshake");
                    return false;
                }
                if (session->key_exchange == TLS_KEY_EXCHANGE_ECDHE_RSA &&
                    session->ecdhe_server_params_ready)
                {
                    got_server_key_exchange = true;
                }
            }
            else if (type == TLS_CONTENT_CHANGE_CIPHER_SPEC)
            {
                tls_log("TLS: server sent ChangeCipherSpec");
                waiting_encrypted = true;
                continue;
            }
        }
        else
        {
            if (type == TLS_CONTENT_HANDSHAKE)
            {
                if (!tls_expect_server_finished(session))
                {
                    tls_log("TLS: server Finished verify failed");
                    return false;
                }
                session->handshake_complete = true;
                break;
            }
            else if (type == TLS_CONTENT_ALERT)
            {
                tls_log("TLS: received alert after cipher spec");
                return false;
            }
        }

        bool have_server_params = (session->key_exchange == TLS_KEY_EXCHANGE_ECDHE_RSA)
                                    ? session->ecdhe_server_params_ready
                                    : true;
        bool server_done_ready = got_hello_done;
        if (got_server_hello && got_certificate && have_server_params && server_done_ready && !client_key_sent)
        {
            uint8_t pre_master[48];
            size_t pre_master_len = 0;

            if (session->key_exchange == TLS_KEY_EXCHANGE_RSA)
            {
                pre_master_len = sizeof(pre_master);
                pre_master[0] = TLS_VERSION_MAJOR;
                pre_master[1] = TLS_VERSION_MINOR;
                if (!tls_random_bytes(pre_master + 2, sizeof(pre_master) - 2))
                {
                    tls_log("TLS: failed to generate pre-master secret");
                    return false;
                }

                size_t modulus_bytes = rsa_public_key_size(&session->server_key);
                uint8_t encrypted[512];
                if (!rsa_encrypt_pkcs1_v15(&session->server_key,
                                           pre_master, pre_master_len,
                                           encrypted, modulus_bytes,
                                           tls_random_fill, NULL))
                {
                    tls_log("TLS: RSA encryption failed");
                    return false;
                }

                if (!tls_send_client_key_exchange_rsa(session, encrypted, modulus_bytes))
                {
                    tls_log("TLS: failed to send ClientKeyExchange");
                    return false;
                }
                memset(encrypted, 0, sizeof(encrypted));
            }
            else if (session->key_exchange == TLS_KEY_EXCHANGE_ECDHE_RSA)
            {
                if (!session->ecdhe_server_params_ready)
                {
                    tls_log("TLS: missing server ECDHE params");
                    return false;
                }
                if (!tls_generate_ecdhe_keypair(session))
                {
                    tls_log("TLS: failed to generate ECDHE keypair");
                    return false;
                }
                if (!tls_send_client_key_exchange_ecdhe(session))
                {
                    tls_log("TLS: failed to send ECDHE ClientKeyExchange");
                    return false;
                }
                uint8_t shared[P256_SCALAR_SIZE];
                if (!tls_ecdhe_compute_shared_secret(session, shared))
                {
                    tls_log("TLS: failed to compute shared secret");
                    return false;
                }
                memcpy(pre_master, shared, sizeof(shared));
#if TLS_DEBUG_SIG
                tls_log_hexdump("TLS: pre-master (ECDHE)", pre_master, sizeof(shared));
#endif
                memset(shared, 0, sizeof(shared));
                pre_master_len = P256_SCALAR_SIZE;
            }
            else
            {
                tls_log("TLS: unsupported key exchange");
                return false;
            }

            if (!tls_compute_master_secret(session, pre_master, pre_master_len))
            {
                tls_log("TLS: failed computing master secret");
                return false;
            }
            memset(pre_master, 0, sizeof(pre_master));

            if (!tls_compute_key_block(session))
            {
                tls_log("TLS: failed computing key block");
                return false;
            }
            if (!tls_send_change_cipher_spec(session))
            {
                tls_log("TLS: failed to send ChangeCipherSpec");
                return false;
            }
            session->keys_ready = true;
            if (!tls_send_finished(session, TLS_LABEL_CLIENT_FINISHED))
            {
                tls_log("TLS: failed to send Finished");
                return false;
            }
            tls_log("TLS: sent ClientKeyExchange/Finished");
            client_key_sent = true;
        }
    }

    tls_log("TLS: handshake complete");
    return session->handshake_complete;
}

bool tls_session_send(tls_session_t *session, const uint8_t *data, size_t length)
{
    if (!session || !session->handshake_complete || !data || length == 0)
    {
        return false;
    }

    size_t offset = 0;
    uint8_t record[TLS_MAX_RECORD];
    while (offset < length)
    {
        size_t chunk = length - offset;
        if (chunk > TLS_APPLICATION_CHUNK)
        {
            chunk = TLS_APPLICATION_CHUNK;
        }
        size_t record_len = 0;
        if (!tls_encrypt_record(session, TLS_CONTENT_APPLICATION_DATA,
                                data + offset, chunk,
                                record, &record_len))
        {
            return false;
        }
        if (!tls_socket_write_all(session, record, record_len, tls_default_timeout_ticks()))
        {
            return false;
        }
        offset += chunk;
    }
    memset(record, 0, sizeof(record));
    return true;
}

size_t tls_session_recv(tls_session_t *session, uint8_t *buffer, size_t capacity)
{
    if (!session || !session->handshake_complete || !buffer || capacity == 0)
    {
        return 0;
    }

    if (session->recv_plain_offset < session->recv_plain_len)
    {
        size_t remaining = session->recv_plain_len - session->recv_plain_offset;
        size_t copy = remaining < capacity ? remaining : capacity;
        memcpy(buffer, session->recv_plain + session->recv_plain_offset, copy);
        session->recv_plain_offset += copy;
        if (session->recv_plain_offset == session->recv_plain_len)
        {
            session->recv_plain_offset = 0;
            session->recv_plain_len = 0;
        }
        return copy;
    }

    uint64_t timeout = tls_default_timeout_ticks();
    uint8_t type = 0;
    size_t len = 0;
    if (!tls_read_record_encrypted(session, &type, &len, timeout))
    {
        return 0;
    }
    if (type == TLS_CONTENT_ALERT)
    {
        if (len >= 2 && session->record_buffer[1] == TLS_ALERT_CLOSE_NOTIFY)
        {
            return 0;
        }
        return 0;
    }
    if (type != TLS_CONTENT_APPLICATION_DATA)
    {
        return 0;
    }
    if (len > sizeof(session->recv_plain))
    {
        return 0;
    }
    memcpy(session->recv_plain, session->record_buffer, len);
    session->recv_plain_len = len;
    session->recv_plain_offset = 0;
    size_t copy = len < capacity ? len : capacity;
    memcpy(buffer, session->recv_plain, copy);
    session->recv_plain_offset = copy;
    if (session->recv_plain_offset == session->recv_plain_len)
    {
        session->recv_plain_offset = 0;
        session->recv_plain_len = 0;
    }
    return copy;
}

void tls_session_close(tls_session_t *session)
{
    if (!session)
    {
        return;
    }
    session->socket = NULL;
    session->socket_fd = -1;
    memset(session->client_write_mac, 0, sizeof(session->client_write_mac));
    memset(session->server_write_mac, 0, sizeof(session->server_write_mac));
    memset(session->client_write_key, 0, sizeof(session->client_write_key));
    memset(session->server_write_key, 0, sizeof(session->server_write_key));
    memset(session->client_write_iv, 0, sizeof(session->client_write_iv));
    memset(session->server_write_iv, 0, sizeof(session->server_write_iv));
    memset(session->master_secret, 0, sizeof(session->master_secret));
    memset(session->ecdhe_private, 0, sizeof(session->ecdhe_private));
    memset(session->ecdhe_public, 0, sizeof(session->ecdhe_public));
    memset(session->ecdhe_server_public, 0, sizeof(session->ecdhe_server_public));
    memset(session->client_gcm_H, 0, sizeof(session->client_gcm_H));
    memset(session->server_gcm_H, 0, sizeof(session->server_gcm_H));
    session->ecdhe_client_keys_ready = false;
    session->ecdhe_server_params_ready = false;
    session->handshake_complete = false;
    session->keys_ready = false;
}
