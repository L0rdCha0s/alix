#include "crypto/sha256.h"

#include "libc.h"

static const uint32_t k_table[64] = {
    0x428A2F98U, 0x71374491U, 0xB5C0FBCFU, 0xE9B5DBA5U,
    0x3956C25BU, 0x59F111F1U, 0x923F82A4U, 0xAB1C5ED5U,
    0xD807AA98U, 0x12835B01U, 0x243185BEU, 0x550C7DC3U,
    0x72BE5D74U, 0x80DEB1FEU, 0x9BDC06A7U, 0xC19BF174U,
    0xE49B69C1U, 0xEFBE4786U, 0x0FC19DC6U, 0x240CA1CCU,
    0x2DE92C6FU, 0x4A7484AAU, 0x5CB0A9DCU, 0x76F988DAU,
    0x983E5152U, 0xA831C66DU, 0xB00327C8U, 0xBF597FC7U,
    0xC6E00BF3U, 0xD5A79147U, 0x06CA6351U, 0x14292967U,
    0x27B70A85U, 0x2E1B2138U, 0x4D2C6DFCU, 0x53380D13U,
    0x650A7354U, 0x766A0ABBU, 0x81C2C92EU, 0x92722C85U,
    0xA2BFE8A1U, 0xA81A664BU, 0xC24B8B70U, 0xC76C51A3U,
    0xD192E819U, 0xD6990624U, 0xF40E3585U, 0x106AA070U,
    0x19A4C116U, 0x1E376C08U, 0x2748774CU, 0x34B0BCB5U,
    0x391C0CB3U, 0x4ED8AA4AU, 0x5B9CCA4FU, 0x682E6FF3U,
    0x748F82EEU, 0x78A5636FU, 0x84C87814U, 0x8CC70208U,
    0x90BEFFF9U, 0xA4506CEBU, 0xBEF9A3F7U, 0xC67178F2U
};

static uint32_t rotr32(uint32_t value, uint32_t bits)
{
    return (value >> bits) | (value << (32U - bits));
}

static void sha256_process_block(sha256_ctx_t *ctx, const uint8_t block[64])
{
    uint32_t w[64];
    for (uint32_t i = 0; i < 16; ++i)
    {
        w[i] = ((uint32_t)block[i * 4 + 0] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (uint32_t i = 16; i < 64; ++i)
    {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];
    uint32_t f = ctx->state[5];
    uint32_t g = ctx->state[6];
    uint32_t h = ctx->state[7];

    for (uint32_t i = 0; i < 64; ++i)
    {
        uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + s1 + ch + k_table[i] + w[i];
        uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha256_init(sha256_ctx_t *ctx)
{
    ctx->state[0] = 0x6A09E667U;
    ctx->state[1] = 0xBB67AE85U;
    ctx->state[2] = 0x3C6EF372U;
    ctx->state[3] = 0xA54FF53AU;
    ctx->state[4] = 0x510E527FU;
    ctx->state[5] = 0x9B05688CU;
    ctx->state[6] = 0x1F83D9ABU;
    ctx->state[7] = 0x5BE0CD19U;
    ctx->bitcount = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

void sha256_update(sha256_ctx_t *ctx, const void *data, size_t len)
{
    const uint8_t *bytes = (const uint8_t *)data;
    size_t buffer_len = (size_t)((ctx->bitcount >> 3) & 0x3F);
    ctx->bitcount += ((uint64_t)len) << 3;

    size_t offset = 0;
    if (buffer_len > 0)
    {
        size_t to_copy = 64 - buffer_len;
        if (to_copy > len)
        {
            to_copy = len;
        }
        memcpy(ctx->buffer + buffer_len, bytes, to_copy);
        buffer_len += to_copy;
        offset += to_copy;
        if (buffer_len == 64)
        {
            sha256_process_block(ctx, ctx->buffer);
            buffer_len = 0;
        }
    }

    while (offset + 64 <= len)
    {
        sha256_process_block(ctx, bytes + offset);
        offset += 64;
    }

    if (offset < len)
    {
        memcpy(ctx->buffer, bytes + offset, len - offset);
    }
}

void sha256_final(sha256_ctx_t *ctx, uint8_t out[32])
{
    size_t buffer_len = (size_t)((ctx->bitcount >> 3) & 0x3F);
    ctx->buffer[buffer_len++] = 0x80;

    if (buffer_len > 56)
    {
        memset(ctx->buffer + buffer_len, 0, 64 - buffer_len);
        sha256_process_block(ctx, ctx->buffer);
        buffer_len = 0;
    }

    memset(ctx->buffer + buffer_len, 0, 56 - buffer_len);
    uint64_t bitcount_be = (ctx->bitcount);
    ctx->buffer[56] = (uint8_t)(bitcount_be >> 56);
    ctx->buffer[57] = (uint8_t)(bitcount_be >> 48);
    ctx->buffer[58] = (uint8_t)(bitcount_be >> 40);
    ctx->buffer[59] = (uint8_t)(bitcount_be >> 32);
    ctx->buffer[60] = (uint8_t)(bitcount_be >> 24);
    ctx->buffer[61] = (uint8_t)(bitcount_be >> 16);
    ctx->buffer[62] = (uint8_t)(bitcount_be >> 8);
    ctx->buffer[63] = (uint8_t)(bitcount_be);
    sha256_process_block(ctx, ctx->buffer);

    for (uint32_t i = 0; i < 8; ++i)
    {
        out[i * 4 + 0] = (uint8_t)(ctx->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

void sha256_digest(const void *data, size_t len, uint8_t out[32])
{
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}
