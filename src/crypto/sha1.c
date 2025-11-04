#include "crypto/sha1.h"

#include "libc.h"

#define ROTL32(x,n) (((x) << (n)) | ((x) >> (32 - (n))))

static void sha1_process_block(sha1_ctx_t *ctx, const uint8_t block[64])
{
    uint32_t w[80];
    for (int i = 0; i < 16; ++i)
    {
        w[i] = ((uint32_t)block[i * 4 + 0] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (int i = 16; i < 80; ++i)
    {
        w[i] = ROTL32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];

    for (int i = 0; i < 80; ++i)
    {
        uint32_t f, k;
        if (i < 20)
        {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999U;
        }
        else if (i < 40)
        {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1U;
        }
        else if (i < 60)
        {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCU;
        }
        else
        {
            f = b ^ c ^ d;
            k = 0xCA62C1D6U;
        }
        uint32_t temp = ROTL32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = ROTL32(b, 30);
        b = a;
        a = temp;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

void sha1_init(sha1_ctx_t *ctx)
{
    if (!ctx)
    {
        return;
    }
    ctx->state[0] = 0x67452301U;
    ctx->state[1] = 0xEFCDAB89U;
    ctx->state[2] = 0x98BADCFEU;
    ctx->state[3] = 0x10325476U;
    ctx->state[4] = 0xC3D2E1F0U;
    ctx->bitcount = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

void sha1_update(sha1_ctx_t *ctx, const void *data, size_t len)
{
    if (!ctx || (!data && len != 0))
    {
        return;
    }

    const uint8_t *bytes = (const uint8_t *)data;
    size_t buffer_bytes = (size_t)((ctx->bitcount / 8) % 64);
    ctx->bitcount += (uint64_t)len * 8U;

    size_t i = 0;
    if (buffer_bytes > 0)
    {
        size_t space = 64 - buffer_bytes;
        size_t to_copy = (len < space) ? len : space;
        memcpy(ctx->buffer + buffer_bytes, bytes, to_copy);
        buffer_bytes += to_copy;
        i += to_copy;
        if (buffer_bytes == 64)
        {
            sha1_process_block(ctx, ctx->buffer);
            buffer_bytes = 0;
        }
    }

    for (; i + 64 <= len; i += 64)
    {
        sha1_process_block(ctx, bytes + i);
    }

    if (i < len)
    {
        memcpy(ctx->buffer, bytes + i, len - i);
    }
}

void sha1_final(sha1_ctx_t *ctx, uint8_t digest[20])
{
    if (!ctx || !digest)
    {
        return;
    }

    size_t buffer_bytes = (size_t)((ctx->bitcount / 8) % 64);
    ctx->buffer[buffer_bytes++] = 0x80;

    if (buffer_bytes > 56)
    {
        memset(ctx->buffer + buffer_bytes, 0, 64 - buffer_bytes);
        sha1_process_block(ctx, ctx->buffer);
        buffer_bytes = 0;
    }

    memset(ctx->buffer + buffer_bytes, 0, 56 - buffer_bytes);
    uint64_t bitcount_be = ctx->bitcount;
    for (int i = 0; i < 8; ++i)
    {
        ctx->buffer[56 + i] = (uint8_t)((bitcount_be >> (56 - 8 * i)) & 0xFF);
    }
    sha1_process_block(ctx, ctx->buffer);

    for (int i = 0; i < 5; ++i)
    {
        digest[i * 4 + 0] = (uint8_t)((ctx->state[i] >> 24) & 0xFF);
        digest[i * 4 + 1] = (uint8_t)((ctx->state[i] >> 16) & 0xFF);
        digest[i * 4 + 2] = (uint8_t)((ctx->state[i] >> 8) & 0xFF);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i] & 0xFF);
    }

    sha1_init(ctx);
}
