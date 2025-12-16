#include "crypto/sha256.h"

#include "libc.h"

#define ROTRIGHT(x, n) (((x) >> (n)) | ((x) << (32U - (n))))
#define CH(x, y, z) ((((x) & (y)) ^ (~(x) & (z))) & 0xFFFFFFFFU)
#define MAJ(x, y, z) ((((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z))) & 0xFFFFFFFFU)
#define EP0(x) (ROTRIGHT((x), 2) ^ ROTRIGHT((x), 13) ^ ROTRIGHT((x), 22))
#define EP1(x) (ROTRIGHT((x), 6) ^ ROTRIGHT((x), 11) ^ ROTRIGHT((x), 25))
#define SIG0(x) (ROTRIGHT((x), 7) ^ ROTRIGHT((x), 18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT((x), 17) ^ ROTRIGHT((x), 19) ^ ((x) >> 10))

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
    0x90BEFFFAU, 0xA4506CEBU, 0xBEF9A3F7U, 0xC67178F2U
};

#ifdef SHA256_DEBUG_EXPOSE
uint32_t sha256_debug_w0 = 0;
#endif

static void sha256_transform(sha256_ctx_t *ctx, const uint8_t data[64])
{
    uint32_t w[64];
    for (uint32_t i = 0; i < 16; ++i)
    {
        w[i] = ((uint32_t)data[i * 4 + 0] << 24) |
               ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) |
               ((uint32_t)data[i * 4 + 3]);
    }
#ifdef SHA256_DEBUG_EXPOSE
    sha256_debug_w0 = w[0];
#endif
    for (uint32_t i = 16; i < 64; ++i)
    {
        w[i] = (SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16]) & 0xFFFFFFFFU;
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
        uint32_t t1 = (h + EP1(e) + CH(e, f, g) + k_table[i] + w[i]) & 0xFFFFFFFFU;
        uint32_t t2 = (EP0(a) + MAJ(a, b, c)) & 0xFFFFFFFFU;
        h = g;
        g = f;
        f = e;
        e = (d + t1) & 0xFFFFFFFFU;
        d = c;
        c = b;
        b = a;
        a = (t1 + t2) & 0xFFFFFFFFU;
    }

    ctx->state[0] = (ctx->state[0] + a) & 0xFFFFFFFFU;
    ctx->state[1] = (ctx->state[1] + b) & 0xFFFFFFFFU;
    ctx->state[2] = (ctx->state[2] + c) & 0xFFFFFFFFU;
    ctx->state[3] = (ctx->state[3] + d) & 0xFFFFFFFFU;
    ctx->state[4] = (ctx->state[4] + e) & 0xFFFFFFFFU;
    ctx->state[5] = (ctx->state[5] + f) & 0xFFFFFFFFU;
    ctx->state[6] = (ctx->state[6] + g) & 0xFFFFFFFFU;
    ctx->state[7] = (ctx->state[7] + h) & 0xFFFFFFFFU;
}

void sha256_init(sha256_ctx_t *ctx)
{
    if (!ctx)
    {
        return;
    }
    ctx->state[0] = 0x6A09E667U;
    ctx->state[1] = 0xBB67AE85U;
    ctx->state[2] = 0x3C6EF372U;
    ctx->state[3] = 0xA54FF53AU;
    ctx->state[4] = 0x510E527FU;
    ctx->state[5] = 0x9B05688CU;
    ctx->state[6] = 0x1F83D9ABU;
    ctx->state[7] = 0x5BE0CD19U;
    ctx->bitcount = 0;
    ctx->datalen = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

void sha256_update(sha256_ctx_t *ctx, const void *data, size_t len)
{
    if (!ctx || (!data && len != 0))
    {
        return;
    }

    const uint8_t *bytes = (const uint8_t *)data;
    for (size_t i = 0; i < len; ++i)
    {
        ctx->buffer[ctx->datalen] = bytes[i];
        ctx->datalen++;
        if (ctx->datalen == 64)
        {
            sha256_transform(ctx, ctx->buffer);
            ctx->bitcount += 512;
            ctx->datalen = 0;
        }
    }
}

void sha256_final(sha256_ctx_t *ctx, uint8_t out[32])
{
    if (!ctx || !out)
    {
        return;
    }

    ctx->bitcount += (uint64_t)ctx->datalen * 8ULL;

    ctx->buffer[ctx->datalen++] = 0x80;
    if (ctx->datalen > 56)
    {
        while (ctx->datalen < 64)
        {
            ctx->buffer[ctx->datalen++] = 0x00;
        }
        sha256_transform(ctx, ctx->buffer);
        ctx->datalen = 0;
    }
    while (ctx->datalen < 56)
    {
        ctx->buffer[ctx->datalen++] = 0x00;
    }

    ctx->buffer[56] = (uint8_t)(ctx->bitcount >> 56);
    ctx->buffer[57] = (uint8_t)(ctx->bitcount >> 48);
    ctx->buffer[58] = (uint8_t)(ctx->bitcount >> 40);
    ctx->buffer[59] = (uint8_t)(ctx->bitcount >> 32);
    ctx->buffer[60] = (uint8_t)(ctx->bitcount >> 24);
    ctx->buffer[61] = (uint8_t)(ctx->bitcount >> 16);
    ctx->buffer[62] = (uint8_t)(ctx->bitcount >> 8);
    ctx->buffer[63] = (uint8_t)(ctx->bitcount);
    sha256_transform(ctx, ctx->buffer);

    for (uint32_t i = 0; i < 8; ++i)
    {
        out[i * 4 + 0] = (uint8_t)(ctx->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }

    sha256_init(ctx);
}

void sha256_digest(const void *data, size_t len, uint8_t out[32])
{
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}
