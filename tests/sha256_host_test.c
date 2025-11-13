#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "crypto/sha256.h"

typedef struct
{
    const char *label;
    const uint8_t *data;
    size_t len;
    const char *expected_hex;
} sha256_vector_t;

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define STR_VECTOR(label, literal, hex) \
    { label, (const uint8_t *)(literal), sizeof(literal) - 1, hex }

static int hex_value(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f')
    {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F')
    {
        return 10 + (c - 'A');
    }
    return -1;
}

static bool parse_hex_digest(const char *hex, uint8_t out[32])
{
    size_t hex_len = strlen(hex);
    if (hex_len != 64)
    {
        return false;
    }
    for (size_t i = 0; i < 32; ++i)
    {
        int hi = hex_value(hex[i * 2]);
        int lo = hex_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
        {
            return false;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static bool check_digest(const sha256_vector_t *vec)
{
    uint8_t expected[32];
    uint8_t digest[32];
    if (!parse_hex_digest(vec->expected_hex, expected))
    {
        printf("sha256: invalid expected hex for %s\n", vec->label);
        return false;
    }
    sha256_digest(vec->data, vec->len, digest);
    if (memcmp(digest, expected, sizeof(digest)) != 0)
    {
        printf("sha256: digest mismatch for %s\n", vec->label);
        return false;
    }
    return true;
}

static bool check_chunked_updates(const char *label,
                                  const uint8_t *data,
                                  size_t len,
                                  size_t chunk_size,
                                  const char *expected_hex)
{
    uint8_t expected[32];
    uint8_t digest[32];
    if (!parse_hex_digest(expected_hex, expected))
    {
        printf("sha256: invalid expected hex for chunk test %s\n", label);
        return false;
    }

    sha256_ctx_t ctx;
    sha256_init(&ctx);
    size_t offset = 0;
    while (offset < len)
    {
        size_t take = len - offset;
        if (take > chunk_size)
        {
            take = chunk_size;
        }
        sha256_update(&ctx, data + offset, take);
        offset += take;
    }
    sha256_final(&ctx, digest);

    if (memcmp(digest, expected, sizeof(digest)) != 0)
    {
        printf("sha256: chunked digest mismatch for %s (chunk=%zu)\n", label, chunk_size);
        return false;
    }
    return true;
}

static const char long_message[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
static const char quick_fox[] = "The quick brown fox jumps over the lazy dog";
static const uint8_t binary_data[] = {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F
};

static const sha256_vector_t vectors[] = {
    STR_VECTOR("empty", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    STR_VECTOR("abc", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    { "long-pattern", (const uint8_t *)long_message, sizeof(long_message) - 1,
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
    { "quick-fox", (const uint8_t *)quick_fox, sizeof(quick_fox) - 1,
      "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592" },
    { "binary-00-0f", binary_data, sizeof(binary_data),
      "be45cb2605bf36bebde684841a28f0fd43c69850a3dce5fedba69928ee3a8991" },
};

int main(void)
{
    for (size_t i = 0; i < ARRAY_LEN(vectors); ++i)
    {
        if (!check_digest(&vectors[i]))
        {
            return 1;
        }
    }

    if (!check_chunked_updates("quick-fox", (const uint8_t *)quick_fox,
                               sizeof(quick_fox) - 1, 5,
                               "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"))
    {
        return 1;
    }

    if (!check_chunked_updates("long-pattern", (const uint8_t *)long_message,
                               sizeof(long_message) - 1, 16,
                               "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"))
    {
        return 1;
    }

    printf("sha256_host_test: success\n");
    return 0;
}
