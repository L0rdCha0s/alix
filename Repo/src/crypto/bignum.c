#include "crypto/bignum.h"

#include "libc.h"
#include "serial.h"

typedef struct
{
    uint32_t words[BIGNUM_MAX_WORDS * 2];
    size_t length;
} bignum_wide_t;

static void bignum_normalize(bignum_t *num)
{
    while (num->length > 0 && num->words[num->length - 1] == 0)
    {
        num->length--;
    }
}

static size_t bignum_words_normalize(uint32_t *words, size_t len)
{
    while (len > 0 && words[len - 1] == 0)
    {
        len--;
    }
    return len;
}

static size_t bignum_words_shift_left1(uint32_t *words, size_t len, uint32_t bit)
{
    uint64_t carry = bit & 0x1U;
    for (size_t i = 0; i < len; ++i)
    {
        uint64_t value = ((uint64_t)words[i] << 1) | carry;
        words[i] = (uint32_t)value;
        carry = value >> 32;
    }
    if (carry != 0)
    {
        words[len++] = (uint32_t)carry;
    }
    else if (len == 0 && bit)
    {
        words[0] = 1;
        len = 1;
    }
    return len;
}

static int bignum_words_compare(const uint32_t *a, size_t a_len,
                                const uint32_t *b, size_t b_len)
{
    if (a_len != b_len)
    {
        return (a_len > b_len) ? 1 : -1;
    }
    for (size_t i = a_len; i-- > 0;)
    {
        if (a[i] != b[i])
        {
            return (a[i] > b[i]) ? 1 : -1;
        }
    }
    return 0;
}

static size_t bignum_words_sub(uint32_t *a, size_t a_len,
                               const uint32_t *b, size_t b_len)
{
    uint64_t borrow = 0;
    for (size_t i = 0; i < a_len; ++i)
    {
        uint64_t av = a[i];
        uint64_t bv = (i < b_len) ? b[i] : 0;
        uint64_t result = av - bv - borrow;
        a[i] = (uint32_t)result;
        borrow = (result >> 63) & 0x1U;
    }
    return bignum_words_normalize(a, a_len);
}

void bignum_init(bignum_t *num)
{
    memset(num->words, 0, sizeof(num->words));
    num->length = 0;
}

void bignum_from_bytes(bignum_t *num, const uint8_t *data, size_t len)
{
    bignum_init(num);
    if (!data || len == 0)
    {
        return;
    }

    size_t max_bytes = BIGNUM_MAX_WORDS * 4;
    if (len > max_bytes)
    {
        data += (len - max_bytes);
        len = max_bytes;
    }

    size_t word_count = (len + 3) / 4;
    if (word_count > BIGNUM_MAX_WORDS)
    {
        word_count = BIGNUM_MAX_WORDS;
    }
    num->length = word_count;

    size_t byte_index = len;
    for (size_t i = 0; i < word_count; ++i)
    {
        uint32_t word = 0;
        for (size_t j = 0; j < 4; ++j)
        {
            if (byte_index == 0)
            {
                break;
            }
            uint8_t byte = data[--byte_index];
            word |= ((uint32_t)byte) << (j * 8);
        }
        num->words[i] = word;
    }
    bignum_normalize(num);
}

void bignum_from_uint(bignum_t *num, uint32_t value)
{
    bignum_init(num);
    if (value == 0)
    {
        return;
    }
    num->words[0] = value;
    num->length = 1;
}

void bignum_copy(bignum_t *dst, const bignum_t *src)
{
    memcpy(dst->words, src->words, sizeof(uint32_t) * src->length);
    dst->length = src->length;
}

int bignum_compare(const bignum_t *a, const bignum_t *b)
{
    if (a->length != b->length)
    {
        return (a->length > b->length) ? 1 : -1;
    }
    for (size_t i = a->length; i-- > 0;)
    {
        if (a->words[i] != b->words[i])
        {
            return (a->words[i] > b->words[i]) ? 1 : -1;
        }
    }
    return 0;
}

void bignum_sub(bignum_t *a, const bignum_t *b)
{
    uint64_t borrow = 0;
    for (size_t i = 0; i < a->length; ++i)
    {
        uint64_t av = a->words[i];
        uint64_t bv = (i < b->length) ? b->words[i] : 0;
        uint64_t result = av - bv - borrow;
        a->words[i] = (uint32_t)result;
        borrow = (result >> 63) & 0x1;
    }
    bignum_normalize(a);
}

static void bignum_mul_wide(const bignum_t *a, const bignum_t *b, bignum_wide_t *out)
{
    memset(out->words, 0, sizeof(out->words));
    out->length = 0;
    for (size_t i = 0; i < a->length; ++i)
    {
        uint64_t carry = 0;
        for (size_t j = 0; j < b->length && i + j < BIGNUM_MAX_WORDS * 2; ++j)
        {
            size_t idx = i + j;
            unsigned __int128 product = (unsigned __int128)a->words[i] * (unsigned __int128)b->words[j];
            product += (unsigned __int128)out->words[idx] + carry;
            out->words[idx] = (uint32_t)product;
            carry = (uint64_t)(product >> 32);
        }
        size_t idx = i + b->length;
        while (carry != 0 && idx < BIGNUM_MAX_WORDS * 2)
        {
            uint64_t value = (uint64_t)out->words[idx] + carry;
            out->words[idx] = (uint32_t)value;
            carry = value >> 32;
            idx++;
        }
        if (idx > out->length)
        {
            out->length = idx;
        }
    }
    if (out->length == 0)
    {
        out->length = a->length + b->length;
    }
    if (out->length > BIGNUM_MAX_WORDS * 2)
    {
        out->length = BIGNUM_MAX_WORDS * 2;
    }
    while (out->length > 0 && out->words[out->length - 1] == 0)
    {
        out->length--;
    }
}

static void bignum_reduce_wide(const bignum_wide_t *value, const bignum_t *mod, bignum_t *out)
{
    if (mod->length == 0)
    {
        bignum_init(out);
        return;
    }
    uint32_t rem[BIGNUM_MAX_WORDS + 1];
    memset(rem, 0, sizeof(rem));
    size_t rem_len = 0;

    if (value->length == 0)
    {
        bignum_init(out);
        return;
    }

    for (size_t word_index = value->length; word_index-- > 0;)
    {
        uint32_t word = value->words[word_index];
        for (int bit = 31; bit >= 0; --bit)
        {
            uint32_t incoming = (word >> bit) & 0x1U;
            rem_len = bignum_words_shift_left1(rem, rem_len, incoming);
            if (rem_len > mod->length ||
                (rem_len == mod->length &&
                 bignum_words_compare(rem, rem_len, mod->words, mod->length) >= 0))
            {
                rem_len = bignum_words_sub(rem, rem_len, mod->words, mod->length);
            }
        }
    }

    size_t copy_len = (rem_len > BIGNUM_MAX_WORDS) ? BIGNUM_MAX_WORDS : rem_len;
    memcpy(out->words, rem, copy_len * sizeof(uint32_t));
    out->length = copy_len;
    bignum_normalize(out);
}

void bignum_mulmod(const bignum_t *a, const bignum_t *b, const bignum_t *mod, bignum_t *out)
{
    bignum_wide_t wide;
    bignum_mul_wide(a, b, &wide);
    bignum_reduce_wide(&wide, mod, out);
}

static size_t bignum_bit_length(const bignum_t *num)
{
    if (num->length == 0)
    {
        return 0;
    }
    uint32_t last = num->words[num->length - 1];
    size_t bits = (num->length - 1) * 32;
    while (last != 0)
    {
        bits++;
        last >>= 1U;
    }
    return bits;
}

void bignum_modexp(const bignum_t *base, const bignum_t *exp, const bignum_t *mod, bignum_t *out)
{
    bignum_t result;
    bignum_t base_acc;
    bignum_copy(&base_acc, base);
    while (bignum_compare(&base_acc, mod) >= 0)
    {
        bignum_sub(&base_acc, mod);
    }
    bignum_from_uint(&result, 1);

    size_t total_bits = bignum_bit_length(exp);
    if (total_bits == 0)
    {
        bignum_copy(out, &result);
        return;
    }

    for (size_t bit_index = 0; bit_index < total_bits; ++bit_index)
    {
        size_t word_index = bit_index / 32;
        uint32_t mask = 1U << (bit_index % 32);
        if (exp->words[word_index] & mask)
        {
            bignum_t temp;
            bignum_mulmod(&result, &base_acc, mod, &temp);
            bignum_copy(&result, &temp);
        }
        if (bit_index != total_bits - 1)
        {
            bignum_t temp;
            bignum_mulmod(&base_acc, &base_acc, mod, &temp);
            bignum_copy(&base_acc, &temp);
        }
    }
    bignum_copy(out, &result);
}

void bignum_to_bytes(const bignum_t *num, uint8_t *out, size_t out_len)
{
    size_t total = num->length * 4;
    if (total > out_len)
    {
        total = out_len;
    }
    memset(out, 0, out_len);
    for (size_t i = 0; i < total; ++i)
    {
        size_t word_index = i / 4;
        size_t byte_index = i % 4;
        uint32_t word = num->words[word_index];
        out[out_len - 1 - i] = (uint8_t)(word >> (byte_index * 8));
    }
}
