#include "crypto/bignum.h"

#include "libc.h"

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

void bignum_init(bignum_t *num)
{
    memset(num->words, 0, sizeof(num->words));
    num->length = 0;
}

void bignum_from_bytes(bignum_t *num, const uint8_t *data, size_t len)
{
    bignum_init(num);
    size_t word_count = (len + 3) / 4;
    if (word_count > BIGNUM_MAX_WORDS)
    {
        word_count = BIGNUM_MAX_WORDS;
    }
    num->length = word_count;
    for (size_t i = 0; i < word_count; ++i)
    {
        size_t index = len - (i + 1) * 4;
        uint32_t word = 0;
        for (size_t j = 0; j < 4; ++j)
        {
            size_t pos = index + j;
            if (index + j < len)
            {
                word <<= 8;
                word |= data[pos];
            }
            else
            {
                word <<= 8;
            }
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

static void bignum_add_word(bignum_t *num, uint32_t word)
{
    uint64_t carry = word;
    size_t i = 0;
    while (carry != 0)
    {
        if (i >= num->length)
        {
            if (i >= BIGNUM_MAX_WORDS)
            {
                return;
            }
            num->words[i] = 0;
            num->length = i + 1;
        }
        uint64_t sum = (uint64_t)num->words[i] + carry;
        num->words[i] = (uint32_t)sum;
        carry = sum >> 32;
        ++i;
    }
    if (i > num->length)
    {
        num->length = i;
    }
}

static void bignum_shift_words_up(bignum_t *num, size_t count)
{
    if (count == 0 || num->length == 0)
    {
        if (num->length == 0)
        {
            num->length = 0;
        }
        return;
    }
    if (num->length + count > BIGNUM_MAX_WORDS)
    {
        count = BIGNUM_MAX_WORDS - num->length;
    }
    for (size_t i = num->length; i-- > 0;)
    {
        num->words[i + count] = num->words[i];
    }
    for (size_t i = 0; i < count; ++i)
    {
        num->words[i] = 0;
    }
    num->length += count;
}

static void bignum_mul_base_add(bignum_t *num, uint32_t word)
{
    if (num->length == 0 && word == 0)
    {
        return;
    }
    if (num->length + 1 > BIGNUM_MAX_WORDS)
    {
        return;
    }
    if (num->length > 0)
    {
        bignum_shift_words_up(num, 1);
    }
    else
    {
        num->length = 1;
        num->words[0] = 0;
    }
    bignum_add_word(num, word);
}

static void bignum_mul_wide(const bignum_t *a, const bignum_t *b, bignum_wide_t *out)
{
    memset(out->words, 0, sizeof(out->words));
    out->length = a->length + b->length;
    if (out->length > BIGNUM_MAX_WORDS * 2)
    {
        out->length = BIGNUM_MAX_WORDS * 2;
    }
    for (size_t i = 0; i < a->length; ++i)
    {
        uint64_t carry = 0;
        for (size_t j = 0; j < b->length && i + j < BIGNUM_MAX_WORDS * 2; ++j)
        {
            size_t idx = i + j;
            uint64_t current = out->words[idx];
            uint64_t product = (uint64_t)a->words[i] * (uint64_t)b->words[j] + current + carry;
            out->words[idx] = (uint32_t)product;
            carry = product >> 32;
        }
        if (i + b->length < BIGNUM_MAX_WORDS * 2)
        {
            out->words[i + b->length] = (uint32_t)carry;
        }
    }
    while (out->length > 0 && out->words[out->length - 1] == 0)
    {
        out->length--;
    }
}

static void bignum_reduce_wide(const bignum_wide_t *value, const bignum_t *mod, bignum_t *out)
{
    bignum_init(out);
    for (size_t i = value->length; i-- > 0;)
    {
        bignum_mul_base_add(out, value->words[i]);
        while (bignum_compare(out, mod) >= 0)
        {
            bignum_sub(out, mod);
        }
    }
}

static void bignum_mulmod(const bignum_t *a, const bignum_t *b, const bignum_t *mod, bignum_t *out)
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
