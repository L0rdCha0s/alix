#ifndef ALIX_LIBC_COMPARE_H
#define ALIX_LIBC_COMPARE_H

#include "types.h"

/* Shared kernel/user scalar comparison. Packed aliasable loads accept byte
 * arrays at any alignment. Every wide read is bounded by the remaining count;
 * a differing block falls back to bytes to preserve unsigned lexical order. */
typedef struct __attribute__((packed, may_alias))
{
    uint64_t value;
} libc_compare_word_t;

static inline int libc_compare_bytes(const void *left, const void *right, size_t count)
{
    const uint8_t *a = left, *b = right;
    if (!count || a == b) return 0;
    /* Keep ordinary early mismatches cheap before reading a wider block. */
    if (*a != *b) return (int)*a - (int)*b;
    while (count >= 32u)
    {
        const libc_compare_word_t *wa = (const void *)a;
        const libc_compare_word_t *wb = (const void *)b;
        uint64_t d0 = wa[0].value ^ wb[0].value;
        uint64_t d1 = wa[1].value ^ wb[1].value;
        uint64_t d2 = wa[2].value ^ wb[2].value;
        uint64_t d3 = wa[3].value ^ wb[3].value;
        if (d0 | d1 | d2 | d3) break;
        a += 32u;
        b += 32u;
        count -= 32u;
    }
    while (count >= sizeof(uint64_t))
    {
        if (((const libc_compare_word_t *)(const void *)a)->value !=
            ((const libc_compare_word_t *)(const void *)b)->value) break;
        a += sizeof(uint64_t);
        b += sizeof(uint64_t);
        count -= sizeof(uint64_t);
    }
    while (count--)
    {
        if (*a != *b) return (int)*a - (int)*b;
        ++a;
        ++b;
    }
    return 0;
}

#endif
