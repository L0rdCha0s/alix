#include "utf8.h"

#define UTF8_REPLACEMENT_CHAR 0xFFFDu

static inline bool utf8_is_cont(uint8_t b)
{
    return (b & 0xC0u) == 0x80u;
}

static inline bool utf8_codepoint_valid(uint32_t codepoint)
{
    if (codepoint > 0x10FFFFu)
    {
        return false;
    }
    if (codepoint >= 0xD800u && codepoint <= 0xDFFFu)
    {
        return false;
    }
    return true;
}

utf8_decode_result_t utf8_decode_one(const char *s)
{
    utf8_decode_result_t res = { 0 };
    if (!s || s[0] == '\0')
    {
        return res;
    }

    uint8_t b0 = (uint8_t)(unsigned char)s[0];
    if (b0 < 0x80u)
    {
        res.codepoint = (uint32_t)b0;
        res.consumed = 1;
        res.valid = true;
        return res;
    }

    uint32_t codepoint = UTF8_REPLACEMENT_CHAR;
    uint8_t needed = 0;

    if (b0 >= 0xC2u && b0 <= 0xDFu)
    {
        needed = 2;
    }
    else if (b0 >= 0xE0u && b0 <= 0xEFu)
    {
        needed = 3;
    }
    else if (b0 >= 0xF0u && b0 <= 0xF4u)
    {
        needed = 4;
    }
    else
    {
        res.codepoint = UTF8_REPLACEMENT_CHAR;
        res.consumed = 1;
        res.valid = false;
        return res;
    }

    for (uint8_t i = 1; i < needed; ++i)
    {
        if (s[i] == '\0')
        {
            res.codepoint = UTF8_REPLACEMENT_CHAR;
            res.consumed = 1;
            res.valid = false;
            return res;
        }
        uint8_t bi = (uint8_t)(unsigned char)s[i];
        if (!utf8_is_cont(bi))
        {
            res.codepoint = UTF8_REPLACEMENT_CHAR;
            res.consumed = 1;
            res.valid = false;
            return res;
        }
    }

    uint8_t b1 = (uint8_t)(unsigned char)s[1];
    if (needed == 2)
    {
        codepoint = ((uint32_t)(b0 & 0x1Fu) << 6) | (uint32_t)(b1 & 0x3Fu);
    }
    else
    {
        uint8_t b2 = (uint8_t)(unsigned char)s[2];
        if (needed == 3)
        {
            if (b0 == 0xE0u && b1 < 0xA0u)
            {
                res.codepoint = UTF8_REPLACEMENT_CHAR;
                res.consumed = 1;
                res.valid = false;
                return res;
            }
            if (b0 == 0xEDu && b1 >= 0xA0u)
            {
                res.codepoint = UTF8_REPLACEMENT_CHAR;
                res.consumed = 1;
                res.valid = false;
                return res;
            }
            codepoint = ((uint32_t)(b0 & 0x0Fu) << 12) |
                        ((uint32_t)(b1 & 0x3Fu) << 6) |
                        (uint32_t)(b2 & 0x3Fu);
        }
        else
        {
            uint8_t b3 = (uint8_t)(unsigned char)s[3];
            if (b0 == 0xF0u && b1 < 0x90u)
            {
                res.codepoint = UTF8_REPLACEMENT_CHAR;
                res.consumed = 1;
                res.valid = false;
                return res;
            }
            if (b0 == 0xF4u && b1 > 0x8Fu)
            {
                res.codepoint = UTF8_REPLACEMENT_CHAR;
                res.consumed = 1;
                res.valid = false;
                return res;
            }
            codepoint = ((uint32_t)(b0 & 0x07u) << 18) |
                        ((uint32_t)(b1 & 0x3Fu) << 12) |
                        ((uint32_t)(b2 & 0x3Fu) << 6) |
                        (uint32_t)(b3 & 0x3Fu);
        }
    }

    if (!utf8_codepoint_valid(codepoint))
    {
        res.codepoint = UTF8_REPLACEMENT_CHAR;
        res.consumed = 1;
        res.valid = false;
        return res;
    }

    res.codepoint = codepoint;
    res.consumed = needed;
    res.valid = true;
    return res;
}

size_t utf8_encode_one(uint32_t codepoint, char out[4])
{
    if (!out)
    {
        return 0;
    }

    if (!utf8_codepoint_valid(codepoint))
    {
        codepoint = UTF8_REPLACEMENT_CHAR;
    }

    if (codepoint <= 0x7Fu)
    {
        out[0] = (char)codepoint;
        return 1;
    }

    if (codepoint <= 0x7FFu)
    {
        out[0] = (char)(0xC0u | ((codepoint >> 6) & 0x1Fu));
        out[1] = (char)(0x80u | (codepoint & 0x3Fu));
        return 2;
    }

    if (codepoint <= 0xFFFFu)
    {
        out[0] = (char)(0xE0u | ((codepoint >> 12) & 0x0Fu));
        out[1] = (char)(0x80u | ((codepoint >> 6) & 0x3Fu));
        out[2] = (char)(0x80u | (codepoint & 0x3Fu));
        return 3;
    }

    out[0] = (char)(0xF0u | ((codepoint >> 18) & 0x07u));
    out[1] = (char)(0x80u | ((codepoint >> 12) & 0x3Fu));
    out[2] = (char)(0x80u | ((codepoint >> 6) & 0x3Fu));
    out[3] = (char)(0x80u | (codepoint & 0x3Fu));
    return 4;
}

size_t utf8_prev_char_start(const char *s, size_t len)
{
    if (!s || len == 0)
    {
        return 0;
    }

    size_t max_back = (len < 4) ? len : 4;
    for (size_t back = 1; back <= max_back; ++back)
    {
        size_t start = len - back;
        utf8_decode_result_t dec = utf8_decode_one(s + start);
        if (dec.valid && dec.consumed == back)
        {
            return start;
        }
    }

    return len - 1;
}

