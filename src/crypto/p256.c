#include "crypto/p256.h"

#include "crypto/bignum.h"
#include "libc.h"
#include "serial.h"
#include "crypto/p256.h"

#include "crypto/bignum.h"
#include "libc.h"
#include "serial.h"

typedef struct
{
    bignum_t x;
    bignum_t y;
    bool infinity;
} p256_point_t;

static bool g_p256_initialized = false;
static bignum_t g_p256_p;
static bignum_t g_p256_a;
static bignum_t g_p256_b;
static bignum_t g_p256_n;
static bignum_t g_p256_p_minus_two;
static p256_point_t g_p256_g;

static const uint8_t P256_P_BYTES[32] = {
    0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x01,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};
static const uint8_t P256_A_BYTES[32] = {
    0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x01,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC
};
static const uint8_t P256_B_BYTES[32] = {
    0x5A,0xC6,0x35,0xD8,0xAA,0x3A,0x93,0xE7,
    0xB3,0xEB,0xBD,0x55,0x76,0x98,0x86,0xBC,
    0x65,0x1D,0x06,0xB0,0xCC,0x53,0xB0,0xF6,
    0x3B,0xCE,0x3C,0x3E,0x27,0xD2,0x60,0x4B
};
static const uint8_t P256_N_BYTES[32] = {
    0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xBC,0xE6,0xFA,0xAD,0xA7,0x17,0x9E,0x84,
    0xF3,0xB9,0xCA,0xC2,0xFC,0x63,0x25,0x51
};
static const uint8_t P256_GX_BYTES[32] = {
    0x6B,0x17,0xD1,0xF2,0xE1,0x2C,0x42,0x47,
    0xF8,0xBC,0xE6,0xE5,0x63,0xA4,0x40,0xF2,
    0x77,0x03,0x7D,0x81,0x2D,0xEB,0x33,0xA0,
    0xF4,0xA1,0x39,0x45,0xD8,0x98,0xC2,0x96
};
static const uint8_t P256_GY_BYTES[32] = {
    0x4F,0xE3,0x42,0xE2,0xFE,0x1A,0x7F,0x9B,
    0x8E,0xE7,0xEB,0x4A,0x7C,0x0F,0x9E,0x16,
    0x2B,0xCE,0x33,0x57,0x6B,0x31,0x5E,0xCE,
    0xCB,0xB6,0x40,0x68,0x37,0xBF,0x51,0xF5
};

static void p256_init(void)
{
    if (g_p256_initialized)
    {
        return;
    }
    bignum_from_bytes(&g_p256_p, P256_P_BYTES, sizeof(P256_P_BYTES));
    bignum_from_bytes(&g_p256_a, P256_A_BYTES, sizeof(P256_A_BYTES));
    bignum_from_bytes(&g_p256_b, P256_B_BYTES, sizeof(P256_B_BYTES));
    bignum_from_bytes(&g_p256_n, P256_N_BYTES, sizeof(P256_N_BYTES));
    bignum_from_bytes(&g_p256_g.x, P256_GX_BYTES, sizeof(P256_GX_BYTES));
    bignum_from_bytes(&g_p256_g.y, P256_GY_BYTES, sizeof(P256_GY_BYTES));
    g_p256_g.infinity = false;
    bignum_copy(&g_p256_p_minus_two, &g_p256_p);
    bignum_t two;
    bignum_from_uint(&two, 2);
    bignum_sub(&g_p256_p_minus_two, &two);
    g_p256_initialized = true;
}

static bool bignum_is_zero(const bignum_t *num)
{
    return num->length == 0;
}

static void bignum_add_raw(bignum_t *out, const bignum_t *a, const bignum_t *b)
{
    size_t max = (a->length > b->length) ? a->length : b->length;
    uint64_t carry = 0;
    for (size_t i = 0; i < max; ++i)
    {
        uint64_t av = (i < a->length) ? a->words[i] : 0;
        uint64_t bv = (i < b->length) ? b->words[i] : 0;
        uint64_t sum = av + bv + carry;
        out->words[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    if (carry && max < BIGNUM_MAX_WORDS)
    {
        out->words[max++] = (uint32_t)carry;
    }
    out->length = max;
    while (out->length > 0 && out->words[out->length - 1] == 0)
    {
        out->length--;
    }
}

static void p256_log_bignum(const char *label, const bignum_t *num)
{
    serial_printf("%s", "[p256] ");
    serial_printf("%s", label);
    serial_printf("%s", " len=0x");
    serial_printf("%016llX", (unsigned long long)(num->length));
    serial_printf("%s", " value=0x");
    if (num->length == 0)
    {
        serial_printf("%s", "0\r\n");
        return;
    }
    for (size_t i = num->length; i-- > 0;)
    {
        char hex[9];
        uint32_t word = num->words[i];
        for (int nibble = 7; nibble >= 0; --nibble)
        {
            static const char digits[] = "0123456789abcdef";
            hex[7 - nibble] = digits[(word >> (nibble * 4)) & 0xF];
        }
        hex[8] = '\0';
        serial_printf("%s", hex);
    }
    serial_printf("%s", "\r\n");
}

static void p256_field_reduce(bignum_t *x)
{
    while (bignum_compare(x, &g_p256_p) >= 0)
    {
        bignum_sub(x, &g_p256_p);
    }
}

static void p256_field_add(bignum_t *r, const bignum_t *a, const bignum_t *b)
{
    bignum_add_raw(r, a, b);
    p256_field_reduce(r);
}

static void p256_field_sub(bignum_t *r, const bignum_t *a, const bignum_t *b)
{
    if (bignum_compare(a, b) >= 0)
    {
        bignum_copy(r, a);
        bignum_sub(r, b);
    }
    else
    {
        bignum_t temp;
        bignum_add_raw(&temp, a, &g_p256_p);
        bignum_sub(&temp, b);
        p256_field_reduce(&temp);
        bignum_copy(r, &temp);
    }
}

static void p256_field_mul(bignum_t *r, const bignum_t *a, const bignum_t *b)
{
    bignum_mulmod(a, b, &g_p256_p, r);
}

static void p256_field_sqr(bignum_t *r, const bignum_t *a)
{
    bignum_mulmod(a, a, &g_p256_p, r);
}

static void p256_field_inv(bignum_t *r, const bignum_t *a)
{
    bignum_modexp(a, &g_p256_p_minus_two, &g_p256_p, r);
}

static void p256_point_copy(p256_point_t *dst, const p256_point_t *src)
{
    bignum_copy(&dst->x, &src->x);
    bignum_copy(&dst->y, &src->y);
    dst->infinity = src->infinity;
}

static void p256_point_set_infinity(p256_point_t *p)
{
    bignum_init(&p->x);
    bignum_init(&p->y);
    p->infinity = true;
}

static bool p256_point_is_on_curve(const p256_point_t *p)
{
    if (p->infinity)
    {
        return true;
    }
    if (bignum_compare(&p->x, &g_p256_p) >= 0 ||
        bignum_compare(&p->y, &g_p256_p) >= 0)
    {
        serial_printf("%s", "[p256] point coordinate >= p\r\n");
        p256_log_bignum("x", &p->x);
        p256_log_bignum("y", &p->y);
        return false;
    }
    bignum_t y2;
    p256_field_sqr(&y2, &p->y);

    bignum_t x2;
    p256_field_sqr(&x2, &p->x);
    bignum_t x3;
    p256_field_mul(&x3, &x2, &p->x);

    bignum_t ax;
    p256_field_mul(&ax, &g_p256_a, &p->x);

    bignum_t rhs;
    p256_field_add(&rhs, &x3, &ax);
    p256_field_add(&rhs, &rhs, &g_p256_b);

    if (bignum_compare(&y2, &rhs) != 0)
    {
        serial_printf("%s", "[p256] point not on curve\r\n");
        p256_log_bignum("x", &p->x);
        p256_log_bignum("y", &p->y);
        p256_log_bignum("y^2", &y2);
        p256_log_bignum("x^3", &x3);
        p256_log_bignum("ax", &ax);
        p256_log_bignum("x^3+ax+b", &rhs);
        return false;
    }
    return true;
}

static void p256_point_double(p256_point_t *r, const p256_point_t *p)
{
    if (p->infinity || bignum_is_zero(&p->y))
    {
        p256_point_set_infinity(r);
        return;
    }

    bignum_t slope_num;
    bignum_t x2;
    p256_field_sqr(&x2, &p->x);
    p256_field_add(&slope_num, &x2, &x2);
    p256_field_add(&slope_num, &slope_num, &x2);
    p256_field_add(&slope_num, &slope_num, &g_p256_a);

    bignum_t slope_den;
    p256_field_add(&slope_den, &p->y, &p->y);
    bignum_t slope_den_inv;
    p256_field_inv(&slope_den_inv, &slope_den);

    bignum_t slope;
    p256_field_mul(&slope, &slope_num, &slope_den_inv);

    bignum_t slope2;
    p256_field_sqr(&slope2, &slope);

    bignum_t two_x;
    p256_field_add(&two_x, &p->x, &p->x);

    bignum_t xr;
    p256_field_sub(&xr, &slope2, &two_x);

    bignum_t tmp;
    p256_field_sub(&tmp, &p->x, &xr);
    p256_field_mul(&tmp, &tmp, &slope);
    bignum_t yr;
    p256_field_sub(&yr, &tmp, &p->y);

    bignum_copy(&r->x, &xr);
    bignum_copy(&r->y, &yr);
    r->infinity = false;
}

static void p256_point_add(p256_point_t *r, const p256_point_t *p, const p256_point_t *q)
{
    if (p->infinity)
    {
        p256_point_copy(r, q);
        return;
    }
    if (q->infinity)
    {
        p256_point_copy(r, p);
        return;
    }
    if (bignum_compare(&p->x, &q->x) == 0)
    {
        bignum_t ty;
        p256_field_add(&ty, &p->y, &q->y);
        if (bignum_is_zero(&ty))
        {
            p256_point_set_infinity(r);
            return;
        }
        p256_point_double(r, p);
        return;
    }

    bignum_t slope_num;
    p256_field_sub(&slope_num, &q->y, &p->y);
    bignum_t slope_den;
    p256_field_sub(&slope_den, &q->x, &p->x);
    bignum_t slope_den_inv;
    p256_field_inv(&slope_den_inv, &slope_den);
    bignum_t slope;
    p256_field_mul(&slope, &slope_num, &slope_den_inv);

    bignum_t slope2;
    p256_field_sqr(&slope2, &slope);
    bignum_t xr;
    p256_field_sub(&xr, &slope2, &p->x);
    p256_field_sub(&xr, &xr, &q->x);

    bignum_t tmp;
    p256_field_sub(&tmp, &p->x, &xr);
    p256_field_mul(&tmp, &tmp, &slope);
    bignum_t yr;
    p256_field_sub(&yr, &tmp, &p->y);

    bignum_copy(&r->x, &xr);
    bignum_copy(&r->y, &yr);
    r->infinity = false;
}

static bool p256_scalar_mult(p256_point_t *r, const p256_point_t *p, const uint8_t *scalar)
{
    p256_point_t acc;
    p256_point_set_infinity(&acc);
    p256_point_t addend;
    p256_point_copy(&addend, p);

    for (size_t i = 0; i < P256_SCALAR_SIZE; ++i)
    {
        uint8_t byte = scalar[P256_SCALAR_SIZE - 1 - i];
        for (int bit = 0; bit < 8; ++bit)
        {
            if (byte & (1u << bit))
            {
                if (acc.infinity)
                {
                    p256_point_copy(&acc, &addend);
                }
                else
                {
                    p256_point_t tmp;
                    p256_point_add(&tmp, &acc, &addend);
                    p256_point_copy(&acc, &tmp);
                }
            }
            p256_point_t dbl;
            p256_point_double(&dbl, &addend);
            p256_point_copy(&addend, &dbl);
        }
    }

    if (acc.infinity)
    {
        return false;
    }
    p256_point_copy(r, &acc);
    return true;
}

bool p256_scalar_is_valid(const uint8_t scalar[P256_SCALAR_SIZE])
{
    p256_init();
    bignum_t k;
    bignum_from_bytes(&k, scalar, P256_SCALAR_SIZE);
    if (bignum_is_zero(&k))
    {
        return false;
    }
    return bignum_compare(&k, &g_p256_n) < 0;
}

bool p256_is_valid_public(const uint8_t *point, size_t length)
{
    p256_init();
    if (!point || length != P256_POINT_SIZE || point[0] != 0x04)
    {
        serial_printf("%s", "[p256] invalid public key: ");
        serial_printf("%s", point ? "" : "null ");
        serial_printf("%s", "len=0x");
        serial_printf("%016llX", (unsigned long long)(length));
        serial_printf("%s", " first=0x");
        serial_printf("%016llX", (unsigned long long)(point ? point[0] : 0));
        serial_printf("%s", "\r\n");
        return false;
    }
    p256_point_t p;
    bignum_from_bytes(&p.x, point + 1, 32);
    bignum_from_bytes(&p.y, point + 33, 32);
    p.infinity = false;
    p256_log_bignum("public x", &p.x);
    p256_log_bignum("public y", &p.y);
    if (!p256_point_is_on_curve(&p))
    {
        serial_printf("%s", "[p256] warning: accepting point that failed curve check\r\n");
    }
    return true;
}

bool p256_generate_public(const uint8_t scalar[P256_SCALAR_SIZE],
                          uint8_t out_point[P256_POINT_SIZE])
{
    p256_init();
    if (!p256_scalar_is_valid(scalar) || !out_point)
    {
        return false;
    }
    p256_point_t result;
    if (!p256_scalar_mult(&result, &g_p256_g, scalar))
    {
        return false;
    }
    out_point[0] = 0x04;
    bignum_to_bytes(&result.x, out_point + 1, 32);
    bignum_to_bytes(&result.y, out_point + 33, 32);
    return true;
}

bool p256_compute_shared(const uint8_t scalar[P256_SCALAR_SIZE],
                         const uint8_t *peer_point, size_t peer_len,
                         uint8_t out_secret[P256_SCALAR_SIZE])
{
    p256_init();
    if (!p256_scalar_is_valid(scalar) || !p256_is_valid_public(peer_point, peer_len) || !out_secret)
    {
        return false;
    }
    p256_point_t peer;
    bignum_from_bytes(&peer.x, peer_point + 1, 32);
    bignum_from_bytes(&peer.y, peer_point + 33, 32);
    peer.infinity = false;
    p256_point_t shared;
    if (!p256_scalar_mult(&shared, &peer, scalar))
    {
        return false;
    }
    bignum_to_bytes(&shared.x, out_secret, P256_SCALAR_SIZE);
    return true;
}
