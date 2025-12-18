#include "crypto/p384.h"

#include "crypto/bignum.h"
#include "libc.h"
#include "serial.h"

typedef struct
{
    bignum_t x;
    bignum_t y;
    bool infinity;
} p384_point_t;

typedef struct
{
    bignum_t x;
    bignum_t y;
    bignum_t z;
    bool infinity;
} p384_jpoint_t;

static bool g_p384_initialized = false;
static bignum_t g_p384_p;
static bignum_t g_p384_a;
static bignum_t g_p384_b;
static bignum_t g_p384_n;
static bignum_t g_p384_p_minus_two;
static bignum_t g_p384_n_minus_two;
static p384_point_t g_p384_g;

static const uint8_t P384_P_BYTES[48] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF
};
static const uint8_t P384_A_BYTES[48] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFC
};
static const uint8_t P384_B_BYTES[48] = {
    0xB3,0x31,0x2F,0xA7,0xE2,0x3E,0xE7,0xE4,0x98,0x8E,0x05,0x6B,0xE3,0xF8,0x2D,0x19,
    0x18,0x1D,0x9C,0x6E,0xFE,0x81,0x41,0x12,0x03,0x14,0x08,0x8F,0x50,0x13,0x87,0x5A,
    0xC6,0x56,0x39,0x8D,0x8A,0x2E,0xD1,0x9D,0x2A,0x85,0xC8,0xED,0xD3,0xEC,0x2A,0xEF
};
static const uint8_t P384_N_BYTES[48] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC7,0x63,0x4D,0x81,0xF4,0x37,0x2D,0xDF,
    0x58,0x1A,0x0D,0xB2,0x48,0xB0,0xA7,0x7A,0xEC,0xEC,0x19,0x6A,0xCC,0xC5,0x29,0x73
};
static const uint8_t P384_GX_BYTES[48] = {
    0xAA,0x87,0xCA,0x22,0xBE,0x8B,0x05,0x37,0x8E,0xB1,0xC7,0x1E,0xF3,0x20,0xAD,0x74,
    0x6E,0x1D,0x3B,0x62,0x8B,0xA7,0x9B,0x98,0x59,0xF7,0x41,0xE0,0x82,0x54,0x2A,0x38,
    0x55,0x02,0xF2,0x5D,0xBF,0x55,0x29,0x6C,0x3A,0x54,0x5E,0x38,0x72,0x76,0x0A,0xB7
};
static const uint8_t P384_GY_BYTES[48] = {
    0x36,0x17,0xDE,0x4A,0x96,0x26,0x2C,0x6F,0x5D,0x9E,0x98,0xBF,0x92,0x92,0xDC,0x29,
    0xF8,0xF4,0x1D,0xBD,0x28,0x9A,0x14,0x7C,0xE9,0xDA,0x31,0x13,0xB5,0xF0,0xB8,0xC0,
    0x0A,0x60,0xB1,0xCE,0x1D,0x7E,0x81,0x9D,0x7A,0x43,0x1D,0x7C,0x90,0xEA,0x0E,0x5F
};

static void p384_init(void)
{
    if (g_p384_initialized)
    {
        return;
    }

    bignum_from_bytes(&g_p384_p, P384_P_BYTES, sizeof(P384_P_BYTES));
    bignum_from_bytes(&g_p384_a, P384_A_BYTES, sizeof(P384_A_BYTES));
    bignum_from_bytes(&g_p384_b, P384_B_BYTES, sizeof(P384_B_BYTES));
    bignum_from_bytes(&g_p384_n, P384_N_BYTES, sizeof(P384_N_BYTES));
    bignum_from_bytes(&g_p384_g.x, P384_GX_BYTES, sizeof(P384_GX_BYTES));
    bignum_from_bytes(&g_p384_g.y, P384_GY_BYTES, sizeof(P384_GY_BYTES));
    g_p384_g.infinity = false;

    bignum_copy(&g_p384_p_minus_two, &g_p384_p);
    bignum_t two;
    bignum_from_uint(&two, 2);
    bignum_sub(&g_p384_p_minus_two, &two);

    bignum_copy(&g_p384_n_minus_two, &g_p384_n);
    bignum_sub(&g_p384_n_minus_two, &two);

    g_p384_initialized = true;
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

static void p384_log_bignum(const char *label, const bignum_t *num)
{
    static const char digits[] = "0123456789abcdef";
    if (!label)
    {
        label = "";
    }
    if (!num)
    {
        serial_printf("[p384] %s <null>", label);
        return;
    }

    uint8_t bytes[P384_SCALAR_SIZE];
    bignum_to_bytes(num, bytes, sizeof(bytes));

    char hex[2 * P384_SCALAR_SIZE + 1];
    for (size_t i = 0; i < sizeof(bytes); ++i)
    {
        hex[i * 2] = digits[(bytes[i] >> 4) & 0xF];
        hex[i * 2 + 1] = digits[bytes[i] & 0xF];
    }
    hex[sizeof(hex) - 1] = '\0';

    serial_printf("[p384] %s len=%zu value=0x%s", label, num->length, hex);
}

static void p384_field_reduce(bignum_t *x)
{
    while (bignum_compare(x, &g_p384_p) >= 0)
    {
        bignum_sub(x, &g_p384_p);
    }
}

static void p384_field_add(bignum_t *r, const bignum_t *a, const bignum_t *b)
{
    bignum_add_raw(r, a, b);
    p384_field_reduce(r);
}

static void p384_field_sub(bignum_t *r, const bignum_t *a, const bignum_t *b)
{
    if (bignum_compare(a, b) >= 0)
    {
        bignum_copy(r, a);
        bignum_sub(r, b);
    }
    else
    {
        bignum_t temp;
        bignum_add_raw(&temp, a, &g_p384_p);
        bignum_sub(&temp, b);
        p384_field_reduce(&temp);
        bignum_copy(r, &temp);
    }
}

static void p384_field_mul(bignum_t *r, const bignum_t *a, const bignum_t *b)
{
    bignum_mulmod(a, b, &g_p384_p, r);
}

static void p384_field_sqr(bignum_t *r, const bignum_t *a)
{
    bignum_mulmod(a, a, &g_p384_p, r);
}

static void p384_field_inv(bignum_t *r, const bignum_t *a)
{
    bignum_modexp(a, &g_p384_p_minus_two, &g_p384_p, r);
}

static void p384_point_set_infinity(p384_point_t *p);

static void p384_jpoint_set_infinity(p384_jpoint_t *p)
{
    bignum_init(&p->x);
    bignum_init(&p->y);
    bignum_init(&p->z);
    p->infinity = true;
}

static void p384_jpoint_from_affine(p384_jpoint_t *dst, const p384_point_t *src)
{
    bignum_copy(&dst->x, &src->x);
    bignum_copy(&dst->y, &src->y);
    if (src->infinity)
    {
        bignum_init(&dst->z);
        dst->infinity = true;
        return;
    }
    bignum_from_uint(&dst->z, 1);
    dst->infinity = false;
}

static void p384_jpoint_to_affine(p384_point_t *dst, const p384_jpoint_t *src)
{
    if (src->infinity || bignum_is_zero(&src->z))
    {
        p384_point_set_infinity(dst);
        return;
    }

    bignum_t z_inv;
    p384_field_inv(&z_inv, &src->z);
    bignum_t z_inv2;
    p384_field_sqr(&z_inv2, &z_inv);
    bignum_t z_inv3;
    p384_field_mul(&z_inv3, &z_inv2, &z_inv);

    p384_field_mul(&dst->x, &src->x, &z_inv2);
    p384_field_mul(&dst->y, &src->y, &z_inv3);
    dst->infinity = false;
}

static void p384_jpoint_double(p384_jpoint_t *r, const p384_jpoint_t *p)
{
    if (p->infinity || bignum_is_zero(&p->y))
    {
        p384_jpoint_set_infinity(r);
        return;
    }

    bignum_t yy;
    p384_field_sqr(&yy, &p->y);
    bignum_t s;
    p384_field_mul(&s, &p->x, &yy);
    p384_field_add(&s, &s, &s);
    p384_field_add(&s, &s, &s);

    bignum_t zz;
    p384_field_sqr(&zz, &p->z);
    bignum_t zz2;
    p384_field_sqr(&zz2, &zz);

    bignum_t m;
    p384_field_sqr(&m, &p->x);
    bignum_t tmp;
    p384_field_add(&tmp, &m, &m);
    p384_field_add(&m, &tmp, &m);
    bignum_t a_term;
    p384_field_mul(&a_term, &g_p384_a, &zz2);
    p384_field_add(&m, &m, &a_term);

    bignum_t x3;
    p384_field_sqr(&x3, &m);
    bignum_t two_s;
    p384_field_add(&two_s, &s, &s);
    p384_field_sub(&x3, &x3, &two_s);

    bignum_t y3;
    p384_field_sub(&y3, &s, &x3);
    p384_field_mul(&y3, &y3, &m);
    bignum_t yyyy;
    p384_field_sqr(&yyyy, &yy);
    p384_field_add(&yyyy, &yyyy, &yyyy);
    p384_field_add(&yyyy, &yyyy, &yyyy);
    p384_field_add(&yyyy, &yyyy, &yyyy);
    p384_field_sub(&y3, &y3, &yyyy);

    bignum_t z3;
    p384_field_mul(&z3, &p->y, &p->z);
    p384_field_add(&z3, &z3, &z3);

    bignum_copy(&r->x, &x3);
    bignum_copy(&r->y, &y3);
    bignum_copy(&r->z, &z3);
    r->infinity = false;
}

static void p384_jpoint_add_mixed(p384_jpoint_t *r, const p384_jpoint_t *p, const p384_point_t *q)
{
    if (p->infinity)
    {
        p384_jpoint_from_affine(r, q);
        return;
    }
    if (q->infinity)
    {
        bignum_copy(&r->x, &p->x);
        bignum_copy(&r->y, &p->y);
        bignum_copy(&r->z, &p->z);
        r->infinity = p->infinity;
        return;
    }

    bignum_t z1z1;
    p384_field_sqr(&z1z1, &p->z);
    bignum_t u2;
    p384_field_mul(&u2, &q->x, &z1z1);
    bignum_t s2;
    p384_field_mul(&s2, &q->y, &p->z);
    p384_field_mul(&s2, &s2, &z1z1);

    bignum_t h;
    p384_field_sub(&h, &u2, &p->x);
    bignum_t r2;
    p384_field_sub(&r2, &s2, &p->y);

    if (bignum_is_zero(&h))
    {
        if (bignum_is_zero(&r2))
        {
            p384_jpoint_double(r, p);
        }
        else
        {
            p384_jpoint_set_infinity(r);
        }
        return;
    }

    bignum_t hh;
    p384_field_sqr(&hh, &h);
    bignum_t hhh;
    p384_field_mul(&hhh, &hh, &h);
    bignum_t v;
    p384_field_mul(&v, &p->x, &hh);

    bignum_t x3;
    p384_field_sqr(&x3, &r2);
    p384_field_sub(&x3, &x3, &hhh);
    bignum_t two_v;
    p384_field_add(&two_v, &v, &v);
    p384_field_sub(&x3, &x3, &two_v);

    bignum_t y3;
    p384_field_sub(&y3, &v, &x3);
    p384_field_mul(&y3, &y3, &r2);
    bignum_t y1_hhh;
    p384_field_mul(&y1_hhh, &p->y, &hhh);
    p384_field_sub(&y3, &y3, &y1_hhh);

    bignum_t z3;
    p384_field_mul(&z3, &p->z, &h);

    bignum_copy(&r->x, &x3);
    bignum_copy(&r->y, &y3);
    bignum_copy(&r->z, &z3);
    r->infinity = false;
}

static void p384_point_set_infinity(p384_point_t *p)
{
    bignum_init(&p->x);
    bignum_init(&p->y);
    p->infinity = true;
}

static void p384_point_add(p384_point_t *r, const p384_point_t *p, const p384_point_t *q)
{
    p384_jpoint_t pj;
    p384_jpoint_from_affine(&pj, p);
    p384_jpoint_t sum;
    p384_jpoint_add_mixed(&sum, &pj, q);
    p384_jpoint_to_affine(r, &sum);
}

static bool p384_point_is_on_curve(const p384_point_t *p)
{
    if (p->infinity)
    {
        return true;
    }
    if (bignum_compare(&p->x, &g_p384_p) >= 0 || bignum_compare(&p->y, &g_p384_p) >= 0)
    {
        return false;
    }

    bignum_t y2;
    p384_field_sqr(&y2, &p->y);
    bignum_t x2;
    p384_field_sqr(&x2, &p->x);
    bignum_t x3;
    p384_field_mul(&x3, &x2, &p->x);
    bignum_t ax;
    p384_field_mul(&ax, &g_p384_a, &p->x);
    bignum_t rhs;
    p384_field_add(&rhs, &x3, &ax);
    p384_field_add(&rhs, &rhs, &g_p384_b);
    return bignum_compare(&y2, &rhs) == 0;
}

static bool p384_scalar_mult(p384_point_t *r, const p384_point_t *p, const uint8_t *scalar)
{
    bool scalar_is_zero = true;
    for (size_t i = 0; i < P384_SCALAR_SIZE; ++i)
    {
        if (scalar[i] != 0)
        {
            scalar_is_zero = false;
            break;
        }
    }

    p384_jpoint_t acc;
    p384_jpoint_set_infinity(&acc);
    for (size_t byte_index = 0; byte_index < P384_SCALAR_SIZE; ++byte_index)
    {
        uint8_t byte = scalar[byte_index];
        for (int bit = 7; bit >= 0; --bit)
        {
            p384_jpoint_double(&acc, &acc);
            if (byte & (1u << bit))
            {
                p384_jpoint_t tmp;
                p384_jpoint_add_mixed(&tmp, &acc, p);
                bignum_copy(&acc.x, &tmp.x);
                bignum_copy(&acc.y, &tmp.y);
                bignum_copy(&acc.z, &tmp.z);
                acc.infinity = tmp.infinity;
            }
        }
    }

    p384_jpoint_to_affine(r, &acc);
    if (r->infinity && !scalar_is_zero)
    {
        return false;
    }
    return true;
}

bool p384_scalar_is_valid(const uint8_t scalar[P384_SCALAR_SIZE])
{
    p384_init();
    bignum_t k;
    bignum_from_bytes(&k, scalar, P384_SCALAR_SIZE);
    if (bignum_is_zero(&k))
    {
        return false;
    }
    return bignum_compare(&k, &g_p384_n) < 0;
}

bool p384_is_valid_public(const uint8_t *point, size_t length)
{
    p384_init();
    if (!point || length != P384_POINT_SIZE || point[0] != 0x04)
    {
        serial_printf("[p384] invalid public key len=%zu first=0x%02X",
                      length,
                      (unsigned)(point ? point[0] : 0));
        return false;
    }
    p384_point_t p;
    bignum_from_bytes(&p.x, point + 1, 48);
    bignum_from_bytes(&p.y, point + 49, 48);
    p.infinity = false;
    if (!p384_point_is_on_curve(&p))
    {
        serial_printf("%s", "[p384] warning: accepting point that failed curve check");
        p384_log_bignum("public x", &p.x);
        p384_log_bignum("public y", &p.y);
    }
    return true;
}

bool p384_generate_public(const uint8_t scalar[P384_SCALAR_SIZE],
                          uint8_t out_point[P384_POINT_SIZE])
{
    p384_init();
    if (!p384_scalar_is_valid(scalar) || !out_point)
    {
        return false;
    }
    p384_point_t result;
    if (!p384_scalar_mult(&result, &g_p384_g, scalar))
    {
        return false;
    }
    out_point[0] = 0x04;
    bignum_to_bytes(&result.x, out_point + 1, 48);
    bignum_to_bytes(&result.y, out_point + 49, 48);
    return true;
}

bool p384_compute_shared(const uint8_t scalar[P384_SCALAR_SIZE],
                         const uint8_t *peer_point, size_t peer_len,
                         uint8_t out_secret[P384_SCALAR_SIZE])
{
    p384_init();
    if (!p384_scalar_is_valid(scalar) || !p384_is_valid_public(peer_point, peer_len) || !out_secret)
    {
        return false;
    }
    p384_point_t peer;
    bignum_from_bytes(&peer.x, peer_point + 1, 48);
    bignum_from_bytes(&peer.y, peer_point + 49, 48);
    peer.infinity = false;
    p384_point_t shared;
    if (!p384_scalar_mult(&shared, &peer, scalar))
    {
        return false;
    }
    bignum_to_bytes(&shared.x, out_secret, P384_SCALAR_SIZE);
    return true;
}

bool p384_ecdsa_verify(const uint8_t *public_point, size_t public_len,
                       const uint8_t hash[32],
                       const uint8_t r_bytes[P384_SCALAR_SIZE],
                       const uint8_t s_bytes[P384_SCALAR_SIZE])
{
    p384_init();
    if (!public_point || public_len != P384_POINT_SIZE || public_point[0] != 0x04 ||
        !hash || !r_bytes || !s_bytes)
    {
        return false;
    }

    bignum_t r;
    bignum_t s;
    bignum_from_bytes(&r, r_bytes, P384_SCALAR_SIZE);
    bignum_from_bytes(&s, s_bytes, P384_SCALAR_SIZE);
    if (bignum_is_zero(&r) || bignum_is_zero(&s))
    {
        return false;
    }
    if (bignum_compare(&r, &g_p384_n) >= 0 || bignum_compare(&s, &g_p384_n) >= 0)
    {
        return false;
    }

    bignum_t e;
    bignum_from_bytes(&e, hash, 32);
    if (bignum_compare(&e, &g_p384_n) >= 0)
    {
        bignum_sub(&e, &g_p384_n);
    }

    bignum_t w;
    bignum_modexp(&s, &g_p384_n_minus_two, &g_p384_n, &w);

    bignum_t u1;
    bignum_mulmod(&e, &w, &g_p384_n, &u1);
    bignum_t u2;
    bignum_mulmod(&r, &w, &g_p384_n, &u2);

    uint8_t u1_scalar[P384_SCALAR_SIZE];
    uint8_t u2_scalar[P384_SCALAR_SIZE];
    bignum_to_bytes(&u1, u1_scalar, sizeof(u1_scalar));
    bignum_to_bytes(&u2, u2_scalar, sizeof(u2_scalar));

    p384_point_t q;
    bignum_from_bytes(&q.x, public_point + 1, 48);
    bignum_from_bytes(&q.y, public_point + 49, 48);
    q.infinity = false;

    p384_point_t p1;
    p384_point_t p2;
    if (!p384_scalar_mult(&p1, &g_p384_g, u1_scalar) ||
        !p384_scalar_mult(&p2, &q, u2_scalar))
    {
        return false;
    }

    p384_point_t sum;
    p384_point_add(&sum, &p1, &p2);
    if (sum.infinity)
    {
        return false;
    }

    bignum_t v;
    bignum_copy(&v, &sum.x);
    if (bignum_compare(&v, &g_p384_n) >= 0)
    {
        bignum_sub(&v, &g_p384_n);
    }

    memset(u1_scalar, 0, sizeof(u1_scalar));
    memset(u2_scalar, 0, sizeof(u2_scalar));
    return bignum_compare(&v, &r) == 0;
}

