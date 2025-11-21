/*
 * jpeg.c — tiny baseline (SOF0) + progressive (SOF2) JPEG → RGBA32 decoder
 * with full instrumentation (no FP/SSE; freestanding-friendly)
 *
 * Highlights:
 *  - Baseline & Progressive decoding (Huffman, no arithmetic coding)
 *  - Libjpeg-like AAN integer IDCT with clamp to [0,255]
 *  - YCbCr→RGB uses integer tables (no float) and rounded 8-bit packing
 *  - Respects APP14 Adobe transform and SOS scan component order
 *  - Rich debug logging via serial (toggle with JPEG_DEBUG flags below)
 */

#include "types.h"
#include "heap.h"
#include "libc.h"
#include "serial.h"
#include "atk/util/jpeg.h"

/* ========================== DEBUG CONFIG ========================== */
#ifndef JPEG_DEBUG
#define JPEG_DEBUG 1
#endif

/* Granular toggles (0 = off, 1 = on) */
#define JPEG_DEBUG_MARKERS      1  /* APP14, DQT/DHT presence, SOF dims/components */
#define JPEG_DEBUG_MAPPING      1  /* Component mapping (RGB vs YCbCr) */
#define JPEG_DEBUG_SOS          1  /* SOS Ns/Ss/Se/Ah/Al + comp ids/td/ta */
#define JPEG_DEBUG_RESTART      1  /* RST markers seen */
#define JPEG_DEBUG_IDCT_CLAMP   1  /* count post-IDCT clamps to [0,255] */
#define JPEG_DEBUG_COLOR_CLAMP  1  /* count YCbCr->RGB out-of-range before pack */
#define JPEG_DEBUG_FIRST_MCU    1  /* log a couple pixels from the first MCU */

/* Quick experiment: swap Cb/Cr during color conversion to test encoder quirks */
#define JPEG_DEBUG_SWAP_CBCR    0

typedef struct {
    uint64_t idct_clamp;      /* number of samples clamped after IDCT */
    uint64_t color_r_clamp;   /* r<0 or r>255 count before pack */
    uint64_t color_g_clamp;
    uint64_t color_b_clamp;
    uint64_t rst_seen;        /* restart markers observed */
    uint64_t blocks_decoded;  /* 8x8 blocks decoded (sequential path) */
} jpeg_dbg_stats_t;

static jpeg_dbg_stats_t g_dbg = {0};

/* Tiny decimal writer so we don't pull in stdio */
static void serial_write_dec(int v)
{
    char buf[32]; int i = 0; unsigned int x;
    if (v < 0) { serial_printf("%s", "-"); x = (unsigned int)(-v); }
    else x = (unsigned int)v;
    do { buf[i++] = (char)('0' + (x % 10)); x /= 10; } while (x && i < (int)sizeof(buf));
    if (i == 0) buf[i++] = '0';
    while (i--) { char s[2] = { buf[i], 0 }; serial_printf("%s", s); }
}
static void jpeg_dbg_kv(const char *k, int v)
{
#if JPEG_DEBUG
    serial_printf("%s", k); serial_printf("%s", "=");
    serial_write_dec(v); serial_printf("%s", " ");
#else
    (void)k; (void)v;
#endif
}
static void jpeg_dbg_line(const char *s)
{
#if JPEG_DEBUG
    serial_printf("%s", "jpeg: ");
    serial_printf("%s", s);
    serial_printf("%s", "\r\n");
#else
    (void)s;
#endif
}

/* ========================== Bitstream ========================== */

typedef struct
{
    const uint8_t *data;
    size_t size;
    size_t byte_pos;
    uint32_t bit_buf;
    int bits_left;
    bool in_scan;
    int last_marker;
} bitreader_t;

static void br_init(bitreader_t *br, const uint8_t *data, size_t size)
{
    br->data = data;
    br->size = size;
    br->byte_pos = 0;
    br->bit_buf = 0;
    br->bits_left = 0;
    br->in_scan = false;
    br->last_marker = -1;
}

static int br_read_u8(bitreader_t *br)
{
    if (br->byte_pos >= br->size)
        return -1;
    return br->data[br->byte_pos++];
}

static bool br_refill(bitreader_t *br)
{
    while (br->bits_left <= 16)
    {
        int b = br_read_u8(br);
        if (b < 0)
        {
            return br->bits_left > 0;
        }
        if (br->in_scan && b == 0xFF)
        {
            int n = br_read_u8(br);
            if (n < 0)
            {
                br->last_marker = 0xFF;
                return br->bits_left > 0;
            }
            if (n != 0x00)
            {
                /* Encountered a marker; back up so higher layers can read it. */
                br->last_marker = (0xFF00 | n);
                if (br->byte_pos >= 2) br->byte_pos -= 2; else br->byte_pos = 0;
                return br->bits_left > 0;
            }
            b = 0xFF; /* stuffed byte */
        }
        br->bit_buf = (br->bit_buf << 8) | (uint32_t)b;
        br->bits_left += 8;
    }
    return true;
}

static uint32_t br_peek(bitreader_t *br, int n)
{
    if (br->bits_left < n) br_refill(br);
    return (br->bit_buf >> (br->bits_left - n)) & ((1u << n) - 1);
}

static void br_drop(bitreader_t *br, int n)
{
    if (n <= 0) return;
    br->bits_left -= n;
    if (br->bits_left < 0) br->bits_left = 0;
}

static uint32_t br_get(bitreader_t *br, int n)
{
    uint32_t v = br_peek(br, n);
    br_drop(br, n);
    return v;
}

static void br_align_byte(bitreader_t *br)
{
    int r = br->bits_left & 7;
    if (r) br_drop(br, r);
}

/* ========================== JPEG structures ========================== */

#define MAX_QUANT 4
#define MAX_HUFF  4
#define MAX_COMP  3

typedef struct { uint16_t q[64]; bool present; } dqt_t;

typedef struct
{
    uint8_t counts[16];
    uint8_t symbols[256];
    uint16_t fast[1 << 8];
    uint16_t codes[256];
    uint8_t sizes[256];
    int num_symbols;
    bool present;
} dht_t;

typedef struct
{
    uint8_t id;   /* component id from SOF (1/2/3 typical JFIF, may be 'R','G','B' from Adobe) */
    uint8_t H, V; /* sampling factors */
    uint8_t tq;   /* quant table index */
    uint8_t td, ta; /* DC/AC Huff selectors from SOS */
    int dc_pred;
} comp_t;

typedef struct
{
    int width, height;
    int mcu_w, mcu_h;
    int mcus_x, mcus_y;
    int comps;
    int Hmax, Vmax;
    comp_t C[MAX_COMP];
    dqt_t  Q[MAX_QUANT];
    dht_t  HTDC[MAX_HUFF];
    dht_t  HTAC[MAX_HUFF];
    int restart_interval;
    int color_transform;  /* Adobe APP14 transform (-1 unknown, 0 RGB, 1 YCbCr) */
    bool adobe_transform_present;

    bool progressive;
    int16_t *coef[MAX_COMP];

    /* Component mapping */
    bool use_rgb;         /* true => input data are already R/G/B */
    int idxY, idxCb, idxCr;   /* for YCbCr */
    int idxR, idxG, idxB;     /* for RGB */
} jpg_t;

static const uint8_t zigzag[64] = {
    0, 1, 5, 6, 14, 15, 27, 28,
    2, 4, 7, 13, 16, 26, 29, 42,
    3, 8, 12, 17, 25, 30, 41, 43,
    9, 11, 18, 24, 31, 40, 44, 53,
    10, 19, 23, 32, 39, 45, 52, 54,
    20, 22, 33, 38, 46, 51, 55, 60,
    21, 34, 37, 47, 50, 56, 59, 61,
    35, 36, 48, 49, 57, 58, 62, 63};

/* ========================== Utilities ========================== */

static inline int clampi(int x, int lo, int hi) { return x < lo ? lo : (x > hi ? hi : x); }

/* rounded scaling to 8-bit channels (avoid bias near thresholds) */
static inline video_color_t pack_rgba32(int r, int g, int b)
{
    r = clampi(r, 0, 255);
    g = clampi(g, 0, 255);
    b = clampi(b, 0, 255);
    return 0xFF000000U | ((video_color_t)r << 16) | ((video_color_t)g << 8) | (video_color_t)b;
}

static inline int u8_saturate(int v) { return (v & ~0xFF) ? (v < 0 ? 0 : 255) : v; }

static char g_last_error_buf[128] = "ok";
static const char *g_last_error = "ok";
const char *jpeg_last_error(void) { return g_last_error; }
static void jpeg_set_error(const char *msg)
{
    if (!msg) msg = "unknown";
    size_t len = strlen(msg);
    if (len >= sizeof(g_last_error_buf)) len = sizeof(g_last_error_buf) - 1;
    memcpy(g_last_error_buf, msg, len);
    g_last_error_buf[len] = '\0';
    g_last_error = g_last_error_buf;
}

/* sign-extend v with n bits (libjpeg-compatible) */
static inline int jsgnextend(int v, int n)
{
    if (n == 0) return 0;
    int lim = 1 << (n - 1);
    if (v < lim) v -= (1 << n) - 1;
    return v;
}

/* ========================== Huffman ========================== */

static void dht_build(dht_t *h)
{
    int code = 0, si = 1, k = 0;
    h->num_symbols = 0;
    for (int i = 0; i < 16; ++i) {
        for (int j = 0; j < h->counts[i]; ++j) {
            h->codes[k] = (uint16_t)code;
            h->sizes[k] = (uint8_t)si;
            ++code; ++k; ++h->num_symbols;
        }
        code <<= 1; ++si;
    }
    for (int i = 0; i < 256; ++i) h->fast[i] = 0xFFFF;

    int idx = 0;
    for (int len = 1; len <= 8; ++len)
    {
        for (int j = 0; j < h->counts[len - 1]; ++j, ++idx)
        {
            int sym  = h->symbols[idx];
            int bits = h->codes[idx] << (8 - len);
            int reps = 1 << (8 - len);
            for (int r = 0; r < reps; ++r)
                h->fast[bits | r] = (uint16_t)((sym << 8) | len);
        }
    }
}

static int huff_decode_symbol(bitreader_t *br, const dht_t *h)
{
    if (br->bits_left < 8) br_refill(br);
    if (br->bits_left >= 8)
    {
        uint16_t e = h->fast[(br->bit_buf >> (br->bits_left - 8)) & 0xFF];
        if (e != 0xFFFF) { br_drop(br, e & 0xFF); return (e >> 8) & 0xFF; }
    }
    int code = 0;
    for (int len = 1; len <= 16; ++len)
    {
        code = (code << 1) | (int)br_get(br, 1);
        int sum = 0; for (int i = 0; i < len - 1; ++i) sum += h->counts[i];
        int cnt = h->counts[len - 1];
        for (int j = 0; j < cnt; ++j)
        {
            int k = sum + j;
            if (h->sizes[k] == len && h->codes[k] == code)
                return h->symbols[k];
        }
    }
    return -1;
}

/* ========================== IDCT (integer AAN, SSE-free) ========================== */

#define CONST_BITS 13
#define PASS1_BITS 2
#define FIX(x)    ((int32_t)((x) * (1 << CONST_BITS) + 0.5))
#define MULTIPLY(a,b) ((int64_t)(a) * (int64_t)(b))
#define DESCALE64(x,n) ((int32_t)(((x) + ((int64_t)1 << ((n) - 1))) >> (n)))

static const int32_t C0_298631336 = FIX(0.298631336);
static const int32_t C0_390180644 = FIX(0.390180644);
static const int32_t C0_541196100 = FIX(0.541196100);
static const int32_t C0_765366865 = FIX(0.765366865);
static const int32_t C0_899976223 = FIX(0.899976223);
static const int32_t C1_175875602 = FIX(1.175875602);
static const int32_t C1_501321110 = FIX(1.501321110);
static const int32_t C1_847759065 = FIX(1.847759065);
static const int32_t C1_961570560 = FIX(1.961570560);
static const int32_t C2_053119869 = FIX(2.053119869);
static const int32_t C2_562915447 = FIX(2.562915447);
static const int32_t C3_072711026 = FIX(3.072711026);

/* AAN scaling factors (scaled by 14 bits, like libjpeg) */
static const uint16_t aanscales[64] = {
    16384, 22725, 21407, 19266, 16384, 12873,  8867,  4520,
    22725, 31521, 29692, 26722, 22725, 17855, 12299,  6270,
    21407, 29692, 27969, 25172, 21407, 16819, 11585,  5906,
    19266, 26722, 25172, 22654, 19266, 15137, 10426,  5315,
    16384, 22725, 21407, 19266, 16384, 12873,  8867,  4520,
    12873, 17855, 16819, 15137, 12873, 10114,  6977,  3552,
     8867, 12299, 11585, 10426,  8867,  6977,  4816,  2459,
     4520,  6270,  5906,  5315,  4520,  3552,  2459,  1259
};

/* IDCT with 32-bit input coefficients (already dequantized), output clamped to 0..255 */
static void idct_8x8(const int32_t *in, int16_t *out)
{
    int32_t workspace[64];

    /* Pre-scale to match AAN expected quant scaling. aanscales[] are 14-bit. */
    int32_t pre[64];
    for (int i = 0; i < 64; ++i) {
        int64_t v = MULTIPLY(in[i], aanscales[i]);
        pre[i] = (int32_t)((v + (1 << 13)) >> 14); /* round back to 32-bit */
    }

    /* Pass 1: columns */
    for (int col = 0; col < 8; ++col)
    {
        const int32_t *ip = pre + col;

        if (ip[8] == 0 && ip[16] == 0 && ip[24] == 0 && ip[32] == 0 &&
            ip[40] == 0 && ip[48] == 0 && ip[56] == 0)
        {
            int32_t dc = ip[0] << PASS1_BITS;
            for (int i = 0; i < 8; ++i) workspace[i * 8 + col] = dc;
            continue;
        }

        int64_t z2 = ip[16];
        int64_t z3 = ip[48];
        int64_t z1 = MULTIPLY(z2 + z3, C0_541196100);
        int64_t tmp2 = z1 + MULTIPLY(z3, -C1_847759065);
        int64_t tmp3 = z1 + MULTIPLY(z2,  C0_765366865);

        int64_t tmp0 = ((int64_t)ip[0] + (int64_t)ip[32]) << CONST_BITS;
        int64_t tmp1 = ((int64_t)ip[0] - (int64_t)ip[32]) << CONST_BITS;

        int64_t tmp10 = tmp0 + tmp3;
        int64_t tmp13 = tmp0 - tmp3;
        int64_t tmp11 = tmp1 + tmp2;
        int64_t tmp12 = tmp1 - tmp2;

        int64_t tmp0o = ip[56];
        int64_t tmp1o = ip[40];
        int64_t tmp2o = ip[24];
        int64_t tmp3o = ip[8];

        int64_t z1o = tmp0o + tmp3o;
        int64_t z2o = tmp1o + tmp2o;
        int64_t z3o = tmp0o + tmp2o;
        int64_t z4o = tmp1o + tmp3o;
        int64_t z5  = MULTIPLY(z3o + z4o, C1_175875602);

        tmp0o = MULTIPLY(tmp0o, C0_298631336);
        tmp1o = MULTIPLY(tmp1o, C2_053119869);
        tmp2o = MULTIPLY(tmp2o, C3_072711026);
        tmp3o = MULTIPLY(tmp3o, C1_501321110);

        z1o = MULTIPLY(z1o, -C0_899976223);
        z2o = MULTIPLY(z2o, -C2_562915447);
        z3o = MULTIPLY(z3o, -C1_961570560);
        z4o = MULTIPLY(z4o, -C0_390180644);

        z3o += z5;
        z4o += z5;

        tmp0o += z1o + z3o;
        tmp1o += z2o + z4o;
        tmp2o += z2o + z3o;
        tmp3o += z1o + z4o;

        workspace[0 * 8 + col] = DESCALE64(tmp10 + tmp3o, CONST_BITS - PASS1_BITS);
        workspace[7 * 8 + col] = DESCALE64(tmp10 - tmp3o, CONST_BITS - PASS1_BITS);
        workspace[1 * 8 + col] = DESCALE64(tmp11 + tmp2o, CONST_BITS - PASS1_BITS);
        workspace[6 * 8 + col] = DESCALE64(tmp11 - tmp2o, CONST_BITS - PASS1_BITS);
        workspace[2 * 8 + col] = DESCALE64(tmp12 + tmp1o, CONST_BITS - PASS1_BITS);
        workspace[5 * 8 + col] = DESCALE64(tmp12 - tmp1o, CONST_BITS - PASS1_BITS);
        workspace[3 * 8 + col] = DESCALE64(tmp13 + tmp0o, CONST_BITS - PASS1_BITS);
        workspace[4 * 8 + col] = DESCALE64(tmp13 - tmp0o, CONST_BITS - PASS1_BITS);
    }

    /* Pass 2: rows */
    for (int row = 0; row < 8; ++row)
    {
        int32_t *rp = workspace + row * 8;

        if (rp[1] == 0 && rp[2] == 0 && rp[3] == 0 && rp[4] == 0 &&
            rp[5] == 0 && rp[6] == 0 && rp[7] == 0)
        {
            int32_t dc = DESCALE64((int64_t)rp[0], PASS1_BITS + 3) + 128;
#if JPEG_DEBUG_IDCT_CLAMP
            if (dc < 0) { ++g_dbg.idct_clamp; dc = 0; }
            else if (dc > 255) { ++g_dbg.idct_clamp; dc = 255; }
#else
            if (dc < 0) dc = 0; else if (dc > 255) dc = 255;
#endif
            for (int i = 0; i < 8; ++i) out[row * 8 + i] = (int16_t)dc;
            continue;
        }

        int64_t z2 = rp[2];
        int64_t z3 = rp[6];
        int64_t z1 = MULTIPLY(z2 + z3, C0_541196100);
        int64_t tmp2 = z1 + MULTIPLY(z3, -C1_847759065);
        int64_t tmp3 = z1 + MULTIPLY(z2,  C0_765366865);

        int64_t tmp0 = ((int64_t)rp[0] + (int64_t)rp[4]) << CONST_BITS;
        int64_t tmp1 = ((int64_t)rp[0] - (int64_t)rp[4]) << CONST_BITS;

        int64_t tmp10 = tmp0 + tmp3;
        int64_t tmp13 = tmp0 - tmp3;
        int64_t tmp11 = tmp1 + tmp2;
        int64_t tmp12 = tmp1 - tmp2;

        int64_t tmp0o = rp[7];
        int64_t tmp1o = rp[5];
        int64_t tmp2o = rp[3];
        int64_t tmp3o = rp[1];

        int64_t z1o = tmp0o + tmp3o;
        int64_t z2o = tmp1o + tmp2o;
        int64_t z3o = tmp0o + tmp2o;
        int64_t z4o = tmp1o + tmp3o;
        int64_t z5  = MULTIPLY(z3o + z4o, C1_175875602);

        tmp0o = MULTIPLY(tmp0o, C0_298631336);
        tmp1o = MULTIPLY(tmp1o, C2_053119869);
        tmp2o = MULTIPLY(tmp2o, C3_072711026);
        tmp3o = MULTIPLY(tmp3o, C1_501321110);

        z1o = MULTIPLY(z1o, -C0_899976223);
        z2o = MULTIPLY(z2o, -C2_562915447);
        z3o = MULTIPLY(z3o, -C1_961570560);
        z4o = MULTIPLY(z4o, -C0_390180644);

        z3o += z5;
        z4o += z5;

        tmp0o += z1o + z3o;
        tmp1o += z2o + z4o;
        tmp2o += z2o + z3o;
        tmp3o += z1o + z4o;

        int32_t v0 = DESCALE64(tmp10 + tmp3o, CONST_BITS + PASS1_BITS + 3) + 128;
        int32_t v7 = DESCALE64(tmp10 - tmp3o, CONST_BITS + PASS1_BITS + 3) + 128;
        int32_t v1 = DESCALE64(tmp11 + tmp2o, CONST_BITS + PASS1_BITS + 3) + 128;
        int32_t v6 = DESCALE64(tmp11 - tmp2o, CONST_BITS + PASS1_BITS + 3) + 128;
        int32_t v2 = DESCALE64(tmp12 + tmp1o, CONST_BITS + PASS1_BITS + 3) + 128;
        int32_t v5 = DESCALE64(tmp12 - tmp1o, CONST_BITS + PASS1_BITS + 3) + 128;
        int32_t v3 = DESCALE64(tmp13 + tmp0o, CONST_BITS + PASS1_BITS + 3) + 128;
        int32_t v4 = DESCALE64(tmp13 - tmp0o, CONST_BITS + PASS1_BITS + 3) + 128;

#if JPEG_DEBUG_IDCT_CLAMP
        if (v0 < 0) { ++g_dbg.idct_clamp; v0 = 0; } else if (v0 > 255) { ++g_dbg.idct_clamp; v0 = 255; }
        if (v1 < 0) { ++g_dbg.idct_clamp; v1 = 0; } else if (v1 > 255) { ++g_dbg.idct_clamp; v1 = 255; }
        if (v2 < 0) { ++g_dbg.idct_clamp; v2 = 0; } else if (v2 > 255) { ++g_dbg.idct_clamp; v2 = 255; }
        if (v3 < 0) { ++g_dbg.idct_clamp; v3 = 0; } else if (v3 > 255) { ++g_dbg.idct_clamp; v3 = 255; }
        if (v4 < 0) { ++g_dbg.idct_clamp; v4 = 0; } else if (v4 > 255) { ++g_dbg.idct_clamp; v4 = 255; }
        if (v5 < 0) { ++g_dbg.idct_clamp; v5 = 0; } else if (v5 > 255) { ++g_dbg.idct_clamp; v5 = 255; }
        if (v6 < 0) { ++g_dbg.idct_clamp; v6 = 0; } else if (v6 > 255) { ++g_dbg.idct_clamp; v6 = 255; }
        if (v7 < 0) { ++g_dbg.idct_clamp; v7 = 0; } else if (v7 > 255) { ++g_dbg.idct_clamp; v7 = 255; }
#else
        if (v0 < 0) v0 = 0; else if (v0 > 255) v0 = 255;
        if (v1 < 0) v1 = 0; else if (v1 > 255) v1 = 255;
        if (v2 < 0) v2 = 0; else if (v2 > 255) v2 = 255;
        if (v3 < 0) v3 = 0; else if (v3 > 255) v3 = 255;
        if (v4 < 0) v4 = 0; else if (v4 > 255) v4 = 255;
        if (v5 < 0) v5 = 0; else if (v5 > 255) v5 = 255;
        if (v6 < 0) v6 = 0; else if (v6 > 255) v6 = 255;
        if (v7 < 0) v7 = 0; else if (v7 > 255) v7 = 255;
#endif

        out[row * 8 + 0] = (int16_t)v0;
        out[row * 8 + 1] = (int16_t)v1;
        out[row * 8 + 2] = (int16_t)v2;
        out[row * 8 + 3] = (int16_t)v3;
        out[row * 8 + 4] = (int16_t)v4;
        out[row * 8 + 5] = (int16_t)v5;
        out[row * 8 + 6] = (int16_t)v6;
        out[row * 8 + 7] = (int16_t)v7;
    }
}



/* ========================== Parsing helpers ========================== */

static uint16_t read_be16(bitreader_t *br)
{
    int a = br_read_u8(br), b = br_read_u8(br);
    if (a < 0 || b < 0) return 0;
    return (uint16_t)((a << 8) | b);
}

static bool skip_bytes(bitreader_t *br, size_t n)
{
    if (br->byte_pos + n > br->size) return false;
    br->byte_pos += n;
    return true;
}

static bool read_bytes(bitreader_t *br, uint8_t *dst, size_t n)
{
    if (!dst) return skip_bytes(br, n);
    for (size_t i = 0; i < n; ++i) {
        int b = br_read_u8(br);
        if (b < 0) return false;
        dst[i] = (uint8_t)b;
    }
    return true;
}

/* ========================== Component mapping ========================== */

static bool jpeg_should_treat_as_rgb(const jpg_t *jpg)
{
    if (!jpg || jpg->comps != 3) return false;
    if (jpg->adobe_transform_present) {
        if (jpg->color_transform == 0) return true;       /* Adobe RGB */
        if (jpg->color_transform == 1) return false;      /* Adobe YCbCr */
    } else {
        if (jpg->C[0].id == 'R' && jpg->C[1].id == 'G' && jpg->C[2].id == 'B') return true;
    }
    return false;
}

static void resolve_component_mapping(jpg_t *jpg)
{
    jpg->use_rgb = jpeg_should_treat_as_rgb(jpg);

#if JPEG_DEBUG_MAPPING
    serial_printf("%s", "jpeg: APP14 present="); serial_write_dec(jpg->adobe_transform_present ? 1 : 0);
    serial_printf("%s", " transform="); serial_write_dec(jpg->color_transform);
    serial_printf("%s", "\r\n");
#endif

    if (jpg->use_rgb) {
        jpg->idxR = jpg->idxG = jpg->idxB = -1;
        for (int i = 0; i < jpg->comps; ++i) {
            if (jpg->C[i].id == 'R') jpg->idxR = i;
            else if (jpg->C[i].id == 'G') jpg->idxG = i;
            else if (jpg->C[i].id == 'B') jpg->idxB = i;
        }
        if (jpg->idxR < 0 || jpg->idxG < 0 || jpg->idxB < 0) {
            jpg->idxR = 0; jpg->idxG = 1; jpg->idxB = 2;
        }
#if JPEG_DEBUG_MAPPING
        serial_printf("%s", "jpeg: mapping RGB idxR=");
        serial_write_dec(jpg->idxR); serial_printf("%s", " idxG=");
        serial_write_dec(jpg->idxG); serial_printf("%s", " idxB=");
        serial_write_dec(jpg->idxB); serial_printf("%s", "\r\n");
#endif
        return;
    }

    jpg->idxY = jpg->idxCb = jpg->idxCr = -1;
    for (int i = 0; i < jpg->comps; ++i)
        if (jpg->C[i].H == jpg->Hmax && jpg->C[i].V == jpg->Vmax) { jpg->idxY = i; break; }
    if (jpg->idxY < 0) jpg->idxY = 0;

    for (int i = 0; i < jpg->comps; ++i) if (i != jpg->idxY) {
        if (jpg->C[i].id == 2) jpg->idxCb = i;
        else if (jpg->C[i].id == 3) jpg->idxCr = i;
    }
    if (jpg->idxCb < 0 || jpg->idxCr < 0) {
        int first = -1, second = -1;
        for (int i = 0; i < jpg->comps; ++i) if (i != jpg->idxY) { if (first < 0) first = i; else second = i; }
        if (jpg->idxCb < 0) jpg->idxCb = first;
        if (jpg->idxCr < 0) jpg->idxCr = second;
    }

#if JPEG_DEBUG_MAPPING
    serial_printf("%s", "jpeg: mapping Y=");
    serial_write_dec(jpg->idxY); serial_printf("%s", " Cb=");
    serial_write_dec(jpg->idxCb); serial_printf("%s", " Cr=");
    serial_write_dec(jpg->idxCr); serial_printf("%s", "\r\n");
#endif
}

/* ========================== Markers ========================== */

static int next_marker(bitreader_t *br)
{
    int c;
    do { c = br_read_u8(br); if (c < 0) return -1; } while (c != 0xFF);
    do { c = br_read_u8(br); if (c < 0) return -1; } while (c == 0xFF);
    return 0xFF00 | c;
}

/* ========================== Segment parsers ========================== */

static bool parse_DQT(bitreader_t *br, jpg_t *jpg)
{
    (void)jpg;
    uint16_t L = read_be16(br);
    if (L < 2) return false;
    size_t remaining = L - 2;
    while (remaining > 0) {
        int pq_tq = br_read_u8(br); if (pq_tq < 0) return false; --remaining;
        int pq = (pq_tq >> 4) & 0xF;
        int tq = pq_tq & 0xF;
        if (tq >= MAX_QUANT || pq != 0) return false; /* 8-bit only */
        if (remaining < 64) return false;
        for (int i = 0; i < 64; ++i) {
            int v = br_read_u8(br); if (v < 0) return false;
            jpg->Q[tq].q[zigzag[i]] = (uint16_t)v; /* file order is zigzag */
        }
        jpg->Q[tq].present = true;
        remaining -= 64;
    }
#if JPEG_DEBUG_MARKERS
    jpeg_dbg_line("DQT parsed");
#endif
    return true;
}

static bool parse_DHT(bitreader_t *br, jpg_t *jpg)
{
    uint16_t L = read_be16(br);
    if (L < 2) { jpeg_set_error("DHT length < 2"); return false; }
    size_t rem = L - 2;
    while (rem > 0) {
        int tc_th = br_read_u8(br); if (tc_th < 0) return false; --rem;
        int tc = (tc_th >> 4) & 0xF, th = tc_th & 0xF;
        if (th >= MAX_HUFF) return false;
        dht_t *H = (tc == 0) ? &jpg->HTDC[th] : &jpg->HTAC[th];
        int total = 0;
        for (int i = 0; i < 16; ++i) { int c = br_read_u8(br); if (c < 0) return false; H->counts[i]=(uint8_t)c; total+=c; }
        if (rem < 16) return false; 
        rem -= 16;
        if (total > 256 || rem < (size_t)total) return false;
        for (int i = 0; i < total; ++i) { int s = br_read_u8(br); if (s < 0) return false; H->symbols[i]=(uint8_t)s; }
        rem -= total; H->present = true; dht_build(H);
    }
#if JPEG_DEBUG_MARKERS
    jpeg_dbg_line("DHT parsed");
#endif
    return true;
}

static bool parse_SOF_common(bitreader_t *br, jpg_t *jpg)
{
    uint16_t L = read_be16(br); if (L < 2) return false;
    int P = br_read_u8(br);
    int Y = read_be16(br);
    int X = read_be16(br);
    int N = br_read_u8(br);
    if (P != 8 || X <= 0 || Y <= 0 || N <= 0 || N > MAX_COMP) return false;

    jpg->width = X; jpg->height = Y; jpg->comps = N; jpg->Hmax = jpg->Vmax = 1;

#if JPEG_DEBUG_MARKERS
    serial_printf("%s", "jpeg: SOF dims ");
    jpeg_dbg_kv("W", X); jpeg_dbg_kv("H", Y); jpeg_dbg_kv("N", N);
    serial_printf("%s", "\r\n");
#endif

    for (int i = 0; i < N; ++i) {
        int C = br_read_u8(br);
        int HV = br_read_u8(br);
        int Tq = br_read_u8(br);
        if (C < 0 || HV < 0 || Tq < 0) return false;

        jpg->C[i].id = (uint8_t)C;
        jpg->C[i].H  = (HV >> 4) & 0xF;
        jpg->C[i].V  = HV & 0xF;
        jpg->C[i].tq = (uint8_t)(Tq & 0xF);
        jpg->C[i].dc_pred = 0;

        if (jpg->C[i].H < 1 || jpg->C[i].H > 2 || jpg->C[i].V < 1 || jpg->C[i].V > 2) return false;
        if (jpg->C[i].H > jpg->Hmax) jpg->Hmax = jpg->C[i].H;
        if (jpg->C[i].V > jpg->Vmax) jpg->Vmax = jpg->C[i].V;

#if JPEG_DEBUG_MARKERS
        serial_printf("%s", "jpeg:   C");
        serial_write_dec(i);
        serial_printf("%s", " id=0x"); serial_printf("%016llX", (unsigned long long)(jpg->C[i].id));
        serial_printf("%s", " H="); serial_write_dec(jpg->C[i].H);
        serial_printf("%s", " V="); serial_write_dec(jpg->C[i].V);
        serial_printf("%s", " Tq="); serial_write_dec(jpg->C[i].tq);
        serial_printf("%s", "\r\n");
#endif
    }

    jpg->mcu_w = 8 * jpg->Hmax;
    jpg->mcu_h = 8 * jpg->Vmax;
    jpg->mcus_x = (jpg->width  + jpg->mcu_w - 1) / jpg->mcu_w;
    jpg->mcus_y = (jpg->height + jpg->mcu_h - 1) / jpg->mcu_h;

#if JPEG_DEBUG_MARKERS
    serial_printf("%s", "jpeg: MCU ");
    jpeg_dbg_kv("mcu_w", jpg->mcu_w); jpeg_dbg_kv("mcu_h", jpg->mcu_h);
    jpeg_dbg_kv("mcus_x", jpg->mcus_x); jpeg_dbg_kv("mcus_y", jpg->mcus_y);
    serial_printf("%s", "\r\n");
#endif

    (void)L;
    return true;
}

static bool parse_DRI(bitreader_t *br, jpg_t *jpg)
{
    uint16_t L = read_be16(br); if (L != 4) return false;
    jpg->restart_interval = (int)read_be16(br);
#if JPEG_DEBUG_MARKERS
    serial_printf("%s", "jpeg: DRI restart_interval=");
    serial_write_dec(jpg->restart_interval);
    serial_printf("%s", "\r\n");
#endif
    return true;
}

static bool read_scan_header(bitreader_t *br, jpg_t *jpg,
                             int *pNs, int scan_comp_idx[MAX_COMP],
                             int *pSs, int *pSe, int *pAh, int *pAl)
{
    uint16_t L = read_be16(br); if (L < 2) return false;
    int Ns = br_read_u8(br); if (Ns <= 0 || Ns > jpg->comps) return false;

#if JPEG_DEBUG_SOS
    serial_printf("%s", "jpeg: SOS Ns="); serial_write_dec(Ns); serial_printf("%s", "\r\n");
#endif

    for (int i = 0; i < Ns; ++i)
    {
        int Cs  = br_read_u8(br);
        int Tda = br_read_u8(br);
        if (Cs < 0 || Tda < 0) return false;

        int idx = -1;
        for (int k = 0; k < jpg->comps; ++k)
            if (jpg->C[k].id == (uint8_t)Cs) { idx = k; break; }
        if (idx < 0) return false;

        scan_comp_idx[i] = idx;
        jpg->C[idx].td = (Tda >> 4) & 0xF;
        jpg->C[idx].ta =  Tda       & 0xF;

#if JPEG_DEBUG_SOS
        serial_printf("%s", "jpeg:   comp["); serial_write_dec(i);
        serial_printf("%s", "] id=0x"); serial_printf("%016llX", (unsigned long long)((uint64_t)Cs));
        serial_printf("%s", " ci="); serial_write_dec(idx);
        serial_printf("%s", " td="); serial_write_dec(jpg->C[idx].td);
        serial_printf("%s", " ta="); serial_write_dec(jpg->C[idx].ta);
        serial_printf("%s", "\r\n");
#endif
    }

    int Ss   = br_read_u8(br);
    int Se   = br_read_u8(br);
    int AhAl = br_read_u8(br);
    if (Ss < 0 || Se < 0 || AhAl < 0) return false;

    *pNs = Ns; *pSs = Ss; *pSe = Se; *pAh = (AhAl >> 4) & 0xF; *pAl = AhAl & 0xF;

#if JPEG_DEBUG_SOS
    serial_printf("%s", "jpeg:   Ss="); serial_write_dec(*pSs);
    serial_printf("%s", " Se="); serial_write_dec(*pSe);
    serial_printf("%s", " Ah="); serial_write_dec(*pAh);
    serial_printf("%s", " Al="); serial_write_dec(*pAl);
    serial_printf("%s", "\r\n");
#endif

    (void)L; return true;
}

/* ========================== YCbCr → RGB tables (integer; no FP/SSE) ========================== */

static bool g_ycc_tabs_init = false;
static int g_Cr_r_tab[256];
static int g_Cb_b_tab[256];
static int g_Cr_g_tab[256];
static int g_Cb_g_tab[256];

static void ycc_build_tables(void)
{
    if (g_ycc_tabs_init) return;

    /* 16-bit fixed-point coefficients (round(k * 65536)) — no FP/SSE */
    const int K_CR_R =  91881;   /*  1.40200 */
    const int K_CB_B = 116130;   /*  1.77200 */
    const int K_CR_G = -46802;   /* -0.714136 */
    const int K_CB_G = -22554;   /* -0.344136 */

    for (int i = 0; i < 256; ++i) {
        int x = i - 128;
        g_Cr_r_tab[i] = (K_CR_R * x) >> 16;  /* add to Y for R */
        g_Cb_b_tab[i] = (K_CB_B * x) >> 16;  /* add to Y for B */
        g_Cr_g_tab[i] = (K_CR_G * x) >> 16;  /* part of G */
        g_Cb_g_tab[i] = (K_CB_G * x) >> 16;  /* part of G */
    }

    g_ycc_tabs_init = true;
}

static bool decode_block(bitreader_t *br, const jpg_t *jpg, comp_t *c, int32_t *block)
{
    for (int i = 0; i < 64; ++i) block[i] = 0;

    const dht_t *HTd = &jpg->HTDC[c->td];
    const dht_t *HTa = &jpg->HTAC[c->ta];
    const uint16_t *Q = jpg->Q[c->tq].q;

    int s = huff_decode_symbol(br, HTd);
    if (s < 0) return false;

    int diff = 0;
    if (s) { int v = (int)br_get(br, s); diff = jsgnextend(v, s); }
    int dc = c->dc_pred + diff; c->dc_pred = dc;
    block[0] = (int32_t)dc * (int32_t)Q[0];

    int k = 1;
    while (k < 64)
    {
        int rs = huff_decode_symbol(br, HTa);
        if (rs < 0) return false;
        int r = (rs >> 4) & 0xF;
        int z = rs & 0xF;

        if (rs == 0x00) break;
        if (rs == 0xF0) { k += 16; continue; }

        k += r; if (k >= 64) return false;
        int vbits = (int)br_get(br, z);
        int coef = jsgnextend(vbits, z);
        /* k is zigzag index; we store at natural index zigzag[k] and use Q at same natural index */
        block[zigzag[k]] = (int32_t)coef * (int32_t)Q[zigzag[k]];
        ++k;
    }
#if JPEG_DEBUG
    ++g_dbg.blocks_decoded;
#endif
    return true;
}


static inline int blocks_x_for(const jpg_t *jpg, int ci) { return jpg->mcus_x * jpg->C[ci].H; }
static inline int blocks_y_for(const jpg_t *jpg, int ci) { return jpg->mcus_y * jpg->C[ci].V; }

/* ========================== Progressive per-block decoders ========================== */

static bool prog_dc_first(bitreader_t *br, const jpg_t *jpg, comp_t *c, int16_t *blk, int Al)
{
    const dht_t *HTd = &jpg->HTDC[c->td];
    int s = huff_decode_symbol(br, HTd);
    if (s < 0) return false;

    int diff = 0;
    if (s) diff = jsgnextend((int)br_get(br, s), s);

    int dc = c->dc_pred + diff; c->dc_pred = dc;
    blk[0] = (int16_t)(dc << Al);
    return true;
}

static bool prog_ac_first(bitreader_t *br, const jpg_t *jpg, const comp_t *c,
                          int16_t *blk, int Ss, int Se, int Al, int *peobrun)
{
    const dht_t *HTa = &jpg->HTAC[c->ta];
    int k = Ss;

    if (*peobrun) { --(*peobrun); return true; }

    while (k <= Se)
    {
        int rs = huff_decode_symbol(br, HTa);
        if (rs < 0) return false;

        int r = (rs >> 4) & 0xF;
        int s =  rs       & 0xF;

        if (s == 0) {
            if (r == 15) { k += 16; continue; }
            int extra = r ? (int)br_get(br, r) : 0;
            *peobrun = ((1 << r) - 1) + extra;
            return true;
        }

        do { if (k > Se) return true; if (r == 0) break; ++k; --r; } while (k <= Se);
        if (k > Se) return true;

        int vbits = (int)br_get(br, s);
        int coef  = jsgnextend(vbits, s);
        blk[zigzag[k]] = (int16_t)(coef << Al);
        ++k;
    }
    return true;
}

static bool prog_ac_refine(bitreader_t *br, const jpg_t *jpg, const comp_t *c,
                           int16_t *blk, int Ss, int Se, int Al, int *peobrun)
{
    const dht_t *HTa = &jpg->HTAC[c->ta];
    int k = Ss, eob = *peobrun;

    if (eob > 0) {
        for (; k <= Se; ++k) {
            int16_t *p = &blk[zigzag[k]];
            if (*p) { int bit = (int)br_get(br, 1); if (bit) *p += (*p > 0) ? (int16_t)(1 << Al) : (int16_t)-(1 << Al); }
        }
        *peobrun = eob - 1;
        return true;
    }

    while (k <= Se)
    {
        int rs = huff_decode_symbol(br, HTa);
        if (rs < 0) return false;

        int r = (rs >> 4) & 0xF;
        int s =  rs       & 0xF;

        if (s == 0) {
            if (r == 15) {
                for (int i = 0; i < 16 && k <= Se; ++i, ++k) {
                    int16_t *p = &blk[zigzag[k]];
                    if (*p) { int bit=(int)br_get(br,1); if (bit) *p += (*p>0)?(int16_t)(1<<Al):(int16_t)-(1<<Al); }
                }
                continue;
            }
            int extra = r ? (int)br_get(br, r) : 0;
            eob = ((1 << r) - 1) + extra;
            for (; k <= Se; ++k) {
                int16_t *p = &blk[zigzag[k]];
                if (*p) { int bit=(int)br_get(br,1); if (bit) *p += (*p>0)?(int16_t)(1<<Al):(int16_t)-(1<<Al); }
            }
            *peobrun = eob;
            return true;
        }

        int zeros_seen = 0;
        for (; k <= Se; ++k) {
            int16_t *p = &blk[zigzag[k]];
            if (*p) { int bit=(int)br_get(br,1); if (bit) *p += (*p>0)?(int16_t)(1<<Al):(int16_t)-(1<<Al); continue; }
            if (zeros_seen == r) break; 
            ++zeros_seen;
        }
        if (k > Se) break;

        int signbit = (int)br_get(br, 1);
        blk[zigzag[k]] = (int16_t)(signbit ? -(1 << Al) : (1 << Al));
        ++k;
    }

    *peobrun = 0;
    return true;
}

/* ========================== Color writeout ========================== */

static void upsample_and_store_RGBA32(const jpg_t *jpg,
                                      const int16_t *P0, const int16_t *P1, const int16_t *P2,
                                      int y0, int x0, video_color_t *dst, int stride_bytes,
                                      bool treat_rgb)
{
    const int W = jpg->width, H = jpg->height;
    const int mH = jpg->mcu_h, mW = jpg->mcu_w;

    if (!treat_rgb) ycc_build_tables();

    /* For first MCU logging */
    int my = y0 / (jpg->mcu_h ? jpg->mcu_h : 1);
    int mx = x0 / (jpg->mcu_w ? jpg->mcu_w : 1);
    bool log_this_mcu =
#if JPEG_DEBUG_FIRST_MCU
        (my == 0 && mx == 0);
#else
        false;
#endif

    for (int y = 0; y < mH; ++y)
    {
        int oy = y0 + y; if (oy >= H) break;
        video_color_t *row = (video_color_t *)((uint8_t *)dst + oy * stride_bytes);

        for (int x = 0; x < mW; ++x)
        {
            int ox = x0 + x; if (ox >= W) break;

            if (treat_rgb)
            {
                int r = u8_saturate(P0[y*mW+x]);
                int g = u8_saturate(P1[y*mW+x]);
                int b = u8_saturate(P2[y*mW+x]);
                row[ox] = pack_rgba32(r,g,b);
            }
            else
            {
                int Yi  = u8_saturate(P0[y*mW+x]);
                int Cbi = P1 ? u8_saturate(P1[y*mW+x]) : 128;
                int Cri = P2 ? u8_saturate(P2[y*mW+x]) : 128;

#if JPEG_DEBUG_SWAP_CBCR
                int tmpCb = Cbi; Cbi = Cri; Cri = tmpCb;
#endif
                /* Simple bilinear smoothing for chroma to reduce blockiness on subsampled images */
                if (!treat_rgb && P1 && P2)
                {
                    int x1 = (x + 1 < mW) ? x + 1 : x;
                    int y1 = (y + 1 < mH) ? y + 1 : y;
                    int idx = y * mW + x;
                    int idxr = y * mW + x1;
                    int idxd = y1 * mW + x;
                    int idxdr= y1 * mW + x1;
                    Cbi = (P1[idx] + P1[idxr] + P1[idxd] + P1[idxdr] + 2) >> 2;
                    Cri = (P2[idx] + P2[idxr] + P2[idxd] + P2[idxdr] + 2) >> 2;
                }
                int r = Yi + g_Cr_r_tab[Cri];
                int g = Yi + (g_Cb_g_tab[Cbi] + g_Cr_g_tab[Cri]);
                int b = Yi + g_Cb_b_tab[Cbi];

#if JPEG_DEBUG_COLOR_CLAMP
                if (r < 0 || r > 255) ++g_dbg.color_r_clamp;
                if (g < 0 || g > 255) ++g_dbg.color_g_clamp;
                if (b < 0 || b > 255) ++g_dbg.color_b_clamp;
#endif

                if (log_this_mcu && ( (y==0 && x==0) || (y==mH-1 && x==mW-1) )) {
                    serial_printf("%s", "jpeg: MCU(");
                    serial_write_dec(mx); serial_printf("%s", ",");
                    serial_write_dec(my); serial_printf("%s", ") px(");
                    serial_write_dec(ox); serial_printf("%s", ",");
                    serial_write_dec(oy); serial_printf("%s", ")  Y=");
                    serial_write_dec(Yi); serial_printf("%s", " Cb=");
                    serial_write_dec(Cbi); serial_printf("%s", " Cr=");
                    serial_write_dec(Cri); serial_printf("%s", " -> r=");
                    serial_write_dec(r); serial_printf("%s", " g=");
                    serial_write_dec(g); serial_printf("%s", " b=");
                    serial_write_dec(b); serial_printf("%s", "\r\n");
                }

                row[ox] = pack_rgba32(r, g, b);
            }
        }
    }
}

/* Decode a sequential scan. Respect SOS scan order. */
static bool decode_scan_sequential(bitreader_t *br, jpg_t *jpg,
                                   video_color_t *dst, int stride_bytes,
                                   int Ns, const int *scan_comp_idx)
{
    const int mW = jpg->mcu_w, mH = jpg->mcu_h;
    int16_t *plane0 = (int16_t *)malloc((size_t)mW * mH * sizeof(int16_t));
    int16_t *plane1 = NULL;
    int16_t *plane2 = NULL;
    bool treat_rgb = jpg->use_rgb;

    if (jpg->comps == 3) {
        plane1 = (int16_t *)malloc((size_t)mW * mH * sizeof(int16_t));
        plane2 = (int16_t *)malloc((size_t)mW * mH * sizeof(int16_t));
        if (!plane0 || !plane1 || !plane2) { free(plane0); free(plane1); free(plane2); return false; }
    } else { if (!plane0) return false; }

    int mcu_countdown = jpg->restart_interval;

    for (int my = 0; my < jpg->mcus_y; ++my)
    {
        for (int mx = 0; mx < jpg->mcus_x; ++mx)
        {
            if (jpg->restart_interval)
            {
                if (mcu_countdown == 0)
                {
                    br_align_byte(br);
                    int mrk = next_marker(br);
                    if (mrk < 0 || (mrk & 0xFFF8) != 0xFFD0)
                    { free(plane0); free(plane1); free(plane2); return false; }
#if JPEG_DEBUG_RESTART
                    ++g_dbg.rst_seen;
#endif
                    for (int i = 0; i < jpg->comps; ++i) jpg->C[i].dc_pred = 0;
                    mcu_countdown = jpg->restart_interval;
                    br->in_scan = true; br->bits_left = 0; br->bit_buf = 0;
                }
                --mcu_countdown;
            }

            memset(plane0, 0, (size_t)mW * mH * sizeof(int16_t));
            if (plane1) memset(plane1, treat_rgb ? 0 : 128, (size_t)mW * mH * sizeof(int16_t));
            if (plane2) memset(plane2, treat_rgb ? 0 : 128, (size_t)mW * mH * sizeof(int16_t));

            /* Iterate components in SOS-provided order */
            for (int si = 0; si < Ns; ++si)
            {
                int ci = scan_comp_idx[si];
                comp_t *c = &jpg->C[ci];

                for (int vy = 0; vy < c->V; ++vy)
                for (int hx = 0; hx < c->H; ++hx)
                {
                    int32_t block[64];
                    if (!decode_block(br, jpg, c, block))
                    { free(plane0); free(plane1); free(plane2); return false; }

                    int16_t deq[64];
                    idct_8x8(block, deq); /* 0..255 */

                    int px = hx * 8 * (jpg->Hmax / c->H);
                    int py = vy * 8 * (jpg->Vmax / c->V);
                    int xstep = (jpg->Hmax / c->H);
                    int ystep = (jpg->Vmax / c->V);

                    int which = 0;
                    if (treat_rgb) {
                        if (ci == jpg->idxR) which = 0;
                        else if (ci == jpg->idxG) which = 1;
                        else if (ci == jpg->idxB) which = 2;
                    } else {
                        if (ci == jpg->idxY) which = 0;
                        else if (ci == jpg->idxCb) which = 1;
                        else if (ci == jpg->idxCr) which = 2;
                    }

                    for (int y = 0; y < 8; ++y)
                    for (int x = 0; x < 8; ++x)
                    {
                        int16_t v = deq[y*8 + x];
                        for (int uy = 0; uy < ystep; ++uy)
                        for (int ux = 0; ux < xstep; ++ux)
                        {
                            int dstx = px + x * xstep + ux;
                            int dsty = py + y * ystep + uy;
                            int idx  = dsty * mW + dstx;
                            if      (which == 0) plane0[idx] = v;
                            else if (which == 1) plane1[idx] = v;
                            else if (which == 2) plane2[idx] = v;
                        }
                    }
                }
            }

            upsample_and_store_RGBA32(jpg, plane0, plane1, plane2,
                                      my * jpg->mcu_h, mx * jpg->mcu_w,
                                      dst, stride_bytes, treat_rgb);
        }
    }

    free(plane0); free(plane1); free(plane2);
    return true;
}

/* ========================== Progressive scan driver ========================== */

static inline int16_t *coef_blk_ptr(jpg_t *jpg, int ci, int bx, int by)
{
    int bxmax = blocks_x_for(jpg, ci);
    size_t idx = ((size_t)by * (size_t)bxmax + (size_t)bx) * 64u;
    return &jpg->coef[ci][idx];
}

static bool decode_progressive_scan(bitreader_t *br, jpg_t *jpg,
                                    int Ns, const int *scan_comp_idx,
                                    int Ss, int Se, int Ah, int Al)
{
    int eobrun = 0;

    if (Ns == 1)
    {
        const int ci = scan_comp_idx[0];
        comp_t *c = &jpg->C[ci];

        const int bxmax = blocks_x_for(jpg, ci);
        const int bymax = blocks_y_for(jpg, ci);

        int rst_countdown = jpg->restart_interval;

        for (int by = 0; by < bymax; ++by)
        {
            for (int bx = 0; bx < bxmax; ++bx)
            {
                if (jpg->restart_interval)
                {
                    if (rst_countdown == 0)
                    {
                        br_align_byte(br);
                        int mrk = next_marker(br);
                        if (mrk < 0 || (mrk & 0xFFF8) != 0xFFD0) return false;
#if JPEG_DEBUG_RESTART
                        ++g_dbg.rst_seen;
#endif
                        for (int i = 0; i < jpg->comps; ++i) jpg->C[i].dc_pred = 0;
                        eobrun = 0;
                        rst_countdown = jpg->restart_interval;
                        br->in_scan = true; br->bits_left = 0; br->bit_buf = 0;
                    }
                    --rst_countdown;
                }

                int16_t *blk = coef_blk_ptr(jpg, ci, bx, by);
                bool ok = true;

                if (Ss == 0 && Se == 0)
                {
                    if (Ah == 0) ok = prog_dc_first(br, jpg, c, blk, Al);
                    else {
                        int bit = (int)br_get(br, 1);
                        if (bit) blk[0] += (blk[0] >= 0) ? (int16_t)(1 << Al) : (int16_t)-(1 << Al);
                    }
                }
                else
                {
                    if (Ah == 0) ok = prog_ac_first(br, jpg, c, blk, Ss, Se, Al, &eobrun);
                    else         ok = prog_ac_refine(br, jpg, c, blk, Ss, Se, Al, &eobrun);
                }

                if (!ok) return false;
            }
        }
    }
    else
    {
        const int imcu_x = jpg->mcus_x, imcu_y = jpg->mcus_y;
        int rst_countdown = jpg->restart_interval;

        for (int imy = 0; imy < imcu_y; ++imy)
        {
            for (int imx = 0; imx < imcu_x; ++imx)
            {
                if (jpg->restart_interval)
                {
                    if (rst_countdown == 0)
                    {
                        br_align_byte(br);
                        int mrk = next_marker(br);
                        if (mrk < 0 || (mrk & 0xFFF8) != 0xFFD0) return false;
#if JPEG_DEBUG_RESTART
                        ++g_dbg.rst_seen;
#endif
                        for (int i = 0; i < jpg->comps; ++i) jpg->C[i].dc_pred = 0;
                        eobrun = 0;
                        rst_countdown = jpg->restart_interval;
                        br->in_scan = true; br->bits_left = 0; br->bit_buf = 0;
                    }
                    --rst_countdown;
                }

                for (int si = 0; si < Ns; ++si)
                {
                    int ci = scan_comp_idx[si];
                    comp_t *c = &jpg->C[ci];

                    for (int vy = 0; vy < c->V; ++vy)
                    for (int hx = 0; hx < c->H; ++hx)
                    {
                        int bx = imx * c->H + hx;
                        int by = imy * c->V + vy;
                        int16_t *blk = coef_blk_ptr(jpg, ci, bx, by);

                        bool ok = true;
                        if (Ss == 0 && Se == 0)
                        {
                            if (Ah == 0) ok = prog_dc_first(br, jpg, c, blk, Al);
                            else {
                                int bit = (int)br_get(br, 1);
                                if (bit) blk[0] += (blk[0] >= 0) ? (int16_t)(1 << Al) : (int16_t)-(1 << Al);
                            }
                        }
                        else
                        {
                            if (Ah == 0) ok = prog_ac_first(br, jpg, c, blk, Ss, Se, Al, &eobrun);
                            else         ok = prog_ac_refine(br, jpg, c, blk, Ss, Se, Al, &eobrun);
                        }

                        if (!ok) return false;
                    }
                }
            }
        }
    }

    return true;
}

/* After all progressive scans, convert coef planes → RGBA32 */
static bool progressive_output_to_rgba32(const jpg_t *jpg, video_color_t *dst, int stride_bytes)
{
    const int mW = jpg->mcu_w, mH = jpg->mcu_h;
    int16_t *plane0  = (int16_t *)malloc((size_t)mW * mH * sizeof(int16_t));
    int16_t *plane1  = NULL;
    int16_t *plane2  = NULL;
    bool treat_rgb = jpg->use_rgb;

    if (jpg->comps == 3) {
        plane1 = (int16_t *)malloc((size_t)mW * mH * sizeof(int16_t));
        plane2 = (int16_t *)malloc((size_t)mW * mH * sizeof(int16_t));
        if (!plane0 || !plane1 || !plane2) { free(plane0); free(plane1); free(plane2); return false; }
    } else { if (!plane0) return false; }

    for (int my = 0; my < jpg->mcus_y; ++my)
    {
        for (int mx = 0; mx < jpg->mcus_x; ++mx)
        {
            memset(plane0, 0, (size_t)mW * mH * sizeof(int16_t));
            if (plane1) memset(plane1, treat_rgb ? 0 : 128, (size_t)mW * mH * sizeof(int16_t));
            if (plane2) memset(plane2, treat_rgb ? 0 : 128, (size_t)mW * mH * sizeof(int16_t));

            for (int ci = 0; ci < jpg->comps; ++ci)
            {
                const comp_t *c = &jpg->C[ci];
                const uint16_t *Q = jpg->Q[c->tq].q;

                for (int vy = 0; vy < c->V; ++vy)
                for (int hx = 0; hx < c->H; ++hx)
                {
                    int bx = mx * c->H + hx;
                    int by = my * c->V + vy;

                    int16_t *blkq = coef_blk_ptr((jpg_t*)jpg, ci, bx, by);
                    int32_t deq_in[64];
                    for (int k = 0; k < 64; ++k) deq_in[k] = (int32_t)blkq[k] * (int32_t)Q[k];

                    int16_t deq[64];
                    idct_8x8(deq_in, deq); /* 0..255 */

                    int px = hx * 8 * (jpg->Hmax / c->H);
                    int py = vy * 8 * (jpg->Vmax / c->V);
                    int xstep = (jpg->Hmax / c->H);
                    int ystep = (jpg->Vmax / c->V);

                    int which = 0;
                    if (treat_rgb) {
                        if (ci == jpg->idxR) which = 0;
                        else if (ci == jpg->idxG) which = 1;
                        else if (ci == jpg->idxB) which = 2;
                    } else {
                        if (ci == jpg->idxY) which = 0;
                        else if (ci == jpg->idxCb) which = 1;
                        else if (ci == jpg->idxCr) which = 2;
                    }

                    for (int y = 0; y < 8; ++y)
                    for (int x = 0; x < 8; ++x)
                    {
                        int16_t v = deq[y*8 + x];
                        for (int uy = 0; uy < ystep; ++uy)
                        for (int ux = 0; ux < xstep; ++ux)
                        {
                            int dstx = px + x * xstep + ux;
                            int dsty = py + y * ystep + uy;
                            int idx  = dsty * mW + dstx;
                            if      (which == 0) plane0[idx] = v;
                            else if (which == 1) plane1[idx] = v;
                            else if (which == 2) plane2[idx] = v;
                        }
                    }
                }
            }

            upsample_and_store_RGBA32(jpg, plane0, plane1, plane2,
                                      my * jpg->mcu_h, mx * jpg->mcu_w,
                                      dst, stride_bytes, treat_rgb);
        }
    }

    free(plane0); free(plane1); free(plane2);
    return true;
}

/* ========================== Public entry ========================== */

int jpeg_decode_rgba32(const uint8_t *jpeg, size_t len,
                       video_color_t **out_pixels, int *out_w, int *out_h, int *out_stride_bytes)
{
    if (!jpeg || len < 4 || !out_pixels || !out_w || !out_h || !out_stride_bytes)
    { jpeg_set_error("invalid arguments"); return -1; }
    *out_pixels = NULL; *out_w = 0; *out_h = 0; *out_stride_bytes = 0;

    bitreader_t br; br_init(&br, jpeg, len);
    jpg_t jpg; memset(&jpg, 0, sizeof(jpg));
    jpg.color_transform = -1;
    jpg.adobe_transform_present = false;
    jpg.progressive = false;
    for (int i = 0; i < MAX_COMP; ++i) jpg.coef[i] = NULL;

    /* Expect SOI */
    int mrk = next_marker(&br);
    if (mrk != 0xFFD8) { jpeg_set_error("missing SOI"); return -2; }

    bool have_SOF = false;
    video_color_t *pixels = NULL;
    int stride_bytes = 0;

    for (;;)
    {
        mrk = next_marker(&br);
        if (mrk < 0) { jpeg_set_error("marker read failed"); goto fail; }

        switch (mrk)
        {
        case 0xFFE0: case 0xFFE1: case 0xFFE2: case 0xFFE3:
        case 0xFFE4: case 0xFFE5: case 0xFFE6: case 0xFFE7:
        case 0xFFE8: case 0xFFE9: case 0xFFEA: case 0xFFEB:
        case 0xFFEC: case 0xFFED:
        case 0xFFEE: /* APP14 (Adobe) */
        case 0xFFEF:
        case 0xFFFE:
        {
            uint16_t L = read_be16(&br);
            if (L < 2) { jpeg_set_error("bad APP/COM length"); goto fail; }

            if (mrk == 0xFFEE && L >= 14)
            {
                uint8_t header[12];
                if (!read_bytes(&br, header, sizeof(header))) { jpeg_set_error("APP14 read failed"); goto fail; }
                if (memcmp(header, "Adobe", 5) == 0)
                {
                    jpg.color_transform = header[11];
                    jpg.adobe_transform_present = true;
#if JPEG_DEBUG_MARKERS
                    serial_printf("%s", "jpeg: APP14 transform=0x");
                    serial_printf("%016llX", (unsigned long long)((uint64_t)(uint32_t)jpg.color_transform));
                    serial_printf("%s", "\r\n");
#endif
                }
                size_t remain = (size_t)L - 2 - sizeof(header);
                if (remain > 0 && !skip_bytes(&br, remain)) { jpeg_set_error("APP14 skip failed"); goto fail; }
            }
            else
            {
                size_t remain = (size_t)L - 2;
                if (remain > 0 && !skip_bytes(&br, remain)) { jpeg_set_error("APP/COM skip failed"); goto fail; }
            }
            break;
        }

        case 0xFFDB: if (!parse_DQT(&br, &jpg)) { jpeg_set_error("parse DQT failed"); goto fail; } break;
        case 0xFFC4: if (!parse_DHT(&br, &jpg)) { jpeg_set_error("parse DHT failed"); goto fail; } break;
        case 0xFFDD: if (!parse_DRI(&br, &jpg)) { jpeg_set_error("parse DRI failed"); goto fail; } break;

        case 0xFFC0: /* SOF0 */
        case 0xFFC1: /* SOF1 */
            if (!parse_SOF_common(&br, &jpg)) { jpeg_set_error("parse SOF failed"); goto fail; }
            jpg.progressive = false;
            have_SOF = true;
            resolve_component_mapping(&jpg);
            break;

        case 0xFFC2: /* SOF2 progressive */
            if (!parse_SOF_common(&br, &jpg)) { jpeg_set_error("parse SOF2 failed"); goto fail; }
            jpg.progressive = true;
            have_SOF = true;
            resolve_component_mapping(&jpg);

            for (int ci = 0; ci < jpg.comps; ++ci)
            {
                int bx = blocks_x_for(&jpg, ci);
                int by = blocks_y_for(&jpg, ci);
                size_t count = (size_t)bx * (size_t)by * 64u;
                jpg.coef[ci] = (int16_t*)calloc(count, sizeof(int16_t));
                if (!jpg.coef[ci]) { jpeg_set_error("coeff alloc failed"); goto fail; }
            }
            break;

        case 0xFFDA: /* SOS */
        {
            if (!have_SOF) { jpeg_set_error("SOS before SOF"); goto fail; }

            int Ns, Ss, Se, Ah, Al;
            int scan_comp_idx[MAX_COMP];

            if (!read_scan_header(&br, &jpg, &Ns, scan_comp_idx, &Ss, &Se, &Ah, &Al))
            { jpeg_set_error("parse SOS failed"); goto fail; }

            br.in_scan   = true;
            br.bits_left = 0;
            br.bit_buf   = 0;

            if (jpg.progressive)
            {
                if (!decode_progressive_scan(&br, &jpg, Ns, scan_comp_idx, Ss, Se, Ah, Al))
                { jpeg_set_error("progressive scan decode failed"); goto fail; }
            }
            else
            {
                if (!pixels)
                {
                    stride_bytes = jpg.width * (int)sizeof(video_color_t);
                    pixels = (video_color_t *)malloc((size_t)jpg.height * stride_bytes);
                    if (!pixels) { jpeg_set_error("pixel alloc failed"); goto fail; }
                    memset(pixels, 0, (size_t)jpg.height * stride_bytes);
                }
                if (!decode_scan_sequential(&br, &jpg, pixels, stride_bytes, Ns, scan_comp_idx))
                { jpeg_set_error("sequential scan decode failed"); goto fail; }
            }

            br_align_byte(&br);
            break;
        }

        case 0xFFD9: /* EOI */
            if (jpg.progressive)
            {
                stride_bytes = jpg.width * (int)sizeof(video_color_t);
                pixels = (video_color_t *)malloc((size_t)jpg.height * stride_bytes);
                if (!pixels) { jpeg_set_error("pixel alloc failed"); goto fail; }
                memset(pixels, 0, (size_t)jpg.height * stride_bytes);

                if (!progressive_output_to_rgba32(&jpg, pixels, stride_bytes))
                { jpeg_set_error("progressive output failed"); goto fail; }
            }

            *out_pixels = pixels;
            *out_w = jpg.width;
            *out_h = jpg.height;
            *out_stride_bytes = stride_bytes;
            jpeg_set_error("ok");

#if JPEG_DEBUG
            serial_printf("%s", "jpeg: SUMMARY ");
            jpeg_dbg_kv("blocks", (int)g_dbg.blocks_decoded);
            jpeg_dbg_kv("idct_clamps", (int)g_dbg.idct_clamp);
            jpeg_dbg_kv("r_clamps", (int)g_dbg.color_r_clamp);
            jpeg_dbg_kv("g_clamps", (int)g_dbg.color_g_clamp);
            jpeg_dbg_kv("b_clamps", (int)g_dbg.color_b_clamp);
            jpeg_dbg_kv("rst", (int)g_dbg.rst_seen);
            serial_printf("%s", "\r\n");
#endif

            for (int ci = 0; ci < jpg.comps; ++ci) { free(jpg.coef[ci]); jpg.coef[ci] = NULL; }
            return 0;

        default:
            if ((mrk & 0xFFF0) == 0xFFD0) {
#if JPEG_DEBUG_RESTART
                ++g_dbg.rst_seen;
#endif
                break; /* stray RST safe to ignore */
            }
            {
                uint16_t L = read_be16(&br);
                if (L < 2 || !skip_bytes(&br, L - 2))
                { jpeg_set_error("bad optional marker"); goto fail; }
            }
            break;
        }
    }

fail:
    for (int ci = 0; ci < MAX_COMP; ++ci) { free(jpg.coef[ci]); jpg.coef[ci] = NULL; }
    free(pixels);
    return -17;
}
