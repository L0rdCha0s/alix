/*
 * jpeg_baseline_decoder.c — tiny baseline (SOF0) JPEG → RGB24 decoder
 *
 * Features
 *  - Baseline DCT (8-bit samples), Huffman entropy coding (no arithmetic)
 *  - Up to 3 components (grayscale or YCbCr)
 *  - Subsampling 4:4:4, 4:2:2, 4:2:0 (H,V ≤ 2)
 *  - DQT, DHT, SOF0, SOS, DRI; skips APPx/COM/unknown markers
 *  - Integer AAN-style IDCT (no floating point)
 *  - Outputs tightly-packed RGB24 buffer (stride = 3*width)
 *
 * Not supported
 *  - Progressive JPEG (SOF2), lossless, arithmetic coding, fancy color spaces
 *  - Subsampling factors > 2, CMYK, unusual marker permutations
 *
 * API
 *   int jpeg_decode_rgb24(const uint8_t *jpeg, size_t len,
 *                         uint8_t **out_pixels, int *out_w, int *out_h, int *out_stride);
 *     On success returns 0 and allocates *out_pixels with malloc(); caller must free().
 *     On error returns negative code; *out_pixels is left NULL.
 *
 * This file is self-contained except it expects the following libc-like functions:
 *   - void *malloc(size_t), void *calloc(size_t,size_t), void free(void*),
 *   - void *memset(void*,int,size_t), void *memcpy(void*, const void*, size_t)
 *
 * The decoder is written for freestanding OS kernels. No stdio/FILE is used.
 */

#include "types.h"
#include "heap.h"
#include "libc.h"

/* --- Minimal libc fallbacks (optional; replace with your libc if present) --- */
#ifndef JPEG_DECODER_HAS_LIBC
#define JPEG_DECODER_HAS_LIBC 1
#endif

/* ========================== Bitstream ========================== */

typedef struct
{
    const uint8_t *data;
    size_t size;
    size_t byte_pos;  /* next byte index in data */
    uint32_t bit_buf; /* left-aligned bit buffer */
    int bits_left;    /* number of bits currently in bit_buf */
    bool in_scan;     /* when true, honor 0xFF00 byte stuffing */
    int last_marker;  /* if we encountered a marker while refilling */
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

/* Refill bit buffer with up to 16 bits. Handle 0xFF 0x00 stuffing inside scans, and detect markers. */
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
            /* could be stuffed 0x00 or a marker (RSTn/EOI/etc.) */
            int n = br_read_u8(br);
            if (n < 0)
            {
                br->last_marker = 0xFF;
                return br->bits_left > 0;
            }
            if (n != 0x00)
            {
                /* Real marker; expose to caller and step back one byte so marker can be re-read at segment level */
                br->last_marker = 0xFF00 | n;
                /* We consumed the 0xFF and marker byte already. To let segment reader see it, back up two bytes. */
                if (br->byte_pos >= 2)
                    br->byte_pos -= 2;
                else
                    br->byte_pos = 0;
                return br->bits_left > 0; /* don't push marker into bit_buf */
            }
            /* stuffed zero → literal 0xFF */
            b = 0xFF;
        }
        br->bit_buf = (br->bit_buf << 8) | (uint32_t)b;
        br->bits_left += 8;
    }
    return true;
}

static uint32_t br_peek(bitreader_t *br, int n)
{
    if (br->bits_left < n)
        br_refill(br);
    return (br->bit_buf >> (br->bits_left - n)) & ((1u << n) - 1);
}

static void br_drop(bitreader_t *br, int n)
{
    if (n <= 0)
        return;
    br->bits_left -= n;
    if (br->bits_left < 0)
        br->bits_left = 0;
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
    if (r)
        br_drop(br, r);
}

/* ========================== JPEG structures ========================== */

#define MAX_QUANT 4
#define MAX_HUFF 4
#define MAX_COMP 3

typedef struct
{
    uint16_t q[64];
    bool present;
} dqt_t;

typedef struct
{
    /* canonical Huffman table representation */
    uint8_t counts[16];   /* number of codes with length i+1 */
    uint8_t symbols[256]; /* symbol values in order */
    /* derived fast decode table */
    uint16_t fast[1 << 8]; /* fast lookup: upper bits: symbol (8 bits), lower: code len (8 bits); 0xFFFF=slow */
    /* for slow path */
    uint16_t codes[256]; /* canonical codes */
    uint8_t sizes[256];  /* code lengths */
    int num_symbols;
    bool present;
} dht_t;

typedef struct
{
    uint8_t id;   /* component id from SOF */
    uint8_t H, V; /* sampling factors */
    uint8_t tq;   /* quant table index */
    /* scan-time fields */
    uint8_t td, ta; /* DC/AC Huffman table selectors from SOS */
    int dc_pred;    /* DC predictor for this component */
} comp_t;

typedef struct
{
    int width, height;
    int mcu_w, mcu_h; /* MCU size in pixels: 8*Hmax, 8*Vmax */
    int mcus_x, mcus_y;
    int comps; /* 1 or 3 */
    int Hmax, Vmax;
    comp_t C[MAX_COMP];
    dqt_t Q[MAX_QUANT];
    dht_t HTDC[MAX_HUFF];
    dht_t HTAC[MAX_HUFF];
    int restart_interval; /* MCUs between RST markers; 0 = none */
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

static inline uint16_t pack_rgb565(int r, int g, int b)
{
    r = clampi(r, 0, 255);
    g = clampi(g, 0, 255);
    b = clampi(b, 0, 255);
    return (uint16_t)(((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3));
}

/* sign-extend value of n-bit "v" as per JPEG spec */
static inline int16_t jsgnextend(int v, int n)
{
    int16_t vt = (int16_t)v;
    if (n == 0)
        return 0;
    int16_t lim = (int16_t)(1u << (n - 1));
    if (vt < lim)
        vt = (int16_t)(vt - (1 << n) + 1);
    return vt;
}

/* ========================== Huffman ========================== */

static void dht_build(dht_t *h)
{
    /* derive canonical codes */
    int code = 0;
    int si = 1;
    int k = 0;
    h->num_symbols = 0;
    for (int i = 0; i < 16; ++i)
    {
        for (int j = 0; j < h->counts[i]; ++j)
        {
            h->codes[k] = (uint16_t)code;
            h->sizes[k] = (uint8_t)si;
            ++code;
            ++k;
            ++h->num_symbols;
        }
        code <<= 1;
        ++si;
    }
    /* build fast table (8-bit) */
    for (int i = 0; i < 256; ++i)
        h->fast[i] = 0xFFFF;
    int idx = 0;
    for (int len = 1; len <= 8; ++len)
    {
        for (int j = 0; j < h->counts[len - 1]; ++j, ++idx)
        {
            int sym = h->symbols[idx];
            int bits = h->codes[idx] << (8 - len);
            int reps = 1 << (8 - len);
            for (int r = 0; r < reps; ++r)
            {
                h->fast[bits | r] = (uint16_t)((sym << 8) | len);
            }
        }
    }
}

static int huff_decode_symbol(bitreader_t *br, const dht_t *h)
{
    /* try fast path */
    if (br->bits_left < 8)
        br_refill(br);
    if (br->bits_left >= 8)
    {
        uint16_t e = h->fast[(br->bit_buf >> (br->bits_left - 8)) & 0xFF];
        if (e != 0xFFFF)
        {
            br_drop(br, e & 0xFF);
            return (e >> 8) & 0xFF;
        }
    }
    /* slow path */
    int code = 0;
    for (int len = 1; len <= 16; ++len)
    {
        code = (code << 1) | br_get(br, 1);
        int idx = 0;
        int sum = 0;
        for (int i = 0; i < len - 1; ++i)
            sum += h->counts[i];
        int cnt = h->counts[len - 1];
        for (int j = 0; j < cnt; ++j)
        {
            int k = sum + j;
            if (h->sizes[k] == len && h->codes[k] == code)
                return h->symbols[k];
        }
    }
    return -1; /* invalid */
}

/* ========================== IDCT (AAN integer) ========================== */

#define FIX(x) ((int32_t)((x) * 16384 + 0.5))
#define DESCALE(x, n) ((int32_t)((x) + (1 << ((n) - 1))) >> (n))

/* constants */
static const int32_t C0_541196100 = FIX(0.541196100); /* sqrt(2)*cos(3pi/8) */
static const int32_t C0_765366865 = FIX(0.765366865); /* sqrt(2)*cos(pi/8)  */
static const int32_t C1_175875602 = FIX(1.175875602); /* sqrt(2)*cos(pi/16) */
static const int32_t C1_501321110 = FIX(1.501321110); /* sqrt(2)*cos(3pi/16)*/
static const int32_t C1_847759065 = FIX(1.847759065); /* sqrt(2)*cos(5pi/16)*/
static const int32_t C1_961570560 = FIX(1.961570560); /* sqrt(2)*cos(7pi/16)*/
static const int32_t C0_390180644 = FIX(0.390180644);
static const int32_t C2_053119869 = FIX(2.053119869);
static const int32_t C3_072711026 = FIX(3.072711026);
static const int32_t C2_562915447 = FIX(2.562915447);
static const int32_t C0_298631336 = FIX(0.298631336);
static const int32_t C0_899976223 = FIX(0.899976223);

static void idct_1d(int32_t *d)
{
    /* Port of AAN 1-D IDCT; input scaled by quant, outputs roughly << 13 */
    int32_t x0 = (d[0] << 13);
    int32_t x1 = (d[4] << 13);
    int32_t x2 = d[2];
    int32_t x3 = d[6];
    int32_t x4 = d[1];
    int32_t x5 = d[7];
    int32_t x6 = d[5];
    int32_t x7 = d[3];

    int32_t x8;

    if ((x2 | x3 | x4 | x5 | x6 | x7) == 0)
    {
        int32_t dc = DESCALE(x0 + x1, 13);
        d[0] = d[1] = d[2] = d[3] = d[4] = d[5] = d[6] = d[7] = dc;
        return;
    }

    x8 = C0_541196100 * (x2 + x3);
    x2 = x8 + (C0_765366865 - C0_541196100) * x2;
    x3 = x8 - (C0_765366865 + C0_541196100) * x3;

    x8 = x0 + x1;
    x0 -= x1;
    x1 = C1_175875602 * (x4 + x5);
    x4 = x1 + (-C1_961570560 + C1_175875602) * x4;
    x5 = x1 + (-C0_390180644 - C1_175875602) * x5;
    x1 = C1_501321110 * (x6 + x7);
    x6 = x1 + (-C1_847759065 + C1_501321110) * x6;
    x7 = x1 + (-C0_899976223 - C1_501321110) * x7;

    int32_t t0 = x8 + x2;
    int32_t t3 = x8 - x2;
    int32_t t1 = x0 + x3;
    int32_t t2 = x0 - x3;

    int32_t t4 = x4 + x6;
    int32_t t7 = x4 - x6;
    int32_t t5 = x5 + x7;
    int32_t t6 = x5 - x7;

    d[0] = DESCALE(t0 + t4, 13);
    d[7] = DESCALE(t0 - t4, 13);
    d[1] = DESCALE(t1 + t5, 13);
    d[6] = DESCALE(t1 - t5, 13);
    d[2] = DESCALE(t2 + t6, 13);
    d[5] = DESCALE(t2 - t6, 13);
    d[3] = DESCALE(t3 + t7, 13);
    d[4] = DESCALE(t3 - t7, 13);
}

static void idct_8x8(const int16_t *in, int16_t *out)
{
    int32_t tmp[64];
    for (int i = 0; i < 8; ++i)
    {
        for (int j = 0; j < 8; ++j)
            tmp[i * 8 + j] = in[i * 8 + j];
        idct_1d(&tmp[i * 8]);
    }
    for (int j = 0; j < 8; ++j)
    {
        int32_t col[8];
        for (int i = 0; i < 8; ++i)
            col[i] = tmp[i * 8 + j];
        idct_1d(col);
        for (int i = 0; i < 8; ++i)
        {
            int32_t v = col[i] + 128; /* level shift */
            if (v < -256)
                v = -256;
            else if (v > 511)
                v = 511;
            out[i * 8 + j] = (int16_t)v;
        }
    }
}

/* ========================== Parsing helpers ========================== */

static uint16_t read_be16(bitreader_t *br)
{
    int a = br_read_u8(br);
    int b = br_read_u8(br);
    if (a < 0 || b < 0)
        return 0;
    return (uint16_t)((a << 8) | b);
}

static bool skip_bytes(bitreader_t *br, size_t n)
{
    if (br->byte_pos + n > br->size)
        return false;
    br->byte_pos += n;
    return true;
}

static int next_marker(bitreader_t *br)
{
    int c;
    do
    {
        c = br_read_u8(br);
        if (c < 0)
            return -1;
    } while (c != 0xFF);
    do
    {
        c = br_read_u8(br);
        if (c < 0)
            return -1;
    } while (c == 0xFF);
    return 0xFF00 | c;
}

/* ========================== Segment parsers ========================== */

static bool parse_DQT(bitreader_t *br, jpg_t *jpg)
{
    uint16_t L = read_be16(br);
    if (L < 2)
        return false;
    size_t remaining = L - 2;
    while (remaining > 0)
    {
        int pq_tq = br_read_u8(br);
        if (pq_tq < 0)
            return false;
        --remaining;
        int pq = (pq_tq >> 4) & 0xF;
        int tq = pq_tq & 0xF;
        if (tq >= MAX_QUANT)
            return false;
        if (pq != 0)
            return false; /* only 8-bit tables supported */
        if (remaining < 64)
            return false;
        for (int i = 0; i < 64; ++i)
        {
            int v = br_read_u8(br);
            if (v < 0)
                return false;
            jpg->Q[tq].q[zigzag[i]] = (uint16_t)v;
        }
        jpg->Q[tq].present = true;
        remaining -= 64;
    }
    return true;
}

static bool parse_DHT(bitreader_t *br, jpg_t *jpg)
{
    uint16_t L = read_be16(br);
    if (L < 2)
        return false;
    size_t rem = L - 2;
    while (rem > 0)
    {
        int tc_th = br_read_u8(br);
        if (tc_th < 0)
            return false;
        --rem;
        int tc = (tc_th >> 4) & 0xF;
        int th = tc_th & 0xF;
        if (th >= MAX_HUFF)
            return false;
        dht_t *H = (tc == 0) ? &jpg->HTDC[th] : &jpg->HTAC[th];
        int total = 0;
        for (int i = 0; i < 16; ++i)
        {
            int c = br_read_u8(br);
            if (c < 0)
                return false;
            H->counts[i] = (uint8_t)c;
            total += c;
        }
        rem -= 1 + 16;
        if (total > 256 || rem < (size_t)total)
            return false;
        for (int i = 0; i < total; ++i)
        {
            int s = br_read_u8(br);
            if (s < 0)
                return false;
            H->symbols[i] = (uint8_t)s;
        }
        rem -= total;
        H->present = true;
        dht_build(H);
    }
    return true;
}

static bool parse_SOF0(bitreader_t *br, jpg_t *jpg)
{
    uint16_t L = read_be16(br);
    if (L < 2)
        return false;
    int P = br_read_u8(br);
    int Y = read_be16(br);
    int X = read_be16(br);
    int N = br_read_u8(br);
    if (P != 8 || X <= 0 || Y <= 0 || N <= 0 || N > MAX_COMP)
        return false;
    jpg->width = X;
    jpg->height = Y;
    jpg->comps = N;
    jpg->Hmax = jpg->Vmax = 1;
    for (int i = 0; i < N; ++i)
    {
        int C = br_read_u8(br);
        int HV = br_read_u8(br);
        int Tq = br_read_u8(br);
        if (C < 0 || HV < 0 || Tq < 0)
            return false;
        jpg->C[i].id = (uint8_t)C;
        jpg->C[i].H = (HV >> 4) & 0xF;
        jpg->C[i].V = HV & 0xF;
        jpg->C[i].tq = (uint8_t)(Tq & 0xF);
        if (jpg->C[i].H < 1 || jpg->C[i].H > 2 || jpg->C[i].V < 1 || jpg->C[i].V > 2)
            return false; /* limit factors */
        if (jpg->C[i].H > jpg->Hmax)
            jpg->Hmax = jpg->C[i].H;
        if (jpg->C[i].V > jpg->Vmax)
            jpg->Vmax = jpg->C[i].V;
    }
    jpg->mcu_w = 8 * jpg->Hmax;
    jpg->mcu_h = 8 * jpg->Vmax;
    jpg->mcus_x = (jpg->width + jpg->mcu_w - 1) / jpg->mcu_w;
    jpg->mcus_y = (jpg->height + jpg->mcu_h - 1) / jpg->mcu_h;
    (void)L;
    return true;
}

static bool parse_DRI(bitreader_t *br, jpg_t *jpg)
{
    uint16_t L = read_be16(br);
    if (L != 4)
        return false;
    jpg->restart_interval = read_be16(br);
    return true;
}

static bool parse_SOS(bitreader_t *br, jpg_t *jpg)
{
    uint16_t L = read_be16(br);
    if (L < 2)
        return false;
    int Ns = br_read_u8(br);
    if (Ns != jpg->comps)
        return false; /* only interleaved scans for simplicity */
    for (int i = 0; i < Ns; ++i)
    {
        int Cs = br_read_u8(br);
        int Tda = br_read_u8(br);
        if (Cs < 0 || Tda < 0)
            return false;
        /* map Cs to component index i (assumes order matches SOF0) */
        int idx = -1;
        for (int k = 0; k < jpg->comps; ++k)
            if (jpg->C[k].id == Cs)
            {
                idx = k;
                break;
            }
        if (idx < 0)
            return false;
        jpg->C[idx].td = (Tda >> 4) & 0xF;
        jpg->C[idx].ta = Tda & 0xF;
    }
    /* skip Ss, Se, AhAl */
    (void)br_read_u8(br);
    (void)br_read_u8(br);
    (void)br_read_u8(br);
    (void)L;
    return true;
}

/* ========================== MCU decoding ========================== */

static bool decode_block(bitreader_t *br, const jpg_t *jpg, comp_t *c,
                         int16_t *block)
{
    /* Zero block */
    for (int i = 0; i < 64; ++i)
        block[i] = 0;

    const dht_t *HTd = &jpg->HTDC[c->td];
    const dht_t *HTa = &jpg->HTAC[c->ta];
    const uint16_t *Q = jpg->Q[c->tq].q;

    /* DC */
    int s = huff_decode_symbol(br, HTd);
    if (s < 0)
        return false;
    int diff = 0;
    if (s)
    {
        int v = br_get(br, s);
        diff = jsgnextend(v, s);
    }
    int dc = c->dc_pred + diff;
    c->dc_pred = dc;
    block[0] = (int16_t)(dc * Q[0]);

    /* AC */
    int k = 1;
    while (k < 64)
    {
        int rs = huff_decode_symbol(br, HTa);
        if (rs < 0)
            return false;
        int r = (rs >> 4) & 0xF;
        int z = rs & 0xF;
        if (rs == 0x00)
        { /* EOB */
            break;
        }
        if (rs == 0xF0)
        { /* ZRL */
            k += 16;
            continue;
        }
        k += r;
        if (k >= 64)
            return false;
        int vbits = br_get(br, z);
        int coef = jsgnextend(vbits, z);
        block[zigzag[k]] = (int16_t)(coef * Q[zigzag[k]]);
        ++k;
    }
    return true;
}

static void upsample_and_store_RGB565(const jpg_t *jpg,
                                      const int16_t *Y, const int16_t *Cb, const int16_t *Cr,
                                      int y0, int x0, uint16_t *dst, int stride_bytes)
{
    const int W = jpg->width, H = jpg->height;
    const int mH = jpg->mcu_h, mW = jpg->mcu_w;
    for (int y = 0; y < mH; ++y)
    {
        int oy = y0 + y;
        if (oy >= H)
            break;
        uint16_t *row = (uint16_t *)((uint8_t *)dst + oy * stride_bytes);
        for (int x = 0; x < mW; ++x)
        {
            int ox = x0 + x;
            if (ox >= W)
                break;
            int Yi = Y[y * mW + x];
            int Cbi = Cb ? Cb[y * mW + x] : 128;
            int Cri = Cr ? Cr[y * mW + x] : 128;
            int r = Yi + ((91881 * (Cri - 128)) >> 16);
            int g = Yi - ((22554 * (Cbi - 128) + 46802 * (Cri - 128)) >> 16);
            int b = Yi + ((116130 * (Cbi - 128)) >> 16);
            row[ox] = pack_rgb565(r, g, b);
        }
    }
}

static bool decode_scan(bitreader_t *br, jpg_t *jpg, uint16_t *dst, int stride_bytes)
{
    /* Prepare per-MCU buffers at full MCU resolution */
    const int mW = jpg->mcu_w, mH = jpg->mcu_h;
    int16_t *planeY = (int16_t *)malloc((size_t)mW * mH * sizeof(int16_t));
    int16_t *planeCb = NULL;
    int16_t *planeCr = NULL;
    if (jpg->comps == 3)
    {
        planeCb = (int16_t *)malloc((size_t)mW * mH * sizeof(int16_t));
        planeCr = (int16_t *)malloc((size_t)mW * mH * sizeof(int16_t));
        if (!planeY || !planeCb || !planeCr)
        {
            free(planeY);
            free(planeCb);
            free(planeCr);
            return false;
        }
    }
    else
    {
        if (!planeY)
        {
            return false;
        }
    }

    /* find component indices: we assume Y is C[0] if comps==3 */
    int idxY = 0, idxCb = 1, idxCr = 2;
    if (jpg->comps == 1)
    {
        idxY = 0;
    }

    int mcu_countdown = jpg->restart_interval;
    for (int my = 0; my < jpg->mcus_y; ++my)
    {
        for (int mx = 0; mx < jpg->mcus_x; ++mx)
        {
            /* handle restart */
            if (jpg->restart_interval)
            {
                if (mcu_countdown == 0)
                {
                    /* consume restart marker (align to byte and read 0xFFD0..D7) */
                    br_align_byte(br);
                    int mrk = next_marker(br);
                    if (mrk < 0 || (mrk & 0xFFF8) != 0xFFD0)
                    {
                        free(planeY);
                        free(planeCb);
                        free(planeCr);
                        return false;
                    }
                    /* reset DC predictors */
                    for (int i = 0; i < jpg->comps; ++i)
                        jpg->C[i].dc_pred = 0;
                    mcu_countdown = jpg->restart_interval;
                    br->in_scan = true;
                    br->bits_left = 0;
                    br->bit_buf = 0;
                }
                --mcu_countdown;
            }

            /* zero planes */
            for (int i = 0; i < mW * mH; ++i)
            {
                planeY[i] = 0;
                if (planeCb)
                    for (int i = 0; i < mW * mH; ++i)
                        planeCb[i] = 128;
                if (planeCr)
                    for (int i = 0; i < mW * mH; ++i)
                        planeCr[i] = 128;

                /* Decode each component's blocks into the plane at proper subsampled resolution (then upsample by replication). */
                for (int ci = 0; ci < jpg->comps; ++ci)
                {
                    comp_t *c = &jpg->C[ci];
                    int cw = 8 * c->H;
                    int ch = 8 * c->V;
                    for (int vy = 0; vy < c->V; ++vy)
                    {
                        for (int hx = 0; hx < c->H; ++hx)
                        {
                            int16_t block[64];
                            if (!decode_block(br, jpg, c, block))
                            {
                                free(planeY);
                                free(planeCb);
                                free(planeCr);
                                return false;
                            }
                            int16_t deq[64]; /* IDCT output */
                            idct_8x8(block, deq);
                            /* Where to place this 8x8 within MCU plane */
                            int px = hx * 8 * (jpg->Hmax / c->H);
                            int py = vy * 8 * (jpg->Vmax / c->V);
                            int xstep = (jpg->Hmax / c->H);
                            int ystep = (jpg->Vmax / c->V);
                            for (int y = 0; y < 8; ++y)
                            {
                                for (int x = 0; x < 8; ++x)
                                {
                                    int16_t v = deq[y * 8 + x];
                                    /* replicate to upsample into MCU plane */
                                    for (int uy = 0; uy < ystep; ++uy)
                                    {
                                        for (int ux = 0; ux < xstep; ++ux)
                                        {
                                            int dstx = px + x * xstep + ux;
                                            int dsty = py + y * ystep + uy;
                                            int idx = dsty * mW + dstx;
                                            if (ci == idxY)
                                                planeY[idx] = v;
                                            else if (ci == idxCb)
                                                planeCb[idx] = v;
                                            else if (ci == idxCr)
                                                planeCr[idx] = v;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                /* Store MCU to output */
                upsample_and_store_RGB565(jpg, planeY, planeCb, planeCr, my * jpg->mcu_h, mx * jpg->mcu_w, dst, stride_bytes);
            }
        }
    }

    free(planeY);
    free(planeCb);
    free(planeCr);
    return true;
}

/* ========================== Public entry ========================== */

int jpeg_decode_rgb565(const uint8_t *jpeg, size_t len,
                       uint16_t **out_pixels, int *out_w, int *out_h, int *out_stride_bytes)
{
    if (!jpeg || len < 4 || !out_pixels || !out_w || !out_h || !out_stride_bytes)
        return -1;
    *out_pixels = NULL;
    *out_w = 0;
    *out_h = 0;
    *out_stride_bytes = 0;

    bitreader_t br;
    br_init(&br, jpeg, len);
    jpg_t jpg;
    memset(&jpg, 0, sizeof(jpg));

    /* Expect SOI */
    int mrk = next_marker(&br);
    if (mrk != 0xFFD8)
        return -2; /* SOI */

    /* Parse segments until SOS */
    bool have_SOF = false, have_SOS = false;
    while (!have_SOS)
    {
        mrk = next_marker(&br);
        if (mrk < 0)
            return -3;
        switch (mrk)
        {
        case 0xFFE0: /* APP0 */
        case 0xFFE1:
        case 0xFFE2:
        case 0xFFE3:
        case 0xFFE4:
        case 0xFFE5:
        case 0xFFE6:
        case 0xFFE7:
        case 0xFFE8:
        case 0xFFE9:
        case 0xFFEA:
        case 0xFFEB:
        case 0xFFEC:
        case 0xFFED:
        case 0xFFEE:
        case 0xFFEF: /* APPn */
        case 0xFFFE: /* COM */
        {
            uint16_t L = read_be16(&br);
            if (L < 2 || !skip_bytes(&br, L - 2))
                return -4;
            break;
        }
        case 0xFFDB:
            if (!parse_DQT(&br, &jpg))
                return -5;
            break;
        case 0xFFC4:
            if (!parse_DHT(&br, &jpg))
                return -6;
            break;
        case 0xFFDD:
            if (!parse_DRI(&br, &jpg))
                return -7;
            break;
        case 0xFFC0:
            if (!parse_SOF0(&br, &jpg))
                return -8;
            have_SOF = true;
            break;
        case 0xFFDA:
            if (!have_SOF)
                return -9;
            if (!parse_SOS(&br, &jpg))
                return -10;
            have_SOS = true;
            break;
        case 0xFFD9:
            return -11; /* EOI before SOS */
        default:
        {
            /* skip any other marker with a length */
            if ((mrk & 0xFFF0) == 0xFFD0)
            { /* RSTn outside scan: ignore */
                break;
            }
            uint16_t L = read_be16(&br);
            if (L < 2 || !skip_bytes(&br, L - 2))
                return -12;
            break;
        }
        }
    }

    if (jpg.comps != 1 && jpg.comps != 3)
        return -13;
    for (int i = 0; i < jpg.comps; ++i)
    {
        if (!jpg.Q[jpg.C[i].tq].present)
            return -14;
    }
    for (int i = 0; i < jpg.comps; ++i)
    {
        if (!jpg.HTDC[jpg.C[i].td].present || !jpg.HTAC[jpg.C[i].ta].present)
            return -15;
    }

    /* prepare output */
    int W = jpg.width, H = jpg.height;
    int stride_bytes = W * 2;
    uint16_t *pixels = (uint16_t *)malloc((size_t)H * stride_bytes);
    if (!pixels)
        return -16;
    memset(pixels, 0, (size_t)H * stride_bytes);

    /* decode scan */
    br.in_scan = true;
    br.bits_left = 0;
    br.bit_buf = 0;
    for (int i = 0; i < jpg.comps; ++i)
        jpg.C[i].dc_pred = 0;
    bool ok = decode_scan(&br, &jpg, pixels, stride_bytes);

    /* consume until EOI (optional) */
    if (ok)
    {
        int mark;
        do
        {
            mark = next_marker(&br);
            if (mark < 0)
                break;
        } while (mark != 0xFFD9); /* EOI */
    }

    if (!ok)
    {
        free(pixels);
        return -17;
    }

    *out_pixels = pixels;
    *out_w = W;
    *out_h = H;
    *out_stride_bytes = stride_bytes;
    return 0;
}

/* ========================== (Optional) Small test shim ==========================

// Example of using the decoder in a freestanding environment:
//
// extern void *malloc(size_t); extern void free(void*);
// int jpeg_decode_rgb24(const uint8_t *jpeg, size_t len,
//                       uint8_t **out_pixels, int *out_w, int *out_h, int *out_stride);
//
// void render_jpeg_to_fb(const uint8_t *jpg, size_t len, uint8_t *fb, int fb_w, int fb_h, int fb_stride) {
//     uint8_t *rgb; int w,h,s;
//     if (jpeg_decode_rgb24(jpg, len, &rgb, &w, &h, &s) == 0) {
//         int copy_w = (w<fb_w?w:fb_w), copy_h=(h<fb_h?h:fb_h);
//         for (int y=0; y<copy_h; ++y) memcpy(fb + y*fb_stride, rgb + y*s, (size_t)copy_w*3);
//         free(rgb);
//     }
// }
//
// Notes:
//  - This decoder avoids floating point and uses only malloc/memcpy/memset.
//  - Performance is modest but acceptable for small UI assets, icons, boot logos.
//  - For production, consider adding a tiny row-wise IDCT and simple (box) chroma upsampler.

*/
