/*
 * jpeg.c — tiny JPEG → RGB565 decoder for freestanding kernels
 *
 * Supports
 *  - Baseline & Extended Sequential (SOF0/SOF1) — 8-bit, Huffman
 *  - Progressive (SOF2) — spectral selection + successive approximation
 *  - Up to 3 components (gray or YCbCr/RGB)
 *  - Subsampling 4:4:4, 4:2:2, 4:2:0 (H,V ≤ 2)
 *  - DQT, DHT, SOF0/SOF1/SOF2, SOS, DRI; skips APPx/COM/unknown
 *  - Integer AAN-style IDCT (no floating point)
 *  - Output: RGB565 (tightly packed; stride = 2*width)
 *
 * Not supported
 *  - Arithmetic coding, lossless, 12/16-bit samples, CMYK/YCCK
 *  - Subsampling factors > 2
 *
 * API
 *   int jpeg_decode_rgb565(const uint8_t *jpeg, size_t len,
 *                          uint16_t **out_pixels, int *out_w, int *out_h, int *out_stride_bytes);
 *     Returns 0 on success and allocates *out_pixels with malloc(); caller must free().
 *     On error returns negative code; *out_pixels is left NULL.
 *
 * Expects the following libc-like functions:
 *   - void *malloc(size_t), void *calloc(size_t,size_t), void free(void*),
 *   - void *memset(void*,int,size_t), void *memcpy(void*, const void*, size_t),
 *     size_t strlen(const char*), int memcmp(const void*, const void*, size_t)
 */

#include "types.h"
#include "heap.h"
#include "libc.h"
#include "serial.h"
#include "atk/util/jpeg.h"

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
    bool in_scan;     /* when true, honor 0xFF00 stuffing */
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
            int n = br_read_u8(br);
            if (n < 0)
            {
                br->last_marker = 0xFF;
                return br->bits_left > 0;
            }
            if (n != 0x00)
            {
                br->last_marker = 0xFF00 | n;
                if (br->byte_pos >= 2) br->byte_pos -= 2; else br->byte_pos = 0;
                return br->bits_left > 0; /* don't push marker into bit_buf */
            }
            b = 0xFF; /* stuffed zero => literal 0xFF */
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
    uint16_t fast[1 << 8]; /* fast lookup: sym|len; 0xFFFF=slow */
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

    /* progressive storage */
    int wblocks;         /* blocks horizontally = mcus_x * H */
    int hblocks;         /* blocks vertically   = mcus_y * V */
    int total_blocks;    /* wblocks * hblocks */
    int32_t *coeff;      /* de-quantized coefficients, total_blocks*64 */
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
    int color_transform;  /* Adobe APP14 transform (-1 unknown) */
    bool adobe_transform_present;

    bool progressive;     /* SOF2? */
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

static void jpeg_log(const char *msg)
{
    if (!msg) return;
    serial_write_string("jpeg: "); serial_write_string(msg); serial_write_string("\r\n");
}

static void jpeg_log_hex(const char *label, uint32_t value)
{
    serial_write_string("jpeg: ");
    if (label) serial_write_string(label);
    serial_write_hex64((uint64_t)value);
    serial_write_string("\r\n");
}

/* sign-extend value of n-bit "v" as per JPEG spec */
static inline int16_t jsgnextend(int v, int n)
{
    int16_t vt = (int16_t)v;
    if (n == 0) return 0;
    int16_t lim = (int16_t)(1u << (n - 1));
    if (vt < lim) vt = (int16_t)(vt - (1 << n) + 1);
    return vt;
}

/* ========================== Huffman ========================== */

static void dht_build(dht_t *h)
{
    /* derive canonical codes */
    int code = 0, si = 1, k = 0;
    h->num_symbols = 0;
    for (int i = 0; i < 16; ++i)
    {
        for (int j = 0; j < h->counts[i]; ++j)
        {
            h->codes[k] = (uint16_t)code;
            h->sizes[k] = (uint8_t)si;
            ++code; ++k; ++h->num_symbols;
        }
        code <<= 1; ++si;
    }
    /* build fast table (8-bit) */
    for (int i = 0; i < 256; ++i) h->fast[i] = 0xFFFF;
    int idx = 0;
    for (int len = 1; len <= 8; ++len)
    {
        for (int j = 0; j < h->counts[len - 1]; ++j, ++idx)
        {
            int sym = h->symbols[idx];
            int bits = h->codes[idx] << (8 - len);
            int reps = 1 << (8 - len);
            for (int r = 0; r < reps; ++r)
                h->fast[bits | r] = (uint16_t)((sym << 8) | len);
        }
    }
}

static int huff_decode_symbol(bitreader_t *br, const dht_t *h)
{
    /* try fast path */
    if (br->bits_left < 8) br_refill(br);
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
        int sum = 0; for (int i = 0; i < len - 1; ++i) sum += h->counts[i];
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
static const int32_t C0_541196100 = FIX(0.541196100);
static const int32_t C0_765366865 = FIX(0.765366865);
static const int32_t C1_175875602 = FIX(1.175875602);
static const int32_t C1_501321110 = FIX(1.501321110);
static const int32_t C1_847759065 = FIX(1.847759065);
static const int32_t C1_961570560 = FIX(1.961570560);
static const int32_t C0_390180644 = FIX(0.390180644);
static const int32_t C2_053119869 = FIX(2.053119869);
static const int32_t C3_072711026 = FIX(3.072711026);
static const int32_t C2_562915447 = FIX(2.562915447);
static const int32_t C0_298631336 = FIX(0.298631336);
static const int32_t C0_899976223 = FIX(0.899976223);

static void idct_1d(int32_t *d)
{
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
        for (int j = 0; j < 8; ++j) tmp[i * 8 + j] = in[i * 8 + j];
        idct_1d(&tmp[i * 8]);
    }
    for (int j = 0; j < 8; ++j)
    {
        int32_t col[8];
        for (int i = 0; i < 8; ++i) col[i] = tmp[i * 8 + j];
        idct_1d(col);
        for (int i = 0; i < 8; ++i)
        {
            int32_t v = col[i] + 128; /* level shift */
            if (v < -256) v = -256;
            else if (v > 511) v = 511;
            out[i * 8 + j] = (int16_t)v;
        }
    }
}

/* ========================== Parsing helpers ========================== */

static uint16_t read_be16(bitreader_t *br)
{
    int a = br_read_u8(br);
    int b = br_read_u8(br);
    if (a < 0 || b < 0) return 0;
    return (uint16_t)((a << 8) | b);
}

static bool skip_bytes(bitreader_t *br, size_t n)
{
    if (br->byte_pos + n > br->size) return false;
    br->byte_pos += n; return true;
}

static bool read_bytes(bitreader_t *br, uint8_t *dst, size_t n)
{
    if (!dst) return skip_bytes(br, n);
    for (size_t i = 0; i < n; ++i)
    {
        int b = br_read_u8(br);
        if (b < 0) return false;
        dst[i] = (uint8_t)b;
    }
    return true;
}

static bool jpeg_should_treat_as_rgb(const jpg_t *jpg)
{
    if (!jpg || jpg->comps != 3) return false;

    if (jpg->adobe_transform_present)
    {
        if (jpg->color_transform == 0) { jpeg_log("Adobe transform=RGB"); return true; }
        if (jpg->color_transform == 1) return false;
    }
    else
    {
        if (jpg->C[0].id == 'R' && jpg->C[1].id == 'G' && jpg->C[2].id == 'B')
        { jpeg_log("component IDs indicate RGB"); return true; }
    }
    return false;
}

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
    uint16_t L = read_be16(br);
    if (L < 2) return false;
    size_t remaining = L - 2;
    while (remaining > 0)
    {
        int pq_tq = br_read_u8(br);
        if (pq_tq < 0) return false;
        --remaining;
        int pq = (pq_tq >> 4) & 0xF;
        int tq = pq_tq & 0xF;
        if (tq >= MAX_QUANT) return false;
        if (pq != 0) return false; /* only 8-bit tables supported */
        if (remaining < 64) return false;
        for (int i = 0; i < 64; ++i)
        {
            int v = br_read_u8(br);
            if (v < 0) return false;
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
    if (L < 2) { jpeg_set_error("DHT length < 2"); return false; }
    size_t rem = L - 2;
    jpeg_log_hex("DHT length=0x", L);
    while (rem > 0)
    {
        int tc_th = br_read_u8(br);
        if (tc_th < 0) { jpeg_set_error("DHT read tc_th failed"); return false; }
        --rem;
        int tc = (tc_th >> 4) & 0xF;
        int th = tc_th & 0xF;
        if (th >= MAX_HUFF) { jpeg_set_error("DHT table index out of range"); return false; }
        dht_t *H = (tc == 0) ? &jpg->HTDC[th] : &jpg->HTAC[th];
        int total = 0;
        for (int i = 0; i < 16; ++i)
        {
            int c = br_read_u8(br);
            if (c < 0) { jpeg_set_error("DHT read count failed"); return false; }
            H->counts[i] = (uint8_t)c; total += c;
        }
        if (rem < 16) { jpeg_set_error("DHT insufficient length for counts"); return false; }
        rem -= 16;
        if (total > 256 || rem < (size_t)total) { jpeg_set_error("DHT symbol count invalid"); return false; }
        for (int i = 0; i < total; ++i)
        {
            int s = br_read_u8(br);
            if (s < 0) { jpeg_set_error("DHT read symbol failed"); return false; }
            H->symbols[i] = (uint8_t)s;
        }
        rem -= total; H->present = true; dht_build(H);
        jpeg_log_hex("DHT symbols=0x", (uint32_t)total);
    }
    return true;
}

static bool parse_SOF0(bitreader_t *br, jpg_t *jpg)
{
    uint16_t L = read_be16(br);
    if (L < 2) return false;
    int P = br_read_u8(br);
    int Y = read_be16(br);
    int X = read_be16(br);
    int N = br_read_u8(br);
    if (P != 8 || X <= 0 || Y <= 0 || N <= 0 || N > MAX_COMP) return false;

    jpg->width = X; jpg->height = Y; jpg->comps = N;
    jpg->Hmax = jpg->Vmax = 1;
    for (int i = 0; i < N; ++i)
    {
        int C = br_read_u8(br);
        int HV = br_read_u8(br);
        int Tq = br_read_u8(br);
        if (C < 0 || HV < 0 || Tq < 0) return false;
        jpg->C[i].id = (uint8_t)C;
        jpg->C[i].H = (HV >> 4) & 0xF;
        jpg->C[i].V = HV & 0xF;
        jpg->C[i].tq = (uint8_t)(Tq & 0xF);
        if (jpg->C[i].H < 1 || jpg->C[i].H > 2 || jpg->C[i].V < 1 || jpg->C[i].V > 2) return false;
        if (jpg->C[i].H > jpg->Hmax) jpg->Hmax = jpg->C[i].H;
        if (jpg->C[i].V > jpg->Vmax) jpg->Vmax = jpg->C[i].V;
    }
    jpg->mcu_w = 8 * jpg->Hmax;
    jpg->mcu_h = 8 * jpg->Vmax;
    jpg->mcus_x = (jpg->width  + jpg->mcu_w - 1) / jpg->mcu_w;
    jpg->mcus_y = (jpg->height + jpg->mcu_h - 1) / jpg->mcu_h;
    (void)L;
    return true;
}

static bool parse_DRI(bitreader_t *br, jpg_t *jpg)
{
    uint16_t L = read_be16(br);
    if (L != 4) return false;
    jpg->restart_interval = read_be16(br);
    return true;
}

/* Progressive-capable SOS (1..N components) */
typedef struct {
    int Ns;
    uint8_t comp_idx[MAX_COMP]; /* indices into jpg->C[] for this scan */
    uint8_t td[MAX_COMP], ta[MAX_COMP];
    int Ss, Se, Ah, Al;
} scan_t;

static bool parse_SOS(bitreader_t *br, jpg_t *jpg, scan_t *scan)
{
    uint16_t L = read_be16(br);
    if (L < 2) return false;

    int Ns = br_read_u8(br);
    if (Ns <= 0 || Ns > jpg->comps) return false;

    scan->Ns = Ns;
    for (int i = 0; i < Ns; ++i)
    {
        int Cs  = br_read_u8(br);
        int Tda = br_read_u8(br);
        if (Cs < 0 || Tda < 0) return false;

        int idx = -1;
        for (int k = 0; k < jpg->comps; ++k)
            if (jpg->C[k].id == Cs) { idx = k; break; }
        if (idx < 0) return false;

        scan->comp_idx[i] = (uint8_t)idx;
        scan->td[i] = (Tda >> 4) & 0xF;
        scan->ta[i] = Tda & 0xF;

        jpg->C[idx].td = scan->td[i];
        jpg->C[idx].ta = scan->ta[i];
    }

    int Ss   = br_read_u8(br);
    int Se   = br_read_u8(br);
    int AhAl = br_read_u8(br);
    if (Ss < 0 || Se < 0 || AhAl < 0) return false;

    scan->Ss = Ss;
    scan->Se = Se;
    scan->Ah = (AhAl >> 4) & 0xF;
    scan->Al = AhAl & 0xF;

    (void)L;
    return true;
}

/* ========================== Baseline MCU decoding ========================== */

static bool decode_block(bitreader_t *br, const jpg_t *jpg, comp_t *c,
                         int16_t *block)
{
    for (int i = 0; i < 64; ++i) block[i] = 0;

    const dht_t *HTd = &jpg->HTDC[c->td];
    const dht_t *HTa = &jpg->HTAC[c->ta];
    const uint16_t *Q = jpg->Q[c->tq].q;

    /* DC */
    int s = huff_decode_symbol(br, HTd);
    if (s < 0) return false;
    int diff = 0;
    if (s) { int v = br_get(br, s); diff = jsgnextend(v, s); }
    int dc = c->dc_pred + diff; c->dc_pred = dc;
    block[0] = (int16_t)(dc * Q[0]);

    /* AC */
    int k = 1;
    while (k < 64)
    {
        int rs = huff_decode_symbol(br, HTa);
        if (rs < 0) return false;
        int r = (rs >> 4) & 0xF;
        int z = rs & 0xF;
        if (rs == 0x00) { break; }       /* EOB */
        if (rs == 0xF0) { k += 16; continue; } /* ZRL */
        k += r; if (k >= 64) return false;
        int vbits = br_get(br, z);
        int coef = jsgnextend(vbits, z);
        block[zigzag[k]] = (int16_t)(coef * Q[zigzag[k]]);
        ++k;
    }
    return true;
}

static void upsample_and_store_RGB565(const jpg_t *jpg,
                                      const int16_t *Y, const int16_t *Cb, const int16_t *Cr,
                                      int y0, int x0, uint16_t *dst, int stride_bytes,
                                      bool treat_rgb)
{
    const int W = jpg->width, H = jpg->height;
    const int mH = jpg->mcu_h, mW = jpg->mcu_w;
    for (int y = 0; y < mH; ++y)
    {
        int oy = y0 + y; if (oy >= H) break;
        uint16_t *row = (uint16_t *)((uint8_t *)dst + oy * stride_bytes);
        for (int x = 0; x < mW; ++x)
        {
            int ox = x0 + x; if (ox >= W) break;
            if (treat_rgb && Cb && Cr)
            {
                int r = Y[y * mW + x];
                int g = Cb[y * mW + x];
                int b = Cr[y * mW + x];
                row[ox] = pack_rgb565(r, g, b);
            }
            else
            {
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
}

static bool decode_scan(bitreader_t *br, jpg_t *jpg, uint16_t *dst, int stride_bytes)
{
    const int mW = jpg->mcu_w, mH = jpg->mcu_h;
    int16_t *planeY = (int16_t *)malloc((size_t)mW * mH * sizeof(int16_t));
    int16_t *planeCb = NULL;
    int16_t *planeCr = NULL;
    bool treat_rgb = jpeg_should_treat_as_rgb(jpg);
    jpeg_log(treat_rgb ? "JPEG color: treating as RGB" : "JPEG color: treating as YCbCr");
    if (jpg->comps == 3)
    {
        planeCb = (int16_t *)malloc((size_t)mW * mH * sizeof(int16_t));
        planeCr = (int16_t *)malloc((size_t)mW * mH * sizeof(int16_t));
        if (!planeY || !planeCb || !planeCr) { free(planeY); free(planeCb); free(planeCr); return false; }
    }
    else { if (!planeY) return false; }

    int idxY = 0, idxCb = 1, idxCr = 2;
    if (jpg->comps == 3)
    {
        int yCand = -1, cbCand = -1, crCand = -1;
        for (int i = 0; i < 3; ++i)
        {
            uint8_t id = jpg->C[i].id;
            if (id == 1 || id == 'R') yCand = i;
            else if (id == 2 || id == 'G') cbCand = i;
            else if (id == 3 || id == 'B') crCand = i;
        }
        if (yCand >= 0) idxY = yCand;
        if (cbCand >= 0) idxCb = cbCand;
        if (crCand >= 0) idxCr = crCand;
    }

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
                    if (mrk < 0 || (mrk & 0xFFF8) != 0xFFD0) { free(planeY); free(planeCb); free(planeCr); return false; }
                    for (int i = 0; i < jpg->comps; ++i) jpg->C[i].dc_pred = 0;
                    mcu_countdown = jpg->restart_interval;
                    br->in_scan = true; br->bits_left = 0; br->bit_buf = 0;
                }
                --mcu_countdown;
            }

            memset(planeY, 0, (size_t)mW * mH * sizeof(int16_t));
            if (planeCb) { int16_t f = treat_rgb ? 0 : 128; for (int i = 0; i < mW*mH; ++i) planeCb[i] = f; }
            if (planeCr) { int16_t f = treat_rgb ? 0 : 128; for (int i = 0; i < mW*mH; ++i) planeCr[i] = f; }

            for (int ci = 0; ci < jpg->comps; ++ci)
            {
                comp_t *c = &jpg->C[ci];
                for (int vy = 0; vy < c->V; ++vy)
                {
                    for (int hx = 0; hx < c->H; ++hx)
                    {
                        int16_t block[64];
                        if (!decode_block(br, jpg, c, block)) { free(planeY); free(planeCb); free(planeCr); return false; }
                        int16_t deq[64]; idct_8x8(block, deq);

                        int px = hx * 8 * (jpg->Hmax / c->H);
                        int py = vy * 8 * (jpg->Vmax / c->V);
                        int xstep = (jpg->Hmax / c->H);
                        int ystep = (jpg->Vmax / c->V);
                        for (int y = 0; y < 8; ++y)
                            for (int x = 0; x < 8; ++x)
                            {
                                int16_t v = deq[y * 8 + x];
                                for (int uy = 0; uy < ystep; ++uy)
                                    for (int ux = 0; ux < xstep; ++ux)
                                    {
                                        int dstx = px + x * xstep + ux;
                                        int dsty = py + y * ystep + uy;
                                        int idx = dsty * mW + dstx;
                                        if (ci == idxY)      planeY[idx]  = v;
                                        else if (ci == idxCb) planeCb[idx] = v;
                                        else if (ci == idxCr) planeCr[idx] = v;
                                    }
                            }
                    }
                }
            }
            upsample_and_store_RGB565(jpg, planeY, planeCb, planeCr,
                                      my * jpg->mcu_h, mx * jpg->mcu_w,
                                      dst, stride_bytes, treat_rgb);
        }
    }

    free(planeY); free(planeCb); free(planeCr);
    return true;
}

/* ========================== Progressive helpers ========================== */

static bool alloc_coeff_buffers(jpg_t *jpg)
{
    for (int i = 0; i < jpg->comps; ++i) {
        comp_t *c = &jpg->C[i];
        c->wblocks = jpg->mcus_x * c->H;
        c->hblocks = jpg->mcus_y * c->V;
        c->total_blocks = c->wblocks * c->hblocks;
        size_t n = (size_t)c->total_blocks * 64;
        c->coeff = (int32_t *)calloc(n, sizeof(int32_t));
        if (!c->coeff) return false;
    }
    return true;
}

static void free_coeff_buffers(jpg_t *jpg)
{
    for (int i = 0; i < jpg->comps; ++i) {
        free(jpg->C[i].coeff);
        jpg->C[i].coeff = NULL;
    }
}

static inline int32_t *coeff_block_ptr(comp_t *c, int bx, int by)
{
    return &c->coeff[((by * c->wblocks) + bx) * 64];
}

/* ---- Progressive DC (initial) ---- */
static bool prog_dc_first(bitreader_t *br, jpg_t *jpg, comp_t *c, int32_t *blk, int Al)
{
    const dht_t *HTd = &jpg->HTDC[c->td];
    int s = huff_decode_symbol(br, HTd);
    if (s < 0) return false;
    int diff = 0;
    if (s) diff = jsgnextend((int)br_get(br, s), s);
    diff <<= Al;
    c->dc_pred += diff;
    blk[0] = (int32_t)c->dc_pred * (int32_t)jpg->Q[c->tq].q[0];
    return true;
}

/* ---- Progressive DC (refine) ---- */
static bool prog_dc_refine(bitreader_t *br, jpg_t *jpg, comp_t *c, int32_t *blk, int Al)
{
    int bit = (int)br_get(br, 1);
    int32_t step = (int32_t)jpg->Q[c->tq].q[0] << Al;
    if (bit) blk[0] += (blk[0] >= 0 ? step : -step);
    return true;
}

/* ---- Progressive AC (initial) ---- */
static bool prog_ac_first(bitreader_t *br, jpg_t *jpg, comp_t *c, int32_t *blk, int Ss, int Se, int Al)
{
    const dht_t *HTa = &jpg->HTAC[c->ta];
    int k = Ss;
    while (k <= Se)
    {
        int rs = huff_decode_symbol(br, HTa);
        if (rs < 0) return false;

        int r = (rs >> 4) & 0xF;
        int s = rs & 0xF;

        if (s == 0)
        {
            if (r == 15) { k += 16; continue; } /* ZRL */
            else break; /* EOB */
        }

        k += r; if (k > Se) return false;

        int v = jsgnextend((int)br_get(br, s), s);
        int idx = zigzag[k];
        int32_t deq = (int32_t)v * (int32_t)jpg->Q[c->tq].q[idx] * (1 << Al);
        blk[idx] = deq;
        ++k;
    }
    return true;
}

/* ---- Progressive AC (refine) ---- */
static bool prog_ac_refine(bitreader_t *br, jpg_t *jpg, comp_t *c, int32_t *blk, int Ss, int Se, int Al, int *p_eobrun)
{
    const dht_t *HTa = &jpg->HTAC[c->ta];
    const uint16_t *Q = jpg->Q[c->tq].q;
    int bitpos = 1 << Al;

    int k = Ss;

    if (*p_eobrun > 0)
    {
        for (int kk = k; kk <= Se; ++kk) {
            int zz = zigzag[kk];
            if (blk[zz] != 0) {
                int b = (int)br_get(br, 1);
                if (b) blk[zz] += (blk[zz] > 0 ? (int32_t)Q[zz] * bitpos : -(int32_t)Q[zz] * bitpos);
            }
        }
        --(*p_eobrun);
        return true;
    }

    while (k <= Se)
    {
        int rs = huff_decode_symbol(br, HTa);
        if (rs < 0) return false;

        int r = (rs >> 4) & 0xF;
        int s = rs & 0xF;

        if (s == 0)
        {
            if (r == 15)
            {
                int zeros = 16;
                while (zeros && k <= Se) {
                    int zz = zigzag[k];
                    if (blk[zz] != 0) {
                        int b = (int)br_get(br, 1);
                        if (b) blk[zz] += (blk[zz] > 0 ? (int32_t)Q[zz] * bitpos : -(int32_t)Q[zz] * bitpos);
                    } else {
                        --zeros;
                    }
                    ++k;
                }
                continue;
            }
            int eobbits = r;
            int run = (1 << eobbits) - 1;
            if (eobbits) run += (int)br_get(br, eobbits);
            for (int kk = k; kk <= Se; ++kk) {
                int zz = zigzag[kk];
                if (blk[zz] != 0) {
                    int b = (int)br_get(br, 1);
                    if (b) blk[zz] += (blk[zz] > 0 ? (int32_t)Q[zz] * bitpos : -(int32_t)Q[zz] * bitpos);
                }
            }
            *p_eobrun = run;
            return true;
        }
        else if (s == 1)
        {
            while (k <= Se) {
                int zz = zigzag[k];
                if (blk[zz] != 0) {
                    int b = (int)br_get(br, 1);
                    if (b) blk[zz] += (blk[zz] > 0 ? (int32_t)Q[zz] * bitpos : -(int32_t)Q[zz] * bitpos);
                } else {
                    if (r == 0) {
                        int sign = (int)br_get(br, 1) ? 1 : -1;
                        blk[zz] = sign * (int32_t)Q[zz] * bitpos;
                        ++k;
                        break;
                    }
                    --r;
                }
                ++k;
            }
        }
        else
        {
            return false; /* s must be 1 in refine scans */
        }
    }
    return true;
}

static bool decode_scan_progressive(bitreader_t *br, jpg_t *jpg, const scan_t *scan, int *p_eobrun)
{
    int mcu_countdown = jpg->restart_interval;

    for (int my = 0; my < jpg->mcus_y; ++my)
    {
        for (int mx = 0; mx < jpg->mcus_x; ++mx)
        {
            if (jpg->restart_interval) {
                if (mcu_countdown == 0) {
                    br_align_byte(br);
                    int mrk = next_marker(br);
                    if (mrk < 0 || (mrk & 0xFFF8) != 0xFFD0) return false;
                    for (int i = 0; i < jpg->comps; ++i) jpg->C[i].dc_pred = 0;
                    *p_eobrun = 0;
                    mcu_countdown = jpg->restart_interval;
                    br->in_scan = true; br->bits_left = 0; br->bit_buf = 0;
                }
                --mcu_countdown;
            }

            if (scan->Ss == 0 && scan->Se == 0) {
                /* DC scan — may be interleaved */
                for (int si = 0; si < scan->Ns; ++si) {
                    comp_t *c = &jpg->C[ scan->comp_idx[si] ];
                    for (int vy = 0; vy < c->V; ++vy)
                        for (int hx = 0; hx < c->H; ++hx) {
                            int bx = mx * c->H + hx;
                            int by = my * c->V + vy;
                            int32_t *blk = coeff_block_ptr(c, bx, by);
                            if (scan->Ah == 0) {
                                if (!prog_dc_first(br, jpg, c, blk, scan->Al)) return false;
                            } else {
                                if (!prog_dc_refine(br, jpg, c, blk, scan->Al)) return false;
                            }
                        }
                }
            } else {
                /* AC scan — single component */
                if (scan->Ns != 1) return false;
                comp_t *c = &jpg->C[ scan->comp_idx[0] ];
                for (int vy = 0; vy < c->V; ++vy)
                    for (int hx = 0; hx < c->H; ++hx) {
                        int bx = mx * c->H + hx;
                        int by = my * c->V + vy;
                        int32_t *blk = coeff_block_ptr(c, bx, by);
                        if (scan->Ah == 0) {
                            if (!prog_ac_first(br, jpg, c, blk, scan->Ss, scan->Se, scan->Al)) return false;
                        } else {
                            if (!prog_ac_refine(br, jpg, c, blk, scan->Ss, scan->Se, scan->Al, p_eobrun)) return false;
                        }
                    }
            }
        }
    }
    return true;
}

/* Final render after all progressive scans */
static bool render_from_coeffs(jpg_t *jpg, uint16_t *dst, int stride_bytes)
{
    const int mW = jpg->mcu_w, mH = jpg->mcu_h;

    int16_t *planeY  = (int16_t *)malloc((size_t)mW * mH * sizeof(int16_t));
    int16_t *planeCb = NULL, *planeCr = NULL;

    bool treat_rgb = jpeg_should_treat_as_rgb(jpg);
    jpeg_log(treat_rgb ? "JPEG color: treating as RGB" : "JPEG color: treating as YCbCr");

    if (jpg->comps == 3) {
        planeCb = (int16_t *)malloc((size_t)mW * mH * sizeof(int16_t));
        planeCr = (int16_t *)malloc((size_t)mW * mH * sizeof(int16_t));
        if (!planeY || !planeCb || !planeCr) { free(planeY); free(planeCb); free(planeCr); return false; }
    } else {
        if (!planeY) return false;
    }

    int idxY = 0, idxCb = 1, idxCr = 2;
    if (jpg->comps == 3) {
        int yCand=-1, cbCand=-1, crCand=-1;
        for (int i=0;i<3;++i){
            uint8_t id = jpg->C[i].id;
            if (id==1 || id=='R') yCand=i;
            else if (id==2 || id=='G') cbCand=i;
            else if (id==3 || id=='B') crCand=i;
        }
        if (yCand>=0) idxY=yCand;
        if (cbCand>=0) idxCb=cbCand;
        if (crCand>=0) idxCr=crCand;
    }

    for (int my = 0; my < jpg->mcus_y; ++my)
    {
        for (int mx = 0; mx < jpg->mcus_x; ++mx)
        {
            memset(planeY, 0, (size_t)mW * mH * sizeof(int16_t));
            if (planeCb) { int16_t f = treat_rgb?0:128; for (int i=0;i<mW*mH;++i) planeCb[i]=f; }
            if (planeCr) { int16_t f = treat_rgb?0:128; for (int i=0;i<mW*mH;++i) planeCr[i]=f; }

            for (int ci = 0; ci < jpg->comps; ++ci)
            {
                comp_t *c = &jpg->C[ci];
                int xstep = (jpg->Hmax / c->H);
                int ystep = (jpg->Vmax / c->V);
                for (int vy = 0; vy < c->V; ++vy)
                    for (int hx = 0; hx < c->H; ++hx)
                    {
                        int bx = mx * c->H + hx;
                        int by = my * c->V + vy;
                        int32_t *src = coeff_block_ptr(c, bx, by);

                        int16_t deq16[64];
                        for (int i = 0; i < 64; ++i) {
                            int32_t v = src[i];
                            if (v < -32768) v = -32768; else if (v > 32767) v = 32767;
                            deq16[i] = (int16_t)v;
                        }

                        int16_t out8x8[64]; idct_8x8(deq16, out8x8);

                        int px = hx * 8 * xstep;
                        int py = vy * 8 * ystep;

                        for (int y = 0; y < 8; ++y)
                            for (int x = 0; x < 8; ++x) {
                                int16_t v = out8x8[y*8 + x];
                                for (int uy = 0; uy < ystep; ++uy)
                                    for (int ux = 0; ux < xstep; ++ux) {
                                        int dstx = px + x*xstep + ux;
                                        int dsty = py + y*ystep + uy;
                                        int idx = dsty * mW + dstx;
                                        if (ci == idxY)      planeY[idx]  = v;
                                        else if (ci == idxCb) planeCb[idx] = v;
                                        else if (ci == idxCr) planeCr[idx] = v;
                                    }
                            }
                    }
            }

            upsample_and_store_RGB565(jpg, planeY, planeCb, planeCr,
                                      my * jpg->mcu_h, mx * jpg->mcu_w,
                                      dst, stride_bytes, treat_rgb);
        }
    }

    free(planeY); free(planeCb); free(planeCr);
    return true;
}

/* ========================== Public entry ========================== */

int jpeg_decode_rgb565(const uint8_t *jpeg, size_t len,
                       uint16_t **out_pixels, int *out_w, int *out_h, int *out_stride_bytes)
{
    if (!jpeg || len < 4 || !out_pixels || !out_w || !out_h || !out_stride_bytes)
    {
        jpeg_set_error("invalid arguments");
        return -1;
    }
    *out_pixels = NULL; *out_w = 0; *out_h = 0; *out_stride_bytes = 0;

    bitreader_t br; br_init(&br, jpeg, len);
    jpg_t jpg; memset(&jpg, 0, sizeof(jpg));
    jpg.color_transform = -1;
    jpg.adobe_transform_present = false;
    jpg.progressive = false;

    jpeg_set_error("decode start");
    jpeg_log("decode begin");

    /* Expect SOI */
    int mrk = next_marker(&br);
    if (mrk != 0xFFD8) { jpeg_set_error("missing SOI"); return -2; }

    bool have_SOF = false;
    bool done = false;

    scan_t scan; /* reused per SOS */
    int progressive_eobrun = 0;
    bool coeff_ready = false;

    while (!done)
    {
        mrk = next_marker(&br);
        if (mrk < 0) { jpeg_set_error("marker read failed"); return -3; }

        switch (mrk)
        {
        case 0xFFE0: case 0xFFE1: case 0xFFE2: case 0xFFE3:
        case 0xFFE4: case 0xFFE5: case 0xFFE6: case 0xFFE7:
        case 0xFFE8: case 0xFFE9: case 0xFFEA: case 0xFFEB:
        case 0xFFEC: case 0xFFED: case 0xFFEE: case 0xFFEF:
        case 0xFFFE:
        {
            uint16_t L = read_be16(&br);
            if (L < 2) { jpeg_set_error("bad APP/COM length"); return -4; }

            if (mrk == 0xFFEE && L >= 14) { /* APP14 Adobe */
                uint8_t header[12];
                if (!read_bytes(&br, header, sizeof(header))) { jpeg_set_error("failed APP14 read"); return -4; }
                if (memcmp(header, "Adobe", 5) == 0) {
                    jpg.color_transform = header[11];
                    jpg.adobe_transform_present = true;
                    jpeg_log_hex("APP14 transform=0x", (uint32_t)jpg.color_transform);
                    jpeg_log("APP14 Adobe segment detected");
                }
                size_t remain = (size_t)L - 2 - sizeof(header);
                if (remain && !skip_bytes(&br, remain)) { jpeg_set_error("failed APP14 skip"); return -4; }
            } else {
                size_t remain = (size_t)L - 2;
                if (remain && !skip_bytes(&br, remain)) { jpeg_set_error("failed APP/COM skip"); return -4; }
            }
            break;
        }

        case 0xFFDB: if (!parse_DQT(&br, &jpg)) { jpeg_set_error("parse DQT failed"); return -5; } break;
        case 0xFFC4: if (!parse_DHT(&br, &jpg)) { jpeg_set_error("parse DHT failed"); return -6; } break;
        case 0xFFDD: if (!parse_DRI(&br, &jpg)) { jpeg_set_error("parse DRI failed"); return -7; } break;

        case 0xFFC0: /* SOF0 */
        case 0xFFC1: /* SOF1 */
        case 0xFFC2: /* SOF2 progressive */
        {
            if (!parse_SOF0(&br, &jpg)) { jpeg_set_error("parse SOF failed"); return -8; }
            jpg.progressive = (mrk == 0xFFC2);
            jpeg_log(jpg.progressive ? "SOF2 (progressive) parsed" : "SOF(sequential) parsed");
            jpeg_log_hex("width=0x",  (uint32_t)jpg.width);
            jpeg_log_hex("height=0x", (uint32_t)jpg.height);
            for (int i = 0; i < jpg.comps; ++i) {
                serial_write_string("jpeg: comp id=0x"); serial_write_hex64((uint64_t)jpg.C[i].id);
                serial_write_string(" H=0x");            serial_write_hex64((uint64_t)jpg.C[i].H);
                serial_write_string(" V=0x");            serial_write_hex64((uint64_t)jpg.C[i].V);
                serial_write_string("\r\n");
            }
            have_SOF = true;
            break;
        }

        case 0xFFDA: /* SOS */
        {
            if (!have_SOF) { jpeg_set_error("SOS before SOF"); return -9; }
            if (!parse_SOS(&br, &jpg, &scan)) { jpeg_set_error("parse SOS failed"); return -10; }

            /* Baseline requires interleaved single-scan (Ns==comps). */
            if (!jpg.progressive && scan.Ns != jpg.comps) { jpeg_set_error("baseline expects interleaved SOS"); return -10; }

            /* Switch to entropy-coded segment */
            br.in_scan   = true; br.bits_left = 0; br.bit_buf = 0;
            for (int i = 0; i < jpg.comps; ++i) jpg.C[i].dc_pred = 0;

            if (jpg.progressive)
            {
                if (!coeff_ready) {
                    if (!alloc_coeff_buffers(&jpg)) { jpeg_set_error("coeff alloc failed"); return -16; }
                    coeff_ready = true;
                }
                if (!decode_scan_progressive(&br, &jpg, &scan, &progressive_eobrun)) {
                    free_coeff_buffers(&jpg);
                    jpeg_set_error("progressive scan decode failed");
                    return -17;
                }
                br.in_scan = false; /* done with this scan; next marker will be read by loop */
            }
            else
            {
                /* Baseline: decode immediately and return pixels */
                int W = jpg.width, H = jpg.height;
                int stride_bytes = W * 2;
                uint16_t *pixels = (uint16_t *)malloc((size_t)H * stride_bytes);
                if (!pixels) { jpeg_set_error("pixel alloc failed"); return -16; }
                memset(pixels, 0, (size_t)H * stride_bytes);

                bool ok = decode_scan(&br, &jpg, pixels, stride_bytes);

                if (ok) {
                    int mark;
                    do { mark = next_marker(&br); if (mark < 0) break; } while (mark != 0xFFD9);
                }
                if (!ok) { free(pixels); jpeg_set_error("scan decode failed"); return -17; }

                *out_pixels = pixels; *out_w = W; *out_h = H; *out_stride_bytes = stride_bytes;
                jpeg_set_error("ok");
                return 0;
            }
            break;
        }

        case 0xFFD9: /* EOI */
            done = true;
            break;

        default:
            if ((mrk & 0xFFF0) == 0xFFD0) {
                /* RST outside scan: ignore */
            } else {
                uint16_t L = read_be16(&br);
                if (L < 2 || !skip_bytes(&br, L - 2)) { jpeg_set_error("bad optional marker"); return -12; }
            }
            break;
        }
    }

    /* Progressive: at EOI, render once from accumulated coefficients */
    if (jpg.progressive)
    {
        int W = jpg.width, H = jpg.height;
        int stride_bytes = W * 2;
        uint16_t *pixels = (uint16_t *)malloc((size_t)H * stride_bytes);
        if (!pixels) { free_coeff_buffers(&jpg); jpeg_set_error("pixel alloc failed"); return -16; }
        memset(pixels, 0, (size_t)H * stride_bytes);

        bool ok = render_from_coeffs(&jpg, pixels, stride_bytes);
        free_coeff_buffers(&jpg);
        if (!ok) { free(pixels); jpeg_set_error("render from coeffs failed"); return -17; }

        *out_pixels = pixels; *out_w = W; *out_h = H; *out_stride_bytes = stride_bytes;
        jpeg_set_error("ok");
        return 0;
    }

    jpeg_set_error("unexpected end without decoding");
    return -18;
}
