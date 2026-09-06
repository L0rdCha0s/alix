#include "hda.h"

#include "pci.h"
#include "libc.h"
#include "serial.h"
#include "ioremap.h"
#include "heap.h"
#include "devfs.h"
#include "process.h"
#include "spinlock.h"
#include "timer.h"
#include "audio.h"

#define HDA_MMIO_BYTES 0x4000ULL

#define HDA_REG_GCTL       0x08
#define HDA_REG_WAKEEN     0x0C
#define HDA_REG_STATESTS   0x0E
#define HDA_REG_INTCTL     0x20
#define HDA_REG_INTSTS     0x24
#define HDA_REG_ICOI       0x60
#define HDA_REG_ICII       0x64
#define HDA_REG_ICIS       0x68

#define HDA_REG_CORBLBASE  0x40
#define HDA_REG_CORBUBASE  0x44
#define HDA_REG_CORBWP     0x48
#define HDA_REG_CORBRP     0x4A
#define HDA_REG_CORBCTL    0x4C
#define HDA_REG_CORBSTS    0x4D
#define HDA_REG_CORBSIZE   0x4E

#define HDA_REG_RIRBLBASE  0x50
#define HDA_REG_RIRBUBASE  0x54
#define HDA_REG_RIRBWP     0x58
#define HDA_REG_RIRBCTL    0x5C
#define HDA_REG_RIRBSTS    0x5D
#define HDA_REG_RIRBSIZE   0x5E

#define HDA_CORB_RUN       0x02u
#define HDA_CORB_RESET     0x01u
#define HDA_CORB_RP_RST    0x8000u
#define HDA_CORB_SIZE_2    0x00u
#define HDA_CORB_SIZE_16   0x01u
#define HDA_CORB_SIZE_256  0x02u

#define HDA_RIRB_RUN       0x02u
#define HDA_RIRB_IRQ_EN    0x01u
#define HDA_RIRB_RP_RST    0x8000u
#define HDA_RIRB_SIZE_2    0x00u
#define HDA_RIRB_SIZE_16   0x01u
#define HDA_RIRB_SIZE_256  0x02u
#define HDA_RIRBSTS_IRQ    0x01u
#define HDA_RIRBSTS_OVERRUN 0x04u

/* Stream descriptor base: use output stream 0 at BAR + 0x100. */
#define HDA_REG_SD_BASE(n) (0x100u + (uint32_t)(n) * 0x20u)
#define HDA_REG_SD_CTL(n)  (HDA_REG_SD_BASE(n) + 0x00u)
#define HDA_REG_SD_STS(n)  (HDA_REG_SD_BASE(n) + 0x03u)
#define HDA_REG_SD_LPIB(n) (HDA_REG_SD_BASE(n) + 0x04u)
#define HDA_REG_SD_CBL(n)  (HDA_REG_SD_BASE(n) + 0x08u)
#define HDA_REG_SD_LVI(n)  (HDA_REG_SD_BASE(n) + 0x0Cu)
#define HDA_REG_SD_FIFOS(n) (HDA_REG_SD_BASE(n) + 0x10u)
#define HDA_REG_SD_FMT(n)  (HDA_REG_SD_BASE(n) + 0x12u)
#define HDA_REG_SD_BDLPL(n) (HDA_REG_SD_BASE(n) + 0x18u)
#define HDA_REG_SD_BDLPU(n) (HDA_REG_SD_BASE(n) + 0x1Cu)

#define HDA_GCTL_CRST      0x00000001u

#define HDA_ICIS_BUSY      0x01u
#define HDA_ICIS_VALID     0x02u

#define HDA_SDCTL_SRST     0x01u /* bit 0 */
#define HDA_SDCTL_RUN      0x02u /* bit 1 */
#define HDA_SDCTL_STREAM_SHIFT 20
#define HDA_SDCTL_STREAM_MASK  (0xFu << HDA_SDCTL_STREAM_SHIFT)

#define HDA_SDSTS_BCIS     0x04u /* Buffer Completion Interrupt Status */
#define HDA_SDSTS_FIFOE    0x08u /* FIFO Error */
#define HDA_SDSTS_DESE     0x10u /* Descriptor Error */
#define HDA_SDSTS_FIFORDY  0x20u /* FIFO Ready */
#define HDA_SDSTS_CLEAR    (HDA_SDSTS_BCIS | HDA_SDSTS_FIFOE | HDA_SDSTS_DESE)

#define HDA_PCM_FORMAT     0x0011u /* 48 kHz, 16-bit, 2 channels */
#define HDA_CONN_LIST_LEN  0x0EL

#define HDA_BDL_ENTRIES    64u
#define HDA_BUFFER_BYTES   (HDA_BDL_ENTRIES * 4096u)
/* Cap how far ahead writers can buffer audio to keep latency bounded. */
#define HDA_MAX_QUEUED_BYTES (64u * 1024u)
#define HDA_START_QUEUED_BYTES (16u * 1024u)
#define HDA_START_WAIT_MS      20u
#define HDA_FRAME_BYTES       4u
#define HDA_FADE_IN_FRAMES    240u /* 5 ms, only on cold start/true underrun. */
#define HDA_REPRIME_LEAD_BYTES 8192u /* Cover the controller/codec fetch window. */
#define HDA_BYTES_PER_SECOND  (48000u * HDA_FRAME_BYTES)
#define HDA_GAIN_RAMP_FRAMES  240u
#define HDA_GAIN_ONE          65536u

#define HDA_STREAM_INDEX   0u
#define HDA_STREAM_TAG     (HDA_STREAM_INDEX + 1u)

#define HDA_PIN_WIDGET_CTRL_OUT 0x40u
#define HDA_EAPD_ENABLE         0x01u
#define HDA_VERB_SET_AMP_GAIN_MUTE 0x300u
#define HDA_AMP_SET_OUTPUT 0x8000u
#define HDA_AMP_SET_INPUT  0x4000u
#define HDA_AMP_SET_LEFT   0x2000u
#define HDA_AMP_SET_RIGHT  0x1000u
#define HDA_AMP_MUTE       0x0080u
#define HDA_AMP_GAIN_MASK  0x007Fu

typedef struct
{
    uint32_t addr_low;
    uint32_t addr_high;
    uint32_t length;
    uint32_t flags;
} __attribute__((packed)) hda_bdl_entry_t;

/* Pre-allocated, aligned buffers to keep DMA addresses below 4 GiB. */
static uint8_t g_hda_buffer[HDA_BUFFER_BYTES] __attribute__((aligned(128)));
static hda_bdl_entry_t g_hda_bdl[HDA_BDL_ENTRIES] __attribute__((aligned(128)));
static uint32_t g_hda_corb_storage[256] __attribute__((aligned(128)));
static uint64_t g_hda_rirb_storage[256] __attribute__((aligned(128)));

typedef struct
{
    volatile uint8_t *regs;
    uint8_t codec_id;
    uint8_t afg_node;
    uint8_t converter_node;
    uint8_t pin_node;
    hda_bdl_entry_t *bdl;
    uint8_t *buffer;
    size_t buffer_size;
    size_t write_pos;
    spinlock_t lock;
    bool running;
    uint32_t *corb;
    uint64_t *rirb;
    uint16_t corb_entries;
    uint16_t rirb_entries;
    uint16_t corb_wp;
    uint16_t rirb_rp;
    uint32_t hw_pos_prev;
    size_t used_bytes;
    uint32_t fade_in_frames;
    uint64_t last_hw_update_ms;
    bool needs_reprogram;
    bool reconfiguring;
    uint64_t first_queued_ms;
    uint64_t writer_pid;
    bool writer_claimed;
    uint32_t gain_q16;
    uint32_t target_gain_q16;
    uint32_t gain_ramp_frames;
    bool gain_initialized;
    uint64_t empty_events;
    uint64_t reprime_events;
    uint64_t stream_errors;
    uint64_t rejected_writers;
} hda_state_t;

static hda_state_t g_hda;
static bool g_hda_ready;

static inline uint64_t hda_now_ms(void)
{
    uint32_t freq = timer_frequency();
    if (freq == 0)
    {
        return 0;
    }
    uint64_t ticks = timer_ticks();
    return (ticks * 1000ULL) / (uint64_t)freq;
}

static inline uint32_t virt_to_phys32(const void *ptr)
{
    return (uint32_t)(uintptr_t)ptr;
}

static inline uint64_t virt_to_phys64(const void *ptr)
{
    return (uint64_t)(uintptr_t)ptr;
}

static bool hda_prepare_corb_rirb(hda_state_t *hda)
{
    if (!hda)
    {
        return false;
    }

    memset(g_hda_corb_storage, 0, sizeof(g_hda_corb_storage));
    memset(g_hda_rirb_storage, 0, sizeof(g_hda_rirb_storage));
    hda->corb = g_hda_corb_storage;
    hda->rirb = g_hda_rirb_storage;
    hda->corb_entries = 256;
    hda->rirb_entries = 256;
    hda->corb_wp = 0;
    hda->rirb_rp = 0;
    return true;
}

static inline void hda_busy_wait(uint32_t iterations)
{
    for (uint32_t i = 0; i < iterations; ++i)
    {
        __asm__ volatile ("pause");
    }
}

static inline uint32_t hda_read32(hda_state_t *hda, uint32_t offset)
{
    return *((volatile uint32_t *)(hda->regs + offset));
}

static inline uint8_t hda_read8(hda_state_t *hda, uint32_t offset)
{
    return *((volatile uint8_t *)(hda->regs + offset));
}

static inline uint16_t hda_read16(hda_state_t *hda, uint32_t offset)
{
    return *((volatile uint16_t *)(hda->regs + offset));
}

static bool hda_program_stream(hda_state_t *hda);
static bool hda_start_stream(hda_state_t *hda);

static inline void hda_write32(hda_state_t *hda, uint32_t offset, uint32_t value)
{
    *((volatile uint32_t *)(hda->regs + offset)) = value;
}

static inline void hda_write8(hda_state_t *hda, uint32_t offset, uint8_t value)
{
    *((volatile uint8_t *)(hda->regs + offset)) = value;
}

static inline void hda_write16(hda_state_t *hda, uint32_t offset, uint16_t value)
{
    *((volatile uint16_t *)(hda->regs + offset)) = value;
}

static uint32_t hda_hw_position(hda_state_t *hda);
static void hda_check_stream_errors_locked(hda_state_t *hda, const char *context);

static int g_hda_lpib_log_budget = 8;
static int g_hda_error_log_budget = 8;

static bool hda_stop_stream(hda_state_t *hda)
{
    if (!hda)
    {
        return false;
    }
    uint32_t ctl_off = HDA_REG_SD_CTL(HDA_STREAM_INDEX);
    uint32_t ctl = hda_read32(hda, ctl_off);
    ctl &= ~HDA_SDCTL_RUN;
    hda_write32(hda, ctl_off, ctl);

    bool stopped = false;
    for (uint32_t i = 0; i < 100000u; ++i)
    {
        if ((hda_read32(hda, ctl_off) & HDA_SDCTL_RUN) == 0)
        {
            stopped = true;
            break;
        }
        __asm__ volatile ("pause");
    }
    if (!stopped)
    {
        hda->needs_reprogram = true;
        return false;
    }

    hda->running = false;
    hda->used_bytes = 0;
    hda->write_pos = 0;
    hda->last_hw_update_ms = 0;
    hda->fade_in_frames = HDA_FADE_IN_FRAMES;
    hda->needs_reprogram = true;
    return true;
}

static void hda_clear_ring_range(hda_state_t *hda, uint32_t offset, size_t len)
{
    if (!hda || !hda->buffer || len == 0)
    {
        return;
    }
    uint32_t pos = offset % (uint32_t)hda->buffer_size;
    while (len > 0)
    {
        size_t to_end = hda->buffer_size - (size_t)pos;
        size_t chunk = (len < to_end) ? len : to_end;
        memset(hda->buffer + pos, 0, chunk);
        len -= chunk;
        pos = 0;
    }
}

static void hda_silence_advance(hda_state_t *hda, uint32_t prev, uint32_t hw_pos)
{
    if (!hda || !hda->buffer || hda->buffer_size == 0 || hw_pos == prev)
    {
        return;
    }

    uint32_t buf = (uint32_t)hda->buffer_size;
    size_t consumed = (hw_pos >= prev)
        ? (size_t)(hw_pos - prev)
        : (size_t)(buf - prev) + (size_t)hw_pos;
    hda_clear_ring_range(hda, prev, consumed);
}

static void hda_log_hwpos(hda_state_t *hda, const char *context)
{
    if (!hda || g_hda_lpib_log_budget <= 0)
    {
        return;
    }
    uint32_t lpib = hda_read32(hda, HDA_REG_SD_LPIB(HDA_STREAM_INDEX));
    uint32_t sts = hda_read8(hda, HDA_REG_SD_STS(HDA_STREAM_INDEX));
    uint32_t ctl = hda_read32(hda, HDA_REG_SD_CTL(HDA_STREAM_INDEX));
    serial_printf("[hda] lpib ctx=%s lpib=0x%08X sts=0x%02X ctl=0x%08X\r\n",
                  context ? context : "?",
                  (unsigned)lpib,
                  (unsigned)sts,
                  (unsigned)ctl);
    g_hda_lpib_log_budget--;
}

static void hda_update_used_bytes(hda_state_t *hda, uint32_t hw_pos)
{
    if (!hda || hda->buffer_size == 0)
    {
        return;
    }
    uint32_t prev = hda->hw_pos_prev % (uint32_t)hda->buffer_size;
    uint32_t buf = (uint32_t)hda->buffer_size;
    uint32_t delta = (hw_pos >= prev) ? (hw_pos - prev) : (buf - (prev - hw_pos));
    uint64_t now_ms = hda_now_ms();
    uint64_t ring_ms = ((uint64_t)hda->buffer_size * 1000ULL) /
                       (uint64_t)HDA_BYTES_PER_SECOND;
    bool missed_full_ring = hda->last_hw_update_ms != 0 &&
                            now_ms >= hda->last_hw_update_ms &&
                            (now_ms - hda->last_hw_update_ms) >= ring_ms;

    if (missed_full_ring)
    {
        /* A modulo LPIB cannot reveal how many full wraps elapsed. */
        hda->used_bytes = 0;
        hda->write_pos = (size_t)hw_pos;
        hda->needs_reprogram = true;
    }
    else
    {
        hda_silence_advance(hda, prev, hw_pos);

        if ((size_t)delta >= hda->used_bytes)
        {
            hda->used_bytes = 0;
            hda->write_pos = (size_t)hw_pos;
        }
        else
        {
            hda->used_bytes -= (size_t)delta;
        }
    }
    hda->hw_pos_prev = hw_pos;
    hda->last_hw_update_ms = now_ms;
}

/* Called with the stream lock held; also used by writers before queueing PCM. */
static void hda_service_locked(hda_state_t *hda)
{
    if (hda->reconfiguring)
    {
        return;
    }
    if (hda->running)
    {
        hda_check_stream_errors_locked(hda, "service");
    }
    if (hda->running)
    {
        uint32_t hw = hda_hw_position(hda);
        size_t used_before = hda->used_bytes;
        hda_update_used_bytes(hda, hw);
        if (hda->needs_reprogram)
        {
            (void)hda_stop_stream(hda);
        }
        if (used_before > 0 && hda->used_bytes == 0)
        {
            hda->empty_events++;
        }
    }
    else if (!hda->needs_reprogram && hda->used_bytes > 0)
    {
        uint64_t now = hda_now_ms();
        if (hda->used_bytes >= HDA_START_QUEUED_BYTES ||
            (now >= hda->first_queued_ms &&
             now - hda->first_queued_ms >= HDA_START_WAIT_MS))
        {
            /* Short sounds must start even when no further write arrives. */
            __atomic_thread_fence(__ATOMIC_RELEASE);
            if (!hda_start_stream(hda))
            {
                hda->needs_reprogram = true;
            }
        }
    }
}

static void hda_housekeeping(void *arg)
{
    (void)arg;
    for (;;)
    {
        process_sleep_ms(1);
        spinlock_lock(&g_hda.lock);
        hda_service_locked(&g_hda);
        spinlock_unlock(&g_hda.lock);
    }
}

static void hda_check_stream_errors_locked(hda_state_t *hda, const char *context)
{
    if (!hda)
    {
        return;
    }
    uint8_t sts = hda_read8(hda, HDA_REG_SD_STS(HDA_STREAM_INDEX));
    if (sts & (HDA_SDSTS_FIFOE | HDA_SDSTS_DESE))
    {
        hda->stream_errors++;
        if (g_hda_error_log_budget > 0)
        {
            g_hda_error_log_budget--;
            uint32_t lpib = hda_read32(hda, HDA_REG_SD_LPIB(HDA_STREAM_INDEX));
            uint32_t cbl = hda_read32(hda, HDA_REG_SD_CBL(HDA_STREAM_INDEX));
            uint16_t lvi = hda_read16(hda, HDA_REG_SD_LVI(HDA_STREAM_INDEX));
            uint32_t bdlpl = hda_read32(hda, HDA_REG_SD_BDLPL(HDA_STREAM_INDEX));
            uint32_t ctl = hda_read32(hda, HDA_REG_SD_CTL(HDA_STREAM_INDEX));
            serial_printf("[hda] stream error ctx=%s sts=0x%02X lpib=0x%08X cbl=0x%08X lvi=0x%04X bdlpl=0x%08X ctl=0x%08X\r\n",
                          context ? context : "?",
                          (unsigned)sts,
                          (unsigned)lpib,
                          (unsigned)cbl,
                          (unsigned)lvi,
                          (unsigned)bdlpl,
                          (unsigned)ctl);
        }
        hda_write8(hda, HDA_REG_SD_STS(HDA_STREAM_INDEX), HDA_SDSTS_CLEAR);
        if (sts & HDA_SDSTS_DESE)
        {
            bool stopped = hda_stop_stream(hda);
            hda->needs_reprogram = true;
            if (!stopped)
            {
                hda->needs_reprogram = true;
            }
        }
    }
}

static uint16_t hda_entries_from_size_reg(uint8_t size_reg)
{
    switch (size_reg & 0x03u)
    {
        case 0x00u: return 2u;
        case 0x01u: return 16u;
        case 0x02u: return 256u;
        default:    return 0;
    }
}

static void hda_select_ring_sizes(hda_state_t *hda)
{
    if (!hda)
    {
        return;
    }

    uint8_t corbsize = hda_read8(hda, HDA_REG_CORBSIZE);
    if ((corbsize & 0x03u) == 0)
    {
        if (corbsize & 0x40u)
        {
            hda_write8(hda, HDA_REG_CORBSIZE, HDA_CORB_SIZE_256);
        }
        else if (corbsize & 0x20u)
        {
            hda_write8(hda, HDA_REG_CORBSIZE, HDA_CORB_SIZE_16);
        }
        else
        {
            hda_write8(hda, HDA_REG_CORBSIZE, HDA_CORB_SIZE_2);
        }
        corbsize = hda_read8(hda, HDA_REG_CORBSIZE);
    }
    hda->corb_entries = hda_entries_from_size_reg(corbsize);
    if (hda->corb_entries == 0)
    {
        hda->corb_entries = 256;
    }

    uint8_t rirbsize = hda_read8(hda, HDA_REG_RIRBSIZE);
    if ((rirbsize & 0x03u) == 0)
    {
        if (rirbsize & 0x40u)
        {
            hda_write8(hda, HDA_REG_RIRBSIZE, HDA_RIRB_SIZE_256);
        }
        else if (rirbsize & 0x20u)
        {
            hda_write8(hda, HDA_REG_RIRBSIZE, HDA_RIRB_SIZE_16);
        }
        else
        {
            hda_write8(hda, HDA_REG_RIRBSIZE, HDA_RIRB_SIZE_2);
        }
        rirbsize = hda_read8(hda, HDA_REG_RIRBSIZE);
    }
    hda->rirb_entries = hda_entries_from_size_reg(rirbsize);
    if (hda->rirb_entries == 0)
    {
        hda->rirb_entries = 256;
    }
}

static bool hda_send_verb_immediate(hda_state_t *hda,
                                    uint8_t codec,
                                    uint8_t node_id,
                                    uint16_t verb,
                                    uint16_t payload,
                                    uint32_t *response)
{
    if (!hda)
    {
        return false;
    }
    uint32_t cmd = ((uint32_t)codec << 28)
                 | ((uint32_t)node_id << 20)
                 | ((uint32_t)verb << 8)
                 | (uint32_t)payload;

    /* Clear response-valid without asserting BUSY. */
    hda_write32(hda, HDA_REG_ICIS, HDA_ICIS_VALID);
    /* Wait for immediate interface idle. */
    for (uint32_t i = 0; i < 500000; ++i)
    {
        if ((hda_read32(hda, HDA_REG_ICIS) & HDA_ICIS_BUSY) == 0)
        {
            break;
        }
        __asm__ volatile ("pause");
    }
    /* Kick the immediate command engine: write command then set BUSY bit. */
    hda_write32(hda, HDA_REG_ICOI, cmd);
    hda_write32(hda, HDA_REG_ICIS, HDA_ICIS_BUSY);
    for (uint32_t i = 0; i < 1000000; ++i)
    {
        uint32_t icis = hda_read32(hda, HDA_REG_ICIS);
        if (icis & HDA_ICIS_VALID)
        {
            uint32_t resp = hda_read32(hda, HDA_REG_ICII);
            /* Clear VALID for next command. */
            hda_write32(hda, HDA_REG_ICIS, HDA_ICIS_VALID);
            if (response)
            {
                *response = resp;
            }
            return true;
        }
        if (icis & HDA_ICIS_BUSY)
        {
            continue;
        }
        if ((i & 0x3FFFu) == 0)
        {
            process_yield();
        }
    }
    serial_printf("[hda] immediate verb 0x%03X:%02X failed icis=0x%08X\r\n",
                  (unsigned)verb,
                  (unsigned)node_id,
                  (unsigned)hda_read32(hda, HDA_REG_ICIS));
    return false;
}

static bool hda_wait_mask32(hda_state_t *hda,
                            uint32_t offset,
                            uint32_t mask,
                            uint32_t expected,
                            uint32_t limit)
{
    for (uint32_t i = 0; i < limit; ++i)
    {
        uint32_t value = hda_read32(hda, offset);
        if ((value & mask) == expected)
        {
            return true;
        }
        if ((i & 0x3FFu) == 0)
        {
            process_yield();
        }
    }
    return false;
}

static bool hda_send_verb(hda_state_t *hda,
                          uint8_t codec,
                          uint8_t node_id,
                          uint16_t verb,
                          uint16_t payload,
                          uint32_t *response)
{
    if (!hda || !hda->corb || !hda->rirb)
    {
        return false;
    }

    /* Prefer the immediate command interface to avoid long CORB waits
       while we bring up codecs. */
    if (hda_send_verb_immediate(hda, codec, node_id, verb, payload, response))
    {
        return true;
    }

    uint32_t cmd = ((uint32_t)codec << 28)
                 | ((uint32_t)node_id << 20)
                 | ((uint32_t)verb << 8)
                 | (uint32_t)payload;

    uint16_t wp = hda->corb_wp;
    uint16_t next_wp = (uint16_t)((wp + 1u) & (hda->corb_entries - 1u));
    hda->corb[next_wp] = cmd;
    hda_write16(hda, HDA_REG_CORBWP, next_wp);
    hda->corb_wp = next_wp;

    /* Clear any stale RIRB interrupt/overrun status. */
    hda_write8(hda, HDA_REG_RIRBSTS, HDA_RIRBSTS_IRQ | HDA_RIRBSTS_OVERRUN);

    uint32_t timeout = 200000; /* shorter CORB wait; immediate already tried */
    while (timeout--)
    {
        uint16_t rp = hda_read16(hda, HDA_REG_RIRBWP);
        if (rp == hda->rirb_rp)
        {
            __asm__ volatile ("pause");
            continue;
        }
        hda->rirb_rp = rp;
        uint16_t idx = rp & (hda->rirb_entries - 1u);
        uint64_t entry = hda->rirb[idx];
        uint32_t resp = (uint32_t)(entry & 0xFFFFFFFFu);
        uint32_t resp_cad = (resp >> 28) & 0x0Fu;
        if (resp_cad != codec)
        {
            continue;
        }
        if (response)
        {
            *response = resp;
        }
        return true;
    }
    serial_printf("[hda] verb 0x%03X:%02X timeout rp=0x%04X\r\n",
                  (unsigned)verb, (unsigned)node_id, (unsigned)hda->rirb_rp);
    return false;
}

static bool hda_get_parameter(hda_state_t *hda,
                              uint8_t node_id,
                              uint8_t param,
                              uint32_t *out)
{
    return hda_send_verb(hda, hda->codec_id, node_id, 0xF00u, param, out);
}

static bool hda_reset_controller(hda_state_t *hda)
{
    if (!hda || !hda->corb || !hda->rirb)
    {
        return false;
    }

    uint32_t gctl = hda_read32(hda, HDA_REG_GCTL);
    hda_write32(hda, HDA_REG_GCTL, gctl & ~HDA_GCTL_CRST);
    if (!hda_wait_mask32(hda, HDA_REG_GCTL, HDA_GCTL_CRST, 0, 100000))
    {
        serial_printf("[hda] controller reset assert timeout\r\n");
        return false;
    }
    hda_write32(hda, HDA_REG_GCTL, hda_read32(hda, HDA_REG_GCTL) | HDA_GCTL_CRST);
    if (!hda_wait_mask32(hda, HDA_REG_GCTL, HDA_GCTL_CRST, HDA_GCTL_CRST, 100000))
    {
        serial_printf("[hda] controller reset deassert timeout\r\n");
        return false;
    }
    hda_busy_wait(5000000);

    /* Stop DMA engines before reprogramming. */
    hda_write8(hda, HDA_REG_CORBCTL, 0);
    hda_write8(hda, HDA_REG_RIRBCTL, 0);

    /* Configure CORB/RIRB sizes based on hardware support. */
    hda_select_ring_sizes(hda);
    serial_printf("[hda] corb_entries=%u rirb_entries=%u\r\n",
                  (unsigned)hda->corb_entries,
                  (unsigned)hda->rirb_entries);

    uint64_t corb_phys = virt_to_phys64(hda->corb);
    uint64_t rirb_phys = virt_to_phys64(hda->rirb);
    hda_write32(hda, HDA_REG_CORBLBASE, (uint32_t)corb_phys);
    hda_write32(hda, HDA_REG_CORBUBASE, (uint32_t)(corb_phys >> 32));
    hda_write32(hda, HDA_REG_RIRBLBASE, (uint32_t)rirb_phys);
    hda_write32(hda, HDA_REG_RIRBUBASE, (uint32_t)(rirb_phys >> 32));
    serial_printf("[hda] corb_phys=0x%llX rirb_phys=0x%llX\r\n",
                  (unsigned long long)corb_phys,
                  (unsigned long long)rirb_phys);

    /* Reset read/write pointers. */
    hda_write16(hda, HDA_REG_CORBRP, HDA_CORB_RP_RST);
    hda_write16(hda, HDA_REG_CORBRP, 0);
    hda_write16(hda, HDA_REG_CORBWP, 0);
    hda->corb_wp = 0;

    hda_write16(hda, HDA_REG_RIRBWP, HDA_RIRB_RP_RST);
    hda_write16(hda, HDA_REG_RIRBWP, 0);
    hda->rirb_rp = 0;
    hda_write8(hda, HDA_REG_RIRBSTS, HDA_RIRBSTS_IRQ | HDA_RIRBSTS_OVERRUN);

    /* Enable CORB/RIRB DMA; leave RIRB IRQ disabled (we poll). */
    hda_write8(hda, HDA_REG_CORBCTL, HDA_CORB_RUN);
    hda_write8(hda, HDA_REG_RIRBCTL, HDA_RIRB_RUN | HDA_RIRB_IRQ_EN);

    return true;
}

static void hda_unmute_output_amp(hda_state_t *hda, uint8_t node_id, uint8_t gain)
{
    if (!hda)
    {
        return;
    }

    uint16_t steps = (uint16_t)gain & HDA_AMP_GAIN_MASK;

    uint16_t left_payload = (uint16_t)(HDA_AMP_SET_OUTPUT | HDA_AMP_SET_LEFT | steps);
    (void)hda_send_verb(hda,
                        hda->codec_id,
                        node_id,
                        HDA_VERB_SET_AMP_GAIN_MUTE,
                        left_payload,
                        NULL);

    uint16_t right_payload = (uint16_t)(HDA_AMP_SET_OUTPUT | HDA_AMP_SET_RIGHT | steps);
    (void)hda_send_verb(hda,
                        hda->codec_id,
                        node_id,
                        HDA_VERB_SET_AMP_GAIN_MUTE,
                        right_payload,
                        NULL);
}

static bool hda_wait_codecs(hda_state_t *hda, uint16_t *out_mask)
{
    /* Poll for codec presence with small sleeps to avoid long busy-spins. */
    uint16_t mask = 0;
    const uint32_t attempts = 50;
    for (uint32_t i = 0; i < attempts; ++i)
    {
        mask = hda_read16(hda, HDA_REG_STATESTS);
        if (mask)
        {
            break;
        }
        process_sleep_ms(1);
    }
    if (out_mask)
    {
        *out_mask = mask;
    }
    return mask != 0;
}

static bool hda_pick_nodes(hda_state_t *hda)
{
    uint32_t info = 0;
    /* Retry root node discovery a few times in case the codec is still waking. */
    for (int attempt = 0; attempt < 8; ++attempt)
    {
        if (hda_get_parameter(hda, 0, 0x04, &info) && info != 0)
        {
            break;
        }
        info = 0;
        process_sleep_ms(2);
    }
    if (info == 0)
    {
        serial_printf("[hda] root node info unavailable\r\n");
        return false;
    }
    uint8_t start = (uint8_t)((info >> 16) & 0xFFu);
    uint8_t count = (uint8_t)(info & 0xFFu);
    serial_printf("[hda] root nodes start=%u count=%u info=0x%08X\r\n",
                  (unsigned)start,
                  (unsigned)count,
                  (unsigned)info);
    if (info == 0)
    {
        serial_printf("[hda] root node GetParameter returned zero response\r\n");
    }

    uint8_t afg = 0;
    for (uint8_t i = 0; i < count; ++i)
    {
        uint8_t nid = (uint8_t)(start + i);
        uint32_t fg_type = 0;
        if (!hda_get_parameter(hda, nid, 0x05, &fg_type))
        {
            continue;
        }
        uint8_t type = (uint8_t)(fg_type & 0xFFu);
        serial_printf("[hda] fg nid=%u type=0x%02X fg_type=0x%08X\r\n",
                      (unsigned)nid,
                      (unsigned)type,
                      (unsigned)fg_type);
        if ((fg_type & 0xFFu) == 0x01u)
        {
            afg = nid;
            break;
        }
    }
    if (!afg && count > 0)
    {
        afg = start; /* fallback to first advertised node */
        serial_printf("[hda] fallback AFG using nid=%u\r\n", (unsigned)afg);
    }
    if (!afg)
    {
        serial_printf("[hda] audio function group not found\r\n");
        return false;
    }
    hda->afg_node = afg;

    if (!hda_get_parameter(hda, afg, 0x04, &info))
    {
        serial_printf("[hda] audio function group missing node info\r\n");
        return false;
    }

    start = (uint8_t)((info >> 16) & 0xFFu);
    count = (uint8_t)(info & 0xFFu);
    serial_printf("[hda] afg nodes start=%u count=%u info=0x%08X\r\n",
                  (unsigned)start,
                  (unsigned)count,
                  (unsigned)info);

    uint8_t converter = 0;
    uint8_t pin = 0;
    uint32_t pin_caps = 0;

    for (uint8_t i = 0; i < count; ++i)
    {
        uint8_t nid = (uint8_t)(start + i);
        uint32_t wcaps = 0;
        if (!hda_get_parameter(hda, nid, 0x09, &wcaps))
        {
            continue;
        }
        uint8_t type = (uint8_t)((wcaps >> 20) & 0x0Fu);
        if (!converter && type == 0x00u)
        {
            converter = nid;
        }
        else if (!pin && type == 0x04u)
        {
            uint32_t caps = 0;
            if (hda_get_parameter(hda, nid, 0x0C, &caps) && (caps & (1u << 4)))
            {
                pin = nid;
                pin_caps = caps;
            }
        }
    }

    if (!converter || !pin)
    {
        serial_printf("[hda] failed to locate converter or output pin\r\n");
        return false;
    }

    hda->converter_node = converter;
    hda->pin_node = pin;

    /* Bring key widgets to D0. */
    (void)hda_send_verb(hda, hda->codec_id, afg, 0x705, 0, NULL);
    (void)hda_send_verb(hda, hda->codec_id, converter, 0x705, 0, NULL);
    (void)hda_send_verb(hda, hda->codec_id, pin, 0x705, 0, NULL);
    /* Unmute amps along the path with a modest gain. */
    hda_unmute_output_amp(hda, afg, 0x08);
    hda_unmute_output_amp(hda, converter, 0x08);
    hda_unmute_output_amp(hda, pin, 0x08);

    /* Enable EAPD if the pin advertises the capability. */
    if (pin_caps != 0)
    {
        (void)hda_send_verb(hda, hda->codec_id, pin, 0x70C, HDA_EAPD_ENABLE, NULL);
    }
    return true;
}

static bool hda_prepare_buffers(hda_state_t *hda)
{
    if (!hda)
    {
        return false;
    }

    hda->bdl = g_hda_bdl;
    memset(hda->bdl, 0, sizeof(g_hda_bdl));

    hda->buffer = g_hda_buffer;
    hda->buffer_size = HDA_BUFFER_BYTES;
    memset(hda->buffer, 0, hda->buffer_size);
    hda->write_pos = 0;
    hda->used_bytes = 0;
    hda->fade_in_frames = HDA_FADE_IN_FRAMES;
    hda->hw_pos_prev = 0;
    hda->last_hw_update_ms = 0;
    hda->first_queued_ms = 0;
    hda->gain_initialized = false;
    hda->gain_ramp_frames = 0;

    size_t entry_bytes = hda->buffer_size / HDA_BDL_ENTRIES;
    for (uint32_t i = 0; i < HDA_BDL_ENTRIES; ++i)
    {
        uintptr_t addr = (uintptr_t)(hda->buffer + (i * entry_bytes));
        hda->bdl[i].addr_low = (uint32_t)addr;
        hda->bdl[i].addr_high = (uint32_t)(addr >> 32);
        hda->bdl[i].length = (uint32_t)entry_bytes;
        /* Set IOC to give the controller a clean wrap/interrupt point. */
        hda->bdl[i].flags = 0x01u;
    }
    return true;
}

static bool hda_reset_stream(hda_state_t *hda)
{
    uint32_t ctl_off = HDA_REG_SD_CTL(HDA_STREAM_INDEX);
    uint32_t ctl = hda_read32(hda, ctl_off);
    /* Ensure RUN is clear before toggling reset. */
    ctl &= ~HDA_SDCTL_RUN;
    hda_write32(hda, ctl_off, ctl);
    if (!hda_wait_mask32(hda, ctl_off, HDA_SDCTL_RUN, 0, 100000))
    {
        serial_printf("[hda] stream run clear timeout\r\n");
        return false;
    }
    /* Assert stream reset. */
    ctl |= HDA_SDCTL_SRST;
    hda_write32(hda, ctl_off, ctl);
    if (!hda_wait_mask32(hda, ctl_off, HDA_SDCTL_SRST, HDA_SDCTL_SRST, 100000))
    {
        serial_printf("[hda] stream reset assert timeout\r\n");
        return false;
    }
    /* Deassert reset. */
    ctl &= ~HDA_SDCTL_SRST;
    hda_write32(hda, ctl_off, ctl);
    if (!hda_wait_mask32(hda, ctl_off, HDA_SDCTL_SRST, 0, 100000))
    {
        serial_printf("[hda] stream reset deassert timeout\r\n");
        return false;
    }
    hda->hw_pos_prev = hda_read32(hda, HDA_REG_SD_LPIB(HDA_STREAM_INDEX));
    hda->used_bytes = 0;
    hda->running = false;
    return true;
}

static bool hda_program_stream(hda_state_t *hda)
{
    /* Stop/reset DMA before clearing the live BDL or sample ring. */
    if (!hda_reset_stream(hda))
    {
        return false;
    }

    if (!hda_prepare_buffers(hda))
    {
        serial_printf("[hda] buffer allocation failed\r\n");
        return false;
    }

    uint32_t ctl_off = HDA_REG_SD_CTL(HDA_STREAM_INDEX);
    uint32_t sts_off = HDA_REG_SD_STS(HDA_STREAM_INDEX);
    uint32_t cbl_off = HDA_REG_SD_CBL(HDA_STREAM_INDEX);
    uint32_t lvi_off = HDA_REG_SD_LVI(HDA_STREAM_INDEX);
    uint32_t fmt_off = HDA_REG_SD_FMT(HDA_STREAM_INDEX);
    uint32_t bdlpl_off = HDA_REG_SD_BDLPL(HDA_STREAM_INDEX);
    uint32_t bdlpu_off = HDA_REG_SD_BDLPU(HDA_STREAM_INDEX);

    hda_write8(hda, sts_off, (uint8_t)HDA_SDSTS_CLEAR);
    hda_write32(hda, cbl_off, (uint32_t)hda->buffer_size);
    hda_write16(hda, lvi_off, (uint16_t)(HDA_BDL_ENTRIES - 1u));
    hda_write16(hda, fmt_off, HDA_PCM_FORMAT);

    uint64_t bdl_phys = virt_to_phys64(hda->bdl);
    hda_write32(hda, bdlpl_off, (uint32_t)bdl_phys);
    hda_write32(hda, bdlpu_off, (uint32_t)(bdl_phys >> 32));
    serial_printf("[hda] bdl[0]=0x%08X len=0x%08X flags=0x%08X bdl_phys=0x%llX cbl=0x%08X lvi=0x%04X\r\n",
                  hda->bdl[0].addr_low,
                  hda->bdl[0].length,
                  hda->bdl[0].flags,
                  (unsigned long long)bdl_phys,
                  (unsigned)hda->buffer_size,
                  (unsigned)(HDA_BDL_ENTRIES - 1u));

    uint32_t ctl = (HDA_STREAM_TAG << HDA_SDCTL_STREAM_SHIFT);
    hda_write32(hda, ctl_off, ctl);

    /* Bind converter to this stream: stereo consumes channel 0 and 1. */
    uint16_t stream_chan = (uint16_t)((HDA_STREAM_TAG << 4) | 0u);
    (void)hda_send_verb(hda,
                        hda->codec_id,
                        hda->converter_node,
                        0x706,
                        stream_chan,
                        NULL);
    /* Explicitly state two channels (0-indexed count). */
    (void)hda_send_verb(hda,
                        hda->codec_id,
                        hda->converter_node,
                        0x72D,
                        1,
                        NULL);
    (void)hda_send_verb(hda,
                        hda->codec_id,
                        hda->converter_node,
                        0x200,
                        HDA_PCM_FORMAT,
                        NULL);
    (void)hda_send_verb(hda,
                        hda->codec_id,
                        hda->pin_node,
                        0x707,
                        HDA_PIN_WIDGET_CTRL_OUT,
                        NULL);

    hda->needs_reprogram = false;
    return true;
}

static bool hda_start_stream(hda_state_t *hda)
{
    if (!hda || hda->used_bytes == 0)
    {
        return false;
    }
    uint32_t ctl_off = HDA_REG_SD_CTL(HDA_STREAM_INDEX);
    uint32_t sts_off = HDA_REG_SD_STS(HDA_STREAM_INDEX);

    hda_write8(hda, sts_off, (uint8_t)HDA_SDSTS_CLEAR);
    uint32_t ctl = hda_read32(hda, ctl_off);
    /* Clear SRST and update stream tag before enabling RUN. */
    ctl &= ~(HDA_SDCTL_STREAM_MASK | HDA_SDCTL_SRST);
    ctl |= (HDA_STREAM_TAG << HDA_SDCTL_STREAM_SHIFT) | HDA_SDCTL_RUN;
    hda_write32(hda, ctl_off, ctl);
    hda->running = true;
    hda->last_hw_update_ms = hda_now_ms();
    hda_log_hwpos(hda, "after-start");
    return true;
}

static uint32_t hda_hw_position(hda_state_t *hda)
{
    uint32_t lpib = hda_read32(hda, HDA_REG_SD_LPIB(HDA_STREAM_INDEX));
    if (hda->buffer_size == 0)
    {
        return 0;
    }
    return lpib % (uint32_t)hda->buffer_size;
}

static inline int16_t hda_scale_sample(int16_t sample, uint32_t volume_percent)
{
    if (volume_percent >= 100)
    {
        return sample;
    }
    if (volume_percent == 0)
    {
        return 0;
    }
    int32_t scaled = ((int32_t)sample * (int32_t)volume_percent) / 100;
    if (scaled > 32767)
    {
        scaled = 32767;
    }
    if (scaled < -32768)
    {
        scaled = -32768;
    }
    return (int16_t)scaled;
}

static void hda_copy_scaled_pcm(uint8_t *dst,
                                const uint8_t *src,
                                size_t len,
                                uint32_t volume_percent)
{
    if (!dst || !src || len == 0)
    {
        return;
    }
    if (volume_percent >= 100)
    {
        memcpy(dst, src, len);
        return;
    }

    for (size_t i = 0; i + 1 < len; i += 2)
    {
        int16_t sample = (int16_t)((uint16_t)src[i] | ((uint16_t)src[i + 1] << 8));
        int16_t scaled = hda_scale_sample(sample, volume_percent);
        dst[i] = (uint8_t)((uint16_t)scaled & 0xFFu);
        dst[i + 1] = (uint8_t)(((uint16_t)scaled >> 8) & 0xFFu);
    }
}

static void hda_copy_pcm_chunk(hda_state_t *hda,
                               uint8_t *dst,
                               const uint8_t *src,
                               size_t len,
                               uint32_t volume_percent)
{
    if (volume_percent > 100u)
    {
        volume_percent = 100u;
    }
    uint32_t target = (volume_percent * HDA_GAIN_ONE) / 100u;
    if (!hda->gain_initialized)
    {
        hda->gain_q16 = target;
        hda->target_gain_q16 = target;
        hda->gain_initialized = true;
    }
    else if (target != hda->target_gain_q16)
    {
        hda->target_gain_q16 = target;
        hda->gain_ramp_frames = HDA_GAIN_RAMP_FRAMES;
    }

    size_t fade_frames = hda->fade_in_frames;
    if (fade_frames < hda->gain_ramp_frames)
    {
        fade_frames = hda->gain_ramp_frames;
    }
    if (fade_frames > len / HDA_FRAME_BYTES)
    {
        fade_frames = len / HDA_FRAME_BYTES;
    }

    size_t faded_bytes = fade_frames * HDA_FRAME_BYTES;
    for (size_t frame = 0; frame < fade_frames; ++frame)
    {
        size_t i = frame * HDA_FRAME_BYTES;
        int16_t left = (int16_t)((uint16_t)src[i] | ((uint16_t)src[i + 1] << 8));
        int16_t right = (int16_t)((uint16_t)src[i + 2] | ((uint16_t)src[i + 3] << 8));
        if (hda->gain_ramp_frames > 0)
        {
            int32_t difference = (int32_t)hda->target_gain_q16 - (int32_t)hda->gain_q16;
            hda->gain_q16 = (uint32_t)((int32_t)hda->gain_q16 +
                difference / (int32_t)hda->gain_ramp_frames);
            hda->gain_ramp_frames--;
        }
        left = (int16_t)(((int32_t)left * (int32_t)hda->gain_q16) / (int32_t)HDA_GAIN_ONE);
        right = (int16_t)(((int32_t)right * (int32_t)hda->gain_q16) / (int32_t)HDA_GAIN_ONE);

        if (hda->fade_in_frames > 0)
        {
            uint32_t numerator = HDA_FADE_IN_FRAMES - hda->fade_in_frames + 1u;
            left = (int16_t)(((int32_t)left * (int32_t)numerator) /
                             (int32_t)HDA_FADE_IN_FRAMES);
            right = (int16_t)(((int32_t)right * (int32_t)numerator) /
                              (int32_t)HDA_FADE_IN_FRAMES);
            hda->fade_in_frames--;
        }

        dst[i] = (uint8_t)((uint16_t)left & 0xFFu);
        dst[i + 1] = (uint8_t)(((uint16_t)left >> 8) & 0xFFu);
        dst[i + 2] = (uint8_t)((uint16_t)right & 0xFFu);
        dst[i + 3] = (uint8_t)(((uint16_t)right >> 8) & 0xFFu);
    }

    if (faded_bytes < len)
    {
        hda_copy_scaled_pcm(dst + faded_bytes,
                            src + faded_bytes,
                            len - faded_bytes,
                            volume_percent);
    }
}

static bool hda_claim_writer_locked(hda_state_t *hda, uint64_t pid)
{
    if (hda->writer_claimed && hda->writer_pid != pid && hda->used_bytes > 0)
    {
        hda->rejected_writers++;
        return false;
    }
    /* A drained stream can change owners, including after a producer exits. */
    hda->writer_pid = pid;
    hda->writer_claimed = true;
    return true;
}

static ssize_t hda_dev_write(vfs_node_t *node,
                             size_t offset,
                             const void *buffer,
                             size_t count,
                             void *context)
{
    (void)node;
    hda_state_t *hda = (hda_state_t *)context;
    if (count == 0)
    {
        return 0;
    }
    if (!hda || !buffer ||
        (count % HDA_FRAME_BYTES) != 0 ||
        (offset % HDA_FRAME_BYTES) != 0)
    {
        return -1;
    }

    const uint8_t *src = (const uint8_t *)buffer;
    uint64_t writer_pid = process_current_pid();
    size_t written = 0;

    while (written < count)
    {
        spinlock_lock(&hda->lock);

        if (hda->reconfiguring)
        {
            spinlock_unlock(&hda->lock);
            process_sleep_ms(1);
            continue;
        }

        hda_service_locked(hda);
        if (!hda_claim_writer_locked(hda, writer_pid))
        {
            spinlock_unlock(&hda->lock);
            return written > 0 ? (ssize_t)written : -1;
        }

        if (hda->running)
        {
            if (hda->used_bytes == 0 && !hda->needs_reprogram)
            {
                uint32_t hw_pos = hda_hw_position(hda);
                /*
                 * RUN must remain set across a short producer gap: QEMU keeps
                 * up to 8 KiB of already-fetched audio in its codec buffer and
                 * discards it on a RUN transition.  Re-prime after a silent
                 * lead instead of stopping or writing under the DMA cursor.
                 */
                hda_clear_ring_range(hda, hw_pos, HDA_REPRIME_LEAD_BYTES);
                hda->write_pos = ((size_t)hw_pos + HDA_REPRIME_LEAD_BYTES) %
                                 hda->buffer_size;
                hda->used_bytes = HDA_REPRIME_LEAD_BYTES;
                hda->hw_pos_prev = hw_pos;
                hda->last_hw_update_ms = hda_now_ms();
                hda->fade_in_frames = HDA_FADE_IN_FRAMES;
                hda->reprime_events++;
            }
        }

        if (hda->needs_reprogram)
        {
            hda->reconfiguring = true;
            spinlock_unlock(&hda->lock);

            bool programmed = hda_program_stream(hda);

            spinlock_lock(&hda->lock);
            hda->needs_reprogram = !programmed;
            hda->reconfiguring = false;
            spinlock_unlock(&hda->lock);
            if (!programmed)
            {
                return written > 0 ? (ssize_t)written : -1;
            }
            continue;
        }

        bool start_after_copy = !hda->running;
        if (start_after_copy && hda->used_bytes == 0)
        {
            hda->first_queued_ms = hda_now_ms();
        }

        size_t max_queue = (hda->buffer_size > 0) ? (hda->buffer_size - 1u) : 0u;
        if (max_queue > HDA_MAX_QUEUED_BYTES)
        {
            max_queue = HDA_MAX_QUEUED_BYTES;
        }
        size_t free_bytes = (max_queue > hda->used_bytes)
            ? (max_queue - hda->used_bytes)
            : 0u;
        free_bytes -= free_bytes % HDA_FRAME_BYTES;
        if (free_bytes == 0)
        {
            hda_log_hwpos(hda, "write-wait");
            spinlock_unlock(&hda->lock);
            /* Avoid busy-spinning when the hardware lags; sleep briefly. */
            process_sleep_ms(1);
            continue;
        }

        size_t remaining = count - written;
        size_t chunk = (remaining < free_bytes) ? remaining : free_bytes;
        size_t to_end = hda->buffer_size - hda->write_pos;
        size_t first = (chunk < to_end) ? chunk : to_end;
        uint32_t volume = audio_volume_get_percent();
        hda_copy_pcm_chunk(hda,
                           hda->buffer + hda->write_pos,
                           src + written,
                           first,
                           volume);
        hda->write_pos = (hda->write_pos + first) % hda->buffer_size;
        hda->used_bytes += first;
        written += first;

        if (first < chunk)
        {
            size_t second = chunk - first;
            hda_copy_pcm_chunk(hda,
                               hda->buffer + hda->write_pos,
                               src + written,
                               second,
                               volume);
            hda->write_pos = (hda->write_pos + second) % hda->buffer_size;
            hda->used_bytes += second;
            written += second;
        }
        if (start_after_copy && hda->used_bytes >= HDA_START_QUEUED_BYTES)
        {
            /* Publish the complete prebuffer before the controller can fetch it. */
            __atomic_thread_fence(__ATOMIC_RELEASE);
            if (!hda_start_stream(hda))
            {
                hda->needs_reprogram = true;
                spinlock_unlock(&hda->lock);
                return -1;
            }
        }
        spinlock_unlock(&hda->lock);
    }

    return (ssize_t)written;
}

bool hda_get_status(hda_status_t *status)
{
    if (!status || !__atomic_load_n(&g_hda_ready, __ATOMIC_ACQUIRE))
    {
        return false;
    }
    spinlock_lock(&g_hda.lock);
    /* Stream reprogramming owns the DMA/accounting fields outside this lock. */
    status->queued_bytes = g_hda.reconfiguring ? 0 : g_hda.used_bytes;
    status->running = !g_hda.reconfiguring && g_hda.running;
    status->empty_events = g_hda.empty_events;
    status->reprime_events = g_hda.reprime_events;
    status->stream_errors = g_hda.stream_errors;
    status->rejected_writers = g_hda.rejected_writers;
    status->writer_pid = g_hda.writer_pid;
    spinlock_unlock(&g_hda.lock);
    return true;
}

void hda_init(void)
{
    memset(&g_hda, 0, sizeof(g_hda));
    spinlock_init(&g_hda.lock);

    pci_device_t dev;
    bool found = false;

    /* Look for an Intel HD Audio controller (class 0x04, subclass 0x03). */
    for (uint16_t bus = 0; bus < 32 && !found; ++bus)
    {
        for (uint8_t device = 0; device < 32 && !found; ++device)
        {
            for (uint8_t fn = 0; fn < 8 && !found; ++fn)
            {
                pci_device_t candidate = { .bus = (uint8_t)bus, .device = device, .function = fn };
                uint16_t vendor = pci_config_read16(candidate, 0x00);
                if (vendor == 0xFFFF)
                {
                    if (fn == 0)
                    {
                        break;
                    }
                    continue;
                }
                uint32_t class_prog = pci_config_read32(candidate, 0x08);
                uint8_t class_code = (uint8_t)(class_prog >> 24);
                uint8_t subclass = (uint8_t)(class_prog >> 16);
                if (class_code == 0x04 && subclass == 0x03)
                {
                    dev = candidate;
                    found = true;
                }
            }
        }
    }

    if (!found)
    {
        serial_printf("[hda] controller not found\r\n");
        return;
    }

    pci_set_command_bits(dev, 0x0006u, 0);

    uint32_t bar_low = pci_config_read32(dev, 0x10);
    uint64_t base = (uint64_t)(bar_low & ~0xFu);
    if (bar_low & 0x04)
    {
        uint32_t bar_high = pci_config_read32(dev, 0x14);
        base |= ((uint64_t)bar_high << 32);
    }
    if (!base)
    {
        serial_printf("[hda] BAR0 invalid\r\n");
        return;
    }

    g_hda.regs = (volatile uint8_t *)ioremap((paddr_t)base, (size_t)HDA_MMIO_BYTES);
    if (!g_hda.regs)
    {
        serial_printf("%s", "[hda] ioremap failed\r\n");
        return;
    }
    g_hda.codec_id = 0;
    g_hda.running = false;

    if (!hda_prepare_corb_rirb(&g_hda))
    {
        serial_printf("[hda] failed to allocate corb/rirb\r\n");
        return;
    }

    serial_printf("[hda] BAR0=0x%llX\r\n", (unsigned long long)base);
    uint32_t gcap = hda_read32(&g_hda, 0x00);
    uint32_t stat = hda_read16(&g_hda, HDA_REG_STATESTS);
    uint32_t stat_initial = stat;
    serial_printf("[hda] gcap=0x%08X stat=0x%04X\r\n", gcap, stat);

    if (!hda_reset_controller(&g_hda))
    {
        return;
    }

    /* Clear and wait for codec presence. */
    hda_write16(&g_hda, HDA_REG_STATESTS, 0xFFFFu);
    hda_write16(&g_hda, HDA_REG_WAKEEN, 0xFFFFu);
    uint16_t codec_mask = 0;
    (void)hda_wait_codecs(&g_hda, &codec_mask);
    if (!codec_mask)
    {
        /* Allow extra settle time and retry detection. */
        hda_busy_wait(1000000);
        (void)hda_wait_codecs(&g_hda, &codec_mask);
    }
    stat = hda_read16(&g_hda, HDA_REG_STATESTS);
    serial_printf("[hda] post-reset stat=0x%04X mask=0x%04X\r\n", stat, codec_mask);
    if (!codec_mask && stat_initial)
    {
        codec_mask = (uint16_t)stat_initial;
        serial_printf("[hda] using initial codec mask=0x%04X\r\n", codec_mask);
    }
    if (!codec_mask)
    {
        serial_printf("[hda] no codecs reported\r\n");
        return;
    }
    /* Give codecs a brief settle window after detection. */
    hda_busy_wait(1000000);

    uint8_t corbctl = hda_read8(&g_hda, HDA_REG_CORBCTL);
    uint8_t rirbctl = hda_read8(&g_hda, HDA_REG_RIRBCTL);
    uint8_t corbsize = hda_read8(&g_hda, HDA_REG_CORBSIZE);
    uint8_t rirbsize = hda_read8(&g_hda, HDA_REG_RIRBSIZE);
    uint16_t corbrp = hda_read16(&g_hda, HDA_REG_CORBRP);
    uint16_t corbwp = hda_read16(&g_hda, HDA_REG_CORBWP);
    uint16_t rirbwp = hda_read16(&g_hda, HDA_REG_RIRBWP);
    serial_printf("[hda] corbctl=0x%02X rirbctl=0x%02X corbsize=0x%02X rirbsize=0x%02X corbrp=0x%04X corbwp=0x%04X rirbwp=0x%04X\r\n",
                  corbctl, rirbctl, corbsize, rirbsize, corbrp, corbwp, rirbwp);

    for (uint8_t idx = 0; idx < 15; ++idx)
    {
        if (codec_mask & (1u << idx))
        {
            g_hda.codec_id = idx;
            break;
        }
    }

    /* Disable interrupts until we have explicit handling. */
    hda_write32(&g_hda, HDA_REG_INTCTL, 0);
    hda_write32(&g_hda, HDA_REG_INTSTS, 0xFFFFFFFFu);
    hda_write16(&g_hda, HDA_REG_WAKEEN, 0);

    if (!hda_pick_nodes(&g_hda))
    {
        return;
    }
    if (!hda_program_stream(&g_hda))
    {
        return;
    }

    if (!process_create_kernel("hda_idle", hda_housekeeping, NULL, PROCESS_DEFAULT_STACK_SIZE, -1))
    {
        serial_printf("[hda] failed to start housekeeping thread\r\n");
        return;
    }

    if (!devfs_register_file("audio", NULL, hda_dev_write, &g_hda))
    {
        serial_printf("[hda] /dev/audio registration failed\r\n");
        return;
    }

    __atomic_store_n(&g_hda_ready, true, __ATOMIC_RELEASE);
    serial_printf("[hda] output ready on /dev/audio\r\n");
}
