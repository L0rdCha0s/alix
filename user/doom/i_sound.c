// AlixOS usermode sound backend for DOOM.
// Implements DOOM's I_*Sound hooks by streaming PCM to /dev/audio.

#include "i_sound.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "serial.h"
#include "usyscall.h"
#include "w_wad.h"
#include "z_zone.h"

enum
{
    AUDIO_OUTPUT_RATE_HZ = 48000,
    AUDIO_CHANNELS = 2,
    AUDIO_BYTES_PER_SAMPLE = 2,
    AUDIO_BYTES_PER_FRAME = AUDIO_CHANNELS * AUDIO_BYTES_PER_SAMPLE,

    MIX_MAX_FRAMES = 2048,
    MIX_NUM_CHANNELS = 8,
    DMX_HEADER_BYTES = 8,
};

typedef struct
{
    bool active;
    int handle;
    int sfx_id;

    const uint8_t *data;
    uint32_t data_len;
    uint32_t src_rate_hz;

    uint32_t pos_fp;
    uint32_t step_fp;

    int left_vol;
    int right_vol;

    uint32_t start_seq;
} mix_channel_t;

static int g_audio_fd = -1;
static uint64_t g_audio_last_ms = 0;
static uint32_t g_audio_frac = 0;
static uint64_t g_audio_retry_ms = 0;

static int g_next_handle = 1;
static uint32_t g_start_seq = 0;

static mix_channel_t g_channels[MIX_NUM_CHANNELS];
static int16_t g_mix_buffer[MIX_MAX_FRAMES * AUDIO_CHANNELS];

static uint32_t g_sfx_lengths[NUMSFX];
static uint32_t g_sfx_rates[NUMSFX];

static uint16_t read_le16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_le32(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static int clamp_int(int v, int lo, int hi)
{
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

static void update_channel_vol(mix_channel_t *ch, int vol, int sep)
{
    if (!ch) return;
    vol = clamp_int(vol, 0, 127);
    sep = clamp_int(sep, 0, 255);

    ch->left_vol = (vol * (255 - sep)) / 255;
    ch->right_vol = (vol * sep) / 255;
}

static uint32_t compute_step_fp(uint32_t src_rate_hz, int pitch)
{
    if (src_rate_hz == 0)
    {
        src_rate_hz = 11025;
    }
    pitch = clamp_int(pitch, 0, 255);

    uint32_t base_step = (uint32_t)(((uint64_t)src_rate_hz << 16) / (uint64_t)AUDIO_OUTPUT_RATE_HZ);
    if (base_step == 0)
    {
        base_step = 1;
    }

    // Pitch is nominally centered at 128; keep it simple for now.
    // (We can add steptable-style exponential scaling later.)
    int delta = pitch - 128;
    int32_t pitch_fp = 65536 + (delta * 256);
    if (pitch_fp < 16384)
    {
        pitch_fp = 16384;
    }

    return (uint32_t)(((uint64_t)base_step * (uint64_t)(uint32_t)pitch_fp) >> 16);
}

static void mix_frames(int16_t *out_interleaved, uint32_t frames)
{
    if (!out_interleaved || frames == 0)
    {
        return;
    }

    for (uint32_t i = 0; i < frames; ++i)
    {
        int32_t left = 0;
        int32_t right = 0;

        for (int c = 0; c < MIX_NUM_CHANNELS; ++c)
        {
            mix_channel_t *ch = &g_channels[c];
            if (!ch->active || !ch->data || ch->data_len == 0)
            {
                continue;
            }

            uint32_t idx = ch->pos_fp >> 16;
            if (idx >= ch->data_len)
            {
                ch->active = false;
                continue;
            }

            int32_t sample = ((int32_t)ch->data[idx] - 128) << 8;

            left += (sample * ch->left_vol) / 127;
            right += (sample * ch->right_vol) / 127;

            ch->pos_fp += ch->step_fp;
        }

        if (left > 32767) left = 32767;
        if (left < -32768) left = -32768;
        if (right > 32767) right = 32767;
        if (right < -32768) right = -32768;

        out_interleaved[i * 2 + 0] = (int16_t)left;
        out_interleaved[i * 2 + 1] = (int16_t)right;
    }
}

static void audio_pump(void)
{
    if (g_audio_fd < 0)
    {
        return;
    }

    uint64_t now_ms = sys_time_millis();
    if (g_audio_last_ms == 0)
    {
        g_audio_last_ms = now_ms;
        // Prime a small amount of silence to avoid immediate underruns while the
        // game is still starting up / frame pacing stabilizes.
        uint32_t prime_frames = (uint32_t)(AUDIO_OUTPUT_RATE_HZ / 20); // ~50ms
        while (prime_frames > 0)
        {
            uint32_t chunk = prime_frames;
            if (chunk > MIX_MAX_FRAMES)
            {
                chunk = MIX_MAX_FRAMES;
            }
            mix_frames(g_mix_buffer, chunk);
            size_t bytes = (size_t)chunk * AUDIO_BYTES_PER_FRAME;
            ssize_t wrote = write(g_audio_fd, g_mix_buffer, bytes);
            if (wrote <= 0)
            {
                break;
            }
            if ((size_t)wrote < bytes)
            {
                break;
            }
            prime_frames -= chunk;
        }
        return;
    }

    uint64_t delta_ms = now_ms - g_audio_last_ms;
    if (delta_ms == 0)
    {
        return;
    }

    // Clamp catch-up to keep worst-case latency bounded.
    if (delta_ms > 200)
    {
        delta_ms = 200;
    }
    g_audio_last_ms = now_ms;

    uint64_t total = delta_ms * (uint64_t)AUDIO_OUTPUT_RATE_HZ + (uint64_t)g_audio_frac;
    uint32_t frames = (uint32_t)(total / 1000ULL);
    g_audio_frac = (uint32_t)(total % 1000ULL);

    while (frames > 0)
    {
        uint32_t chunk = frames;
        if (chunk > MIX_MAX_FRAMES)
        {
            chunk = MIX_MAX_FRAMES;
        }

        mix_frames(g_mix_buffer, chunk);

        size_t bytes = (size_t)chunk * AUDIO_BYTES_PER_FRAME;
        ssize_t wrote = write(g_audio_fd, g_mix_buffer, bytes);
        if (wrote <= 0)
        {
            close(g_audio_fd);
            g_audio_fd = -1;
            g_audio_last_ms = 0;
            g_audio_frac = 0;
            break;
        }

        if ((size_t)wrote < bytes)
        {
            // Partial writes are unexpected for /dev/audio, but avoid stalling.
            close(g_audio_fd);
            g_audio_fd = -1;
            g_audio_last_ms = 0;
            g_audio_frac = 0;
            break;
        }

        frames -= chunk;
    }
}

void I_InitSound(void)
{
    if (g_audio_fd >= 0)
    {
        return;
    }

    g_audio_fd = open("/dev/audio", O_WRONLY);
    if (g_audio_fd < 0)
    {
        serial_printf("[doom][sound] /dev/audio unavailable; continuing without sound\n");
    }

    memset(g_sfx_lengths, 0, sizeof(g_sfx_lengths));
    memset(g_sfx_rates, 0, sizeof(g_sfx_rates));

    // Pre-cache all sound effects (Linux DOOM mixing expects sfx->data pointers).
    for (int i = 1; i < NUMSFX; ++i)
    {
        if (S_sfx[i].link)
        {
            continue;
        }

        int lump = I_GetSfxLumpNum(&S_sfx[i]);
        int lump_size = W_LumpLength(lump);
        if (lump_size <= DMX_HEADER_BYTES)
        {
            continue;
        }

        uint8_t *raw = (uint8_t *)W_CacheLumpNum(lump, PU_STATIC);
        uint32_t sample_rate = read_le16(raw + 2);
        uint32_t sample_count = read_le32(raw + 4);
        uint32_t available = (uint32_t)(lump_size - DMX_HEADER_BYTES);
        if (sample_count == 0 || sample_count > available)
        {
            sample_count = available;
        }
        if (sample_rate == 0)
        {
            sample_rate = 11025;
        }

        S_sfx[i].data = raw + DMX_HEADER_BYTES;
        g_sfx_lengths[i] = sample_count;
        g_sfx_rates[i] = sample_rate;
    }

    for (int i = 1; i < NUMSFX; ++i)
    {
        if (!S_sfx[i].link)
        {
            continue;
        }

        int link_index = (int)(S_sfx[i].link - S_sfx);
        if (link_index <= 0 || link_index >= NUMSFX)
        {
            continue;
        }

        S_sfx[i].data = S_sfx[link_index].data;
        g_sfx_lengths[i] = g_sfx_lengths[link_index];
        g_sfx_rates[i] = g_sfx_rates[link_index];
    }

    for (int c = 0; c < MIX_NUM_CHANNELS; ++c)
    {
        g_channels[c].active = false;
        g_channels[c].handle = 0;
        g_channels[c].sfx_id = 0;
        g_channels[c].data = NULL;
        g_channels[c].data_len = 0;
        g_channels[c].src_rate_hz = 0;
        g_channels[c].pos_fp = 0;
        g_channels[c].step_fp = 0;
        g_channels[c].left_vol = 0;
        g_channels[c].right_vol = 0;
        g_channels[c].start_seq = 0;
    }

    g_audio_last_ms = 0;
    g_audio_frac = 0;
}

void I_ShutdownSound(void)
{
    if (g_audio_fd >= 0)
    {
        close(g_audio_fd);
        g_audio_fd = -1;
    }
    g_audio_retry_ms = 0;
}

void I_UpdateSound(void)
{
    // Keep mixing/output in I_SubmitSound (called once per frame).
}

void I_SubmitSound(void)
{
    if (g_audio_fd < 0)
    {
        uint64_t now_ms = sys_time_millis();
        if (g_audio_retry_ms == 0 || (now_ms - g_audio_retry_ms) >= 1000ULL)
        {
            g_audio_retry_ms = now_ms;
            g_audio_fd = open("/dev/audio", O_WRONLY);
            if (g_audio_fd >= 0)
            {
                g_audio_last_ms = 0;
                g_audio_frac = 0;
            }
        }
    }
    audio_pump();
}

void I_SetChannels(void)
{
    // Reset runtime mixing channels. (S_Init calls this.)
    for (int c = 0; c < MIX_NUM_CHANNELS; ++c)
    {
        g_channels[c].active = false;
        g_channels[c].handle = 0;
        g_channels[c].sfx_id = 0;
        g_channels[c].data = NULL;
        g_channels[c].data_len = 0;
        g_channels[c].src_rate_hz = 0;
        g_channels[c].pos_fp = 0;
        g_channels[c].step_fp = 0;
        g_channels[c].left_vol = 0;
        g_channels[c].right_vol = 0;
        g_channels[c].start_seq = 0;
    }
}

int I_GetSfxLumpNum(sfxinfo_t *sfxinfo)
{
    if (!sfxinfo || !sfxinfo->name)
    {
        return W_GetNumForName("dspistol");
    }

    char namebuf[9];
    namebuf[0] = 'd';
    namebuf[1] = 's';
    strncpy(namebuf + 2, sfxinfo->name, sizeof(namebuf) - 3);
    namebuf[sizeof(namebuf) - 1] = '\0';

    int lump = W_CheckNumForName(namebuf);
    if (lump == -1)
    {
        lump = W_GetNumForName("dspistol");
    }
    return lump;
}

static bool is_singular_sfx(int sfx_id)
{
    return sfx_id == sfx_sawup
        || sfx_id == sfx_sawidl
        || sfx_id == sfx_sawful
        || sfx_id == sfx_sawhit
        || sfx_id == sfx_stnmov
        || sfx_id == sfx_pistol;
}

int I_StartSound(int id, int vol, int sep, int pitch, int priority)
{
    (void)priority;

    if (id <= 0 || id >= NUMSFX)
    {
        return g_next_handle++;
    }

    const uint8_t *data = (const uint8_t *)S_sfx[id].data;
    uint32_t len = g_sfx_lengths[id];
    uint32_t src_rate = g_sfx_rates[id];
    if (!data || len == 0)
    {
        return g_next_handle++;
    }

    if (is_singular_sfx(id))
    {
        for (int c = 0; c < MIX_NUM_CHANNELS; ++c)
        {
            if (g_channels[c].active && g_channels[c].sfx_id == id)
            {
                g_channels[c].active = false;
            }
        }
    }

    int slot = -1;
    for (int c = 0; c < MIX_NUM_CHANNELS; ++c)
    {
        if (!g_channels[c].active)
        {
            slot = c;
            break;
        }
    }
    if (slot < 0)
    {
        uint32_t oldest_seq = UINT32_MAX;
        int oldest_idx = 0;
        for (int c = 0; c < MIX_NUM_CHANNELS; ++c)
        {
            if (g_channels[c].start_seq < oldest_seq)
            {
                oldest_seq = g_channels[c].start_seq;
                oldest_idx = c;
            }
        }
        slot = oldest_idx;
    }

    int handle = g_next_handle++;

    mix_channel_t *ch = &g_channels[slot];
    ch->active = true;
    ch->handle = handle;
    ch->sfx_id = id;
    ch->data = data;
    ch->data_len = len;
    ch->src_rate_hz = src_rate ? src_rate : 11025;
    ch->pos_fp = 0;
    ch->step_fp = compute_step_fp(ch->src_rate_hz, pitch);
    update_channel_vol(ch, vol, sep);
    ch->start_seq = ++g_start_seq;

    return handle;
}

void I_StopSound(int handle)
{
    for (int c = 0; c < MIX_NUM_CHANNELS; ++c)
    {
        if (g_channels[c].active && g_channels[c].handle == handle)
        {
            g_channels[c].active = false;
            return;
        }
    }
}

int I_SoundIsPlaying(int handle)
{
    for (int c = 0; c < MIX_NUM_CHANNELS; ++c)
    {
        if (g_channels[c].active && g_channels[c].handle == handle)
        {
            return 1;
        }
    }
    return 0;
}

void I_UpdateSoundParams(int handle, int vol, int sep, int pitch)
{
    for (int c = 0; c < MIX_NUM_CHANNELS; ++c)
    {
        mix_channel_t *ch = &g_channels[c];
        if (!ch->active || ch->handle != handle)
        {
            continue;
        }
        update_channel_vol(ch, vol, sep);
        ch->step_fp = compute_step_fp(ch->src_rate_hz, pitch);
        return;
    }
}

void I_InitMusic(void) {}
void I_ShutdownMusic(void) {}

void I_SetMusicVolume(int volume)
{
    (void)volume;
}

void I_PauseSong(int handle)
{
    (void)handle;
}

void I_ResumeSong(int handle)
{
    (void)handle;
}

int I_RegisterSong(void *data)
{
    (void)data;
    return 1;
}

void I_PlaySong(int handle, int looping)
{
    (void)handle;
    (void)looping;
}

void I_StopSong(int handle)
{
    (void)handle;
}

void I_UnRegisterSong(int handle)
{
    (void)handle;
}
