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
static uint32_t g_audio_queued_frames = 0;
static uint64_t g_audio_retry_ms = 0;

static int g_next_handle = 1;
static uint32_t g_start_seq = 0;

static mix_channel_t g_channels[MIX_NUM_CHANNELS];
static int16_t g_mix_buffer[MIX_MAX_FRAMES * AUDIO_CHANNELS];

static uint32_t g_sfx_lengths[NUMSFX];
static uint32_t g_sfx_rates[NUMSFX];

enum
{
    MUS_TICKS_PER_SEC = 140,
    MUSIC_MAX_VOICES = 16,
    MUSIC_BASE_AMPLITUDE = 3500,
};

typedef enum
{
    MUSIC_WAVE_SQUARE = 0,
    MUSIC_WAVE_NOISE = 1,
} music_wave_t;

typedef struct
{
    bool active;
    uint8_t channel;
    uint8_t note;
    uint8_t wave;
    uint32_t phase;
    uint32_t step;
    int32_t amp;
    int32_t amp_target;
    uint8_t pan_l;
    uint8_t pan_r;
    uint32_t age;
} music_voice_t;

typedef struct
{
    bool loaded;
    bool playing;
    bool paused;
    bool looping;
    int handle;

    const uint8_t *data;
    const uint8_t *score;
    const uint8_t *pos;
    const uint8_t *end;
    uint32_t wait_ticks;
    uint32_t tick_accum;

    uint8_t chan_volume[16];
    uint8_t chan_pan[16];
    uint8_t chan_program[16];
    uint8_t chan_pitch[16];

    int volume;
} music_state_t;

static music_state_t g_music;
static music_voice_t g_music_voices[MUSIC_MAX_VOICES];
static uint32_t g_music_voice_seq = 0;
static uint32_t g_music_noise = 0x12345678u;

static const uint32_t g_music_note_step_48k[128] =
{
    0x000B29A6u, 0x000BD393u, 0x000C879Au, 0x000D4656u, 0x000E1069u, 0x000EE681u, 0x000FC953u, 0x0010B9A3u,
    0x0011B83Cu, 0x0012C5F9u, 0x0013E3C0u, 0x00151286u, 0x0016534Cu, 0x0017A726u, 0x00190F34u, 0x001A8CACu,
    0x001C20D3u, 0x001DCD02u, 0x001F92A7u, 0x00217345u, 0x00237078u, 0x00258BF2u, 0x0027C781u, 0x002A250Cu,
    0x002CA698u, 0x002F4E4Bu, 0x00321E69u, 0x00351958u, 0x003841A6u, 0x003B9A04u, 0x003F254Eu, 0x0042E68Bu,
    0x0046E0F0u, 0x004B17E5u, 0x004F8F01u, 0x00544A17u, 0x00594D31u, 0x005E9C96u, 0x00643CD2u, 0x006A32B1u,
    0x0070834Cu, 0x00773407u, 0x007E4A9Bu, 0x0085CD15u, 0x008DC1E1u, 0x00962FC9u, 0x009F1E03u, 0x00A8942Eu,
    0x00B29A62u, 0x00BD392Du, 0x00C879A3u, 0x00D46562u, 0x00E10697u, 0x00EE680Fu, 0x00FC9536u, 0x010B9A2Bu,
    0x011B83C2u, 0x012C5F93u, 0x013E3C06u, 0x0151285Du, 0x016534C3u, 0x017A725Au, 0x0190F347u, 0x01A8CAC3u,
    0x01C20D2Fu, 0x01DCD01Du, 0x01F92A6Du, 0x02173456u, 0x02370783u, 0x0258BF26u, 0x027C780Bu, 0x02A250BAu,
    0x02CA6987u, 0x02F4E4B4u, 0x0321E68Du, 0x03519586u, 0x03841A5Du, 0x03B9A03Au, 0x03F254D9u, 0x042E68ACu,
    0x046E0F07u, 0x04B17E4Bu, 0x04F8F017u, 0x0544A173u, 0x0594D30Du, 0x05E9C968u, 0x0643CD1Bu, 0x06A32B0Du,
    0x070834BAu, 0x07734075u, 0x07E4A9B2u, 0x085CD157u, 0x08DC1E0Du, 0x0962FC96u, 0x09F1E02Du, 0x0A8942E7u,
    0x0B29A61Au, 0x0BD392D0u, 0x0C879A35u, 0x0D46561Au, 0x0E106974u, 0x0EE680E9u, 0x0FC95364u, 0x10B9A2AFu,
    0x11B83C1Au, 0x12C5F92Cu, 0x13E3C05Au, 0x151285CEu, 0x16534C35u, 0x17A725A0u, 0x190F346Au, 0x1A8CAC34u,
    0x1C20D2E8u, 0x1DCD01D3u, 0x1F92A6C8u, 0x2173455Eu, 0x23707835u, 0x258BF259u, 0x27C780B5u, 0x2A250B9Cu,
    0x2CA6986Au, 0x2F4E4B3Fu, 0x321E68D4u, 0x35195868u, 0x3841A5D1u, 0x3B9A03A6u, 0x3F254D91u, 0x42E68ABCu,
};

enum
{
    // Keep a small amount of audio queued to avoid underruns but also avoid
    // the ~1s latency that can build up if we continuously write too far ahead.
    AUDIO_TARGET_LATENCY_MS = 60,
};

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
    // DOOM uses a 0..15 slider for snd_SfxVolume (see m_menu.c) but the
    // original mixer operates on a 0..127 volume range. Map 0..15 -> 0..127
    // so effects are audible on AlixOS's /dev/audio output.
    int volume127;
    if (vol <= 15)
    {
        vol = clamp_int(vol, 0, 15);
        volume127 = (vol * 127 + 7) / 15;
    }
    else
    {
        volume127 = clamp_int(vol, 0, 127);
    }
    sep = clamp_int(sep, 0, 255);

    // Match the original Linux DOOM left/right volume curve, including the
    // "squared" stereo separation.
    int seperation = sep + 1; // 1..256
    int left = volume127 - ((volume127 * seperation * seperation) >> 16);
    seperation = seperation - 257; // -256..-1
    int right = volume127 - ((volume127 * seperation * seperation) >> 16);
    ch->left_vol = clamp_int(left, 0, 127);
    ch->right_vol = clamp_int(right, 0, 127);
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

static void music_voices_reset(void)
{
    for (int i = 0; i < MUSIC_MAX_VOICES; ++i)
    {
        g_music_voices[i].active = false;
        g_music_voices[i].channel = 0;
        g_music_voices[i].note = 0;
        g_music_voices[i].wave = MUSIC_WAVE_SQUARE;
        g_music_voices[i].phase = 0;
        g_music_voices[i].step = 0;
        g_music_voices[i].amp = 0;
        g_music_voices[i].amp_target = 0;
        g_music_voices[i].pan_l = 64;
        g_music_voices[i].pan_r = 64;
        g_music_voices[i].age = 0;
    }
    g_music_voice_seq = 0;
}

static void music_all_notes_off(void)
{
    for (int i = 0; i < MUSIC_MAX_VOICES; ++i)
    {
        if (g_music_voices[i].active)
        {
            g_music_voices[i].amp_target = 0;
        }
    }
}

static music_wave_t music_wave_for_channel(uint8_t channel)
{
    // Treat channel 9 as percussion (MIDI convention).
    if ((channel & 0x0Fu) == 9)
    {
        return MUSIC_WAVE_NOISE;
    }
    return MUSIC_WAVE_SQUARE;
}

static uint32_t music_step_for_note(uint8_t channel, uint8_t note)
{
    uint32_t base_step = g_music_note_step_48k[note & 0x7Fu];

    uint8_t pitch = g_music.chan_pitch[channel & 0x0Fu];
    int delta = (int)pitch - 64;
    int32_t pitch_fp = 65536 + (delta * 128);
    if (pitch_fp < 32768)
    {
        pitch_fp = 32768;
    }
    if (pitch_fp > 98304)
    {
        pitch_fp = 98304;
    }

    return (uint32_t)(((uint64_t)base_step * (uint64_t)(uint32_t)pitch_fp) >> 16);
}

static void music_note_on(uint8_t channel, uint8_t note, uint8_t volume)
{
    if (!g_music.loaded)
    {
        return;
    }
    channel &= 0x0Fu;
    note &= 0x7Fu;
    volume &= 0x7Fu;

    uint8_t pan = g_music.chan_pan[channel];
    uint8_t pan_r = pan;
    uint8_t pan_l = (uint8_t)(127 - pan);

    int mv = g_music.volume;
    if (mv <= 0)
    {
        return;
    }
    int32_t amp_target = (int32_t)(((int64_t)volume * (int64_t)mv * (int64_t)MUSIC_BASE_AMPLITUDE) / (127LL * 127LL));
    if (amp_target <= 0)
    {
        return;
    }

    int slot = -1;
    for (int i = 0; i < MUSIC_MAX_VOICES; ++i)
    {
        music_voice_t *v = &g_music_voices[i];
        if (v->active && v->channel == channel && v->note == note)
        {
            slot = i;
            break;
        }
    }
    if (slot < 0)
    {
        for (int i = 0; i < MUSIC_MAX_VOICES; ++i)
        {
            if (!g_music_voices[i].active)
            {
                slot = i;
                break;
            }
        }
    }
    if (slot < 0)
    {
        uint32_t oldest = UINT32_MAX;
        int oldest_idx = 0;
        for (int i = 0; i < MUSIC_MAX_VOICES; ++i)
        {
            if (g_music_voices[i].age < oldest)
            {
                oldest = g_music_voices[i].age;
                oldest_idx = i;
            }
        }
        slot = oldest_idx;
    }

    music_voice_t *v = &g_music_voices[slot];
    v->active = true;
    v->channel = channel;
    v->note = note;
    v->wave = (uint8_t)music_wave_for_channel(channel);
    v->phase = 0;
    v->step = music_step_for_note(channel, note);
    v->amp = 0;
    v->amp_target = amp_target;
    v->pan_l = pan_l;
    v->pan_r = pan_r;
    v->age = ++g_music_voice_seq;
}

static void music_note_off(uint8_t channel, uint8_t note)
{
    channel &= 0x0Fu;
    note &= 0x7Fu;
    for (int i = 0; i < MUSIC_MAX_VOICES; ++i)
    {
        music_voice_t *v = &g_music_voices[i];
        if (v->active && v->channel == channel && v->note == note)
        {
            v->amp_target = 0;
        }
    }
}

static void music_update_channel_pitch(uint8_t channel)
{
    channel &= 0x0Fu;
    for (int i = 0; i < MUSIC_MAX_VOICES; ++i)
    {
        music_voice_t *v = &g_music_voices[i];
        if (v->active && v->channel == channel)
        {
            v->step = music_step_for_note(channel, v->note);
        }
    }
}

static void music_reset_cursor(void)
{
    g_music.pos = g_music.score;
    g_music.wait_ticks = 0;
    g_music.tick_accum = 0;
    for (int c = 0; c < 16; ++c)
    {
        g_music.chan_volume[c] = 127;
        g_music.chan_pan[c] = 64;
        g_music.chan_program[c] = 0;
        g_music.chan_pitch[c] = 64;
    }
    music_voices_reset();
}

static uint32_t mus_read_delay(const uint8_t **pos, const uint8_t *end)
{
    if (!pos || !*pos)
    {
        return 0;
    }
    const uint8_t *p = *pos;
    uint32_t delay = 0;
    uint32_t shift = 0;
    while (p < end)
    {
        uint8_t b = *p++;
        delay |= (uint32_t)(b & 0x7Fu) << shift;
        if ((b & 0x80u) == 0)
        {
            break;
        }
        shift += 7;
        if (shift > 28)
        {
            break;
        }
    }
    *pos = p;
    return delay;
}

static void music_tick(void)
{
    if (!g_music.loaded || !g_music.playing || g_music.paused)
    {
        return;
    }

    if (g_music.wait_ticks > 0)
    {
        g_music.wait_ticks--;
        return;
    }

    while (g_music.pos && g_music.pos < g_music.end)
    {
        uint8_t ev = *g_music.pos++;
        uint8_t channel = (uint8_t)(ev & 0x0Fu);
        uint8_t type = (uint8_t)((ev >> 4) & 0x07u);
        bool last = (ev & 0x80u) != 0;

        switch (type)
        {
            case 0: // release note
            {
                if (g_music.pos >= g_music.end) break;
                uint8_t note = *g_music.pos++ & 0x7Fu;
                music_note_off(channel, note);
                break;
            }
            case 1: // play note
            {
                if (g_music.pos >= g_music.end) break;
                uint8_t b = *g_music.pos++;
                uint8_t note = b & 0x7Fu;
                uint8_t vol = g_music.chan_volume[channel];
                if (b & 0x80u)
                {
                    if (g_music.pos >= g_music.end) break;
                    vol = *g_music.pos++ & 0x7Fu;
                    g_music.chan_volume[channel] = vol;
                }
                music_note_on(channel, note, vol);
                break;
            }
            case 2: // pitch wheel
            {
                if (g_music.pos >= g_music.end) break;
                g_music.chan_pitch[channel] = *g_music.pos++ & 0x7Fu;
                music_update_channel_pitch(channel);
                break;
            }
            case 3: // system event
            {
                if (g_music.pos >= g_music.end) break;
                uint8_t sys = *g_music.pos++ & 0x7Fu;
                if (sys == 10 || sys == 11)
                {
                    music_all_notes_off();
                }
                break;
            }
            case 4: // control change
            {
                if ((g_music.end - g_music.pos) < 2) break;
                uint8_t ctl = g_music.pos[0] & 0x7Fu;
                uint8_t val = g_music.pos[1] & 0x7Fu;
                g_music.pos += 2;
                if (ctl == 0)
                {
                    g_music.chan_program[channel] = val;
                }
                else if (ctl == 3)
                {
                    g_music.chan_volume[channel] = val;
                }
                else if (ctl == 4)
                {
                    g_music.chan_pan[channel] = val;
                }
                else if (ctl == 10 || ctl == 11)
                {
                    music_all_notes_off();
                }
                break;
            }
            case 6: // end
            {
                if (g_music.looping)
                {
                    music_reset_cursor();
                    return;
                }
                g_music.playing = false;
                music_all_notes_off();
                return;
            }
            default:
                break;
        }

        if (last)
        {
            g_music.wait_ticks = mus_read_delay(&g_music.pos, g_music.end);
            if (g_music.wait_ticks == 0)
            {
                continue;
            }
            return;
        }
    }

    g_music.playing = false;
    music_all_notes_off();
}

static void music_advance_one_frame(void)
{
    if (!g_music.loaded || !g_music.playing || g_music.paused)
    {
        return;
    }
    g_music.tick_accum += MUS_TICKS_PER_SEC;
    if (g_music.tick_accum >= AUDIO_OUTPUT_RATE_HZ)
    {
        g_music.tick_accum -= AUDIO_OUTPUT_RATE_HZ;
        music_tick();
    }
}

static void music_mix_frame(int32_t *left, int32_t *right)
{
    if (!left || !right || !g_music.loaded || !g_music.playing || g_music.paused || g_music.volume <= 0)
    {
        return;
    }

    for (int i = 0; i < MUSIC_MAX_VOICES; ++i)
    {
        music_voice_t *v = &g_music_voices[i];
        if (!v->active)
        {
            continue;
        }

        int32_t amp = v->amp;
        amp += (v->amp_target - amp) >> 4;
        v->amp = amp;
        if (v->amp_target == 0 && amp > -8 && amp < 8)
        {
            v->active = false;
            continue;
        }

        int32_t s;
        if (v->wave == MUSIC_WAVE_NOISE)
        {
            g_music_noise = g_music_noise * 1664525u + 1013904223u;
            s = (g_music_noise & 0x80000000u) ? amp : -amp;
        }
        else
        {
            s = (v->phase & 0x80000000u) ? -amp : amp;
        }
        v->phase += v->step;

        *left += (s * (int32_t)v->pan_l) / 127;
        *right += (s * (int32_t)v->pan_r) / 127;
    }
}

static void mix_frames(int16_t *out_interleaved, uint32_t frames)
{
    if (!out_interleaved || frames == 0)
    {
        return;
    }

    for (uint32_t i = 0; i < frames; ++i)
    {
        music_advance_one_frame();

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

        music_mix_frame(&left, &right);

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
    uint32_t target_frames = (uint32_t)((AUDIO_OUTPUT_RATE_HZ * (uint64_t)AUDIO_TARGET_LATENCY_MS) / 1000ULL);
    if (g_audio_last_ms == 0)
    {
        g_audio_last_ms = now_ms;
        g_audio_frac = 0;
        g_audio_queued_frames = 0;

        // Prime a small amount of audio so we don't underrun during startup.
        uint32_t prime_frames = target_frames;
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
            g_audio_queued_frames += chunk;
            prime_frames -= chunk;
        }
        return;
    }

    uint64_t delta_ms = now_ms - g_audio_last_ms;
    if (delta_ms == 0)
    {
        return;
    }

    g_audio_last_ms = now_ms;

    // Track how much of our queued audio has been played since the last pump.
    uint64_t total = delta_ms * (uint64_t)AUDIO_OUTPUT_RATE_HZ + (uint64_t)g_audio_frac;
    uint32_t consumed = (uint32_t)(total / 1000ULL);
    g_audio_frac = (uint32_t)(total % 1000ULL);
    if (consumed >= g_audio_queued_frames)
    {
        g_audio_queued_frames = 0;
    }
    else
    {
        g_audio_queued_frames -= consumed;
    }

    if (g_audio_queued_frames >= target_frames)
    {
        return;
    }

    uint32_t frames = target_frames - g_audio_queued_frames;

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
            g_audio_queued_frames = 0;
            break;
        }

        if ((size_t)wrote < bytes)
        {
            // Partial writes are unexpected for /dev/audio, but avoid stalling.
            close(g_audio_fd);
            g_audio_fd = -1;
            g_audio_last_ms = 0;
            g_audio_frac = 0;
            g_audio_queued_frames = 0;
            break;
        }

        g_audio_queued_frames += chunk;
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
    g_audio_queued_frames = 0;

    memset(&g_music, 0, sizeof(g_music));
    g_music.loaded = false;
    g_music.playing = false;
    g_music.paused = false;
    g_music.looping = false;
    g_music.handle = 0;
    g_music.data = NULL;
    g_music.score = NULL;
    g_music.pos = NULL;
    g_music.end = NULL;
    g_music.wait_ticks = 0;
    g_music.tick_accum = 0;
    g_music.volume = 127;
    for (int c = 0; c < 16; ++c)
    {
        g_music.chan_volume[c] = 127;
        g_music.chan_pan[c] = 64;
        g_music.chan_program[c] = 0;
        g_music.chan_pitch[c] = 64;
    }
    music_voices_reset();
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
                g_audio_queued_frames = 0;
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

void I_InitMusic(void)
{
    g_music.volume = clamp_int(g_music.volume, 0, 127);
}

void I_ShutdownMusic(void)
{
    g_music.loaded = false;
    g_music.playing = false;
    g_music.paused = false;
    g_music.looping = false;
    g_music.handle = 0;
    g_music.data = NULL;
    g_music.score = NULL;
    g_music.pos = NULL;
    g_music.end = NULL;
    g_music.wait_ticks = 0;
    g_music.tick_accum = 0;
    music_all_notes_off();
}

void I_SetMusicVolume(int volume)
{
    // DOOM uses a 0..127 music volume range; some code paths still pass 0..15.
    int volume127;
    if (volume <= 15)
    {
        volume = clamp_int(volume, 0, 15);
        volume127 = (volume * 127 + 7) / 15;
    }
    else
    {
        volume127 = clamp_int(volume, 0, 127);
    }
    g_music.volume = volume127;
}

void I_PauseSong(int handle)
{
    if (g_music.loaded && g_music.handle != 0 && handle == g_music.handle)
    {
        g_music.paused = true;
    }
}

void I_ResumeSong(int handle)
{
    if (g_music.loaded && g_music.handle != 0 && handle == g_music.handle)
    {
        g_music.paused = false;
    }
}

int I_RegisterSong(void *data)
{
    const uint8_t *p = (const uint8_t *)data;
    if (!p)
    {
        g_music.loaded = false;
        g_music.data = NULL;
        g_music.score = NULL;
        g_music.pos = NULL;
        g_music.end = NULL;
        g_music.handle = 0;
        return 1;
    }

    if (!(p[0] == 'M' && p[1] == 'U' && p[2] == 'S' && p[3] == 0x1Au))
    {
        serial_printf("[doom][music] unsupported music header; skipping\n");
        g_music.loaded = false;
        g_music.data = NULL;
        g_music.score = NULL;
        g_music.pos = NULL;
        g_music.end = NULL;
        g_music.handle = 0;
        return 1;
    }

    uint16_t score_len = read_le16(p + 4);
    uint16_t score_start = read_le16(p + 6);
    if (score_len == 0)
    {
        g_music.loaded = false;
        g_music.data = NULL;
        g_music.score = NULL;
        g_music.pos = NULL;
        g_music.end = NULL;
        g_music.handle = 0;
        return 1;
    }

    music_all_notes_off();

    g_music.data = p;
    g_music.score = p + score_start;
    g_music.pos = g_music.score;
    g_music.end = g_music.score + score_len;
    g_music.loaded = true;
    g_music.playing = false;
    g_music.paused = false;
    g_music.looping = false;
    g_music.wait_ticks = 0;
    g_music.tick_accum = 0;

    if (g_music.handle == 0)
    {
        g_music.handle = 1;
    }
    else
    {
        g_music.handle++;
        if (g_music.handle == 0)
        {
            g_music.handle = 1;
        }
    }

    music_reset_cursor();
    return g_music.handle;
}

void I_PlaySong(int handle, int looping)
{
    if (!g_music.loaded || g_music.handle == 0 || handle != g_music.handle)
    {
        return;
    }
    g_music.looping = looping != 0;
    g_music.playing = true;
    g_music.paused = false;
    music_reset_cursor();
}

void I_StopSong(int handle)
{
    if (!g_music.loaded || g_music.handle == 0 || handle != g_music.handle)
    {
        return;
    }
    g_music.playing = false;
    g_music.paused = false;
    g_music.looping = false;
    music_all_notes_off();
}

void I_UnRegisterSong(int handle)
{
    if (!g_music.loaded || g_music.handle == 0 || handle != g_music.handle)
    {
        return;
    }
    I_StopSong(handle);
    g_music.loaded = false;
    g_music.data = NULL;
    g_music.score = NULL;
    g_music.pos = NULL;
    g_music.end = NULL;
    g_music.handle = 0;
}
