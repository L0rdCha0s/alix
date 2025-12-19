/*
Copyright (C) 1996-1997 Id Software, Inc.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

*/
// snd_alix.c -- /dev/audio backend for AlixOS

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "quakedef.h"
#include "usyscall.h"

enum
{
    AUDIO_RATE_HZ = 48000,
    AUDIO_TARGET_LATENCY_MS = 60,
    DMA_BUFFER_BYTES = 1 << 16,
};

static int g_audio_fd = -1;
static int g_wbufp = 0;
static uint64_t g_audio_last_ms = 0;
static uint64_t g_audio_played_frames = 0;
static uint32_t g_audio_frac = 0;
static uint64_t g_audio_written_frames = 0;

static uint8_t g_dma_buffer[DMA_BUFFER_BYTES];
static uint8_t g_write_buffer[8192];

static void audio_reset_timing(void)
{
    g_audio_last_ms = 0;
    g_audio_played_frames = 0;
    g_audio_frac = 0;
    g_audio_written_frames = 0;
}

static void audio_update_playback(void)
{
    if (!shm || shm->speed <= 0)
    {
        return;
    }

    uint64_t now_ms = sys_time_millis();
    if (g_audio_last_ms == 0 || now_ms < g_audio_last_ms)
    {
        g_audio_last_ms = now_ms;
        return;
    }

    uint64_t delta_ms = now_ms - g_audio_last_ms;
    g_audio_last_ms = now_ms;

    uint64_t total = delta_ms * (uint64_t)shm->speed + (uint64_t)g_audio_frac;
    uint64_t frames = total / 1000ULL;
    g_audio_frac = (uint32_t)(total % 1000ULL);
    g_audio_played_frames += frames;
}

qboolean SNDDMA_Init(void)
{
    if (g_audio_fd >= 0)
    {
        return true;
    }

    g_audio_fd = open("/dev/audio", O_WRONLY);
    if (g_audio_fd < 0)
    {
        Con_Printf("SNDDMA_Init: /dev/audio unavailable\n");
        return false;
    }

    shm = &sn;
    shm->splitbuffer = 0;
    shm->channels = 2;
    shm->samplebits = 16;
    shm->speed = AUDIO_RATE_HZ;
    shm->samples = DMA_BUFFER_BYTES / (shm->samplebits / 8);
    shm->samplepos = 0;
    shm->submission_chunk = 1;
    shm->soundalive = true;
    shm->gamealive = true;
    shm->buffer = g_dma_buffer;
    Q_memset(g_dma_buffer, 0, sizeof(g_dma_buffer));

    g_wbufp = 0;
    audio_reset_timing();
    return true;
}

int SNDDMA_GetDMAPos(void)
{
    if (g_audio_fd < 0 || !shm || shm->samples <= 0)
    {
        return 0;
    }

    audio_update_playback();

    uint64_t sample_pos = (g_audio_played_frames * (uint64_t)shm->channels) %
                          (uint64_t)shm->samples;
    shm->samplepos = (int)sample_pos;
    return (int)sample_pos;
}

int SNDDMA_GetSamples(void)
{
    if (g_audio_fd < 0)
    {
        return 0;
    }
    audio_update_playback();
    return (int)g_audio_played_frames;
}

void SNDDMA_Shutdown(void)
{
    if (g_audio_fd >= 0)
    {
        close(g_audio_fd);
        g_audio_fd = -1;
    }
    audio_reset_timing();
}

void SNDDMA_Submit(void)
{
    if (g_audio_fd < 0 || !shm)
    {
        return;
    }

    if (paintedtime < g_wbufp)
    {
        g_wbufp = 0;
    }

    audio_update_playback();

    uint64_t queued_frames = 0;
    if (g_audio_written_frames > g_audio_played_frames)
    {
        queued_frames = g_audio_written_frames - g_audio_played_frames;
    }

    uint64_t target_frames = ((uint64_t)shm->speed * AUDIO_TARGET_LATENCY_MS) / 1000ULL;
    if (queued_frames >= target_frames)
    {
        return;
    }

    int frame_bytes = shm->channels * (shm->samplebits / 8);
    int available_frames = paintedtime - g_wbufp;
    if (available_frames <= 0)
    {
        return;
    }

    uint64_t frames_to_write = target_frames - queued_frames;
    if (frames_to_write > (uint64_t)available_frames)
    {
        frames_to_write = (uint64_t)available_frames;
    }

    uint64_t bytes_to_write = frames_to_write * (uint64_t)frame_bytes;
    while (bytes_to_write > 0)
    {
        size_t chunk = bytes_to_write;
        if (chunk > sizeof(g_write_buffer))
        {
            chunk = sizeof(g_write_buffer);
        }

        uint64_t offset_bytes = (uint64_t)g_wbufp * (uint64_t)frame_bytes;
        size_t idx = (size_t)(offset_bytes & (DMA_BUFFER_BYTES - 1));
        size_t first = DMA_BUFFER_BYTES - idx;
        if (first > chunk)
        {
            first = chunk;
        }

        memcpy(g_write_buffer, g_dma_buffer + idx, first);
        if (first < chunk)
        {
            memcpy(g_write_buffer + first, g_dma_buffer, chunk - first);
        }

        ssize_t wrote = write(g_audio_fd, g_write_buffer, chunk);
        if (wrote <= 0)
        {
            break;
        }

        size_t frames_written = (size_t)wrote / (size_t)frame_bytes;
        g_wbufp += (int)frames_written;
        g_audio_written_frames += (uint64_t)frames_written;
        bytes_to_write -= (size_t)wrote;

        if ((size_t)wrote < chunk)
        {
            break;
        }
    }
}
