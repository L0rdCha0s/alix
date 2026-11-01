#!/usr/bin/env python3
"""Execute production HDA queue transitions against a deterministic DMA clock."""

import os
import shlex
import sys

sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition


def typedef(text: str, name: str) -> str:
    end = text.index("} " + name + ";") + len(name) + 3
    return text[text.rfind("typedef struct", 0, end):end]


def build_program(hda: str) -> str:
    macros = hda[hda.index("#define HDA_MMIO_BYTES"):hda.index("typedef struct")]
    program = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
typedef struct { unsigned value; } spinlock_t;
typedef struct { unsigned unused; } vfs_node_t;
typedef struct { uint64_t pid; } process_t;
static process_t caller = { 11u };
static uint64_t process_current_pid(void) { return caller.pid; }
static void spinlock_lock(spinlock_t *lock) { if (lock->value++) abort(); }
static void spinlock_unlock(spinlock_t *lock) { if (--lock->value) abort(); }
static void serial_printf(const char *fmt, ...) { (void)fmt; }
'''
    program += macros
    program += hda[hda.index("typedef struct"):hda.index("/* Pre-allocated")]
    account_start = hda.index("struct hda_pcm_stream\n")
    account_end = hda.index("\n};", account_start) + 3
    program += "typedef struct hda_pcm_stream hda_pcm_stream_t;\n" + hda[account_start:account_end] + "\n"
    header = (ROOT / "include/hda.h").read_text()
    program += typedef(header, "hda_pcm_status_t") + "\n"
    program += "\n".join(line for line in header.splitlines() if line.startswith("#define HDA_PCM_")) + "\n"
    program += typedef(hda, "hda_state_t") + "\n"
    program += r'''
static hda_state_t g_hda;
static bool g_hda_ready;
static unsigned pcm_live;
static bool fail_pcm_allocation;
static void *pcm_test_calloc(size_t count, size_t size) {
    if (g_hda.lock.value) abort();
    if (fail_pcm_allocation) { fail_pcm_allocation=false; return NULL; }
    void *result=calloc(count,size); if (result) ++pcm_live; return result;
}
static void pcm_test_free(void *pointer) {
    if (g_hda.lock.value || !pcm_live) abort();
    --pcm_live; free(pointer);
}
static uint8_t registers[HDA_MMIO_BYTES];
static uint8_t ring[HDA_BUFFER_BYTES];
static uint64_t now_ms;
static unsigned starts, sleeps, reprograms;
static uint32_t volume = 100u;
static bool fail_reprogram, fail_after_sleep, takeover_after_sleep;
static int g_hda_error_log_budget;
static uint8_t *played;
static size_t played_bytes, played_capacity;
static uint64_t hda_now_ms(void) { return now_ms; }
static uint32_t audio_volume_get_percent(void) { return volume; }
static void hda_log_hwpos(hda_state_t *hda, const char *ctx) { (void)hda; (void)ctx; }
static uint32_t hda_read32(hda_state_t *hda, uint32_t offset)
{ uint32_t value; memcpy(&value, (const void *)(hda->regs + offset), sizeof(value)); return value; }
static uint16_t hda_read16(hda_state_t *hda, uint32_t offset)
{ uint16_t value; memcpy(&value, (const void *)(hda->regs + offset), sizeof(value)); return value; }
static uint8_t hda_read8(hda_state_t *hda, uint32_t offset) { return hda->regs[offset]; }
static void hda_write32(hda_state_t *hda, uint32_t offset, uint32_t value)
{
    if (offset == HDA_REG_SD_CTL(HDA_STREAM_INDEX) && (value & HDA_SDCTL_RUN) &&
        !(hda_read32(hda, offset) & HDA_SDCTL_RUN)) starts++;
    memcpy((void *)(hda->regs + offset), &value, sizeof(value));
}
static void hda_write8(hda_state_t *hda, uint32_t offset, uint8_t value)
{ hda->regs[offset] &= (uint8_t)~value; }
static bool hda_program_stream(hda_state_t *hda)
{
    reprograms++;
    if (fail_reprogram) return false;
    hda->running = false; hda->used_bytes = 0; hda->write_pos = 0; hda->hw_pos_prev = 0;
    hda->pcm_lead_bytes = 0;
    memset(hda->buffer, 0, hda->buffer_size);
    hda_write32(hda, HDA_REG_SD_LPIB(HDA_STREAM_INDEX), 0);
    return true;
}
static void hda_service_locked(hda_state_t *hda);
static bool hda_start_stream(hda_state_t *hda);
static uint32_t hda_hw_position(hda_state_t *hda);
static void hda_check_stream_errors_locked(hda_state_t *hda, const char *context);
static ssize_t hda_dev_write(vfs_node_t *node, size_t offset, const void *buffer, size_t count, void *context);

static void advance_dma(size_t bytes)
{
    if (!g_hda.running) return;
    size_t position = hda_read32(&g_hda, HDA_REG_SD_LPIB(HDA_STREAM_INDEX));
    if (played_bytes + bytes > played_capacity)
    {
        played_capacity = (played_bytes + bytes) * 2u + 4096u;
        played = realloc(played, played_capacity);
        if (!played) abort();
    }
    for (size_t i = 0; i < bytes; ++i)
        played[played_bytes + i] = ring[(position + i) % sizeof(ring)];
    played_bytes += bytes;
    hda_write32(&g_hda, HDA_REG_SD_LPIB(HDA_STREAM_INDEX), (uint32_t)((position + bytes) % sizeof(ring)));
    now_ms += bytes * 1000u / HDA_BYTES_PER_SECOND;
}

static void process_sleep_ms(uint32_t ms)
{
    (void)ms;
    if (++sleeps > 1000u || g_hda.lock.value) abort();
    advance_dma(takeover_after_sleep ? g_hda.used_bytes : 4096u);
    if (takeover_after_sleep)
    {
        static const uint8_t other_pcm[4096];
        takeover_after_sleep = false;
        hda_service_locked(&g_hda);
        caller.pid = 22u;
        if (hda_dev_write(NULL, 0, other_pcm, sizeof(other_pcm), &g_hda) != sizeof(other_pcm)) abort();
        caller.pid = 11u;
    }
    if (fail_after_sleep) { g_hda.needs_reprogram = true; fail_reprogram = true; }
}
'''
    for signature in (
        "static void hda_pcm_put_locked",
        "static void hda_pcm_end_queue_locked",
        "static void hda_pcm_consumed_locked",
        "static void hda_pcm_reap",
        "static bool hda_stop_stream",
        "static void hda_clear_ring_range",
        "static void hda_silence_advance",
        "static void hda_update_used_bytes",
        "static void hda_check_stream_errors_locked",
        "static bool hda_start_stream",
        "static uint32_t hda_hw_position",
        "static void hda_service_locked",
        "static inline int16_t hda_scale_sample",
        "static void hda_copy_scaled_pcm",
        "static void hda_copy_pcm_chunk",
        "static ssize_t hda_queue_pcm_locked",
        "static bool hda_claim_writer_locked",
        "static ssize_t hda_dev_write",
        "int hda_pcm_create",
        "void hda_pcm_release",
        "ssize_t hda_pcm_try_write",
        "int hda_pcm_writable",
        "int hda_pcm_snapshot",
        "static void hda_housekeeping_step",
    ):
        # Host may be ARM; the polling hint has no observable device semantics.
        body = function_definition(hda, signature).replace('__asm__ volatile ("pause");', '(void)0;')
        if signature == "int hda_pcm_create": body = body.replace("calloc(", "pcm_test_calloc(")
        if signature == "static void hda_pcm_reap": body = body.replace("free(", "pcm_test_free(")
        program += body + "\n"
    program += r'''
#define CHECK(condition, message) do { if (!(condition)) { fprintf(stderr, "%s\n", message); exit(1); } } while (0)
static void reset(void)
{
    hda_pcm_reap(); if (pcm_live) abort();
    memset(&g_hda, 0, sizeof(g_hda)); memset(ring, 0, sizeof(ring)); memset(registers, 0, sizeof(registers));
    g_hda.regs = registers; g_hda.buffer = ring; g_hda.buffer_size = sizeof(ring);
    now_ms = 100u; starts = 0; sleeps = 0; reprograms = 0;
    caller.pid = 11u; volume = 100u; fail_reprogram = false; fail_after_sleep = false; takeover_after_sleep = false;
    played_bytes = 0;
    g_hda_ready = true; fail_pcm_allocation = false;
}

static void test_start_and_ownership(const uint8_t *pcm)
{
    reset();
    CHECK(hda_dev_write(NULL, 0, pcm, 4096u, &g_hda) == 4096, "short write not accepted");
    CHECK(!g_hda.running && starts == 0u, "cold stream started before prebuffer/deadline");
    now_ms += HDA_START_WAIT_MS - 1u; hda_service_locked(&g_hda);
    CHECK(!g_hda.running, "short startup deadline fired early");
    now_ms++; hda_service_locked(&g_hda);
    CHECK(g_hda.running && starts == 1u, "short sound stranded without a subsequent write");
    caller.pid = 22u;
    CHECK(hda_dev_write(NULL, 0, pcm, 4u, &g_hda) == -1, "second process interleaved into queued audio");
    CHECK(g_hda.rejected_writers == 1u && g_hda.used_bytes == 4096u, "rejected writer changed queue");
    advance_dma(4096u); hda_service_locked(&g_hda);
    CHECK(g_hda.used_bytes == 0u && g_hda.running, "retirement stopped RUN or retained played PCM");
    CHECK(hda_dev_write(NULL, 0, pcm, 4096u, &g_hda) == 4096, "drained stream never released ownership");
    CHECK(starts == 1u && reprograms == 0u, "short underrun restarted/reset the controller");
    CHECK(g_hda.used_bytes == 4096u + HDA_REPRIME_LEAD_BYTES && g_hda.reprime_events == 1u,
          "running recovery omitted silent fetch lead");
    reset();
    CHECK(hda_dev_write(NULL, 0, pcm, HDA_START_QUEUED_BYTES, &g_hda) == HDA_START_QUEUED_BYTES,
          "prebuffer write failed");
    CHECK(g_hda.running && starts == 1u, "sufficient prebuffer did not start promptly");
}

static void test_long_write_and_wrap(const uint8_t *pcm, size_t bytes)
{
    reset();
    CHECK(hda_dev_write(NULL, 0, pcm, bytes, &g_hda) == (ssize_t)bytes, "long write failed");
    CHECK(sleeps > 0u && g_hda.used_bytes <= HDA_MAX_QUEUED_BYTES, "full queue lacks bounded backpressure");
    while (g_hda.used_bytes)
    {
        size_t part = g_hda.used_bytes < 4096u ? g_hda.used_bytes : 4096u;
        advance_dma(part); hda_service_locked(&g_hda);
    }
    CHECK(played_bytes == bytes && memcmp(played, pcm, bytes) == 0,
          "DMA wrap/full-queue write lost, duplicated, or overwrote PCM");
    CHECK(starts == 1u && reprograms == 0u, "continuous write toggled RUN");
    for (size_t i = 0; i < sizeof(ring); ++i) CHECK(ring[i] == 0, "retired PCM could replay on wrap");
}

static void test_failure_prefix(const uint8_t *pcm)
{
    reset(); fail_after_sleep = true;
    size_t count = HDA_MAX_QUEUED_BYTES + 4096u;
    ssize_t accepted = hda_dev_write(NULL, 0, pcm, count, &g_hda);
    CHECK(accepted == HDA_MAX_QUEUED_BYTES,
          "failure after partial write concealed accepted bytes, allowing caller replay");
    CHECK(g_hda.lock.value == 0u && reprograms == 1u, "failed recovery stranded lock or retried forever");
    reset(); takeover_after_sleep = true;
    accepted = hda_dev_write(NULL, 0, pcm, count, &g_hda);
    CHECK(accepted == HDA_MAX_QUEUED_BYTES && g_hda.writer_pid == 22u && g_hda.rejected_writers == 1u,
          "descheduled previous owner appended into the replacement producer's stream");
    reset();
    CHECK(hda_dev_write(NULL, 1u, pcm, 4u, &g_hda) == -1 &&
          hda_dev_write(NULL, 0, pcm, 3u, &g_hda) == -1 && starts == 0u,
          "unaligned write changed device state");
}

static void test_error_and_missed_ring(const uint8_t *pcm)
{
    reset();
    CHECK(hda_dev_write(NULL, 0, pcm, HDA_START_QUEUED_BYTES, &g_hda) == HDA_START_QUEUED_BYTES,
          "error test stream failed to start");
    registers[HDA_REG_SD_STS(HDA_STREAM_INDEX)] = HDA_SDSTS_FIFOE;
    hda_service_locked(&g_hda);
    CHECK(g_hda.stream_errors == 1u && g_hda.running && !g_hda.needs_reprogram,
          "FIFO status handling restarted a valid descriptor stream");
    registers[HDA_REG_SD_STS(HDA_STREAM_INDEX)] = HDA_SDSTS_DESE;
    hda_service_locked(&g_hda);
    CHECK(g_hda.stream_errors == 2u && !g_hda.running && g_hda.needs_reprogram,
          "descriptor error failed to stop DMA for recovery");
    reset();
    CHECK(hda_dev_write(NULL, 0, pcm, HDA_START_QUEUED_BYTES, &g_hda) == HDA_START_QUEUED_BYTES,
          "missed-ring test stream failed to start");
    now_ms += ((uint64_t)HDA_BUFFER_BYTES * 1000u) / HDA_BYTES_PER_SECOND + 1u;
    hda_service_locked(&g_hda);
    CHECK(!g_hda.running && g_hda.needs_reprogram && !g_hda.used_bytes,
          "full unobserved DMA wrap retained ambiguous queue accounting");
}

static int16_t sample_at(const uint8_t *pcm, size_t frame)
{
    size_t offset = frame * HDA_FRAME_BYTES;
    return (int16_t)((uint16_t)pcm[offset] | ((uint16_t)pcm[offset + 1u] << 8));
}

static void test_gain_ramp(void)
{
    enum { FRAMES = HDA_GAIN_RAMP_FRAMES + 30u, SPLIT = 37u };
    uint8_t input[FRAMES * HDA_FRAME_BYTES], single[sizeof(input)], split[sizeof(input)];
    for (size_t i = 0; i < FRAMES; ++i)
    {
        input[i * 4u] = 0xC0; input[i * 4u + 1u] = 0x5D;
        input[i * 4u + 2u] = 0x40; input[i * 4u + 3u] = 0xA2;
    }
    hda_state_t first = {0}, second = {0};
    hda_copy_pcm_chunk(&first, single, input, HDA_FRAME_BYTES, 100u);
    hda_copy_pcm_chunk(&second, split, input, HDA_FRAME_BYTES, 100u);
    hda_copy_pcm_chunk(&first, single, input, sizeof(input), 0u);
    hda_copy_pcm_chunk(&second, split, input, SPLIT * HDA_FRAME_BYTES, 0u);
    hda_copy_pcm_chunk(&second, split + SPLIT * HDA_FRAME_BYTES,
                       input + SPLIT * HDA_FRAME_BYTES, sizeof(input) - SPLIT * HDA_FRAME_BYTES, 0u);
    CHECK(memcmp(single, split, sizeof(single)) == 0, "volume ramp restarted at syscall/chunk boundary");
    int16_t previous = 24000;
    for (size_t i = 0; i < FRAMES; ++i)
    {
        int16_t sample = sample_at(single, i);
        CHECK(sample >= 0 && sample <= previous && previous - sample <= 102,
              "volume decrease produced an abrupt waveform discontinuity");
        previous = sample;
    }
    CHECK(first.gain_ramp_frames == 0u && sample_at(single, FRAMES - 1u) == 0,
          "mute ramp failed to reach silence");
    hda_copy_pcm_chunk(&first, single, input, sizeof(input), 50u);
    previous = 0;
    for (size_t i = 0; i < FRAMES; ++i)
    {
        int16_t sample = sample_at(single, i);
        CHECK(sample >= previous && sample - previous <= 52, "volume increase jumped at chunk boundary");
        previous = sample;
    }
    CHECK(sample_at(single, FRAMES - 1u) == 12000, "gain ramp ended at wrong volume");
}

static void test_owned_pcm(const uint8_t *pcm)
{
    reset();
    hda_pcm_stream_t *first = NULL, *second = NULL;
    hda_pcm_status_t status;
    CHECK(hda_pcm_create(11, &first) == 0 && first && first->references == 1, "PCM stream ownership");
    CHECK(hda_pcm_writable(first) == 1 && first->references == 1 && !g_hda.active_pcm && !g_hda.used_bytes,
          "PCM readiness claimed or queued the channel");
    g_hda.reconfiguring = true;
    CHECK(hda_pcm_writable(first) == 0 && first->references == 1, "PCM recovery was reported writable");
    g_hda.reconfiguring = false;
    first->failed = true;
    CHECK(hda_pcm_writable(first) == -EIO, "failed PCM stream was reported writable");
    first->failed = false;
    CHECK(hda_pcm_writable(NULL) == -EINVAL, "NULL PCM readiness accepted");
    g_hda_ready = false;
    CHECK(hda_pcm_writable(first) == -ENODEV, "absent PCM device was reported writable");
    g_hda_ready = true;
    CHECK(hda_pcm_snapshot(first, &status) == 0 && status.rate == 48000 && status.channels == 2 &&
          status.frame_bytes == 4 && !status.submitted_frames && !status.flags, "PCM initial hardware format");
    CHECK(hda_pcm_try_write(first, pcm, 3) == -EINVAL && hda_pcm_try_write(first, NULL, 4) == -EINVAL &&
          hda_pcm_try_write(first, NULL, 0) == 0 && !g_hda.used_bytes && first->references == 1,
          "PCM invalid writes changed ownership or queued data");
    CHECK(hda_pcm_try_write(first, pcm, HDA_START_QUEUED_BYTES) == HDA_START_QUEUED_BYTES,
          "PCM prebuffer write");
    advance_dma(4096);
    CHECK(hda_pcm_snapshot(first, &status) == 0 && status.played_frames == 1024 &&
          status.submitted_frames == HDA_START_QUEUED_BYTES/4 && status.queued_frames == 3072,
          "PCM hardware position counts queued frames as played");
    size_t space = HDA_MAX_QUEUED_BYTES - status.queued_frames*4;
    unsigned prior_sleeps = sleeps;
    CHECK(hda_pcm_try_write(first, pcm, HDA_MAX_QUEUED_BYTES) == (ssize_t)space &&
          hda_pcm_try_write(first, pcm, 4) == -EAGAIN && sleeps == prior_sleeps,
          "PCM short write/backpressure blocked its executor");
    CHECK(hda_pcm_writable(first) == 0, "full DMA queue was reported writable");
    CHECK(hda_pcm_create(11, &second) == 0 && hda_pcm_try_write(second, pcm, 4) == -EBUSY &&
          hda_dev_write(NULL, 0, pcm, 4, &g_hda) == -1, "PCM streams or legacy writes interleaved");
    CHECK(hda_pcm_writable(second) == 0, "readiness bypassed a different stream owner");
    hda_pcm_release(first); hda_pcm_reap();
    CHECK(pcm_live == 2 && g_hda.active_pcm, "close freed a live DMA metadata owner");
    advance_dma(g_hda.used_bytes); hda_service_locked(&g_hda); hda_pcm_reap();
    CHECK(pcm_live == 1 && !g_hda.active_pcm, "drained PCM metadata owner leaked");
    CHECK(hda_pcm_writable(second) == 1 && second->references == 1 && !g_hda.active_pcm,
          "drain did not restore passive write readiness");
    CHECK(hda_pcm_try_write(second, pcm, 4) == 4 && hda_pcm_snapshot(second, &status) == 0 &&
          status.queued_frames == 1 && status.latency_frames == HDA_REPRIME_LEAD_BYTES/4+1,
          "PCM reprime latency omitted hardware silent lead");
    advance_dma(HDA_REPRIME_LEAD_BYTES);
    CHECK(hda_pcm_snapshot(second, &status) == 0 && !status.played_frames && status.queued_frames == 1,
          "PCM reported silent lead as client frames");
    advance_dma(4);
    CHECK(hda_pcm_snapshot(second, &status) == 0 && status.played_frames == 1 &&
          !status.queued_frames && second->references == 1, "PCM drain position/reference");
    advance_dma(4096);
    CHECK(hda_pcm_snapshot(second, &status) == 0 && status.played_frames == 1,
          "PCM position advanced during hardware silence");
    hda_pcm_release(second); hda_pcm_reap(); CHECK(!pcm_live, "PCM final retirement");

    reset();
    CHECK(hda_pcm_create(11, &first) == 0 && hda_pcm_create(22, &second) == 0, "PCM independent owners");
    CHECK(hda_pcm_try_write(first, pcm, HDA_START_QUEUED_BYTES) == HDA_START_QUEUED_BYTES, "PCM first owner");
    advance_dma(HDA_START_QUEUED_BYTES); CHECK(hda_pcm_snapshot(first,&status) == 0, "PCM first drain");
    CHECK(hda_pcm_try_write(second, pcm, 4) == 4 && hda_pcm_snapshot(first,&status) == 0 &&
          status.played_frames == HDA_START_QUEUED_BYTES/4 && !status.latency_frames,
          "PCM later owner changed a completed stream's position");
    hda_pcm_release(first); hda_pcm_release(second); hda_pcm_reap();
    CHECK(pcm_live == 1, "PCM pending owner did not survive both closes");
    advance_dma(g_hda.used_bytes); hda_housekeeping_step(); CHECK(!pcm_live, "PCM completed owner was not reaped");
}

static void test_pcm_errors(const uint8_t *pcm)
{
    reset(); hda_pcm_stream_t *stream = NULL;
    fail_pcm_allocation = true;
    CHECK(hda_pcm_create(11,&stream) == -ENOMEM && !stream && !pcm_live, "PCM allocation failure ownership");
    g_hda_ready = false;
    CHECK(hda_pcm_create(11,&stream) == -ENODEV && !stream && !pcm_live, "PCM absent device fabricated success");
    g_hda_ready = true;
    CHECK(hda_pcm_create(11,&stream) == 0 && hda_pcm_try_write(stream,pcm,HDA_START_QUEUED_BYTES) == HDA_START_QUEUED_BYTES,
          "PCM error stream preparation");
    advance_dma(4096);
    hda_pcm_status_t status; CHECK(hda_pcm_snapshot(stream,&status) == 0, "PCM error baseline snapshot");
    registers[HDA_REG_SD_STS(HDA_STREAM_INDEX)] = HDA_SDSTS_DESE;
    CHECK(hda_pcm_snapshot(stream,&status) == 0 && (status.flags&HDA_PCM_FAILED) &&
          status.played_frames == 1024 && status.dropped_frames == 3072 && !status.queued_frames &&
          hda_pcm_try_write(stream,pcm,4) == -EIO, "PCM device failure fabricated played frames");
    hda_pcm_release(stream); fail_reprogram = true; hda_housekeeping_step();
    CHECK(!pcm_live && reprograms == 1 && g_hda.needs_reprogram && !g_hda.reconfiguring,
          "PCM failed recovery stranded metadata or ownership");
    hda_housekeeping_step(); CHECK(reprograms == 1, "PCM recovery ignored backoff");
    fail_reprogram = false; now_ms += 100; hda_housekeeping_step();
    CHECK(reprograms == 2 && !g_hda.needs_reprogram, "PCM hardware recovery did not reopen admission");
    CHECK(hda_pcm_create(11,&stream) == 0 && hda_pcm_try_write(stream,pcm,HDA_START_QUEUED_BYTES) == HDA_START_QUEUED_BYTES,
          "PCM recovered device rejected a new stream");
    now_ms += (uint64_t)HDA_BUFFER_BYTES*1000/HDA_BYTES_PER_SECOND + 1;
    CHECK(hda_pcm_snapshot(stream,&status) == 0 && (status.flags&HDA_PCM_FAILED) &&
          !status.played_frames && status.dropped_frames == HDA_START_QUEUED_BYTES/4,
          "PCM ambiguous full ring invented playback progress");
    hda_pcm_release(stream); hda_housekeeping_step(); CHECK(!pcm_live, "PCM full-ring retirement leaked");
    CHECK(hda_pcm_create(11,&stream) == 0, "PCM overflow stream");
    stream->submitted_frames = UINT64_MAX; stream->played_frames = UINT64_MAX;
    CHECK(hda_pcm_try_write(stream,pcm,4) == -EOVERFLOW && !g_hda.used_bytes && stream->references == 1,
          "PCM counter overflow committed data or leaked a DMA reference");
    hda_pcm_release(stream); hda_pcm_reap(); CHECK(!pcm_live, "PCM overflow cleanup");
}

int main(void)
{
    size_t bytes = HDA_BUFFER_BYTES + HDA_MAX_QUEUED_BYTES + 8192u;
    uint8_t *pcm = malloc(bytes);
    if (!pcm) abort();
    for (size_t i = 0; i < bytes; ++i) pcm[i] = (uint8_t)((i * 37u + i / 256u) & 0xFFu);
    test_start_and_ownership(pcm);
    test_long_write_and_wrap(pcm, bytes);
    test_failure_prefix(pcm);
    test_error_and_missed_ring(pcm);
    test_gain_ramp();
    test_owned_pcm(pcm);
    test_pcm_errors(pcm);
    free(pcm); free(played);
    return 0;
}
'''
    return program


def test_hda_state_behavior(hda: str) -> None:
    program = build_program(hda)
    compile_and_run("hda-state-behavior", program)
    threaded = "#include <pthread.h>\n#include <sched.h>\n" + program
    threaded = threaded.replace(
        'static void spinlock_lock(spinlock_t *lock) { if (lock->value++) abort(); }',
        '''static pthread_mutex_t hda_test_guard = PTHREAD_MUTEX_INITIALIZER;
static _Thread_local bool hda_test_lock_held;
static void spinlock_lock(spinlock_t *lock) {
    if (hda_test_lock_held || pthread_mutex_lock(&hda_test_guard)) abort();
    hda_test_lock_held=true; lock->value=1;
}''', 1)
    threaded = threaded.replace(
        'static void spinlock_unlock(spinlock_t *lock) { if (--lock->value) abort(); }',
        '''static void spinlock_unlock(spinlock_t *lock) {
    if (!hda_test_lock_held) abort();
    lock->value=0; hda_test_lock_held=false;
    if (pthread_mutex_unlock(&hda_test_guard)) abort();
}''', 1)
    threaded = threaded.replace('g_hda.lock.value', 'hda_test_lock_held')
    races = r'''
typedef struct { hda_pcm_stream_t *stream; uint32_t ready,go,done; } pcm_race_t;
static void race_ready(pcm_race_t *race) {
    __atomic_add_fetch(&race->ready,1,__ATOMIC_RELEASE);
    while (!__atomic_load_n(&race->go,__ATOMIC_ACQUIRE)) sched_yield();
}
static void *race_release(void *argument) {
    pcm_race_t *race=argument; race_ready(race);
    hda_pcm_release(race->stream);
    __atomic_add_fetch(&race->done,1,__ATOMIC_RELEASE); return NULL;
}
static void *race_consume(void *argument) {
    pcm_race_t *race=argument; race_ready(race);
    spinlock_lock(&g_hda.lock);
    advance_dma(g_hda.used_bytes); hda_service_locked(&g_hda);
    spinlock_unlock(&g_hda.lock);
    __atomic_add_fetch(&race->done,1,__ATOMIC_RELEASE); return NULL;
}
static void *race_reap(void *argument) {
    pcm_race_t *race=argument; race_ready(race);
    while (__atomic_load_n(&race->done,__ATOMIC_ACQUIRE)!=2) { hda_pcm_reap(); sched_yield(); }
    hda_pcm_reap(); return NULL;
}
static void test_pcm_release_races(const uint8_t *pcm) {
    for (unsigned iteration=0;iteration<64;++iteration) {
        reset(); pcm_race_t *race=calloc(1,sizeof(*race)); CHECK(race,"race allocation");
        CHECK(hda_pcm_create(11,&race->stream)==0 &&
              hda_pcm_try_write(race->stream,pcm,HDA_START_QUEUED_BYTES)==HDA_START_QUEUED_BYTES,"race stream");
        pthread_t release,consume,reap;
        CHECK(!pthread_create(&release,NULL,race_release,race) && !pthread_create(&consume,NULL,race_consume,race) &&
              !pthread_create(&reap,NULL,race_reap,race),"race threads");
        while (__atomic_load_n(&race->ready,__ATOMIC_ACQUIRE)!=3) sched_yield();
        __atomic_store_n(&race->go,1,__ATOMIC_RELEASE);
        CHECK(!pthread_join(release,NULL) && !pthread_join(consume,NULL) && !pthread_join(reap,NULL),"race joins");
        CHECK(!pcm_live && !g_hda.active_pcm && !g_hda.retired_pcm,"release/DMA/retirement race leaked or stranded an owner");
        free(race);
    }
}
'''
    threaded = threaded.replace('int main(void)', races + '\nint main(void)', 1)
    threaded = threaded.replace('test_pcm_errors(pcm);', 'test_pcm_errors(pcm); test_pcm_release_races(pcm);', 1)
    previous = os.environ.get("HOST_CC")
    os.environ["HOST_CC"] = shlex.join(shlex.split(previous or "cc") + ["-pthread"])
    try:
        compile_and_run("hda-pcm-owner-races", threaded)
    finally:
        if previous is None: os.environ.pop("HOST_CC", None)
        else: os.environ["HOST_CC"] = previous
    print("production HDA legacy/owned PCM, hardware accounting and 64 final-owner/DMA/reaper races: PASS")


if __name__ == "__main__":
    test_hda_state_behavior((ROOT / "src/drivers/hda.c").read_text())
