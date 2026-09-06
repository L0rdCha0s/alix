#!/usr/bin/env python3
"""Execute production HDA queue transitions against a deterministic DMA clock."""

import sys

sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition


def typedef(text: str, name: str) -> str:
    end = text.index("} " + name + ";") + len(name) + 3
    return text[text.rfind("typedef struct", 0, end):end]


def test_hda_state_behavior(hda: str) -> None:
    macros = hda[hda.index("#define HDA_MMIO_BYTES"):hda.index("typedef struct")]
    program = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
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
    program += typedef(hda, "hda_state_t") + "\n"
    program += r'''
static hda_state_t g_hda;
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
        "static bool hda_claim_writer_locked",
        "static ssize_t hda_dev_write",
    ):
        # Host may be ARM; the polling hint has no observable device semantics.
        program += function_definition(hda, signature).replace('__asm__ volatile ("pause");', '(void)0;') + "\n"
    program += r'''
#define CHECK(condition, message) do { if (!(condition)) { fprintf(stderr, "%s\n", message); exit(1); } } while (0)
static void reset(void)
{
    memset(&g_hda, 0, sizeof(g_hda)); memset(ring, 0, sizeof(ring)); memset(registers, 0, sizeof(registers));
    g_hda.regs = registers; g_hda.buffer = ring; g_hda.buffer_size = sizeof(ring);
    now_ms = 100u; starts = 0; sleeps = 0; reprograms = 0;
    caller.pid = 11u; volume = 100u; fail_reprogram = false; fail_after_sleep = false; takeover_after_sleep = false;
    played_bytes = 0;
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
    free(pcm); free(played);
    return 0;
}
'''
    compile_and_run("hda-state-behavior", program)


if __name__ == "__main__":
    test_hda_state_behavior((ROOT / "src/drivers/hda.c").read_text())
