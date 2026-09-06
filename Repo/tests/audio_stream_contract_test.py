#!/usr/bin/env python3
"""Structural and host-behavior regressions for audio stream transitions."""

import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]


def source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def function_bounds(text: str, signature: str) -> tuple[int, int, int]:
    start = text.find(signature)
    while start >= 0:
        opening = text.find("{", start + len(signature))
        semicolon = text.find(";", start + len(signature))
        if opening >= 0 and (semicolon < 0 or opening < semicolon):
            break
        start = text.find(signature, start + len(signature))
    if start < 0 or opening < 0:
        raise AssertionError(f"missing function definition: {signature}")

    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return start, opening, index
    raise AssertionError(f"unterminated body: {signature}")


def function_body(text: str, signature: str) -> str:
    _, opening, closing = function_bounds(text, signature)
    return text[opening + 1:closing]


def function_definition(text: str, signature: str) -> str:
    start, _, closing = function_bounds(text, signature)
    return text[start:closing + 1]


def uint_macro(text: str, name: str) -> int:
    match = re.search(
        rf"^\s*#define\s+{re.escape(name)}\s+(\d+)[uUlL]*\b",
        text,
        re.MULTILINE,
    )
    if not match:
        raise AssertionError(f"missing integer macro: {name}")
    return int(match.group(1))


def compile_and_run(label: str, program: str) -> None:
    compiler = shlex.split(os.environ.get("HOST_CC", "cc"))
    with tempfile.TemporaryDirectory(prefix=f"alix-{label}-") as temp_dir:
        binary = Path(temp_dir) / label
        compiled = subprocess.run(
            [
                *compiler,
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-x",
                "c",
                "-",
                "-o",
                str(binary),
            ],
            input=program,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if compiled.returncode != 0:
            raise AssertionError(
                f"{label} host harness did not compile:\n{compiled.stderr}"
            )

        executed = subprocess.run(
            [str(binary)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if executed.returncode != 0:
            detail = executed.stderr or executed.stdout or "no diagnostic"
            raise AssertionError(f"{label} host harness failed: {detail.strip()}")


def test_hda_ring_behavior(hda: str) -> None:
    clear_range = function_definition(hda, "static void hda_clear_ring_range")
    silence_advance = function_definition(hda, "static void hda_silence_advance")
    program = """\
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct
{
    uint8_t *buffer;
    size_t buffer_size;
} hda_state_t;

""" + clear_range + "\n\n" + silence_advance + """

static int expect_range(const uint8_t *buffer,
                        size_t size,
                        size_t first,
                        size_t count,
                        uint8_t inside,
                        uint8_t outside)
{
    for (size_t i = 0; i < size; ++i)
    {
        size_t distance = (i + size - first) % size;
        uint8_t expected = distance < count ? inside : outside;
        if (buffer[i] != expected)
        {
            fprintf(stderr,
                    "range mismatch index=%zu actual=%u expected=%u\\n",
                    i,
                    (unsigned)buffer[i],
                    (unsigned)expected);
            return 0;
        }
    }
    return 1;
}

int main(void)
{
    uint8_t buffer[32];
    hda_state_t state = { .buffer = buffer, .buffer_size = sizeof(buffer) };

    memset(buffer, 0x7A, sizeof(buffer));
    hda_silence_advance(&state, 28u, 4u);
    if (!expect_range(buffer, sizeof(buffer), 28u, 8u, 0u, 0x7Au))
    {
        return 1;
    }

    memset(buffer, 0x35, sizeof(buffer));
    hda_clear_ring_range(&state, 7u, 9u);
    if (!expect_range(buffer, sizeof(buffer), 7u, 9u, 0u, 0x35u))
    {
        return 2;
    }

    memset(buffer, 0x61, sizeof(buffer));
    hda_silence_advance(&state, 13u, 13u);
    for (size_t i = 0; i < sizeof(buffer); ++i)
    {
        if (buffer[i] != 0x61u)
        {
            fprintf(stderr, "zero-distance retirement changed index=%zu\\n", i);
            return 3;
        }
    }
    return 0;
}
"""
    compile_and_run("hda-ring-behavior", program)


def test_hda_fade_behavior(hda: str) -> None:
    frame_bytes = uint_macro(hda, "HDA_FRAME_BYTES")
    fade_frames = uint_macro(hda, "HDA_FADE_IN_FRAMES")
    gain_frames = uint_macro(hda, "HDA_GAIN_RAMP_FRAMES")
    gain_one = uint_macro(hda, "HDA_GAIN_ONE")
    scale_sample = function_definition(hda, "static inline int16_t hda_scale_sample")
    copy_scaled = function_definition(hda, "static void hda_copy_scaled_pcm")
    copy_chunk = function_definition(hda, "static void hda_copy_pcm_chunk")

    program = f"""\
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#define HDA_FRAME_BYTES {frame_bytes}u
#define HDA_FADE_IN_FRAMES {fade_frames}u
#define HDA_GAIN_RAMP_FRAMES {gain_frames}u
#define HDA_GAIN_ONE {gain_one}u

typedef struct
{{
    uint32_t fade_in_frames;
    uint32_t gain_q16;
    uint32_t target_gain_q16;
    uint32_t gain_ramp_frames;
    unsigned gain_initialized;
}} hda_state_t;

""" + scale_sample + "\n\n" + copy_scaled + "\n\n" + copy_chunk + """

static void store16(uint8_t *dst, int16_t value)
{
    dst[0] = (uint8_t)((uint16_t)value & 0xFFu);
    dst[1] = (uint8_t)(((uint16_t)value >> 8) & 0xFFu);
}

static int16_t load16(const uint8_t *src)
{
    return (int16_t)((uint16_t)src[0] | ((uint16_t)src[1] << 8));
}

static void fill_frames(uint8_t *buffer, size_t frames, int16_t left, int16_t right)
{
    for (size_t frame = 0; frame < frames; ++frame)
    {
        size_t offset = frame * HDA_FRAME_BYTES;
        store16(buffer + offset, left);
        store16(buffer + offset + 2u, right);
    }
}

int main(void)
{
    enum { TOTAL_FRAMES = HDA_FADE_IN_FRAMES + 80u, SPLIT_FRAMES = 37u };
    uint8_t input[TOTAL_FRAMES * HDA_FRAME_BYTES];
    uint8_t output[TOTAL_FRAMES * HDA_FRAME_BYTES];
    hda_state_t state = { .fade_in_frames = HDA_FADE_IN_FRAMES };
    fill_frames(input, TOTAL_FRAMES, 24000, -24000);
    memset(output, 0, sizeof(output));

    hda_copy_pcm_chunk(&state,
                       output,
                       input,
                       SPLIT_FRAMES * HDA_FRAME_BYTES,
                       100u);
    hda_copy_pcm_chunk(&state,
                       output + SPLIT_FRAMES * HDA_FRAME_BYTES,
                       input + SPLIT_FRAMES * HDA_FRAME_BYTES,
                       (TOTAL_FRAMES - SPLIT_FRAMES) * HDA_FRAME_BYTES,
                       100u);

    if (state.fade_in_frames != 0u)
    {
        fprintf(stderr, "fade state did not reach zero: %u\\n", state.fade_in_frames);
        return 1;
    }
    for (size_t frame = 0; frame < TOTAL_FRAMES; ++frame)
    {
        uint32_t numerator = frame < HDA_FADE_IN_FRAMES
            ? (uint32_t)frame + 1u
            : HDA_FADE_IN_FRAMES;
        int16_t expected_left = (int16_t)((24000 * (int32_t)numerator) /
                                          (int32_t)HDA_FADE_IN_FRAMES);
        int16_t expected_right = (int16_t)((-24000 * (int32_t)numerator) /
                                           (int32_t)HDA_FADE_IN_FRAMES);
        size_t offset = frame * HDA_FRAME_BYTES;
        int16_t actual_left = load16(output + offset);
        int16_t actual_right = load16(output + offset + 2u);
        if (actual_left != expected_left || actual_right != expected_right)
        {
            fprintf(stderr,
                    "fade mismatch frame=%zu left=%d/%d right=%d/%d\\n",
                    frame,
                    actual_left,
                    expected_left,
                    actual_right,
                    expected_right);
            return 2;
        }
    }

    uint8_t volume_output[HDA_FRAME_BYTES] = { 0 };
    state.gain_initialized = 0u;
    hda_copy_pcm_chunk(&state, volume_output, input, HDA_FRAME_BYTES, 50u);
    if (load16(volume_output) != 12000 || load16(volume_output + 2u) != -12000)
    {
        fprintf(stderr, "post-fade volume scaling changed\\n");
        return 3;
    }
    return 0;
}
"""
    compile_and_run("hda-fade-behavior", program)


def test_mp3_pending_fades(mp3: str) -> None:
    channels = uint_macro(mp3, "MP3_TARGET_CHANNELS")
    transition_frames = uint_macro(mp3, "MP3_TRANSITION_FRAMES")
    fade_in = function_definition(mp3, "static void mp3_apply_pending_fade_in")
    fade_out = function_definition(mp3, "static void mp3_apply_pending_fade_out")

    program = f"""\
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define MP3_TARGET_CHANNELS {channels}u
#define MP3_TRANSITION_FRAMES {transition_frames}u

typedef struct
{{
    int16_t *pending_buffer;
    size_t pending_samples;
    uint32_t fade_in_frames;
}} mp3_player_t;

""" + fade_in + "\n\n" + fade_out + """

static void fill_frames(int16_t *buffer, size_t frames, int16_t left, int16_t right)
{
    for (size_t frame = 0; frame < frames; ++frame)
    {
        size_t sample = frame * MP3_TARGET_CHANNELS;
        buffer[sample] = left;
        buffer[sample + 1u] = right;
    }
}

int main(void)
{
    enum { TOTAL_FRAMES = MP3_TRANSITION_FRAMES + 60u };
    int16_t pending[TOTAL_FRAMES * MP3_TARGET_CHANNELS];
    mp3_player_t player = {
        .pending_buffer = pending,
        .pending_samples = TOTAL_FRAMES * MP3_TARGET_CHANNELS,
        .fade_in_frames = MP3_TRANSITION_FRAMES,
    };

    fill_frames(pending, TOTAL_FRAMES, 24000, -24000);
    mp3_apply_pending_fade_in(&player);
    if (player.fade_in_frames != 0u)
    {
        fprintf(stderr, "pending fade-in state did not reach zero\\n");
        return 1;
    }
    for (size_t frame = 0; frame < TOTAL_FRAMES; ++frame)
    {
        uint32_t numerator = frame < MP3_TRANSITION_FRAMES
            ? (uint32_t)frame + 1u
            : MP3_TRANSITION_FRAMES;
        int16_t expected = (int16_t)((24000 * (int32_t)numerator) /
                                     (int32_t)MP3_TRANSITION_FRAMES);
        if (pending[frame * MP3_TARGET_CHANNELS] != expected)
        {
            fprintf(stderr, "pending fade-in mismatch frame=%zu\\n", frame);
            return 2;
        }
    }

    fill_frames(pending, TOTAL_FRAMES, 24000, -24000);
    mp3_apply_pending_fade_out(&player);
    size_t first_fade = TOTAL_FRAMES - MP3_TRANSITION_FRAMES;
    for (size_t frame = 0; frame < TOTAL_FRAMES; ++frame)
    {
        uint32_t numerator = frame < first_fade
            ? MP3_TRANSITION_FRAMES
            : (uint32_t)(TOTAL_FRAMES - frame);
        int16_t expected = (int16_t)((24000 * (int32_t)numerator) /
                                     (int32_t)MP3_TRANSITION_FRAMES);
        if (pending[frame * MP3_TARGET_CHANNELS] != expected)
        {
            fprintf(stderr, "pending fade-out mismatch frame=%zu\\n", frame);
            return 3;
        }
    }

    enum { SHORT_FRAMES = 10u };
    player.pending_samples = SHORT_FRAMES * MP3_TARGET_CHANNELS;
    fill_frames(pending, SHORT_FRAMES, 20000, -20000);
    mp3_apply_pending_fade_out(&player);
    for (size_t frame = 0; frame < SHORT_FRAMES; ++frame)
    {
        uint32_t numerator = (uint32_t)(SHORT_FRAMES - frame);
        int16_t expected = (int16_t)((20000 * (int32_t)numerator) /
                                     (int32_t)SHORT_FRAMES);
        if (pending[frame * MP3_TARGET_CHANNELS] != expected)
        {
            fprintf(stderr, "short pending fade-out mismatch frame=%zu\\n", frame);
            return 4;
        }
    }
    return 0;
}
"""
    compile_and_run("mp3-pending-fades", program)


def require(body: str, token: str, scope: str) -> None:
    if token not in body:
        raise AssertionError(f"{scope} must contain {token!r}")


def absent(body: str, tokens: tuple[str, ...], scope: str) -> None:
    for token in tokens:
        if token in body:
            raise AssertionError(f"{scope} must not contain {token!r}")


def before(body: str, first: str, second: str, scope: str) -> None:
    first_at = body.find(first)
    second_at = body.find(second)
    if first_at < 0 or second_at < 0 or first_at >= second_at:
        raise AssertionError(
            f"{scope}: expected {first!r} before {second!r}"
        )


def main() -> int:
    hda = source("src/drivers/hda.c")
    mp3 = source("user/apps/atk_mp3/atk_mp3_app.c")

    clear_range = function_body(hda, "static void hda_clear_ring_range")
    require(
        clear_range,
        "memset(hda->buffer + pos, 0, chunk)",
        "retired ring clearing",
    )
    absent(
        clear_range,
        ("last_sample", "HDA_FADE_FRAMES", "hda_store_stereo_frame"),
        "retired ring clearing",
    )

    silence_advance = function_body(hda, "static void hda_silence_advance")
    require(
        silence_advance,
        "hda_clear_ring_range(hda, prev, consumed)",
        "LPIB retirement",
    )

    update_used = function_body(hda, "static void hda_update_used_bytes")
    absent(
        update_used,
        ("memset(hda->buffer", "hda_prepare_buffers"),
        "live LPIB accounting",
    )
    require(
        update_used,
        "hda->needs_reprogram = true",
        "missed-ring recovery",
    )
    absent(
        silence_advance,
        ("hda_fill_pattern", "last_sample", "HDA_FADE_FRAMES"),
        "LPIB retirement",
    )

    init = function_body(hda, "void hda_init(void)")
    require(init, "hda_program_stream(&g_hda)", "HDA initialization")
    absent(
        init,
        ("hda_start_stream(&g_hda)", "HDA_SDCTL_RUN"),
        "HDA initialization",
    )

    start = function_body(hda, "static bool hda_start_stream")
    require(start, "hda->used_bytes == 0", "HDA stream start")
    before(start, "hda->used_bytes == 0", "HDA_SDCTL_RUN", "HDA stream start")
    before(start, "return false", "HDA_SDCTL_RUN", "HDA stream start")
    absent(
        start,
        ("hda->hw_pos_prev = hda_read32", "hda->used_bytes = 0"),
        "HDA stream start accounting",
    )

    stop = function_body(hda, "static bool hda_stop_stream")
    before(
        stop,
        "hda_read32(hda, ctl_off) & HDA_SDCTL_RUN",
        "hda->running = false",
        "HDA stream stop",
    )

    program = function_body(hda, "static bool hda_program_stream")
    before(
        program,
        "hda_reset_stream(hda)",
        "hda_prepare_buffers(hda)",
        "HDA recovery ordering",
    )

    write = function_body(hda, "static ssize_t hda_dev_write")
    require(
        write,
        "bool start_after_copy = !hda->running",
        "HDA write lifecycle",
    )
    before(
        write,
        "hda_copy_pcm_chunk(hda",
        "__atomic_thread_fence(__ATOMIC_RELEASE)",
        "HDA cold-start prefill",
    )
    before(
        write,
        "__atomic_thread_fence(__ATOMIC_RELEASE)",
        "hda_start_stream(hda)",
        "HDA cold-start prefill",
    )
    require(
        write,
        "(offset % HDA_FRAME_BYTES) != 0",
        "audio frame alignment",
    )
    require(
        write,
        "hda_clear_ring_range(hda, hw_pos, HDA_REPRIME_LEAD_BYTES)",
        "running underrun recovery",
    )
    require(
        write,
        "hda->used_bytes = HDA_REPRIME_LEAD_BYTES",
        "running underrun recovery",
    )
    if uint_macro(hda, "HDA_REPRIME_LEAD_BYTES") < 8192:
        raise AssertionError("running underrun lead must cover the 8 KiB fetch window")
    absent(
        write,
        ("hda_stop_stream(hda)", "hda_write_tail_guard", "hda_prepare_append"),
        "hot audio write path",
    )

    housekeeping = function_body(hda, "static void hda_service_locked")
    require(
        housekeeping,
        "if (hda->needs_reprogram)",
        "hard-error recovery",
    )

    absent(
        hda,
        (
            "tail_guard_bytes",
            "HDA_TAIL_GUARD",
            "hda_store_stereo_frame",
            "empty_since_ms",
            "HDA_IDLE_STOP_AFTER_EMPTY_MS",
        ),
        "HDA source",
    )

    require(mp3, "#define MP3_SEEK_PREROLL_BYTES", "ATK MP3 seek")
    seek = function_body(mp3, "static bool mp3_player_seek_bytes")
    require(
        seek,
        "target_offset - MP3_SEEK_PREROLL_BYTES",
        "ATK MP3 seek preroll",
    )
    require(seek, "mp3_write_pending(p, true)", "ATK MP3 seek boundary")
    require(
        seek,
        "p->discard_until_offset = target_offset",
        "ATK MP3 seek preroll",
    )

    queue_pcm = function_body(mp3, "static bool mp3_queue_pcm")
    before(
        queue_pcm,
        "mp3_write_pending(p, false)",
        "memcpy(p->pending_buffer",
        "ATK MP3 one-block lookahead",
    )
    cleanup = function_body(mp3, "static void mp3_player_cleanup")
    before(
        cleanup,
        "mp3_write_pending(p, true)",
        "close(p->audio_fd)",
        "ATK MP3 end fade",
    )

    tick = function_body(mp3, "static int mp3_player_tick")
    before(
        tick,
        "uint64_t decode_offset = mp3_current_offset(p)",
        "if (p->discard_until_offset != 0)",
        "ATK MP3 preroll discard",
    )
    require(
        tick,
        "frame_start_offset += (uint64_t)frame_info.frame_offset",
        "ATK MP3 frame location",
    )
    before(
        tick,
        "if (p->discard_until_offset != 0)",
        "mp3_queue_pcm",
        "ATK MP3 preroll discard",
    )
    require(
        tick,
        "frame_start_offset < p->discard_until_offset",
        "ATK MP3 preroll discard",
    )

    test_hda_ring_behavior(hda)
    test_hda_fade_behavior(hda)
    test_mp3_pending_fades(mp3)
    from audio_hda_state_test import test_hda_state_behavior
    test_hda_state_behavior(hda)
    from audio_mp3_stream_test import test_mp3_stream_behavior
    test_mp3_stream_behavior(mp3)

    print("audio stream contract and host behavior test passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"audio stream contract test failed: {error}", file=sys.stderr)
        raise SystemExit(1)
