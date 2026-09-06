#!/usr/bin/env python3
"""Run the real MP3 producer/decoder against deterministic read boundaries."""

from pathlib import Path
import sys

sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition


def test_mp3_stream_behavior(mp3: str) -> None:
    definitions = mp3[mp3.index("#define MP3_TARGET_RATE"):mp3.index("typedef struct\n{\n    atk_user_window_t")]
    program = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#define MINIMP3_IMPLEMENTATION
#define MINIMP3_NO_STDIO
'''
    program += '#include "' + str(ROOT / "user/lib/minimp3.h") + '"\n'
    program += r'''
typedef uint64_t alix_thread_t;
static const uint8_t *input_data;
static size_t input_size, input_pos, read_limit, read_calls;
static int16_t *captured;
static size_t captured_samples, captured_capacity;
static size_t decode_calls, decoded_frames;
static bool inject_read_error, inject_audio_error;
static bool interrupt_streaming_worker;
static bool *stop_flag;
static size_t stop_after_frames;

static ssize_t test_read(int fd, void *out, size_t count)
{
    (void)fd;
    if (++read_calls > 1000000u) abort();
    if (inject_read_error && input_pos >= 1000u) return -1;
    if (count > read_limit) count = read_limit;
    if (count > input_size - input_pos) count = input_size - input_pos;
    if (inject_read_error && count > 1000u - input_pos) count = 1000u - input_pos;
    memcpy(out, input_data + input_pos, count);
    input_pos += count;
    return (ssize_t)count;
}

static bool mp3_write_all(int fd, const void *pcm, size_t bytes)
{
    (void)fd;
    if (inject_audio_error) return false;
    size_t count = bytes / sizeof(int16_t);
    if (bytes % sizeof(int16_t)) abort();
    if (captured_samples + count > captured_capacity)
    {
        captured_capacity = (captured_samples + count) * 2u + 4096u;
        captured = realloc(captured, captured_capacity * sizeof(*captured));
        if (!captured) abort();
    }
    memcpy(captured + captured_samples, pcm, bytes);
    captured_samples += count;
    return true;
}

static int test_decode(mp3dec_t *decoder, const uint8_t *input, int bytes,
                       mp3d_sample_t *pcm, mp3dec_frame_info_t *info)
{
    if (++decode_calls > 100000u) abort();
    int samples = mp3dec_decode_frame(decoder, input, bytes, pcm, info);
    if (samples > 0) decoded_frames++;
    if (stop_after_frames && decoded_frames == stop_after_frames)
        __atomic_store_n(stop_flag, true, __ATOMIC_RELEASE);
    return samples;
}

'''
    program += '#define read test_read\n#define mp3dec_decode_frame test_decode\n'
    program += '#include "' + str(ROOT / "user/lib/mp3_stream.h") + '"\n'
    program += '#undef read\n#undef mp3dec_decode_frame\n'
    program += definitions
    for signature in (
        "static uint64_t mp3_current_offset",
        "static int16_t mp3_clamp16",
        "static size_t mp3_resample_to_target",
        "static void mp3_apply_pending_fade_in",
        "static void mp3_apply_pending_fade_out",
        "static bool mp3_write_pending",
        "static bool mp3_queue_pcm",
    ):
        program += function_definition(mp3, signature) + "\n"
    program += function_definition(mp3, "static int mp3_player_tick") + "\n"
    program += function_definition(mp3, "static void mp3_audio_worker") + "\n"
    program += r'''
#undef read
#undef mp3dec_decode_frame

typedef struct { int16_t *pcm; size_t samples, frames; } result_t;

static result_t render(const uint8_t *data, size_t bytes, size_t max_read, bool whole)
{
    mp3_player_t *p = calloc(1, sizeof(*p));
    if (!p) abort();
    input_data = data; input_size = bytes; input_pos = 0;
    read_limit = max_read; read_calls = 0;
    captured = NULL; captured_samples = 0; captured_capacity = 0;
    decoded_frames = 0; decode_calls = 0;
    p->input.capacity = whole && bytes > MP3_INPUT_BUFFER_SIZE ? bytes : MP3_INPUT_BUFFER_SIZE;
    p->input.buffer = malloc(p->input.capacity);
    p->decode_buffer = malloc(sizeof(mp3d_sample_t) * MINIMP3_MAX_SAMPLES_PER_FRAME);
    p->out_buffer = malloc(sizeof(int16_t) * MP3_MAX_RESAMPLED_SAMPLES);
    p->pending_buffer = malloc(sizeof(int16_t) * MP3_MAX_RESAMPLED_SAMPLES);
    if (!p->input.buffer || !p->decode_buffer || !p->out_buffer || !p->pending_buffer) abort();
    p->input_fd = 1; p->audio_fd = 2; p->file_size = bytes;
    p->fade_in_frames = MP3_TRANSITION_FRAMES; p->active = true;
    stop_flag = &p->worker_stop;
    stop_after_frames = interrupt_streaming_worker && !whole ? 7u : 0u;
    mp3dec_init(&p->dec);
    if (whole)
    {
        memcpy(p->input.buffer, data, bytes);
        input_pos = bytes; p->input.filled = bytes; p->input.file_pos = bytes;
        p->input.eof = true;
    }
    mp3_audio_worker(p);
    if (stop_after_frames)
    {
        if (!p->worker_done || p->worker_result != MP3_PLAYER_RUNNING ||
            decoded_frames != stop_after_frames || !p->pending_samples) abort();
        stop_after_frames = 0;
        __atomic_store_n(&p->worker_stop, false, __ATOMIC_RELEASE);
        __atomic_store_n(&p->worker_done, false, __ATOMIC_RELEASE);
        mp3_audio_worker(p);
    }
    int expected_result = inject_read_error ? MP3_PLAYER_READ_ERROR :
                          inject_audio_error ? MP3_PLAYER_AUDIO_ERROR : MP3_PLAYER_FINISHED;
    if (!p->worker_done || p->worker_result != expected_result || p->pending_samples)
    {
        fprintf(stderr, "unexpected producer completion: result=%d pending=%zu\n",
                p->worker_result, p->pending_samples);
        exit(1);
    }
    result_t result = { captured, captured_samples, decoded_frames };
    free(p->pending_buffer); free(p->out_buffer); free(p->decode_buffer); free(p->input.buffer); free(p);
    return result;
}

static void compare_against(const char *fixture, const char *scenario,
                    const uint8_t *data, size_t bytes, size_t max_read,
                    const uint8_t *reference_data, size_t reference_bytes)
{
    result_t expected = render(reference_data, reference_bytes, reference_bytes + 1u, true);
    result_t actual = render(data, bytes, max_read, false);
    if (expected.frames != actual.frames || expected.samples != actual.samples ||
        (expected.samples && memcmp(expected.pcm, actual.pcm, expected.samples * sizeof(int16_t)) != 0))
    {
        fprintf(stderr,
                "%s %s read_limit=%zu: whole=%zu MPEG frames/%zu PCM samples, streaming=%zu/%zu; PCM must match exactly\n",
                fixture, scenario, max_read, expected.frames, expected.samples, actual.frames, actual.samples);
        exit(1);
    }
    if (bytes > MP3_INPUT_BUFFER_SIZE && expected.frames < 70u)
    {
        fprintf(stderr, "%s baseline unexpectedly lost audio\n", fixture);
        exit(1);
    }
    free(expected.pcm); free(actual.pcm);
}

static void compare(const char *fixture, const char *scenario,
                    const uint8_t *data, size_t bytes, size_t max_read)
{
    compare_against(fixture, scenario, data, bytes, max_read, data, bytes);
}

static void exercise(const char *path)
{
    FILE *file = fopen(path, "rb");
    if (!file) abort();
    if (fseek(file, 0, SEEK_END) != 0) abort();
    size_t bytes = (size_t)ftell(file);
    if (fseek(file, 0, SEEK_SET) != 0) abort();
    uint8_t *data = calloc(1, bytes + 65536u);
    if (!data || fread(data, 1, bytes, file) != bytes) abort();
    fclose(file);
    if (bytes <= MP3_INPUT_BUFFER_SIZE || !hdr_valid(data)) abort();
    size_t scan = 0, encoded_frames = 0;
    while (scan < bytes)
    {
        if (bytes - scan < HDR_SIZE || !hdr_valid(data + scan)) abort();
        size_t frame_bytes = (size_t)(hdr_frame_bytes(data + scan, 0) + hdr_padding(data + scan));
        if (frame_bytes < HDR_SIZE || frame_bytes > bytes - scan) abort();
        scan += frame_bytes; encoded_frames++;
    }
    result_t baseline = render(data, bytes, bytes, true);
    if (baseline.frames != encoded_frames) abort();
    free(baseline.pcm);
    size_t limits[] = { MP3_INPUT_BUFFER_SIZE, 8192u, 257u, 17u, 3u, 1u };
    for (size_t i = 0; i < sizeof(limits) / sizeof(*limits); ++i)
        compare(path, "complete file", data, bytes, limits[i]);
    interrupt_streaming_worker = true;
    compare(path, "worker stop/resume preserves decoder and pending PCM", data, bytes, 257u);
    interrupt_streaming_worker = false;

    size_t first_frame = (size_t)(hdr_frame_bytes(data, 0) + hdr_padding(data));
    result_t one = render(data, first_frame, 1u, false);
    size_t wanted = (size_t)hdr_frame_samples(data) * MP3_TARGET_CHANNELS;
    if (hdr_sample_rate_hz(data) != MP3_TARGET_RATE)
        wanted = (size_t)(((uint64_t)(hdr_frame_samples(data) - 1) * MP3_TARGET_RATE + hdr_sample_rate_hz(data) - 1u) / hdr_sample_rate_hz(data)) * MP3_TARGET_CHANNELS;
    if (one.frames != 1u || one.samples != wanted)
    {
        fprintf(stderr, "%s final pending block not flushed once: frames=%zu samples=%zu expected=%zu\n",
                path, one.frames, one.samples, wanted);
        exit(1);
    }
    free(one.pcm);
    compare(path, "exact first frame EOF", data, first_frame, first_frame);
    compare(path, "truncated last frame", data, bytes - 173u, 257u);
    compare(path, "less than header", data, 3u, 1u);
    compare(path, "empty", data, 0u, 1u);
    memcpy(data + bytes, "TAG", 3u);
    memset(data + bytes + 3u, 0x4Au, 125u);
    compare_against(path, "trailing ID3v1", data, bytes + 128u, 17u, data, bytes);
    memset(data + bytes, 0, 4096u);
    compare(path, "unrecognized trailing padding terminates", data, bytes + 4096u, 257u);
    const uint8_t ape_footer[32] = { 'A','P','E','T','A','G','E','X', 0xD0,0x07,0,0, 32,0,0,0 };
    memcpy(data + bytes, ape_footer, sizeof(ape_footer));
    compare_against(path, "trailing APEv2", data, bytes + sizeof(ape_footer), 17u, data, bytes);
    memcpy(data + bytes + sizeof(ape_footer), "TAG", 3u);
    memset(data + bytes + sizeof(ape_footer) + 3u, 0x4Au, 125u);
    compare_against(path, "trailing APEv2 plus ID3v1", data, bytes + sizeof(ape_footer) + 128u, 257u, data, bytes);
    inject_read_error = true;
    result_t read_error = render(data, bytes, 257u, false);
    if (read_error.samples || read_error.frames) abort();
    free(read_error.pcm); inject_read_error = false;
    inject_audio_error = true;
    result_t audio_error = render(data, bytes, 257u, false);
    if (audio_error.samples) abort();
    free(audio_error.pcm); inject_audio_error = false;
    memmove(data + 35000u, data, bytes);
    memset(data, 0, 35000u);
    memcpy(data, "ID3\004\000\000\000\002\021\056", 10u);
    compare_against(path, "large leading ID3 tag", data, bytes + 35000u, 257u, data + 35000u, bytes);
    free(data);
}

int main(void)
{
'''
    for fixture in ("tone-44100-stereo.mp3", "tone-48000-stereo.mp3"):
        program += '    exercise("' + str(ROOT / "tests/fixtures/audio" / fixture) + '");\n'
    program += '    puts("real MP3 stream boundaries and complete PCM equivalence passed");\n    return 0;\n}\n'
    compile_and_run("mp3-stream-behavior", program)


if __name__ == "__main__":
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "user/apps/atk_mp3/atk_mp3_app.c"
    test_mp3_stream_behavior(path.read_text())
