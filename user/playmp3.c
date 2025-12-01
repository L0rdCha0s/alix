#include "userlib.h"

#define MINIMP3_IMPLEMENTATION
#define MINIMP3_NO_STDIO
#include "minimp3.h"

#define READ_CHUNK 8192u
#define INPUT_BUFFER_SIZE (READ_CHUNK * 4u)
#define TARGET_RATE 48000
#define TARGET_CHANNELS 2
#define MAX_INPUT_SAMPLES_PER_CHANNEL 1152
#define MAX_RESAMPLED_SAMPLES (MAX_INPUT_SAMPLES_PER_CHANNEL * 6 * TARGET_CHANNELS)

static int16_t clamp16(int32_t v)
{
    if (v > 32767) return 32767;
    if (v < -32768) return -32768;
    return (int16_t)v;
}

static int open_input(const char *path)
{
    if (!path)
    {
        return -1;
    }

    int fd = open(path, SYSCALL_OPEN_READ);
    if (fd >= 0)
    {
        return fd;
    }

    if (path[0] != '/')
    {
        char alt[256];
        const char prefix[] = "/root/";
        size_t prefix_len = sizeof(prefix) - 1;
        size_t path_len = strlen(path);
        if (prefix_len + path_len < sizeof(alt))
        {
            memcpy(alt, prefix, prefix_len);
            memcpy(alt + prefix_len, path, path_len);
            alt[prefix_len + path_len] = '\0';
            fd = open(alt, SYSCALL_OPEN_READ);
            if (fd >= 0)
            {
                printf("playmp3: opened %s\n", alt);
                return fd;
            }
        }
    }

    return -1;
}

static size_t resample_to_target(const mp3d_sample_t *in,
                                 size_t samples_per_channel,
                                 int src_channels,
                                 int src_rate,
                                 int16_t *out,
                                 size_t out_capacity)
{
    if (!in || !out || src_rate <= 0 || src_channels <= 0)
    {
        return 0;
    }

    uint64_t dst_per_channel = ((uint64_t)samples_per_channel * TARGET_RATE + (uint64_t)src_rate / 2u) / (uint64_t)src_rate;
    if (dst_per_channel == 0)
    {
        return 0;
    }

    size_t required = (size_t)dst_per_channel * TARGET_CHANNELS;
    if (required > out_capacity)
    {
        dst_per_channel = out_capacity / TARGET_CHANNELS;
        required = dst_per_channel * TARGET_CHANNELS;
    }

    for (uint64_t i = 0; i < dst_per_channel; ++i)
    {
        uint64_t scaled = i * (uint64_t)src_rate;
        uint64_t src_idx = scaled / TARGET_RATE;
        uint64_t frac = scaled % TARGET_RATE;
        uint64_t next = (src_idx + 1 < samples_per_channel) ? (src_idx + 1) : src_idx;

        for (int ch = 0; ch < TARGET_CHANNELS; ++ch)
        {
            int ch_src = (src_channels == 1) ? 0 : ch;
            int32_t s0 = in[src_idx * (uint64_t)src_channels + ch_src];
            int32_t s1 = in[next * (uint64_t)src_channels + ch_src];
            int64_t blended = s0 * (int64_t)(TARGET_RATE - frac) + s1 * (int64_t)frac;
            int32_t sample = (int32_t)(blended / TARGET_RATE);
            out[i * TARGET_CHANNELS + (uint64_t)ch] = clamp16(sample);
        }
    }

    return required;
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        printf("Usage: playmp3 <file>\n");
        return 1;
    }

    int input_fd = open_input(argv[1]);
    if (input_fd < 0)
    {
        printf("playmp3: unable to open %s\n", argv[1]);
        return 1;
    }

    mp3dec_t dec;
    mp3dec_init(&dec);

    int audio_fd = open("/dev/audio", SYSCALL_OPEN_WRITE);
    if (audio_fd < 0)
    {
        printf("playmp3: /dev/audio unavailable\n");
        close(input_fd);
        return 1;
    }

    int16_t *out_buffer = (int16_t *)malloc(sizeof(int16_t) * MAX_RESAMPLED_SAMPLES);
    mp3d_sample_t *decode_buffer = (mp3d_sample_t *)malloc(sizeof(mp3d_sample_t) * MINIMP3_MAX_SAMPLES_PER_FRAME);
    if (!out_buffer || !decode_buffer)
    {
        printf("playmp3: out of memory\n");
        if (out_buffer) free(out_buffer);
        close(audio_fd);
        close(input_fd);
        if (decode_buffer) free(decode_buffer);
        return 1;
    }

    uint8_t *in_buffer = (uint8_t *)malloc(INPUT_BUFFER_SIZE);
    if (!in_buffer)
    {
        printf("playmp3: out of memory\n");
        free(decode_buffer);
        free(out_buffer);
        close(audio_fd);
        close(input_fd);
        return 1;
    }

    size_t buf_filled = 0;
    size_t buf_pos = 0;
    ssize_t initial = read(input_fd, in_buffer, INPUT_BUFFER_SIZE);
    if (initial <= 0)
    {
        printf("playmp3: empty input\n");
        free(in_buffer);
        free(out_buffer);
        free(decode_buffer);
        close(audio_fd);
        close(input_fd);
        return 1;
    }
    buf_filled = (size_t)initial;

    for (;;)
    {
        mp3dec_frame_info_t frame_info;
        int samples = mp3dec_decode_frame(&dec,
                                          in_buffer + buf_pos,
                                          (int)(buf_filled - buf_pos),
                                          decode_buffer,
                                          &frame_info);

        if (frame_info.frame_bytes == 0 && samples == 0)
        {
            if (buf_pos > 0 && buf_pos < buf_filled)
            {
                memmove(in_buffer, in_buffer + buf_pos, buf_filled - buf_pos);
                buf_filled -= buf_pos;
                buf_pos = 0;
            }
            else if (buf_pos == buf_filled)
            {
                buf_pos = 0;
                buf_filled = 0;
            }

            ssize_t got = read(input_fd, in_buffer + buf_filled, INPUT_BUFFER_SIZE - buf_filled);
            if (got <= 0)
            {
                break;
            }
            buf_filled += (size_t)got;
            continue;
        }

        buf_pos += (size_t)frame_info.frame_bytes;
        if (samples <= 0)
        {
            if (buf_pos >= buf_filled)
            {
                buf_pos = 0;
                buf_filled = 0;
            }
            continue;
        }

        if (frame_info.hz <= 0 || frame_info.channels <= 0)
        {
            continue;
        }

        /* minimp3 returns samples per channel; do not divide by channel count. */
        size_t samples_per_channel = (size_t)samples;
        size_t out_samples = resample_to_target(decode_buffer,
                                                samples_per_channel,
                                                frame_info.channels,
                                                frame_info.hz,
                                                out_buffer,
                                                MAX_RESAMPLED_SAMPLES);
        if (out_samples == 0)
        {
            continue;
        }

        size_t bytes_to_write = out_samples * sizeof(int16_t);
        size_t written = 0;
        while (written < bytes_to_write)
        {
            ssize_t w = write(audio_fd, (uint8_t *)out_buffer + written, bytes_to_write - written);
            if (w <= 0)
            {
                printf("playmp3: audio write failed\n");
                free(in_buffer);
                free(out_buffer);
                free(decode_buffer);
                close(audio_fd);
                close(input_fd);
                return 1;
            }
            written += (size_t)w;
        }

        if (buf_pos >= buf_filled)
        {
            buf_pos = 0;
            buf_filled = 0;
        }
    }

    free(in_buffer);
    free(out_buffer);
    free(decode_buffer);
    close(audio_fd);
    close(input_fd);
    return 0;
}
