#include "userlib.h"

#define WAV_BUFFER_SIZE 32768

static uint32_t read_le32(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static uint16_t read_le16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static int open_wave_file(const char *path)
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

    /* Fallback to /root/<path> so files on disk can be played without absolute paths. */
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
                printf("playsound: opened %s\n", alt);
                return fd;
            }
        }
    }
    return -1;
}

static ssize_t read_full(int fd, void *buf, size_t len)
{
    size_t total = 0;
    uint8_t *out = (uint8_t *)buf;
    while (total < len)
    {
        ssize_t got = read(fd, out + total, len - total);
        if (got <= 0)
        {
            return (total > 0) ? (ssize_t)total : got;
        }
        total += (size_t)got;
    }
    return (ssize_t)total;
}

static bool skip_bytes(int fd, size_t bytes)
{
    uint8_t scratch[256];
    size_t remaining = bytes;
    while (remaining > 0)
    {
        size_t chunk = remaining;
        if (chunk > sizeof(scratch))
        {
            chunk = sizeof(scratch);
        }
        ssize_t read_len = read(fd, scratch, chunk);
        if (read_len <= 0)
        {
            return false;
        }
        remaining -= (size_t)read_len;
    }
    return true;
}

static bool parse_wave_header(int fd,
                              uint32_t *data_size_out,
                              uint32_t *sample_rate_out,
                              uint16_t *channels_out,
                              uint16_t *bits_out)
{
    uint8_t header[12];
    if (read_full(fd, header, sizeof(header)) != (ssize_t)sizeof(header))
    {
        return false;
    }

    if (memcmp(header, "RIFF", 4) != 0 || memcmp(header + 8, "WAVE", 4) != 0)
    {
        return false;
    }

    bool have_fmt = false;
    bool have_data = false;
    uint32_t data_size = 0;
    uint32_t sample_rate = 0;
    uint16_t channels = 0;
    uint16_t bits = 0;

    while (!have_data || !have_fmt)
    {
        uint8_t chunk_header[8];
        if (read_full(fd, chunk_header, sizeof(chunk_header)) != (ssize_t)sizeof(chunk_header))
        {
            return false;
        }
        uint32_t chunk_size = read_le32(chunk_header + 4);

        if (memcmp(chunk_header, "fmt ", 4) == 0)
        {
            uint8_t fmt_buf[64];
            if (chunk_size > sizeof(fmt_buf))
            {
                if (!skip_bytes(fd, chunk_size))
                {
                    return false;
                }
                continue;
            }
            if (read_full(fd, fmt_buf, chunk_size) != (ssize_t)chunk_size)
            {
                return false;
            }

            uint16_t audio_format = read_le16(fmt_buf + 0);
            channels = read_le16(fmt_buf + 2);
            sample_rate = read_le32(fmt_buf + 4);
            bits = read_le16(fmt_buf + 14);

            if (audio_format != 1)
            {
                return false;
            }
            have_fmt = true;
        }
        else if (memcmp(chunk_header, "data", 4) == 0)
        {
            data_size = chunk_size;
            have_data = true;
            break;
        }
        else
        {
            if (!skip_bytes(fd, chunk_size))
            {
                return false;
            }
        }
    }

    if (!have_data || !have_fmt)
    {
        return false;
    }

    if (data_size_out) *data_size_out = data_size;
    if (sample_rate_out) *sample_rate_out = sample_rate;
    if (channels_out) *channels_out = channels;
    if (bits_out) *bits_out = bits;
    return true;
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        printf("Usage: playsound <wave-file>\n");
        return 1;
    }

    const char *path = argv[1];
    int fd = open_wave_file(path);
    if (fd < 0)
    {
        printf("playsound: unable to open %s\n", path);
        return 1;
    }

    uint32_t data_size = 0;
    uint32_t sample_rate = 0;
    uint16_t channels = 0;
    uint16_t bits_per_sample = 0;

    if (!parse_wave_header(fd, &data_size, &sample_rate, &channels, &bits_per_sample))
    {
        printf("playsound: invalid or unsupported wave header\n");
        close(fd);
        return 1;
    }

    if (sample_rate != 48000 || channels != 2 || bits_per_sample != 16)
    {
        printf("playsound: only 48kHz 16-bit stereo PCM is supported\n");
        close(fd);
        return 1;
    }

    int audio_fd = open("/dev/audio", SYSCALL_OPEN_WRITE);
    if (audio_fd < 0)
    {
        printf("playsound: /dev/audio unavailable\n");
        close(fd);
        return 1;
    }

    uint8_t buffer[WAV_BUFFER_SIZE];
    uint32_t remaining = data_size;
    while (remaining > 0)
    {
        size_t chunk = remaining > WAV_BUFFER_SIZE ? WAV_BUFFER_SIZE : remaining;
        ssize_t got = read_full(fd, buffer, chunk);
        if (got <= 0)
        {
            break;
        }

        ssize_t wrote = write(audio_fd, buffer, (size_t)got);
        if (wrote != got)
        {
            printf("playsound: audio write interrupted\n");
            break;
        }

        remaining -= (uint32_t)got;
    }

    close(audio_fd);
    close(fd);
    return 0;
}
