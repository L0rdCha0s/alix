#ifndef ALIX_MP3_STREAM_H
#define ALIX_MP3_STREAM_H

/* Include minimp3.h and the caller's libc declarations before this header. */
#define MP3_STREAM_BUFFER_SIZE 32768u
#define MP3_STREAM_LOOKAHEAD 16384u
#define MP3_STREAM_EOF (-1)
#define MP3_STREAM_ERROR (-2)

typedef struct
{
    uint8_t *buffer;
    size_t capacity;
    size_t filled;
    size_t consumed;
    uint64_t file_pos;
    bool eof;
    bool failed;
} mp3_stream_input_t;

static inline uint64_t mp3_stream_offset(const mp3_stream_input_t *input)
{
    return input->file_pos - (uint64_t)(input->filled - input->consumed);
}

/* Exclude recognized trailing tags from decoder lookahead, not file offsets. */
static inline size_t mp3_stream_audio_bytes(const uint8_t *buffer, size_t bytes)
{
    if (bytes >= 128u && memcmp(buffer + bytes - 128u, "TAG", 3u) == 0)
    {
        bytes -= 128u;
        if (bytes >= 227u && memcmp(buffer + bytes - 227u, "TAG+", 4u) == 0)
        {
            bytes -= 227u;
        }
    }
    if (bytes >= 32u && memcmp(buffer + bytes - 32u, "APETAGEX", 8u) == 0)
    {
        const uint8_t *footer = buffer + bytes - 32u;
        uint32_t version = (uint32_t)footer[8] | ((uint32_t)footer[9] << 8) |
                           ((uint32_t)footer[10] << 16) | ((uint32_t)footer[11] << 24);
        uint32_t size = (uint32_t)footer[12] | ((uint32_t)footer[13] << 8) |
                        ((uint32_t)footer[14] << 16) | ((uint32_t)footer[15] << 24);
        uint32_t flags = (uint32_t)footer[20] | ((uint32_t)footer[21] << 8) |
                         ((uint32_t)footer[22] << 16) | ((uint32_t)footer[23] << 24);
        /* The declared APE size includes its footer and excludes its header. */
        if ((version == 1000u || version == 2000u) && size >= 32u && size <= bytes &&
            (flags & (1u << 29)) == 0)
        {
            size_t start = bytes - size;
            if ((flags & (1u << 31)) != 0)
            {
                if (start < 32u || memcmp(buffer + start - 32u, "APETAGEX", 8u) != 0)
                {
                    return bytes;
                }
                start -= 32u;
            }
            bytes = start;
        }
    }
    return bytes;
}

/*
 * minimp3 treats an incomplete input frame as lost synchronization and resets
 * its bit reservoir. Refill before decoding, retaining unread bytes and enough
 * lookahead for frame synchronization (also used by minimp3_ex's streaming API).
 * A short successful read is not EOF: only a zero-byte read ends the stream.
 */
static inline bool mp3_stream_refill(mp3_stream_input_t *input, int fd)
{
    if (!input || !input->buffer || input->capacity < MP3_STREAM_BUFFER_SIZE ||
        input->consumed > input->filled || input->filled > input->capacity ||
        input->failed)
    {
        return false;
    }
    if (input->eof || input->filled - input->consumed > MP3_STREAM_LOOKAHEAD)
    {
        return true;
    }

    size_t remaining = input->filled - input->consumed;
    if (remaining && input->consumed)
    {
        memmove(input->buffer, input->buffer + input->consumed, remaining);
    }
    input->filled = remaining;
    input->consumed = 0;

    while (input->filled < input->capacity)
    {
        size_t wanted = input->capacity - input->filled;
        ssize_t got = read(fd, input->buffer + input->filled, wanted);
        if (got < 0 || (size_t)got > wanted)
        {
            input->failed = true;
            return false;
        }
        if (got == 0)
        {
            input->eof = true;
            break;
        }
        input->filled += (size_t)got;
        input->file_pos += (uint64_t)got;
    }
    return true;
}

/* Return samples per channel, zero for skipped input, or an EOF/error code. */
static inline int mp3_stream_next(mp3_stream_input_t *input,
                                  mp3dec_t *decoder,
                                  int fd,
                                  mp3d_sample_t *pcm,
                                  mp3dec_frame_info_t *info)
{
    if (!decoder || !pcm || !info || !mp3_stream_refill(input, fd))
    {
        return MP3_STREAM_ERROR;
    }
    size_t available = input->filled - input->consumed;
    if (input->eof)
    {
        available = mp3_stream_audio_bytes(input->buffer + input->consumed, available);
    }
    if (available == 0)
    {
        input->consumed = input->filled;
        return MP3_STREAM_EOF;
    }

    memset(info, 0, sizeof(*info));
    int samples = mp3dec_decode_frame(decoder,
                                      input->buffer + input->consumed,
                                      (int)available,
                                      pcm,
                                      info);
    if (info->frame_bytes <= 0 || (size_t)info->frame_bytes > available)
    {
        input->failed = true;
        return MP3_STREAM_ERROR;
    }

    /*
     * A large ID3 tag or damaged region can end just before a partial frame at
     * the far end of the buffer. If sync found nothing, retain the suffix for
     * the next read instead of discarding that possible frame header.
     */
    if (samples == 0 && (size_t)info->frame_bytes == available && !input->eof)
    {
        info->frame_bytes = (int)(available - MP3_STREAM_LOOKAHEAD);
    }
    input->consumed += (size_t)info->frame_bytes;
    return samples;
}

#endif
