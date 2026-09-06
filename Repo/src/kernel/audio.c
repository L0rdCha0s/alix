#include "audio.h"

#include "libc.h"
#include "procfs.h"
#include "vfs.h"
#include "hda.h"

static uint32_t g_audio_volume_percent = 100;

uint32_t audio_volume_get_percent(void)
{
    uint32_t value = __atomic_load_n(&g_audio_volume_percent, __ATOMIC_RELAXED);
    if (value > 100)
    {
        value = 100;
    }
    return value;
}

void audio_volume_set_percent(uint32_t percent)
{
    if (percent > 100)
    {
        percent = 100;
    }
    __atomic_store_n(&g_audio_volume_percent, percent, __ATOMIC_RELEASE);
}

static size_t audio_append_char(char *out, size_t cap, size_t pos, char ch)
{
    if (!out || cap == 0)
    {
        return pos;
    }
    if (pos >= cap)
    {
        return pos;
    }
    out[pos++] = ch;
    return pos;
}

static size_t audio_append_uint(char *out, size_t cap, size_t pos, uint64_t value)
{
    if (!out || cap == 0 || pos >= cap)
    {
        return pos;
    }

    char tmp[20];
    size_t digits = 0;
    if (value == 0)
    {
        tmp[digits++] = '0';
    }
    else
    {
        while (value > 0 && digits < sizeof(tmp))
        {
            tmp[digits++] = (char)('0' + (value % 10u));
            value /= 10u;
        }
    }

    while (digits > 0 && pos < cap)
    {
        out[pos++] = tmp[--digits];
    }
    return pos;
}

static ssize_t audio_volume_read(vfs_node_t *node, size_t offset, void *buffer, size_t count, void *context)
{
    (void)node;
    (void)context;
    if (!buffer || count == 0)
    {
        return 0;
    }

    char tmp[16];
    size_t pos = 0;
    pos = audio_append_uint(tmp, sizeof(tmp), pos, audio_volume_get_percent());
    pos = audio_append_char(tmp, sizeof(tmp), pos, '\n');
    size_t len = pos;

    if (offset >= len)
    {
        return 0;
    }
    size_t to_copy = len - offset;
    if (to_copy > count)
    {
        to_copy = count;
    }
    memcpy(buffer, tmp + offset, to_copy);
    return (ssize_t)to_copy;
}

static bool audio_parse_volume(const char *buf, size_t count, uint32_t *value_out)
{
    if (!buf || !value_out)
    {
        return false;
    }

    size_t idx = 0;
    while (idx < count && (buf[idx] == ' ' || buf[idx] == '\t'))
    {
        ++idx;
    }

    uint64_t value = 0;
    size_t digits = 0;
    while (idx < count)
    {
        char ch = buf[idx];
        if (ch < '0' || ch > '9')
        {
            break;
        }
        value = value * 10u + (uint64_t)(ch - '0');
        ++idx;
        ++digits;
        if (value > 1000u)
        {
            return false;
        }
    }

    if (digits == 0)
    {
        return false;
    }

    while (idx < count)
    {
        char ch = buf[idx++];
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
        {
            continue;
        }
        return false;
    }

    if (value > 100u)
    {
        value = 100u;
    }

    *value_out = (uint32_t)value;
    return true;
}

static ssize_t audio_volume_write(vfs_node_t *node, size_t offset, const void *buffer, size_t count, void *context)
{
    (void)node;
    (void)context;
    (void)offset;
    if (!buffer || count == 0)
    {
        return -1;
    }

    uint32_t value = 0;
    if (!audio_parse_volume((const char *)buffer, count, &value))
    {
        return -1;
    }

    audio_volume_set_percent(value);
    return (ssize_t)count;
}

static ssize_t audio_status_read(vfs_node_t *node, size_t offset,
                                 void *buffer, size_t count, void *context)
{
    (void)node;
    if (!buffer || count == 0)
    {
        return 0;
    }
    /* Small synchronous snapshot; no stack address escapes to another thread. */
    hda_status_t status = {0};
    (void)hda_get_status(&status);
    uint64_t value;
    switch ((uintptr_t)context)
    {
        case 0: value = status.queued_bytes; break;
        case 1: value = status.empty_events; break;
        case 2: value = status.reprime_events; break;
        case 3: value = status.stream_errors; break;
        case 4: value = status.rejected_writers; break;
        case 5: value = status.writer_pid; break;
        default: value = status.running ? 1u : 0u; break;
    }
    char text[24];
    size_t len = audio_append_uint(text, sizeof(text), 0, value);
    len = audio_append_char(text, sizeof(text), len, '\n');
    if (offset >= len)
    {
        return 0;
    }
    size_t bytes = len - offset;
    if (bytes > count)
    {
        bytes = count;
    }
    memcpy(buffer, text + offset, bytes);
    return (ssize_t)bytes;
}

void audio_sys_controls_init(void)
{
    (void)procfs_create_file_at("sys/audio/volume", audio_volume_read, audio_volume_write, NULL);
    (void)procfs_create_file_at("sys/audio/queued_bytes", audio_status_read, NULL, (void *)0u);
    (void)procfs_create_file_at("sys/audio/empty_events", audio_status_read, NULL, (void *)1u);
    (void)procfs_create_file_at("sys/audio/reprime_events", audio_status_read, NULL, (void *)2u);
    (void)procfs_create_file_at("sys/audio/stream_errors", audio_status_read, NULL, (void *)3u);
    (void)procfs_create_file_at("sys/audio/rejected_writers", audio_status_read, NULL, (void *)4u);
    (void)procfs_create_file_at("sys/audio/writer_pid", audio_status_read, NULL, (void *)5u);
    (void)procfs_create_file_at("sys/audio/running", audio_status_read, NULL, (void *)6u);
}
