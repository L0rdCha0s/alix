#include "io_audio.h"
#include "errno.h"

_Static_assert(sizeof(syscall_audio_status_t) == 64, "audio status wire layout");

static int io_audio_close(void *context)
{
    hda_pcm_release(context);
    return 0;
}

static uint32_t io_audio_poll(void *context)
{
    int result = hda_pcm_writable(context);
    return result < 0 ? SYSCALL_POLL_ERR : result ? SYSCALL_POLL_OUT : 0;
}
static const fd_ops_t io_audio_ops = { .close = io_audio_close, .poll = io_audio_poll };

bool io_audio_description_valid(const fd_description_t *description)
{
    return description && fd_description_ops(description)->close == io_audio_close;
}

int io_audio_create(fd_retirement_queue_t *retirement, uint64_t owner_pid,
                      fd_description_t **output)
{
    if (!output || !retirement) return -EINVAL;
    *output = NULL;
    hda_pcm_stream_t *stream = NULL;
    int result = hda_pcm_create(owner_pid, &stream);
    if (result) return result;
    *output = fd_description_create_deferred(&io_audio_ops, stream, retirement);
    if (!*output) { hda_pcm_release(stream); return -ENOMEM; }
    (void)fd_description_initialize_status(*output, FD_STATUS_WRITE);
    return 0;
}

int io_audio_stat(const fd_description_t *description, syscall_stat_t *output)
{
    if (!io_audio_description_valid(description)) return -EBADF;
    if (!output) return -EINVAL;
    *output = (syscall_stat_t){ .type = SYSCALL_NODE_TYPE_CHARACTER };
    return 0;
}

bool io_audio_execute(io_request_t *request, io_service_result_t *result)
{
    if (!result) return true;
    result->result = -EINVAL; result->description_owned = NULL;
    if (!request || io_request_buffer_size(request) < sizeof(io_audio_operation_t)) return true;
    io_audio_operation_t *operation = io_request_buffer(request);
    size_t available = io_request_buffer_size(request) - sizeof(*operation);
    if (operation->reserved || operation->count > available) return true;
    fd_description_t *description = io_request_description(request);
    if (!io_audio_description_valid(description)) { result->result = -ENOTTY; return true; }
    hda_pcm_stream_t *stream = fd_description_context(description);
    if (operation->opcode == IO_AUDIO_READ) { result->result = -EBADF; return true; }
    if (operation->opcode == IO_AUDIO_WRITE)
    {
        result->result = hda_pcm_try_write(stream, operation->data, (size_t)operation->count);
        if (result->result == -EAGAIN && !(fd_description_status_flags(description) & FD_STATUS_NONBLOCK)) return false;
        if (result->result > 0 && ((uint64_t)result->result > operation->count || result->result % 4))
            result->result = -EIO;
        return true;
    }
    if (operation->opcode != IO_AUDIO_STATUS && operation->opcode != IO_AUDIO_DRAIN) return true;
    if ((operation->opcode == IO_AUDIO_STATUS && operation->count != sizeof(syscall_audio_status_t)) ||
        (operation->opcode == IO_AUDIO_DRAIN && operation->count)) return true;
    result->result = hda_pcm_snapshot(stream, &operation->status);
    if (result->result) return true;
    if (operation->opcode == IO_AUDIO_DRAIN)
    {
        if (operation->status.flags & HDA_PCM_FAILED) { result->result = -EIO; return true; }
        return operation->status.queued_frames == 0;
    }
    syscall_audio_status_t *output = (void *)operation->data;
    *output = (syscall_audio_status_t){ .version = SYSCALL_AUDIO_STATUS_VERSION, .size = sizeof(*output),
        .rate = operation->status.rate, .channels = operation->status.channels,
        .frame_bytes = operation->status.frame_bytes,
        .flags = ((operation->status.flags & HDA_PCM_FAILED) ? SYSCALL_AUDIO_FAILED : 0) |
                 ((operation->status.flags & HDA_PCM_RECOVERING) ? SYSCALL_AUDIO_RECOVERING : 0),
        .submitted_frames = operation->status.submitted_frames,
        .played_frames = operation->status.played_frames, .dropped_frames = operation->status.dropped_frames,
        .queued_frames = operation->status.queued_frames, .latency_frames = operation->status.latency_frames };
    return true;
}
