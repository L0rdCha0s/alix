#include "alix_audio.h"
#include "usyscall.h"
#include "errno.h"

static int64_t audio_result(int64_t result)
{
    if (result < 0) { errno = (int)-result; return -1; }
    return result;
}

int alix_audio_open(uint32_t flags)
{
    return (int)audio_result(sys_file_io(SYSCALL_FILE_AUDIO_OPEN, flags, 0, 0, 0));
}

ssize_t alix_audio_write(int handle, const void *pcm, size_t bytes)
{
    return (ssize_t)audio_result(sys_file_io(SYSCALL_FILE_AUDIO_WRITE, (uint64_t)(int64_t)handle,
                                              (uintptr_t)pcm, bytes, 0));
}

int alix_audio_get_status(int handle, alix_audio_status_t *output)
{
    return (int)audio_result(sys_file_io(SYSCALL_FILE_AUDIO_STATUS, (uint64_t)(int64_t)handle,
                                       (uintptr_t)output, sizeof(*output), SYSCALL_AUDIO_STATUS_VERSION));
}

int alix_audio_drain(int handle)
{
    return (int)audio_result(sys_file_io(SYSCALL_FILE_AUDIO_DRAIN, (uint64_t)(int64_t)handle, 0, 0, 0));
}

int alix_audio_close(int handle)
{
    return (int)audio_result(sys_file_io(SYSCALL_FILE_CLOSE, (uint64_t)(int64_t)handle, 0, 0, 0));
}
