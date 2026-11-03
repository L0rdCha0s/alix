#ifndef ALIX_AUDIO_NATIVE_H
#define ALIX_AUDIO_NATIVE_H
#include "syscall_defs.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef syscall_audio_status_t alix_audio_status_t;
#define ALIX_AUDIO_CLOEXEC SYSCALL_FILE_CLOEXEC
#define ALIX_AUDIO_FAILED SYSCALL_AUDIO_FAILED
#define ALIX_AUDIO_RECOVERING SYSCALL_AUDIO_RECOVERING
/* Process-owned output channel, 48 kHz stereo S16LE. This handle belongs to the
 * private descriptor namespace; these wrappers work in both runtime profiles.
 * Queued PCM owns its metadata through DMA completion, including after close. */
__attribute__((visibility("default"))) int alix_audio_open(uint32_t flags);
__attribute__((visibility("default"))) ssize_t alix_audio_write(int handle, const void *pcm, size_t bytes);
__attribute__((visibility("default"))) int alix_audio_get_status(int handle, alix_audio_status_t *output);
__attribute__((visibility("default"))) int alix_audio_drain(int handle);
__attribute__((visibility("default"))) int alix_audio_close(int handle);
#ifdef __cplusplus
}
#endif
#endif
