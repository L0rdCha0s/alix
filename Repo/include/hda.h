#ifndef HDA_H
#define HDA_H

#include "types.h"

typedef struct
{
    uint64_t queued_bytes;
    uint64_t empty_events;
    uint64_t reprime_events;
    uint64_t stream_errors;
    uint64_t rejected_writers;
    uint64_t writer_pid;
    bool running;
} hda_status_t;

void hda_init(void);
bool hda_get_status(hda_status_t *status);

/* Kernel-owned PCM streams. A caller owns the create reference; queued DMA
 * independently owns a reference until its copied PCM drains or is discarded.
 * No process pointer, user buffer, or caller stack is retained by the driver. */
typedef struct hda_pcm_stream hda_pcm_stream_t;
typedef struct
{
    uint64_t submitted_frames, played_frames, dropped_frames;
    uint64_t queued_frames, latency_frames;
    uint32_t rate, channels, frame_bytes, flags;
} hda_pcm_status_t;
#define HDA_PCM_FAILED 1u
#define HDA_PCM_RECOVERING 2u
int hda_pcm_create(uint64_t owner_pid, hda_pcm_stream_t **output);
void hda_pcm_release(hda_pcm_stream_t *stream);
/* One bounded enqueue attempt: -EAGAIN means a full/recovering queue, -EBUSY
 * means another stream owns queued PCM. Success can be a short frame-aligned
 * write. Input must be owned kernel storage for this synchronous call. */
ssize_t hda_pcm_try_write(hda_pcm_stream_t *stream, const void *pcm, size_t bytes);
int hda_pcm_snapshot(hda_pcm_stream_t *stream, hda_pcm_status_t *output);
/* Nonblocking readiness for at least one complete frame; negative errno on
 * permanent stream/device failure. Does not claim or enqueue DMA ownership. */
int hda_pcm_writable(hda_pcm_stream_t *stream);

#endif
