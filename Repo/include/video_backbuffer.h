#ifndef VIDEO_BACKBUFFER_H
#define VIDEO_BACKBUFFER_H

#include "video.h"

/*
 * Kernel GUI backbuffer.
 *
 * Historical backbuffer layout, retained for source compatibility. The video
 * driver now allocates a persistent heap surface at the active mode's size.
 * PMM no longer reserves this obsolete fixed physical range.
 */

#define VIDEO_BACKBUFFER_BASE  0x0000000001800000ULL
#define VIDEO_BACKBUFFER_BYTES ((size_t)VIDEO_WIDTH * (size_t)VIDEO_HEIGHT * sizeof(video_color_t))

#endif /* VIDEO_BACKBUFFER_H */
