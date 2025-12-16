#ifndef VIDEO_BACKBUFFER_H
#define VIDEO_BACKBUFFER_H

#include "video.h"

/*
 * Kernel GUI backbuffer.
 *
 * The video driver currently uses a fixed physical address for its software
 * backbuffer (identity-mapped). With the PMM in place, this range must be
 * reserved so it is never handed out as allocatable RAM (e.g. for user heap
 * pages), otherwise video drawing will corrupt unrelated memory.
 */

#define VIDEO_BACKBUFFER_BASE  0x0000000001800000ULL
#define VIDEO_BACKBUFFER_BYTES ((size_t)VIDEO_WIDTH * (size_t)VIDEO_HEIGHT * sizeof(video_color_t))

#endif /* VIDEO_BACKBUFFER_H */
