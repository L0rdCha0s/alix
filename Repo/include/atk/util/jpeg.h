#ifndef ATK_UTIL_JPEG_H
#define ATK_UTIL_JPEG_H

#include <stddef.h>
#include <stdint.h>
#include "video.h"

int jpeg_decode_rgba32(const uint8_t *jpeg, size_t len,
                       video_color_t **out_pixels, int *out_w, int *out_h, int *out_stride_bytes);

const char *jpeg_last_error(void);


#endif /* ATK_UTIL_JPEG_H */
