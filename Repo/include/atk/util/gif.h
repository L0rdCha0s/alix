#ifndef ATK_UTIL_GIF_H
#define ATK_UTIL_GIF_H

#include <stddef.h>
#include <stdint.h>
#include "video.h"

int gif_decode_rgba32(const uint8_t *gif,
                      size_t len,
                      video_color_t **out_pixels,
                      int *out_w,
                      int *out_h,
                      int *out_stride_bytes);

const char *gif_last_error(void);

#endif /* ATK_UTIL_GIF_H */
