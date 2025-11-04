#ifndef ATK_UTIL_JPEG_H
#define ATK_UTIL_JPEG_H

#include <stddef.h>
#include <stdint.h>

int jpeg_decode_rgb565(const uint8_t *jpeg, size_t len,
                       uint16_t **out_pixels, int *out_w, int *out_h, int *out_stride_bytes);

const char *jpeg_last_error(void);


#endif /* ATK_UTIL_JPEG_H */
