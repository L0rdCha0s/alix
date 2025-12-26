#ifndef ATK_IMAGE_H
#define ATK_IMAGE_H

#include <stddef.h>
#include <stdint.h>

#include "atk/object.h"
#include "video.h"

struct atk_state;
typedef struct atk_state atk_state_t;

/*
 * Create an image widget as a child of `window`.
 *
 * The returned widget is owned by the window and will be destroyed with it.
 * Initial size is 0×0; call `atk_image_set_pixels()` or a loader to size it.
 */
atk_widget_t *atk_window_add_image(atk_widget_t *window, int x, int y);

/*
 * Decode a JPEG into RGBA32 pixels and set the image contents.
 *
 * The decoded pixel buffer is owned by the image widget.
 */
bool atk_image_load_jpeg(atk_widget_t *image, const uint8_t *data, size_t size);

/*
 * Decode a PNG into RGBA32 pixels and set the image contents.
 *
 * The decoded pixel buffer is owned by the image widget.
 */
bool atk_image_load_png(atk_widget_t *image, const uint8_t *data, size_t size);

/*
 * Decode a GIF into RGBA32 pixels and set the image contents.
 *
 * The decoded pixel buffer is owned by the image widget.
 */
bool atk_image_load_gif(atk_widget_t *image, const uint8_t *data, size_t size);

/*
 * Load an image by sniffing the input format.
 *
 * Prefers GIF/PNG/JPEG signature detection and falls back to trying each decoder.
 */
bool atk_image_load_image(atk_widget_t *image, const uint8_t *data, size_t size);

/*
 * Replace the image pixel buffer.
 *
 * `stride_bytes` is the number of bytes between rows in `pixels`. If
 * `take_ownership` is true, the image will `free()` the buffer when replaced or
 * destroyed.
 */
bool atk_image_set_pixels(atk_widget_t *image,
                          video_color_t *pixels,
                          int width,
                          int height,
                          int stride_bytes,
                          bool take_ownership);

/* Return the current pixel buffer pointer (may be NULL). */
video_color_t *atk_image_pixels(const atk_widget_t *image);

/* Return the current pixel stride in bytes (0 when unset). */
int atk_image_stride_bytes(const atk_widget_t *image);

/* Destroy image-owned resources (pixel buffer if owned). */
void atk_image_destroy(atk_widget_t *image);

/* Draw the image into the current backbuffer. */
void atk_image_draw(const atk_state_t *state, const atk_widget_t *image);

/* Return the current image pixel width (0 when unset). */
int atk_image_width(const atk_widget_t *image);

/* Return the current image pixel height (0 when unset). */
int atk_image_height(const atk_widget_t *image);

extern const struct atk_class ATK_IMAGE_CLASS;

#endif /* ATK_IMAGE_H */
