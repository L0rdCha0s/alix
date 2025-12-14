# Image (`atk_image_*`)

Header: `include/atk/atk_image.h`

`atk_image` is a widget that blits a pixel buffer into the backbuffer. The image can either own its pixel buffer or reference an external buffer.

## Key functions

- `atk_window_add_image(window, x, y)` – creates an image widget (initial size is 0×0).
- `atk_image_set_pixels(image, pixels, w, h, stride_bytes, take_ownership)` – sets the pixel buffer and size.
- `atk_image_pixels(image)` / `atk_image_stride_bytes(image)` – accessors.
- `atk_image_width(image)` / `atk_image_height(image)` – dimension accessors.
- `atk_image_load_png(image, data, size)` / `atk_image_load_jpeg(image, data, size)` / `atk_image_load_image(...)` – loaders that decode and install an owned pixel buffer.
- `atk_image_draw(state, image)` / `atk_image_destroy(image)` – draw/destroy helpers.

## Notes

- The pixel format is `video_color_t` (currently RGBA32).
- When `take_ownership` is true, the image will `free()` the buffer when replaced or destroyed.
