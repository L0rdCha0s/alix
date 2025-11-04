#ifndef ATK_IMAGE_H
#define ATK_IMAGE_H

#include <stddef.h>
#include <stdint.h>


#include "atk/object.h"

struct atk_state;
typedef struct atk_state atk_state_t;

atk_widget_t *atk_window_add_image(atk_widget_t *window, int x, int y);
bool atk_image_load_jpeg(atk_widget_t *image, const uint8_t *data, size_t size);
void atk_image_destroy(atk_widget_t *image);
void atk_image_draw(const atk_state_t *state, const atk_widget_t *image);
int atk_image_width(const atk_widget_t *image);
int atk_image_height(const atk_widget_t *image);

extern const struct atk_class ATK_IMAGE_CLASS;

#endif /* ATK_IMAGE_H */
