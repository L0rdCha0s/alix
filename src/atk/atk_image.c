#include "atk/atk_image.h"

#include "atk_internal.h"
#include "atk/util/jpeg.h"
#include "video.h"
#include "libc.h"
#include "heap.h"

typedef struct
{
    uint16_t *pixels;
    int img_width;
    int img_height;
    int stride_bytes;
    atk_list_node_t *list_node;
} atk_image_priv_t;

static void atk_image_invalidate(const atk_widget_t *image);

static const atk_widget_vtable_t image_vtable = { 0 };
const atk_class_t ATK_IMAGE_CLASS = { "Image", &ATK_WIDGET_CLASS, &image_vtable, sizeof(atk_image_priv_t) };

atk_widget_t *atk_window_add_image(atk_widget_t *window, int x, int y)
{
    if (!window)
    {
        return NULL;
    }

    atk_window_priv_t *priv = (atk_window_priv_t *)atk_widget_priv(window, &ATK_WINDOW_CLASS);
    if (!priv)
    {
        return NULL;
    }

    atk_widget_t *image = atk_widget_create(&ATK_IMAGE_CLASS);
    if (!image)
    {
        return NULL;
    }

    image->x = x;
    image->y = y;
    image->width = 0;
    image->height = 0;
    image->parent = window;
    image->used = true;

    atk_image_priv_t *image_priv = (atk_image_priv_t *)atk_widget_priv(image, &ATK_IMAGE_CLASS);
    if (!image_priv)
    {
        atk_widget_destroy(image);
        return NULL;
    }
    image_priv->pixels = NULL;
    image_priv->img_width = 0;
    image_priv->img_height = 0;
    image_priv->stride_bytes = 0;

    atk_list_node_t *child_node = atk_list_push_back(&priv->children, image);
    if (!child_node)
    {
        atk_widget_destroy(image);
        return NULL;
    }
    image_priv->list_node = child_node;

    return image;
}

bool atk_image_load_jpeg(atk_widget_t *image, const uint8_t *data, size_t size)
{
    if (!image || !data || size == 0)
    {
        return false;
    }

    atk_image_priv_t *priv = (atk_image_priv_t *)atk_widget_priv(image, &ATK_IMAGE_CLASS);
    if (!priv)
    {
        return false;
    }

    uint16_t *pixels = NULL;
    int width = 0;
    int height = 0;
    int stride_bytes = 0;
    int rc = jpeg_decode_rgb565(data, size, &pixels, &width, &height, &stride_bytes);
    if (rc != 0 || !pixels)
    {
        return false;
    }

    if (priv->pixels)
    {
        free(priv->pixels);
    }
    priv->pixels = pixels;
    priv->img_width = width;
    priv->img_height = height;
    priv->stride_bytes = stride_bytes;

    image->width = width;
    image->height = height;

    atk_image_invalidate(image);
    return true;
}

void atk_image_destroy(atk_widget_t *image)
{
    if (!image)
    {
        return;
    }
    atk_image_priv_t *priv = (atk_image_priv_t *)atk_widget_priv(image, &ATK_IMAGE_CLASS);
    if (!priv)
    {
        return;
    }
    if (priv->pixels)
    {
        free(priv->pixels);
        priv->pixels = NULL;
    }
    priv->img_width = 0;
    priv->img_height = 0;
    priv->stride_bytes = 0;
    priv->list_node = NULL;
}

void atk_image_draw(const atk_state_t *state, const atk_widget_t *image)
{
    if (!state || !image || !image->used)
    {
        return;
    }

    const atk_image_priv_t *priv = (const atk_image_priv_t *)atk_widget_priv(image, &ATK_IMAGE_CLASS);
    if (!priv)
    {
        return;
    }

    int origin_x = image->parent ? image->parent->x : 0;
    int origin_y = image->parent ? image->parent->y : 0;
    int draw_x = origin_x + image->x;
    int draw_y = origin_y + image->y;

    if (image->width > 0 && image->height > 0)
    {
        video_draw_rect(draw_x, draw_y, image->width, image->height, state->theme.window_body);
    }

    if (priv->pixels && priv->img_width > 0 && priv->img_height > 0)
    {
        video_blit_rgb565(draw_x, draw_y, priv->img_width, priv->img_height, priv->pixels, priv->stride_bytes);
    }
}

int atk_image_width(const atk_widget_t *image)
{
    const atk_image_priv_t *priv = (const atk_image_priv_t *)atk_widget_priv(image, &ATK_IMAGE_CLASS);
    return priv ? priv->img_width : 0;
}

int atk_image_height(const atk_widget_t *image)
{
    const atk_image_priv_t *priv = (const atk_image_priv_t *)atk_widget_priv(image, &ATK_IMAGE_CLASS);
    return priv ? priv->img_height : 0;
}

static void atk_image_invalidate(const atk_widget_t *image)
{
    if (!image || !image->parent)
    {
        return;
    }
    int origin_x = image->parent->x + image->x;
    int origin_y = image->parent->y + image->y;
    video_invalidate_rect(origin_x, origin_y, image->width, image->height);
}
