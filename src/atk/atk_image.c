#include "atk/atk_image.h"

#include "atk_internal.h"
#include "atk/util/jpeg.h"
#include "video.h"
#include "libc.h"
#include "heap.h"

#ifdef KERNEL_BUILD
#include "serial.h"
#endif

typedef struct
{
    uint16_t *pixels;
    int img_width;
    int img_height;
    int stride_bytes;
    atk_list_node_t *list_node;
    bool owns_pixels;
} atk_image_priv_t;

static void atk_image_invalidate(const atk_widget_t *image);

#ifdef KERNEL_BUILD
static void atk_image_log_guard(const char *label, const char *msg, const atk_widget_t *ptr)
{
    serial_printf("%s", "[atk_image] ");
    serial_printf("%s", label ? label : "check");
    serial_printf("%s", ": ");
    serial_printf("%s", msg ? msg : "invalid");
    serial_printf("%s", " ptr=0x");
    serial_printf("%016llX", (unsigned long long)((uint64_t)(uintptr_t)ptr));
    serial_printf("%s", "\r\n");
}
#else
static void atk_image_log_guard(const char *label, const char *msg, const atk_widget_t *ptr)
{
    (void)label;
    (void)msg;
    (void)ptr;
}
#endif

static bool atk_image_validate_widget(const atk_widget_t *image,
                                      const char *label,
                                      const atk_widget_t **parent_out)
{
    if (!image)
    {
        return false;
    }
    if (!atk_widget_validate(image, label))
    {
        return false;
    }
    const atk_widget_t *parent = image->parent;
    if (parent && !atk_widget_validate(parent, "atk_image parent"))
    {
        atk_image_log_guard(label, "invalid parent", parent);
        return false;
    }
    if (parent_out)
    {
        *parent_out = parent;
    }
    return true;
}

static void image_draw_cb(const atk_state_t *state,
                          const atk_widget_t *widget,
                          int origin_x,
                          int origin_y,
                          void *context);
static void image_destroy_cb(atk_widget_t *widget, void *context);
static const atk_widget_vtable_t image_vtable = { 0 };
static const atk_widget_ops_t g_image_ops = {
    .destroy = image_destroy_cb,
    .draw = image_draw_cb,
    .hit_test = NULL,
    .on_mouse = NULL,
    .on_key = NULL
};
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
    atk_widget_set_ops(image, &g_image_ops, NULL);

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
    image_priv->owns_pixels = false;

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

    return atk_image_set_pixels(image, pixels, width, height, stride_bytes, true);
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
    if (priv->pixels && priv->owns_pixels)
    {
        free(priv->pixels);
    }
    priv->pixels = NULL;
    priv->img_width = 0;
    priv->img_height = 0;
    priv->stride_bytes = 0;
    priv->owns_pixels = false;
    priv->list_node = NULL;
}

void atk_image_draw(const atk_state_t *state, const atk_widget_t *image)
{
    if (!state || !image || !image->used)
    {
        return;
    }

    atk_state_theme_validate(state, "atk_image_draw");

    const atk_widget_t *parent = NULL;
    if (!atk_image_validate_widget(image, "atk_image_draw", &parent))
    {
        return;
    }

    const atk_image_priv_t *priv = (const atk_image_priv_t *)atk_widget_priv(image, &ATK_IMAGE_CLASS);
    if (!priv)
    {
        return;
    }

    int origin_x = parent ? parent->x : 0;
    int origin_y = parent ? parent->y : 0;
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

bool atk_image_set_pixels(atk_widget_t *image,
                          uint16_t *pixels,
                          int width,
                          int height,
                          int stride_bytes,
                          bool take_ownership)
{
    if (!image || !pixels || width <= 0 || height <= 0 || stride_bytes <= 0)
    {
        return false;
    }

    atk_image_priv_t *priv = (atk_image_priv_t *)atk_widget_priv(image, &ATK_IMAGE_CLASS);
    if (!priv)
    {
        return false;
    }

    if (priv->pixels && priv->owns_pixels)
    {
        free(priv->pixels);
    }

    priv->pixels = pixels;
    priv->img_width = width;
    priv->img_height = height;
    priv->stride_bytes = stride_bytes;
    priv->owns_pixels = take_ownership;

    image->width = width;
    image->height = height;

    atk_image_invalidate(image);
    return true;
}

uint16_t *atk_image_pixels(const atk_widget_t *image)
{
    const atk_image_priv_t *priv = (const atk_image_priv_t *)atk_widget_priv(image, &ATK_IMAGE_CLASS);
    return priv ? priv->pixels : NULL;
}

int atk_image_stride_bytes(const atk_widget_t *image)
{
    const atk_image_priv_t *priv = (const atk_image_priv_t *)atk_widget_priv(image, &ATK_IMAGE_CLASS);
    return priv ? priv->stride_bytes : 0;
}

static void atk_image_invalidate(const atk_widget_t *image)
{
    if (!image)
    {
        return;
    }
    const atk_widget_t *parent = NULL;
    if (!atk_image_validate_widget(image, "atk_image_invalidate", &parent))
    {
        return;
    }
    int origin_x = parent ? parent->x : 0;
    int origin_y = parent ? parent->y : 0;
    atk_dirty_mark_rect(origin_x + image->x, origin_y + image->y, image->width, image->height);
}
static void image_draw_cb(const atk_state_t *state,
                          const atk_widget_t *widget,
                          int origin_x,
                          int origin_y,
                          void *context)
{
    (void)origin_x;
    (void)origin_y;
    (void)context;
    atk_image_draw(state, widget);
}

static void image_destroy_cb(atk_widget_t *widget, void *context)
{
    (void)context;
    atk_image_destroy(widget);
    atk_widget_destroy(widget);
}
