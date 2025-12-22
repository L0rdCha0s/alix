#include "atk_user.h"

#include "atk.h"
#include "atk_app.h"
#include "atk_internal.h"
#include "atk_menu_bar.h"
#include "atk_window.h"
#include "atk/layout.h"
#include "atk/atk_font.h"
#include "atk/atk_image.h"
#include "atk/atk_label.h"
#include "atk/atk_file_dialog.h"
#include "atk/util/jpeg.h"
#include "atk/util/png.h"
#include "libc.h"
#include "video.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PREVIEW_WINDOW_WIDTH  920
#define PREVIEW_WINDOW_HEIGHT 640
#define PREVIEW_MARGIN        12
#define PREVIEW_TOOLBAR_HEIGHT 44
#define PREVIEW_STATUS_HEIGHT  26
#define PREVIEW_TOOLBAR_GAP     8
#define PREVIEW_BUTTON_GAP      8
#define PREVIEW_BUTTON_PAD     16
#define PREVIEW_BUTTON_MIN_W   52

#define PREVIEW_MIN_SCALE 0.02f
#define PREVIEW_MAX_SCALE 8.0f
#define PREVIEW_MAX_SCALED_PIXELS 16000000u

typedef enum
{
    PREVIEW_SCALE_FIT = 0,
    PREVIEW_SCALE_ACTUAL = 1,
    PREVIEW_SCALE_ZOOM = 2
} preview_scale_mode_t;

typedef struct
{
    atk_user_window_t remote;
    atk_widget_t *window;
    atk_widget_t *image;
    atk_widget_t *title_label;
    atk_widget_t *status_label;
    atk_widget_t *open_button;
    atk_widget_t *zoom_out_button;
    atk_widget_t *zoom_in_button;
    atk_widget_t *actual_button;
    atk_widget_t *fit_button;
    atk_widget_t *file_dialog;
    atk_modal_session_t dialog_modal;
    char *image_path;
    video_color_t *image_pixels;
    int image_width;
    int image_height;
    int image_stride_bytes;
    int scaled_width;
    int scaled_height;
    int view_x;
    int view_y;
    int view_w;
    int view_h;
    int pan_x;
    int pan_y;
    bool dragging;
    int drag_start_x;
    int drag_start_y;
    int drag_origin_x;
    int drag_origin_y;
    preview_scale_mode_t scale_mode;
    float zoom_scale;
    float current_scale;
    char title_text[128];
    char status_text[256];
} preview_app_t;

static void preview_apply_theme(atk_state_t *state);
static bool preview_build_ui(preview_app_t *app);
static void preview_layout(preview_app_t *app);
static void preview_update_title(preview_app_t *app);
static void preview_update_status(preview_app_t *app, const char *message);
static bool preview_load_image(preview_app_t *app, const char *path);
static bool preview_refresh_image(preview_app_t *app, bool recenter);
static void preview_center_image(preview_app_t *app);
static void preview_clamp_pan(preview_app_t *app);
static void preview_apply_pan(preview_app_t *app, bool mark_dirty);
static void preview_close_file_dialog(preview_app_t *app);

static void preview_request_redraw(preview_app_t *app)
{
    if (!app || !app->window)
    {
        return;
    }
    atk_dirty_mark_all();
    atk_window_mark_dirty(app->window);
}

static char *preview_strdup(const char *src)
{
    if (!src)
    {
        return NULL;
    }
    size_t len = strlen(src);
    char *copy = (char *)malloc(len + 1);
    if (!copy)
    {
        return NULL;
    }
    memcpy(copy, src, len + 1);
    return copy;
}

static const char *preview_basename(const char *path)
{
    if (!path || !path[0])
    {
        return "";
    }
    const char *last = path;
    for (const char *p = path; *p; ++p)
    {
        if (*p == '/')
        {
            last = p + 1;
        }
    }
    return last;
}

static int preview_button_width(const char *title)
{
    int text_width = atk_font_text_width(title ? title : "");
    int width = text_width + PREVIEW_BUTTON_PAD;
    if (width < PREVIEW_BUTTON_MIN_W)
    {
        width = PREVIEW_BUTTON_MIN_W;
    }
    return width;
}

static void preview_image_destroy(atk_widget_t *widget, void *context)
{
    (void)context;
    atk_image_destroy(widget);
    atk_widget_destroy(widget);
}

static void preview_image_draw(const atk_state_t *state,
                               const atk_widget_t *widget,
                               int origin_x,
                               int origin_y,
                               void *context)
{
    const preview_app_t *app = (const preview_app_t *)context;
    if (!state || !widget || !widget->used)
    {
        return;
    }

    const video_color_t *pixels = atk_image_pixels(widget);
    int img_w = atk_image_width(widget);
    int img_h = atk_image_height(widget);
    int stride_bytes = atk_image_stride_bytes(widget);
    if (!pixels || img_w <= 0 || img_h <= 0 || stride_bytes <= 0)
    {
        return;
    }

    int draw_x = origin_x + widget->x;
    int draw_y = origin_y + widget->y;

    int clip_x0 = 0;
    int clip_y0 = 0;
    int clip_x1 = video_screen_width();
    int clip_y1 = video_screen_height();
    if (app)
    {
        clip_x0 = app->view_x;
        clip_y0 = app->view_y;
        clip_x1 = app->view_x + app->view_w;
        clip_y1 = app->view_y + app->view_h;
    }

    int x0 = draw_x;
    int y0 = draw_y;
    int x1 = draw_x + img_w;
    int y1 = draw_y + img_h;

    if (x0 < clip_x0) x0 = clip_x0;
    if (y0 < clip_y0) y0 = clip_y0;
    if (x1 > clip_x1) x1 = clip_x1;
    if (y1 > clip_y1) y1 = clip_y1;

    int draw_w = x1 - x0;
    int draw_h = y1 - y0;
    if (draw_w <= 0 || draw_h <= 0)
    {
        return;
    }

    int offset_x = x0 - draw_x;
    int offset_y = y0 - draw_y;
    int stride_px = stride_bytes / (int)sizeof(video_color_t);
    const video_color_t *src = pixels + offset_y * stride_px + offset_x;

    video_blit_rgba32_untracked(x0, y0, draw_w, draw_h, src, stride_bytes, true);
}

static const atk_widget_ops_t g_preview_image_ops = {
    .destroy = preview_image_destroy,
    .draw = preview_image_draw,
    .hit_test = NULL,
    .on_mouse = NULL,
    .on_key = NULL
};

static void preview_apply_theme(atk_state_t *state)
{
    if (!state)
    {
        return;
    }
    state->theme.background = video_make_color(0xD3, 0xD6, 0xDB);
    state->theme.window_border = video_make_color(0xA4, 0xA7, 0xAD);
    state->theme.window_title = video_make_color(0xE1, 0xE4, 0xE8);
    state->theme.window_title_text = video_make_color(0x23, 0x25, 0x28);
    state->theme.window_body = video_make_color(0xF2, 0xF4, 0xF7);
    state->theme.button_face = video_make_color(0xE3, 0xE6, 0xEB);
    state->theme.button_border = video_make_color(0xB4, 0xB8, 0xBE);
    state->theme.button_text = video_make_color(0x1E, 0x21, 0x25);
    state->theme.desktop_icon_face = video_make_color(0x5A, 0x7E, 0xB2);
    state->theme.desktop_icon_text = state->theme.window_title_text;
    state->theme.menu_bar_face = video_make_color(0xE6, 0xE9, 0xEE);
    state->theme.menu_bar_text = state->theme.button_text;
    state->theme.menu_bar_highlight = video_make_color(0xD4, 0xD8, 0xE0);
    state->theme.menu_dropdown_face = video_make_color(0xFA, 0xFA, 0xFB);
    state->theme.menu_dropdown_border = video_make_color(0xA3, 0xA7, 0xAD);
    state->theme.menu_dropdown_text = state->theme.button_text;
    state->theme.menu_dropdown_highlight = video_make_color(0xD7, 0xDB, 0xE3);
    atk_state_theme_commit(state);
}

static bool preview_read_file(const char *path, uint8_t **data_out, size_t *size_out)
{
    if (!path || !data_out || !size_out)
    {
        return false;
    }

    FILE *fp = fopen(path, "rb");
    if (!fp)
    {
        return false;
    }
    if (fseek(fp, 0, SEEK_END) != 0)
    {
        fclose(fp);
        return false;
    }
    long size_long = ftell(fp);
    if (size_long <= 0)
    {
        fclose(fp);
        return false;
    }
    if (fseek(fp, 0, SEEK_SET) != 0)
    {
        fclose(fp);
        return false;
    }

    size_t size = (size_t)size_long;
    uint8_t *data = (uint8_t *)malloc(size);
    if (!data)
    {
        fclose(fp);
        return false;
    }

    size_t read_bytes = fread(data, 1, size, fp);
    fclose(fp);
    if (read_bytes != size)
    {
        free(data);
        return false;
    }

    *data_out = data;
    *size_out = size;
    return true;
}

static bool preview_decode_image(const uint8_t *data,
                                 size_t size,
                                 video_color_t **pixels_out,
                                 int *width_out,
                                 int *height_out,
                                 int *stride_out,
                                 const char **error_out)
{
    if (!data || size == 0 || !pixels_out || !width_out || !height_out || !stride_out)
    {
        if (error_out)
        {
            *error_out = "invalid image data";
        }
        return false;
    }

    bool is_png = (size >= 4 && data[0] == 0x89 && data[1] == 'P' && data[2] == 'N' && data[3] == 'G');
    bool is_jpeg = (size >= 2 && data[0] == 0xFF && data[1] == 0xD8);

    video_color_t *pixels = NULL;
    int width = 0;
    int height = 0;
    int stride = 0;
    const char *reason = "unknown format";

    if (is_png)
    {
        int rc = png_decode_rgba32(data, size, &pixels, &width, &height, &stride);
        if (rc == 0 && pixels)
        {
            *pixels_out = pixels;
            *width_out = width;
            *height_out = height;
            *stride_out = stride;
            return true;
        }
        if (pixels)
        {
            free(pixels);
            pixels = NULL;
        }
        reason = png_last_error();
    }
    else if (is_jpeg)
    {
        int rc = jpeg_decode_rgba32(data, size, &pixels, &width, &height, &stride);
        if (rc == 0 && pixels)
        {
            *pixels_out = pixels;
            *width_out = width;
            *height_out = height;
            *stride_out = stride;
            return true;
        }
        if (pixels)
        {
            free(pixels);
            pixels = NULL;
        }
        reason = jpeg_last_error();
    }
    else
    {
        int rc = png_decode_rgba32(data, size, &pixels, &width, &height, &stride);
        if (rc == 0 && pixels)
        {
            *pixels_out = pixels;
            *width_out = width;
            *height_out = height;
            *stride_out = stride;
            return true;
        }
        if (pixels)
        {
            free(pixels);
            pixels = NULL;
        }
        reason = png_last_error();

        rc = jpeg_decode_rgba32(data, size, &pixels, &width, &height, &stride);
        if (rc == 0 && pixels)
        {
            *pixels_out = pixels;
            *width_out = width;
            *height_out = height;
            *stride_out = stride;
            return true;
        }
        if (pixels)
        {
            free(pixels);
            pixels = NULL;
        }
        reason = jpeg_last_error();
    }

    if (error_out)
    {
        *error_out = reason ? reason : "decode failed";
    }
    return false;
}

static video_color_t *preview_scale_nearest(const video_color_t *src,
                                            int src_w,
                                            int src_h,
                                            int src_stride_bytes,
                                            int dst_w,
                                            int dst_h)
{
    if (!src || src_w <= 0 || src_h <= 0 || dst_w <= 0 || dst_h <= 0 || src_stride_bytes <= 0)
    {
        return NULL;
    }

    size_t dst_pixels = (size_t)dst_w * (size_t)dst_h;
    if (dst_pixels == 0 || dst_pixels > PREVIEW_MAX_SCALED_PIXELS)
    {
        return NULL;
    }
    size_t dst_bytes = dst_pixels * sizeof(video_color_t);
    video_color_t *dst = (video_color_t *)malloc(dst_bytes);
    if (!dst)
    {
        return NULL;
    }

    int src_stride = src_stride_bytes / (int)sizeof(video_color_t);
    for (int y = 0; y < dst_h; ++y)
    {
        int src_y = (int)((int64_t)y * src_h / dst_h);
        const video_color_t *src_row = src + src_y * src_stride;
        video_color_t *dst_row = dst + (size_t)y * (size_t)dst_w;
        for (int x = 0; x < dst_w; ++x)
        {
            int src_x = (int)((int64_t)x * src_w / dst_w);
            dst_row[x] = src_row[src_x];
        }
    }

    return dst;
}

static float preview_clamp_scale(float scale)
{
    if (scale < PREVIEW_MIN_SCALE)
    {
        return PREVIEW_MIN_SCALE;
    }
    if (scale > PREVIEW_MAX_SCALE)
    {
        return PREVIEW_MAX_SCALE;
    }
    return scale;
}

static float preview_compute_fit_scale(const preview_app_t *app)
{
    if (!app || app->image_width <= 0 || app->image_height <= 0 || app->view_w <= 0 || app->view_h <= 0)
    {
        return 1.0f;
    }

    float scale_x = (float)app->view_w / (float)app->image_width;
    float scale_y = (float)app->view_h / (float)app->image_height;
    float scale = (scale_x < scale_y) ? scale_x : scale_y;
    return preview_clamp_scale(scale);
}

static bool preview_apply_scale(preview_app_t *app, float scale)
{
    if (!app || !app->image || !app->image_pixels)
    {
        return false;
    }

    scale = preview_clamp_scale(scale);

    int target_w = (int)((float)app->image_width * scale + 0.5f);
    int target_h = (int)((float)app->image_height * scale + 0.5f);
    if (target_w < 1) target_w = 1;
    if (target_h < 1) target_h = 1;

    bool uses_original = (target_w == app->image_width && target_h == app->image_height);
    if (uses_original)
    {
        if (!atk_image_set_pixels(app->image,
                                  app->image_pixels,
                                  app->image_width,
                                  app->image_height,
                                  app->image_stride_bytes,
                                  false))
        {
            return false;
        }
        app->scaled_width = app->image_width;
        app->scaled_height = app->image_height;
        app->current_scale = scale;
        return true;
    }

    video_color_t *scaled = preview_scale_nearest(app->image_pixels,
                                                  app->image_width,
                                                  app->image_height,
                                                  app->image_stride_bytes,
                                                  target_w,
                                                  target_h);
    if (!scaled)
    {
        return false;
    }

    if (!atk_image_set_pixels(app->image,
                              scaled,
                              target_w,
                              target_h,
                              target_w * (int)sizeof(video_color_t),
                              true))
    {
        free(scaled);
        return false;
    }

    app->scaled_width = target_w;
    app->scaled_height = target_h;
    app->current_scale = scale;
    return true;
}

static void preview_center_image(preview_app_t *app)
{
    if (!app || !app->image)
    {
        return;
    }

    int x = app->view_x + (app->view_w - app->scaled_width) / 2;
    int y = app->view_y + (app->view_h - app->scaled_height) / 2;
    app->pan_x = x;
    app->pan_y = y;
    preview_clamp_pan(app);
}

static void preview_clamp_pan(preview_app_t *app)
{
    if (!app)
    {
        return;
    }

    int min_x = app->view_x + app->view_w - app->scaled_width;
    int max_x = app->view_x;
    if (app->scaled_width <= app->view_w)
    {
        int centered = app->view_x + (app->view_w - app->scaled_width) / 2;
        min_x = centered;
        max_x = centered;
    }

    int min_y = app->view_y + app->view_h - app->scaled_height;
    int max_y = app->view_y;
    if (app->scaled_height <= app->view_h)
    {
        int centered = app->view_y + (app->view_h - app->scaled_height) / 2;
        min_y = centered;
        max_y = centered;
    }

    if (app->pan_x < min_x) app->pan_x = min_x;
    if (app->pan_x > max_x) app->pan_x = max_x;
    if (app->pan_y < min_y) app->pan_y = min_y;
    if (app->pan_y > max_y) app->pan_y = max_y;
}

static void preview_apply_pan(preview_app_t *app, bool mark_dirty)
{
    if (!app || !app->image)
    {
        return;
    }
    app->image->x = app->pan_x;
    app->image->y = app->pan_y;
    if (mark_dirty)
    {
        preview_request_redraw(app);
    }
}

static float preview_current_scale(const preview_app_t *app)
{
    if (!app)
    {
        return 1.0f;
    }

    if (app->scale_mode == PREVIEW_SCALE_FIT)
    {
        return preview_compute_fit_scale(app);
    }
    if (app->scale_mode == PREVIEW_SCALE_ACTUAL)
    {
        return 1.0f;
    }
    if (app->zoom_scale <= 0.0f)
    {
        return 1.0f;
    }
    return preview_clamp_scale(app->zoom_scale);
}

static bool preview_refresh_image(preview_app_t *app, bool recenter)
{
    if (!app || !app->image_pixels)
    {
        preview_update_status(app, "Open a PNG or JPEG to begin");
        return false;
    }

    float scale = preview_current_scale(app);
    if (!preview_apply_scale(app, scale))
    {
        preview_update_status(app, "Image scale is too large");
        return false;
    }

    if (recenter)
    {
        preview_center_image(app);
    }
    else
    {
        preview_clamp_pan(app);
    }

    preview_apply_pan(app, true);
    preview_update_status(app, NULL);
    return true;
}

static void preview_update_title(preview_app_t *app)
{
    if (!app)
    {
        return;
    }

    if (app->image_path && app->image_path[0])
    {
        const char *name = preview_basename(app->image_path);
        snprintf(app->title_text, sizeof(app->title_text), "%s", name && name[0] ? name : "Preview");
        if (app->window)
        {
            char title_buf[160];
            snprintf(title_buf, sizeof(title_buf), "Preview - %s", name && name[0] ? name : "Image");
            atk_window_set_title_text(app->window, title_buf);
        }
    }
    else
    {
        snprintf(app->title_text, sizeof(app->title_text), "Preview");
        if (app->window)
        {
            atk_window_set_title_text(app->window, "Preview");
        }
    }

    if (app->title_label)
    {
        atk_label_set_text(app->title_label, app->title_text);
    }
}

static void preview_update_status(preview_app_t *app, const char *message)
{
    if (!app || !app->status_label)
    {
        return;
    }

    if (message)
    {
        snprintf(app->status_text, sizeof(app->status_text), "%s", message);
    }
    else if (!app->image_pixels)
    {
        snprintf(app->status_text, sizeof(app->status_text), "Open a PNG or JPEG to begin");
    }
    else
    {
        const char *name = preview_basename(app->image_path);
        int percent = (int)(app->current_scale * 100.0f + 0.5f);
        if (percent < 1) percent = 1;
        snprintf(app->status_text,
                 sizeof(app->status_text),
                 "%s  %dx%d  %d%%",
                 (name && name[0]) ? name : "Image",
                 app->image_width,
                 app->image_height,
                 percent);
    }

    atk_label_set_text(app->status_label, app->status_text);
    preview_request_redraw(app);
}

static void preview_layout(preview_app_t *app)
{
    if (!app || !app->window)
    {
        return;
    }

    atk_layout_t layout;
    int chrome_top = atk_window_is_chrome_visible(app->window) ? ATK_WINDOW_TITLE_HEIGHT : 0;
    atk_layout_init(&layout,
                    PREVIEW_MARGIN,
                    chrome_top + PREVIEW_MARGIN,
                    app->window->width - PREVIEW_MARGIN * 2,
                    app->window->height - chrome_top - PREVIEW_MARGIN * 2);

    atk_layout_region_t toolbar = atk_layout_take_top(&layout, PREVIEW_TOOLBAR_HEIGHT, PREVIEW_TOOLBAR_GAP);
    atk_layout_region_t status = atk_layout_take_bottom(&layout, PREVIEW_STATUS_HEIGHT, PREVIEW_TOOLBAR_GAP);
    atk_layout_region_t view = atk_layout_content(&layout);

    if (view.width < 1) view.width = 1;
    if (view.height < 1) view.height = 1;

    app->view_x = view.x;
    app->view_y = view.y;
    app->view_w = view.width;
    app->view_h = view.height;

    int btn_h = toolbar.height;
    int open_w = preview_button_width("Open");
    int fit_w = preview_button_width("Fit");
    int actual_w = preview_button_width("1:1");
    int zoom_out_w = preview_button_width("Zoom-");
    int zoom_in_w = preview_button_width("Zoom+");

    int left_x = toolbar.x;
    if (app->open_button)
    {
        app->open_button->x = left_x;
        app->open_button->y = toolbar.y;
        app->open_button->width = open_w;
        app->open_button->height = btn_h;
    }

    int right_x = toolbar.x + toolbar.width;
    if (app->fit_button)
    {
        right_x -= fit_w;
        app->fit_button->x = right_x;
        app->fit_button->y = toolbar.y;
        app->fit_button->width = fit_w;
        app->fit_button->height = btn_h;
        right_x -= PREVIEW_BUTTON_GAP;
    }
    if (app->actual_button)
    {
        right_x -= actual_w;
        app->actual_button->x = right_x;
        app->actual_button->y = toolbar.y;
        app->actual_button->width = actual_w;
        app->actual_button->height = btn_h;
        right_x -= PREVIEW_BUTTON_GAP;
    }
    if (app->zoom_in_button)
    {
        right_x -= zoom_in_w;
        app->zoom_in_button->x = right_x;
        app->zoom_in_button->y = toolbar.y;
        app->zoom_in_button->width = zoom_in_w;
        app->zoom_in_button->height = btn_h;
        right_x -= PREVIEW_BUTTON_GAP;
    }
    if (app->zoom_out_button)
    {
        right_x -= zoom_out_w;
        app->zoom_out_button->x = right_x;
        app->zoom_out_button->y = toolbar.y;
        app->zoom_out_button->width = zoom_out_w;
        app->zoom_out_button->height = btn_h;
        right_x -= PREVIEW_BUTTON_GAP;
    }

    if (app->title_label)
    {
        int label_x = toolbar.x + open_w + PREVIEW_BUTTON_GAP;
        int label_w = right_x - label_x;
        if (label_w < 40)
        {
            label_w = 40;
        }
        app->title_label->x = label_x;
        app->title_label->y = toolbar.y;
        app->title_label->width = label_w;
        app->title_label->height = btn_h;
    }

    if (app->status_label)
    {
        app->status_label->x = status.x;
        app->status_label->y = status.y;
        app->status_label->width = status.width;
        app->status_label->height = status.height;
    }
}

static bool preview_apply_zoom(preview_app_t *app, float factor)
{
    if (!app || !app->image_pixels)
    {
        preview_update_status(app, "No image loaded");
        return false;
    }

    float current = app->current_scale;
    if (current <= 0.0f)
    {
        current = preview_compute_fit_scale(app);
    }
    float next = preview_clamp_scale(current * factor);
    app->scale_mode = PREVIEW_SCALE_ZOOM;
    app->zoom_scale = next;
    return preview_refresh_image(app, true);
}

static void preview_set_actual(preview_app_t *app)
{
    if (!app)
    {
        return;
    }
    app->scale_mode = PREVIEW_SCALE_ACTUAL;
    app->zoom_scale = 1.0f;
    preview_refresh_image(app, true);
}

static void preview_set_fit(preview_app_t *app)
{
    if (!app)
    {
        return;
    }
    app->scale_mode = PREVIEW_SCALE_FIT;
    preview_refresh_image(app, true);
}

static bool preview_load_image(preview_app_t *app, const char *path)
{
    if (!app || !path || !path[0])
    {
        preview_update_status(app, "No file selected");
        return false;
    }

    uint8_t *data = NULL;
    size_t size = 0;
    if (!preview_read_file(path, &data, &size))
    {
        preview_update_status(app, "Failed to read file");
        return false;
    }

    video_color_t *pixels = NULL;
    int width = 0;
    int height = 0;
    int stride = 0;
    const char *reason = NULL;
    bool decoded = preview_decode_image(data, size, &pixels, &width, &height, &stride, &reason);
    free(data);

    if (!decoded || !pixels)
    {
        snprintf(app->status_text,
                 sizeof(app->status_text),
                 "Failed to decode image: %s",
                 reason ? reason : "unknown");
        preview_update_status(app, app->status_text);
        return false;
    }

    char *path_copy = preview_strdup(path);
    if (!path_copy)
    {
        free(pixels);
        preview_update_status(app, "Out of memory");
        return false;
    }

    video_color_t *old_pixels = app->image_pixels;
    char *old_path = app->image_path;
    int old_width = app->image_width;
    int old_height = app->image_height;
    int old_stride = app->image_stride_bytes;

    app->image_pixels = pixels;
    app->image_width = width;
    app->image_height = height;
    app->image_stride_bytes = stride;
    app->image_path = path_copy;
    app->scale_mode = PREVIEW_SCALE_FIT;
    app->zoom_scale = 1.0f;
    app->dragging = false;

    preview_layout(app);
    if (!preview_refresh_image(app, true))
    {
        app->image_pixels = old_pixels;
        app->image_width = old_width;
        app->image_height = old_height;
        app->image_stride_bytes = old_stride;
        free(app->image_path);
        app->image_path = old_path;
        free(pixels);
        preview_update_status(app, "Failed to apply image");
        return false;
    }

    if (old_pixels)
    {
        free(old_pixels);
    }
    if (old_path)
    {
        free(old_path);
    }

    preview_update_title(app);
    preview_update_status(app, NULL);
    return true;
}

static const char *preview_dialog_initial_path(const preview_app_t *app, char *buf, size_t cap)
{
    if (!buf || cap == 0)
    {
        return "/root";
    }
    buf[0] = '\0';

    const char *src = (app && app->image_path) ? app->image_path : NULL;
    if (!src || src[0] == '\0')
    {
        memcpy(buf, "/root", 6);
        return buf;
    }

    size_t len = strlen(src);
    if (len >= cap)
    {
        len = cap - 1;
    }
    memcpy(buf, src, len);
    buf[len] = '\0';

    while (len > 1 && buf[len - 1] == '/')
    {
        buf[--len] = '\0';
    }

    char *last_slash = NULL;
    for (size_t i = 0; i < len; ++i)
    {
        if (buf[i] == '/')
        {
            last_slash = &buf[i];
        }
    }
    if (!last_slash)
    {
        memcpy(buf, "/root", 6);
    }
    else if (buf[len - 1] != '/')
    {
        if (last_slash == buf)
        {
            buf[1] = '\0';
        }
        else
        {
            *last_slash = '\0';
        }
    }

    if (buf[0] == '\0')
    {
        memcpy(buf, "/root", 6);
    }
    return buf;
}

static void preview_on_file_dialog_result(atk_widget_t *requester,
                                          const char *path,
                                          bool confirmed,
                                          void *context)
{
    (void)requester;
    preview_app_t *app = (preview_app_t *)context;
    if (!app)
    {
        return;
    }

    app->file_dialog = NULL;
    if (confirmed && path && path[0])
    {
        preview_load_image(app, path);
    }
    preview_close_file_dialog(app);
}

static void preview_open_file_dialog(preview_app_t *app)
{
    if (!app || !app->window)
    {
        return;
    }

    char initial_path[256];
    const char *initial = preview_dialog_initial_path(app, initial_path, sizeof(initial_path));
    const uint32_t dialog_w = 720;
    const uint32_t dialog_h = 420;

    app->file_dialog = atk_app_open_file_dialog_modal(&app->dialog_modal,
                                                      app->window,
                                                      "Open Image",
                                                      initial,
                                                      preview_on_file_dialog_result,
                                                      app,
                                                      dialog_w,
                                                      dialog_h,
                                                      USER_ATK_WINDOW_FLAG_RESIZABLE);
    if (!app->file_dialog)
    {
        preview_update_status(app, "Open dialog unavailable");
        return;
    }

    preview_update_status(app, "Select an image file");
}

static void preview_close_file_dialog(preview_app_t *app)
{
    if (!app)
    {
        return;
    }
    if (app->file_dialog && app->file_dialog->used)
    {
        atk_state_t *state = atk_state_get();
        if (state)
        {
            atk_window_close(state, app->file_dialog);
        }
    }
    if (app->dialog_modal.active)
    {
        atk_modal_end(&app->dialog_modal);
    }
    app->file_dialog = NULL;
    preview_request_redraw(app);
    atk_render();
    atk_user_present_force(&app->remote);
}

static void preview_on_open_click(atk_widget_t *button, void *context)
{
    (void)button;
    preview_open_file_dialog((preview_app_t *)context);
}

static void preview_on_zoom_out_click(atk_widget_t *button, void *context)
{
    (void)button;
    preview_apply_zoom((preview_app_t *)context, 0.8f);
}

static void preview_on_zoom_in_click(atk_widget_t *button, void *context)
{
    (void)button;
    preview_apply_zoom((preview_app_t *)context, 1.25f);
}

static void preview_on_actual_click(atk_widget_t *button, void *context)
{
    (void)button;
    preview_set_actual((preview_app_t *)context);
}

static void preview_on_fit_click(atk_widget_t *button, void *context)
{
    (void)button;
    preview_set_fit((preview_app_t *)context);
}

static bool preview_on_resize_event(uint32_t width, uint32_t height, void *context)
{
    preview_app_t *app = (preview_app_t *)context;
    if (!app || !app->window)
    {
        return false;
    }
    if (app->dialog_modal.active)
    {
        return true;
    }

    app->window->width = (int)width;
    app->window->height = (int)height;
    preview_layout(app);

    if (app->image_pixels)
    {
        preview_refresh_image(app, app->scale_mode != PREVIEW_SCALE_ZOOM);
    }

    preview_update_title(app);
    atk_window_request_layout(app->window);
    preview_request_redraw(app);
    return true;
}

static bool preview_point_in_view(const preview_app_t *app, int x, int y)
{
    if (!app)
    {
        return false;
    }
    return (x >= app->view_x && x < app->view_x + app->view_w &&
            y >= app->view_y && y < app->view_y + app->view_h);
}

static bool preview_on_mouse_event(const user_atk_event_t *event, void *context)
{
    preview_app_t *app = (preview_app_t *)context;
    if (!app || !event)
    {
        return false;
    }
    if (app->dialog_modal.active)
    {
        return false;
    }

    bool left = (event->flags & USER_ATK_MOUSE_FLAG_LEFT) != 0;
    bool press = (event->flags & USER_ATK_MOUSE_FLAG_PRESS) != 0;
    bool release = (event->flags & USER_ATK_MOUSE_FLAG_RELEASE) != 0;

    if (press && left && preview_point_in_view(app, event->x, event->y))
    {
        bool can_pan = (app->scaled_width > app->view_w) || (app->scaled_height > app->view_h);
        if (can_pan)
        {
            app->dragging = true;
            app->drag_start_x = event->x;
            app->drag_start_y = event->y;
            app->drag_origin_x = app->pan_x;
            app->drag_origin_y = app->pan_y;
        }
    }

    if (release)
    {
        app->dragging = false;
    }

    if (app->dragging && left)
    {
        int dx = event->x - app->drag_start_x;
        int dy = event->y - app->drag_start_y;
        app->pan_x = app->drag_origin_x + dx;
        app->pan_y = app->drag_origin_y + dy;
        preview_clamp_pan(app);
        preview_apply_pan(app, true);
        return true;
    }

    return false;
}

static bool preview_on_key_event(const user_atk_event_t *event, void *context)
{
    preview_app_t *app = (preview_app_t *)context;
    if (!app || !event)
    {
        return false;
    }
    if (app->dialog_modal.active)
    {
        return false;
    }
    if (event->flags & USER_ATK_KEY_FLAG_RELEASE)
    {
        return false;
    }

    char key = (char)event->data0;
    switch (key)
    {
        case 'o':
        case 'O':
            preview_open_file_dialog(app);
            return true;
        case '+':
        case '=':
            return preview_apply_zoom(app, 1.25f);
        case '-':
            return preview_apply_zoom(app, 0.8f);
        case '0':
            preview_set_actual(app);
            return true;
        case 'f':
        case 'F':
            preview_set_fit(app);
            return true;
        default:
            break;
    }

    return false;
}

static void preview_on_close_event(void *context)
{
    preview_app_t *app = (preview_app_t *)context;
    if (app && app->dialog_modal.active)
    {
        preview_close_file_dialog(app);
        return;
    }
    atk_main_request_exit();
}

static bool preview_build_ui(preview_app_t *app)
{
    if (!app)
    {
        return false;
    }

    atk_init();
    atk_state_t *state = atk_state_get();
    if (!state)
    {
        return false;
    }
    atk_menu_bar_set_enabled(state, false);
    preview_apply_theme(state);

    app->window = atk_window_create_at(state, PREVIEW_WINDOW_WIDTH / 2, PREVIEW_WINDOW_HEIGHT / 2);
    if (!app->window)
    {
        return false;
    }

    atk_window_set_title_text(app->window, "Preview");
    atk_window_set_chrome_visible(app->window, false);
    app->window->x = 0;
    app->window->y = 0;
    app->window->width = PREVIEW_WINDOW_WIDTH;
    app->window->height = PREVIEW_WINDOW_HEIGHT;

    app->image = atk_window_add_image(app->window, 0, 0);
    if (!app->image)
    {
        return false;
    }
    atk_widget_set_ops(app->image, &g_preview_image_ops, app);

    app->title_label = atk_window_add_label(app->window, 0, 0, 100, 20);
    if (!app->title_label)
    {
        return false;
    }

    app->status_label = atk_window_add_label(app->window, 0, 0, 100, 20);
    if (!app->status_label)
    {
        return false;
    }

    app->open_button = atk_window_add_button(app->window,
                                              "Open",
                                              0,
                                              0,
                                              60,
                                              PREVIEW_TOOLBAR_HEIGHT,
                                              ATK_BUTTON_STYLE_TITLE_INSIDE,
                                              false,
                                              preview_on_open_click,
                                              app);
    if (!app->open_button)
    {
        return false;
    }

    app->zoom_out_button = atk_window_add_button(app->window,
                                                 "Zoom-",
                                                 0,
                                                 0,
                                                 60,
                                                 PREVIEW_TOOLBAR_HEIGHT,
                                                 ATK_BUTTON_STYLE_TITLE_INSIDE,
                                                 false,
                                                 preview_on_zoom_out_click,
                                                 app);
    if (!app->zoom_out_button)
    {
        return false;
    }

    app->zoom_in_button = atk_window_add_button(app->window,
                                                "Zoom+",
                                                0,
                                                0,
                                                60,
                                                PREVIEW_TOOLBAR_HEIGHT,
                                                ATK_BUTTON_STYLE_TITLE_INSIDE,
                                                false,
                                                preview_on_zoom_in_click,
                                                app);
    if (!app->zoom_in_button)
    {
        return false;
    }

    app->actual_button = atk_window_add_button(app->window,
                                               "1:1",
                                               0,
                                               0,
                                               60,
                                               PREVIEW_TOOLBAR_HEIGHT,
                                               ATK_BUTTON_STYLE_TITLE_INSIDE,
                                               false,
                                               preview_on_actual_click,
                                               app);
    if (!app->actual_button)
    {
        return false;
    }

    app->fit_button = atk_window_add_button(app->window,
                                            "Fit",
                                            0,
                                            0,
                                            60,
                                            PREVIEW_TOOLBAR_HEIGHT,
                                            ATK_BUTTON_STYLE_TITLE_INSIDE,
                                            false,
                                            preview_on_fit_click,
                                            app);
    if (!app->fit_button)
    {
        return false;
    }

    preview_layout(app);
    preview_update_title(app);
    preview_update_status(app, NULL);
    return true;
}

int main(int argc, char **argv)
{
    preview_app_t app = { 0 };

    if (!atk_user_window_open_with_flags(&app.remote,
                                         "Preview",
                                         PREVIEW_WINDOW_WIDTH,
                                         PREVIEW_WINDOW_HEIGHT,
                                         USER_ATK_WINDOW_FLAG_RESIZABLE))
    {
        printf("preview: failed to open window\n");
        return 1;
    }

    atk_user_enable_dirty_tracking(&app.remote, true);

    if (!preview_build_ui(&app))
    {
        printf("preview: failed to init UI\n");
        atk_user_close(&app.remote);
        return 1;
    }

    if (argc > 1 && argv[1] && argv[1][0])
    {
        preview_load_image(&app, argv[1]);
    }

    atk_render();
    atk_user_present_force(&app.remote);

    atk_main_register_resize_handler(preview_on_resize_event, &app);
    atk_main_register_mouse_handler(preview_on_mouse_event, &app);
    atk_main_register_key_handler(preview_on_key_event, &app);
    atk_main_register_close_handler(preview_on_close_event, &app);

    atk_main_config_t main_cfg = {
        .window = &app.remote,
        .tick = NULL,
        .tick_context = NULL,
        .present_on_idle = false,
        .legacy_input = false
    };

    atk_main(&main_cfg);

    if (app.image_pixels)
    {
        free(app.image_pixels);
        app.image_pixels = NULL;
    }
    if (app.image_path)
    {
        free(app.image_path);
        app.image_path = NULL;
    }
    atk_user_close(&app.remote);
    return 0;
}
