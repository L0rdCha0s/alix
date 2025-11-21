#include "shell_commands.h"

#include "vfs.h"
#include "libc.h"
#include "video.h"
#include "atk/atk_image.h"
#include "atk/util/jpeg.h"
#include "atk/util/png.h"
#include "../atk/atk_window.h"
#include "../atk/atk_internal.h"

static const char *skip_ws(const char *s)
{
    while (s && (*s == ' ' || *s == '\t'))
    {
        ++s;
    }
    return s;
}

bool shell_cmd_imgview(shell_state_t *shell, shell_output_t *out, const char *args)
{
    const char *path = skip_ws(args);
    if (!path || *path == '\0')
    {
        return shell_output_error(out, "imgview needs a path");
    }

    if (!video_is_active())
    {
        return shell_output_error(out, "video mode not active (run start_video)");
    }

    vfs_node_t *node = vfs_resolve(shell->cwd, path);
    if (!node)
    {
        return shell_output_error(out, "file not found");
    }
    if (vfs_is_dir(node))
    {
        return shell_output_error(out, "path is a directory");
    }
    if (vfs_is_block(node))
    {
        return shell_output_error(out, "path is a block device");
    }

    size_t file_size = 0;
    const char *file_data = vfs_data(node, &file_size);
    if (!file_data || file_size == 0)
    {
        return shell_output_error(out, "file is empty");
    }

    atk_state_t *state = atk_state_get();
    if (!state)
    {
        return shell_output_error(out, "atk state unavailable");
    }

    atk_widget_t *window = atk_window_create_at(state, VIDEO_WIDTH / 2, VIDEO_HEIGHT / 2);
    if (!window)
    {
        return shell_output_error(out, "failed to create window");
    }

    int padding = 16;
    atk_widget_t *image_widget = atk_window_add_image(window, padding, ATK_WINDOW_TITLE_HEIGHT + padding);
    if (!image_widget)
    {
        atk_window_close(state, window);
        return shell_output_error(out, "failed to create image widget");
    }

    bool loaded = false;
    const uint8_t *bytes = (const uint8_t *)file_data;
    const char *reason = "unknown format";

    if (file_size >= 8 && bytes[0] == 0x89 && bytes[1] == 'P' && bytes[2] == 'N' && bytes[3] == 'G')
    {
        loaded = atk_image_load_png(image_widget, bytes, file_size);
        reason = png_last_error();
    }
    else if (file_size >= 3 && bytes[0] == 0xFF && bytes[1] == 0xD8)
    {
        loaded = atk_image_load_jpeg(image_widget, bytes, file_size);
        reason = jpeg_last_error();
    }
    else
    {
        loaded = atk_image_load_png(image_widget, bytes, file_size);
        reason = png_last_error();
        if (!loaded)
        {
            loaded = atk_image_load_jpeg(image_widget, bytes, file_size);
            reason = jpeg_last_error();
        }
    }

    if (!loaded)
    {
        atk_window_close(state, window);
        if (!reason)
        {
            reason = "unknown";
        }
        shell_output_write(out, "Error: failed to decode image: ");
        shell_output_write(out, reason);
        shell_output_write(out, "\n");
        return false;
    }

    int img_w = atk_image_width(image_widget);
    int img_h = atk_image_height(image_widget);
    if (img_w <= 0 || img_h <= 0)
    {
        atk_window_close(state, window);
        return shell_output_error(out, "image produced empty result");
    }

    int desired_width = img_w + padding * 2;
    int desired_height = ATK_WINDOW_TITLE_HEIGHT + padding + img_h + padding;

    if (window->width < desired_width)
    {
        window->width = desired_width;
    }
    if (window->height < desired_height)
    {
        window->height = desired_height;
    }

    atk_window_ensure_inside(window);
    atk_window_mark_dirty(window);

    if (!shell_output_write(out, "Image viewer window opened\n"))
    {
        return shell_output_error(out, "output failed");
    }

    return true;
}
