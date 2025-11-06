#include "atk/atk_shell.h"

#include "atk_internal.h"
#include <stddef.h>

#include "atk_window.h"
#include "atk/atk_label.h"
#include "atk/atk_text_input.h"
#include "shell.h"
#include "vfs.h"
#include "libc.h"
#include "fd.h"
#include "process.h"
#include "video.h"

typedef struct
{
    atk_state_t *state;
    atk_widget_t *window;
    atk_widget_t *label;
    atk_widget_t *input;
    shell_state_t shell;
    int stdout_fd;
} atk_shell_view_t;

static void atk_shell_view_destroy(void *context);
static void atk_shell_on_submit(atk_widget_t *input, void *context);
static void atk_shell_append_prompt(atk_shell_view_t *view);
static void atk_shell_stream_write(void *context, const char *data, size_t len);
static ssize_t atk_shell_fd_write(void *ctx, const void *buffer, size_t count);
static int atk_shell_fd_close(void *ctx);

static const fd_ops_t g_atk_shell_fd_ops = {
    .read = NULL,
    .write = atk_shell_fd_write,
    .close = atk_shell_fd_close,
};

bool atk_shell_open(atk_state_t *state)
{
    if (!state)
    {
        return false;
    }

    atk_widget_t *window = atk_window_create_at(state, 360, 240);
    if (!window)
    {
        return false;
    }

    window->x = 80;
    window->y = 80;
    atk_window_ensure_inside(window);

    atk_shell_view_t *view = (atk_shell_view_t *)malloc(sizeof(atk_shell_view_t));
    if (!view)
    {
        atk_window_close(state, window);
        return false;
    }

    view->state = state;
    view->window = window;
    view->label = NULL;
    view->input = NULL;
    view->shell.cwd = vfs_root();
    view->shell.stdout_fd = process_current_stdout_fd();
    view->shell.stream_fn = atk_shell_stream_write;
    view->shell.stream_context = view;
    view->stdout_fd = -1;

    int label_x = 16;
    int label_y = ATK_WINDOW_TITLE_HEIGHT + 10;
    int input_margin = 16;

    atk_widget_t *input = atk_window_add_text_input(window,
                                                    label_x,
                                                    window->height - input_margin - (ATK_FONT_HEIGHT + 8),
                                                    window->width - label_x * 2);
    if (!input)
    {
        free(view);
        atk_window_close(state, window);
        return false;
    }

    int input_height = input->height;
    atk_widget_t *label = atk_window_add_label(window,
                                               label_x,
                                               label_y,
                                               window->width - label_x * 2,
                                               window->height - label_y - input_height - input_margin - 8);
    if (!label)
    {
        free(view);
        atk_window_close(state, window);
        return false;
    }

    view->label = label;
    view->input = input;

    atk_window_set_context(window, view, atk_shell_view_destroy);

    atk_text_input_set_submit_handler(input, atk_shell_on_submit, view);
    atk_text_input_clear(input);
    atk_shell_append_prompt(view);
    atk_label_scroll_to_bottom(label);
    atk_text_input_focus(state, input);

    int fd = fd_allocate(&g_atk_shell_fd_ops, view);
    if (fd >= 0)
    {
        view->stdout_fd = fd;
        view->shell.stdout_fd = fd;
    }

    atk_window_mark_dirty(window);
    return true;
}

static void atk_shell_view_destroy(void *context)
{
    atk_shell_view_t *view = (atk_shell_view_t *)context;
    if (!view)
    {
        return;
    }
    if (view->stdout_fd >= 0)
    {
        fd_close(view->stdout_fd);
        view->stdout_fd = -1;
    }
    view->shell.stream_fn = NULL;
    view->shell.stream_context = NULL;
    free(view);
}

static void atk_shell_append_prompt(atk_shell_view_t *view)
{
    if (!view || !view->label)
    {
        return;
    }
    atk_label_append_text(view->label, "alex@alix$ ");
}

static void atk_shell_on_submit(atk_widget_t *input_widget, void *context)
{
    atk_shell_view_t *view = (atk_shell_view_t *)context;
    if (!view || !input_widget)
    {
        return;
    }

    const char *command = atk_text_input_text(input_widget);
    if (!command)
    {
        command = "";
    }

    atk_label_append_text(view->label, command);
    atk_label_append_text(view->label, "\n");

    bool success = false;
    char *output = shell_execute_line(&view->shell, command, &success);
    if (output && *output)
    {
        atk_label_append_text(view->label, output);
        if (output[strlen(output) - 1] != '\n')
        {
            atk_label_append_text(view->label, "\n");
        }
    }
    if (output)
    {
        free(output);
    }

    atk_text_input_clear(input_widget);
    atk_shell_append_prompt(view);
    atk_label_scroll_to_bottom(view->label);
    atk_text_input_focus(view->state, input_widget);
    atk_window_mark_dirty(view->window);
    (void)success;
}

static void atk_shell_stream_write(void *context, const char *data, size_t len)
{
    atk_shell_view_t *view = (atk_shell_view_t *)context;
    if (!view || !view->label || !data || len == 0)
    {
        return;
    }

    for (size_t i = 0; i < len; ++i)
    {
        char buf[2] = { data[i], 0 };
        atk_label_append_text(view->label, buf);
    }
    atk_label_scroll_to_bottom(view->label);
    atk_window_mark_dirty(view->window);
    video_request_refresh();
}

static ssize_t atk_shell_fd_write(void *ctx, const void *buffer, size_t count)
{
    atk_shell_view_t *view = (atk_shell_view_t *)ctx;
    if (!view || !buffer || count == 0)
    {
        return (ssize_t)count;
    }
    atk_shell_stream_write(view, (const char *)buffer, count);
    return (ssize_t)count;
}

static int atk_shell_fd_close(void *ctx)
{
    (void)ctx;
    return 0;
}
