#include "atk/atk_shell.h"

#include "atk_internal.h"
#include <stddef.h>

#include "atk_window.h"
#include "atk/atk_terminal.h"
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
    atk_widget_t *terminal;
    shell_state_t shell;
    int stdout_fd;
    process_t *shell_process;
    bool shell_process_should_exit;
} atk_shell_view_t;

static void atk_shell_view_destroy(void *context);
static void atk_shell_on_submit(atk_widget_t *terminal, void *context, const char *line);
static bool atk_shell_on_control(atk_widget_t *terminal, void *context, char control);
static void atk_shell_append_prompt(atk_shell_view_t *view);
static void atk_shell_stream_write(void *context, const char *data, size_t len);
static ssize_t atk_shell_fd_write(void *ctx, const void *buffer, size_t count);
static int atk_shell_fd_close(void *ctx);
static void atk_shell_wait_hook(void *context);
static void atk_shell_process_entry(void *arg);
static void atk_shell_update_title(atk_shell_view_t *view);
static void atk_shell_on_cwd_changed(void *context, vfs_node_t *cwd);

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
    view->terminal = NULL;
    view->shell.cwd = process_current_cwd();
    view->shell.stdout_fd = process_current_stdout_fd();
    view->shell.stream_fn = atk_shell_stream_write;
    view->shell.stream_context = view;
    view->shell.foreground_process = NULL;
    view->shell.wait_hook = atk_shell_wait_hook;
    view->shell.wait_context = view;
    view->shell.owner_process = NULL;
    view->stdout_fd = -1;
    view->shell_process = NULL;
    view->shell_process_should_exit = false;

    int margin_x = 8; /* tighter horizontal margin to balance scrollbar width */
    int margin_y = 12;
    int top = ATK_WINDOW_TITLE_HEIGHT + 8;
    atk_widget_t *terminal = atk_window_add_terminal(window,
                                                     margin_x,
                                                     top,
                                                     window->width - margin_x * 2,
                                                     window->height - top - margin_y);
    if (!terminal)
    {
        free(view);
        atk_window_close(state, window);
        return false;
    }

    view->terminal = terminal;

    atk_window_set_context(window, view, atk_shell_view_destroy);

    int fd = fd_allocate(&g_atk_shell_fd_ops, view);
    if (fd >= 0)
    {
        view->stdout_fd = fd;
        view->shell.stdout_fd = fd;
    }

    process_t *shell_proc = process_create_kernel_with_parent("atk_shell",
                                                             atk_shell_process_entry,
                                                             view,
                                                             0,
                                                             view->shell.stdout_fd,
                                                             process_current());
    if (!shell_proc)
    {
        if (view->stdout_fd >= 0)
        {
            fd_close(view->stdout_fd);
            view->stdout_fd = -1;
        }
        atk_terminal_destroy(terminal);
        atk_widget_destroy(terminal);
        free(view);
        atk_window_close(state, window);
        return false;
    }
    view->shell_process = shell_proc;
    view->shell.owner_process = shell_proc;
    view->shell.cwd_changed_fn = atk_shell_on_cwd_changed;
    view->shell.cwd_changed_context = view;

    atk_terminal_reset(terminal);
    atk_terminal_set_submit_handler(terminal, atk_shell_on_submit, view);
    atk_terminal_set_control_handler(terminal, atk_shell_on_control, view);
    atk_terminal_focus(state, terminal);
    atk_shell_update_title(view);
    atk_shell_append_prompt(view);

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
    if (view->state && view->terminal && atk_terminal_is_focused(view->state, view->terminal))
    {
        atk_terminal_focus(view->state, NULL);
    }
    if (view->shell_process)
    {
        view->shell_process_should_exit = true;
        process_kill_tree(view->shell_process);
        process_destroy(view->shell_process);
        view->shell_process = NULL;
        view->shell.foreground_process = NULL;
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
    if (!view || !view->terminal)
    {
        return;
    }
    static const char prompt[] = "alex@alix$ ";
    atk_terminal_write(view->terminal, prompt, sizeof(prompt) - 1);
}

static void atk_shell_build_path(vfs_node_t *cwd, char *buffer, size_t capacity)
{
    if (!buffer || capacity == 0)
    {
        return;
    }
    size_t written = vfs_build_path(cwd, buffer, capacity);
    if (written == 0)
    {
        buffer[0] = '/';
        if (capacity > 1)
        {
            buffer[1] = '\0';
        }
    }
}

static void atk_shell_update_title(atk_shell_view_t *view)
{
    if (!view || !view->window)
    {
        return;
    }
    char title[256];
    atk_shell_build_path(view->shell.cwd, title, sizeof(title));
    atk_window_set_title_text(view->window, title);
    atk_window_mark_dirty(view->window);
}

static void atk_shell_on_cwd_changed(void *context, vfs_node_t *cwd)
{
    atk_shell_view_t *view = (atk_shell_view_t *)context;
    if (!view)
    {
        return;
    }
    view->shell.cwd = cwd ? cwd : vfs_root();
    atk_shell_update_title(view);
}

static bool atk_shell_on_control(atk_widget_t *terminal_widget, void *context, char control)
{
    atk_shell_view_t *view = (atk_shell_view_t *)context;
    if (!view || !terminal_widget || control != 0x03)
    {
        return false;
    }

    bool had_process = (view->shell.foreground_process != NULL);
    shell_request_interrupt(&view->shell);
    atk_terminal_clear_input(terminal_widget);

    static const char ctrlc_text[] = "^C\r\n";
    atk_terminal_write(terminal_widget, ctrlc_text, sizeof(ctrlc_text) - 1);

    if (!had_process)
    {
        atk_shell_append_prompt(view);
    }

    atk_window_mark_dirty(view->window);
    return true;
}

static void atk_shell_on_submit(atk_widget_t *terminal_widget, void *context, const char *line)
{
    atk_shell_view_t *view = (atk_shell_view_t *)context;
    if (!view || !terminal_widget)
    {
        return;
    }

    if (view->shell.foreground_process)
    {
        /* Input while a process is running should be consumed by that
         * process. We do not yet have a stdin path, so just leave the
         * text in the transcript without invoking the shell again. */
        atk_window_mark_dirty(view->window);
        (void)line;
        return;
    }

    const char *command = line ? line : "";

    bool success = false;
    char *output = shell_execute_line(&view->shell, command, &success);
    if (output && *output)
    {
        size_t len = strlen(output);
        atk_terminal_write(view->terminal, output, len);
        if (len == 0 || output[len - 1] != '\n')
        {
            const char newline[] = "\r\n";
            atk_terminal_write(view->terminal, newline, sizeof(newline) - 1);
        }
    }
    if (output)
    {
        free(output);
    }

    atk_shell_append_prompt(view);
    atk_window_mark_dirty(view->window);
    (void)success;
}

static void atk_shell_stream_write(void *context, const char *data, size_t len)
{
    atk_shell_view_t *view = (atk_shell_view_t *)context;
    if (!view || !view->terminal || !data || len == 0)
    {
        return;
    }

    atk_terminal_write(view->terminal, data, len);
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

static void atk_shell_wait_hook(void *context)
{
    (void)context;
    video_pump_events();
}

static void atk_shell_process_entry(void *arg)
{
    atk_shell_view_t *view = (atk_shell_view_t *)arg;
    while (view && !view->shell_process_should_exit)
    {
        process_yield();
    }
    process_exit(0);
}
