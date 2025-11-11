#include "atk_user.h"

#include "atk.h"
#include "atk_internal.h"
#include "atk_menu_bar.h"
#include "atk_window.h"
#include "atk/atk_terminal.h"
#include "libc.h"
#include "video.h"
#include "usyscall.h"

#define SHELL_WINDOW_WIDTH   VIDEO_WIDTH
#define SHELL_WINDOW_HEIGHT  VIDEO_HEIGHT
#define SHELL_PROMPT         "alex@alix$ "
#define SHELL_OUTPUT_BUFFER  4096

typedef struct
{
    atk_user_window_t remote;
    atk_widget_t *window;
    atk_widget_t *terminal;
    bool running;
    int shell_handle;
} atk_shell_app_t;

static void shell_apply_theme(atk_state_t *state);
static void shell_log_key(char ch);
static bool shell_state_has_dirty(void);
static bool shell_dispatch_event(atk_shell_app_t *app, const user_atk_event_t *event);

static void shell_apply_theme(atk_state_t *state)
{
    state->theme.background = video_make_color(0x12, 0x18, 0x20);
    state->theme.window_border = video_make_color(0x30, 0x30, 0x30);
    state->theme.window_title = video_make_color(0x45, 0x65, 0xA0);
    state->theme.window_title_text = video_make_color(0xFF, 0xFF, 0xFF);
    state->theme.window_body = video_make_color(0x08, 0x0C, 0x10);
    state->theme.button_face = video_make_color(0x20, 0x38, 0x58);
    state->theme.button_border = video_make_color(0x10, 0x10, 0x10);
    state->theme.button_text = video_make_color(0xEE, 0xEE, 0xEE);
    state->theme.desktop_icon_face = video_make_color(0x40, 0x60, 0x90);
    state->theme.desktop_icon_text = state->theme.window_title_text;
}

static void shell_render(atk_shell_app_t *app)
{
    if (!app)
    {
        return;
    }
    atk_render();
    atk_user_present(&app->remote);
}

static void shell_append(atk_shell_app_t *app, const char *text)
{
    if (!app || !app->terminal || !text)
    {
        return;
    }
    atk_terminal_write(app->terminal, text, strlen(text));
}

static void shell_append_prompt(atk_shell_app_t *app)
{
    shell_append(app, SHELL_PROMPT);
}

static void shell_handle_output(atk_shell_app_t *app, const char *buffer, size_t len)
{
    if (!app || !buffer || len == 0)
    {
        return;
    }
    atk_terminal_write(app->terminal, buffer, len);
}

static void shell_log_key(char ch)
{
    char msg[32];
    size_t pos = 0;
    const char prefix[] = "[atk_shell] key=";
    const size_t prefix_len = sizeof(prefix) - 1;
    memcpy(msg + pos, prefix, prefix_len);
    pos += prefix_len;
    static const char hex[] = "0123456789ABCDEF";
    unsigned char u = (unsigned char)ch;
    msg[pos++] = '0';
    msg[pos++] = 'x';
    msg[pos++] = hex[(u >> 4) & 0xF];
    msg[pos++] = hex[u & 0xF];
    msg[pos++] = ' ';
    msg[pos++] = '(';
    msg[pos++] = (u >= 32 && u <= 126) ? (char)u : '.';
    msg[pos++] = ')';
    msg[pos++] = '\n';
    sys_serial_write(msg, pos);
}

static void shell_on_submit(atk_widget_t *terminal, void *context, const char *line)
{
    (void)terminal;
    atk_shell_app_t *app = (atk_shell_app_t *)context;
    if (!app || app->shell_handle < 0)
    {
        return;
    }

    const char *command = (line && *line) ? line : "";
    shell_append(app, command);
    shell_append(app, "\n");

    char buffer[SHELL_OUTPUT_BUFFER];
    int status = 0;
    ssize_t written = sys_shell_exec(app->shell_handle,
                                     command,
                                     0,
                                     buffer,
                                     sizeof(buffer),
                                     &status);
    if (written > 0)
    {
        size_t copy_len = (size_t)written;
        if (copy_len >= sizeof(buffer))
        {
            copy_len = sizeof(buffer) - 1;
        }
        buffer[copy_len] = '\0';
        shell_handle_output(app, buffer, copy_len);
        if (copy_len == 0 || buffer[copy_len - 1] != '\n')
        {
            shell_append(app, "\n");
        }
    }
    else if (written < 0)
    {
        shell_append(app, "Error: shell exec failed\n");
    }

    (void)status;
    shell_append_prompt(app);
    shell_render(app);
}

static bool shell_on_control(atk_widget_t *terminal, void *context, char control)
{
    (void)terminal;
    (void)context;
    (void)control;
    return false;
}

static bool shell_handle_mouse(atk_shell_app_t *app, const user_atk_event_t *event)
{
    if (!event)
    {
        return false;
    }
    bool left = (event->flags & USER_ATK_MOUSE_FLAG_LEFT) != 0;
    bool press = (event->flags & USER_ATK_MOUSE_FLAG_PRESS) != 0;
    bool release = (event->flags & USER_ATK_MOUSE_FLAG_RELEASE) != 0;
    atk_mouse_event_result_t result = atk_handle_mouse_event(event->x,
                                                             event->y,
                                                             press,
                                                             release,
                                                             left);
    return result.redraw;
}

static bool shell_handle_key(atk_shell_app_t *app, const user_atk_event_t *event)
{
    if (!app || !event)
    {
        return false;
    }

    if (app && app->terminal)
    {
        atk_state_t *state = atk_state_get();
        if (state && atk_state_focus_widget(state) != app->terminal)
        {
            atk_terminal_focus(state, app->terminal);
        }
    }

    char ch = (char)event->data0;
    shell_log_key(ch);

    atk_key_event_result_t result = atk_handle_key_char(ch);
    return result.redraw;
}

static bool shell_init_ui(atk_shell_app_t *app)
{
    atk_init();
    atk_state_t *state = atk_state_get();
    atk_menu_bar_set_enabled(state, false);
    shell_apply_theme(state);

    atk_widget_t *window = atk_window_create_at(state, SHELL_WINDOW_WIDTH, SHELL_WINDOW_HEIGHT);
    if (!window)
    {
        return false;
    }

    atk_window_set_title_text(window, "ATK Shell");
    atk_window_set_chrome_visible(window, false);
    window->x = 0;
    window->y = 0;
    window->width = SHELL_WINDOW_WIDTH;
    window->height = SHELL_WINDOW_HEIGHT;

    int margin = 8;
    int top = margin;
    atk_widget_t *terminal = atk_window_add_terminal(window,
                                                     margin,
                                                     top,
                                                     window->width - margin * 2,
                                                     window->height - top - margin);
    if (!terminal)
    {
        return false;
    }

    atk_terminal_reset(terminal);
    atk_terminal_set_submit_handler(terminal, shell_on_submit, app);
    atk_terminal_set_control_handler(terminal, shell_on_control, app);
    atk_terminal_focus(state, terminal);

    app->window = window;
    app->terminal = terminal;
    shell_append_prompt(app);
    atk_window_mark_dirty(window);
    return true;
}

static bool shell_dispatch_event(atk_shell_app_t *app, const user_atk_event_t *event)
{
    if (!app || !event)
    {
        return false;
    }

    switch (event->type)
    {
        case USER_ATK_EVENT_MOUSE:
            return shell_handle_mouse(app, event);
        case USER_ATK_EVENT_KEY:
            return shell_handle_key(app, event);
        case USER_ATK_EVENT_CLOSE:
            app->running = false;
            return false;
        default:
            break;
    }
    return false;
}

static bool shell_state_has_dirty(void)
{
    atk_state_t *state = atk_state_get();
    if (!state)
    {
        return false;
    }
    return state->dirty_full || state->dirty_active;
}

int main(void)
{
    atk_shell_app_t app;
    memset(&app, 0, sizeof(app));
    app.shell_handle = -1;
    app.running = true;

    if (!atk_user_window_open(&app.remote, "ATK Shell", SHELL_WINDOW_WIDTH, SHELL_WINDOW_HEIGHT))
    {
        printf("atk_shell: failed to open remote window\n");
        return 1;
    }

    if (!shell_init_ui(&app))
    {
        printf("atk_shell: failed to init UI\n");
        atk_user_close(&app.remote);
        return 1;
    }

    app.shell_handle = sys_shell_open();
    if (app.shell_handle < 0)
    {
        printf("atk_shell: failed to open shell session\n");
        atk_user_close(&app.remote);
        return 1;
    }

    shell_render(&app);

    while (app.running)
    {
        bool redraw = false;
        user_atk_event_t event;

        if (!atk_user_wait_event(&app.remote, &event))
        {
            sys_yield();
            continue;
        }

        redraw |= shell_dispatch_event(&app, &event);

        while (atk_user_poll_event(&app.remote, &event))
        {
            redraw |= shell_dispatch_event(&app, &event);
        }

        if (redraw || shell_state_has_dirty())
        {
            shell_render(&app);
        }
    }

    if (app.shell_handle >= 0)
    {
        sys_shell_close(app.shell_handle);
    }
    atk_user_close(&app.remote);
    return 0;
}
