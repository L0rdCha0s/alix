#include "atk_user.h"

#include "atk.h"
#include "atk_app.h"
#include "atk_internal.h"
#include "atk_menu_bar.h"
#include "atk_window.h"
#include "atk/atk_terminal.h"
#include "libc.h"
#include "stdio.h"
#include "video.h"
#include "usyscall.h"
#include "user_atk_defs.h"

#define SHELL_WINDOW_WIDTH   640
#define SHELL_WINDOW_HEIGHT  480
#define SHELL_PROMPT         "alex@alix$ "
#define SHELL_OUTPUT_BUFFER  4096
#define SHELL_INPUT_CAPACITY 256
#define SHELL_TICK_MS        50u

typedef struct
{
    char **items;
    size_t count;
    size_t capacity;
} shell_completion_list_t;

typedef struct
{
    atk_user_window_t remote;
    atk_widget_t *window;
    atk_widget_t *terminal;
    bool running;
    int shell_handle;
    bool command_active;
    bool last_output_newline;
} atk_shell_app_t;

static const char *g_shell_commands[] = {
    "echo", "cat", "mkdir", "cd", "pwd", "rm", "mkfs", "mount", "tzset", "tzstatus",
    "tzsync", "ntpdate", "shutdown", "ls", "ip", "ping", "nslookup", "wget", "imgview",
    "logcat", "sha1sum", "dhclient", "start_video", "net_mac", "dnsdebug", "alloc1m",
    "free", "loop1", "loop2", "letters", "top", "useratk", "atkshell", "taskmgr",
    "bgset", "doom", "wolf3d", "runelf"
};
static const size_t g_shell_command_count = sizeof(g_shell_commands) / sizeof(g_shell_commands[0]);

static void shell_apply_theme(atk_state_t *state);
static bool shell_handle_resize(atk_shell_app_t *app, uint32_t width, uint32_t height);
static bool shell_poll_output(atk_shell_app_t *app);
static void shell_handle_output(atk_shell_app_t *app, const char *buffer, size_t len);
static void shell_append_prompt(atk_shell_app_t *app);
static void shell_completion_reset(shell_completion_list_t *list);
static bool shell_completion_add(shell_completion_list_t *list, const char *text);
static size_t shell_completion_common_prefix(const shell_completion_list_t *list);
static bool shell_command_matches(const char *name, const char *token, size_t token_len);
static void shell_collect_command_completions(const char *token,
                                              size_t token_len,
                                              shell_completion_list_t *list);
static void shell_collect_path_completions(atk_shell_app_t *app,
                                           const char *cwd,
                                           const char *token,
                                           size_t token_len,
                                           shell_completion_list_t *list);
static void shell_render_completion_options(atk_shell_app_t *app,
                                            const shell_completion_list_t *list,
                                            const char *buffer,
                                            size_t cursor);
static bool shell_handle_tab_completion(atk_shell_app_t *app);

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

static void shell_completion_reset(shell_completion_list_t *list)
{
    if (!list)
    {
        return;
    }
    if (list->items)
    {
        for (size_t i = 0; i < list->count; ++i)
        {
            if (list->items[i])
            {
                free(list->items[i]);
            }
        }
        free(list->items);
    }
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static bool shell_completion_add(shell_completion_list_t *list, const char *text)
{
    if (!list || !text)
    {
        return false;
    }
    size_t len = strlen(text);
    char *copy = (char *)malloc(len + 1);
    if (!copy)
    {
        return false;
    }
    memcpy(copy, text, len + 1);

    if (list->count >= list->capacity)
    {
        size_t new_capacity = list->capacity ? list->capacity * 2 : 8;
        char **items = (char **)realloc(list->items, new_capacity * sizeof(char *));
        if (!items)
        {
            free(copy);
            return false;
        }
        list->items = items;
        list->capacity = new_capacity;
    }

    list->items[list->count++] = copy;
    return true;
}

static size_t shell_completion_common_prefix(const shell_completion_list_t *list)
{
    if (!list || list->count == 0)
    {
        return 0;
    }
    size_t prefix = strlen(list->items[0]);
    for (size_t i = 1; i < list->count; ++i)
    {
        const char *item = list->items[i];
        size_t len = strlen(item);
        size_t max = prefix < len ? prefix : len;
        size_t j = 0;
        for (; j < max; ++j)
        {
            if (list->items[0][j] != item[j])
            {
                break;
            }
        }
        prefix = j;
        if (prefix == 0)
        {
            break;
        }
    }
    return prefix;
}

static bool shell_command_matches(const char *name, const char *token, size_t token_len)
{
    if (!name)
    {
        return false;
    }
    size_t name_len = strlen(name);
    if (token_len > name_len)
    {
        return false;
    }
    for (size_t i = 0; i < token_len; ++i)
    {
        char c = token[i];
        if (c >= 'A' && c <= 'Z')
        {
            c = (char)(c + ('a' - 'A'));
        }
        if (name[i] != c)
        {
            return false;
        }
    }
    return true;
}

static void shell_collect_command_completions(const char *token,
                                              size_t token_len,
                                              shell_completion_list_t *list)
{
    if (!list)
    {
        return;
    }
    for (size_t i = 0; i < g_shell_command_count; ++i)
    {
        const char *name = g_shell_commands[i];
        if (shell_command_matches(name, token, token_len))
        {
            shell_completion_add(list, name);
        }
    }
}

static void shell_collect_path_completions(atk_shell_app_t *app,
                                           const char *cwd,
                                           const char *token,
                                           size_t token_len,
                                           shell_completion_list_t *list)
{
    if (!app || !cwd || !list)
    {
        return;
    }

    char dir_part[SHELL_INPUT_CAPACITY];
    size_t dir_len = 0;
    size_t base_len = token_len;
    const char *base = token;
    for (size_t i = 0; i < token_len; ++i)
    {
        if (token[i] == '/')
        {
            dir_len = i + 1;
        }
    }

    if (dir_len >= sizeof(dir_part))
    {
        return;
    }

    if (dir_len > 0)
    {
        memcpy(dir_part, token, dir_len);
    }
    dir_part[dir_len] = '\0';
    base = token + dir_len;
    base_len = token_len >= dir_len ? token_len - dir_len : 0;

    char dir_path[512];
    if (dir_len == 0)
    {
        snprintf(dir_path, sizeof(dir_path), "%s", cwd);
    }
    else if (dir_part[0] == '/')
    {
        snprintf(dir_path, sizeof(dir_path), "%s", dir_part);
    }
    else
    {
        snprintf(dir_path, sizeof(dir_path), "%s/%s", cwd, dir_part);
    }

    syscall_dirent_t entries[128];
    ssize_t count = sys_list_dir(dir_path, entries, sizeof(entries) / sizeof(entries[0]));
    if (count <= 0)
    {
        return;
    }

    for (ssize_t i = 0; i < count; ++i)
    {
        const syscall_dirent_t *ent = &entries[i];
        size_t name_len = strlen(ent->name);
        if (base_len > name_len)
        {
            continue;
        }
        if (base_len > 0 && memcmp(ent->name, base, base_len) != 0)
        {
            continue;
        }

        size_t candidate_len = dir_len + name_len + 1;
        char candidate[256];
        if (candidate_len >= sizeof(candidate))
        {
            continue;
        }
        size_t pos = 0;
        if (dir_len > 0)
        {
            memcpy(candidate, dir_part, dir_len);
            pos += dir_len;
        }
        memcpy(candidate + pos, ent->name, name_len);
        pos += name_len;
        if (ent->type == SYSCALL_NODE_TYPE_DIR)
        {
            candidate[pos++] = '/';
        }
        candidate[pos] = '\0';
        shell_completion_add(list, candidate);
    }
}

static void shell_render_completion_options(atk_shell_app_t *app,
                                            const shell_completion_list_t *list,
                                            const char *buffer,
                                            size_t cursor)
{
    if (!app || !list || list->count == 0)
    {
        return;
    }
    const char newline = '\n';
    shell_handle_output(app, &newline, 1);
    for (size_t i = 0; i < list->count; ++i)
    {
        const char *item = list->items[i] ? list->items[i] : "";
        shell_handle_output(app, item, strlen(item));
        if (i + 1 < list->count)
        {
            shell_handle_output(app, " ", 1);
        }
    }
    shell_handle_output(app, &newline, 1);
    shell_append_prompt(app);
    atk_terminal_clear_input(app->terminal);
    atk_terminal_set_input(app->terminal, buffer, cursor);
}

static bool shell_handle_tab_completion(atk_shell_app_t *app)
{
    if (!app || !app->terminal || app->shell_handle < 0 || app->command_active)
    {
        return false;
    }

    char input[SHELL_INPUT_CAPACITY];
    size_t cursor = 0;
    size_t len = atk_terminal_get_input(app->terminal, input, sizeof(input), &cursor);

    char cwd[256];
    if (sys_shell_get_cwd(app->shell_handle, cwd, sizeof(cwd)) < 0)
    {
        snprintf(cwd, sizeof(cwd), "/");
    }

    size_t word_start = cursor;
    while (word_start > 0 && input[word_start - 1] != ' ' && input[word_start - 1] != '\t')
    {
        --word_start;
    }
    size_t token_len = cursor - word_start;
    const char *token = input + word_start;

    size_t scan = 0;
    while (scan < word_start && (input[scan] == ' ' || input[scan] == '\t'))
    {
        ++scan;
    }
    bool first_token = (scan == word_start);

    bool has_slash = false;
    for (size_t i = 0; i < token_len; ++i)
    {
        if (token[i] == '/')
        {
            has_slash = true;
            break;
        }
    }

    shell_completion_list_t list = { 0 };
    if (first_token && !has_slash)
    {
        shell_collect_command_completions(token, token_len, &list);
    }
    shell_collect_path_completions(app, cwd, token, token_len, &list);

    if (list.count == 0)
    {
        shell_completion_reset(&list);
        return false;
    }

    bool updated = false;
    size_t common = shell_completion_common_prefix(&list);
    if (common > token_len)
    {
        size_t add_len = common - token_len;
        if (len + add_len < sizeof(input))
        {
            memmove(input + cursor + add_len, input + cursor, len - cursor);
            memcpy(input + word_start + token_len, list.items[0] + token_len, add_len);
            len += add_len;
            cursor += add_len;
            token_len = common;
            input[len] = '\0';
            updated = true;
        }
    }

    if (list.count == 1)
    {
        size_t full_len = strlen(list.items[0]);
        size_t tail_len = len - (word_start + token_len);
        size_t new_len = word_start + full_len + tail_len;
        if (new_len < sizeof(input))
        {
            memmove(input + word_start + full_len,
                    input + word_start + token_len,
                    tail_len);
            memcpy(input + word_start, list.items[0], full_len);
            len = new_len;
            cursor = word_start + full_len;
            input[len] = '\0';
            updated = true;
        }
    }

    if (!updated)
    {
        shell_render_completion_options(app, &list, input, cursor);
    }
    else
    {
        atk_terminal_set_input(app->terminal, input, cursor);
    }

    shell_completion_reset(&list);
    return true;
}

static void shell_render(atk_shell_app_t *app)
{
    if (!app)
    {
        return;
    }
    atk_render();
    atk_user_present_force(&app->remote);
}

static bool shell_handle_resize(atk_shell_app_t *app, uint32_t width, uint32_t height)
{
    if (!app || !app->window || width == 0 || height == 0)
    {
        return false;
    }

    atk_widget_t *window = app->window;
    window->width = (int)width;
    window->height = (int)height;
    atk_window_request_layout(window);
    return true;
}

static bool shell_on_resize_event(uint32_t width, uint32_t height, void *context)
{
    return shell_handle_resize((atk_shell_app_t *)context, width, height);
}

static void shell_on_close_event(void *context)
{
    atk_shell_app_t *app = (atk_shell_app_t *)context;
    if (app)
    {
        app->running = false;
    }
    atk_main_request_exit();
}

static void shell_append(atk_shell_app_t *app, const char *text)
{
    if (!app || !app->terminal || !text)
    {
        return;
    }
    atk_terminal_write(app->terminal, text, strlen(text));
    if (app)
    {
        size_t len = strlen(text);
        if (len > 0)
        {
            app->last_output_newline = text[len - 1] == '\n';
        }
    }
    if (app && app->window)
    {
        atk_window_mark_dirty(app->window);
    }
}

static void shell_append_prompt(atk_shell_app_t *app)
{
    shell_append(app, SHELL_PROMPT);
    if (app)
    {
        app->last_output_newline = false;
    }
}

static void shell_handle_output(atk_shell_app_t *app, const char *buffer, size_t len)
{
    if (!app || !buffer || len == 0)
    {
        return;
    }
    atk_terminal_write(app->terminal, buffer, len);
    /* Mark terminal region dirty and request a refresh so output appears promptly. */
    if (app->window)
    {
        atk_window_mark_dirty(app->window);
        video_request_refresh_window(app->window);
    }
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
    int start = sys_shell_exec(app->shell_handle, command, 0);
    if (start < 0)
    {
        shell_append(app, "Error: shell exec failed\n");
        shell_append_prompt(app);
    }
    else
    {
        app->command_active = true;
    }
}

static bool shell_on_control(atk_widget_t *terminal, void *context, char control)
{
    (void)terminal;
    atk_shell_app_t *app = (atk_shell_app_t *)context;
    if (!app || app->shell_handle < 0)
    {
        return false;
    }

    if (control == '\t')
    {
        return shell_handle_tab_completion(app);
    }

    if (control == 0x03)
    {
        char msg[64];
        int len = snprintf(msg,
                           sizeof(msg),
                           "[atk_shell] ctrl-c handle=%d\r\n",
                           app->shell_handle);
        if (len > 0)
        {
            sys_serial_write(msg, (size_t)len);
        }
        if (sys_shell_interrupt(app->shell_handle) == 0)
        {
            shell_poll_output(app);
            return true;
        }
        return false;
    }
    return false;
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

    atk_window_set_title_text(window, "Terminal");
    atk_window_set_chrome_visible(window, false);
    window->x = 0;
    window->y = 0;
    window->width = SHELL_WINDOW_WIDTH;
    window->height = SHELL_WINDOW_HEIGHT;

    int margin = 2;
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
    atk_widget_set_layout(terminal,
                          ATK_WIDGET_ANCHOR_LEFT |
                          ATK_WIDGET_ANCHOR_RIGHT |
                          ATK_WIDGET_ANCHOR_TOP |
                          ATK_WIDGET_ANCHOR_BOTTOM);

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

static bool shell_poll_output(atk_shell_app_t *app)
{
    if (!app || app->shell_handle < 0)
    {
        return false;
    }
    char buffer[SHELL_OUTPUT_BUFFER];
    int status = 0;
    int running = 0;
    bool changed = false;
    ssize_t copied = sys_shell_poll(app->shell_handle,
                                    buffer,
                                    sizeof(buffer),
                                    &status,
                                    &running);
    if (copied > 0)
    {
        shell_handle_output(app, buffer, (size_t)copied);
        changed = true;
    }

    if (!running && app->command_active)
    {
        app->command_active = false;
        if (!app->last_output_newline)
        {
            shell_append(app, "\n");
        }
        shell_append_prompt(app);
        changed = true;
    }
    return changed;
}

static bool shell_on_tick(void *context)
{
    atk_shell_app_t *app = (atk_shell_app_t *)context;
    if (!app || !app->running)
    {
        return false;
    }
    return shell_poll_output(app);
}

int main(void)
{
    atk_shell_app_t app;
    memset(&app, 0, sizeof(app));
    app.shell_handle = -1;
    app.running = true;
    app.command_active = false;
    app.last_output_newline = true;

    if (!atk_user_window_open_with_flags(&app.remote,
                                         "Terminal",
                                         SHELL_WINDOW_WIDTH,
                                         SHELL_WINDOW_HEIGHT,
                                         USER_ATK_WINDOW_FLAG_RESIZABLE))
    {
        printf("atk_shell: failed to open remote window\n");
        return 1;
    }
    atk_user_enable_dirty_tracking(&app.remote, true);

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

    atk_main_config_t main_cfg = {
        .window = &app.remote,
        .tick = shell_on_tick,
        .tick_context = &app,
        .present_on_idle = false,
        .legacy_input = false,
        .tick_interval_ms = SHELL_TICK_MS
    };

    atk_main_register_resize_handler(shell_on_resize_event, &app);
    atk_main_register_close_handler(shell_on_close_event, &app);

    atk_main(&main_cfg);

    if (app.shell_handle >= 0)
    {
        sys_shell_close(app.shell_handle);
    }
    atk_user_close(&app.remote);
    return 0;
}
