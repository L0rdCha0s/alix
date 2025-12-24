#include "shell.h"
#include "shell_commands.h"

#include "console.h"
#include "serial.h"
#include "keyboard.h"
#include "mouse.h"
#include "libc.h"
#include "process.h"
#include "vfs.h"
#include "user_auth.h"
#include "keyboard.h"
#include "video.h"

#define INPUT_CAPACITY 256
#define SHELL_HISTORY_LIMIT 20

static char *cli_history_entries[SHELL_HISTORY_LIMIT];
static size_t cli_history_start = 0;
static size_t cli_history_count = 0;
static size_t cli_history_cursor_from_end = 0;
static char cli_history_saved_line[INPUT_CAPACITY];
static bool cli_history_saved_valid = false;

typedef struct
{
    const char *name;
    bool (*handler)(shell_state_t *, shell_output_t *, const char *);
} shell_command_t;

typedef struct
{
    shell_state_t *shell;
    shell_output_t *output;
    const char *args;
    char *args_owned;
    bool (*handler)(shell_state_t *, shell_output_t *, const char *);
    bool result;
} shell_command_task_t;

static bool cli_try_read_char(char *out);
static char cli_get_char(void);
static size_t cli_read_line(shell_state_t *shell, char *buffer, size_t capacity);
static size_t cli_read_line_simple(char *buffer, size_t capacity, bool echo);
static bool cli_handle_escape_sequence(char *buffer,
                                       size_t *len,
                                       size_t *cursor,
                                       size_t capacity,
                                       size_t *rendered_len);
static bool cli_wait_for_char(char *out, int attempts);
static void cli_discard_escape_sequence(void);
static void cli_render_line(const char *buffer,
                            size_t len,
                            size_t cursor,
                            size_t *rendered_len);
static bool cli_handle_tab(shell_state_t *shell,
                           char *buffer,
                           size_t *len,
                           size_t *cursor,
                           size_t capacity,
                           size_t *rendered_len);
static bool is_space(char c);
static char *trim_whitespace(char *text);
static char *shell_expand_arguments(shell_state_t *shell, const char *args);
static bool shell_is_script_path(const char *path);
static bool shell_run_script(shell_state_t *shell,
                             shell_output_t *out,
                             const char *path,
                             const char *args);
static void serial_emit_char(char c);
static bool shell_output_redirect(shell_output_t *out, shell_state_t *shell, const char *path);
static void shell_print_prompt(void);
static void shell_run_and_display(shell_state_t *shell, const char *input);
static char *shell_duplicate_empty(void);
static char *shell_duplicate_string(const char *text);
static void shell_command_runner(void *arg);
static void shell_stream_console_write(void *context, const char *data, size_t len);
static void cli_history_record(const char *line);
static bool cli_history_show_previous(char *buffer, size_t *len, size_t capacity);
static bool cli_history_show_next(char *buffer, size_t *len, size_t capacity);
static void cli_history_load_current(char *buffer, size_t *len, size_t capacity);
static void cli_history_load_text(const char *text, char *buffer, size_t *len, size_t capacity);
static void cli_history_save_current(const char *buffer, size_t len);
static bool cli_line_is_blank(const char *line);
static const char SHELL_PROMPT[] = "alex@alix$ ";

typedef struct
{
    char **items;
    size_t count;
    size_t capacity;
} shell_completion_list_t;

static void shell_completion_reset(shell_completion_list_t *list);
static bool shell_completion_add(shell_completion_list_t *list, const char *text);
static bool shell_collect_command_completions(const char *token,
                                              size_t token_len,
                                              shell_completion_list_t *list);
static bool shell_collect_path_completions(shell_state_t *shell,
                                           const char *token,
                                           size_t token_len,
                                           shell_completion_list_t *list);
static size_t shell_completion_common_prefix(shell_completion_list_t *list);
static void shell_completion_render_options(shell_completion_list_t *list);
static size_t cli_read_line_hidden(char *buffer, size_t capacity);
static bool shell_prompt_login(shell_state_t *shell);
static void shell_write_text(const char *text);

static shell_state_t *g_active_shell = NULL;
static shell_console_tap_fn g_console_tap_fn = NULL;
static void *g_console_tap_ctx = NULL;
static shell_state_t *shell_push_active(shell_state_t *shell)
{
    shell_state_t *prev = g_active_shell;
    g_active_shell = shell;
    return prev;
}

static void shell_pop_active(shell_state_t *prev)
{
    g_active_shell = prev;
}
static void shell_wait_for_interrupt(void *context);

void shell_set_console_tap(shell_console_tap_fn fn, void *context)
{
    g_console_tap_fn = fn;
    g_console_tap_ctx = context;
}

void shell_get_console_tap(shell_console_tap_fn *fn_out, void **ctx_out)
{
    if (fn_out)
    {
        *fn_out = g_console_tap_fn;
    }
    if (ctx_out)
    {
        *ctx_out = g_console_tap_ctx;
    }
}

void shell_emit_console_tap(const char *data, size_t len)
{
    shell_console_tap_fn fn = g_console_tap_fn;
    void *ctx = g_console_tap_ctx;
    if (fn && data && len > 0)
    {
        fn(ctx, data, len);
    }
}

void shell_output_init_console(shell_output_t *out)
{
    out->to_file = false;
    out->file = NULL;
    out->file_offset = 0;
    out->to_buffer = false;
    out->buffer = NULL;
    out->length = 0;
    out->capacity = 0;
}

void shell_output_init_buffer(shell_output_t *out)
{
    out->to_file = false;
    out->file = NULL;
    out->file_offset = 0;
    out->to_buffer = true;
    out->buffer = NULL;
    out->length = 0;
    out->capacity = 0;
}

bool shell_output_prepare_file(shell_output_t *out, vfs_node_t *file)
{
    if (!out)
    {
        return false;
    }
    out->to_file = true;
    out->file = file;
    out->to_buffer = false;
    if (out->buffer)
    {
        free(out->buffer);
        out->buffer = NULL;
    }
    out->file_offset = 0;
    out->length = 0;
    out->capacity = 0;
    return true;
}

static bool shell_output_write_console(shell_output_t *out, const char *text, size_t len)
{
    (void)out;
    if (!text)
    {
        return true;
    }

    for (size_t i = 0; i < len; ++i)
    {
        char c = text[i];
        console_putc(c);
        serial_emit_char(c);
    }
    return true;
}

static bool shell_output_buffer_ensure(shell_output_t *out, size_t extra)
{
    size_t needed = out->length + extra + 1;
    if (needed <= out->capacity)
    {
        return true;
    }
    size_t new_capacity = out->capacity ? out->capacity : 64;
    while (new_capacity < needed)
    {
        new_capacity *= 2;
    }
    char *new_buffer = (char *)realloc(out->buffer, new_capacity);
    if (!new_buffer)
    {
        return false;
    }
    out->buffer = new_buffer;
    out->capacity = new_capacity;
    return true;
}

bool shell_output_write_len(shell_output_t *out, const char *text, size_t len)
{
    if (!text || len == 0)
    {
        return true;
    }

    shell_state_t *active = g_active_shell;
    if (active && active->stream_fn)
    {
        /*
         * Stream immediately so remote shells (and the interactive console)
         * see output as it is produced. Avoid double-printing when the stream
         * target is already the console sink.
         */
        if (active->stream_fn != shell_stream_console_write || out->to_buffer || out->to_file)
        {
            active->stream_fn(active->stream_context, text, len);
        }
    }

    if (out->to_file)
    {
        if (!out->file)
        {
            return false;
        }
        ssize_t written = vfs_write_at(out->file, out->file_offset, text, len);
        if (written < 0)
        {
            return false;
        }
        out->file_offset += (size_t)written;
        return written == (ssize_t)len;
    }
    if (out->to_buffer)
    {
        if (!shell_output_buffer_ensure(out, len))
        {
            return false;
        }
        memcpy(out->buffer + out->length, text, len);
        out->length += len;
        out->buffer[out->length] = '\0';
        return true;
    }

    return shell_output_write_console(out, text, len);
}

bool shell_output_write(shell_output_t *out, const char *text)
{
    if (!text)
    {
        text = "";
    }
    return shell_output_write_len(out, text, strlen(text));
}

void shell_print_error(const char *msg)
{
    shell_output_t out;
    shell_output_init_console(&out);
    shell_output_write(&out, "Error: ");
    shell_output_write(&out, msg);
    shell_output_write(&out, "\n");
}

bool shell_output_error(shell_output_t *out, const char *msg)
{
    if (!out)
    {
        return false;
    }
    shell_output_write(out, "Error: ");
    shell_output_write(out, msg);
    shell_output_write(out, "\n");
    return false;
}

bool shell_request_interrupt(shell_state_t *shell)
{
    if (!shell)
    {
        return false;
    }

    process_t *proc = shell_foreground_load(shell);
    if (!proc)
    {
        return false;
    }

    process_kill_tree(proc);
    return true;
}

char *shell_output_take_buffer(shell_output_t *out)
{
    if (!out || !out->to_buffer)
    {
        return shell_duplicate_empty();
    }

    if (!out->buffer)
    {
        return shell_duplicate_empty();
    }

    char *result = out->buffer;
    out->buffer = NULL;
    out->capacity = 0;
    out->length = 0;
    out->to_buffer = false;
    return result;
}

void shell_output_reset(shell_output_t *out)
{
    if (!out)
    {
        return;
    }
    if (out->buffer)
    {
        free(out->buffer);
        out->buffer = NULL;
    }
    out->to_file = false;
    out->file = NULL;
    out->file_offset = 0;
    out->to_buffer = false;
    out->length = 0;
    out->capacity = 0;
}

typedef struct
{
    char **items;
    size_t count;
    size_t capacity;
} shell_arg_list_t;

static void shell_arg_list_reset(shell_arg_list_t *list)
{
    if (!list)
    {
        return;
    }
    if (list->items)
    {
        for (size_t i = 0; i < list->count; ++i)
        {
            free(list->items[i]);
        }
        free(list->items);
    }
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static bool shell_arg_list_push(shell_arg_list_t *list, char *value)
{
    if (!list || !value)
    {
        return false;
    }
    if (list->count >= list->capacity)
    {
        size_t new_capacity = list->capacity ? list->capacity * 2 : 4;
        char **new_items = (char **)realloc(list->items, new_capacity * sizeof(char *));
        if (!new_items)
        {
            return false;
        }
        list->items = new_items;
        list->capacity = new_capacity;
    }
    list->items[list->count++] = value;
    return true;
}

static bool shell_pattern_has_wildcard(const char *text)
{
    if (!text)
    {
        return false;
    }
    while (*text)
    {
        if (*text == '*' || *text == '?')
        {
            return true;
        }
        ++text;
    }
    return false;
}

static bool shell_pattern_match(const char *pattern, const char *text)
{
    const char *star = NULL;
    const char *match = NULL;

    while (*text)
    {
        if (*pattern == '?' || *pattern == *text)
        {
            ++pattern;
            ++text;
        }
        else if (*pattern == '*')
        {
            star = pattern++;
            match = text;
        }
        else if (star)
        {
            pattern = star + 1;
            text = ++match;
        }
        else
        {
            return false;
        }
    }

    while (*pattern == '*')
    {
        ++pattern;
    }
    return *pattern == '\0';
}

static vfs_node_t *shell_resolve_dir(shell_state_t *shell, const char *path)
{
    vfs_node_t *cwd = (shell && shell->cwd) ? shell->cwd : vfs_root();
    if (!path || *path == '\0')
    {
        return cwd;
    }
    if (path[0] == '/')
    {
        return vfs_resolve(vfs_root(), path);
    }
    vfs_node_t *node = vfs_resolve(cwd, path);
    if (!node)
    {
        node = vfs_resolve(vfs_root(), path);
    }
    return node;
}

static bool shell_expand_token(shell_state_t *shell, const char *token, shell_arg_list_t *list)
{
    if (!token || !list)
    {
        return false;
    }

    if (!shell_pattern_has_wildcard(token))
    {
        char *copy = shell_duplicate_string(token);
        if (!copy)
        {
            return false;
        }
        if (!shell_arg_list_push(list, copy))
        {
            free(copy);
            return false;
        }
        return true;
    }

    const char *slash = NULL;
    for (const char *p = token; *p; ++p)
    {
        if (*p == '/')
        {
            slash = p;
        }
    }

    char *dir_part = NULL;
    const char *pattern = token;
    if (slash)
    {
        size_t dir_len = (size_t)(slash - token);
        if (dir_len == 0)
        {
            dir_part = shell_duplicate_string("/");
        }
        else
        {
            dir_part = (char *)malloc(dir_len + 1);
            if (!dir_part)
            {
                return false;
            }
            memcpy(dir_part, token, dir_len);
            dir_part[dir_len] = '\0';
        }
        pattern = slash + 1;
    }

    if (!pattern || *pattern == '\0')
    {
        pattern = "*";
    }

    vfs_node_t *dir = shell_resolve_dir(shell, dir_part);
    if (!dir || !vfs_is_dir(dir))
    {
        if (dir_part)
        {
            free(dir_part);
        }
        char *copy = shell_duplicate_string(token);
        if (!copy)
        {
            return false;
        }
        if (!shell_arg_list_push(list, copy))
        {
            free(copy);
            return false;
        }
        return true;
    }

    bool matched = false;
    for (vfs_node_t *child = vfs_first_child(dir); child; child = vfs_next_sibling(child))
    {
        const char *name = vfs_name(child);
        if (!name || !shell_pattern_match(pattern, name))
        {
            continue;
        }
        matched = true;
        size_t prefix_len = (dir_part && *dir_part) ? strlen(dir_part) : 0;
        bool needs_separator = dir_part && prefix_len > 0 && dir_part[prefix_len - 1] != '/';
        size_t name_len = strlen(name);
        size_t full_len = prefix_len + (needs_separator ? 1 : 0) + name_len;
        char *full = (char *)malloc(full_len + 1);
        if (!full)
        {
            if (dir_part)
            {
                free(dir_part);
            }
            return false;
        }
        size_t pos = 0;
        if (dir_part && *dir_part)
        {
            memcpy(full, dir_part, prefix_len);
            pos += prefix_len;
            if (needs_separator)
            {
                full[pos++] = '/';
            }
        }
        memcpy(full + pos, name, name_len);
        pos += name_len;
        full[pos] = '\0';
        if (!shell_arg_list_push(list, full))
        {
            free(full);
            if (dir_part)
            {
                free(dir_part);
            }
            return false;
        }
    }

    if (!matched)
    {
        char *copy = shell_duplicate_string(token);
        if (!copy)
        {
            if (dir_part)
            {
                free(dir_part);
            }
            return false;
        }
        if (!shell_arg_list_push(list, copy))
        {
            free(copy);
            if (dir_part)
            {
                free(dir_part);
            }
            return false;
        }
    }

    if (dir_part)
    {
        free(dir_part);
    }
    return true;
}

static char *shell_expand_arguments(shell_state_t *shell, const char *args)
{
    shell_arg_list_t list = { 0 };
    const char *cursor = args ? args : "";

    while (*cursor)
    {
        while (is_space(*cursor))
        {
            ++cursor;
        }
        if (*cursor == '\0')
        {
            break;
        }

        const char *start = cursor;
        while (*cursor && !is_space(*cursor))
        {
            ++cursor;
        }
        size_t len = (size_t)(cursor - start);
        char *token = (char *)malloc(len + 1);
        if (!token)
        {
            shell_arg_list_reset(&list);
            return NULL;
        }
        memcpy(token, start, len);
        token[len] = '\0';

        if (!shell_expand_token(shell, token, &list))
        {
            free(token);
            shell_arg_list_reset(&list);
            return NULL;
        }
        free(token);
    }

    if (list.count == 0)
    {
        shell_arg_list_reset(&list);
        return shell_duplicate_empty();
    }

    size_t total_len = 0;
    for (size_t i = 0; i < list.count; ++i)
    {
        total_len += strlen(list.items[i]);
        if (i + 1 < list.count)
        {
            total_len += 1;
        }
    }

    char *result = (char *)malloc(total_len + 1);
    if (!result)
    {
        shell_arg_list_reset(&list);
        return NULL;
    }

    size_t pos = 0;
    for (size_t i = 0; i < list.count; ++i)
    {
        size_t len = strlen(list.items[i]);
        memcpy(result + pos, list.items[i], len);
        pos += len;
        if (i + 1 < list.count)
        {
            result[pos++] = ' ';
        }
    }
    result[pos] = '\0';

    shell_arg_list_reset(&list);
    return result;
}

static bool shell_is_script_path(const char *path)
{
    if (!path)
    {
        return false;
    }
    size_t len = strlen(path);
    if (len < 3)
    {
        return false;
    }
    char second = path[len - 2];
    char third = path[len - 1];
    if (second >= 'A' && second <= 'Z')
    {
        second = (char)(second + ('a' - 'A'));
    }
    if (third >= 'A' && third <= 'Z')
    {
        third = (char)(third + ('a' - 'A'));
    }
    return path[len - 3] == '.' && second == 's' && third == 'h';
}

static bool shell_run_script(shell_state_t *shell,
                             shell_output_t *out,
                             const char *path,
                             const char *args)
{
    (void)args;
    if (!shell || !path || *path == '\0')
    {
        if (out)
        {
            shell_output_error(out, "script: invalid path");
        }
        return false;
    }

    vfs_node_t *cwd = shell->cwd ? shell->cwd : vfs_root();
    vfs_node_t *node = vfs_resolve(cwd, path);
    if (!node)
    {
        node = vfs_resolve(vfs_root(), path);
    }
    if (!node || !vfs_is_file(node))
    {
        if (out)
        {
            shell_output_error(out, "script: file not found");
        }
        return false;
    }

    size_t size = 0;
    char *data = vfs_data(node, &size);
    if (!data)
    {
        if (out)
        {
            shell_output_error(out, "script: unable to read");
        }
        return false;
    }
    if (size == 0)
    {
        return true;
    }

    char *buffer = (char *)malloc(size + 1);
    if (!buffer)
    {
        if (out)
        {
            shell_output_error(out, "script: out of memory");
        }
        return false;
    }
    memcpy(buffer, data, size);
    buffer[size] = '\0';

    bool interactive = shell->stream_fn == shell_stream_console_write;
    bool redirecting = out && out->to_file;
    bool stream_immediately = interactive && !redirecting;
    bool overall_ok = true;

    char *cursor = buffer;
    while (*cursor)
    {
        char *line = cursor;
        while (*cursor && *cursor != '\n' && *cursor != '\r')
        {
            ++cursor;
        }
        char saved = *cursor;
        *cursor = '\0';

        char *trimmed = trim_whitespace(line);
        if (*trimmed && trimmed[0] != '#')
        {
            bool line_success = false;
            char *result = shell_execute_line(shell, trimmed, &line_success);
            if (result && *result)
            {
                if (stream_immediately)
                {
                    console_write(result);
                    serial_printf("%s", result);
                }
                else if (out)
                {
                    shell_output_write(out, result);
                }
            }
            if (result)
            {
                free(result);
            }
            if (!line_success)
            {
                overall_ok = false;
            }
        }

        *cursor = saved;
        while (*cursor == '\n' || *cursor == '\r')
        {
            ++cursor;
        }
    }

    free(buffer);
    return overall_ok;
}

static bool shell_prompt_login(shell_state_t *shell)
{
    if (!shell)
    {
        return false;
    }

    char user_buf[64];
    char pass_buf[64];

    while (1)
    {
        shell_write_text("login: ");
        cli_read_line_simple(user_buf, sizeof(user_buf), true);
        char *user = trim_whitespace(user_buf);
        if (!user || user[0] == '\0')
        {
            continue;
        }

        shell_write_text("password: ");
        cli_read_line_hidden(pass_buf, sizeof(pass_buf));
        char *pass = trim_whitespace(pass_buf);

        user_record_t record;
        memset(&record, 0, sizeof(record));
        bool ok = user_auth_lookup(user, &record) && user_auth_check_password(user, pass);
        if (ok)
        {
            process_set_identity(shell->owner_process, record.uid, record.gid);
            if (record.home && record.home[0] != '\0')
            {
                vfs_node_t *home = vfs_resolve(vfs_root(), record.home);
                if (home && vfs_is_dir(home))
                {
                    process_set_cwd(shell->owner_process, home);
                }
            }
            user_auth_free_record(&record);
            shell->cwd = process_current_cwd();
            return true;
        }
        user_auth_free_record(&record);
        shell_write_text("Login incorrect\n");
    }
}

void shell_main(void)
{
    /* Commands run in separate threads mutate shell state, so keep it off-stack. */
    shell_state_t *shell = (shell_state_t *)malloc(sizeof(shell_state_t));
    if (!shell)
    {
        console_write("Shell: unable to allocate state\n");
        serial_printf("%s", "Shell: unable to allocate state\r\n");
        return;
    }
    shell->cwd = process_current_cwd();
    shell->stream_fn = shell_stream_console_write;
    shell->stream_context = NULL;
    shell->stdout_fd = process_current_stdout_fd();
    shell_foreground_store(shell, NULL);
    shell->wait_hook = shell_wait_for_interrupt;
    shell->wait_context = shell;
    shell->owner_process = process_current();
    shell->cwd_changed_fn = NULL;
    shell->cwd_changed_context = NULL;
    g_active_shell = shell;
    char input[INPUT_CAPACITY];

    if (shell->owner_process)
    {
        process_set_identity(shell->owner_process, PROCESS_UID_INVALID, PROCESS_GID_INVALID);
    }
    (void)shell_prompt_login(shell);

    console_write("In-memory FS shell ready. Commands: echo, cat, mkdir, cd, pwd, rm, mkfs, mount, tzset, tzstatus, tzsync, ntpdate, shutdown, ls, ip, ping, nslookup, wget, imgview, preview, logcat, sha1sum, dhclient, start_video, net_mac, dnsdebug, alloc1m, free, loop1, loop2, letters, top, useratk, atkshell, taskmgr, wolf3d, doom, bgset, runelf, or ./path for binaries.\n");
    serial_printf("%s", "In-memory FS shell ready. Commands: echo, cat, mkdir, cd, pwd, rm, mkfs, mount, tzset, tzstatus, tzsync, ntpdate, shutdown, ls, ip, ping, nslookup, wget, imgview, preview, logcat, sha1sum, dhclient, start_video, net_mac, dnsdebug, alloc1m, free, loop1, loop2, letters, top, useratk, atkshell, taskmgr, wolf3d, doom, bgset, runelf, or ./path for binaries.\r\n");

    while (1)
    {
        shell_print_prompt();
        size_t len = cli_read_line(shell, input, INPUT_CAPACITY);
        (void)len;
        cli_history_record(input);
        shell_run_and_display(shell, input);
    }
}

static const shell_command_t g_commands[] = {
    { "echo",        shell_cmd_echo },
    { "cat",         shell_cmd_cat },
    { "mkdir",       shell_cmd_mkdir },
    { "cd",          shell_cmd_cd },
    { "pwd",         shell_cmd_pwd },
    { "rm",          shell_cmd_rm },
    { "mkfs",        shell_cmd_mkfs },
    { "mount",       shell_cmd_mount },
    { "tzset",       shell_cmd_tzset },
    { "tzstatus",    shell_cmd_tzstatus },
    { "tzsync",      shell_cmd_tzsync },
    { "ntpdate",     shell_cmd_ntpdate },
    { "shutdown",    shell_cmd_shutdown },
    { "ls",          shell_cmd_ls },
    { "ip",          shell_cmd_ip },
    { "ping",        shell_cmd_ping },
    { "nslookup",    shell_cmd_nslookup },
    { "wget",        shell_cmd_wget },
    { "imgview",     shell_cmd_imgview },
    { "preview",     shell_cmd_preview },
    { "logcat",      shell_cmd_logcat },
    { "sha1sum",     shell_cmd_sha1sum },
    { "dhclient",    shell_cmd_dhclient },
    { "start_video", shell_cmd_start_video },
    { "net_mac",     shell_cmd_net_mac },
    { "dnsdebug",    shell_cmd_dnsdebug },
    { "alloc1m",     shell_cmd_alloc1m },
    { "free",        shell_cmd_free },
    { "loop1",       shell_cmd_loop1 },
    { "loop2",       shell_cmd_loop2 },
    { "letters",     shell_cmd_letters },
    { "top",         shell_cmd_top },
    { "useratk",     shell_cmd_useratk },
    { "atkshell",    shell_cmd_atkshell },
    { "taskmgr",     shell_cmd_atktaskmgr },
    { "bgset",       shell_cmd_bgset },
    { "doom",        shell_cmd_doom },
    { "quake",       shell_cmd_quake },
    { "wolf3d",      shell_cmd_wolf3d },
    { "runelf",      shell_cmd_runelf },
};

static void shell_command_runner(void *arg)
{
    shell_command_task_t *task = (shell_command_task_t *)arg;
    bool ok = false;
    if (task && task->handler)
    {
        ok = task->handler(task->shell, task->output, task->args);
        task->result = ok;
    }
    process_exit(ok ? 0 : 1);
}

char *shell_execute_line(shell_state_t *shell, const char *input, bool *success)
{
    if (success)
    {
        *success = false;
    }

    if (!input)
    {
        return shell_duplicate_empty();
    }

    shell_state_t *prev_shell = shell_push_active(shell);
    shell_console_tap_fn prev_tap_fn = NULL;
    void *prev_tap_ctx = NULL;
    shell_get_console_tap(&prev_tap_fn, &prev_tap_ctx);
    if (shell && shell->stream_fn)
    {
        shell_set_console_tap(shell->stream_fn, shell->stream_context);
    }

    size_t input_len = strlen(input);
    char *working = (char *)malloc(input_len + 1);
    if (!working)
    {
        shell_pop_active(prev_shell);
        shell_set_console_tap(prev_tap_fn, prev_tap_ctx);
        return shell_duplicate_empty();
    }
    memcpy(working, input, input_len + 1);

    char *line = trim_whitespace(working);
    if (*line == '\0')
    {
        free(working);
        if (success)
        {
            *success = true;
        }
        shell_pop_active(prev_shell);
        shell_set_console_tap(prev_tap_fn, prev_tap_ctx);
        return shell_duplicate_empty();
    }

    char *redirect = NULL;
    for (char *p = line; *p; ++p)
    {
        if (*p == '>')
        {
            redirect = p;
            break;
        }
    }

    char *redirect_path = NULL;
    if (redirect)
    {
        *redirect = '\0';
        redirect_path = trim_whitespace(redirect + 1);
        if (*redirect_path == '\0')
        {
        free(working);
        shell_pop_active(prev_shell);
        shell_set_console_tap(prev_tap_fn, prev_tap_ctx);
        return shell_duplicate_string("Error: redirect target missing\n");
        }
    }

    char *cursor = line;
    while (*cursor && !is_space(*cursor))
    {
        ++cursor;
    }

    char *args = cursor;
    if (*cursor)
    {
        *cursor = '\0';
        args = trim_whitespace(cursor + 1);
    }
    else
    {
        args = trim_whitespace(cursor);
    }

    char *args_owned = shell_expand_arguments(shell, args);
    if (!args_owned)
    {
        free(working);
        shell_pop_active(prev_shell);
        shell_set_console_tap(prev_tap_fn, prev_tap_ctx);
        return shell_duplicate_string("Error: failed to expand arguments\n");
    }
    args = args_owned;

    bool is_path_command = false;
    for (char *p = line; *p; ++p)
    {
        if (*p == '/')
        {
            is_path_command = true;
            break;
        }
    }

    if (!is_path_command)
    {
        for (char *p = line; *p; ++p)
        {
            if (*p >= 'A' && *p <= 'Z')
            {
                *p = (char)(*p + ('a' - 'A'));
            }
        }
    }

    shell_output_t *output = (shell_output_t *)malloc(sizeof(shell_output_t));
    if (!output)
    {
        if (args_owned)
        {
            free(args_owned);
        }
        free(working);
        shell_pop_active(prev_shell);
        shell_set_console_tap(prev_tap_fn, prev_tap_ctx);
        return shell_duplicate_string("Error: out of memory\n");
    }
    if (redirect_path)
    {
        shell_output_init_buffer(output);
        if (!shell_output_redirect(output, shell, redirect_path))
        {
            shell_output_reset(output);
            free(output);
            if (args_owned)
            {
                free(args_owned);
            }
            free(working);
            shell_pop_active(prev_shell);
            shell_set_console_tap(prev_tap_fn, prev_tap_ctx);
            return shell_duplicate_string("Error: redirect failed\n");
        }
    }
    else
    {
        shell_output_init_buffer(output);
    }

    bool handler_found = false;
    bool handler_result = false;
    for (size_t i = 0; i < sizeof(g_commands) / sizeof(g_commands[0]); ++i)
    {
        if (strcmp(line, g_commands[i].name) == 0)
        {
            handler_found = true;
            shell_command_task_t *task = (shell_command_task_t *)malloc(sizeof(shell_command_task_t));
            if (!task)
            {
                handler_result = false;
                break;
            }
            task->shell = shell;
            task->output = output;
            task->args = args ? args : "";
            task->args_owned = args_owned;
            args_owned = NULL;
            task->handler = g_commands[i].handler;
            task->result = false;

            process_t *proc = process_create_kernel_with_parent(g_commands[i].name,
                                                                shell_command_runner,
                                                                task,
                                                                0,
                                                                shell ? shell->stdout_fd : -1,
                                                                shell ? shell->owner_process : NULL);
            if (!proc)
            {
                free(task);
                handler_result = false;
                break;
            }

            if (shell)
            {
                shell_foreground_store(shell, proc);
            }

            process_join_with_hook(proc,
                                    NULL,
                                    shell ? shell->wait_hook : NULL,
                                    shell ? shell->wait_context : NULL);
            handler_result = task->result;
            process_destroy(proc);
            if (task->args_owned)
            {
                free(task->args_owned);
            }
            free(task);

            if (shell && shell_foreground_load(shell) == proc)
            {
                shell_foreground_store(shell, NULL);
            }
            break;
        }
    }

    char *result = NULL;

    if (!handler_found)
    {
        if (is_path_command)
        {
            bool script_attempted = false;
            if (shell_is_script_path(line))
            {
                handler_found = true;
                script_attempted = true;
                handler_result = shell_run_script(shell, output, line, args);
                if (args_owned)
                {
                    free(args_owned);
                    args_owned = NULL;
                }
            }

            if (!script_attempted)
            {
                handler_found = true;

                size_t path_len = strlen(line);
                size_t args_len = (args && *args) ? strlen(args) : 0;
                size_t combined_len = path_len + (args_len ? (1 + args_len) : 0);
                char *path_args = (char *)malloc(combined_len + 1);
                if (!path_args)
                {
                    handler_result = false;
                }
                else
                {
                    memcpy(path_args, line, path_len);
                    if (args_len)
                    {
                        path_args[path_len] = ' ';
                        memcpy(path_args + path_len + 1, args, args_len);
                        path_args[combined_len] = '\0';
                    }
                    else
                    {
                        path_args[path_len] = '\0';
                    }

                    if (args_owned)
                    {
                        free(args_owned);
                        args_owned = NULL;
                    }

                    shell_command_task_t *task = (shell_command_task_t *)malloc(sizeof(shell_command_task_t));
                    if (!task)
                    {
                        free(path_args);
                        handler_result = false;
                    }
                    else
                    {
                        task->shell = shell;
                        task->output = output;
                        task->args = path_args;
                        task->args_owned = path_args;
                        task->handler = shell_cmd_runelf;
                        task->result = false;

                        process_t *proc = process_create_kernel_with_parent("runelf",
                                                                            shell_command_runner,
                                                                            task,
                                                                            0,
                                                                            shell ? shell->stdout_fd : -1,
                                                                            shell ? shell->owner_process : NULL);
                        if (!proc)
                        {
                            free(path_args);
                            free(task);
                            handler_result = false;
                        }
                        else
                        {
                            if (shell)
                            {
                                shell_foreground_store(shell, proc);
                            }
                            process_join_with_hook(proc,
                                                    NULL,
                                                    shell ? shell->wait_hook : NULL,
                                                    shell ? shell->wait_context : NULL);
                            handler_result = task->result;
                            process_destroy(proc);
                            if (task->args_owned)
                            {
                                free(task->args_owned);
                            }
                            if (shell && shell_foreground_load(shell) == proc)
                            {
                                shell_foreground_store(shell, NULL);
                            }
                            free(task);
                        }
                    }
                }
            }
        }
        else
        {
            result = shell_duplicate_string("Error: unknown command\n");
            handler_result = false;
        }
    }

    if (handler_found)
    {
        if (redirect_path)
        {
            result = shell_duplicate_empty();
        }
        else if (!result)
        {
            result = shell_output_take_buffer(output);
        }
    }

    shell_output_reset(output);
    free(output);
    free(working);
    if (args_owned)
    {
        free(args_owned);
        args_owned = NULL;
    }

    if (!result)
    {
        result = shell_duplicate_empty();
    }

    if (success)
    {
        *success = handler_found && handler_result;
    }
    shell_pop_active(prev_shell);
    shell_set_console_tap(prev_tap_fn, prev_tap_ctx);
    return result;
}

static bool shell_output_redirect(shell_output_t *out, shell_state_t *shell, const char *path)
{
    if (!path || *path == '\0')
    {
        return false;
    }
    vfs_node_t *file = vfs_open_file(shell->cwd, path, true, true);
    if (!file)
    {
        return false;
    }
    return shell_output_prepare_file(out, file);
}

static void shell_run_and_display(shell_state_t *shell, const char *input)
{
    bool success = false;
    char *result = shell_execute_line(shell, input, &success);
    bool streamed = shell && shell->stream_fn;
    if (result && *result && !streamed)
    {
        console_write(result);
        serial_printf("%s", result);
    }
    if (result)
    {
        free(result);
    }
    (void)success;
}

static char *shell_duplicate_empty(void)
{
    char *result = (char *)malloc(1);
    if (result)
    {
        result[0] = '\0';
    }
    return result;
}

static char *shell_duplicate_string(const char *text)
{
    if (!text)
    {
        return shell_duplicate_empty();
    }
    size_t len = strlen(text);
    char *copy = (char *)malloc(len + 1);
    if (!copy)
    {
        return shell_duplicate_empty();
    }
    memcpy(copy, text, len + 1);
    return copy;
}

static void shell_print_prompt(void)
{
    console_write(SHELL_PROMPT);
    serial_output_bytes(SHELL_PROMPT, sizeof(SHELL_PROMPT) - 1);
}

static void shell_write_text(const char *text)
{
    if (!text)
    {
        return;
    }
    console_write(text);
    serial_output_bytes(text, strlen(text));
}

static bool cli_try_read_char(char *out)
{
    if (!out)
    {
        return false;
    }
    /* When video mode is active, leave keyboard input for ATK/GUI paths. */
    if (video_is_active())
    {
        if (serial_has_char())
        {
            *out = serial_read_char();
            return true;
        }
        return false;
    }
    if (keyboard_try_read(out))
    {
        return true;
    }
    if (serial_has_char())
    {
        *out = serial_read_char();
        return true;
    }
    return false;
}

static char cli_get_char(void)
{
    //serial_write_string("In cli_get_char\n");

    char c;
    while (!cli_try_read_char(&c))
    {
        mouse_poll();
        process_sleep_ms(5);
    }
    return c;
}

static bool cli_wait_for_char(char *out, int attempts)
{
    while (attempts-- > 0)
    {
        if (cli_try_read_char(out))
        {
            return true;
        }
        mouse_poll();
    }
    return false;
}

static void cli_discard_escape_sequence(void)
{
    char next = 0;
    if (!cli_wait_for_char(&next, 8))
    {
        return;
    }
    if (next != '[')
    {
        return;
    }
    char final = 0;
    if (!cli_wait_for_char(&final, 8))
    {
        return;
    }
    if ((final >= '0' && final <= '9') || final == ';')
    {
        for (int i = 0; i < 4; ++i)
        {
            if (!cli_wait_for_char(&final, 8))
            {
                break;
            }
            if ((final >= 'A' && final <= 'Z') || (final >= 'a' && final <= 'z'))
            {
                break;
            }
        }
    }
}

static void shell_wait_for_interrupt(void *context)
{
    shell_state_t *shell = (shell_state_t *)context;
    if (!shell)
    {
        return;
    }

    char c;
    if (!cli_try_read_char(&c))
    {
        mouse_poll();
        return;
    }
    if (c == 0x03) /* Ctrl-C */
    {
        console_write("^C\n");
        serial_output_bytes("^C\r\n", 4);
        shell_request_interrupt(shell);
        return;
    }
    /* Not Ctrl-C: push it back so interactive sessions don't lose input. */
    keyboard_unread_char(c);
}

static bool cli_handle_escape_sequence(char *buffer,
                                       size_t *len,
                                       size_t *cursor,
                                       size_t capacity,
                                       size_t *rendered_len)
{
    if (!buffer || !len || !cursor)
    {
        return true;
    }

    char next = 0;
    if (!cli_wait_for_char(&next, 64))
    {
        return true;
    }
    if (next != '[')
    {
        return true;
    }

    char final = 0;
    if (!cli_wait_for_char(&final, 64))
    {
        return true;
    }

    switch (final)
    {
        case 'A':
            if (cli_history_show_previous(buffer, len, capacity))
            {
                *cursor = *len;
                cli_render_line(buffer, *len, *cursor, rendered_len);
            }
            break;
        case 'B':
            if (cli_history_show_next(buffer, len, capacity))
            {
                *cursor = *len;
                cli_render_line(buffer, *len, *cursor, rendered_len);
            }
            break;
        case 'C':
            if (*cursor < *len)
            {
                (*cursor)++;
                cli_render_line(buffer, *len, *cursor, rendered_len);
            }
            break;
        case 'D':
            if (*cursor > 0)
            {
                (*cursor)--;
                cli_render_line(buffer, *len, *cursor, rendered_len);
            }
            break;
        default:
            break;
    }
    return true;
}

static size_t cli_read_line(shell_state_t *shell, char *buffer, size_t capacity)
{
    size_t len = 0;
    size_t cursor = 0;
    size_t rendered_len = 0;
    if (buffer && capacity > 0)
    {
        buffer[0] = '\0';
    }

    while (1)
    {
        char c = cli_get_char();

        if (c == 0x1B)
        {
            if (cli_handle_escape_sequence(buffer, &len, &cursor, capacity, &rendered_len))
            {
                continue;
            }
        }
        else if (c == 0x03) /* Ctrl-C */
        {
            console_write("^C\n");
            serial_output_bytes("^C\r\n", 4);
            if (shell)
            {
                shell_request_interrupt(shell);
            }
            buffer[0] = '\0';
            return 0;
        }
        else if (c == '\t')
        {
            if (cli_handle_tab(shell, buffer, &len, &cursor, capacity, &rendered_len))
            {
                continue;
            }
        }
        else if (c == '\r')
        {
            c = '\n';
        }

        if (c == '\n')
        {
            console_putc('\n');
            serial_emit_char('\n');
            buffer[len] = '\0';
            return len;
        }

        if ((c == '\b' || c == 0x7F))
        {
            if (cursor > 0)
            {
                memmove(buffer + cursor - 1, buffer + cursor, len - cursor);
                len--;
                cursor--;
                buffer[len] = '\0';
                cli_render_line(buffer, len, cursor, &rendered_len);
            }
            continue;
        }

        if (c >= ' ' && len < capacity - 1)
        {
            memmove(buffer + cursor + 1, buffer + cursor, len - cursor);
            buffer[cursor] = c;
            len++;
            cursor++;
            buffer[len] = '\0';
            cli_render_line(buffer, len, cursor, &rendered_len);
        }
    }
}

static size_t cli_read_line_hidden(char *buffer, size_t capacity)
{
    return cli_read_line_simple(buffer, capacity, false);
}

static size_t cli_read_line_simple(char *buffer, size_t capacity, bool echo)
{
    size_t len = 0;
    if (buffer && capacity > 0)
    {
        buffer[0] = '\0';
    }

    while (1)
    {
        char c = cli_get_char();

        if (c == 0x1B)
        {
            cli_discard_escape_sequence();
            continue;
        }
        if (c == 0x03)
        {
            console_write("^C\n");
            serial_output_bytes("^C\r\n", 4);
            if (buffer && capacity > 0)
            {
                buffer[0] = '\0';
            }
            return 0;
        }
        if (c == '\r')
        {
            c = '\n';
        }

        if (c == '\n')
        {
            console_putc('\n');
            serial_emit_char('\n');
            if (buffer)
            {
                buffer[len] = '\0';
            }
            return len;
        }

        if (c == '\b' || c == 0x7F)
        {
            if (len > 0)
            {
                len--;
                buffer[len] = '\0';
                if (echo)
                {
                    console_putc('\b');
                    console_putc(' ');
                    console_putc('\b');
                    serial_emit_char('\b');
                    serial_emit_char(' ');
                    serial_emit_char('\b');
                }
            }
            continue;
        }

        if (c >= ' ' && len < capacity - 1)
        {
            buffer[len++] = c;
            buffer[len] = '\0';
            if (echo)
            {
                console_putc(c);
                serial_emit_char(c);
            }
        }
    }
}

static bool is_space(char c)
{
    return c == ' ' || c == '\t';
}

static char *trim_whitespace(char *text)
{
    if (!text)
    {
        return text;
    }
    while (*text && is_space(*text))
    {
        ++text;
    }
    size_t len = strlen(text);
    while (len > 0 && is_space(text[len - 1]))
    {
        text[--len] = '\0';
    }
    return text;
}

static void serial_emit_char(char c)
{
    /* Write directly without log prefix/newline to keep shell output contiguous. */
    serial_output_bytes(&c, 1);
}

static void shell_stream_console_write(void *context, const char *data, size_t len)
{
    (void)context;
    for (size_t i = 0; i < len; ++i)
    {
        char c = data[i];
        console_putc(c);
        serial_emit_char(c);
    }
}

static void cli_render_line(const char *buffer,
                            size_t len,
                            size_t cursor,
                            size_t *rendered_len)
{
    size_t previous_len = rendered_len ? *rendered_len : len;
    size_t prompt_len = sizeof(SHELL_PROMPT) - 1;

    console_write("\r");
    serial_emit_char('\r');
    shell_print_prompt();
    for (size_t i = 0; i < len; ++i)
    {
        char ch = buffer[i];
        console_putc(ch);
        serial_emit_char(ch);
    }

    size_t total_display = prompt_len + len;
    size_t prev_display = prompt_len + previous_len;
    if (prev_display > total_display)
    {
        size_t clear = prev_display - total_display;
        for (size_t i = 0; i < clear; ++i)
        {
            console_putc(' ');
            serial_emit_char(' ');
        }
    }

    console_write("\r");
    serial_emit_char('\r');
    shell_print_prompt();
    size_t target = (cursor < len) ? cursor : len;
    for (size_t i = 0; i < target; ++i)
    {
        char ch = buffer[i];
        console_putc(ch);
        serial_emit_char(ch);
    }

    if (rendered_len)
    {
        *rendered_len = len;
    }
}

static bool cli_replace_token(char *buffer,
                              size_t *len,
                              size_t capacity,
                              size_t token_start,
                              size_t token_len,
                              const char *replacement,
                              size_t replacement_len)
{
    if (!buffer || !len || !replacement)
    {
        return false;
    }
    if (token_start > *len || token_len > (*len - token_start))
    {
        return false;
    }
    size_t tail_len = *len - (token_start + token_len);
    size_t new_len = token_start + replacement_len + tail_len;
    if (new_len >= capacity)
    {
        return false;
    }
    if (tail_len > 0)
    {
        memmove(buffer + token_start + replacement_len,
                buffer + token_start + token_len,
                tail_len);
    }
    memcpy(buffer + token_start, replacement, replacement_len);
    *len = new_len;
    buffer[new_len] = '\0';
    return true;
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
        char **new_items = (char **)realloc(list->items, new_capacity * sizeof(char *));
        if (!new_items)
        {
            free(copy);
            return false;
        }
        list->items = new_items;
        list->capacity = new_capacity;
    }
    list->items[list->count++] = copy;
    return true;
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

static bool shell_collect_command_completions(const char *token,
                                              size_t token_len,
                                              shell_completion_list_t *list)
{
    if (!list)
    {
        return false;
    }
    for (size_t i = 0; i < sizeof(g_commands) / sizeof(g_commands[0]); ++i)
    {
        const char *name = g_commands[i].name;
        if (shell_command_matches(name, token, token_len))
        {
            shell_completion_add(list, name);
        }
    }
    return true;
}

static bool shell_collect_path_completions(shell_state_t *shell,
                                           const char *token,
                                           size_t token_len,
                                           shell_completion_list_t *list)
{
    if (!shell || !list)
    {
        return false;
    }

    char dir_part[256];
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
        return false;
    }

    if (dir_len > 0)
    {
        memcpy(dir_part, token, dir_len);
    }
    dir_part[dir_len] = '\0';
    base = token + dir_len;
    base_len = token_len >= dir_len ? token_len - dir_len : 0;

    vfs_node_t *root_dir = vfs_root();
    vfs_node_t *cwd = shell->cwd ? shell->cwd : root_dir;
    vfs_node_t *target_dir = cwd;
    if (dir_len > 0)
    {
        if (dir_part[0] == '/')
        {
            target_dir = vfs_resolve(root_dir, dir_part);
        }
        else
        {
            target_dir = vfs_resolve(cwd, dir_part);
        }
    }

    if (!target_dir || !vfs_is_dir(target_dir))
    {
        return false;
    }

    for (vfs_node_t *child = vfs_first_child(target_dir); child; child = vfs_next_sibling(child))
    {
        const char *name = vfs_name(child);
        if (!name)
        {
            continue;
        }
        size_t name_len = strlen(name);
        if (base_len > name_len)
        {
            continue;
        }
        if (base_len > 0 && memcmp(name, base, base_len) != 0)
        {
            continue;
        }

        size_t total_len = dir_len + name_len + 1;
        char *candidate = (char *)malloc(total_len + 1);
        if (!candidate)
        {
            continue;
        }

        size_t pos = 0;
        if (dir_len > 0)
        {
            memcpy(candidate, dir_part, dir_len);
            pos += dir_len;
        }
        memcpy(candidate + pos, name, name_len);
        pos += name_len;
        if (vfs_is_dir(child))
        {
            candidate[pos++] = '/';
        }
        candidate[pos] = '\0';
        shell_completion_add(list, candidate);
        free(candidate);
    }
    return true;
}

static size_t shell_completion_common_prefix(shell_completion_list_t *list)
{
    if (!list || list->count == 0)
    {
        return 0;
    }
    size_t prefix = strlen(list->items[0]);
    for (size_t i = 1; i < list->count; ++i)
    {
        const char *item = list->items[i];
        size_t item_len = strlen(item);
        size_t max = prefix < item_len ? prefix : item_len;
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

static void shell_completion_render_options(shell_completion_list_t *list)
{
    if (!list || list->count == 0)
    {
        return;
    }
    console_putc('\n');
    serial_emit_char('\n');
    for (size_t i = 0; i < list->count; ++i)
    {
        const char *item = list->items[i] ? list->items[i] : "";
        console_write(item);
        serial_output_bytes(item, strlen(item));
        if (i + 1 < list->count)
        {
            console_putc(' ');
            serial_emit_char(' ');
        }
    }
    console_putc('\n');
    serial_emit_char('\n');
}

static bool cli_handle_tab(shell_state_t *shell,
                           char *buffer,
                           size_t *len,
                           size_t *cursor,
                           size_t capacity,
                           size_t *rendered_len)
{
    if (!shell || !buffer || !len || !cursor)
    {
        return false;
    }

    size_t cursor_pos = *cursor;
    size_t word_start = cursor_pos;
    while (word_start > 0 && !is_space(buffer[word_start - 1]))
    {
        --word_start;
    }
    size_t token_len = cursor_pos - word_start;
    const char *token = buffer + word_start;

    size_t scan = 0;
    while (scan < word_start && is_space(buffer[scan]))
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
    shell_collect_path_completions(shell, token, token_len, &list);

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
        if (*len + add_len < capacity)
        {
            memmove(buffer + cursor_pos + add_len,
                    buffer + cursor_pos,
                    *len - cursor_pos);
            memcpy(buffer + word_start + token_len, list.items[0] + token_len, add_len);
            *len += add_len;
            cursor_pos += add_len;
            token_len = common;
            buffer[*len] = '\0';
            updated = true;
        }
    }

    if (list.count == 1)
    {
        const char *full = list.items[0];
        size_t full_len = strlen(full);
        if (cli_replace_token(buffer, len, capacity, word_start, token_len, full, full_len))
        {
            cursor_pos = word_start + full_len;
            updated = true;
        }
    }

    if (!updated)
    {
        shell_completion_render_options(&list);
    }

    *cursor = cursor_pos;
    cli_render_line(buffer, *len, *cursor, rendered_len);
    shell_completion_reset(&list);
    return true;
}

static bool cli_line_is_blank(const char *line)
{
    if (!line)
    {
        return true;
    }
    while (*line)
    {
        if (!is_space(*line))
        {
            return false;
        }
        ++line;
    }
    return true;
}

static void cli_history_record(const char *line)
{
    if (cli_line_is_blank(line))
    {
        cli_history_cursor_from_end = 0;
        cli_history_saved_valid = false;
        return;
    }

    char *copy = shell_duplicate_string(line);
    if (!copy)
    {
        return;
    }

    if (cli_history_count < SHELL_HISTORY_LIMIT)
    {
        size_t index = (cli_history_start + cli_history_count) % SHELL_HISTORY_LIMIT;
        cli_history_entries[index] = copy;
        cli_history_count++;
    }
    else
    {
        size_t index = cli_history_start;
        free(cli_history_entries[index]);
        cli_history_entries[index] = copy;
        cli_history_start = (cli_history_start + 1) % SHELL_HISTORY_LIMIT;
    }

    cli_history_cursor_from_end = 0;
    cli_history_saved_valid = false;
}

static void cli_history_save_current(const char *buffer, size_t len)
{
    if (!buffer)
    {
        cli_history_saved_valid = false;
        return;
    }
    if (len >= INPUT_CAPACITY)
    {
        len = INPUT_CAPACITY - 1;
    }
    memcpy(cli_history_saved_line, buffer, len);
    cli_history_saved_line[len] = '\0';
    cli_history_saved_valid = true;
}

static void cli_history_load_text(const char *text,
                                  char *buffer,
                                  size_t *len,
                                  size_t capacity)
{
    if (!buffer || !len || capacity == 0)
    {
        return;
    }

    size_t copy_len = text ? strlen(text) : 0;
    if (copy_len >= capacity)
    {
        copy_len = capacity - 1;
    }
    if (copy_len > 0 && text)
    {
        memcpy(buffer, text, copy_len);
    }
    buffer[copy_len] = '\0';
    *len = copy_len;
}

static void cli_history_load_current(char *buffer, size_t *len, size_t capacity)
{
    if (cli_history_cursor_from_end == 0)
    {
        if (cli_history_saved_valid)
        {
            cli_history_load_text(cli_history_saved_line, buffer, len, capacity);
            cli_history_saved_valid = false;
        }
        else
        {
            cli_history_load_text("", buffer, len, capacity);
        }
        return;
    }

    if (cli_history_count == 0)
    {
        cli_history_load_text("", buffer, len, capacity);
        return;
    }

    size_t offset = cli_history_count - cli_history_cursor_from_end;
    size_t slot = (cli_history_start + offset) % SHELL_HISTORY_LIMIT;
    const char *entry = cli_history_entries[slot];
    cli_history_load_text(entry ? entry : "", buffer, len, capacity);
}

static bool cli_history_show_previous(char *buffer, size_t *len, size_t capacity)
{
    if (!buffer || !len || capacity == 0)
    {
        return true;
    }
    if (cli_history_count == 0)
    {
        return true;
    }
    if (cli_history_cursor_from_end >= cli_history_count)
    {
        return true;
    }
    if (cli_history_cursor_from_end == 0)
    {
        cli_history_save_current(buffer, *len);
    }
    cli_history_cursor_from_end++;
    cli_history_load_current(buffer, len, capacity);
    return true;
}

static bool cli_history_show_next(char *buffer, size_t *len, size_t capacity)
{
    if (!buffer || !len || capacity == 0)
    {
        return true;
    }
    if (cli_history_cursor_from_end == 0)
    {
        return true;
    }
    cli_history_cursor_from_end--;
    cli_history_load_current(buffer, len, capacity);
    return true;
}
