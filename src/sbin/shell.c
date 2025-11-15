#include "shell.h"
#include "shell_commands.h"

#include "console.h"
#include "serial.h"
#include "keyboard.h"
#include "mouse.h"
#include "libc.h"
#include "process.h"
#include "vfs.h"

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
static size_t cli_read_line(char *buffer, size_t capacity);
static bool cli_handle_escape_sequence(char *buffer, size_t *len, size_t capacity);
static bool cli_wait_for_char(char *out, int attempts);
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

void shell_output_init_console(shell_output_t *out)
{
    out->to_file = false;
    out->file = NULL;
    out->to_buffer = false;
    out->buffer = NULL;
    out->length = 0;
    out->capacity = 0;
}

void shell_output_init_buffer(shell_output_t *out)
{
    out->to_file = false;
    out->file = NULL;
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

    if (out->to_file)
    {
        return vfs_append(out->file, text, len);
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

    process_t *proc = shell->foreground_process;
    if (!proc)
    {
        return false;
    }

    return process_kill(proc, -1);
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
    const char *data = vfs_data(node, &size);
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
    shell->foreground_process = NULL;
    shell->wait_hook = NULL;
    shell->wait_context = NULL;
    shell->owner_process = process_current();
    shell->cwd_changed_fn = NULL;
    shell->cwd_changed_context = NULL;
    char input[INPUT_CAPACITY];

    console_write("In-memory FS shell ready. Commands: echo, cat, mkdir, cd, rm, mkfs, mount, tzset, tzstatus, tzsync, ntpdate, shutdown, ls, ip, ping, nslookup, wget, imgview, logcat, sha1sum, dhclient, start_video, net_mac, dnsdebug, alloc1m, free, loop1, loop2, letters, top, useratk, atkshell, taskmgr, wolf3d, doom, runelf, or ./path for binaries.\n");
    serial_printf("%s", "In-memory FS shell ready. Commands: echo, cat, mkdir, cd, rm, mkfs, mount, tzset, tzstatus, tzsync, ntpdate, shutdown, ls, ip, ping, nslookup, wget, imgview, logcat, sha1sum, dhclient, start_video, net_mac, dnsdebug, alloc1m, free, loop1, loop2, letters, top, useratk, atkshell, taskmgr, wolf3d, doom, runelf, or ./path for binaries.\r\n");

    while (1)
    {
        shell_print_prompt();
        size_t len = cli_read_line(input, INPUT_CAPACITY);
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
    { "doom",        shell_cmd_doom },
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

    size_t input_len = strlen(input);
    char *working = (char *)malloc(input_len + 1);
    if (!working)
    {
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
                shell->foreground_process = proc;
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

            if (shell && shell->foreground_process == proc)
            {
                shell->foreground_process = NULL;
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
                                shell->foreground_process = proc;
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
                            if (shell && shell->foreground_process == proc)
                            {
                                shell->foreground_process = NULL;
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
    if (result && *result)
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
    console_write("alex@alix$ ");
    serial_printf("%s", "alex@alix$ ");
}

static bool cli_try_read_char(char *out)
{
    if (!out)
    {
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

static size_t cli_read_line(char *buffer, size_t capacity)
{
    //serial_write_string("shell.c: cli_read_line in\n");
    
    size_t len = 0;
    while (1)
    {
        char c = cli_get_char();

        if (c == 0x1B)
        {
            if (cli_handle_escape_sequence(buffer, &len, capacity))
            {
                continue;
            }
        }

        if (c == '\r')
        {
            c = '\n';
        }

        if ((c == '\b' || c == 0x7F))
        {
            if (len > 0)
            {
                --len;
                console_backspace();
                serial_printf("%s", "\b \b");
            }
            continue;
        }

        if (c == '\n')
        {
            console_putc('\n');
            serial_emit_char('\n');
            buffer[len] = '\0';
            return len;
        }

        if (c >= ' ' && len < capacity - 1)
        {
            buffer[len++] = c;
            console_putc(c);
            serial_printf("%c", c);
        }
    }

    //serial_write_string("shell.c: cli_read_line out\n");
}

static bool cli_handle_escape_sequence(char *buffer, size_t *len, size_t capacity)
{
    (void)capacity;
    if (!buffer || !len)
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
            cli_history_show_previous(buffer, len, capacity);
            break;
        case 'B':
            cli_history_show_next(buffer, len, capacity);
            break;
        default:
            break;
    }
    return true;
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
    serial_printf("%c", c);
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

    while (*len > 0)
    {
        --(*len);
        console_backspace();
        serial_printf("%s", "\b \b");
    }

    size_t copy_len = 0;
    if (text)
    {
        copy_len = strlen(text);
    }
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

    for (size_t i = 0; i < copy_len; ++i)
    {
        char ch = buffer[i];
        console_putc(ch);
        serial_printf("%c", ch);
    }
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
