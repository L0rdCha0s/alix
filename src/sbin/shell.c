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
    bool (*handler)(shell_state_t *, shell_output_t *, const char *);
    bool result;
} shell_command_task_t;

static char cli_get_char(void);
static size_t cli_read_line(char *buffer, size_t capacity);
static bool is_space(char c);
static char *trim_whitespace(char *text);
static void serial_emit_char(char c);
static bool shell_output_redirect(shell_output_t *out, shell_state_t *shell, const char *path);
static void shell_print_prompt(void);
static void shell_run_and_display(shell_state_t *shell, const char *input);
static char *shell_duplicate_empty(void);
static char *shell_duplicate_string(const char *text);
static void shell_command_runner(void *arg);
static void shell_stream_console_write(void *context, const char *data, size_t len);

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

void shell_main(void)
{
    shell_state_t shell = {
        .cwd = vfs_root(),
        .stream_fn = shell_stream_console_write,
        .stream_context = NULL,
        .stdout_fd = process_current_stdout_fd(),
        .foreground_process = NULL,
        .wait_hook = NULL,
        .wait_context = NULL,
        .owner_process = process_current()
    };
    char input[INPUT_CAPACITY];

    console_write("In-memory FS shell ready. Commands: echo, cat, mkdir, mkfs, mount, shutdown, ls, ip, ping, nslookup, wget, imgview, logcat, sha1sum, dhclient, start_video, net_mac, alloc1m, free, loop1, loop2, top, userdemo, userdemo2, useratk, runelf.\n");
    serial_write_string("In-memory FS shell ready. Commands: echo, cat, mkdir, mkfs, mount, shutdown, ls, ip, ping, nslookup, wget, imgview, logcat, sha1sum, dhclient, start_video, net_mac, alloc1m, free, loop1, loop2, top, userdemo, userdemo2, useratk, runelf.\r\n");

    while (1)
    {
        shell_print_prompt();
        size_t len = cli_read_line(input, INPUT_CAPACITY);
        (void)len;
        shell_run_and_display(&shell, input);
    }
}

static const shell_command_t g_commands[] = {
    { "echo",        shell_cmd_echo },
    { "cat",         shell_cmd_cat },
    { "mkdir",       shell_cmd_mkdir },
    { "mkfs",        shell_cmd_mkfs },
    { "mount",       shell_cmd_mount },
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
    { "alloc1m",     shell_cmd_alloc1m },
    { "free",        shell_cmd_free },
    { "loop1",       shell_cmd_loop1 },
    { "loop2",       shell_cmd_loop2 },
    { "top",         shell_cmd_top },
    { "userdemo",    shell_cmd_userdemo },
    { "userdemo2",   shell_cmd_userdemo2 },
    { "useratk",     shell_cmd_useratk },
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

    for (char *p = line; *p; ++p)
    {
        if (*p >= 'A' && *p <= 'Z')
        {
            *p = (char)(*p + ('a' - 'A'));
        }
    }

    shell_output_t output;
    if (redirect_path)
    {
        shell_output_init_buffer(&output);
        if (!shell_output_redirect(&output, shell, redirect_path))
        {
            shell_output_reset(&output);
            free(working);
            return shell_duplicate_string("Error: redirect failed\n");
        }
    }
    else
    {
        shell_output_init_buffer(&output);
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
            task->output = &output;
            task->args = args;
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
        result = shell_duplicate_string("Error: unknown command\n");
        handler_result = false;
    }
    else if (redirect_path)
    {
        result = shell_duplicate_empty();
    }
    else
    {
        result = shell_output_take_buffer(&output);
    }

    shell_output_reset(&output);
    free(working);

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
        serial_write_string(result);
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
    serial_write_string("alex@alix$ ");
}

static char cli_get_char(void)
{
    //serial_write_string("In cli_get_char\n");

    while (1)
    {
        char c;
        if (keyboard_try_read(&c))
        {
            //serial_write_string("shell.c: keyboard_try_read has char\n");

            return c;
        }
        if (serial_has_char())
        {
            //serial_write_string("shell.c: serial_has_char has char\n");

            return serial_read_char();
        }

        mouse_poll();
    }
}

static size_t cli_read_line(char *buffer, size_t capacity)
{
    //serial_write_string("shell.c: cli_read_line in\n");
    
    size_t len = 0;
    while (1)
    {
        char c = cli_get_char();

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
                serial_write_string("\b \b");
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
            serial_write_char(c);
        }
    }

    //serial_write_string("shell.c: cli_read_line out\n");
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
    if (c == '\n')
    {
        serial_write_char('\r');
    }
    serial_write_char(c);
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
