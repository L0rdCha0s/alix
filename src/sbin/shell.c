#include <stddef.h>

#include "shell.h"
#include "shell_commands.h"

#include "console.h"
#include "serial.h"
#include "keyboard.h"
#include "mouse.h"
#include "libc.h"
#include "rtl8139.h"
#include "vfs.h"

#define INPUT_CAPACITY 256

typedef struct
{
    const char *name;
    bool (*handler)(shell_state_t *, shell_output_t *, const char *);
} shell_command_t;

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
    shell_state_t shell = { .cwd = vfs_root() };
    char input[INPUT_CAPACITY];

    console_write("In-memory FS shell ready. Commands: echo, cat, mkdir, ls, ip, ping, nslookup, wget, dhclient, start_video, alloc1m, free.\n");
    serial_write_string("In-memory FS shell ready. Commands: echo, cat, mkdir, ls, ip, ping, nslookup, wget, dhclient, start_video, alloc1m, free.\r\n");

    while (1)
    {
        shell_print_prompt();
        size_t len = cli_read_line(input, INPUT_CAPACITY);
        (void)len;
        shell_run_and_display(&shell, input);
        rtl8139_poll();
    }
}

static const shell_command_t g_commands[] = {
    { "echo",        shell_cmd_echo },
    { "cat",         shell_cmd_cat },
    { "mkdir",       shell_cmd_mkdir },
    { "ls",          shell_cmd_ls },
    { "ip",          shell_cmd_ip },
    { "ping",        shell_cmd_ping },
    { "nslookup",    shell_cmd_nslookup },
    { "wget",        shell_cmd_wget },
    { "dhclient",    shell_cmd_dhclient },
    { "start_video", shell_cmd_start_video },
    { "net_mac",     shell_cmd_net_mac },
    { "alloc1m",     shell_cmd_alloc1m },
    { "free",        shell_cmd_free },
};

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
            handler_result = g_commands[i].handler(shell, &output, args);
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
    while (1)
    {
        char c;
        if (keyboard_try_read(&c))
        {
            return c;
        }
        if (serial_has_char())
        {
            return serial_read_char();
        }
        mouse_poll();
    }
}

static size_t cli_read_line(char *buffer, size_t capacity)
{
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
