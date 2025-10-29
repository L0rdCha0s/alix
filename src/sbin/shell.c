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
static void shell_process_line(shell_state_t *shell, char *buffer);

void shell_output_init_console(shell_output_t *out)
{
    out->to_file = false;
    out->file = NULL;
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

    for (size_t i = 0; i < len; ++i)
    {
        char c = text[i];
        console_putc(c);
        serial_emit_char(c);
    }
    return true;
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

void shell_main(void)
{
    shell_state_t shell = { .cwd = vfs_root() };
    char input[INPUT_CAPACITY];

    console_write("In-memory FS shell ready. Commands: echo, cat, mkdir, ls, ip, ping, dhclient, start_video.\n");
    serial_write_string("In-memory FS shell ready. Commands: echo, cat, mkdir, ls, ip, ping, dhclient, start_video.\r\n");

    while (1)
    {
        shell_print_prompt();
        size_t len = cli_read_line(input, INPUT_CAPACITY);
        (void)len;
        shell_process_line(&shell, input);
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
    { "dhclient",    shell_cmd_dhclient },
    { "start_video", shell_cmd_start_video },
    { "net_mac",     shell_cmd_net_mac },
};

static void shell_process_line(shell_state_t *shell, char *buffer)
{
    char *line = trim_whitespace(buffer);
    if (*line == '\0')
    {
        return;
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
            shell_print_error("redirect target missing");
            return;
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
    shell_output_init_console(&output);

    if (redirect_path)
    {
        if (!shell_output_redirect(&output, shell, redirect_path))
        {
            shell_print_error("redirect failed");
            return;
        }
    }

    for (size_t i = 0; i < sizeof(g_commands) / sizeof(g_commands[0]); ++i)
    {
        if (strcmp(line, g_commands[i].name) == 0)
        {
            g_commands[i].handler(shell, &output, args);
            return;
        }
    }

    shell_print_error("unknown command");
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
    out->to_file = true;
    out->file = file;
    return true;
}

static void shell_print_prompt(void)
{
    console_write("> ");
    serial_write_string("> ");
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
