#include <stddef.h>
#include "console.h"
#include "serial.h"
#include "libc.h"
#include "keyboard.h"
#include "vfs.h"
#include "types.h"
#include "interrupts.h"
#include "timer.h"
#include "mouse.h"
#include "video.h"
#include "hwinfo.h"
#include "rtl8139.h"

#define INPUT_CAPACITY 256

static void serial_emit_char(char c);

typedef struct
{
    vfs_node_t *cwd;
} shell_state_t;

typedef struct
{
    bool to_file;
    vfs_node_t *file;
} shell_output_t;

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
        /* Drain PS/2 aux (mouse) bytes when IRQs are masked so they
           don't clog the controller's output buffer and block keyboard. */
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

/* Minimal, dependency-free writer to both VGA and serial. Avoids strlen
   or other helpers in case rodata or libc gets upset during bring-up. */
static void write_both(const char *s)
{
    if (!s) { return; }
    for (const char *p = s; *p; ++p)
    {
        console_putc(*p);
        serial_emit_char(*p);
    }
}

static void shell_output_init_console(shell_output_t *out)
{
    out->to_file = false;
    out->file = NULL;
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

static bool shell_output_write_len(shell_output_t *out, const char *text, size_t len)
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

static bool shell_output_write(shell_output_t *out, const char *text)
{
    if (!text)
    {
        text = "";
    }
    return shell_output_write_len(out, text, strlen(text));
}

static void shell_print_error(const char *msg)
{
    write_both("Error: ");
    write_both(msg);
    write_both("\n");
}

static bool shell_cmd_echo(shell_output_t *out, const char *args)
{
    const char *text = (args && *args) ? args : "";
    if (!shell_output_write(out, text) || !shell_output_write(out, "\n"))
    {
        shell_print_error("write failed");
        return false;
    }
    return true;
}

static bool shell_cmd_cat(shell_state_t *shell, shell_output_t *out, const char *path)
{
    vfs_node_t *node = vfs_resolve(shell->cwd, path);
    if (!node)
    {
        shell_print_error("file not found");
        return false;
    }
    if (vfs_is_dir(node))
    {
        shell_print_error("path is a directory");
        return false;
    }

    size_t size = 0;
    const char *data = vfs_data(node, &size);
    if (!data)
    {
        return true;
    }
    if (!shell_output_write_len(out, data, size))
    {
        shell_print_error("write failed");
        return false;
    }
    if (!out->to_file && (size == 0 || data[size - 1] != '\n'))
    {
        shell_output_write(out, "\n");
    }
    return true;
}

static bool shell_cmd_mkdir(shell_state_t *shell, const char *path)
{
    if (!vfs_mkdir(shell->cwd, path))
    {
        shell_print_error("mkdir failed");
        return false;
    }
    return true;
}

static bool shell_cmd_ls(shell_state_t *shell, shell_output_t *out, const char *path)
{
    vfs_node_t *target = NULL;

    serial_write_char('{');
    serial_write_hex64((uint64_t)shell);
    serial_write_char('/');
    serial_write_hex64((uint64_t)shell->cwd);
    serial_write_char('}');

    serial_write_string("Trying path..\n");
    // serial_write_string(path);
    serial_write_string("...");

    if (!path || *path == '\0')
    {
        target = shell->cwd;
    }
    else
    {
        target = vfs_resolve(shell->cwd, path);
    }

    serial_write_string("In shell command ls\n");

    if (!target)
    {
        serial_write_string("Path not found\n");
        shell_print_error("path not found");
        return false;
    }
    if (!vfs_is_dir(target))
    {
        shell_print_error("path is not a directory");
        return false;
    }

    for (vfs_node_t *child = vfs_first_child(target); child; child = vfs_next_sibling(child))
    {
        shell_output_write(out, vfs_name(child));
        if (vfs_is_dir(child))
        {
            shell_output_write(out, "/");
        }
        shell_output_write(out, "\n");
    }
    return true;
}

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

    serial_write_string("Looking for matching command..\n");

    if (strcmp(line, "echo") == 0)
    {
        shell_cmd_echo(&output, args);
    }
    else if (strcmp(line, "cat") == 0)
    {
        if (*args == '\0')
        {
            shell_print_error("cat needs a path");
            return;
        }
        shell_cmd_cat(shell, &output, args);
    }
    else if (strcmp(line, "mkdir") == 0)
    {
        if (*args == '\0')
        {
            shell_print_error("mkdir needs a path");
            return;
        }
        shell_cmd_mkdir(shell, args);
    }
    else if (strcmp(line, "ls") == 0)
    {
        serial_write_string("It's ls!\n");
        shell_cmd_ls(shell, &output, args);
    }
    else if (strcmp(line, "start_video") == 0)
    {
        serial_write_string("Starting video mode...\r\n");
        video_init();
        mouse_register_listener(video_on_mouse_event);
        mouse_init();
        if (video_enter_mode())
        {
            serial_write_string("Video mode active. Double-click to exit.\r\n");
            video_run_loop();
            video_exit_mode();
            console_clear();
        }
        else
        {
            shell_print_error("video init failed");
        }
    }
    else if (strcmp(line, "net_mac") == 0)
    {
        uint8_t mac[6];
        if (!rtl8139_get_mac(mac))
        {
            shell_print_error("network device not present");
            return;
        }
        console_write("rtl8139 mac: ");
        serial_write_string("rtl8139 mac: ");
        for (int i = 0; i < 6; ++i)
        {
            static const char hex[] = "0123456789ABCDEF";
            char bytes[3];
            bytes[0] = hex[(mac[i] >> 4) & 0xF];
            bytes[1] = hex[mac[i] & 0xF];
            bytes[2] = '\0';
            console_write(bytes);
            serial_write_string(bytes);
            if (i != 5)
            {
                console_putc(':');
                serial_write_char(':');
            }
        }
        console_putc('\n');
        serial_write_string("\r\n");
    }
    else
    {
        shell_print_error("unknown command");
    }
}

static void shell_print_prompt(void)
{
    console_write("> ");
    serial_write_string("> ");
}

void kernel_main(void)
{
    serial_init();
    keyboard_init();
    console_init();
    console_clear();
    serial_write_char('k');
    hwinfo_print_boot_summary();
    serial_write_char('h');
    /* Defer video_init until start_video to avoid touching VGA state here */
    serial_write_char('v');
    vfs_init();
    serial_write_char('Q');
    serial_write_hex64((uint64_t)vfs_root());
    serial_write_char('\n');
    serial_write_char('f');
    interrupts_init();
    serial_write_char('I');
    timer_init(100);
    serial_write_char('T');

    /* Network init deferred until after CLI is up */
    rtl8139_init();
    serial_write_char('N');
    /* Defer mouse listener + streaming until graphics mode */
    serial_write_char('m');
    serial_write_char('E'); /* before enabling */
    interrupts_enable();
    serial_write_char('e'); /* after enabling */
    rtl8139_poll();

    console_write("In-memory FS shell ready. Commands: echo, cat, mkdir, ls, start_video.\n");
    serial_write_string("In-memory FS shell ready. Commands: echo, cat, mkdir, ls, start_video.\r\n");
    serial_write_char('S');
    /* Ensure the first prompt is visible even if prior logs scrolled */
    serial_write_string("\r\n> ");

    shell_state_t shell = { .cwd = vfs_root() };
    char input[INPUT_CAPACITY];
    while (1)
    {
        serial_write_char('[');
        serial_write_hex64((uint64_t)&shell);
        serial_write_char('/');
        serial_write_hex64((uint64_t)shell.cwd);
        serial_write_char(']');
        shell_print_prompt();
        size_t len = cli_read_line(input, INPUT_CAPACITY);
        (void)len;
        shell_process_line(&shell, input);
        rtl8139_poll();
    }
}
