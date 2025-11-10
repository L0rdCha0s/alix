#include "startup.h"

#include "console.h"
#include "libc.h"
#include "process.h"
#include "serial.h"
#include "shell.h"
#include "vfs.h"

#define STARTUP_SCRIPT_PATH "/etc/startup.rc"

typedef struct
{
    char **commands;
    size_t count;
} startup_command_list_t;

static void startup_log(const char *message);
static void startup_log_command(const char *command);
static bool startup_ensure_default_script(void);
static void startup_wait_for_environment(void);
static char *startup_trim(char *text);
static bool startup_collect_commands(startup_command_list_t *list);
static void startup_command_list_reset(startup_command_list_t *list);
static void startup_process_entry(void *arg);

void startup_init(void)
{
    /* Defer creation until the filesystem is ready. */
}

bool startup_schedule(void)
{
    process_t *proc = process_create_kernel("startup", startup_process_entry, NULL, 0, -1);
    if (!proc)
    {
        startup_log("failed to schedule startup process");
        return false;
    }
    return true;
}

static void startup_process_entry(void *arg)
{
    (void)arg;

    startup_wait_for_environment();

    startup_command_list_t list = { 0 };
    if (!startup_collect_commands(&list))
    {
        startup_log("failed to load startup script");
        process_exit(1);
    }

    if (list.count == 0)
    {
        startup_log("startup script empty");
        startup_command_list_reset(&list);
        process_exit(0);
    }

    shell_state_t shell = {
        .cwd = vfs_root(),
        .stream_fn = NULL,
        .stream_context = NULL,
        .stdout_fd = process_current_stdout_fd(),
        .foreground_process = NULL,
        .wait_hook = NULL,
        .wait_context = NULL,
        .owner_process = process_current()
    };

    for (size_t i = 0; i < list.count; ++i)
    {
        const char *command = list.commands[i];
        if (!command)
        {
            continue;
        }
        startup_log_command(command);
        bool success = false;
        char *output = shell_execute_line(&shell, command, &success);
        if (output && *output)
        {
            console_write(output);
            serial_write_string(output);
        }
        if (output)
        {
            free(output);
        }
        if (!success)
        {
            startup_log("command failed");
        }
    }

    startup_command_list_reset(&list);
    process_exit(0);
}

static void startup_log(const char *message)
{
    if (!message)
    {
        return;
    }
    console_write("[startup] ");
    console_write(message);
    console_write("\n");

    serial_write_string("[startup] ");
    serial_write_string(message);
    serial_write_string("\r\n");
}

static void startup_log_command(const char *command)
{
    if (!command)
    {
        return;
    }
    console_write("[startup] running ");
    console_write(command);
    console_write("\n");

    serial_write_string("[startup] running ");
    serial_write_string(command);
    serial_write_string("\r\n");
}

static bool startup_ensure_default_script(void)
{
    vfs_node_t *file = vfs_open_file(vfs_root(), STARTUP_SCRIPT_PATH, false, false);
    if (file)
    {
        return true;
    }

    file = vfs_open_file(vfs_root(), STARTUP_SCRIPT_PATH, true, true);
    if (!file)
    {
        return false;
    }

    static const char default_script[] =
        "# AlixOS startup script\n"
        "# Lines that begin with # are treated as comments.\n"
        "\n"
        "dhclient rtl0\n"
        "ntpdate\n";

    if (!vfs_append(file, default_script, sizeof(default_script) - 1))
    {
        return false;
    }
    return true;
}

static char *startup_trim(char *text)
{
    if (!text)
    {
        return text;
    }
    while (*text == ' ' || *text == '\t')
    {
        ++text;
    }
    size_t len = strlen(text);
    while (len > 0 && (text[len - 1] == ' ' || text[len - 1] == '\t'))
    {
        text[--len] = '\0';
    }
    return text;
}

static bool startup_collect_commands(startup_command_list_t *list)
{
    if (!list)
    {
        return false;
    }

    list->commands = NULL;
    list->count = 0;

    vfs_node_t *file = vfs_open_file(vfs_root(), STARTUP_SCRIPT_PATH, false, false);
    if (!file)
    {
        if (!startup_ensure_default_script())
        {
            startup_log("unable to create default startup script");
            return false;
        }
        file = vfs_open_file(vfs_root(), STARTUP_SCRIPT_PATH, false, false);
        if (!file)
        {
            return false;
        }
    }

    size_t size = 0;
    const char *data = vfs_data(file, &size);
    if (!data || size == 0)
    {
        return true;
    }

    char *buffer = (char *)malloc(size + 1);
    if (!buffer)
    {
        return false;
    }
    memcpy(buffer, data, size);
    buffer[size] = '\0';

    char **commands = NULL;
    size_t capacity = 0;
    size_t count = 0;

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

        char *trimmed = startup_trim(line);
        if (*trimmed && trimmed[0] != '#')
        {
            size_t len = strlen(trimmed);
            char *entry = (char *)malloc(len + 1);
            if (!entry)
            {
                free(buffer);
                startup_command_list_reset(&(startup_command_list_t){ .commands = commands, .count = count });
                return false;
            }
            memcpy(entry, trimmed, len + 1);

            if (count >= capacity)
            {
                size_t new_capacity = capacity ? capacity * 2 : 4;
                char **new_commands = (char **)realloc(commands, new_capacity * sizeof(char *));
                if (!new_commands)
                {
                    free(entry);
                    free(buffer);
                    startup_command_list_reset(&(startup_command_list_t){ .commands = commands, .count = count });
                    return false;
                }
                commands = new_commands;
                capacity = new_capacity;
            }

            commands[count++] = entry;
        }

        *cursor = saved;
        while (*cursor == '\n' || *cursor == '\r')
        {
            ++cursor;
        }
    }

    free(buffer);
    list->commands = commands;
    list->count = count;
    return true;
}

static void startup_wait_for_environment(void)
{
    const uint32_t wait_ms = 100;
    const uint32_t max_attempts = 200;
    for (uint32_t attempt = 0; attempt < max_attempts; ++attempt)
    {
        vfs_node_t *etc = vfs_resolve(vfs_root(), "/etc");
        if (etc)
        {
            return;
        }
        process_sleep_ms(wait_ms);
    }
    startup_log("warning: /etc not available, continuing anyway");
}

static void startup_command_list_reset(startup_command_list_t *list)
{
    if (!list)
    {
        return;
    }
    if (list->commands)
    {
        for (size_t i = 0; i < list->count; ++i)
        {
            free(list->commands[i]);
        }
        free(list->commands);
    }
    list->commands = NULL;
    list->count = 0;
}
