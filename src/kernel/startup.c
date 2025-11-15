#include "startup.h"
#include "build_features.h"

#include "console.h"
#include "libc.h"
#include "process.h"
#include "serial.h"
#include "shell.h"
#include "vfs.h"
#include "net/dhcp.h"
#include "net/interface.h"

#define STARTUP_SCRIPT_PATH "/etc/startup.rc"

#if ENABLE_STARTUP_SCRIPT
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
static void startup_wait_for_command_completion(const char *line);
static void startup_wait_for_dhclient(const char *args);
static void startup_log_with_iface(const char *prefix, const char *iface);
static const char *startup_skip_spaces(const char *text);
#define STARTUP_WAIT_INTERVAL_MS 100U
#define STARTUP_WAIT_MAX_MS      10000U
#endif

void startup_init(void)
{
    /* Defer creation until the filesystem is ready. */
}

bool startup_schedule(void)
{
#if ENABLE_STARTUP_SCRIPT
    process_t *startup_process = process_create_kernel("startup",
                                                       startup_process_entry,
                                                       NULL,
                                                       0,
                                                       -1);
    if (!startup_process)
    {
        startup_log("failed to create startup process");
        return false;
    }
    return true;
#else
    return true;
#endif
}

#if ENABLE_STARTUP_SCRIPT
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
        .owner_process = process_current(),
        .cwd_changed_fn = NULL,
        .cwd_changed_context = NULL
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
            serial_printf("%s", output);
        }
        if (output)
        {
            free(output);
        }
        if (!success)
        {
            startup_log("command failed");
        }
        else
        {
            startup_wait_for_command_completion(command);
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

    serial_printf("%s", "[startup] ");
    serial_printf("%s", message);
    serial_printf("%s", "\r\n");
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

    serial_printf("%s", "[startup] running ");
    serial_printf("%s", command);
    serial_printf("%s", "\r\n");
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
        "ntpdate pool.ntp.org\n";

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

static void startup_wait_for_command_completion(const char *line)
{
    if (!line || *line == '\0')
    {
        return;
    }

    char command[32];
    size_t cmd_len = 0;
    const char *cursor = line;
    cursor = startup_skip_spaces(cursor);
    while (*cursor && *cursor != ' ' && *cursor != '\t')
    {
        if (cmd_len + 1 >= sizeof(command))
        {
            break;
        }
        command[cmd_len++] = *cursor++;
    }
    command[cmd_len] = '\0';

    const char *args = startup_skip_spaces(cursor);

    if (strcmp(command, "dhclient") == 0)
    {
        startup_wait_for_dhclient(args);
    }
}

static void startup_wait_for_dhclient(const char *args)
{
    const char *iface_text = startup_skip_spaces(args);
    if (!iface_text || *iface_text == '\0')
    {
        return;
    }

    char name[NET_IF_NAME_MAX];
    size_t len = 0;
    while (iface_text[len] && iface_text[len] != ' ' && iface_text[len] != '\t')
    {
        if (len + 1 >= sizeof(name))
        {
            break;
        }
        name[len] = iface_text[len];
        ++len;
    }
    name[len] = '\0';

    if (name[0] == '\0')
    {
        return;
    }

    net_interface_t *iface = net_if_by_name(name);
    if (!iface)
    {
        startup_log("dhclient wait skipped (interface not found)");
        return;
    }

    startup_log_with_iface("waiting for dhclient on ", name);

    uint32_t waited = 0;
    while (waited < STARTUP_WAIT_MAX_MS)
    {
        if (iface->ipv4_addr != 0)
        {
            startup_log_with_iface("dhclient lease acquired on ", name);
            return;
        }
        if (!net_dhcp_in_progress())
        {
            break;
        }
        process_sleep_ms(STARTUP_WAIT_INTERVAL_MS);
        waited += STARTUP_WAIT_INTERVAL_MS;
    }

    if (iface->ipv4_addr != 0)
    {
        startup_log_with_iface("dhclient lease acquired on ", name);
    }
    else
    {
        startup_log_with_iface("dhclient timed out on ", name);
    }
}

static void startup_log_with_iface(const char *prefix, const char *iface)
{
    if (!prefix)
    {
        prefix = "";
    }
    if (!iface)
    {
        iface = "";
    }
    char message[64];
    size_t prefix_len = strlen(prefix);
    if (prefix_len >= sizeof(message))
    {
        prefix_len = sizeof(message) - 1;
    }
    memcpy(message, prefix, prefix_len);
    size_t remaining = (prefix_len < sizeof(message)) ? (sizeof(message) - prefix_len - 1) : 0;
    size_t iface_len = strlen(iface);
    if (iface_len > remaining)
    {
        iface_len = remaining;
    }
    memcpy(message + prefix_len, iface, iface_len);
    message[prefix_len + iface_len] = '\0';
    startup_log(message);
}

static const char *startup_skip_spaces(const char *text)
{
    if (!text)
    {
        return "";
    }
    while (*text == ' ' || *text == '\t')
    {
        ++text;
    }
    return text;
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

#endif /* ENABLE_STARTUP_SCRIPT */
