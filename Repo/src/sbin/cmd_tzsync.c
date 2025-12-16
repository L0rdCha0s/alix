#include "shell_commands.h"

#include "libc.h"
#include "net/interface.h"
#include "shell.h"
#include "timekeeping.h"
#include "timezone_paths.h"
#include "vfs.h"

#define TZSYNC_TZDATA_URL          "https://data.iana.org/time-zones/tzdata.zi"
#define TZSYNC_ZONE1970_URL        "https://data.iana.org/time-zones/zone1970.tab"
#define TZSYNC_RELEASE_URL_PREFIX  "https://data.iana.org/time-zones/releases/"
#define TZSYNC_VERSION_MAX         64

typedef struct
{
    char iface[NET_IF_NAME_MAX];
    char release[TZSYNC_VERSION_MAX];
    bool has_iface;
    bool has_release;
} tzsync_options_t;

static void tzsync_copy_string(char *dest, size_t capacity, const char *src);
static const char *tzsync_last_slash(const char *text);
static bool tzsync_append(char *dest, size_t capacity, const char *text);
static size_t tzsync_format_unsigned(char *buffer, size_t capacity, size_t value);
static bool tzsync_write_kv_line(vfs_node_t *file, const char *key, const char *value);

static const char *tzsync_skip_ws(const char *cursor)
{
    while (cursor && (*cursor == ' ' || *cursor == '\t'))
    {
        ++cursor;
    }
    return cursor;
}

static bool tzsync_next_token(const char **cursor, char *out, size_t capacity)
{
    if (!cursor || !*cursor || !out || capacity == 0)
    {
        return false;
    }
    const char *pos = tzsync_skip_ws(*cursor);
    if (*pos == '\0')
    {
        *cursor = pos;
        return false;
    }
    size_t len = 0;
    while (pos[len] && pos[len] != ' ' && pos[len] != '\t')
    {
        if (len + 1 >= capacity)
        {
            return false;
        }
        out[len] = pos[len];
        ++len;
    }
    out[len] = '\0';
    *cursor = tzsync_skip_ws(pos + len);
    return true;
}

static void tzsync_copy_string(char *dest, size_t capacity, const char *src)
{
    if (!dest || capacity == 0)
    {
        return;
    }
    if (!src)
    {
        dest[0] = '\0';
        return;
    }
    size_t len = strlen(src);
    if (len >= capacity)
    {
        len = capacity - 1;
    }
    memcpy(dest, src, len);
    dest[len] = '\0';
}

static const char *tzsync_last_slash(const char *text)
{
    const char *last = NULL;
    while (text && *text)
    {
        if (*text == '/')
        {
            last = text;
        }
        ++text;
    }
    return last;
}

static bool tzsync_append(char *dest, size_t capacity, const char *text)
{
    if (!dest || !text)
    {
        return false;
    }
    size_t len = strlen(dest);
    size_t text_len = strlen(text);
    if (len + text_len >= capacity)
    {
        return false;
    }
    memcpy(dest + len, text, text_len + 1);
    return true;
}

static size_t tzsync_format_unsigned(char *buffer, size_t capacity, size_t value)
{
    if (!buffer || capacity == 0)
    {
        return 0;
    }
    char tmp[32];
    size_t len = 0;
    if (value == 0)
    {
        tmp[len++] = '0';
    }
    else
    {
        while (value > 0 && len < sizeof(tmp))
        {
            tmp[len++] = (char)('0' + (value % 10));
            value /= 10;
        }
    }
    if (len + 1 > capacity)
    {
        return 0;
    }
    size_t pos = 0;
    while (len > 0)
    {
        buffer[pos++] = tmp[--len];
    }
    buffer[pos] = '\0';
    return pos;
}

static bool tzsync_write_kv_line(vfs_node_t *file, const char *key, const char *value)
{
    if (!file || !key || !value)
    {
        return false;
    }
    char line[160];
    size_t key_len = strlen(key);
    size_t value_len = strlen(value);
    if (key_len + value_len + 2 >= sizeof(line))
    {
        return false;
    }
    memcpy(line, key, key_len);
    line[key_len] = '=';
    memcpy(line + key_len + 1, value, value_len);
    line[key_len + 1 + value_len] = '\n';
    return vfs_append(file, line, key_len + value_len + 2);
}

static bool tzsync_mkdir_recursive(const char *path)
{
    if (!path || path[0] != '/')
    {
        return false;
    }
    if (path[1] == '\0')
    {
        return true;
    }

    char partial[256];
    size_t partial_len = 0;
    memset(partial, 0, sizeof(partial));

    const char *cursor = path;
    while (*cursor == '/')
    {
        cursor++;
    }
    partial[partial_len++] = '/';
    partial[partial_len] = '\0';

    while (*cursor)
    {
        const char *start = cursor;
        while (*cursor && *cursor != '/')
        {
            cursor++;
        }
        size_t comp_len = (size_t)(cursor - start);
        if (comp_len == 0)
        {
            while (*cursor == '/')
            {
                cursor++;
            }
            continue;
        }

        if (partial_len > 1)
        {
            if (partial_len + 1 >= sizeof(partial))
            {
                return false;
            }
            partial[partial_len++] = '/';
            partial[partial_len] = '\0';
        }

        if (partial_len + comp_len >= sizeof(partial))
        {
            return false;
        }
        memcpy(partial + partial_len, start, comp_len);
        partial_len += comp_len;
        partial[partial_len] = '\0';

        vfs_node_t *dir = vfs_resolve(vfs_root(), partial);
        if (!dir)
        {
            dir = vfs_mkdir(vfs_root(), partial);
        }
        if (!dir)
        {
            return false;
        }

        while (*cursor == '/')
        {
            cursor++;
        }
    }
    return true;
}

static bool tzsync_run_wget(shell_state_t *shell,
                            shell_output_t *out,
                            const char *iface,
                            const char *url,
                            const char *dest_path)
{
    if (!shell || !out || !url || !dest_path)
    {
        return false;
    }
    char args[768];
    args[0] = '\0';
    if (iface && *iface)
    {
        tzsync_append(args, sizeof(args), iface);
        tzsync_append(args, sizeof(args), " ");
    }
    tzsync_append(args, sizeof(args), url);
    tzsync_append(args, sizeof(args), " ");
    tzsync_append(args, sizeof(args), dest_path);
    return shell_cmd_wget(shell, out, args);
}

static bool tzsync_detect_version(const char *tzdata_path, char *buffer, size_t capacity)
{
    if (!tzdata_path || !buffer || capacity == 0)
    {
        return false;
    }
    vfs_node_t *file = vfs_open_file(vfs_root(), tzdata_path, false, false);
    if (!file)
    {
        return false;
    }
    size_t size = 0;
    char *data = vfs_data(file, &size);
    if (!data || size == 0)
    {
        return false;
    }

    const char *cursor = data;
    const char *end = data + size;
    while (cursor < end)
    {
        const char *line_end = cursor;
        while (line_end < end && *line_end != '\n' && *line_end != '\r')
        {
            line_end++;
        }
        size_t line_len = (size_t)(line_end - cursor);
        if (line_len > 10 && strncmp(cursor, "# version ", 10) == 0)
        {
            size_t copy_len = line_len - 10;
            if (copy_len >= capacity)
            {
                copy_len = capacity - 1;
            }
            memcpy(buffer, cursor + 10, copy_len);
            buffer[copy_len] = '\0';
            return true;
        }
        cursor = line_end;
        while (cursor < end && (*cursor == '\n' || *cursor == '\r'))
        {
            cursor++;
        }
    }
    return false;
}

static bool tzsync_write_manifest(const char *version,
                                  size_t tzdata_size,
                                  size_t zone_tab_size)
{
    vfs_node_t *file = vfs_open_file(vfs_root(), TZDB_MANIFEST_PATH, true, true);
    if (!file)
    {
        return false;
    }
    vfs_truncate(file);

    char number[32];
    if (!tzsync_write_kv_line(file, "version", version ? version : "unknown"))
    {
        return false;
    }
    if (tzsync_format_unsigned(number, sizeof(number), tzdata_size) == 0)
    {
        return false;
    }
    if (!tzsync_write_kv_line(file, "tzdata_size", number))
    {
        return false;
    }
    if (tzsync_format_unsigned(number, sizeof(number), zone_tab_size) == 0)
    {
        return false;
    }
    if (!tzsync_write_kv_line(file, "zone1970_size", number))
    {
        return false;
    }

    uint64_t timestamp = timekeeping_now_seconds();
    if (tzsync_format_unsigned(number, sizeof(number), (size_t)timestamp) == 0)
    {
        return false;
    }
    return tzsync_write_kv_line(file, "downloaded_at", number);
}

static bool tzsync_parse_args(const char *args, tzsync_options_t *opts)
{
    if (!opts)
    {
        return false;
    }
    memset(opts, 0, sizeof(*opts));

    const char *cursor = args ? args : "";
    char token[128];

    while (tzsync_next_token(&cursor, token, sizeof(token)))
    {
        if (strncmp(token, "--iface=", 8) == 0)
        {
            tzsync_copy_string(opts->iface, sizeof(opts->iface), token + 8);
            opts->has_iface = true;
        }
        else if (strcmp(token, "--iface") == 0)
        {
            if (!tzsync_next_token(&cursor, opts->iface, sizeof(opts->iface)))
            {
                return false;
            }
            opts->has_iface = true;
        }
        else if (strncmp(token, "--release=", 10) == 0)
        {
            tzsync_copy_string(opts->release, sizeof(opts->release), token + 10);
            opts->has_release = true;
        }
        else if (strcmp(token, "--release") == 0)
        {
            if (!tzsync_next_token(&cursor, opts->release, sizeof(opts->release)))
            {
                return false;
            }
            opts->has_release = true;
        }
        else
        {
            net_interface_t *iface = net_if_by_name(token);
            if (iface)
            {
                tzsync_copy_string(opts->iface, sizeof(opts->iface), iface->name);
                opts->has_iface = true;
            }
            else if (!opts->has_release)
            {
                tzsync_copy_string(opts->release, sizeof(opts->release), token);
                opts->has_release = true;
            }
            else
            {
                return false;
            }
        }
    }

    return true;
}

static const char *tzsync_select_url(const char *release,
                                     bool has_release,
                                     const char *base_suffix,
                                     char *buffer,
                                     size_t capacity)
{
    if (!has_release || !release || release[0] == '\0' || strcmp(release, "latest") == 0)
    {
        return base_suffix;
    }

    const char *file_name = tzsync_last_slash(base_suffix);
    if (!file_name || file_name[1] == '\0')
    {
        return NULL;
    }
    file_name++; // skip '/'

    buffer[0] = '\0';
    if (!tzsync_append(buffer, capacity, TZSYNC_RELEASE_URL_PREFIX))
    {
        return NULL;
    }
    if (!tzsync_append(buffer, capacity, release))
    {
        return NULL;
    }
    if (!tzsync_append(buffer, capacity, "/"))
    {
        return NULL;
    }
    if (!tzsync_append(buffer, capacity, file_name))
    {
        return NULL;
    }
    return buffer;
}

bool shell_cmd_tzsync(shell_state_t *shell, shell_output_t *out, const char *args)
{
    if (!shell || !out)
    {
        return false;
    }

    tzsync_options_t options;
    if (!tzsync_parse_args(args, &options))
    {
        return shell_output_error(out, "Usage: tzsync [--iface NAME] [--release VERSION]");
    }

    static const char *dirs_to_ensure[] = {
        "/usr",
        "/usr/share",
        "/usr/share/zoneinfo",
        TZDB_SOURCE_DIR
    };
    for (size_t i = 0; i < sizeof(dirs_to_ensure) / sizeof(dirs_to_ensure[0]); ++i)
    {
        if (!tzsync_mkdir_recursive(dirs_to_ensure[i]))
        {
            return shell_output_error(out, "failed to prepare zoneinfo directories");
        }
    }

    char tzdata_url[256];
    char zone1970_url[256];
    const char *release_value = options.has_release ? options.release : NULL;
    const char *tzdata_src = tzsync_select_url(release_value, options.has_release, TZSYNC_TZDATA_URL, tzdata_url, sizeof(tzdata_url));
    const char *zone1970_src = tzsync_select_url(release_value, options.has_release, TZSYNC_ZONE1970_URL, zone1970_url, sizeof(zone1970_url));
    if (!tzdata_src || !zone1970_src)
    {
        return shell_output_error(out, "invalid release argument");
    }

    shell_output_write(out, "Downloading tzdata...\n");
    const char *iface_arg = options.has_iface ? options.iface : NULL;

    if (!tzsync_run_wget(shell, out, iface_arg, tzdata_src, TZDB_TZDATA_PATH))
    {
        return false;
    }

    shell_output_write(out, "Downloading zone tab...\n");
    if (!tzsync_run_wget(shell, out, iface_arg, zone1970_src, TZDB_ZONE1970_PATH))
    {
        return false;
    }

    vfs_node_t *tzdata_file = vfs_open_file(vfs_root(), TZDB_TZDATA_PATH, false, false);
    vfs_node_t *zone_file = vfs_open_file(vfs_root(), TZDB_ZONE1970_PATH, false, false);
    if (!tzdata_file || !zone_file)
    {
        return shell_output_error(out, "failed to access downloaded files");
    }

    size_t tzdata_size = 0;
    size_t zone_tab_size = 0;
    (void)vfs_data(tzdata_file, &tzdata_size);
    (void)vfs_data(zone_file, &zone_tab_size);

    char version[TZSYNC_VERSION_MAX] = { 0 };
    if (!tzsync_detect_version(TZDB_TZDATA_PATH, version, sizeof(version)))
    {
        const char *fallback = options.has_release ? options.release : "unknown";
        tzsync_copy_string(version, sizeof(version), fallback);
    }

    if (!tzsync_write_manifest(version, tzdata_size, zone_tab_size))
    {
        return shell_output_error(out, "failed to write manifest");
    }

    shell_output_write(out, "tzsync complete.\n");
    shell_output_write(out, "Current tzdata version: ");
    shell_output_write(out, version);
    shell_output_write(out, "\n");
    return true;
}
