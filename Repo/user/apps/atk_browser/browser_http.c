#include "browser_internal.h"

#include "crypto/sha1.h"
#include "net/tls.h"
#include "usyscall.h"
#include "unistd.h"

#include "stdio.h"
#include "string.h"

#define BROWSER_MAX_PASSWD_BYTES (64u * 1024u)
#define BROWSER_CACHE_MAX_AGE_DEFAULT_SECONDS 7200u
#define BROWSER_CACHE_MAX_AGE_LONG_SECONDS (48u * 60u * 60u)
#define BROWSER_CACHE_META_MAX_BYTES 64u

typedef enum
{
    BROWSER_READ_STATUS_OK = 0,
    BROWSER_READ_STATUS_INVALID,
    BROWSER_READ_STATUS_OPEN,
    BROWSER_READ_STATUS_STAT,
    BROWSER_READ_STATUS_EMPTY,
    BROWSER_READ_STATUS_TOO_LARGE,
    BROWSER_READ_STATUS_ALLOC,
    BROWSER_READ_STATUS_READ
} browser_read_status_t;

typedef enum
{
    BROWSER_CACHE_STATE_MISS = 0,
    BROWSER_CACHE_STATE_HIT,
    BROWSER_CACHE_STATE_STALE
} browser_cache_state_t;

static bool browser_parse_u32_range(const char *start, const char *end, uint32_t *out)
{
    if (!start || !end || !out || start >= end)
    {
        return false;
    }
    uint32_t value = 0;
    for (const char *cur = start; cur < end; ++cur)
    {
        if (*cur < '0' || *cur > '9')
        {
            return false;
        }
        uint32_t digit = (uint32_t)(*cur - '0');
        uint32_t next = value * 10u + digit;
        if (next < value)
        {
            return false;
        }
        value = next;
    }
    *out = value;
    return true;
}

static bool browser_parse_u64_range(const char *start, const char *end, uint64_t *out)
{
    if (!start || !end || !out || start >= end)
    {
        return false;
    }
    uint64_t value = 0;
    for (const char *cur = start; cur < end; ++cur)
    {
        if (*cur < '0' || *cur > '9')
        {
            return false;
        }
        uint64_t digit = (uint64_t)(*cur - '0');
        if (value > (((uint64_t)-1 - digit) / 10u))
        {
            return false;
        }
        value = value * 10u + digit;
    }
    *out = value;
    return true;
}

static char browser_ascii_lower(char c)
{
    if (c >= 'A' && c <= 'Z')
    {
        return (char)(c + ('a' - 'A'));
    }
    return c;
}

static const char *browser_url_find_extension(const char *uri, size_t *ext_len_out)
{
    if (ext_len_out)
    {
        *ext_len_out = 0;
    }
    if (!uri)
    {
        return NULL;
    }
    const char *end = uri + strlen(uri);
    for (const char *p = uri; *p; ++p)
    {
        if (*p == '?' || *p == '#')
        {
            end = p;
            break;
        }
    }
    const char *last_slash = NULL;
    const char *last_dot = NULL;
    for (const char *p = uri; p < end; ++p)
    {
        if (*p == '/')
        {
            last_slash = p;
        }
        else if (*p == '.')
        {
            last_dot = p;
        }
    }
    if (!last_dot || (last_slash && last_dot < last_slash) || last_dot + 1 >= end)
    {
        return NULL;
    }
    if (ext_len_out)
    {
        *ext_len_out = (size_t)(end - (last_dot + 1));
    }
    return last_dot + 1;
}

static bool browser_extension_matches(const char *ext, size_t ext_len, const char *match)
{
    if (!ext || !match)
    {
        return false;
    }
    size_t match_len = strlen(match);
    if (ext_len != match_len)
    {
        return false;
    }
    for (size_t i = 0; i < ext_len; ++i)
    {
        if (browser_ascii_lower(ext[i]) != browser_ascii_lower(match[i]))
        {
            return false;
        }
    }
    return true;
}

static uint32_t browser_cache_max_age_for_uri(const char *uri)
{
    size_t ext_len = 0;
    const char *ext = browser_url_find_extension(uri, &ext_len);
    if (!ext || ext_len == 0)
    {
        return BROWSER_CACHE_MAX_AGE_DEFAULT_SECONDS;
    }
    if (browser_extension_matches(ext, ext_len, "css"))
    {
        return BROWSER_CACHE_MAX_AGE_LONG_SECONDS;
    }
    if (browser_extension_matches(ext, ext_len, "png") ||
        browser_extension_matches(ext, ext_len, "jpg") ||
        browser_extension_matches(ext, ext_len, "jpeg") ||
        browser_extension_matches(ext, ext_len, "gif") ||
        browser_extension_matches(ext, ext_len, "svg") ||
        browser_extension_matches(ext, ext_len, "webp") ||
        browser_extension_matches(ext, ext_len, "bmp") ||
        browser_extension_matches(ext, ext_len, "ico") ||
        browser_extension_matches(ext, ext_len, "tif") ||
        browser_extension_matches(ext, ext_len, "tiff") ||
        browser_extension_matches(ext, ext_len, "avif"))
    {
        return BROWSER_CACHE_MAX_AGE_LONG_SECONDS;
    }
    return BROWSER_CACHE_MAX_AGE_DEFAULT_SECONDS;
}

static bool browser_cache_expired(uint64_t mtime_seconds, uint32_t max_age_seconds)
{
    if (max_age_seconds == 0)
    {
        return false;
    }
    uint64_t now_seconds = sys_time_millis() / 1000ULL;
    if (now_seconds == 0)
    {
        return false;
    }
    if (mtime_seconds == 0)
    {
        return true;
    }
    if (now_seconds <= mtime_seconds)
    {
        return false;
    }
    return (now_seconds - mtime_seconds) >= (uint64_t)max_age_seconds;
}

static const char *browser_read_status_reason(browser_read_status_t status)
{
    switch (status)
    {
        case BROWSER_READ_STATUS_OK:
            return "ok";
        case BROWSER_READ_STATUS_INVALID:
            return "invalid";
        case BROWSER_READ_STATUS_OPEN:
            return "open-failed";
        case BROWSER_READ_STATUS_STAT:
            return "stat-failed";
        case BROWSER_READ_STATUS_EMPTY:
            return "empty";
        case BROWSER_READ_STATUS_TOO_LARGE:
            return "too-large";
        case BROWSER_READ_STATUS_ALLOC:
            return "alloc";
        case BROWSER_READ_STATUS_READ:
            return "read-failed";
        default:
            return "unknown";
    }
}

static char *browser_read_file_all(const char *path,
                                  size_t *len_out,
                                  size_t max_bytes,
                                  uint64_t *mtime_out,
                                  browser_read_status_t *status_out)
{
    if (len_out)
    {
        *len_out = 0;
    }
    if (mtime_out)
    {
        *mtime_out = 0;
    }
    if (status_out)
    {
        *status_out = BROWSER_READ_STATUS_INVALID;
    }
    if (!path || path[0] == '\0')
    {
        return NULL;
    }

    int fd = open(path, SYSCALL_OPEN_READ);
    if (fd < 0)
    {
        if (status_out)
        {
            *status_out = BROWSER_READ_STATUS_OPEN;
        }
        return NULL;
    }

    struct stat st;
    if (fstat(fd, &st) != 0)
    {
        close(fd);
        if (status_out)
        {
            *status_out = BROWSER_READ_STATUS_STAT;
        }
        return NULL;
    }
    if (mtime_out)
    {
        *mtime_out = st.st_mtime;
    }

    if (st.st_size == 0)
    {
        close(fd);
        if (status_out)
        {
            *status_out = BROWSER_READ_STATUS_EMPTY;
        }
        return NULL;
    }
    if (st.st_size > (uint64_t)max_bytes)
    {
        close(fd);
        if (status_out)
        {
            *status_out = BROWSER_READ_STATUS_TOO_LARGE;
        }
        return NULL;
    }

    size_t size = (size_t)st.st_size;
    char *buf = (char *)malloc(size + 1);
    if (!buf)
    {
        close(fd);
        if (status_out)
        {
            *status_out = BROWSER_READ_STATUS_ALLOC;
        }
        return NULL;
    }

    size_t offset = 0;
    while (offset < size)
    {
        ssize_t got = read(fd, buf + offset, size - offset);
        if (got <= 0)
        {
            free(buf);
            close(fd);
            if (status_out)
            {
                *status_out = BROWSER_READ_STATUS_READ;
            }
            return NULL;
        }
        offset += (size_t)got;
    }
    buf[size] = '\0';
    close(fd);

    if (len_out)
    {
        *len_out = size;
    }
    if (status_out)
    {
        *status_out = BROWSER_READ_STATUS_OK;
    }
    return buf;
}

static bool browser_passwd_line_home(const char *line,
                                     const char *end,
                                     uint32_t *uid_out,
                                     const char **home_start_out,
                                     size_t *home_len_out)
{
    if (!line || !end || line >= end || !uid_out || !home_start_out || !home_len_out)
    {
        return false;
    }

    const char *colon1 = NULL;
    const char *colon2 = NULL;
    const char *colon3 = NULL;
    const char *colon4 = NULL;
    for (const char *cur = line; cur < end; ++cur)
    {
        if (*cur == ':')
        {
            if (!colon1)
            {
                colon1 = cur;
            }
            else if (!colon2)
            {
                colon2 = cur;
            }
            else if (!colon3)
            {
                colon3 = cur;
            }
            else
            {
                colon4 = cur;
                break;
            }
        }
    }

    if (!colon1 || !colon2 || !colon3 || !colon4)
    {
        return false;
    }

    uint32_t uid = 0;
    if (!browser_parse_u32_range(colon1 + 1, colon2, &uid))
    {
        return false;
    }

    const char *home_start = colon4 + 1;
    if (home_start > end)
    {
        return false;
    }
    size_t home_len = (size_t)(end - home_start);
    if (home_len == 0)
    {
        return false;
    }

    *uid_out = uid;
    *home_start_out = home_start;
    *home_len_out = home_len;
    return true;
}

static char *browser_home_from_passwd(uint32_t uid)
{
    size_t data_len = 0;
    char *data = browser_read_file_all("/etc/passwd",
                                       &data_len,
                                       BROWSER_MAX_PASSWD_BYTES,
                                       NULL,
                                       NULL);
    if (!data || data_len == 0)
    {
        free(data);
        return NULL;
    }

    char *home = NULL;
    char *root_home = NULL;
    size_t pos = 0;
    while (pos < data_len)
    {
        size_t line_end = pos;
        while (line_end < data_len && data[line_end] != '\n' && data[line_end] != '\r')
        {
            ++line_end;
        }

        if (line_end > pos)
        {
            const char *line = data + pos;
            const char *end = data + line_end;
            uint32_t line_uid = 0;
            const char *home_start = NULL;
            size_t home_len = 0;
            if (browser_passwd_line_home(line, end, &line_uid, &home_start, &home_len))
            {
                if (!home && line_uid == uid)
                {
                    home = browser_strdup_len(home_start, home_len);
                }
                if (!root_home && line_uid == 0)
                {
                    root_home = browser_strdup_len(home_start, home_len);
                }
            }
        }

        while (line_end < data_len && (data[line_end] == '\n' || data[line_end] == '\r'))
        {
            ++line_end;
        }
        pos = line_end;
    }

    free(data);
    if (home)
    {
        free(root_home);
        return home;
    }
    return root_home;
}

static bool browser_dir_exists(const char *path)
{
    if (!path || path[0] == '\0')
    {
        return false;
    }
    syscall_dirent_t *scratch = (syscall_dirent_t *)malloc(sizeof(*scratch));
    if (!scratch)
    {
        return false;
    }
    ssize_t count = sys_list_dir(path, scratch, 1);
    free(scratch);
    return count >= 0;
}

static bool browser_ensure_dir_path(const char *path)
{
    if (!path || path[0] == '\0')
    {
        return false;
    }

    char *copy = browser_strdup(path);
    if (!copy)
    {
        return false;
    }

    size_t len = strlen(copy);
    if (len == 0)
    {
        free(copy);
        return false;
    }

    size_t pos = 0;
    if (copy[0] == '/')
    {
        pos = 1;
        while (copy[pos] == '/')
        {
            pos++;
        }
    }

    for (; pos <= len; ++pos)
    {
        if (copy[pos] == '/' || copy[pos] == '\0')
        {
            char saved = copy[pos];
            copy[pos] = '\0';
            if (copy[0] != '\0' && !(copy[0] == '/' && copy[1] == '\0'))
            {
                if (mkdir(copy, 0) != 0)
                {
                    if (!browser_dir_exists(copy))
                    {
                        free(copy);
                        return false;
                    }
                }
            }
            copy[pos] = saved;
            while (copy[pos] == '/')
            {
                pos++;
            }
        }
    }

    free(copy);
    return true;
}

static const char *browser_cache_dir(browser_app_t *app)
{
    if (!app)
    {
        return NULL;
    }

    browser_lock_enter(app, &app->lock, "app_lock");
    if (app->cache_ready)
    {
        const char *dir = app->cache_dir;
        browser_lock_exit(app, &app->lock, "app_lock");
        return dir;
    }
    if (app->cache_attempted)
    {
        browser_lock_exit(app, &app->lock, "app_lock");
        return NULL;
    }
    app->cache_attempted = true;
    browser_lock_exit(app, &app->lock, "app_lock");

    char *home = browser_home_from_passwd(getuid());
    if (!home || home[0] == '\0')
    {
        free(home);
        return NULL;
    }

    size_t home_len = strlen(home);
    while (home_len > 1 && home[home_len - 1] == '/')
    {
        home_len--;
    }
    home[home_len] = '\0';

    if (!browser_ensure_dir_path(home))
    {
        free(home);
        return NULL;
    }

    const char suffix[] = "/.browser/cache";
    size_t suffix_len = sizeof(suffix) - 1;
    size_t cache_len = home_len + suffix_len;
    char *cache_dir = (char *)malloc(cache_len + 1);
    if (!cache_dir)
    {
        free(home);
        return NULL;
    }

    memcpy(cache_dir, home, home_len);
    memcpy(cache_dir + home_len, suffix, suffix_len);
    cache_dir[cache_len] = '\0';
    free(home);

    if (!browser_ensure_dir_path(cache_dir))
    {
        free(cache_dir);
        return NULL;
    }

    browser_lock_enter(app, &app->lock, "app_lock");
    if (!app->cache_ready)
    {
        app->cache_dir = cache_dir;
        app->cache_ready = true;
    }
    const char *dir = app->cache_dir;
    browser_lock_exit(app, &app->lock, "app_lock");

    if (dir != cache_dir)
    {
        free(cache_dir);
    }
    return dir;
}

static bool browser_cache_hash_uri(const char *uri, char out[41])
{
    if (!uri || !out)
    {
        return false;
    }

    uint8_t digest[20];
    sha1_ctx_t ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, uri, strlen(uri));
    sha1_final(&ctx, digest);

    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(digest); ++i)
    {
        out[i * 2] = hex[(digest[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex[digest[i] & 0x0F];
    }
    out[40] = '\0';
    return true;
}

static char *browser_cache_path_for_uri(const char *cache_dir, const char *uri)
{
    if (!cache_dir || !uri)
    {
        return NULL;
    }

    char hash[41];
    if (!browser_cache_hash_uri(uri, hash))
    {
        return NULL;
    }

    size_t dir_len = strlen(cache_dir);
    size_t path_len = dir_len + 1 + sizeof(hash) - 1;
    char *path = (char *)malloc(path_len + 1);
    if (!path)
    {
        return NULL;
    }

    memcpy(path, cache_dir, dir_len);
    path[dir_len] = '/';
    memcpy(path + dir_len + 1, hash, sizeof(hash));
    path[path_len] = '\0';
    return path;
}

static char *browser_cache_meta_path(const char *path)
{
    if (!path)
    {
        return NULL;
    }
    const char suffix[] = ".meta";
    size_t path_len = strlen(path);
    size_t meta_len = path_len + sizeof(suffix);
    char *meta_path = (char *)malloc(meta_len);
    if (!meta_path)
    {
        return NULL;
    }
    memcpy(meta_path, path, path_len);
    memcpy(meta_path + path_len, suffix, sizeof(suffix));
    return meta_path;
}

static bool browser_cache_parse_timestamp(const char *data, size_t len, uint64_t *timestamp_out)
{
    if (!data || len == 0 || !timestamp_out)
    {
        return false;
    }
    const char *cur = data;
    const char *end = data + len;
    while (cur < end &&
           (*cur == ' ' || *cur == '\n' || *cur == '\r' || *cur == '\t'))
    {
        ++cur;
    }
    const char *start = cur;
    while (cur < end && *cur >= '0' && *cur <= '9')
    {
        ++cur;
    }
    if (start == cur)
    {
        return false;
    }
    return browser_parse_u64_range(start, cur, timestamp_out);
}

static bool browser_cache_read_meta(const char *path, uint64_t *timestamp_out)
{
    if (timestamp_out)
    {
        *timestamp_out = 0;
    }
    if (!path || !timestamp_out)
    {
        return false;
    }
    char *meta_path = browser_cache_meta_path(path);
    if (!meta_path)
    {
        return false;
    }
    size_t len = 0;
    char *data = browser_read_file_all(meta_path,
                                       &len,
                                       BROWSER_CACHE_META_MAX_BYTES,
                                       NULL,
                                       NULL);
    free(meta_path);
    if (!data)
    {
        return false;
    }
    uint64_t timestamp = 0;
    bool ok = browser_cache_parse_timestamp(data, len, &timestamp);
    free(data);
    if (!ok || timestamp == 0)
    {
        return false;
    }
    *timestamp_out = timestamp;
    return true;
}

static char *browser_cache_read(browser_app_t *app,
                                const char *uri,
                                size_t *body_len_out,
                                browser_cache_state_t *state_out)
{
    if (body_len_out)
    {
        *body_len_out = 0;
    }
    if (state_out)
    {
        *state_out = BROWSER_CACHE_STATE_MISS;
    }
    if (!app || !uri || uri[0] == '\0')
    {
        return NULL;
    }

    const char *cache_dir = browser_cache_dir(app);
    if (!cache_dir)
    {
        browser_debug_logf(app, "[cache] miss url=%s reason=no-dir", uri);
        serial_printf("[cache] miss url=%s reason=no-dir", uri);
        return NULL;
    }

    char *path = browser_cache_path_for_uri(cache_dir, uri);
    if (!path)
    {
        browser_debug_logf(app, "[cache] miss url=%s reason=alloc", uri);
        serial_printf("[cache] miss url=%s reason=alloc", uri);
        return NULL;
    }

    uint64_t mtime_seconds = 0;
    browser_read_status_t read_status = BROWSER_READ_STATUS_OK;
    char *data = browser_read_file_all(path,
                                       body_len_out,
                                       BROWSER_MAX_BYTES,
                                       &mtime_seconds,
                                       &read_status);
    if (data)
    {
        uint32_t max_age_seconds = browser_cache_max_age_for_uri(uri);
        uint64_t cache_time_seconds = mtime_seconds;
        const char *time_source = "mtime";
        uint64_t meta_seconds = 0;
        if (browser_cache_read_meta(path, &meta_seconds))
        {
            cache_time_seconds = meta_seconds;
            time_source = "meta";
        }
        else if (cache_time_seconds == 0)
        {
            time_source = "none";
        }
        if (browser_cache_expired(cache_time_seconds, max_age_seconds))
        {
            uint64_t now_seconds = sys_time_millis() / 1000ULL;
            uint64_t age = (now_seconds > cache_time_seconds) ? (now_seconds - cache_time_seconds) : 0;
            if (state_out)
            {
                *state_out = BROWSER_CACHE_STATE_STALE;
            }
            browser_debug_logf(app,
                               "[cache] stale url=%s age=%llu max=%u src=%s",
                               uri,
                               (unsigned long long)age,
                               (unsigned)max_age_seconds,
                               time_source);
            serial_printf("[cache] stale url=%s age=%llu max=%u src=%s",
                          uri,
                          (unsigned long long)age,
                          (unsigned)max_age_seconds,
                          time_source);
        }
        else
        {
            uint64_t now_seconds = sys_time_millis() / 1000ULL;
            uint64_t age = (now_seconds > cache_time_seconds) ? (now_seconds - cache_time_seconds) : 0;
            unsigned bytes = body_len_out ? (unsigned)*body_len_out : 0;
            if (state_out)
            {
                *state_out = BROWSER_CACHE_STATE_HIT;
            }
            browser_debug_logf(app,
                               "[cache] hit url=%s bytes=%u age=%llu src=%s",
                               uri,
                               bytes,
                               (unsigned long long)age,
                               time_source);
            serial_printf("[cache] hit url=%s bytes=%u age=%llu src=%s",
                          uri,
                          bytes,
                          (unsigned long long)age,
                          time_source);
        }
    }
    else
    {
        const char *reason = browser_read_status_reason(read_status);
        browser_debug_logf(app, "[cache] miss url=%s reason=%s", uri, reason);
        serial_printf("[cache] miss url=%s reason=%s", uri, reason);
    }
    free(path);
    return data;
}

static void browser_cache_write_meta(const char *path, uint64_t timestamp_seconds)
{
    if (!path || timestamp_seconds == 0)
    {
        return;
    }
    char *meta_path = browser_cache_meta_path(path);
    if (!meta_path)
    {
        return;
    }
    char buf[32];
    int len = snprintf(buf, sizeof(buf), "%llu\n", (unsigned long long)timestamp_seconds);
    if (len <= 0)
    {
        free(meta_path);
        return;
    }
    int fd = open(meta_path, SYSCALL_OPEN_WRITE | SYSCALL_OPEN_CREATE | SYSCALL_OPEN_TRUNCATE);
    if (fd >= 0)
    {
        (void)browser_write_all(fd, (const uint8_t *)buf, (size_t)len);
        close(fd);
    }
    free(meta_path);
}

static void browser_cache_write(browser_app_t *app, const char *uri, const uint8_t *data, size_t len)
{
    if (!app || !uri || uri[0] == '\0' || !data || len == 0 || len > BROWSER_MAX_BYTES)
    {
        return;
    }

    const char *cache_dir = browser_cache_dir(app);
    if (!cache_dir)
    {
        return;
    }

    char *path = browser_cache_path_for_uri(cache_dir, uri);
    if (!path)
    {
        return;
    }

    int fd = open(path, SYSCALL_OPEN_WRITE | SYSCALL_OPEN_CREATE | SYSCALL_OPEN_TRUNCATE);
    if (fd >= 0)
    {
        if (browser_write_all(fd, data, len))
        {
            uint64_t now_seconds = sys_time_millis() / 1000ULL;
            browser_cache_write_meta(path, now_seconds);
            browser_debug_logf(app, "[cache] store url=%s bytes=%u", uri, (unsigned)len);
            serial_printf("[cache] store url=%s bytes=%u", uri, (unsigned)len);
        }
        close(fd);
    }
    free(path);
}

static char *browser_cache_join_path(const char *base, const char *name)
{
    if (!base || !name)
    {
        return NULL;
    }

    size_t base_len = strlen(base);
    size_t name_len = strlen(name);
    bool needs_slash = (base_len > 0 && base[base_len - 1] != '/');
    size_t total_len = base_len + name_len + (needs_slash ? 1u : 0u);
    if (total_len == 0)
    {
        return NULL;
    }

    char *path = (char *)malloc(total_len + 1);
    if (!path)
    {
        return NULL;
    }

    memcpy(path, base, base_len);
    size_t offset = base_len;
    if (needs_slash)
    {
        path[offset++] = '/';
    }
    memcpy(path + offset, name, name_len);
    path[total_len] = '\0';
    return path;
}

bool browser_cache_clear(browser_app_t *app)
{
    if (!app)
    {
        return false;
    }

    const char *cache_dir = browser_cache_dir(app);
    if (!cache_dir)
    {
        browser_debug_logf(app, "[cache] clear skipped (no dir)");
        serial_printf("[cache] clear skipped (no dir)");
        return false;
    }

    const size_t capacity = 128;
    syscall_dirent_t *entries = (syscall_dirent_t *)calloc(capacity, sizeof(*entries));
    if (!entries)
    {
        browser_debug_logf(app, "[cache] clear failed (alloc)");
        serial_printf("[cache] clear failed (alloc)");
        return false;
    }

    size_t removed = 0;
    size_t skipped = 0;
    bool error = false;
    for (;;)
    {
        ssize_t count = sys_list_dir(cache_dir, entries, capacity);
        if (count < 0)
        {
            error = true;
            break;
        }
        if (count == 0)
        {
            break;
        }

        size_t removed_this_round = 0;
        for (ssize_t i = 0; i < count; ++i)
        {
            const syscall_dirent_t *ent = &entries[i];
            if (ent->name[0] == '\0' || strcmp(ent->name, ".") == 0 || strcmp(ent->name, "..") == 0)
            {
                continue;
            }
            if (ent->type != SYSCALL_NODE_TYPE_FILE && ent->type != SYSCALL_NODE_TYPE_SYMLINK)
            {
                skipped++;
                continue;
            }

            char *path = browser_cache_join_path(cache_dir, ent->name);
            if (!path)
            {
                skipped++;
                continue;
            }
            if (unlink(path) == 0)
            {
                removed++;
                removed_this_round++;
            }
            else
            {
                skipped++;
            }
            free(path);
        }

        if ((size_t)count < capacity || removed_this_round == 0)
        {
            break;
        }
    }

    free(entries);

    if (error)
    {
        browser_debug_logf(app, "[cache] clear failed dir=%s", cache_dir);
        serial_printf("[cache] clear failed dir=%s", cache_dir);
        return false;
    }

    browser_debug_logf(app, "[cache] clear removed=%u skipped=%u", (unsigned)removed, (unsigned)skipped);
    serial_printf("[cache] clear removed=%u skipped=%u", (unsigned)removed, (unsigned)skipped);
    return true;
}

static bool browser_http_find_header_end(const char *data,
                                        size_t len,
                                        size_t *header_len_out,
                                        size_t *body_offset_out)
{
    if (!data || len == 0)
    {
        return false;
    }

    for (size_t i = 0; i + 3 < len; ++i)
    {
        if (data[i] == '\r' &&
            data[i + 1] == '\n' &&
            data[i + 2] == '\r' &&
            data[i + 3] == '\n')
        {
            if (header_len_out)
            {
                *header_len_out = i;
            }
            if (body_offset_out)
            {
                *body_offset_out = i + 4;
            }
            return true;
        }
    }

    for (size_t i = 0; i + 1 < len; ++i)
    {
        if (data[i] == '\n' && data[i + 1] == '\n')
        {
            if (header_len_out)
            {
                *header_len_out = i;
            }
            if (body_offset_out)
            {
                *body_offset_out = i + 2;
            }
            return true;
        }
    }

    return false;
}

static bool browser_http_find_header_value(const char *headers,
                                          size_t headers_len,
                                          const char *name,
                                          const char **value_out,
                                          size_t *value_len_out)
{
    if (!headers || headers_len == 0 || !name || !value_out || !value_len_out)
    {
        return false;
    }

    const size_t name_len = strlen(name);
    const char *p = headers;
    const char *end = headers + headers_len;

    while (p < end)
    {
        const char *line = p;
        const char *line_end = NULL;
        for (const char *it = p; it < end; ++it)
        {
            if (*it == '\n')
            {
                line_end = it;
                break;
            }
        }
        if (!line_end)
        {
            line_end = end;
            p = end;
        }
        else
        {
            p = line_end + 1;
        }

        size_t line_len = (size_t)(line_end - line);
        if (line_len > 0 && line[line_len - 1] == '\r')
        {
            line_len--;
        }
        if (line_len == 0)
        {
            continue;
        }

        const char *colon = NULL;
        for (size_t i = 0; i < line_len; ++i)
        {
            if (line[i] == ':')
            {
                colon = line + i;
                break;
            }
        }
        if (!colon)
        {
            continue;
        }

        size_t key_len = (size_t)(colon - line);
        if (key_len != name_len)
        {
            continue;
        }
        if (strncasecmp(line, name, name_len) != 0)
        {
            continue;
        }

        const char *value = colon + 1;
        const char *line_data_end = line + line_len;
        while (value < line_data_end && (*value == ' ' || *value == '\t'))
        {
            value++;
        }
        const char *value_end = line_data_end;
        while (value_end > value && (value_end[-1] == ' ' || value_end[-1] == '\t'))
        {
            value_end--;
        }

        *value_out = value;
        *value_len_out = (size_t)(value_end - value);
        return true;
    }

    return false;
}

static bool browser_parse_decimal_size(const char *value, size_t value_len, size_t *out)
{
    if (!value || value_len == 0 || !out)
    {
        return false;
    }

    size_t parsed = 0;
    bool saw_digit = false;
    for (size_t i = 0; i < value_len; ++i)
    {
        char c = value[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
        {
            continue;
        }
        if (c < '0' || c > '9')
        {
            return false;
        }
        saw_digit = true;
        size_t digit = (size_t)(c - '0');
        if (parsed > (BROWSER_MAX_BYTES - digit) / 10u)
        {
            return false;
        }
        parsed = parsed * 10u + digit;
    }
    if (!saw_digit)
    {
        return false;
    }
    *out = parsed;
    return true;
}

static void browser_http_copy_status_line(const char *headers,
                                         size_t headers_len,
                                         char *out,
                                         size_t out_cap)
{
    if (!out || out_cap == 0)
    {
        return;
    }
    out[0] = '\0';
    if (!headers || headers_len == 0)
    {
        return;
    }

    size_t max = headers_len;
    for (size_t i = 0; i < max; ++i)
    {
        char c = headers[i];
        if (c == '\r' || c == '\n')
        {
            max = i;
            break;
        }
    }
    if (max >= out_cap)
    {
        max = out_cap - 1;
    }
    memcpy(out, headers, max);
    out[max] = '\0';
}

static int browser_http_parse_status_code(const char *headers, size_t headers_len)
{
    if (!headers || headers_len == 0)
    {
        return -1;
    }

    size_t i = 0;
    while (i < headers_len && (headers[i] == ' ' || headers[i] == '\t'))
    {
        ++i;
    }

    while (i < headers_len && headers[i] != ' ' && headers[i] != '\t' && headers[i] != '\r' && headers[i] != '\n')
    {
        ++i;
    }
    while (i < headers_len && (headers[i] == ' ' || headers[i] == '\t'))
    {
        ++i;
    }

    if (i + 3 > headers_len)
    {
        return -1;
    }
    int code = 0;
    for (int d = 0; d < 3; ++d)
    {
        char c = headers[i + (size_t)d];
        if (c < '0' || c > '9')
        {
            return -1;
        }
        code = code * 10 + (c - '0');
    }
    return code;
}

typedef enum
{
    BROWSER_CHUNK_READ_SIZE = 0,
    BROWSER_CHUNK_READ_DATA,
    BROWSER_CHUNK_READ_DATA_CR,
    BROWSER_CHUNK_READ_DATA_LF,
    BROWSER_CHUNK_READ_TRAILERS,
    BROWSER_CHUNK_DONE
} browser_chunk_state_t;

typedef struct
{
    browser_chunk_state_t state;
    size_t current_size;
    size_t remaining;
    char linebuf[64];
    size_t line_len;
    int trailer_stage;
} browser_chunked_t;

static void browser_chunked_init(browser_chunked_t *st)
{
    if (!st)
    {
        return;
    }
    st->state = BROWSER_CHUNK_READ_SIZE;
    st->current_size = 0;
    st->remaining = 0;
    st->line_len = 0;
    st->trailer_stage = 0;
}

static bool browser_parse_chunk_size_line(const char *line, size_t len, size_t *out)
{
    if (!line || len == 0 || !out)
    {
        return false;
    }

    size_t val = 0;
    bool saw_digit = false;
    for (size_t i = 0; i < len; ++i)
    {
        char c = line[i];
        if (c == ';' || c == ' ' || c == '\t')
        {
            break;
        }

        unsigned d = 0;
        if (c >= '0' && c <= '9')
        {
            d = (unsigned)(c - '0');
        }
        else if (c >= 'a' && c <= 'f')
        {
            d = 10u + (unsigned)(c - 'a');
        }
        else if (c >= 'A' && c <= 'F')
        {
            d = 10u + (unsigned)(c - 'A');
        }
        else
        {
            return false;
        }

        saw_digit = true;
        if (val > (BROWSER_MAX_BYTES - (size_t)d) / 16u)
        {
            return false;
        }
        val = (val << 4) | (size_t)d;
    }

    if (!saw_digit)
    {
        return false;
    }

    *out = val;
    return true;
}

static bool browser_chunked_consume(browser_chunked_t *st,
                                   char **out_body,
                                   size_t *out_len,
                                   size_t *out_cap,
                                   const uint8_t *data,
                                   size_t len,
                                   bool *done)
{
    if (!st || !out_body || !out_len || !out_cap || (!data && len > 0) || !done)
    {
        return false;
    }

    size_t pos = 0;
    *done = false;

    while (pos < len && st->state != BROWSER_CHUNK_DONE)
    {
        switch (st->state)
        {
            case BROWSER_CHUNK_READ_SIZE:
            {
                char b = (char)data[pos++];
                if (st->line_len >= sizeof(st->linebuf))
                {
                    return false;
                }
                st->linebuf[st->line_len++] = b;
                if (st->line_len >= 2 &&
                    st->linebuf[st->line_len - 2] == '\r' &&
                    st->linebuf[st->line_len - 1] == '\n')
                {
                    size_t linelen = st->line_len - 2;
                    if (!browser_parse_chunk_size_line(st->linebuf, linelen, &st->current_size))
                    {
                        return false;
                    }
                    st->line_len = 0;
                    st->remaining = st->current_size;
                    if (st->current_size == 0)
                    {
                        st->state = BROWSER_CHUNK_READ_TRAILERS;
                        st->trailer_stage = 2;
                    }
                    else
                    {
                        st->state = BROWSER_CHUNK_READ_DATA;
                    }
                }
                break;
            }

            case BROWSER_CHUNK_READ_DATA:
            {
                size_t avail = len - pos;
                size_t take = (st->remaining < avail) ? st->remaining : avail;
                if (take > 0)
                {
                    if (!browser_buf_append(out_body, out_len, out_cap, data + pos, take))
                    {
                        return false;
                    }
                    pos += take;
                    st->remaining -= take;
                }
                if (st->remaining == 0)
                {
                    st->state = BROWSER_CHUNK_READ_DATA_CR;
                }
                break;
            }

            case BROWSER_CHUNK_READ_DATA_CR:
                if (pos >= len)
                {
                    return true;
                }
                if (data[pos++] != '\r')
                {
                    return false;
                }
                st->state = BROWSER_CHUNK_READ_DATA_LF;
                break;

            case BROWSER_CHUNK_READ_DATA_LF:
                if (pos >= len)
                {
                    return true;
                }
                if (data[pos++] != '\n')
                {
                    return false;
                }
                st->state = BROWSER_CHUNK_READ_SIZE;
                break;

            case BROWSER_CHUNK_READ_TRAILERS:
            {
                char c = (char)data[pos++];
                switch (st->trailer_stage)
                {
                    case 0: st->trailer_stage = (c == '\r') ? 1 : 0; break;
                    case 1: st->trailer_stage = (c == '\n') ? 2 : (c == '\r' ? 1 : 0); break;
                    case 2: st->trailer_stage = (c == '\r') ? 3 : 0; break;
                    case 3:
                        if (c == '\n')
                        {
                            st->state = BROWSER_CHUNK_DONE;
                            *done = true;
                        }
                        else
                        {
                            st->trailer_stage = 0;
                        }
                        break;
                }
                break;
            }

            case BROWSER_CHUNK_DONE:
                *done = true;
                break;
        }
    }

    return true;
}

static char *browser_format_error(const char *message)
{
    if (!message)
    {
        message = "unknown error";
    }
    const char *prefix = "Error:\n";
    size_t plen = strlen(prefix);
    size_t mlen = strlen(message);
    char *out = (char *)malloc(plen + mlen + 2);
    if (!out)
    {
        return NULL;
    }
    memcpy(out, prefix, plen);
    memcpy(out + plen, message, mlen);
    out[plen + mlen] = '\n';
    out[plen + mlen + 1] = '\0';
    return out;
}

static char *browser_build_request(const char *host, const char *path)
{
    if (!host || host[0] == '\0')
    {
        host = "unknown";
    }
    if (!path || path[0] == '\0')
    {
        path = "/";
    }
    const char *fmt =
        "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\nUser-Agent: atk_browser/0.1\r\n"
        "Accept-Encoding: identity\r\n\r\n";
    size_t cap = strlen(fmt) + strlen(host) + strlen(path) + 32;
    char *req = (char *)malloc(cap);
    if (!req)
    {
        return NULL;
    }
    snprintf(req, cap, fmt, path, host);
    return req;
}

static char *browser_fetch_http_internal(browser_app_t *app,
                                         const browser_url_t *url,
                                         int redirect_depth,
                                         size_t *body_len_out,
                                         browser_url_t *final_url_out,
                                         int *status_out)
{
    if (body_len_out)
    {
        *body_len_out = 0;
    }
    if (status_out)
    {
        *status_out = 0;
    }

    if (!url || !url->host || !url->path)
    {
        browser_debug_logf(app, "[fetch] invalid url (missing host/path)");
        serial_printf("[http] invalid url");
        return browser_format_error("invalid url");
    }

    if (redirect_depth < 0)
    {
        redirect_depth = 0;
    }
    if (redirect_depth > BROWSER_MAX_REDIRECTS)
    {
        browser_debug_logf(app, "[http] too many redirects");
        serial_printf("[http] too many redirects");
        return browser_format_error("too many redirects");
    }

    browser_debug_logf(app,
                       "[fetch] connect tls=%d host=%s port=%u path=%s",
                       url->use_tls ? 1 : 0,
                       url->host ? url->host : "(null)",
                       (unsigned)url->port,
                       url->path ? url->path : "(null)");
    serial_printf("[http] connect tls=%u host=%s port=%u path=%s",
                  url->use_tls ? 1u : 0u,
                  url->host ? url->host : "(null)",
                  (unsigned)url->port,
                  url->path ? url->path : "(null)");

    int fd = socket_open(NULL);
    if (fd < 0)
    {
        browser_debug_logf(app, "[net] socket_open failed");
        return browser_format_error("socket_open failed");
    }

    if (socket_connect(fd, url->host, url->port) != 0)
    {
        browser_debug_logf(app, "[net] socket_connect failed");
        serial_printf("[net] socket_connect failed host=%s port=%u",
                      url->host ? url->host : "(null)",
                      (unsigned)url->port);
        close(fd);
        return browser_format_error("socket_connect failed");
    }
    browser_debug_logf(app, "[net] connected");
    serial_printf("[net] connected host=%s port=%u",
                  url->host ? url->host : "(null)",
                  (unsigned)url->port);

    char *request = browser_build_request(url->host, url->path);
    if (!request)
    {
        browser_debug_logf(app, "[http] alloc request failed");
        serial_printf("[http] request alloc failed host=%s",
                      url->host ? url->host : "(null)");
        close(fd);
        return browser_format_error("alloc request failed");
    }
    browser_debug_logf(app,
                       "[http] request GET %s Host: %s",
                       url->path ? url->path : "/",
                       url->host ? url->host : "(null)");
    serial_printf("[http] request host=%s path=%s",
                  url->host ? url->host : "(null)",
                  url->path ? url->path : "/");

    char *header_buf = NULL;
    size_t header_len = 0;
    size_t header_cap = 0;
    bool header_done = false;

    char *body_buf = NULL;
    size_t body_len = 0;
    size_t body_cap = 0;

    bool have_content_length = false;
    size_t content_length = 0;
    bool is_chunked = false;
    browser_chunked_t chunked;
    browser_chunked_init(&chunked);

    char *redirect_target = NULL;
    int redirect_status = 0;
    int status_code = 0;

    uint8_t *chunk = (uint8_t *)malloc(2048);
    if (!chunk)
    {
        browser_debug_logf(app, "[http] alloc recv buffer failed");
        serial_printf("[http] recv buffer alloc failed host=%s",
                      url->host ? url->host : "(null)");
        free(request);
        close(fd);
        return browser_format_error("alloc recv buffer failed");
    }

    if (url->use_tls)
    {
        browser_debug_logf(app, "[tls] handshake start");
        serial_printf("[tls] handshake start host=%s", url->host ? url->host : "(null)");
        tls_session_t *tls = tls_session_create_fd(fd);
        if (!tls)
        {
            browser_debug_logf(app, "[tls] alloc tls session failed");
            serial_printf("[tls] alloc session failed host=%s", url->host ? url->host : "(null)");
            free(chunk);
            free(request);
            close(fd);
            return browser_format_error("alloc tls session failed");
        }

        if (!tls_session_handshake(tls, url->host))
        {
            browser_debug_logf(app, "[tls] handshake failed (see serial log)");
            serial_printf("[tls] handshake failed host=%s", url->host ? url->host : "(null)");
            tls_session_destroy(tls);
            free(chunk);
            free(request);
            close(fd);
            return browser_format_error("tls handshake failed");
        }
        browser_debug_logf(app, "[tls] handshake ok");
        serial_printf("[tls] handshake ok host=%s", url->host ? url->host : "(null)");

        if (!tls_session_send(tls, (const uint8_t *)request, strlen(request)))
        {
            browser_debug_logf(app, "[tls] send failed");
            serial_printf("[tls] send failed host=%s", url->host ? url->host : "(null)");
            tls_session_destroy(tls);
            free(chunk);
            free(request);
            close(fd);
            return browser_format_error("tls send failed");
        }

        while (1)
        {
            size_t got = tls_session_recv(tls, chunk, 2048);
            if (got == 0)
            {
                break;
            }

            if (!header_done)
            {
                if (!browser_buf_append(&header_buf, &header_len, &header_cap, chunk, got))
                {
                    tls_session_destroy(tls);
                    free(request);
                    close(fd);
                    free(header_buf);
                    free(body_buf);
                    free(chunk);
                    return browser_format_error("response too large");
                }

                size_t header_block_len = 0;
                size_t body_offset = 0;
                if (!browser_http_find_header_end(header_buf, header_len, &header_block_len, &body_offset))
                {
                    continue;
                }

                header_done = true;

                char status_line[128];
                browser_http_copy_status_line(header_buf, header_block_len, status_line, sizeof(status_line));
                int status = browser_http_parse_status_code(header_buf, header_block_len);
                status_code = status;
                browser_debug_logf(app, "[http] status %s (code=%d)", status_line, status);
                serial_printf("[http] status %s code=%d", status_line, status);

                const char *value = NULL;
                size_t value_len = 0;
                const char *location_value = NULL;
                size_t location_len = 0;
                if (browser_http_find_header_value(header_buf, header_block_len,
                                                   "transfer-encoding",
                                                   &value, &value_len) &&
                    browser_has_token_ci(value, value_len, "chunked"))
                {
                    is_chunked = true;
                    have_content_length = false;
                }

                if (!is_chunked &&
                    browser_http_find_header_value(header_buf, header_block_len,
                                                   "content-length",
                                                   &value, &value_len))
                {
                    size_t parsed_len = 0;
                    if (browser_parse_decimal_size(value, value_len, &parsed_len) &&
                        parsed_len <= BROWSER_MAX_BYTES)
                    {
                        have_content_length = true;
                        content_length = parsed_len;
                    }
                }

                if (have_content_length)
                {
                    size_t reserve = content_length + 1;
                    if (reserve > body_cap)
                    {
                        char *new_buf = (char *)realloc(body_buf, reserve);
                        if (!new_buf)
                        {
                            tls_session_destroy(tls);
                            free(request);
                            close(fd);
                            free(header_buf);
                            free(body_buf);
                            free(chunk);
                            return browser_format_error("alloc body buffer failed");
                        }
                        body_buf = new_buf;
                        body_cap = reserve;
                    }
                }

                if (browser_http_find_header_value(header_buf, header_block_len,
                                                   "content-type",
                                                   &value, &value_len))
                {
                    char type_buf[96];
                    size_t copy = value_len;
                    if (copy >= sizeof(type_buf))
                    {
                        copy = sizeof(type_buf) - 1;
                    }
                    memcpy(type_buf, value, copy);
                    type_buf[copy] = '\0';
                    browser_debug_logf(app, "[http] content-type %s", type_buf);
                }

                if (browser_http_find_header_value(header_buf, header_block_len,
                                                   "content-encoding",
                                                   &value, &value_len))
                {
                    char enc_buf[64];
                    size_t copy = value_len;
                    if (copy >= sizeof(enc_buf))
                    {
                        copy = sizeof(enc_buf) - 1;
                    }
                    memcpy(enc_buf, value, copy);
                    enc_buf[copy] = '\0';
                    browser_debug_logf(app, "[http] content-encoding %s", enc_buf);
                }

                if (browser_http_find_header_value(header_buf, header_block_len,
                                                   "content-encoding",
                                                   &value, &value_len))
                {
                    char enc_buf[64];
                    size_t copy = value_len;
                    if (copy >= sizeof(enc_buf))
                    {
                        copy = sizeof(enc_buf) - 1;
                    }
                    memcpy(enc_buf, value, copy);
                    enc_buf[copy] = '\0';
                    browser_debug_logf(app, "[http] content-encoding %s", enc_buf);
                }

                if (browser_http_find_header_value(header_buf, header_block_len,
                                                   "location",
                                                   &value, &value_len))
                {
                    location_value = value;
                    location_len = value_len;
                    char loc_buf[160];
                    size_t copy = value_len;
                    if (copy >= sizeof(loc_buf))
                    {
                        copy = sizeof(loc_buf) - 1;
                    }
                    memcpy(loc_buf, value, copy);
                    loc_buf[copy] = '\0';
                    browser_debug_logf(app, "[http] location %s", loc_buf);
                }

                if (!redirect_target &&
                    (status == 301 || status == 302 || status == 303 || status == 307 || status == 308) &&
                    location_value && location_len > 0 && location_value[0] != '#')
                {
                    if (redirect_depth >= BROWSER_MAX_REDIRECTS)
                    {
                        tls_session_destroy(tls);
                        free(request);
                        close(fd);
                        free(header_buf);
                        free(body_buf);
                        free(chunk);
                        return browser_format_error("too many redirects");
                    }
                    redirect_target = browser_build_absolute_url(url, location_value, location_len);
                    if (!redirect_target)
                    {
                        tls_session_destroy(tls);
                        free(request);
                        close(fd);
                        free(header_buf);
                        free(body_buf);
                        free(chunk);
                        return browser_format_error("redirect allocation failed");
                    }
                    redirect_status = status;
                    browser_debug_logf(app, "[http] redirect %d -> %s", status, redirect_target);
                    serial_printf("[http] redirect %d url=%s", status, redirect_target);

                    free(header_buf);
                    header_buf = NULL;
                    header_len = 0;
                    header_cap = 0;
                    break;
                }

                browser_debug_logf(app,
                                   "[http] transfer=%s content-length=%u",
                                   is_chunked ? "chunked" : "identity",
                                   have_content_length ? (unsigned)content_length : 0u);
                serial_printf("[http] transfer=%s content-length=%u",
                              is_chunked ? "chunked" : "identity",
                              have_content_length ? (unsigned)content_length : 0u);

                if (header_len > body_offset)
                {
                    size_t body_bytes = header_len - body_offset;
                    if (is_chunked)
                    {
                        bool done = false;
                        if (!browser_chunked_consume(&chunked, &body_buf, &body_len, &body_cap,
                                                     (const uint8_t *)header_buf + body_offset,
                                                     body_bytes,
                                                     &done))
                        {
                            tls_session_destroy(tls);
                            free(request);
                            close(fd);
                            free(header_buf);
                            free(body_buf);
                            free(chunk);
                            return browser_format_error("invalid chunked body");
                        }
                        if (done)
                        {
                            break;
                        }
                    }
                    else
                    {
                        size_t take = body_bytes;
                        if (have_content_length && body_len < content_length)
                        {
                            size_t remaining = content_length - body_len;
                            if (take > remaining)
                            {
                                take = remaining;
                            }
                        }
                        if (take > 0 &&
                            !browser_buf_append(&body_buf, &body_len, &body_cap,
                                                (const uint8_t *)header_buf + body_offset,
                                                take))
                        {
                            tls_session_destroy(tls);
                            free(request);
                            close(fd);
                            free(header_buf);
                            free(body_buf);
                            free(chunk);
                            return browser_format_error("response too large");
                        }
                    }
                }

                free(header_buf);
                header_buf = NULL;
                header_len = 0;
                header_cap = 0;
            }
            else
            {
                if (is_chunked)
                {
                    bool done = false;
                    if (!browser_chunked_consume(&chunked, &body_buf, &body_len, &body_cap,
                                                 chunk, got, &done))
                    {
                        tls_session_destroy(tls);
                        free(request);
                        close(fd);
                        free(body_buf);
                        free(chunk);
                        return browser_format_error("invalid chunked body");
                    }
                    if (done)
                    {
                        break;
                    }
                }
                else
                {
                    size_t take = got;
                    if (have_content_length && body_len < content_length)
                    {
                        size_t remaining = content_length - body_len;
                        if (take > remaining)
                        {
                            take = remaining;
                        }
                    }
                    if (take > 0 &&
                        !browser_buf_append(&body_buf, &body_len, &body_cap, chunk, take))
                    {
                        tls_session_destroy(tls);
                        free(request);
                        close(fd);
                        free(body_buf);
                        free(chunk);
                        return browser_format_error("response too large");
                    }
                }
            }

            if (!is_chunked &&
                have_content_length &&
                body_len >= content_length)
            {
                break;
            }
        }

        tls_session_destroy(tls);
    }
    else
    {
        if (!browser_write_all(fd, (const uint8_t *)request, strlen(request)))
        {
            browser_debug_logf(app, "[http] write failed");
            serial_printf("[http] write failed host=%s", url->host ? url->host : "(null)");
            free(chunk);
            free(request);
            close(fd);
            return browser_format_error("write failed");
        }

        while (1)
        {
            ssize_t got_raw = read(fd, chunk, 2048);
            if (got_raw < 0)
            {
                continue;
            }
            if (got_raw == 0)
            {
                break;
            }

            size_t got = (size_t)got_raw;
            if (!header_done)
            {
                if (!browser_buf_append(&header_buf, &header_len, &header_cap, chunk, got))
                {
                    browser_debug_logf(app, "[http] header too large");
                    free(request);
                    close(fd);
                    free(header_buf);
                    free(body_buf);
                    free(chunk);
                    return browser_format_error("response too large");
                }

                size_t header_block_len = 0;
                size_t body_offset = 0;
                if (!browser_http_find_header_end(header_buf, header_len, &header_block_len, &body_offset))
                {
                    continue;
                }

                header_done = true;

                char status_line[128];
                browser_http_copy_status_line(header_buf, header_block_len, status_line, sizeof(status_line));
                int status = browser_http_parse_status_code(header_buf, header_block_len);
                status_code = status;
                browser_debug_logf(app, "[http] status %s (code=%d)", status_line, status);
                serial_printf("[http] status %s code=%d", status_line, status);

                const char *value = NULL;
                size_t value_len = 0;
                const char *location_value = NULL;
                size_t location_len = 0;
                if (browser_http_find_header_value(header_buf, header_block_len,
                                                   "transfer-encoding",
                                                   &value, &value_len) &&
                    browser_has_token_ci(value, value_len, "chunked"))
                {
                    is_chunked = true;
                    have_content_length = false;
                }

                if (!is_chunked &&
                    browser_http_find_header_value(header_buf, header_block_len,
                                                   "content-length",
                                                   &value, &value_len))
                {
                    size_t parsed_len = 0;
                    if (browser_parse_decimal_size(value, value_len, &parsed_len) &&
                        parsed_len <= BROWSER_MAX_BYTES)
                    {
                        have_content_length = true;
                        content_length = parsed_len;
                    }
                }

                if (have_content_length)
                {
                    size_t reserve = content_length + 1;
                    if (reserve > body_cap)
                    {
                        char *new_buf = (char *)realloc(body_buf, reserve);
                        if (!new_buf)
                        {
                            browser_debug_logf(app, "[http] body alloc failed");
                            free(request);
                            close(fd);
                            free(header_buf);
                            free(body_buf);
                            free(chunk);
                            return browser_format_error("alloc body buffer failed");
                        }
                        body_buf = new_buf;
                        body_cap = reserve;
                    }
                }

                if (browser_http_find_header_value(header_buf, header_block_len,
                                                   "content-type",
                                                   &value, &value_len))
                {
                    char type_buf[96];
                    size_t copy = value_len;
                    if (copy >= sizeof(type_buf))
                    {
                        copy = sizeof(type_buf) - 1;
                    }
                    memcpy(type_buf, value, copy);
                    type_buf[copy] = '\0';
                    browser_debug_logf(app, "[http] content-type %s", type_buf);
                }

                if (browser_http_find_header_value(header_buf, header_block_len,
                                                   "location",
                                                   &value, &value_len))
                {
                    location_value = value;
                    location_len = value_len;
                    char loc_buf[160];
                    size_t copy = value_len;
                    if (copy >= sizeof(loc_buf))
                    {
                        copy = sizeof(loc_buf) - 1;
                    }
                    memcpy(loc_buf, value, copy);
                    loc_buf[copy] = '\0';
                    browser_debug_logf(app, "[http] location %s", loc_buf);
                }

                if (!redirect_target &&
                    (status == 301 || status == 302 || status == 303 || status == 307 || status == 308) &&
                    location_value && location_len > 0 && location_value[0] != '#')
                {
                    if (redirect_depth >= BROWSER_MAX_REDIRECTS)
                    {
                        free(request);
                        close(fd);
                        free(header_buf);
                        free(body_buf);
                        free(chunk);
                        return browser_format_error("too many redirects");
                    }
                    redirect_target = browser_build_absolute_url(url, location_value, location_len);
                    if (!redirect_target)
                    {
                        free(request);
                        close(fd);
                        free(header_buf);
                        free(body_buf);
                        free(chunk);
                        return browser_format_error("redirect allocation failed");
                    }
                    redirect_status = status;
                    browser_debug_logf(app, "[http] redirect %d -> %s", status, redirect_target);
                    serial_printf("[http] redirect %d url=%s", status, redirect_target);

                    free(header_buf);
                    header_buf = NULL;
                    header_len = 0;
                    header_cap = 0;
                    break;
                }

                browser_debug_logf(app,
                                   "[http] transfer=%s content-length=%u",
                                   is_chunked ? "chunked" : "identity",
                                   have_content_length ? (unsigned)content_length : 0u);
                serial_printf("[http] transfer=%s content-length=%u",
                              is_chunked ? "chunked" : "identity",
                              have_content_length ? (unsigned)content_length : 0u);

                if (header_len > body_offset)
                {
                    size_t body_bytes = header_len - body_offset;
                    if (is_chunked)
                    {
                        bool done = false;
                        if (!browser_chunked_consume(&chunked, &body_buf, &body_len, &body_cap,
                                                     (const uint8_t *)header_buf + body_offset,
                                                     body_bytes,
                                                     &done))
                        {
                            browser_debug_logf(app, "[http] response too large");
                            free(request);
                            close(fd);
                            free(header_buf);
                            free(body_buf);
                            free(chunk);
                            return browser_format_error("invalid chunked body");
                        }
                        if (done)
                        {
                            break;
                        }
                    }
                    else
                    {
                        size_t take = body_bytes;
                        if (have_content_length && body_len < content_length)
                        {
                            size_t remaining = content_length - body_len;
                            if (take > remaining)
                            {
                                take = remaining;
                            }
                        }
                        if (take > 0 &&
                            !browser_buf_append(&body_buf, &body_len, &body_cap,
                                                (const uint8_t *)header_buf + body_offset,
                                                take))
                        {
                            free(request);
                            close(fd);
                            free(header_buf);
                            free(body_buf);
                            free(chunk);
                            return browser_format_error("response too large");
                        }
                    }
                }

                free(header_buf);
                header_buf = NULL;
                header_len = 0;
                header_cap = 0;
            }
            else
            {
                if (is_chunked)
                {
                    bool done = false;
                    if (!browser_chunked_consume(&chunked, &body_buf, &body_len, &body_cap,
                                                 chunk, got, &done))
                    {
                        free(request);
                        close(fd);
                        free(body_buf);
                        free(chunk);
                        return browser_format_error("invalid chunked body");
                    }
                    if (done)
                    {
                        break;
                    }
                }
                else
                {
                    size_t take = got;
                    if (have_content_length && body_len < content_length)
                    {
                        size_t remaining = content_length - body_len;
                        if (take > remaining)
                        {
                            take = remaining;
                        }
                    }
                    if (take > 0 &&
                        !browser_buf_append(&body_buf, &body_len, &body_cap, chunk, take))
                    {
                        browser_debug_logf(app, "[http] response too large");
                        free(request);
                        close(fd);
                        free(body_buf);
                        free(chunk);
                        return browser_format_error("response too large");
                    }
                }
            }

            if (!is_chunked &&
                have_content_length &&
                body_len >= content_length)
            {
                break;
            }
        }
    }

    free(request);
    close(fd);
    free(chunk);

    if (header_buf)
    {
        free(header_buf);
        header_buf = NULL;
    }

    if (redirect_target)
    {
        if (body_buf)
        {
            free(body_buf);
            body_buf = NULL;
        }

        browser_url_t next = {0};
        if (!browser_parse_url(redirect_target, &next))
        {
        browser_debug_logf(app, "[http] redirect parse failed");
        serial_printf("[http] redirect parse failed url=%s",
                      redirect_target ? redirect_target : "(null)");
        free(redirect_target);
        return browser_format_error("invalid redirect url");
    }
    browser_debug_logf(app, "[http] follow redirect %d depth=%d url=%s",
                       redirect_status,
                       redirect_depth + 1,
                       redirect_target);
    serial_printf("[http] follow redirect status=%d depth=%d url=%s",
                  redirect_status,
                  redirect_depth + 1,
                  redirect_target);
        free(redirect_target);
        char *res = browser_fetch_http_internal(app,
                                                &next,
                                                redirect_depth + 1,
                                                body_len_out,
                                                final_url_out,
                                                status_out);
        browser_url_destroy(&next);
        return res;
    }

    if (have_content_length && body_len < content_length)
    {
        browser_debug_logf(app, "[http] incomplete body got=%u expected=%u",
                           (unsigned)body_len, (unsigned)content_length);
        serial_printf("[http] incomplete body got=%u expected=%u",
                      (unsigned)body_len, (unsigned)content_length);
        free(body_buf);
        return browser_format_error("incomplete response body");
    }

    if (!body_buf)
    {
        browser_debug_logf(app, "[http] empty response body");
        serial_printf("[http] empty response body");
        return browser_format_error("empty response");
    }

    browser_debug_logf(app, "[http] body bytes=%u", (unsigned)body_len);
    serial_printf("[http] body bytes=%u", (unsigned)body_len);
    if (body_len_out)
    {
        *body_len_out = body_len;
    }
    if (final_url_out)
    {
        (void)browser_url_clone(url, final_url_out);
    }
    if (status_out)
    {
        *status_out = status_code;
    }
    return body_buf;
}

char *browser_fetch_http_with_status(browser_app_t *app,
                                     const browser_url_t *url,
                                     size_t *body_len_out,
                                     browser_url_t *final_url_out,
                                     int *status_out)
{
    browser_url_t final_local = {0};
    browser_url_t *final_url = final_url_out ? final_url_out : &final_local;
    char *url_text = browser_url_to_string(url);
    if (url_text)
    {
        browser_cache_state_t cache_state = BROWSER_CACHE_STATE_MISS;
        size_t cached_len = 0;
        char *cached = browser_cache_read(app, url_text, &cached_len, &cache_state);
        if (cached && cache_state == BROWSER_CACHE_STATE_HIT)
        {
            if (body_len_out)
            {
                *body_len_out = cached_len;
            }
            if (final_url_out)
            {
                (void)browser_url_clone(url, final_url_out);
            }
            if (status_out)
            {
                *status_out = 200;
            }
            free(url_text);
            return cached;
        }
        if (cached && cache_state == BROWSER_CACHE_STATE_STALE)
        {
            char *stale = cached;
            size_t stale_len = cached_len;
            int status_code = 0;
            size_t body_len = 0;
            char *body = browser_fetch_http_internal(app, url, 0, &body_len, final_url, &status_code);
            if (body_len_out)
            {
                *body_len_out = body_len;
            }
            if (status_out)
            {
                *status_out = status_code;
            }

            bool fetch_error = (body == NULL) ||
                               (status_code >= 400) ||
                               (body && strncmp(body, "Error:\n", 6) == 0);
            if (fetch_error)
            {
                browser_debug_logf(app, "[cache] stale use url=%s status=%d", url_text, status_code);
                serial_printf("[cache] stale use url=%s status=%d", url_text, status_code);
                free(body);
                if (!final_url_out)
                {
                    browser_url_destroy(&final_local);
                }
                if (body_len_out)
                {
                    *body_len_out = stale_len;
                }
                if (final_url_out)
                {
                    (void)browser_url_clone(url, final_url_out);
                }
                if (status_out)
                {
                    *status_out = 200;
                }
                free(url_text);
                return stale;
            }
            free(stale);
            if (body && url_text && body_len_out && *body_len_out > 0 &&
                status_code > 0 && status_code < 400 &&
                strncmp(body, "Error:\n", 6) != 0)
            {
                char *final_text = NULL;
                if (final_url && final_url->host && final_url->path)
                {
                    final_text = browser_url_to_string(final_url);
                }
                if (final_text && (!url_text || strcmp(final_text, url_text) != 0))
                {
                    browser_cache_write(app, final_text, (const uint8_t *)body, *body_len_out);
                }
                if (url_text)
                {
                    browser_cache_write(app, url_text, (const uint8_t *)body, *body_len_out);
                }
                free(final_text);
            }
            free(url_text);
            if (!final_url_out)
            {
                browser_url_destroy(&final_local);
            }
            return body;
        }
    }

    int status_code = 0;
    size_t body_len = 0;
    char *body = browser_fetch_http_internal(app, url, 0, &body_len, final_url, &status_code);
    if (body_len_out)
    {
        *body_len_out = body_len;
    }
    if (status_out)
    {
        *status_out = status_code;
    }
    if (body && url_text && body_len_out && *body_len_out > 0 &&
        status_code > 0 && status_code < 400 &&
        strncmp(body, "Error:\n", 6) != 0)
    {
        char *final_text = NULL;
        if (final_url && final_url->host && final_url->path)
        {
            final_text = browser_url_to_string(final_url);
        }
        if (final_text && (!url_text || strcmp(final_text, url_text) != 0))
        {
            browser_cache_write(app, final_text, (const uint8_t *)body, *body_len_out);
        }
        if (url_text)
        {
            browser_cache_write(app, url_text, (const uint8_t *)body, *body_len_out);
        }
        free(final_text);
    }
    free(url_text);
    if (!final_url_out)
    {
        browser_url_destroy(&final_local);
    }
    return body;
}

char *browser_fetch_http(browser_app_t *app,
                         const browser_url_t *url,
                         size_t *body_len_out,
                         browser_url_t *final_url_out)
{
    return browser_fetch_http_with_status(app, url, body_len_out, final_url_out, NULL);
}
