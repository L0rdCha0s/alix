#include "logger.h"

#include "libc.h"
#include "vfs.h"

#define LOGGER_DIR_PATH "/var/log"
#define LOGGER_MAX_PATH 256

static vfs_node_t *logger_file = NULL;
static bool logger_ready = false;

static bool logger_ensure_directory(const char *path);

bool logger_init(void)
{
    if (logger_ready)
    {
        return true;
    }
    if (!vfs_root())
    {
        return false;
    }
    if (!logger_ensure_directory(LOGGER_DIR_PATH))
    {
        return false;
    }

    logger_file = vfs_open_file(vfs_root(), LOGGER_FILE_PATH, true, true);
    if (!logger_file)
    {
        return false;
    }

    logger_ready = true;
    logger_log("logger: initialized");
    return true;
}

bool logger_is_ready(void)
{
    return logger_ready && logger_file;
}

bool logger_write_len(const char *text, size_t len)
{
    if (!logger_is_ready() || !text || len == 0)
    {
        return logger_is_ready();
    }
    return vfs_append(logger_file, text, len);
}

bool logger_write(const char *text)
{
    if (!text)
    {
        return logger_is_ready();
    }
    return logger_write_len(text, strlen(text));
}

bool logger_log(const char *line)
{
    if (!line)
    {
        line = "(null)";
    }
    if (!logger_write(line))
    {
        return false;
    }
    return logger_write_len("\n", 1);
}

static bool logger_ensure_directory(const char *path)
{
    if (!path || path[0] == '\0')
    {
        return false;
    }

    char partial[LOGGER_MAX_PATH];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(partial))
    {
        return false;
    }

    size_t index = 0;
    size_t partial_len = 0;

    if (path[0] != '/')
    {
        partial[partial_len++] = '/';
    }

    while (index < len)
    {
        while (index < len && path[index] == '/')
        {
            index++;
        }
        if (index >= len)
        {
            break;
        }

        if (partial_len == 0 || partial[partial_len - 1] != '/')
        {
            partial[partial_len++] = '/';
        }

        size_t start = index;
        while (index < len && path[index] != '/')
        {
            index++;
        }
        size_t segment_len = index - start;
        if (partial_len + segment_len >= sizeof(partial))
        {
            return false;
        }
        memcpy(partial + partial_len, path + start, segment_len);
        partial_len += segment_len;
        partial[partial_len] = '\0';

        vfs_node_t *node = vfs_resolve(vfs_root(), partial);
        if (!node)
        {
            if (!vfs_mkdir(vfs_root(), partial))
            {
                return false;
            }
        }
        else if (!vfs_is_dir(node))
        {
            return false;
        }
    }
    return true;
}
