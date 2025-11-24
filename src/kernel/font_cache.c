#include "font_cache.h"

#include "libc.h"
#include "spinlock.h"
#include "user_copy.h"
#include "vfs.h"

#define FONT_CACHE_PATH "/usr/share/fonts/PublicSans.ttf"

static uint8_t *g_font_cache = NULL;
static size_t g_font_cache_size = 0;
static spinlock_t g_font_cache_lock;

static bool font_cache_load(void)
{
    if (g_font_cache && g_font_cache_size > 0)
    {
        return true;
    }

    /* Avoid holding the lock while touching VFS. */
    vfs_node_t *node = vfs_open_file(vfs_root(), FONT_CACHE_PATH, false, false);
    if (!node)
    {
        return false;
    }

    size_t size = 0;
    char *data = vfs_data(node, &size);
    if (!data || size == 0)
    {
        return false;
    }

    uint8_t *copy = (uint8_t *)malloc(size);
    if (!copy)
    {
        return false;
    }
    memcpy(copy, data, size);

    spinlock_lock(&g_font_cache_lock);
    if (!g_font_cache)
    {
        g_font_cache = copy;
        g_font_cache_size = size;
        copy = NULL;
    }
    spinlock_unlock(&g_font_cache_lock);

    if (copy)
    {
        free(copy);
    }

    return g_font_cache && g_font_cache_size > 0;
}

ssize_t font_cache_copy_to_user(void *user_dst, size_t capacity)
{
    if (!font_cache_load())
    {
        return -1;
    }

    size_t size = g_font_cache_size;
    if (!user_dst || capacity == 0)
    {
        return (ssize_t)size;
    }

    size_t copy_bytes = size;
    if (copy_bytes > capacity)
    {
        copy_bytes = capacity;
    }

    if (!user_copy_to_user(user_dst, g_font_cache, copy_bytes))
    {
        return -1;
    }

    return (ssize_t)size;
}

size_t font_cache_size(void)
{
    return font_cache_load() ? g_font_cache_size : 0;
}
