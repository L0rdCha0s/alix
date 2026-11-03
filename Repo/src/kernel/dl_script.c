#include "dl_script.h"

#include "libc.h"
#include "vfs.h"

extern const char g_dl_script_content[];
extern const size_t g_dl_script_content_len;
extern const char g_dl_zen_script_content[];
extern const size_t g_dl_zen_script_content_len;

static bool dl_script_install(const char *path, const char *content, size_t content_len)
{
    if (content_len == 0)
    {
        return false;
    }

    vfs_node_t *file = vfs_open_file(vfs_root(), path, false, false);
    if (file)
    {
        size_t size = 0;
        char *data = vfs_data(file, &size);
        if (data && size == content_len &&
            memcmp(data, content, size) == 0)
        {
            return true;
        }
    }

    file = vfs_open_file(vfs_root(), path, true, true);
    if (!file)
    {
        return false;
    }

    if (!vfs_append(file, content, content_len))
    {
        return false;
    }

    return true;
}

bool dl_script_install_default(void)
{
    bool dl_ok = dl_script_install("/usr/bin/dl.sh", g_dl_script_content,
                                   g_dl_script_content_len);
    bool zen_ok = dl_script_install("/usr/bin/dl-zen.sh", g_dl_zen_script_content,
                                    g_dl_zen_script_content_len);
    return dl_ok && zen_ok;
}
