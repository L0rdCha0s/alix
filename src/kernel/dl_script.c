#include "dl_script.h"

#include "libc.h"
#include "vfs.h"

extern const char g_dl_script_content[];
extern const size_t g_dl_script_content_len;

#define DL_SCRIPT_PATH "/usr/bin/dl.sh"

bool dl_script_install_default(void)
{
    if (!g_dl_script_content || g_dl_script_content_len == 0)
    {
        return false;
    }

    vfs_node_t *file = vfs_open_file(vfs_root(), DL_SCRIPT_PATH, false, false);
    if (file)
    {
        size_t size = 0;
        const char *data = vfs_data(file, &size);
        if (data && size == g_dl_script_content_len &&
            memcmp(data, g_dl_script_content, size) == 0)
        {
            return true;
        }
    }

    file = vfs_open_file(vfs_root(), DL_SCRIPT_PATH, true, true);
    if (!file)
    {
        return false;
    }

    if (!vfs_append(file, g_dl_script_content, g_dl_script_content_len))
    {
        return false;
    }

    return true;
}
