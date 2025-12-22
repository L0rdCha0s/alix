#include "atk_user.h"

#include "atk.h"
#include "atk_app.h"
#include "atk_internal.h"
#include "atk_menu_bar.h"
#include "atk_window.h"
#include "atk/atk_list_view.h"
#include "atk/atk_iconbox.h"
#include "atk/atk_tree_view.h"
#include "atk/util/png.h"
#include "libc.h"
#include "stdio.h"
#include "video.h"
#include "usyscall.h"
#include "user_atk_defs.h"

#define ATK_COL(chars) ((chars) * ATK_FONT_WIDTH)

#define FILEMAN_WINDOW_WIDTH  960
#define FILEMAN_WINDOW_HEIGHT 640
#define FILEMAN_MARGIN 12
#define FILEMAN_TREE_MIN_WIDTH 200
#define FILEMAN_TREE_MAX_WIDTH 320
#define FILEMAN_PATH_MAX 512
#define FILEMAN_MAX_ENTRIES 256
#define FILEMAN_DBLCLICK_MS 500
#define FILEMAN_CLICK_DEBOUNCE_MS 150
#define FILEMAN_VIEW_BUTTON_HEIGHT 24
#define FILEMAN_VIEW_BUTTON_WIDTH 80
#define FILEMAN_VIEW_BUTTON_GAP 8
#define FILEMAN_VIEW_BUTTON_SPACING 8
#define FILEMAN_ICON_BASE "/usr/share/icons/48x48"
#define FILEMAN_ICON_MIMETYPE_DIR FILEMAN_ICON_BASE "/mimetypes"
#define FILEMAN_PREVIEW_ELF "/usr/bin/atk_preview.elf"

typedef struct fileman_app fileman_app_t;

typedef struct
{
    fileman_app_t *app;
    char name[SYSCALL_DIR_NAME_MAX];
    char path[FILEMAN_PATH_MAX];
    uint64_t size_bytes;
    const atk_iconbox_image_t *icon;
    bool is_dir;
    bool is_elf;
    bool is_image;
} fileman_entry_t;

typedef struct
{
    char *path;
    video_color_t *pixels;
    atk_iconbox_image_t image;
} fileman_icon_cache_entry_t;

typedef struct
{
    fileman_icon_cache_entry_t *entries;
    size_t count;
    size_t capacity;
} fileman_icon_cache_t;

struct fileman_app
{
    atk_user_window_t remote;
    atk_widget_t *window;
    atk_widget_t *tree;
    atk_widget_t *list_button;
    atk_widget_t *icon_button;
    atk_widget_t *list_view;
    atk_widget_t *iconbox;
    int shell_handle;
    char current_path[FILEMAN_PATH_MAX];
    fileman_entry_t *entries;
    size_t entry_count;
    fileman_icon_cache_t icon_cache;
    const fileman_entry_t *last_click_entry;
    uint64_t last_click_ms;
    size_t view_mode;
    bool running;
};

enum
{
    FILEMAN_VIEW_LIST = 0,
    FILEMAN_VIEW_ICONS = 1
};

static void fileman_tree_on_select(atk_widget_t *tree, void *context, atk_tree_node_t *node);
static void fileman_icon_action(atk_widget_t *button, void *context);
static void fileman_set_view_mode(fileman_app_t *app, size_t mode);

static char *fileman_strdup(const char *src)
{
    if (!src)
    {
        return NULL;
    }
    size_t len = strlen(src);
    char *dst = (char *)malloc(len + 1);
    if (!dst)
    {
        return NULL;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
    return dst;
}

static bool fileman_is_dot_entry(const char *name)
{
    if (!name)
    {
        return true;
    }
    return (strcmp(name, ".") == 0 || strcmp(name, "..") == 0);
}

static bool fileman_has_extension(const char *name, const char *ext)
{
    if (!name || !ext)
    {
        return false;
    }
    const char *dot = strrchr(name, '.');
    if (!dot)
    {
        return false;
    }
    return strcasecmp(dot, ext) == 0;
}

static bool fileman_is_image_name(const char *name)
{
    return fileman_has_extension(name, ".png") ||
           fileman_has_extension(name, ".jpg") ||
           fileman_has_extension(name, ".jpeg");
}

static bool fileman_has_suffix(const char *name, const char *suffix)
{
    if (!name || !suffix)
    {
        return false;
    }
    size_t name_len = strlen(name);
    size_t suffix_len = strlen(suffix);
    if (suffix_len == 0 || suffix_len > name_len)
    {
        return false;
    }
    return strcasecmp(name + (name_len - suffix_len), suffix) == 0;
}

static void fileman_join_path(char *dst, size_t cap, const char *base, const char *name)
{
    if (!dst || cap == 0)
    {
        return;
    }
    const char *root = (base && base[0]) ? base : "/";
    if (strcmp(root, "/") == 0)
    {
        snprintf(dst, cap, "/%s", name ? name : "");
    }
    else
    {
        snprintf(dst, cap, "%s/%s", root, name ? name : "");
    }
    dst[cap - 1] = '\0';
}

static void fileman_normalize_path(char *path)
{
    if (!path || path[0] == '\0')
    {
        return;
    }
    size_t len = strlen(path);
    while (len > 1 && path[len - 1] == '/')
    {
        path[len - 1] = '\0';
        len--;
    }
}

typedef struct
{
    const char *suffix;
    const char *icon_name;
} fileman_icon_map_t;

static const fileman_icon_map_t FILEMAN_ICON_MAP[] = {
    { ".tar.gz", "application-x-compressed-tar.png" },
    { ".tgz", "application-x-compressed-tar.png" },
    { ".tar.bz2", "application-x-bzip-compressed-tar.png" },
    { ".tbz2", "application-x-bzip-compressed-tar.png" },
    { ".tbz", "application-x-bzip-compressed-tar.png" },
    { ".tar.xz", "application-x-lzma-compressed-tar.png" },
    { ".txz", "application-x-lzma-compressed-tar.png" },
    { ".7z", "application-x-7z-compressed.png" },
    { ".zip", "application-zip.png" },
    { ".rar", "application-x-rar.png" },
    { ".tar", "application-x-tar.png" },
    { ".gz", "application-x-gzip.png" },
    { ".bz2", "application-x-bzip.png" },
    { ".xz", "application-x-lzma-compressed-tar.png" },
    { ".epub", "application-epub+zip.png" },
    { ".pdf", "application-pdf.png" },
    { ".ps", "application-postscript.png" },
    { ".rtf", "application-rtf.png" },
    { ".doc", "application-msword.png" },
    { ".docx", "application-vnd.openxmlformats-officedocument.wordprocessingml.document.png" },
    { ".odt", "application-vnd.oasis.opendocument.text.png" },
    { ".xls", "application-vnd.ms-excel.png" },
    { ".xlsx", "application-vnd.ms-excel.png" },
    { ".ods", "application-vnd.oasis.opendocument.spreadsheet.png" },
    { ".ppt", "application-vnd.ms-powerpoint.png" },
    { ".pptx", "application-vnd.ms-powerpoint.png" },
    { ".odp", "application-vnd.oasis.opendocument.presentation.png" },
    { ".iso", "application-x-cd-image.png" },
    { ".c", "text-x-csrc.png" },
    { ".h", "text-x-chdr.png" },
    { ".cc", "text-x-c++src.png" },
    { ".cpp", "text-x-c++src.png" },
    { ".hh", "text-x-c++hdr.png" },
    { ".hpp", "text-x-c++hdr.png" },
    { ".py", "text-x-python.png" },
    { ".js", "application-javascript.png" },
    { ".css", "text-css.png" },
    { ".html", "text-html.png" },
    { ".htm", "text-html.png" },
    { ".xml", "text-xml.png" },
    { ".csv", "text-csv.png" },
    { ".md", "text-x-readme.png" },
    { ".txt", "text-plain.png" },
    { ".log", "text-x-log.png" },
    { ".sh", "application-x-shellscript.png" },
    { ".bash", "application-x-shellscript.png" },
    { ".exe", "application-x-ms-dos-executable.png" },
    { ".elf", "application-x-executable.png" },
    { ".png", "image-x-generic.png" },
    { ".jpg", "image-x-generic.png" },
    { ".jpeg", "image-x-generic.png" },
    { ".gif", "image-x-generic.png" },
    { ".bmp", "image-x-generic.png" },
    { ".svg", "image-svg+xml.png" },
    { ".mp3", "audio-x-generic.png" },
    { ".wav", "audio-x-wav.png" },
    { ".flac", "audio-x-flac.png" },
    { ".ogg", "audio-x-generic.png" },
    { ".mp4", "video-x-generic.png" },
    { ".mkv", "video-x-generic.png" },
    { ".avi", "video-x-generic.png" },
    { ".mov", "video-x-generic.png" },
};

static bool fileman_path_is_dir(const char *path)
{
    if (!path || !path[0])
    {
        return false;
    }
    syscall_dirent_t *scratch = (syscall_dirent_t *)malloc(sizeof(syscall_dirent_t));
    if (!scratch)
    {
        return false;
    }
    ssize_t count = sys_list_dir(path, scratch, 1);
    free(scratch);
    return count >= 0;
}

static bool fileman_dirent_is_dir(const syscall_dirent_t *ent, const char *path)
{
    if (!ent || !path)
    {
        return false;
    }
    if (ent->type == SYSCALL_NODE_TYPE_DIR)
    {
        return true;
    }
    if (ent->type != SYSCALL_NODE_TYPE_SYMLINK)
    {
        return false;
    }
    return fileman_path_is_dir(path);
}

static fileman_icon_cache_entry_t *fileman_icon_cache_alloc(fileman_app_t *app)
{
    if (!app)
    {
        return NULL;
    }
    if (app->icon_cache.count == app->icon_cache.capacity)
    {
        size_t next_capacity = app->icon_cache.capacity ? app->icon_cache.capacity * 2 : 8;
        fileman_icon_cache_entry_t *next_entries = (fileman_icon_cache_entry_t *)realloc(app->icon_cache.entries,
                                                                                          next_capacity * sizeof(fileman_icon_cache_entry_t));
        if (!next_entries)
        {
            return NULL;
        }
        app->icon_cache.entries = next_entries;
        app->icon_cache.capacity = next_capacity;
    }
    fileman_icon_cache_entry_t *entry = &app->icon_cache.entries[app->icon_cache.count];
    memset(entry, 0, sizeof(*entry));
    app->icon_cache.count++;
    return entry;
}

static const atk_iconbox_image_t *fileman_icon_cache_load(fileman_app_t *app, const char *path)
{
    if (!app || !path || !path[0])
    {
        return NULL;
    }
    for (size_t i = 0; i < app->icon_cache.count; ++i)
    {
        fileman_icon_cache_entry_t *entry = &app->icon_cache.entries[i];
        if (entry->path && strcmp(entry->path, path) == 0)
        {
            return entry->pixels ? &entry->image : NULL;
        }
    }

    FILE *fp = fopen(path, "rb");
    if (!fp)
    {
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0)
    {
        fclose(fp);
        return NULL;
    }
    long size_long = ftell(fp);
    if (size_long <= 0)
    {
        fclose(fp);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_SET) != 0)
    {
        fclose(fp);
        return NULL;
    }

    size_t size = (size_t)size_long;
    uint8_t *data = (uint8_t *)malloc(size);
    if (!data)
    {
        fclose(fp);
        return NULL;
    }
    size_t read = fread(data, 1, size, fp);
    fclose(fp);
    if (read != size)
    {
        free(data);
        return NULL;
    }

    video_color_t *pixels = NULL;
    int width = 0;
    int height = 0;
    int stride_bytes = 0;
    int rc = png_decode_rgba32(data, size, &pixels, &width, &height, &stride_bytes);
    free(data);
    if (rc != 0 || !pixels)
    {
        return NULL;
    }

    fileman_icon_cache_entry_t *entry = fileman_icon_cache_alloc(app);
    if (!entry)
    {
        free(pixels);
        return NULL;
    }
    entry->path = fileman_strdup(path);
    if (!entry->path)
    {
        app->icon_cache.count--;
        free(pixels);
        return NULL;
    }
    entry->pixels = pixels;
    entry->image.pixels = pixels;
    entry->image.width = width;
    entry->image.height = height;
    entry->image.stride_bytes = stride_bytes;
    entry->image.use_alpha = true;
    return &entry->image;
}

static void fileman_icon_cache_clear(fileman_app_t *app)
{
    if (!app)
    {
        return;
    }
    for (size_t i = 0; i < app->icon_cache.count; ++i)
    {
        fileman_icon_cache_entry_t *entry = &app->icon_cache.entries[i];
        free(entry->pixels);
        free(entry->path);
    }
    free(app->icon_cache.entries);
    app->icon_cache.entries = NULL;
    app->icon_cache.count = 0;
    app->icon_cache.capacity = 0;
}

static const char *fileman_icon_name_for_file(const char *name)
{
    if (!name)
    {
        return "unknown.png";
    }
    for (size_t i = 0; i < sizeof(FILEMAN_ICON_MAP) / sizeof(FILEMAN_ICON_MAP[0]); ++i)
    {
        if (fileman_has_suffix(name, FILEMAN_ICON_MAP[i].suffix))
        {
            return FILEMAN_ICON_MAP[i].icon_name;
        }
    }
    return "unknown.png";
}

static const atk_iconbox_image_t *fileman_icon_for_entry(fileman_app_t *app, const fileman_entry_t *entry)
{
    if (!app || !entry)
    {
        return NULL;
    }
    const char *icon_name = NULL;
    if (entry->is_dir)
    {
        icon_name = "inode-directory.png";
    }
    else if (entry->is_elf)
    {
        icon_name = "application-x-executable.png";
    }
    else
    {
        icon_name = fileman_icon_name_for_file(entry->name);
    }

    char path[FILEMAN_PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", FILEMAN_ICON_MIMETYPE_DIR, icon_name);
    path[sizeof(path) - 1] = '\0';
    const atk_iconbox_image_t *icon = fileman_icon_cache_load(app, path);
    if (icon)
    {
        return icon;
    }

    snprintf(path, sizeof(path), "%s/unknown.png", FILEMAN_ICON_MIMETYPE_DIR);
    path[sizeof(path) - 1] = '\0';
    return fileman_icon_cache_load(app, path);
}

static void fileman_entries_clear(fileman_app_t *app)
{
    if (!app)
    {
        return;
    }
    free(app->entries);
    app->entries = NULL;
    app->entry_count = 0;
}

static void fileman_sort_entries(fileman_entry_t *entries, size_t count)
{
    if (!entries || count < 2)
    {
        return;
    }
    for (size_t i = 0; i + 1 < count; ++i)
    {
        for (size_t j = i + 1; j < count; ++j)
        {
            fileman_entry_t *a = &entries[i];
            fileman_entry_t *b = &entries[j];
            if (a->is_dir != b->is_dir)
            {
                if (!a->is_dir && b->is_dir)
                {
                    fileman_entry_t tmp = *a;
                    *a = *b;
                    *b = tmp;
                }
                continue;
            }
            if (strcmp(a->name, b->name) > 0)
            {
                fileman_entry_t tmp = *a;
                *a = *b;
                *b = tmp;
            }
        }
    }
}

static void fileman_format_size(char *dst, size_t cap, const fileman_entry_t *entry)
{
    if (!dst || cap == 0)
    {
        return;
    }
    if (!entry)
    {
        dst[0] = '\0';
        return;
    }
    if (entry->is_dir)
    {
        snprintf(dst, cap, "<DIR>");
    }
    else
    {
        snprintf(dst, cap, "%llu", (unsigned long long)entry->size_bytes);
    }
    dst[cap - 1] = '\0';
}

static void fileman_update_title(fileman_app_t *app)
{
    if (!app || !app->window)
    {
        return;
    }
    char title[128];
    const char *path = app->current_path[0] ? app->current_path : "/";
    snprintf(title, sizeof(title), "File Manager - %s", path);
    title[sizeof(title) - 1] = '\0';
    atk_window_set_title_text(app->window, title);
}

static void fileman_apply_view_state(fileman_app_t *app)
{
    if (!app)
    {
        return;
    }
    bool list_active = (app->view_mode == FILEMAN_VIEW_LIST);
    if (app->list_view)
    {
        atk_list_view_set_active(app->list_view, list_active);
    }
    if (app->iconbox)
    {
        atk_iconbox_set_active(app->iconbox, !list_active);
    }
}

static void fileman_refresh_right_view(fileman_app_t *app)
{
    if (!app || !app->list_view || !app->iconbox)
    {
        return;
    }

    atk_list_view_clear(app->list_view);
    atk_iconbox_clear(app->iconbox);
    fileman_entries_clear(app);
    app->last_click_entry = NULL;
    app->last_click_ms = 0;

    syscall_dirent_t entries[FILEMAN_MAX_ENTRIES];
    const char *path = app->current_path[0] ? app->current_path : "/";
    ssize_t count = sys_list_dir(path, entries, FILEMAN_MAX_ENTRIES);
    if (count <= 0)
    {
        atk_list_view_set_row_count(app->list_view, 0);
        atk_list_view_relayout(app->list_view);
        atk_iconbox_relayout(app->iconbox);
        fileman_apply_view_state(app);
        if (app->window)
        {
            atk_window_mark_dirty(app->window);
        }
        return;
    }

    size_t visible = 0;
    for (ssize_t i = 0; i < count; ++i)
    {
        if (!fileman_is_dot_entry(entries[i].name))
        {
            visible++;
        }
    }

    if (visible == 0)
    {
        atk_list_view_set_row_count(app->list_view, 0);
        atk_list_view_relayout(app->list_view);
        atk_iconbox_relayout(app->iconbox);
        fileman_apply_view_state(app);
        if (app->window)
        {
            atk_window_mark_dirty(app->window);
        }
        return;
    }

    app->entries = (fileman_entry_t *)calloc(visible, sizeof(fileman_entry_t));
    if (!app->entries)
    {
        atk_list_view_set_row_count(app->list_view, 0);
        atk_list_view_relayout(app->list_view);
        atk_iconbox_relayout(app->iconbox);
        fileman_apply_view_state(app);
        if (app->window)
        {
            atk_window_mark_dirty(app->window);
        }
        return;
    }

    size_t out = 0;
    for (ssize_t i = 0; i < count && out < visible; ++i)
    {
        syscall_dirent_t *ent = &entries[i];
        if (fileman_is_dot_entry(ent->name))
        {
            continue;
        }
        fileman_entry_t *dst = &app->entries[out++];
        dst->app = app;
        size_t name_len = strlen(ent->name);
        if (name_len >= sizeof(dst->name))
        {
            name_len = sizeof(dst->name) - 1;
        }
        memcpy(dst->name, ent->name, name_len);
        dst->name[name_len] = '\0';
        fileman_join_path(dst->path, sizeof(dst->path), path, dst->name);
        dst->size_bytes = ent->size_bytes;
        dst->is_dir = fileman_dirent_is_dir(ent, dst->path);
        dst->is_elf = (!dst->is_dir && fileman_has_extension(dst->name, ".elf"));
        dst->is_image = (!dst->is_dir && fileman_is_image_name(dst->name));
        dst->icon = fileman_icon_for_entry(app, dst);
    }

    app->entry_count = out;
    fileman_sort_entries(app->entries, app->entry_count);

    atk_list_view_set_row_count(app->list_view, app->entry_count);
    for (size_t i = 0; i < app->entry_count; ++i)
    {
        fileman_entry_t *entry = &app->entries[i];
        atk_list_view_set_cell_text(app->list_view, i, 0, entry->name);
        char size_buf[32];
        fileman_format_size(size_buf, sizeof(size_buf), entry);
        atk_list_view_set_cell_text(app->list_view, i, 1, size_buf);
    }
    atk_list_view_set_selected(app->list_view, ATK_LIST_VIEW_NO_SELECTION);
    atk_list_view_relayout(app->list_view);

    for (size_t i = 0; i < app->entry_count; ++i)
    {
        fileman_entry_t *entry = &app->entries[i];
        atk_iconbox_add_icon_with_image(app->iconbox, entry->name, entry->icon, fileman_icon_action, entry);
    }
    atk_iconbox_relayout(app->iconbox);

    fileman_apply_view_state(app);
    if (app->window)
    {
        atk_window_mark_dirty(app->window);
    }
}

static void fileman_set_current_path(fileman_app_t *app, const char *path)
{
    if (!app || !path)
    {
        return;
    }
    size_t len = strlen(path);
    if (len >= sizeof(app->current_path))
    {
        len = sizeof(app->current_path) - 1;
    }
    memcpy(app->current_path, path, len);
    app->current_path[len] = '\0';
    fileman_normalize_path(app->current_path);
    fileman_update_title(app);
    fileman_refresh_right_view(app);
}

static bool fileman_is_double_click(fileman_app_t *app, const fileman_entry_t *entry)
{
    if (!app || !entry)
    {
        return false;
    }
    uint64_t now = sys_time_millis();
    uint64_t delta = (app->last_click_ms > 0) ? (now - app->last_click_ms) : (uint64_t)-1;
    if (delta < FILEMAN_CLICK_DEBOUNCE_MS)
    {
        return false;
    }
    bool is_double = (app->last_click_entry == entry) && (delta <= FILEMAN_DBLCLICK_MS);
    app->last_click_entry = entry;
    app->last_click_ms = now;
    return is_double;
}

static void fileman_run_elf(fileman_app_t *app, const char *path)
{
    if (!app || !path || !path[0])
    {
        return;
    }
    if (app->shell_handle < 0)
    {
        return;
    }
    char command[FILEMAN_PATH_MAX + 16];
    snprintf(command, sizeof(command), "runelf %s", path);
    command[sizeof(command) - 1] = '\0';
    sys_shell_exec(app->shell_handle, command, 0);
}

static void fileman_run_preview(fileman_app_t *app, const char *path)
{
    if (!app || !path || !path[0])
    {
        return;
    }
    if (app->shell_handle < 0)
    {
        return;
    }
    char command[FILEMAN_PATH_MAX + 64];
    snprintf(command, sizeof(command), "runelf %s %s", FILEMAN_PREVIEW_ELF, path);
    command[sizeof(command) - 1] = '\0';
    sys_shell_exec(app->shell_handle, command, 0);
}

static void fileman_open_entry(fileman_app_t *app, fileman_entry_t *entry)
{
    if (!app || !entry)
    {
        return;
    }
    if (entry->is_dir)
    {
        atk_tree_node_t *current = atk_tree_view_selected(app->tree);
        atk_tree_node_t *child = current ? atk_tree_view_node_find_child(current, entry->name) : NULL;
        if (child)
        {
            atk_tree_view_set_selected(app->tree, child);
            fileman_tree_on_select(app->tree, app, child);
        }
        else
        {
            fileman_set_current_path(app, entry->path);
        }
        return;
    }
    if (entry->is_image)
    {
        fileman_run_preview(app, entry->path);
        return;
    }
    if (entry->is_elf)
    {
        fileman_run_elf(app, entry->path);
    }
}

static bool fileman_tree_lazy_load(atk_widget_t *tree, void *context, atk_tree_node_t *node)
{
    (void)context;
    if (!tree || !node)
    {
        return true;
    }
    const char *path = (const char *)atk_tree_view_node_user(node);
    if (!path || !path[0])
    {
        return true;
    }

    syscall_dirent_t entries[FILEMAN_MAX_ENTRIES];
    ssize_t count = sys_list_dir(path, entries, FILEMAN_MAX_ENTRIES);
    if (count <= 0)
    {
        atk_tree_view_set_node_expandable(node, false);
        return true;
    }

    bool added = false;
    for (ssize_t i = 0; i < count; ++i)
    {
        syscall_dirent_t *ent = &entries[i];
        if (fileman_is_dot_entry(ent->name))
        {
            continue;
        }
        char child_path[FILEMAN_PATH_MAX];
        fileman_join_path(child_path, sizeof(child_path), path, ent->name);
        if (!fileman_dirent_is_dir(ent, child_path))
        {
            continue;
        }
        char *path_copy = fileman_strdup(child_path);
        if (!path_copy)
        {
            continue;
        }
        atk_tree_node_t *child = atk_tree_view_add_child(tree, node, ent->name, path_copy);
        if (!child)
        {
            free(path_copy);
            continue;
        }
        atk_tree_view_set_node_expandable(child, true);
        added = true;
    }
    if (!added)
    {
        atk_tree_view_set_node_expandable(node, false);
    }
    return true;
}

static void fileman_tree_destroy_node(atk_widget_t *tree, void *context, atk_tree_node_t *node)
{
    (void)tree;
    (void)context;
    if (!node)
    {
        return;
    }
    char *path = (char *)atk_tree_view_node_user(node);
    free(path);
}

static void fileman_tree_on_select(atk_widget_t *tree, void *context, atk_tree_node_t *node)
{
    fileman_app_t *app = (fileman_app_t *)context;
    if (!app || !tree || !node)
    {
        return;
    }
    atk_tree_view_set_node_expanded(tree, node, true);
    const char *path = (const char *)atk_tree_view_node_user(node);
    if (path && path[0])
    {
        fileman_set_current_path(app, path);
    }
}

static void fileman_list_on_select(atk_widget_t *list, void *context, size_t row)
{
    (void)list;
    fileman_app_t *app = (fileman_app_t *)context;
    if (!app || row >= app->entry_count)
    {
        return;
    }
    fileman_entry_t *entry = &app->entries[row];
    if (fileman_is_double_click(app, entry))
    {
        fileman_open_entry(app, entry);
    }
}

static void fileman_icon_action(atk_widget_t *button, void *context)
{
    (void)button;
    fileman_entry_t *entry = (fileman_entry_t *)context;
    fileman_app_t *app = entry ? entry->app : NULL;
    if (!app || !entry)
    {
        return;
    }
    if (fileman_is_double_click(app, entry))
    {
        fileman_open_entry(app, entry);
    }
}

static void fileman_set_view_mode(fileman_app_t *app, size_t index)
{
    if (!app)
    {
        return;
    }
    if (index > FILEMAN_VIEW_ICONS)
    {
        index = FILEMAN_VIEW_LIST;
    }
    app->view_mode = index;
    fileman_apply_view_state(app);
    if (app->view_mode == FILEMAN_VIEW_LIST && app->list_view)
    {
        atk_list_view_relayout(app->list_view);
    }
    else if (app->view_mode == FILEMAN_VIEW_ICONS && app->iconbox)
    {
        atk_iconbox_relayout(app->iconbox);
    }
    if (app->window)
    {
        atk_window_mark_dirty(app->window);
    }
}

static void fileman_list_view_action(atk_widget_t *button, void *context)
{
    (void)button;
    fileman_set_view_mode((fileman_app_t *)context, FILEMAN_VIEW_LIST);
}

static void fileman_icon_view_action(atk_widget_t *button, void *context)
{
    (void)button;
    fileman_set_view_mode((fileman_app_t *)context, FILEMAN_VIEW_ICONS);
}

static void fileman_layout(fileman_app_t *app)
{
    if (!app || !app->window || !app->tree || !app->list_view || !app->iconbox)
    {
        return;
    }

    int chrome_top = atk_window_is_chrome_visible(app->window) ? ATK_WINDOW_TITLE_HEIGHT : 0;
    int content_x = FILEMAN_MARGIN;
    int content_y = chrome_top + FILEMAN_MARGIN;
    int content_w = app->window->width - FILEMAN_MARGIN * 2;
    int content_h = app->window->height - chrome_top - FILEMAN_MARGIN * 2;
    if (content_w < 0)
    {
        content_w = 0;
    }
    if (content_h < 0)
    {
        content_h = 0;
    }

    int tree_w = content_w / 3;
    if (tree_w < FILEMAN_TREE_MIN_WIDTH)
    {
        tree_w = FILEMAN_TREE_MIN_WIDTH;
    }
    if (tree_w > FILEMAN_TREE_MAX_WIDTH)
    {
        tree_w = FILEMAN_TREE_MAX_WIDTH;
    }
    if (tree_w > content_w)
    {
        tree_w = content_w;
    }
    int right_w = content_w - tree_w - FILEMAN_MARGIN;
    if (right_w < 0)
    {
        right_w = 0;
    }

    app->tree->x = content_x;
    app->tree->y = content_y;
    app->tree->width = tree_w;
    app->tree->height = content_h;

    int right_x = content_x + tree_w + FILEMAN_MARGIN;
    int right_y = content_y;
    int right_h = content_h;

    int button_w = FILEMAN_VIEW_BUTTON_WIDTH;
    int button_h = FILEMAN_VIEW_BUTTON_HEIGHT;
    if (right_w > 0 && right_w < button_w * 2 + FILEMAN_VIEW_BUTTON_GAP)
    {
        button_w = (right_w - FILEMAN_VIEW_BUTTON_GAP) / 2;
        if (button_w < 0)
        {
            button_w = 0;
        }
    }
    if (button_h > right_h)
    {
        button_h = right_h;
    }

    if (app->list_button)
    {
        app->list_button->x = right_x;
        app->list_button->y = right_y;
        app->list_button->width = button_w;
        app->list_button->height = button_h;
    }
    if (app->icon_button)
    {
        app->icon_button->x = right_x + button_w + FILEMAN_VIEW_BUTTON_GAP;
        app->icon_button->y = right_y;
        app->icon_button->width = button_w;
        app->icon_button->height = button_h;
    }

    int view_y = right_y + button_h + FILEMAN_VIEW_BUTTON_SPACING;
    int view_h = right_h - (button_h + FILEMAN_VIEW_BUTTON_SPACING);
    if (view_h < 0)
    {
        view_h = 0;
    }

    atk_tree_view_relayout(app->tree);
    app->list_view->x = right_x;
    app->list_view->y = view_y;
    app->list_view->width = right_w;
    app->list_view->height = view_h;
    atk_list_view_relayout(app->list_view);

    app->iconbox->x = right_x;
    app->iconbox->y = view_y;
    app->iconbox->width = right_w;
    app->iconbox->height = view_h;
    atk_iconbox_relayout(app->iconbox);
    fileman_apply_view_state(app);
    atk_window_mark_dirty(app->window);
}

static bool fileman_init_ui(fileman_app_t *app)
{
    if (!app)
    {
        return false;
    }

    atk_init();
    atk_state_t *state = atk_state_get();
    atk_menu_bar_set_enabled(state, false);

    atk_widget_t *window = atk_window_create_at(state, FILEMAN_WINDOW_WIDTH / 2, FILEMAN_WINDOW_HEIGHT / 2);
    if (!window)
    {
        return false;
    }
    atk_window_set_title_text(window, "File Manager");
    atk_window_set_chrome_visible(window, false);
    window->x = 0;
    window->y = 0;
    window->width = FILEMAN_WINDOW_WIDTH;
    window->height = FILEMAN_WINDOW_HEIGHT;

    atk_widget_t *tree = atk_window_add_tree_view(window, 0, 0, 100, 100);
    if (!tree)
    {
        return false;
    }

    atk_widget_t *list_view = atk_window_add_list_view(window, 0, 0, 100, 100);
    if (!list_view)
    {
        return false;
    }
    static const atk_list_view_column_def_t FILEMAN_COLUMNS[] = {
        { "Name", 0 },
        { "Size", ATK_COL(10) },
    };
    atk_list_view_configure_columns(list_view, FILEMAN_COLUMNS, sizeof(FILEMAN_COLUMNS) / sizeof(FILEMAN_COLUMNS[0]));
    atk_list_view_force_vertical_scrollbar(list_view, true);
    atk_list_view_set_select_handler(list_view, fileman_list_on_select, app);

    atk_widget_t *iconbox = atk_window_add_iconbox(window, 0, 0, 100, 100);
    if (!iconbox)
    {
        return false;
    }

    atk_widget_t *list_button = atk_window_add_button(window,
                                                      "List",
                                                      0,
                                                      0,
                                                      FILEMAN_VIEW_BUTTON_WIDTH,
                                                      FILEMAN_VIEW_BUTTON_HEIGHT,
                                                      ATK_BUTTON_STYLE_TITLE_INSIDE,
                                                      false,
                                                      fileman_list_view_action,
                                                      app);
    if (!list_button)
    {
        return false;
    }

    atk_widget_t *icon_button = atk_window_add_button(window,
                                                      "Icons",
                                                      0,
                                                      0,
                                                      FILEMAN_VIEW_BUTTON_WIDTH,
                                                      FILEMAN_VIEW_BUTTON_HEIGHT,
                                                      ATK_BUTTON_STYLE_TITLE_INSIDE,
                                                      false,
                                                      fileman_icon_view_action,
                                                      app);
    if (!icon_button)
    {
        return false;
    }

    atk_tree_view_set_select_handler(tree, fileman_tree_on_select, app);
    atk_tree_view_set_lazy_load_handler(tree, fileman_tree_lazy_load, app);
    atk_tree_view_set_node_destroy_handler(tree, fileman_tree_destroy_node, app);

    char *root_path = fileman_strdup("/");
    atk_tree_node_t *root = atk_tree_view_add_root(tree, "/", root_path);
    if (!root)
    {
        free(root_path);
        return false;
    }
    atk_tree_view_set_node_expandable(root, true);
    atk_tree_view_set_selected(tree, root);

    app->window = window;
    app->tree = tree;
    app->list_button = list_button;
    app->icon_button = icon_button;
    app->list_view = list_view;
    app->iconbox = iconbox;
    app->view_mode = FILEMAN_VIEW_LIST;

    fileman_layout(app);
    fileman_set_view_mode(app, FILEMAN_VIEW_LIST);
    fileman_tree_on_select(tree, app, root);
    return true;
}

static bool fileman_on_resize_event(uint32_t width, uint32_t height, void *context)
{
    fileman_app_t *app = (fileman_app_t *)context;
    if (!app || !app->window)
    {
        return false;
    }
    app->window->width = (int)width;
    app->window->height = (int)height;
    atk_window_request_layout(app->window);
    fileman_layout(app);
    return true;
}

static void fileman_on_close_event(void *context)
{
    fileman_app_t *app = (fileman_app_t *)context;
    if (app)
    {
        app->running = false;
    }
    atk_main_request_exit();
}

int main(void)
{
    fileman_app_t app;
    memset(&app, 0, sizeof(app));
    app.shell_handle = sys_shell_open();
    app.running = true;

    if (!atk_user_window_open_with_flags(&app.remote,
                                         "File Manager",
                                         FILEMAN_WINDOW_WIDTH,
                                         FILEMAN_WINDOW_HEIGHT,
                                         USER_ATK_WINDOW_FLAG_RESIZABLE))
    {
        printf("atk_fileman: failed to open remote window\n");
        if (app.shell_handle >= 0)
        {
            sys_shell_close(app.shell_handle);
        }
        return 1;
    }
    atk_user_enable_dirty_tracking(&app.remote, true);

    if (!fileman_init_ui(&app))
    {
        printf("atk_fileman: failed to init UI\n");
        atk_user_close(&app.remote);
        if (app.shell_handle >= 0)
        {
            sys_shell_close(app.shell_handle);
        }
        return 1;
    }

    atk_render();
    atk_user_present_force(&app.remote);

    atk_main_config_t main_cfg = {
        .window = &app.remote,
        .tick = NULL,
        .tick_context = NULL,
        .present_on_idle = false,
        .legacy_input = false
    };

    atk_main_register_resize_handler(fileman_on_resize_event, &app);
    atk_main_register_close_handler(fileman_on_close_event, &app);

    atk_main(&main_cfg);

    fileman_entries_clear(&app);
    fileman_icon_cache_clear(&app);
    if (app.shell_handle >= 0)
    {
        sys_shell_close(app.shell_handle);
    }
    atk_user_close(&app.remote);
    return 0;
}
