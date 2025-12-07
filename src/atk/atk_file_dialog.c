#include "atk/atk_file_dialog.h"

#include "atk.h"
#include "atk_internal.h"
#include "atk_window.h"
#include "atk/layout.h"
#include "atk/atk_label.h"
#include "atk/atk_list_view.h"
#include "atk/atk_text_input.h"
#include "atk_menu_bar.h"
#include "atk_button.h"
#include "libc.h"
#include "serial.h"
#include "syscall_defs.h"
#include "video.h"
#ifdef KERNEL_BUILD
#include "vfs.h"
#else
#include "usyscall.h"
#endif

#define ATK_FILE_DIALOG_WIDTH      640
#define ATK_FILE_DIALOG_HEIGHT     420
#define ATK_FILE_DIALOG_MARGIN     10
#define ATK_FILE_DIALOG_SPACING    8
#define ATK_FILE_DIALOG_ENTRY_CAP  256
#define ATK_FILE_DIALOG_PATH_MAX   1024

typedef struct
{
    atk_widget_t *window;
    atk_widget_t *folder_list;
    atk_widget_t *file_list;
    atk_widget_t *path_input;
    atk_widget_t *open_button;
    atk_widget_t *requester;
    atk_file_dialog_result_t callback;
    void *callback_ctx;
    syscall_dirent_t *scratch;
    syscall_dirent_t *dir_entries;
    syscall_dirent_t *file_entries;
    size_t scratch_capacity;
    size_t dir_capacity;
    size_t file_capacity;
    size_t dir_count;
    size_t file_count;
    char *current_dir;
    size_t path_capacity;
    char *selected_path;
    size_t selected_capacity;
    char title_prefix[64];
    bool result_sent;
} atk_file_dialog_t;

static void file_dialog_on_destroy(void *context);
static void file_dialog_refresh(atk_file_dialog_t *dlg);
static void file_dialog_finish(atk_file_dialog_t *dlg, bool confirmed);

typedef struct
{
    syscall_dirent_t *entries;
    size_t capacity;
    size_t count;
} file_dialog_enum_ctx_t;

#ifdef KERNEL_BUILD
static bool file_dialog_collect_kernel(const vfs_node_t *node, void *context)
{
    file_dialog_enum_ctx_t *ctx = (file_dialog_enum_ctx_t *)context;
    if (!ctx || !ctx->entries || ctx->count >= ctx->capacity)
    {
        return false;
    }

    syscall_dirent_t *dst = &ctx->entries[ctx->count];
    size_t size_bytes = 0;
    vfs_node_type_t type = VFS_NODE_FILE;
    if (!vfs_stat(node, &size_bytes, &type))
    {
        return false;
    }
    dst->type = (uint32_t)type;
    dst->size_bytes = size_bytes;
    dst->reserved = 0;

    const char *name = vfs_name(node);
    size_t len = name ? strlen(name) : 0;
    if (len >= SYSCALL_DIR_NAME_MAX)
    {
        len = SYSCALL_DIR_NAME_MAX - 1;
    }
    if (len > 0 && name)
    {
        memcpy(dst->name, name, len);
    }
    dst->name[len] = '\0';
    ctx->count++;
    return ctx->count < ctx->capacity;
}
#endif

static ssize_t file_dialog_list_dir(const char *path, syscall_dirent_t *entries, size_t capacity)
{
    if (!entries || capacity == 0)
    {
        return -1;
    }

#ifdef KERNEL_BUILD
    const char *src = (path && path[0]) ? path : "/";
    vfs_node_t *dir = vfs_resolve(vfs_root(), src);
    if (!dir || !vfs_is_dir(dir))
    {
        return -1;
    }
    file_dialog_enum_ctx_t ctx = {
        .entries = entries,
        .capacity = capacity,
        .count = 0
    };
    vfs_enum_children(dir, file_dialog_collect_kernel, &ctx);
    return (ssize_t)ctx.count;
#else
    return sys_list_dir(path, entries, capacity);
#endif
}

static void file_dialog_sort_entries(syscall_dirent_t *entries, size_t count)
{
    if (!entries || count < 2)
    {
        return;
    }

    size_t start = 0;
    if (count > 0 && strcmp(entries[0].name, "..") == 0)
    {
        start = 1;
    }

    for (size_t i = start; i + 1 < count; ++i)
    {
        for (size_t j = i + 1; j < count; ++j)
        {
            if (strcmp(entries[i].name, entries[j].name) > 0)
            {
                syscall_dirent_t tmp = entries[i];
                entries[i] = entries[j];
                entries[j] = tmp;
            }
        }
    }
}

static void file_dialog_update_title(atk_file_dialog_t *dlg)
{
    if (!dlg || !dlg->window || !dlg->current_dir)
    {
        return;
    }
    char title[128];
    const char *prefix = dlg->title_prefix[0] ? dlg->title_prefix : "Open File";
    size_t pos = 0;
    size_t prefix_len = strlen(prefix);
    if (prefix_len >= sizeof(title))
    {
        prefix_len = sizeof(title) - 1;
    }
    memcpy(title + pos, prefix, prefix_len);
    pos += prefix_len;
    if (pos + 3 < sizeof(title))
    {
        title[pos++] = ' ';
        title[pos++] = '-';
        title[pos++] = ' ';
    }
    size_t remaining = (pos < sizeof(title)) ? (sizeof(title) - pos - 1) : 0;
    size_t path_len = strlen(dlg->current_dir);
    if (path_len > remaining)
    {
        path_len = remaining;
    }
    if (remaining > 0 && path_len > 0)
    {
        memcpy(title + pos, dlg->current_dir, path_len);
        pos += path_len;
    }
    title[pos] = '\0';
    atk_window_set_title_text(dlg->window, title);
}

static void file_dialog_set_directory(atk_file_dialog_t *dlg, const char *path)
{
    if (!dlg || !dlg->current_dir || dlg->path_capacity == 0)
    {
        return;
    }

    const char *src = (path && path[0]) ? path : "/root";
    size_t cap = dlg->path_capacity;
    char *tmp = (char *)malloc(cap);
    if (!tmp)
    {
        return;
    }
    size_t len = strlen(src);
    if (len >= cap)
    {
        len = cap - 1;
    }
    memcpy(tmp, src, len);
    tmp[len] = '\0';

    if (tmp[0] != '/')
    {
        const char prefix[] = "/root/";
        size_t prefix_len = sizeof(prefix) - 1;
        if (prefix_len + len >= cap)
        {
            len = cap - prefix_len - 1;
        }
        memmove(tmp + prefix_len, tmp, len);
        memcpy(tmp, prefix, prefix_len);
        len += prefix_len;
        tmp[len] = '\0';
    }

    while (len > 1 && tmp[len - 1] == '/')
    {
        tmp[len - 1] = '\0';
        --len;
    }

    memcpy(dlg->current_dir, tmp, len + 1);
    free(tmp);
    file_dialog_update_title(dlg);
    file_dialog_refresh(dlg);
}

static bool file_dialog_has_parent(const char *path)
{
    return path && path[0] == '/' && path[1] != '\0';
}

static void file_dialog_add_parent_entry(atk_file_dialog_t *dlg)
{
    if (!dlg || !dlg->dir_entries || dlg->dir_capacity == 0)
    {
        return;
    }
    dlg->dir_entries[0].type = SYSCALL_NODE_TYPE_DIR;
    dlg->dir_entries[0].size_bytes = 0;
    dlg->dir_entries[0].reserved = 0;
    dlg->dir_entries[0].name[0] = '.';
    dlg->dir_entries[0].name[1] = '.';
    dlg->dir_entries[0].name[2] = '\0';
    dlg->dir_count = 1;
}

static void file_dialog_copy_path(atk_file_dialog_t *dlg, const char *path)
{
    if (!dlg || !dlg->selected_path || dlg->selected_capacity == 0)
    {
        return;
    }
    const char *src = (path && path[0]) ? path : "";
    size_t len = strlen(src);
    if (len >= dlg->selected_capacity)
    {
        len = dlg->selected_capacity - 1;
    }
    memcpy(dlg->selected_path, src, len);
    dlg->selected_path[len] = '\0';
}

static const char *file_dialog_capture_input(atk_file_dialog_t *dlg)
{
    if (!dlg || !dlg->path_input)
    {
        return NULL;
    }
    const char *text = atk_text_input_text(dlg->path_input);
    if (!text || text[0] == '\0')
    {
        dlg->selected_path[0] = '\0';
        return NULL;
    }
    file_dialog_copy_path(dlg, text);
    return dlg->selected_path;
}

static void file_dialog_set_selected_path(atk_file_dialog_t *dlg, const char *name)
{
    if (!dlg || !name || !dlg->selected_path || !dlg->current_dir)
    {
        return;
    }
    const char *dir = dlg->current_dir;
    size_t dir_len = strlen(dir);
    bool needs_sep = (dir_len > 0 && dir[dir_len - 1] != '/');
    size_t name_len = strlen(name);
    size_t total = dir_len + (needs_sep ? 1 : 0) + name_len;
    if (total >= dlg->selected_capacity)
    {
        total = dlg->selected_capacity - 1;
        name_len = (total > dir_len) ? (total - dir_len - (needs_sep ? 1 : 0)) : 0;
    }

    size_t pos = 0;
    memcpy(dlg->selected_path + pos, dir, dir_len);
    pos += dir_len;
    if (needs_sep && pos < dlg->selected_capacity - 1)
    {
        dlg->selected_path[pos++] = '/';
    }
    if (name_len > 0 && pos < dlg->selected_capacity)
    {
        memcpy(dlg->selected_path + pos, name, name_len);
        pos += name_len;
    }
    dlg->selected_path[pos] = '\0';

    if (dlg->path_input)
    {
        atk_text_input_set_text(dlg->path_input, dlg->selected_path);
    }
    if (dlg->window)
    {
        atk_window_mark_dirty(dlg->window);
    }
}

static void file_dialog_update_lists(atk_file_dialog_t *dlg)
{
    if (!dlg || !dlg->folder_list || !dlg->file_list)
    {
        return;
    }

    atk_list_view_set_row_count(dlg->folder_list, dlg->dir_count);
    for (size_t i = 0; i < dlg->dir_count; ++i)
    {
        atk_list_view_set_cell_text(dlg->folder_list, i, 0, dlg->dir_entries[i].name);
    }

    atk_list_view_set_row_count(dlg->file_list, dlg->file_count);
    for (size_t i = 0; i < dlg->file_count; ++i)
    {
        atk_list_view_set_cell_text(dlg->file_list, i, 0, dlg->file_entries[i].name);
    }

    atk_list_view_set_selected(dlg->folder_list, ATK_LIST_VIEW_NO_SELECTION);
    atk_list_view_set_selected(dlg->file_list, ATK_LIST_VIEW_NO_SELECTION);
    if (dlg->path_input)
    {
        atk_text_input_set_text(dlg->path_input, "");
    }
    atk_list_view_relayout(dlg->folder_list);
    atk_list_view_relayout(dlg->file_list);
    if (dlg->window)
    {
        atk_window_mark_dirty(dlg->window);
    }
}

static void file_dialog_refresh(atk_file_dialog_t *dlg)
{
    if (!dlg || !dlg->current_dir || !dlg->scratch || dlg->scratch_capacity == 0)
    {
        return;
    }

    dlg->dir_count = 0;
    dlg->file_count = 0;
    ssize_t count = file_dialog_list_dir(dlg->current_dir, dlg->scratch, dlg->scratch_capacity);
    if (count < 0)
    {
        file_dialog_update_lists(dlg);
        return;
    }

    if (file_dialog_has_parent(dlg->current_dir))
    {
        file_dialog_add_parent_entry(dlg);
    }

    for (ssize_t i = 0; i < count; ++i)
    {
        syscall_dirent_t *entry = &dlg->scratch[i];
        if (entry->type == SYSCALL_NODE_TYPE_DIR)
        {
            if (dlg->dir_count < dlg->dir_capacity)
            {
                dlg->dir_entries[dlg->dir_count++] = *entry;
            }
        }
        else if (entry->type == SYSCALL_NODE_TYPE_FILE)
        {
            if (dlg->file_count < dlg->file_capacity)
            {
                dlg->file_entries[dlg->file_count++] = *entry;
            }
        }
    }

    file_dialog_sort_entries(dlg->dir_entries, dlg->dir_count);
    file_dialog_sort_entries(dlg->file_entries, dlg->file_count);
    file_dialog_update_lists(dlg);
}

static void file_dialog_finish(atk_file_dialog_t *dlg, bool confirmed)
{
    if (!dlg || dlg->result_sent)
    {
        return;
    }
    const char *path = confirmed ? file_dialog_capture_input(dlg) : NULL;
    if (confirmed && (!path || path[0] == '\0'))
    {
        return;
    }
    dlg->result_sent = true;

    if (dlg->window && dlg->window->used)
    {
        atk_state_t *state = atk_state_get();
        atk_window_close(state, dlg->window);
        atk_dirty_mark_all();
    }

    if (dlg->callback)
    {
        dlg->callback(dlg->requester, path, confirmed, dlg->callback_ctx);
    }
}

static void file_dialog_on_open(atk_widget_t *button, void *context)
{
    (void)button;
    file_dialog_finish((atk_file_dialog_t *)context, true);
}

static void file_dialog_on_folder_selected(atk_widget_t *list, void *context, size_t row)
{
    (void)list;
    atk_file_dialog_t *dlg = (atk_file_dialog_t *)context;
    if (!dlg || row >= dlg->dir_count)
    {
        return;
    }

    const char *name = dlg->dir_entries[row].name;
    serial_printf("[filedlg] folder row=%zu name=%s\r\n", row, name ? name : "?");
    if (!name)
    {
        return;
    }

    if (strcmp(name, "..") == 0)
    {
        size_t len = strlen(dlg->current_dir);
        if (len <= 1)
        {
            return;
        }
        size_t pos = len;
        while (pos > 0 && dlg->current_dir[pos - 1] == '/')
        {
            --pos;
        }
        while (pos > 0 && dlg->current_dir[pos - 1] != '/')
        {
            --pos;
        }
        if (pos == 0)
        {
            pos = 1;
        }
        dlg->current_dir[pos] = '\0';
        file_dialog_update_title(dlg);
        file_dialog_refresh(dlg);
        return;
    }

    size_t dir_len = strlen(dlg->current_dir);
    bool needs_sep = dir_len > 0 && dlg->current_dir[dir_len - 1] != '/';
    size_t name_len = strlen(name);
    size_t total = dir_len + (needs_sep ? 1 : 0) + name_len;
    if (total >= dlg->path_capacity)
    {
        total = dlg->path_capacity - 1;
        name_len = (total > dir_len) ? (total - dir_len - (needs_sep ? 1 : 0)) : 0;
    }

    size_t pos = dir_len;
    if (needs_sep && pos < dlg->path_capacity - 1)
    {
        dlg->current_dir[pos++] = '/';
    }
    if (name_len > 0 && pos < dlg->path_capacity)
    {
        memcpy(dlg->current_dir + pos, name, name_len);
        pos += name_len;
    }
    dlg->current_dir[pos] = '\0';
    file_dialog_update_title(dlg);
    file_dialog_refresh(dlg);
}

static void file_dialog_on_file_selected(atk_widget_t *list, void *context, size_t row)
{
    (void)list;
    atk_file_dialog_t *dlg = (atk_file_dialog_t *)context;
    if (!dlg || row >= dlg->file_count)
    {
        return;
    }
    serial_printf("[filedlg] file row=%zu name=%s\r\n", row, dlg->file_entries[row].name);
    file_dialog_set_selected_path(dlg, dlg->file_entries[row].name);
}

static void file_dialog_on_submit(atk_widget_t *input, void *context)
{
    (void)input;
    file_dialog_finish((atk_file_dialog_t *)context, true);
}

static void file_dialog_on_destroy(void *context)
{
    atk_file_dialog_t *dlg = (atk_file_dialog_t *)context;
    if (!dlg)
    {
        return;
    }

    if (!dlg->result_sent && dlg->window && dlg->callback)
    {
        dlg->callback(dlg->requester, NULL, false, dlg->callback_ctx);
    }

    free(dlg->scratch);
    free(dlg->dir_entries);
    free(dlg->file_entries);
    free(dlg->current_dir);
    free(dlg->selected_path);
    free(dlg);
}

atk_widget_t *atk_file_dialog_open(atk_widget_t *requester,
                                   const char *title,
                                   const char *initial_path,
                                   atk_file_dialog_result_t on_result,
                                   void *context)
{
    atk_state_t *state = atk_state_get();
    if (!state)
    {
        return NULL;
    }
    atk_menu_bar_set_enabled(state, false);

    atk_file_dialog_t *dlg = (atk_file_dialog_t *)calloc(1, sizeof(atk_file_dialog_t));
    if (!dlg)
    {
        return NULL;
    }

    dlg->scratch_capacity = ATK_FILE_DIALOG_ENTRY_CAP;
    dlg->dir_capacity = ATK_FILE_DIALOG_ENTRY_CAP;
    dlg->file_capacity = ATK_FILE_DIALOG_ENTRY_CAP;
    dlg->path_capacity = ATK_FILE_DIALOG_PATH_MAX;
    dlg->selected_capacity = ATK_FILE_DIALOG_PATH_MAX;
    dlg->scratch = (syscall_dirent_t *)malloc(sizeof(syscall_dirent_t) * dlg->scratch_capacity);
    dlg->dir_entries = (syscall_dirent_t *)malloc(sizeof(syscall_dirent_t) * dlg->dir_capacity);
    dlg->file_entries = (syscall_dirent_t *)malloc(sizeof(syscall_dirent_t) * dlg->file_capacity);
    dlg->current_dir = (char *)malloc(dlg->path_capacity);
    dlg->selected_path = (char *)malloc(dlg->selected_capacity);
    if (!dlg->scratch || !dlg->dir_entries || !dlg->file_entries || !dlg->current_dir || !dlg->selected_path)
    {
        dlg->result_sent = true;
        file_dialog_on_destroy(dlg);
        return NULL;
    }

    dlg->requester = requester;
    dlg->callback = on_result;
    dlg->callback_ctx = context;
    if (title && title[0])
    {
        size_t len = strlen(title);
        if (len >= sizeof(dlg->title_prefix))
        {
            len = sizeof(dlg->title_prefix) - 1;
        }
        memcpy(dlg->title_prefix, title, len);
        dlg->title_prefix[len] = '\0';
    }
    else
    {
        const char def_title[] = "Open File";
        memcpy(dlg->title_prefix, def_title, sizeof(def_title));
    }

    int screen_w = video_screen_width();
    int screen_h = video_screen_height();
    if (screen_w <= 0)
    {
        screen_w = ATK_FILE_DIALOG_WIDTH;
    }
    if (screen_h <= 0)
    {
        screen_h = ATK_FILE_DIALOG_HEIGHT;
    }

    dlg->window = atk_window_create_at(state, screen_w / 2, screen_h / 2);
    if (!dlg->window)
    {
        dlg->result_sent = true;
        file_dialog_on_destroy(dlg);
        return NULL;
    }
    atk_window_set_chrome_visible(dlg->window, false);
    dlg->window->x = 0;
    dlg->window->y = 0;
    dlg->window->width = screen_w;
    dlg->window->height = screen_h;
    atk_window_set_context(dlg->window, dlg, file_dialog_on_destroy);
    atk_window_set_title_text(dlg->window, dlg->title_prefix);
    atk_window_ensure_inside(dlg->window);
    atk_window_bring_to_front(state, dlg->window);
    serial_printf("[filedlg] window=%p pos=(%d,%d) size=%dx%d\r\n",
                  (void *)dlg->window,
                  dlg->window->x,
                  dlg->window->y,
                  dlg->window->width,
                  dlg->window->height);

    int chrome_top = atk_window_is_chrome_visible(dlg->window) ? ATK_WINDOW_TITLE_HEIGHT : 0;
    int content_x = ATK_FILE_DIALOG_MARGIN;
    int content_y = chrome_top + ATK_FILE_DIALOG_MARGIN;
    int content_w = dlg->window->width - ATK_FILE_DIALOG_MARGIN * 2;
    int content_h = dlg->window->height - chrome_top - ATK_FILE_DIALOG_MARGIN * 2;
    int label_h = ATK_FONT_HEIGHT + 4;
    int input_h = ATK_FONT_HEIGHT + 8;
    int list_height = content_h - label_h - ATK_FILE_DIALOG_SPACING - input_h - ATK_FILE_DIALOG_SPACING;
    if (list_height < ATK_FONT_HEIGHT * 2)
    {
        list_height = ATK_FONT_HEIGHT * 2;
    }
    int folders_w = content_w / 3;
    int files_w = content_w - folders_w - ATK_FILE_DIALOG_SPACING;

    atk_widget_t *folder_label = atk_window_add_label(dlg->window, content_x, content_y, folders_w, label_h);
    atk_widget_t *file_label = atk_window_add_label(dlg->window,
                                                    content_x + folders_w + ATK_FILE_DIALOG_SPACING,
                                                    content_y,
                                                    files_w,
                                                    label_h);
    if (folder_label)
    {
        atk_label_set_text(folder_label, "Folders");
    }
    if (file_label)
    {
        atk_label_set_text(file_label, "Files");
    }

    int list_y = content_y + label_h + ATK_FILE_DIALOG_SPACING / 2;
    dlg->folder_list = atk_window_add_list_view(dlg->window, content_x, list_y, folders_w, list_height);
    dlg->file_list = atk_window_add_list_view(dlg->window,
                                              content_x + folders_w + ATK_FILE_DIALOG_SPACING,
                                              list_y,
                                              files_w,
                                              list_height);

    atk_list_view_column_def_t folder_cols[] = { { "Folders", 0 } };
    atk_list_view_column_def_t file_cols[] = { { "Files", 0 } };
    if (dlg->folder_list)
    {
        atk_list_view_configure_columns(dlg->folder_list, folder_cols, 1);
        atk_list_view_force_vertical_scrollbar(dlg->folder_list, true);
        atk_list_view_set_select_handler(dlg->folder_list, file_dialog_on_folder_selected, dlg);
    }
    if (dlg->file_list)
    {
        atk_list_view_configure_columns(dlg->file_list, file_cols, 1);
        atk_list_view_force_vertical_scrollbar(dlg->file_list, true);
        atk_list_view_set_select_handler(dlg->file_list, file_dialog_on_file_selected, dlg);
    }

    int input_y = list_y + list_height + ATK_FILE_DIALOG_SPACING;
    int open_w = 90;
    int input_w = content_w - open_w - ATK_FILE_DIALOG_SPACING;
    dlg->path_input = atk_window_add_text_input(dlg->window, content_x, input_y, input_w);
    if (dlg->path_input)
    {
        atk_text_input_set_submit_handler(dlg->path_input, file_dialog_on_submit, dlg);
    }
    dlg->open_button = atk_window_add_button(dlg->window,
                                             "Open",
                                             content_x + input_w + ATK_FILE_DIALOG_SPACING,
                                             input_y,
                                             open_w,
                                             input_h,
                                             ATK_BUTTON_STYLE_TITLE_INSIDE,
                                             false,
                                             file_dialog_on_open,
                                             dlg);

    file_dialog_set_directory(dlg, initial_path);
    atk_window_mark_dirty(dlg->window);
    return dlg->window;
}
