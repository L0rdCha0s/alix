#include "atk_user.h"

#include "atk.h"
#include "atk_app.h"
#include "atk_internal.h"
#include "atk_menu_bar.h"
#include "atk_window.h"
#include "atk/atk_list_view.h"
#include "atk/atk_iconbox.h"
#include "atk/atk_tree_view.h"
#include "atk/atk_tabs.h"
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

typedef struct fileman_app fileman_app_t;

typedef struct
{
    fileman_app_t *app;
    char name[SYSCALL_DIR_NAME_MAX];
    char path[FILEMAN_PATH_MAX];
    uint64_t size_bytes;
    bool is_dir;
    bool is_elf;
} fileman_entry_t;

struct fileman_app
{
    atk_user_window_t remote;
    atk_widget_t *window;
    atk_widget_t *tree;
    atk_widget_t *tab_view;
    atk_widget_t *list_view;
    atk_widget_t *iconbox;
    int shell_handle;
    char current_path[FILEMAN_PATH_MAX];
    fileman_entry_t *entries;
    size_t entry_count;
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
        dst->is_dir = (ent->type == SYSCALL_NODE_TYPE_DIR);
        dst->is_elf = (!dst->is_dir && fileman_has_extension(dst->name, ".elf"));
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
        atk_iconbox_add_icon(app->iconbox, entry->name, fileman_icon_action, entry);
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
        return true;
    }

    for (ssize_t i = 0; i < count; ++i)
    {
        syscall_dirent_t *ent = &entries[i];
        if (ent->type != SYSCALL_NODE_TYPE_DIR)
        {
            continue;
        }
        if (fileman_is_dot_entry(ent->name))
        {
            continue;
        }
        char child_path[FILEMAN_PATH_MAX];
        fileman_join_path(child_path, sizeof(child_path), path, ent->name);
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

static void fileman_view_changed(atk_widget_t *tab_view, void *context, size_t index)
{
    (void)tab_view;
    fileman_app_t *app = (fileman_app_t *)context;
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

static void fileman_layout(fileman_app_t *app)
{
    if (!app || !app->window || !app->tree || !app->tab_view)
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

    app->tab_view->x = content_x + tree_w + FILEMAN_MARGIN;
    app->tab_view->y = content_y;
    app->tab_view->width = right_w;
    app->tab_view->height = content_h;

    atk_tree_view_relayout(app->tree);
    atk_tab_view_relayout(app->tab_view);
    if (app->list_view)
    {
        atk_list_view_relayout(app->list_view);
    }
    if (app->iconbox)
    {
        atk_iconbox_relayout(app->iconbox);
    }
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

    atk_widget_t *tab_view = atk_window_add_tab_view(window, 0, 0, 100, 100);
    if (!tab_view)
    {
        return false;
    }

    atk_widget_t *list_view = atk_list_view_create();
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

    if (!atk_tab_view_add_page(tab_view, "List", list_view))
    {
        return false;
    }
    if (!atk_tab_view_add_page(tab_view, "Icons", iconbox))
    {
        return false;
    }
    atk_tab_view_set_change_handler(tab_view, fileman_view_changed, app);

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
    app->tab_view = tab_view;
    app->list_view = list_view;
    app->iconbox = iconbox;
    app->view_mode = FILEMAN_VIEW_LIST;

    fileman_layout(app);
    fileman_view_changed(tab_view, app, FILEMAN_VIEW_LIST);
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
    if (app.shell_handle >= 0)
    {
        sys_shell_close(app.shell_handle);
    }
    atk_user_close(&app.remote);
    return 0;
}
