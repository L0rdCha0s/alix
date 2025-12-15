#include "atk_user.h"

#include "atk.h"
#include "atk_app.h"
#include "atk_internal.h"
#include "atk_window.h"
#include "atk_menu_bar.h"
#include "atk/layout.h"
#include "atk_button.h"
#include "atk/atk_dropdown.h"
#include "atk/atk_file_dialog.h"
#include "atk/atk_font.h"
#include "atk/atk_label.h"
#include "atk/atk_menu.h"
#include "atk/atk_rich_text.h"
#include <stdio.h>
#include "libc.h"
#include "video.h"
#include "user_atk_defs.h"

#define RICH_APP_WIDTH  1000
#define RICH_APP_HEIGHT 720
#define RICH_APP_MARGIN 14
#define RICH_MENU_HEIGHT 28
#define RICH_TOOLBAR_HEIGHT 42
#define RICH_STATUS_HEIGHT 24

typedef enum
{
    RICH_CMD_FILE_NEW = 1,
    RICH_CMD_FILE_OPEN = 2,
    RICH_CMD_FILE_SAVE = 3,
    RICH_CMD_FILE_SAVE_AS = 4,
    RICH_CMD_FILE_EXIT = 5,
    RICH_CMD_INSERT_PAGE_BREAK = 10,
    RICH_CMD_VIEW_TOGGLE_PAGINATION = 20,
} rich_command_t;

typedef struct
{
    atk_user_window_t remote;
    atk_widget_t *window;

    atk_widget_t *menu_file_button;
    atk_widget_t *menu_insert_button;
    atk_widget_t *menu_view_button;
    atk_widget_t *menu_file;
    atk_widget_t *menu_insert;
    atk_widget_t *menu_view;
    atk_widget_t *menu_open;

    atk_widget_t *toolbar_label;
    atk_widget_t *font_dropdown;
    atk_widget_t *bold_button;
    atk_widget_t *italic_button;
    atk_widget_t *underline_button;

    atk_widget_t *editor;
    atk_widget_t *status;

    atk_widget_t *file_dialog;
    atk_modal_session_t dialog_modal;

    char *current_path;
    bool dirty;
    bool suppress_dirty;
    bool running;
} rich_app_t;

static const int k_font_sizes[] = { 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 32, 36, 40, 48, 56, 64 };

static void apply_theme(atk_state_t *state);
static bool build_ui(rich_app_t *app);
static void relayout(rich_app_t *app);
static void populate_sample(rich_app_t *app);
static void sync_controls(rich_app_t *app);
static void update_window_title(rich_app_t *app);
static void update_status(rich_app_t *app, const char *note);
static void on_editor_change(atk_widget_t *editor, void *context);
static void on_font_size_selected(atk_widget_t *dropdown, void *context, size_t index, uintptr_t value);
static void on_menu_button(atk_widget_t *button, void *context);
static void on_style_button(atk_widget_t *button, void *context);
static bool handle_resize(rich_app_t *app, uint32_t width, uint32_t height);
static bool rich_on_mouse_event(const user_atk_event_t *event, void *context);
static bool rich_on_key_event(const user_atk_event_t *event, void *context);

static bool rich_read_file(const char *path, uint8_t **data_out, size_t *size_out);
static bool rich_write_file(const char *path, const uint8_t *data, size_t size);
static bool rich_path_has_ext(const char *path, const char *ext);
static char *rich_strdup(const char *src);
static const char *rich_path_basename(const char *path);
static const char *rich_dialog_initial_dir(const rich_app_t *app, char *buf, size_t cap);
static void rich_set_current_path(rich_app_t *app, const char *path);
static void rich_set_dirty(rich_app_t *app, bool dirty);
static void rich_new_document(rich_app_t *app);
static void rich_request_open(rich_app_t *app);
static void rich_request_save_as(rich_app_t *app);
static void rich_load_from_path(rich_app_t *app, const char *path);
static bool rich_save_to_path(rich_app_t *app, const char *path);
static void rich_on_open_result(atk_widget_t *requester, const char *path, bool confirmed, void *context);
static void rich_on_save_result(atk_widget_t *requester, const char *path, bool confirmed, void *context);
static void rich_close_file_dialog(rich_app_t *app);
static void rich_menus_close(rich_app_t *app);
static void rich_menu_toggle(rich_app_t *app, atk_widget_t *menu, atk_widget_t *button);
static bool rich_menu_button_hit_test(const atk_widget_t *button, int px, int py);
static void rich_menu_action_file_new(void *context);
static void rich_menu_action_file_open(void *context);
static void rich_menu_action_file_save(void *context);
static void rich_menu_action_file_save_as(void *context);
static void rich_menu_action_file_exit(void *context);
static void rich_menu_action_insert_page_break(void *context);
static void rich_menu_action_view_toggle_pagination(void *context);

static void apply_theme(atk_state_t *state)
{
    if (!state)
    {
        return;
    }
    state->theme.background = video_make_color(0x12, 0x16, 0x1F);
    state->theme.window_border = video_make_color(0x2F, 0x38, 0x46);
    state->theme.window_title = video_make_color(0x28, 0x6A, 0xA8);
    state->theme.window_title_text = video_make_color(0xF3, 0xF5, 0xF7);
    state->theme.window_body = video_make_color(0x1B, 0x22, 0x2F);
    state->theme.button_face = video_make_color(0x28, 0x36, 0x48);
    state->theme.button_border = video_make_color(0x14, 0x1B, 0x26);
    state->theme.button_text = video_make_color(0xE4, 0xE9, 0xEF);
    state->theme.desktop_icon_face = video_make_color(0x3A, 0x78, 0xB0);
    state->theme.desktop_icon_text = state->theme.window_title_text;
    state->theme.menu_bar_face = video_make_color(0x18, 0x22, 0x2E);
    state->theme.menu_bar_text = state->theme.button_text;
    state->theme.menu_bar_highlight = video_make_color(0x2D, 0x4D, 0x73);
    state->theme.menu_dropdown_face = video_make_color(0xF7, 0xF7, 0xF7);
    state->theme.menu_dropdown_border = video_make_color(0x38, 0x3D, 0x45);
    state->theme.menu_dropdown_text = video_make_color(0x20, 0x22, 0x24);
    state->theme.menu_dropdown_highlight = video_make_color(0x2F, 0x54, 0x83);
    atk_state_theme_commit(state);
}

static bool build_ui(rich_app_t *app)
{
    if (!app)
    {
        return false;
    }

    atk_init();
    atk_state_t *state = atk_state_get();
    atk_menu_bar_set_enabled(state, false);
    apply_theme(state);

    app->window = atk_window_create_at(state, RICH_APP_WIDTH / 2, RICH_APP_HEIGHT / 2);
    if (!app->window)
    {
        return false;
    }

    atk_window_set_chrome_visible(app->window, false);
    atk_window_set_title_text(app->window, "ATK Rich Text");
    app->window->x = 0;
    app->window->y = 0;
    app->window->width = RICH_APP_WIDTH;
    app->window->height = RICH_APP_HEIGHT;
    atk_window_ensure_inside(app->window);

    atk_layout_t layout;
    int chrome_top = (atk_window_is_chrome_visible(app->window) ? ATK_WINDOW_TITLE_HEIGHT : 0) + RICH_APP_MARGIN;
    atk_layout_init(&layout,
                    RICH_APP_MARGIN,
                    chrome_top,
                    app->window->width - RICH_APP_MARGIN * 2,
                    app->window->height - chrome_top - RICH_APP_MARGIN);
    atk_layout_region_t menu = atk_layout_take_top(&layout, RICH_MENU_HEIGHT, 6);
    atk_layout_region_t toolbar = atk_layout_take_top(&layout, RICH_TOOLBAR_HEIGHT, 10);
    atk_layout_region_t status = atk_layout_take_bottom(&layout, RICH_STATUS_HEIGHT, 10);
    atk_layout_region_t editor_region = atk_layout_content(&layout);

    app->editor = atk_window_add_rich_text(app->window,
                                           editor_region.x,
                                           editor_region.y,
                                           editor_region.width,
                                           editor_region.height);
    if (!app->editor)
    {
        return false;
    }
    atk_widget_set_layout(app->editor,
                          ATK_WIDGET_ANCHOR_LEFT | ATK_WIDGET_ANCHOR_RIGHT |
                          ATK_WIDGET_ANCHOR_TOP | ATK_WIDGET_ANCHOR_BOTTOM);
    atk_rich_text_set_pagination_enabled(app->editor, true);
    atk_rich_text_set_change_handler(app->editor, on_editor_change, app);

    int menu_x = menu.x;
    int menu_y = menu.y;
    int menu_h = menu.height;
    int menu_w_file = atk_font_text_width("File") + 32;
    int menu_w_insert = atk_font_text_width("Insert") + 32;
    int menu_w_view = atk_font_text_width("View") + 32;
    if (menu_w_file < 56) menu_w_file = 56;
    if (menu_w_insert < 72) menu_w_insert = 72;
    if (menu_w_view < 64) menu_w_view = 64;

    app->menu_file_button = atk_window_add_button(app->window,
                                                  "File",
                                                  menu_x,
                                                  menu_y,
                                                  menu_w_file,
                                                  menu_h,
                                                  ATK_BUTTON_STYLE_TITLE_INSIDE,
                                                  false,
                                                  on_menu_button,
                                                  app);
    if (!app->menu_file_button)
    {
        return false;
    }
    atk_widget_set_layout(app->menu_file_button, ATK_WIDGET_ANCHOR_TOP | ATK_WIDGET_ANCHOR_LEFT);

    menu_x += menu_w_file + 8;
    app->menu_insert_button = atk_window_add_button(app->window,
                                                    "Insert",
                                                    menu_x,
                                                    menu_y,
                                                    menu_w_insert,
                                                    menu_h,
                                                    ATK_BUTTON_STYLE_TITLE_INSIDE,
                                                    false,
                                                    on_menu_button,
                                                    app);
    if (!app->menu_insert_button)
    {
        return false;
    }
    atk_widget_set_layout(app->menu_insert_button, ATK_WIDGET_ANCHOR_TOP | ATK_WIDGET_ANCHOR_LEFT);

    menu_x += menu_w_insert + 8;
    app->menu_view_button = atk_window_add_button(app->window,
                                                  "View",
                                                  menu_x,
                                                  menu_y,
                                                  menu_w_view,
                                                  menu_h,
                                                  ATK_BUTTON_STYLE_TITLE_INSIDE,
                                                  false,
                                                  on_menu_button,
                                                  app);
    if (!app->menu_view_button)
    {
        return false;
    }
    atk_widget_set_layout(app->menu_view_button, ATK_WIDGET_ANCHOR_TOP | ATK_WIDGET_ANCHOR_LEFT);

    int toolbar_x = toolbar.x;
    int toolbar_y = toolbar.y;
    int toolbar_h = toolbar.height;

    int btn_h = toolbar_h;
    int btn_w = 44;
    app->bold_button = atk_window_add_button(app->window,
                                             "B",
                                             toolbar_x,
                                             toolbar_y,
                                             btn_w,
                                             btn_h,
                                             ATK_BUTTON_STYLE_TITLE_INSIDE,
                                             false,
                                             on_style_button,
                                             app);
    if (!app->bold_button)
    {
        return false;
    }
    toolbar_x += btn_w + 8;
    app->italic_button = atk_window_add_button(app->window,
                                               "I",
                                               toolbar_x,
                                               toolbar_y,
                                               btn_w,
                                               btn_h,
                                               ATK_BUTTON_STYLE_TITLE_INSIDE,
                                               false,
                                               on_style_button,
                                               app);
    if (!app->italic_button)
    {
        return false;
    }
    toolbar_x += btn_w + 8;
    app->underline_button = atk_window_add_button(app->window,
                                                  "U",
                                                  toolbar_x,
                                                  toolbar_y,
                                                  btn_w,
                                                  btn_h,
                                                  ATK_BUTTON_STYLE_TITLE_INSIDE,
                                                  false,
                                                  on_style_button,
                                                  app);
    if (!app->underline_button)
    {
        return false;
    }
    toolbar_x += btn_w + 16;

    app->toolbar_label = atk_window_add_label(app->window,
                                              toolbar_x,
                                              toolbar_y,
                                              54,
                                              toolbar_h);
    if (!app->toolbar_label)
    {
        return false;
    }
    atk_label_set_text(app->toolbar_label, "Size:");
    toolbar_x += 54 + 8;

    app->font_dropdown = atk_window_add_dropdown(app->window,
                                                 toolbar_x,
                                                 toolbar_y,
                                                 120,
                                                 toolbar_h,
                                                 ATK_DROPDOWN_STYLE_COMBO,
                                                 on_font_size_selected,
                                                 app);
    if (!app->font_dropdown)
    {
        return false;
    }
    atk_dropdown_set_title(app->font_dropdown, "Font");
    for (size_t i = 0; i < sizeof(k_font_sizes) / sizeof(k_font_sizes[0]); ++i)
    {
        char item[16];
        snprintf(item, sizeof(item), "%d px", k_font_sizes[i]);
        atk_dropdown_add_item(app->font_dropdown, item, (uintptr_t)k_font_sizes[i]);
    }
    atk_dropdown_set_selected(app->font_dropdown, 4); /* 18px */

    app->status = atk_window_add_label(app->window,
                                       status.x,
                                       status.y,
                                       status.width,
                                       status.height);
    if (!app->status)
    {
        return false;
    }

    atk_window_priv_t *wpriv = (atk_window_priv_t *)atk_widget_priv(app->window, &ATK_WINDOW_CLASS);
    if (!wpriv)
    {
        return false;
    }

    app->menu_file = atk_menu_create();
    app->menu_insert = atk_menu_create();
    app->menu_view = atk_menu_create();
    if (!app->menu_file || !app->menu_insert || !app->menu_view)
    {
        if (app->menu_file) atk_menu_destroy(app->menu_file);
        if (app->menu_insert) atk_menu_destroy(app->menu_insert);
        if (app->menu_view) atk_menu_destroy(app->menu_view);
        app->menu_file = NULL;
        app->menu_insert = NULL;
        app->menu_view = NULL;
        return false;
    }

    app->menu_file->parent = app->window;
    app->menu_insert->parent = app->window;
    app->menu_view->parent = app->window;
    if (!atk_list_push_back(&wpriv->children, app->menu_file) ||
        !atk_list_push_back(&wpriv->children, app->menu_insert) ||
        !atk_list_push_back(&wpriv->children, app->menu_view))
    {
        atk_menu_destroy(app->menu_file);
        atk_menu_destroy(app->menu_insert);
        atk_menu_destroy(app->menu_view);
        app->menu_file = NULL;
        app->menu_insert = NULL;
        app->menu_view = NULL;
        return false;
    }

    if (!atk_menu_add_item(app->menu_file, "New", rich_menu_action_file_new, app) ||
        !atk_menu_add_item(app->menu_file, "Open...", rich_menu_action_file_open, app) ||
        !atk_menu_add_item(app->menu_file, "Save", rich_menu_action_file_save, app) ||
        !atk_menu_add_item(app->menu_file, "Save As...", rich_menu_action_file_save_as, app) ||
        !atk_menu_add_item(app->menu_file, "Exit", rich_menu_action_file_exit, app))
    {
        return false;
    }
    if (!atk_menu_add_item(app->menu_insert, "Page Break", rich_menu_action_insert_page_break, app))
    {
        return false;
    }
    if (!atk_menu_add_item(app->menu_view, "Toggle Pagination", rich_menu_action_view_toggle_pagination, app))
    {
        return false;
    }
    app->menu_open = NULL;

    rich_set_dirty(app, false);
    update_status(app, "Ready");

    atk_rich_text_set_font_size(app->editor, 18);
    populate_sample(app);
    atk_rich_text_focus(state, app->editor);
    atk_window_mark_dirty(app->window);
    return true;
}

static void relayout(rich_app_t *app)
{
    if (!app || !app->window)
    {
        return;
    }
    atk_layout_t layout;
    int chrome_top = (atk_window_is_chrome_visible(app->window) ? ATK_WINDOW_TITLE_HEIGHT : 0) + RICH_APP_MARGIN;
    atk_layout_init(&layout,
                    RICH_APP_MARGIN,
                    chrome_top,
                    app->window->width - RICH_APP_MARGIN * 2,
                    app->window->height - chrome_top - RICH_APP_MARGIN);
    atk_layout_region_t menu = atk_layout_take_top(&layout, RICH_MENU_HEIGHT, 6);
    atk_layout_region_t toolbar = atk_layout_take_top(&layout, RICH_TOOLBAR_HEIGHT, 10);
    atk_layout_region_t status = atk_layout_take_bottom(&layout, RICH_STATUS_HEIGHT, 10);
    atk_layout_region_t editor_region = atk_layout_content(&layout);

    int menu_x = menu.x;
    int menu_y = menu.y;
    int menu_h = menu.height;

    int menu_w_file = atk_font_text_width("File") + 32;
    int menu_w_insert = atk_font_text_width("Insert") + 32;
    int menu_w_view = atk_font_text_width("View") + 32;
    if (menu_w_file < 56) menu_w_file = 56;
    if (menu_w_insert < 72) menu_w_insert = 72;
    if (menu_w_view < 64) menu_w_view = 64;

    if (app->menu_file_button)
    {
        app->menu_file_button->x = menu_x;
        app->menu_file_button->y = menu_y;
        app->menu_file_button->width = menu_w_file;
        app->menu_file_button->height = menu_h;
    }

    menu_x += menu_w_file + 8;
    if (app->menu_insert_button)
    {
        app->menu_insert_button->x = menu_x;
        app->menu_insert_button->y = menu_y;
        app->menu_insert_button->width = menu_w_insert;
        app->menu_insert_button->height = menu_h;
    }

    menu_x += menu_w_insert + 8;
    if (app->menu_view_button)
    {
        app->menu_view_button->x = menu_x;
        app->menu_view_button->y = menu_y;
        app->menu_view_button->width = menu_w_view;
        app->menu_view_button->height = menu_h;
    }

    int toolbar_x = toolbar.x;
    int toolbar_y = toolbar.y;
    int toolbar_h = toolbar.height;
    int btn_w = 44;

    if (app->bold_button)
    {
        app->bold_button->x = toolbar_x;
        app->bold_button->y = toolbar_y;
        app->bold_button->width = btn_w;
        app->bold_button->height = toolbar_h;
        toolbar_x += btn_w + 8;
    }
    if (app->italic_button)
    {
        app->italic_button->x = toolbar_x;
        app->italic_button->y = toolbar_y;
        app->italic_button->width = btn_w;
        app->italic_button->height = toolbar_h;
        toolbar_x += btn_w + 8;
    }
    if (app->underline_button)
    {
        app->underline_button->x = toolbar_x;
        app->underline_button->y = toolbar_y;
        app->underline_button->width = btn_w;
        app->underline_button->height = toolbar_h;
        toolbar_x += btn_w + 16;
    }
    if (app->toolbar_label)
    {
        app->toolbar_label->x = toolbar_x;
        app->toolbar_label->y = toolbar_y;
        app->toolbar_label->width = 54;
        app->toolbar_label->height = toolbar_h;
        toolbar_x += 54 + 8;
    }
    if (app->font_dropdown)
    {
        app->font_dropdown->x = toolbar_x;
        app->font_dropdown->y = toolbar_y;
        app->font_dropdown->width = 120;
        app->font_dropdown->height = toolbar_h;
    }

    if (app->editor)
    {
        app->editor->x = editor_region.x;
        app->editor->y = editor_region.y;
        app->editor->width = editor_region.width;
        app->editor->height = editor_region.height;
    }

    if (app->status)
    {
        app->status->x = status.x;
        app->status->y = status.y;
        app->status->width = status.width;
        app->status->height = status.height;
    }
}

static void populate_sample(rich_app_t *app)
{
    if (!app || !app->editor)
    {
        return;
    }

    app->suppress_dirty = true;
    atk_rich_text_set_text(app->editor, "");
    atk_rich_text_set_pagination_enabled(app->editor, true);

    atk_rich_text_set_font_size(app->editor, 26);
    atk_rich_text_apply_style(app->editor, ATK_RICH_TEXT_STYLE_BOLD, true);
    atk_rich_text_append(app->editor, "Rich Text Editor\n");

    atk_rich_text_apply_style(app->editor, ATK_RICH_TEXT_STYLE_BOLD, false);
    atk_rich_text_set_font_size(app->editor, 18);
    atk_rich_text_append(app->editor, "Use the toolbar to toggle ");
    atk_rich_text_apply_style(app->editor, ATK_RICH_TEXT_STYLE_BOLD, true);
    atk_rich_text_append(app->editor, "bold");
    atk_rich_text_apply_style(app->editor, ATK_RICH_TEXT_STYLE_BOLD, false);
    atk_rich_text_append(app->editor, ", ");
    atk_rich_text_apply_style(app->editor, ATK_RICH_TEXT_STYLE_ITALIC, true);
    atk_rich_text_append(app->editor, "italic");
    atk_rich_text_apply_style(app->editor, ATK_RICH_TEXT_STYLE_ITALIC, false);
    atk_rich_text_append(app->editor, ", and ");
    atk_rich_text_apply_style(app->editor, ATK_RICH_TEXT_STYLE_UNDERLINE, true);
    atk_rich_text_append(app->editor, "underline");
    atk_rich_text_apply_style(app->editor, ATK_RICH_TEXT_STYLE_UNDERLINE, false);
    atk_rich_text_append(app->editor, ".\n");
    atk_rich_text_append(app->editor, "Use File → Open/Save, and Insert → Page Break.\n\n");

    atk_rich_text_set_font_size(app->editor, 16);
    atk_rich_text_append(app->editor,
                         "Pagination is enabled by default: each page renders like a document on paper. "
                         "Try inserting a page break to start a new page.\n");
    atk_rich_text_append(app->editor, "\f");
    atk_rich_text_set_font_size(app->editor, 18);
    atk_rich_text_append(app->editor, "Page 2 starts here.\n");

    atk_rich_text_apply_style(app->editor,
                              ATK_RICH_TEXT_STYLE_BOLD | ATK_RICH_TEXT_STYLE_ITALIC | ATK_RICH_TEXT_STYLE_UNDERLINE,
                              false);
    atk_rich_text_set_font_size(app->editor, 18);
    app->suppress_dirty = false;
    rich_set_dirty(app, false);
    sync_controls(app);
    update_status(app, "Ready");
}

static bool handle_resize(rich_app_t *app, uint32_t width, uint32_t height)
{
    if (!app || !app->window || width == 0 || height == 0)
    {
        return false;
    }
    if (app->dialog_modal.active)
    {
        return true;
    }
    rich_menus_close(app);
    app->window->width = (int)width;
    app->window->height = (int)height;
    relayout(app);
    update_status(app, NULL);
    atk_window_request_layout(app->window);
    if (app->window)
    {
        atk_window_mark_dirty(app->window);
    }
    return true;
}

static bool rich_on_resize_event(uint32_t width, uint32_t height, void *context)
{
    return handle_resize((rich_app_t *)context, width, height);
}

static void rich_on_close_event(void *context)
{
    rich_app_t *app = (rich_app_t *)context;
    if (app)
    {
        if (app->dialog_modal.active)
        {
            rich_close_file_dialog(app);
            return;
        }
        app->running = false;
        rich_close_file_dialog(app);
    }
    atk_main_request_exit();
}

static bool rich_on_mouse_event(const user_atk_event_t *event, void *context)
{
    rich_app_t *app = (rich_app_t *)context;
    if (!app || !event)
    {
        return false;
    }

    bool left = (event->flags & USER_ATK_MOUSE_FLAG_LEFT) != 0;
    bool press = (event->flags & USER_ATK_MOUSE_FLAG_PRESS) != 0;
    if (left && press && app->menu_open && atk_menu_is_visible(app->menu_open))
    {
        int px = event->x;
        int py = event->y;
        bool inside_menu = atk_menu_contains(app->menu_open, px, py);
        bool inside_menu_button = rich_menu_button_hit_test(app->menu_file_button, px, py) ||
                                  rich_menu_button_hit_test(app->menu_insert_button, px, py) ||
                                  rich_menu_button_hit_test(app->menu_view_button, px, py);
        if (!inside_menu && !inside_menu_button)
        {
            rich_menus_close(app);
        }
    }

    if (!app->editor)
    {
        return false;
    }
    sync_controls(app);
    return false;
}

static bool rich_on_key_event(const user_atk_event_t *event, void *context)
{
    (void)event;
    rich_app_t *app = (rich_app_t *)context;
    if (!app || !app->editor)
    {
        return false;
    }
    sync_controls(app);
    return false;
}

static void on_editor_change(atk_widget_t *editor, void *context)
{
    (void)editor;
    rich_app_t *app = (rich_app_t *)context;
    if (!app || app->suppress_dirty)
    {
        return;
    }
    rich_set_dirty(app, true);
    update_status(app, NULL);
}

static void on_style_button(atk_widget_t *button, void *context)
{
    rich_app_t *app = (rich_app_t *)context;
    if (!app || !button || !app->editor)
    {
        return;
    }

    if (button == app->bold_button)
    {
        atk_rich_text_toggle_style(app->editor, ATK_RICH_TEXT_STYLE_BOLD);
    }
    else if (button == app->italic_button)
    {
        atk_rich_text_toggle_style(app->editor, ATK_RICH_TEXT_STYLE_ITALIC);
    }
    else if (button == app->underline_button)
    {
        atk_rich_text_toggle_style(app->editor, ATK_RICH_TEXT_STYLE_UNDERLINE);
    }

    atk_rich_text_focus(atk_state_get(), app->editor);
    sync_controls(app);
    update_status(app, NULL);
    atk_window_mark_dirty(app->window);
}

static void on_font_size_selected(atk_widget_t *dropdown, void *context, size_t index, uintptr_t value)
{
    (void)dropdown;
    (void)index;
    rich_app_t *app = (rich_app_t *)context;
    if (!app || !app->editor)
    {
        return;
    }
    int size_px = (int)value;
    if (size_px <= 0)
    {
        return;
    }
    atk_rich_text_apply_font_size(app->editor, size_px);
    atk_rich_text_focus(atk_state_get(), app->editor);
    sync_controls(app);
    update_status(app, NULL);
    atk_window_mark_dirty(app->window);
}

static void on_menu_button(atk_widget_t *button, void *context)
{
    rich_app_t *app = (rich_app_t *)context;
    if (!app || !button)
    {
        return;
    }

    if (button == app->menu_file_button)
    {
        rich_menu_toggle(app, app->menu_file, app->menu_file_button);
        return;
    }

    if (button == app->menu_insert_button)
    {
        rich_menu_toggle(app, app->menu_insert, app->menu_insert_button);
        return;
    }

    if (button == app->menu_view_button)
    {
        rich_menu_toggle(app, app->menu_view, app->menu_view_button);
        return;
    }
}

static void rich_menus_close(rich_app_t *app)
{
    if (!app)
    {
        return;
    }

    if (app->menu_file)
    {
        atk_menu_hide(app->menu_file);
    }
    if (app->menu_insert)
    {
        atk_menu_hide(app->menu_insert);
    }
    if (app->menu_view)
    {
        atk_menu_hide(app->menu_view);
    }

    app->menu_open = NULL;
}

static void rich_menu_toggle(rich_app_t *app, atk_widget_t *menu, atk_widget_t *button)
{
    if (!app || !app->window || !menu || !button)
    {
        return;
    }

    bool already_open = (app->menu_open == menu) && atk_menu_is_visible(menu);
    rich_menus_close(app);
    if (already_open)
    {
        atk_window_mark_dirty(app->window);
        return;
    }

    atk_window_priv_t *wpriv = (atk_window_priv_t *)atk_widget_priv(app->window, &ATK_WINDOW_CLASS);
    if (wpriv)
    {
        atk_list_node_t *node = atk_list_find(&wpriv->children, menu);
        if (node)
        {
            atk_list_move_to_back(&wpriv->children, node);
        }
    }

    int menu_x = button->x;
    int menu_y = button->y + button->height;
    atk_menu_show(menu, menu_x, menu_y);
    if (menu->width < button->width)
    {
        menu->width = button->width;
    }

    if (menu->width > app->window->width)
    {
        menu->width = app->window->width;
    }
    if (menu->x + menu->width > app->window->width - 2)
    {
        menu->x = app->window->width - menu->width - 2;
    }
    if (menu->x < 0)
    {
        menu->x = 0;
    }

    app->menu_open = menu;
    atk_window_mark_dirty(app->window);
}

static bool rich_menu_button_hit_test(const atk_widget_t *button, int px, int py)
{
    if (!button || !button->used)
    {
        return false;
    }

    int origin_x = 0;
    int origin_y = 0;
    if (button->parent)
    {
        atk_widget_absolute_position(button->parent, &origin_x, &origin_y);
    }
    return atk_button_hit_test(button, origin_x, origin_y, px, py);
}

static void rich_menu_action_file_new(void *context)
{
    rich_app_t *app = (rich_app_t *)context;
    if (!app)
    {
        return;
    }
    rich_menus_close(app);
    rich_new_document(app);
}

static void rich_menu_action_file_open(void *context)
{
    rich_app_t *app = (rich_app_t *)context;
    if (!app)
    {
        return;
    }
    rich_menus_close(app);
    rich_request_open(app);
}

static void rich_menu_action_file_save(void *context)
{
    rich_app_t *app = (rich_app_t *)context;
    if (!app)
    {
        return;
    }
    rich_menus_close(app);
    if (app->current_path && app->current_path[0])
    {
        (void)rich_save_to_path(app, app->current_path);
    }
    else
    {
        rich_request_save_as(app);
    }
}

static void rich_menu_action_file_save_as(void *context)
{
    rich_app_t *app = (rich_app_t *)context;
    if (!app)
    {
        return;
    }
    rich_menus_close(app);
    rich_request_save_as(app);
}

static void rich_menu_action_file_exit(void *context)
{
    rich_app_t *app = (rich_app_t *)context;
    if (!app)
    {
        return;
    }
    rich_menus_close(app);
    app->running = false;
    atk_main_request_exit();
}

static void rich_menu_action_insert_page_break(void *context)
{
    rich_app_t *app = (rich_app_t *)context;
    if (!app || !app->editor)
    {
        return;
    }
    rich_menus_close(app);
    atk_rich_text_insert_page_break(app->editor);
    atk_rich_text_focus(atk_state_get(), app->editor);
    update_status(app, "Inserted page break");
    atk_window_mark_dirty(app->window);
}

static void rich_menu_action_view_toggle_pagination(void *context)
{
    rich_app_t *app = (rich_app_t *)context;
    if (!app || !app->editor)
    {
        return;
    }
    rich_menus_close(app);
    bool enabled = atk_rich_text_pagination_enabled(app->editor);
    atk_rich_text_set_pagination_enabled(app->editor, !enabled);
    update_status(app, NULL);
    atk_window_mark_dirty(app->window);
}

static void sync_controls(rich_app_t *app)
{
    if (!app || !app->editor)
    {
        return;
    }

    uint32_t style = atk_rich_text_current_style(app->editor);
    int font_size = atk_rich_text_current_font_size(app->editor);

    if (app->bold_button)
    {
        atk_button_set_title(app->bold_button, (style & ATK_RICH_TEXT_STYLE_BOLD) ? "[B]" : "B");
    }
    if (app->italic_button)
    {
        atk_button_set_title(app->italic_button, (style & ATK_RICH_TEXT_STYLE_ITALIC) ? "[I]" : "I");
    }
    if (app->underline_button)
    {
        atk_button_set_title(app->underline_button, (style & ATK_RICH_TEXT_STYLE_UNDERLINE) ? "[U]" : "U");
    }

    if (app->font_dropdown)
    {
        size_t best = 0;
        int best_diff = 0x7FFFFFFF;
        for (size_t i = 0; i < sizeof(k_font_sizes) / sizeof(k_font_sizes[0]); ++i)
        {
            int diff = k_font_sizes[i] - font_size;
            if (diff < 0)
            {
                diff = -diff;
            }
            if (diff < best_diff)
            {
                best_diff = diff;
                best = i;
                if (diff == 0)
                {
                    break;
                }
            }
        }
        atk_dropdown_set_selected(app->font_dropdown, best);
    }
}

static void update_window_title(rich_app_t *app)
{
    if (!app || !app->window)
    {
        return;
    }

    const char *name = app->current_path ? rich_path_basename(app->current_path) : "Untitled";
    char title[48];
    snprintf(title,
             sizeof(title),
             "ATK Rich Text - %s%s",
             name ? name : "Untitled",
             app->dirty ? "*" : "");
    atk_window_set_title_text(app->window, title);
}

static void update_status(rich_app_t *app, const char *note)
{
    if (!app || !app->status)
    {
        return;
    }

    const char *name = app->current_path ? rich_path_basename(app->current_path) : "Untitled";
    bool paged = app->editor ? atk_rich_text_pagination_enabled(app->editor) : false;
    size_t pages = (paged && app->editor) ? atk_rich_text_page_count(app->editor) : 0;
    const char *state = app->dirty ? "Modified" : "Saved";
    const char *mode = paged ? "Pagination: on" : "Pagination: off";

    char buffer[256];
    if (note && note[0])
    {
        snprintf(buffer,
                 sizeof(buffer),
                 "%s | %s | %s | Pages: %zu",
                 name ? name : "Untitled",
                 state,
                 note,
                 pages);
    }
    else
    {
        snprintf(buffer,
                 sizeof(buffer),
                 "%s | %s | %s | Pages: %zu",
                 name ? name : "Untitled",
                 state,
                 mode,
                 pages);
    }
    atk_label_set_text(app->status, buffer);
}

static char *rich_strdup(const char *src)
{
    if (!src)
    {
        return NULL;
    }
    size_t len = strlen(src);
    char *out = (char *)malloc(len + 1);
    if (!out)
    {
        return NULL;
    }
    memcpy(out, src, len);
    out[len] = '\0';
    return out;
}

static const char *rich_path_basename(const char *path)
{
    if (!path || !path[0])
    {
        return path;
    }
    const char *last = path;
    for (const char *p = path; *p; ++p)
    {
        if (*p == '/')
        {
            last = p + 1;
        }
    }
    return last;
}

static const char *rich_dialog_initial_dir(const rich_app_t *app, char *buf, size_t cap)
{
    if (!buf || cap == 0)
    {
        return "/root";
    }
    buf[0] = '\0';

    const char *src = (app && app->current_path) ? app->current_path : NULL;
    if (!src || src[0] == '\0')
    {
        memcpy(buf, "/root", 6);
        return buf;
    }

    size_t len = strlen(src);
    if (len >= cap)
    {
        len = cap - 1;
    }
    memcpy(buf, src, len);
    buf[len] = '\0';

    while (len > 1 && buf[len - 1] == '/')
    {
        buf[--len] = '\0';
    }

    char *last_slash = NULL;
    for (size_t i = 0; i < len; ++i)
    {
        if (buf[i] == '/')
        {
            last_slash = &buf[i];
        }
    }

    if (!last_slash)
    {
        memcpy(buf, "/root", 6);
        return buf;
    }

    if (buf[len - 1] != '/')
    {
        if (last_slash == buf)
        {
            buf[1] = '\0';
        }
        else
        {
            *last_slash = '\0';
        }
    }

    if (buf[0] == '\0')
    {
        memcpy(buf, "/root", 6);
    }
    return buf;
}

static void rich_set_current_path(rich_app_t *app, const char *path)
{
    if (!app)
    {
        return;
    }
    if (app->current_path)
    {
        free(app->current_path);
        app->current_path = NULL;
    }
    if (path && path[0])
    {
        app->current_path = rich_strdup(path);
    }
    update_window_title(app);
}

static void rich_set_dirty(rich_app_t *app, bool dirty)
{
    if (!app)
    {
        return;
    }
    app->dirty = dirty;
    update_window_title(app);
}

static void rich_new_document(rich_app_t *app)
{
    if (!app || !app->editor)
    {
        return;
    }
    app->suppress_dirty = true;
    atk_rich_text_set_text(app->editor, "");
    atk_rich_text_set_pagination_enabled(app->editor, true);
    atk_rich_text_set_font_size(app->editor, 18);
    atk_rich_text_apply_style(app->editor,
                              ATK_RICH_TEXT_STYLE_BOLD | ATK_RICH_TEXT_STYLE_ITALIC | ATK_RICH_TEXT_STYLE_UNDERLINE,
                              false);
    app->suppress_dirty = false;

    rich_set_current_path(app, NULL);
    rich_set_dirty(app, false);
    sync_controls(app);
    update_status(app, "New document");
    atk_rich_text_scroll_to_top(app->editor);
    atk_rich_text_focus(atk_state_get(), app->editor);
    atk_window_mark_dirty(app->window);
}

static void rich_request_open(rich_app_t *app)
{
    if (!app || !app->window)
    {
        return;
    }
    rich_close_file_dialog(app);

    char initial_path[256];
    const char *initial = rich_dialog_initial_dir(app, initial_path, sizeof(initial_path));

    app->file_dialog = atk_app_open_file_dialog_modal(&app->dialog_modal,
                                                      app->window,
                                                      "Open File",
                                                      initial,
                                                      rich_on_open_result,
                                                      app,
                                                      720,
                                                      420,
                                                      USER_ATK_WINDOW_FLAG_RESIZABLE);
    if (!app->file_dialog)
    {
        update_status(app, "Open dialog unavailable");
    }
}

static void rich_request_save_as(rich_app_t *app)
{
    if (!app || !app->window)
    {
        return;
    }
    rich_close_file_dialog(app);

    const char *initial = app->current_path ? app->current_path : "/root/untitled.artk";
    app->file_dialog = atk_app_save_file_dialog_modal(&app->dialog_modal,
                                                      app->window,
                                                      "Save As",
                                                      initial,
                                                      rich_on_save_result,
                                                      app,
                                                      720,
                                                      420,
                                                      USER_ATK_WINDOW_FLAG_RESIZABLE);
    if (!app->file_dialog)
    {
        update_status(app, "Save dialog unavailable");
    }
}

static void rich_load_from_path(rich_app_t *app, const char *path)
{
    if (!app || !app->editor || !path || !path[0])
    {
        return;
    }

    uint8_t *data = NULL;
    size_t size = 0;
    if (!rich_read_file(path, &data, &size))
    {
        update_status(app, "Open failed");
        return;
    }

    app->suppress_dirty = true;
    bool ok = atk_rich_text_deserialize(app->editor, data, size);
    if (!ok)
    {
        char *text = (char *)malloc(size + 1);
        if (text)
        {
            memcpy(text, data, size);
            text[size] = '\0';
            atk_rich_text_set_font_size(app->editor, 18);
            atk_rich_text_apply_style(app->editor,
                                      ATK_RICH_TEXT_STYLE_BOLD | ATK_RICH_TEXT_STYLE_ITALIC | ATK_RICH_TEXT_STYLE_UNDERLINE,
                                      false);
            atk_rich_text_set_text(app->editor, text);
            free(text);
            ok = true;
        }
    }
    free(data);
    app->suppress_dirty = false;

    if (ok)
    {
        rich_set_current_path(app, path);
        rich_set_dirty(app, false);
        sync_controls(app);
        update_status(app, "Opened");
        atk_window_mark_dirty(app->window);
    }
    else
    {
        update_status(app, "Unsupported file");
    }
}

static bool rich_save_to_path(rich_app_t *app, const char *path)
{
    if (!app || !app->editor || !path || !path[0])
    {
        return false;
    }

    bool txt = rich_path_has_ext(path, ".txt");
    bool ok = false;
    if (txt)
    {
        char *text = atk_rich_text_copy_text(app->editor);
        if (!text)
        {
            update_status(app, "Save failed");
            return false;
        }
        size_t len = strlen(text);
        ok = rich_write_file(path, (const uint8_t *)text, len);
        free(text);
    }
    else
    {
        uint8_t *data = NULL;
        size_t size = 0;
        if (!atk_rich_text_serialize(app->editor, &data, &size) || !data)
        {
            update_status(app, "Save failed");
            return false;
        }
        ok = rich_write_file(path, data, size);
        free(data);
    }

    if (ok)
    {
        rich_set_current_path(app, path);
        rich_set_dirty(app, false);
        update_status(app, "Saved");
        atk_window_mark_dirty(app->window);
        return true;
    }

    update_status(app, "Save failed");
    return false;
}

static void rich_on_open_result(atk_widget_t *requester, const char *path, bool confirmed, void *context)
{
    (void)requester;
    rich_app_t *app = (rich_app_t *)context;
    if (!app)
    {
        return;
    }
    app->file_dialog = NULL;
    if (confirmed && path)
    {
        rich_load_from_path(app, path);
    }
    rich_close_file_dialog(app);
}

static void rich_on_save_result(atk_widget_t *requester, const char *path, bool confirmed, void *context)
{
    (void)requester;
    rich_app_t *app = (rich_app_t *)context;
    if (!app)
    {
        return;
    }
    app->file_dialog = NULL;
    if (confirmed && path)
    {
        (void)rich_save_to_path(app, path);
    }
    rich_close_file_dialog(app);
}

static void rich_close_file_dialog(rich_app_t *app)
{
    if (!app)
    {
        return;
    }

    if (app->file_dialog && app->file_dialog->used)
    {
        atk_state_t *state = atk_state_get();
        if (state)
        {
            atk_window_close(state, app->file_dialog);
        }
    }

    if (app->dialog_modal.active)
    {
        atk_modal_end(&app->dialog_modal);
    }

    app->file_dialog = NULL;
    if (app->window)
    {
        atk_window_mark_dirty(app->window);
    }
}

static bool rich_read_file(const char *path, uint8_t **data_out, size_t *size_out)
{
    if (!path || !data_out || !size_out)
    {
        return false;
    }
    *data_out = NULL;
    *size_out = 0;

    FILE *f = fopen(path, "rb");
    if (!f)
    {
        return false;
    }
    if (fseek(f, 0, SEEK_END) != 0)
    {
        fclose(f);
        return false;
    }
    long end = ftell(f);
    if (end < 0)
    {
        fclose(f);
        return false;
    }
    if (fseek(f, 0, SEEK_SET) != 0)
    {
        fclose(f);
        return false;
    }

    size_t size = (size_t)end;
    uint8_t *buf = (uint8_t *)malloc(size ? size : 1);
    if (!buf)
    {
        fclose(f);
        return false;
    }
    size_t got = (size > 0) ? fread(buf, 1, size, f) : 0;
    fclose(f);

    *data_out = buf;
    *size_out = got;
    return true;
}

static bool rich_write_file(const char *path, const uint8_t *data, size_t size)
{
    if (!path || !data)
    {
        return false;
    }
    FILE *f = fopen(path, "wb");
    if (!f)
    {
        return false;
    }
    size_t wrote = (size > 0) ? fwrite(data, 1, size, f) : 0;
    fclose(f);
    return wrote == size;
}

static bool rich_path_has_ext(const char *path, const char *ext)
{
    if (!path || !ext)
    {
        return false;
    }
    size_t path_len = strlen(path);
    size_t ext_len = strlen(ext);
    if (ext_len == 0 || path_len < ext_len)
    {
        return false;
    }
    const char *tail = path + (path_len - ext_len);
    for (size_t i = 0; i < ext_len; ++i)
    {
        char a = tail[i];
        char b = ext[i];
        if (a >= 'A' && a <= 'Z')
        {
            a = (char)(a - 'A' + 'a');
        }
        if (b >= 'A' && b <= 'Z')
        {
            b = (char)(b - 'A' + 'a');
        }
        if (a != b)
        {
            return false;
        }
    }
    return true;
}

int main(void)
{
    rich_app_t app;
    memset(&app, 0, sizeof(app));

    if (!atk_user_window_open_with_flags(&app.remote,
                                         "ATK Rich Text",
                                         RICH_APP_WIDTH,
                                         RICH_APP_HEIGHT,
                                         USER_ATK_WINDOW_FLAG_RESIZABLE))
    {
        printf("richtext: failed to open window\n");
        return 1;
    }
    atk_user_enable_dirty_tracking(&app.remote, true);

    if (!build_ui(&app))
    {
        printf("richtext: failed to init UI\n");
        atk_user_close(&app.remote);
        return 1;
    }

    atk_render();
    atk_user_present_force(&app.remote);

    app.running = true;

    atk_main_config_t main_cfg = {
        .window = &app.remote,
        .tick = NULL,
        .tick_context = NULL,
        .present_on_idle = false,
        .legacy_input = false
    };

    atk_main_register_resize_handler(rich_on_resize_event, &app);
    atk_main_register_close_handler(rich_on_close_event, &app);
    atk_main_register_mouse_handler(rich_on_mouse_event, &app);
    atk_main_register_key_handler(rich_on_key_event, &app);

    atk_main(&main_cfg);

    rich_close_file_dialog(&app);
    if (app.current_path)
    {
        free(app.current_path);
        app.current_path = NULL;
    }
    atk_user_close(&app.remote);
    return 0;
}
