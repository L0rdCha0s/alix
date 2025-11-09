#ifndef ATK_INTERNAL_H
#define ATK_INTERNAL_H

#include "atk/object.h"
#include "atk/atk_list.h"
#include "atk/atk_terminal.h"
#include "types.h"

typedef struct atk_menu_bar_entry atk_menu_bar_entry_t;

typedef struct atk_rect
{
    int x;
    int y;
    int width;
    int height;
} atk_rect_t;
#define ATK_WINDOW_TITLE_HEIGHT 28
#define ATK_WINDOW_BORDER 2
#define ATK_WINDOW_TITLE_PADDING_X 8
#define ATK_WINDOW_TITLE_TEXT_Y_OFFSET 6
#define ATK_FONT_WIDTH 8
#define ATK_FONT_HEIGHT 16
#define ATK_BUTTON_TITLE_MAX 32
#define ATK_MENU_BAR_DEFAULT_HEIGHT 40

typedef enum
{
    ATK_BUTTON_STYLE_TITLE_INSIDE = 0,
    ATK_BUTTON_STYLE_TITLE_BELOW = 1
} atk_button_style_t;

typedef void (*atk_button_action_t)(atk_widget_t *widget, void *context);

typedef struct
{
    atk_button_style_t style;
    bool draggable;
    bool absolute;
    char title[ATK_BUTTON_TITLE_MAX];
    atk_button_action_t action;
    void *action_context;
    atk_list_node_t *list_node;
} atk_button_priv_t;

typedef struct
{
    char title[32];
    atk_list_t buttons;
    atk_list_node_t *list_node;
    atk_list_t children;
    atk_list_t text_inputs;
    atk_list_t terminals;
    atk_list_t scrollbars;
    void *user_context;
    void (*on_destroy)(void *context);
} atk_window_priv_t;

typedef struct
{
    uint16_t background;
    uint16_t window_border;
    uint16_t window_title;
    uint16_t window_title_text;
    uint16_t window_body;
    uint16_t button_face;
    uint16_t button_border;
    uint16_t button_text;
    uint16_t desktop_icon_face;
    uint16_t desktop_icon_text;
    uint16_t menu_bar_face;
    uint16_t menu_bar_text;
    uint16_t menu_bar_highlight;
    uint16_t menu_dropdown_face;
    uint16_t menu_dropdown_border;
    uint16_t menu_dropdown_text;
    uint16_t menu_dropdown_highlight;
} atk_theme_t;

typedef struct atk_state
{
    atk_list_t windows;
    int next_window_id;
    atk_widget_t *dragging_window;
    int drag_offset_x;
    int drag_offset_y;

    atk_widget_t *pressed_window_button_window;
    atk_widget_t *pressed_window_button;

    atk_list_t desktop_buttons;
    atk_widget_t *pressed_desktop_button;
    atk_widget_t *dragging_desktop_button;
    int desktop_drag_offset_x;
    int desktop_drag_offset_y;
    bool desktop_drag_moved;

    atk_widget_t *focused_input;
    atk_widget_t *focused_terminal;
    atk_widget_t *dragging_scrollbar;

    atk_theme_t theme;
    bool exit_requested;

    atk_list_t menu_entries;
    struct atk_menu_bar_entry *menu_open_entry;
    struct atk_menu_bar_entry *menu_hover_entry;
    atk_widget_t *menu_logo;
    int menu_bar_height;

    bool dirty_full;
    bool dirty_active;
    int dirty_x0;
    int dirty_y0;
    int dirty_x1;
    int dirty_y1;
} atk_state_t;

extern const atk_class_t ATK_WIDGET_CLASS;
extern const atk_class_t ATK_BUTTON_CLASS;
extern const atk_class_t ATK_WINDOW_CLASS;
extern const atk_class_t ATK_LABEL_CLASS;
extern const atk_class_t ATK_TEXT_INPUT_CLASS;
extern const atk_class_t ATK_TERMINAL_CLASS;
extern const atk_class_t ATK_SCROLLBAR_CLASS;
extern const atk_class_t ATK_LIST_VIEW_CLASS;
extern const atk_class_t ATK_TAB_VIEW_CLASS;
extern const atk_class_t ATK_MENU_CLASS;

atk_state_t *atk_state_get(void);
void atk_widget_draw_any(const atk_state_t *state, const atk_widget_t *widget);
void atk_widget_destroy_any(atk_widget_t *widget);
void atk_dirty_init(atk_state_t *state);
void atk_dirty_mark_rect(int x, int y, int width, int height);
void atk_dirty_mark_all(void);
bool atk_dirty_consume(atk_rect_t *out_rect);

#endif
