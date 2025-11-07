#ifndef ATK_INTERNAL_H
#define ATK_INTERNAL_H

#include "atk/object.h"
#include "atk/atk_list.h"
#include "atk/atk_terminal.h"
#include "types.h"

#define ATK_WINDOW_TITLE_HEIGHT 28
#define ATK_WINDOW_BORDER 2
#define ATK_WINDOW_TITLE_PADDING_X 8
#define ATK_WINDOW_TITLE_TEXT_Y_OFFSET 6
#define ATK_FONT_WIDTH 8
#define ATK_FONT_HEIGHT 16
#define ATK_BUTTON_TITLE_MAX 32

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
} atk_state_t;

extern const atk_class_t ATK_WIDGET_CLASS;
extern const atk_class_t ATK_BUTTON_CLASS;
extern const atk_class_t ATK_WINDOW_CLASS;
extern const atk_class_t ATK_LABEL_CLASS;
extern const atk_class_t ATK_TEXT_INPUT_CLASS;
extern const atk_class_t ATK_TERMINAL_CLASS;
extern const atk_class_t ATK_SCROLLBAR_CLASS;

atk_state_t *atk_state_get(void);

#endif
