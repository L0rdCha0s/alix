#ifndef ATK_INTERNAL_H
#define ATK_INTERNAL_H

#include "atk/object.h"
#include "types.h"

#define ATK_MAX_WINDOWS 16
#define ATK_WINDOW_TITLE_HEIGHT 28
#define ATK_WINDOW_BORDER 2
#define ATK_WINDOW_TITLE_PADDING_X 8
#define ATK_WINDOW_TITLE_TEXT_Y_OFFSET 6
#define ATK_FONT_WIDTH 8
#define ATK_FONT_HEIGHT 16
#define ATK_BUTTON_TITLE_MAX 32
#define ATK_MAX_WINDOW_BUTTONS 8
#define ATK_MAX_DESKTOP_BUTTONS 16

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
} atk_button_priv_t;

#define ATK_BUTTON_INSTANCE_SIZE (sizeof(atk_widget_t) + sizeof(atk_button_priv_t))

typedef struct
{
    char title[32];
    int button_count;
    atk_widget_t *buttons[ATK_MAX_WINDOW_BUTTONS];
    uint8_t button_storage[ATK_MAX_WINDOW_BUTTONS][ATK_BUTTON_INSTANCE_SIZE];
} atk_window_priv_t;

#define ATK_WINDOW_INSTANCE_SIZE (sizeof(atk_widget_t) + sizeof(atk_window_priv_t))

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

typedef struct
{
    atk_widget_t *windows[ATK_MAX_WINDOWS];
    uint8_t window_storage[ATK_MAX_WINDOWS][ATK_WINDOW_INSTANCE_SIZE];
    int window_count;
    int next_window_id;
    int dragging_window;
    int drag_offset_x;
    int drag_offset_y;

    atk_widget_t *desktop_buttons[ATK_MAX_DESKTOP_BUTTONS];
    uint8_t desktop_button_storage[ATK_MAX_DESKTOP_BUTTONS][ATK_BUTTON_INSTANCE_SIZE];
    int desktop_button_count;
    int pressed_window_button_window;
    int pressed_window_button_index;
    int pressed_desktop_button;
    int dragging_desktop_button;
    int desktop_drag_offset_x;
    int desktop_drag_offset_y;
    bool desktop_drag_moved;

    atk_theme_t theme;
    bool exit_requested;
} atk_state_t;

extern const atk_class_t ATK_WIDGET_CLASS;
extern const atk_class_t ATK_BUTTON_CLASS;
extern const atk_class_t ATK_WINDOW_CLASS;

atk_state_t *atk_state_get(void);

#endif
