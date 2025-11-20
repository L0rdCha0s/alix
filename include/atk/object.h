#ifndef ATK_OBJECT_H
#define ATK_OBJECT_H

#include "types.h"
#include "libc.h"

typedef struct atk_widget atk_widget_t;
typedef struct atk_class atk_class_t;
struct atk_state;

#define ATK_WIDGET_ANCHOR_LEFT    (1u << 0)
#define ATK_WIDGET_ANCHOR_TOP     (1u << 1)
#define ATK_WIDGET_ANCHOR_RIGHT   (1u << 2)
#define ATK_WIDGET_ANCHOR_BOTTOM  (1u << 3)

typedef struct atk_mouse_event
{
    int cursor_x;
    int cursor_y;
    int origin_x;
    int origin_y;
    int local_x;
    int local_y;
    bool pressed_edge;
    bool released_edge;
    bool left_pressed;
    uint64_t id;
} atk_mouse_event_t;

typedef enum
{
    ATK_MOUSE_RESPONSE_NONE = 0,
    ATK_MOUSE_RESPONSE_HANDLED = (1u << 0),
    ATK_MOUSE_RESPONSE_REDRAW = (1u << 1),
    ATK_MOUSE_RESPONSE_CAPTURE = (1u << 2),
    ATK_MOUSE_RESPONSE_RELEASE = (1u << 3)
} atk_mouse_response_flag_t;

typedef uint32_t atk_mouse_response_t;

typedef enum
{
    ATK_KEY_RESPONSE_NONE = 0,
    ATK_KEY_RESPONSE_HANDLED = (1u << 0),
    ATK_KEY_RESPONSE_REDRAW = (1u << 1)
} atk_key_response_flag_t;

typedef uint32_t atk_key_response_t;

typedef struct atk_widget_ops
{
    void (*destroy)(atk_widget_t *widget, void *context);
    void (*draw)(const struct atk_state *state,
                 const atk_widget_t *widget,
                 int origin_x,
                 int origin_y,
                 void *context);
    bool (*hit_test)(const atk_widget_t *widget,
                     int origin_x,
                     int origin_y,
                     int px,
                     int py,
                     void *context);
    atk_mouse_response_t (*on_mouse)(atk_widget_t *widget,
                                     const atk_mouse_event_t *event,
                                     void *context);
    atk_key_response_t (*on_key)(atk_widget_t *widget, int key, int modifiers, int action, void *context);
} atk_widget_ops_t;

typedef struct
{
    void (*destroy)(atk_widget_t *widget);
    void (*draw)(atk_widget_t *widget, void *context);
    void (*layout)(atk_widget_t *widget, int avail_width, int avail_height);
    bool (*hit_test)(atk_widget_t *widget, int x, int y);
    bool (*on_mouse)(atk_widget_t *widget, int x, int y, int buttons, int action);
    bool (*on_key)(atk_widget_t *widget, int key, int modifiers, int action);
} atk_widget_vtable_t;

struct atk_class
{
    const char *name;
    const atk_class_t *parent;
    const atk_widget_vtable_t *vtable;
    size_t payload_size;
};

struct atk_widget
{
    const atk_class_t *cls;
    bool used;
    int x;
    int y;
    int width;
    int height;
    uint32_t flags;
    int layout_margin_left;
    int layout_margin_top;
    int layout_margin_right;
    int layout_margin_bottom;
    atk_widget_t *parent;
    const atk_widget_ops_t *ops;
    void *ops_context;
};

size_t atk_class_total_payload(const atk_class_t *cls);
atk_widget_t *atk_widget_init(void *memory, const atk_class_t *cls);
atk_widget_t *atk_widget_create(const atk_class_t *cls);
void atk_widget_destroy(atk_widget_t *widget);
bool atk_widget_validate(const atk_widget_t *widget, const char *label);
bool atk_widget_is_a(const atk_widget_t *widget, const atk_class_t *cls);
void *atk_widget_priv(const atk_widget_t *widget, const atk_class_t *cls);
void atk_widget_absolute_position(const atk_widget_t *widget, int *x_out, int *y_out);
void atk_widget_absolute_bounds(const atk_widget_t *widget, int *x_out, int *y_out, int *width_out, int *height_out);
void atk_widget_set_ops(atk_widget_t *widget, const atk_widget_ops_t *ops, void *context);
void atk_widget_clear_ops(atk_widget_t *widget);
const atk_widget_ops_t *atk_widget_get_ops(const atk_widget_t *widget);
void *atk_widget_ops_context(const atk_widget_t *widget);
bool atk_widget_hit_test(const atk_widget_t *widget, int origin_x, int origin_y, int px, int py);
atk_mouse_response_t atk_widget_dispatch_mouse(atk_widget_t *widget, const atk_mouse_event_t *event);
atk_key_response_t atk_widget_dispatch_key(atk_widget_t *widget, int key, int modifiers, int action);
void atk_widget_set_layout(atk_widget_t *widget, uint32_t anchors);
void atk_widget_apply_layout(atk_widget_t *widget);

#endif
