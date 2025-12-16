#ifndef ATK_OBJECT_H
#define ATK_OBJECT_H

#include "types.h"
#include "libc.h"

typedef struct atk_widget atk_widget_t;
typedef struct atk_class atk_class_t;
struct atk_state;

/* Layout anchors used by `atk_widget_set_layout()` / `atk_widget_apply_layout()`. */
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

/*
 * Return the total payload size for `cls`, including all inherited payloads.
 *
 * This excludes `sizeof(atk_widget_t)` itself and is intended for callers that
 * allocate widgets into custom storage.
 */
size_t atk_class_total_payload(const atk_class_t *cls);

/*
 * Initialize an `atk_widget_t` in caller-provided memory.
 *
 * `memory` must point to a buffer of at least:
 *   `sizeof(atk_widget_t) + atk_class_total_payload(cls)`
 *
 * The returned widget is not "live" yet: `used` is set to false and callers
 * must fill coordinates, parent, ops, etc. before participating in hit testing
 * or draw/dispatch.
 */
atk_widget_t *atk_widget_init(void *memory, const atk_class_t *cls);

/*
 * Allocate and initialize a widget instance for `cls`.
 *
 * This allocates `atk_widget_t` plus class payload storage, sets fields to
 * zeroed defaults, and returns an unconfigured widget (with `used == false`).
 * Destroy via `atk_widget_destroy()`.
 */
atk_widget_t *atk_widget_create(const atk_class_t *cls);

/*
 * Destroy a widget allocated with `atk_widget_create()` (or legacy `malloc`).
 *
 * This frees the widget and any guard metadata used for validation. It does
 * not automatically remove the widget from any parent list; widget owners
 * should unlink before destroying when applicable.
 */
void atk_widget_destroy(atk_widget_t *widget);

/*
 * Validate a widget pointer against internal guard metadata.
 *
 * Returns false if the pointer is unknown or appears corrupted. `label` is
 * used for debug logging and can be NULL.
 */
bool atk_widget_validate(const atk_widget_t *widget, const char *label);

/*
 * Return true if `widget` is an instance of `cls` or any subclass of it.
 *
 * Returns false for NULL/invalid inputs.
 */
bool atk_widget_is_a(const atk_widget_t *widget, const atk_class_t *cls);

/*
 * Return the payload pointer for `cls` within `widget`.
 *
 * `cls` must be in the widget's inheritance chain (see `atk_widget_is_a()`).
 * Returns NULL for invalid widgets or mismatched classes.
 */
void *atk_widget_priv(const atk_widget_t *widget, const atk_class_t *cls);

/*
 * Compute the absolute (screen-space) position of a widget.
 *
 * This walks up the parent chain and sums `x`/`y`. NULL widgets yield (0,0).
 */
void atk_widget_absolute_position(const atk_widget_t *widget, int *x_out, int *y_out);

/*
 * Compute absolute bounds for a widget.
 *
 * Like `atk_widget_absolute_position()`, but also returns the widget's width
 * and height. For NULL/invalid widgets, all outputs are set to 0.
 */
void atk_widget_absolute_bounds(const atk_widget_t *widget, int *x_out, int *y_out, int *width_out, int *height_out);

/*
 * Attach an ops table to a widget.
 *
 * `ops` provides callback-style behavior (draw, hit test, mouse/key handling)
 * for widgets implemented using the base object model.
 */
void atk_widget_set_ops(atk_widget_t *widget, const atk_widget_ops_t *ops, void *context);

/* Remove any previously installed ops table from `widget`. */
void atk_widget_clear_ops(atk_widget_t *widget);

/* Return the currently installed ops table for `widget` (or NULL). */
const atk_widget_ops_t *atk_widget_get_ops(const atk_widget_t *widget);

/* Return the ops context pointer previously set via `atk_widget_set_ops()`. */
void *atk_widget_ops_context(const atk_widget_t *widget);

/*
 * Hit test a widget against an absolute point.
 *
 * `origin_x`/`origin_y` are the absolute position of the parent. If an ops
 * hit-test callback exists, it is used; otherwise ATK falls back to rectangle
 * bounds.
 */
bool atk_widget_hit_test(const atk_widget_t *widget, int origin_x, int origin_y, int px, int py);

/*
 * Dispatch a mouse event to a widget's ops callback.
 *
 * The returned value is a bitmask of `atk_mouse_response_flag_t`. The ATK core
 * uses this to decide whether to redraw, capture the mouse, etc.
 */
atk_mouse_response_t atk_widget_dispatch_mouse(atk_widget_t *widget, const atk_mouse_event_t *event);

/*
 * Dispatch a key event to a widget's ops callback.
 *
 * The returned value is a bitmask of `atk_key_response_flag_t`.
 */
atk_key_response_t atk_widget_dispatch_key(atk_widget_t *widget, int key, int modifiers, int action);

/*
 * Record layout anchors and margins relative to the current parent size.
 *
 * Call this after initial placement to make `atk_widget_apply_layout()` able to
 * reposition/resize the widget when its parent changes size.
 */
void atk_widget_set_layout(atk_widget_t *widget, uint32_t anchors);

/*
 * Apply layout anchors to a widget using margins captured by `atk_widget_set_layout()`.
 *
 * This is a no-op if the widget has no parent or `flags == 0`.
 */
void atk_widget_apply_layout(atk_widget_t *widget);

#endif
