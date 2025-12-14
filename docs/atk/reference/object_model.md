# ATK Object Model

Header: `include/atk/object.h`

ATK widgets use a small class/payload model: an `atk_widget_t` header plus per-class payload bytes, with optional callback ops for behavior.

## Widget basics

- `atk_widget_create(cls)` allocates `sizeof(atk_widget_t) + payload` and returns an unconfigured widget.
- `atk_widget_destroy(widget)` frees a widget allocated by `atk_widget_create()`.
- `atk_widget_init(memory, cls)` initializes a widget inside caller-provided memory.

## Classes and payloads

- `atk_class_total_payload(cls)` computes the payload bytes required for `cls` including inherited payloads.
- `atk_widget_priv(widget, cls)` returns the payload pointer for a class within the widget (used by widget implementations).
- `atk_widget_is_a(widget, cls)` checks class inheritance.

## Event and draw dispatch

Widgets can install ops callbacks (`atk_widget_ops_t`) that implement draw/hit-test and input handlers:

- `atk_widget_set_ops(widget, ops, context)` / `atk_widget_clear_ops(widget)`
- `atk_widget_dispatch_mouse(widget, event)` returns a bitmask of `atk_mouse_response_flag_t`
- `atk_widget_dispatch_key(widget, key, modifiers, action)` returns a bitmask of `atk_key_response_flag_t`
- `atk_widget_hit_test(widget, origin_x, origin_y, px, py)` performs hit testing (ops hit-test or rectangle fallback)

## Geometry helpers

- `atk_widget_absolute_position(widget, &x, &y)` – converts to screen space.
- `atk_widget_absolute_bounds(widget, &x, &y, &w, &h)` – screen-space rectangle.

## Layout anchors

Anchor flags (`ATK_WIDGET_ANCHOR_*`) implement simple “stick to edges” layout:

- `atk_widget_set_layout(widget, anchors)` captures margins relative to the widget’s current parent size.
- `atk_widget_apply_layout(widget)` recomputes `x/y/width/height` based on current parent size and stored margins.

This is typically used by container widgets and `atk_window_request_layout()`.
