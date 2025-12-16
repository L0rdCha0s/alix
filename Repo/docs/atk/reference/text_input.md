# Text Input (`atk_text_input_*`)

Header: `include/atk/atk_text_input.h`

`atk_text_input` is a single-line editable text field with optional submit handler (Enter).

## Key functions

- `atk_window_add_text_input(window, x, y, width)` – creates a text input widget (height derived from font metrics).
- `atk_text_input_set_text(input, text)` / `atk_text_input_text(input)` / `atk_text_input_clear(input)`
- `atk_text_input_set_submit_handler(input, handler, context)` – called on Enter.
- `atk_text_input_focus(state, input)` / `atk_text_input_blur(state, input)` – focus management.
- `atk_text_input_is_focused(input)` – current focus state.
- `atk_text_input_request_redraw(input)` – mark dirty without changing state.

Lower-level helpers (mostly used by ATK internals):

- `atk_text_input_handle_char(input, ch)` – mutates the input and returns an `atk_text_input_event_t`.
- `atk_text_input_hit_test(input, origin_x, origin_y, px, py)`
- `atk_text_input_draw(state, input)` / `atk_text_input_destroy(input)`
