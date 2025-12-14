# Terminal (`atk_terminal_*`)

Header: `include/atk/atk_terminal.h`

The terminal widget provides a scrollback view plus a single-line prompt. It’s used by userland ATK apps such as the graphical shell.

## Key functions

- `atk_window_add_terminal(window, x, y, width, height)` – creates a terminal widget.
- `atk_terminal_write(terminal, data, len)` – append to scrollback.
- `atk_terminal_reset(terminal)` – clears scrollback + input.
- `atk_terminal_handle_char(terminal, ch)` – updates input/scrollback for typed characters.
- `atk_terminal_set_submit_handler(terminal, handler, ctx)` – called on Enter with the submitted line.
- `atk_terminal_set_control_handler(terminal, handler, ctx)` – called for control characters (e.g., Ctrl+C).
- `atk_terminal_focus(state, terminal)` / `atk_terminal_is_focused(state, terminal)` – focus helpers.
- `atk_terminal_get_input(...)` / `atk_terminal_set_input(...)` – manage the current prompt line.
- `atk_terminal_mark_dirty(terminal)` – mark terminal area dirty.
- `atk_terminal_get_dimensions(terminal, &rows, &cols)` – terminal grid size from pixel size + font.
- `atk_terminal_draw(state, terminal)` / `atk_terminal_destroy(terminal)` – draw/destroy helpers.

Userland-only:

- `atk_terminal_handle_resize(terminal)` – reallocate internal buffers after size changes.
