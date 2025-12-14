# Navigation Stack (`atk_nav_stack_*`)

Header: `include/atk/atk_nav_stack.h`

Nav stacks manage a stack of “frames” (widgets) and can animate push/pop transitions.

## Key functions

- `atk_window_add_nav_stack(window, x, y, w, h)` / `atk_nav_stack_create()`
- `atk_nav_stack_push_owned(nav, frame, title, owned)` – optionally transfers ownership of `frame` to the stack.
- `atk_nav_stack_push(nav, frame, title)` – pushes a non-owned frame.
- `atk_nav_stack_pop(nav)` – pops the top frame.
- `atk_nav_stack_relayout(nav)` – call after size changes.
- `atk_nav_stack_sliding(nav)` – whether an animated transition is in progress.
