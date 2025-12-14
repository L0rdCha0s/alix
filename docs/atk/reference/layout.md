# Layout Helper (`atk_layout_*`)

Header: `include/atk/layout.h`

`atk_layout_t` is a small “layout cursor” for slicing rectangular regions. It’s useful for composing UIs without hard-coding every coordinate.

## Key functions

- `atk_layout_init(layout, x, y, width, height)` – initializes the outer rectangle.
- `atk_layout_set_padding(layout, l, t, r, b)` – sets padding and shrinks the usable “content” area.
- `atk_layout_take_top(layout, height, spacing)` – allocates a top region and advances downward.
- `atk_layout_take_bottom(layout, height, spacing)` – allocates a bottom region and advances upward.
- `atk_layout_content(layout)` – returns the remaining content region.

## Example

```c
atk_layout_t l;
atk_layout_init(&l, 0, 0, window->width, window->height);
atk_layout_set_padding(&l, 16, 16, 16, 16);

atk_layout_region_t header = atk_layout_take_top(&l, 40, 8);
atk_layout_region_t body = atk_layout_content(&l);
```
