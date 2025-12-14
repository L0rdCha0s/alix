#ifndef ATK_WINDOW_H
#define ATK_WINDOW_H

#include "atk_button.h"

/*
 * Destroy all windows and reset the window list.
 *
 * This is used on mode entry and when rebuilding global UI state.
 */
void atk_window_reset_all(atk_state_t *state);

/*
 * Draw all windows (bottom to top) that intersect `clip`.
 *
 * The typical full-scene renderer draws background/desktop first, then windows.
 */
void atk_window_draw_all(const atk_state_t *state, const atk_rect_t *clip);

/*
 * Draw all windows except `skip` that intersect `clip`.
 *
 * Used by fast move/resize paths to paint the scene without a specific window.
 */
void atk_window_draw_all_except(const atk_state_t *state, const atk_rect_t *clip, const atk_widget_t *skip);

/*
 * Draw a single window, including chrome (if enabled) and all children.
 *
 * `window` must be an `ATK_WINDOW_CLASS` instance.
 */
void atk_window_draw(atk_state_t *state, atk_widget_t *window);

/*
 * Draw `start_window` and every window above it in Z-order.
 *
 * This is used by targeted refresh paths that want to repaint only the top
 * portion of the stack (e.g., when a topmost window presents new content).
 */
void atk_window_draw_from(atk_state_t *state, atk_widget_t *start_window);

/* Return true if `window` is currently in `state->windows`. */
bool atk_window_contains(const atk_state_t *state, const atk_widget_t *window);

/* Return true if `window` is the topmost window in Z-order. */
bool atk_window_is_topmost(const atk_state_t *state, const atk_widget_t *window);

/*
 * Move `window` to the front (topmost) of the window list.
 *
 * Returns true if the list order changed.
 */
bool atk_window_bring_to_front(atk_state_t *state, atk_widget_t *window);

/*
 * Return the topmost window under an absolute point.
 *
 * Hit testing includes window chrome when visible.
 */
atk_widget_t *atk_window_hit_test(const atk_state_t *state, int x, int y);

/*
 * Return the topmost window whose title bar is under an absolute point.
 *
 * Returns NULL if no window title bar intersects the point or if chrome is
 * hidden on the candidate window.
 */
atk_widget_t *atk_window_title_hit_test(const atk_state_t *state, int x, int y);

/*
 * Return the window button (e.g., close) under an absolute point.
 *
 * `window` is the owning window; the returned widget is a child button or NULL.
 */
atk_widget_t *atk_window_get_button_at(atk_widget_t *window, int px, int py);

/*
 * Return the topmost child widget within `window` under an absolute point.
 *
 * Used by the ATK mouse dispatcher to route clicks/drags to controls inside a
 * window's client area.
 */
atk_widget_t *atk_window_widget_at(atk_widget_t *window, int px, int py);

/*
 * Mark a window as visually dirty.
 *
 * This invalidates any cached window surface and expands the dirty region so
 * `atk_render()` will repaint the window area.
 */
void atk_window_mark_dirty(const atk_widget_t *window);

/*
 * Clamp a window's position/size to the visible screen bounds.
 *
 * This does not repaint; callers typically mark the old/new bounds dirty and
 * request a redraw.
 */
void atk_window_ensure_inside(atk_widget_t *window);

/*
 * Recompute window layout after a size change.
 *
 * This applies anchor-based layout to children and marks the window dirty.
 */
void atk_window_request_layout(atk_widget_t *window);

/*
 * Return true if the window supports interactive resize.
 *
 * Some window types (e.g., remote windows) may opt out of resizing.
 */
bool atk_window_supports_resize(const atk_widget_t *window);

/*
 * Create and register a new window at (x,y).
 *
 * Returns the window widget owned by the ATK window list, or NULL on failure.
 * Callers typically set title and add children via `atk_window_add_*` helpers.
 */
atk_widget_t *atk_window_create_at(atk_state_t *state, int x, int y);

/*
 * Close (destroy) a window and remove it from the window list.
 *
 * After this call, the `window` pointer should not be used.
 */
void atk_window_close(atk_state_t *state, atk_widget_t *window);

/* Return the window title string (always non-NULL). */
const char *atk_window_title(const atk_widget_t *window);

/* Set the window title text and mark the title bar area dirty. */
void atk_window_set_title_text(atk_widget_t *window, const char *title);

/*
 * Add a button child to a window.
 *
 * Coordinates are relative to the window origin. The returned widget is owned
 * by the window and will be destroyed with it.
 */
atk_widget_t *atk_window_add_button(atk_widget_t *window,
                                    const char *title,
                                    int rel_x,
                                    int rel_y,
                                    int width,
                                    int height,
                                    atk_button_style_t style,
                                    bool draggable,
                                    atk_button_action_t action,
                                    void *context);

/*
 * Attach an arbitrary user context pointer to a window.
 *
 * `on_destroy` (if non-NULL) is invoked when the window is destroyed so callers
 * can release associated resources.
 */
void atk_window_set_context(atk_widget_t *window, void *context, void (*on_destroy)(void *context));

/* Return the window context pointer previously set via `atk_window_set_context()`. */
void *atk_window_context(const atk_widget_t *window);

/*
 * Toggle drawing of window chrome (border/title/close button).
 *
 * When hidden, hit testing for title-bar actions is disabled for the window.
 */
void atk_window_set_chrome_visible(atk_widget_t *window, bool visible);

/* Return whether the window currently draws chrome. */
bool atk_window_is_chrome_visible(const atk_widget_t *window);

/*
 * Validate the internal window list structure.
 *
 * Returns false if corruption is detected; typically used for debug builds.
 */
bool atk_window_list_validate(atk_state_t *state);

/*
 * Dump the window list to the kernel log for debugging.
 *
 * `label` is included in the log output to help correlate call sites.
 */
void atk_window_list_dump(atk_state_t *state, const char *label);

#endif
