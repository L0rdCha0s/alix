#ifndef ATK_INTERNAL_H
#define ATK_INTERNAL_H

#include "atk/object.h"
#include "atk/atk_list.h"
#include "types.h"
#include "video.h"
#ifndef KERNEL_BUILD
#include "atk/atk_terminal.h"
#endif

typedef struct atk_menu_bar_entry atk_menu_bar_entry_t;

typedef struct atk_rect
{
    int x;
    int y;
    int width;
    int height;
} atk_rect_t;
#define ATK_WINDOW_TITLE_HEIGHT 28
#define ATK_WINDOW_BORDER 2
#define ATK_WINDOW_TITLE_PADDING_X 8
#define ATK_WINDOW_TITLE_TEXT_Y_OFFSET 6
#define ATK_FONT_WIDTH 8
#define ATK_FONT_HEIGHT 16
#define ATK_WINDOW_MIN_WIDTH 160
#define ATK_WINDOW_MIN_HEIGHT (ATK_WINDOW_TITLE_HEIGHT + 96)
#define ATK_WINDOW_RESIZE_MARGIN 6
#define ATK_BUTTON_TITLE_MAX 32
#define ATK_MAX_WINDOWS 16
#define ATK_MAX_WINDOW_BUTTONS 8
#define ATK_MAX_DESKTOP_BUTTONS 16
#define ATK_MENU_BAR_DEFAULT_HEIGHT 40
#define ATK_GUARD_MAGIC 0x6AEBC0DE5AFECAFEULL

#ifndef ATK_DEBUG
#define ATK_DEBUG 0
#endif

#ifndef ATK_USER_POINTER_MIN
#define ATK_USER_POINTER_MIN 0ULL
#endif

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
    bool pressed;
    char title[ATK_BUTTON_TITLE_MAX];
    atk_button_action_t action;
    void *action_context;
    atk_list_node_t *list_node;
} atk_button_priv_t;

typedef struct
{
    char title[32];
    atk_list_t buttons;
    atk_widget_t *close_button;
    atk_list_node_t *list_node;
    atk_list_t children;
    atk_list_t text_inputs;
    atk_list_t terminals;
    atk_list_t scrollbars;
    void *user_context;
    void (*on_destroy)(void *context);
    bool chrome_visible;
    bool shaded;
    int shade_restore_height;
    /* Cached surface of the window (including chrome). */
    video_color_t *surface;
    int surface_width;
    int surface_height;
    int surface_stride_bytes;
    bool surface_valid;
} atk_window_priv_t;

typedef struct
{
    video_color_t background;
    video_color_t window_border;
    video_color_t window_title;
    video_color_t window_title_text;
    video_color_t window_body;
    video_color_t button_face;
    video_color_t button_border;
    video_color_t button_text;
    video_color_t desktop_icon_face;
    video_color_t desktop_icon_text;
    video_color_t menu_bar_face;
    video_color_t menu_bar_text;
    video_color_t menu_bar_highlight;
    video_color_t menu_dropdown_face;
    video_color_t menu_dropdown_border;
    video_color_t menu_dropdown_text;
    video_color_t menu_dropdown_highlight;
} atk_theme_t;

typedef struct atk_state
{
    uint64_t windows_guard_front;
    atk_list_t windows;
    uint64_t windows_guard_back;
    int next_window_id;
    atk_widget_t *dragging_window;
    int drag_offset_x;
    int drag_offset_y;
    atk_widget_t *resizing_window;
    uint32_t resize_edges;
    int resize_start_cursor_x;
    int resize_start_cursor_y;
    int resize_start_x;
    int resize_start_y;
    int resize_start_width;
    int resize_start_height;

    atk_widget_t *pressed_window_button_window;
    atk_widget_t *pressed_window_button;
    uint64_t title_click_last_ms;
    atk_widget_t *title_click_last_window;
    int title_click_last_x;
    int title_click_last_y;

    uint64_t desktop_guard_front;
    atk_list_t desktop_buttons;
    uint64_t desktop_guard_back;
    atk_widget_t *pressed_desktop_button;
    atk_widget_t *dragging_desktop_button;
    int desktop_drag_offset_x;
    int desktop_drag_offset_y;
    bool desktop_drag_moved;

    atk_widget_t *focus_widget;
    atk_widget_t *mouse_capture_widget;

    uint64_t theme_guard_front;
    atk_theme_t theme;
    uint64_t theme_guard_back;
    uint64_t theme_crc;
    bool exit_requested;

    uint64_t menu_guard_front;
    atk_list_t menu_entries;
    uint64_t menu_guard_back;
    struct atk_menu_bar_entry *menu_open_entry;
    struct atk_menu_bar_entry *menu_hover_entry;
    atk_widget_t *menu_logo;
    int menu_bar_height;

    bool dirty_full;
    bool dirty_active;
    int dirty_x0;
    int dirty_y0;
    int dirty_x1;
    int dirty_y1;

    /* Fast-move/resize compositing state */
    video_color_t *drag_scene; /* full-screen scene without the actively dragged window */
    int drag_scene_w;
    int drag_scene_h;
    int drag_scene_stride_bytes;
    bool drag_scene_valid;
    video_color_t *drag_window_surface;
    int drag_window_w;
    int drag_window_h;
    int drag_window_stride_bytes;
    int drag_prev_x;
    int drag_prev_y;
    int drag_start_x;
    int drag_start_y;
    int drag_start_w;
    int drag_start_h;
    bool drag_active;
    video_color_t *drag_overlay;
    int drag_overlay_w;
    int drag_overlay_h;
    int drag_overlay_stride_bytes;

    struct
    {
        bool active;
        int x;
        int y;
        int width;
        int height;
    } resize_band;

    int resize_proposed_x;
    int resize_proposed_y;
    int resize_proposed_w;
    int resize_proposed_h;
} atk_state_t;

extern const atk_class_t ATK_WIDGET_CLASS;
extern const atk_class_t ATK_BUTTON_CLASS;
extern const atk_class_t ATK_WINDOW_CLASS;
extern const atk_class_t ATK_LABEL_CLASS;
extern const atk_class_t ATK_TEXT_INPUT_CLASS;
extern const atk_class_t ATK_TERMINAL_CLASS;
extern const atk_class_t ATK_SCROLLBAR_CLASS;
extern const atk_class_t ATK_LIST_VIEW_CLASS;
extern const atk_class_t ATK_TAB_VIEW_CLASS;
extern const atk_class_t ATK_MENU_CLASS;
extern const atk_class_t ATK_DROPDOWN_CLASS;
extern const atk_class_t ATK_RICH_TEXT_CLASS;

/*
 * Internal: return the global ATK state pointer.
 *
 * The state is owned by `atk.c` and is protected by the ATK state lock.
 */
atk_state_t *atk_state_get(void);

/*
 * Internal: draw an arbitrary widget via its ops table.
 *
 * This does not do any z-ordering or clipping beyond what the widget implements.
 */
void atk_widget_draw_any(const atk_state_t *state, const atk_widget_t *widget);

/*
 * Internal: destroy a widget via its ops table.
 *
 * This is used by containers that own child widgets and need to run per-widget
 * teardown hooks.
 */
void atk_widget_destroy_any(atk_widget_t *widget);

/*
 * Internal: initialize dirty tracking for a newly created state.
 *
 * This marks the full screen dirty and primes the dirty rectangle model.
 */
void atk_dirty_init(atk_state_t *state);

/* Internal: mark an on-screen rectangle dirty (screen-space coordinates). */
void atk_dirty_mark_rect(int x, int y, int width, int height);

/* Internal: mark the entire screen dirty. */
void atk_dirty_mark_all(void);

/*
 * Internal: consume the current dirty region.
 *
 * Returns true and fills `out_rect` when there is pending work for `atk_render()`.
 */
bool atk_dirty_consume(atk_rect_t *out_rect);

/* Internal: return the widget currently holding mouse capture, if any. */
atk_widget_t *atk_state_mouse_capture(const atk_state_t *state);

/*
 * Internal: set mouse capture to `widget`.
 *
 * Captured widgets continue to receive mouse events even if the cursor leaves
 * their bounds until capture is released.
 */
void atk_state_set_mouse_capture(atk_state_t *state, atk_widget_t *widget);

/* Internal: release mouse capture if it is currently held by `widget`. */
void atk_state_release_mouse_capture(atk_state_t *state, const atk_widget_t *widget);

/* Internal: return the currently focused widget, if any. */
atk_widget_t *atk_state_focus_widget(const atk_state_t *state);

/*
 * Internal: set focus to `widget`.
 *
 * Focused widgets are eligible to receive key events.
 */
void atk_state_set_focus_widget(atk_state_t *state, atk_widget_t *widget);

/*
 * Internal: initialize guard fields used to detect state corruption.
 *
 * Guards are defensive only and do not provide synchronization.
 */
void atk_state_guard_init(atk_state_t *state);

/* Internal: reset a guard pair to the known good magic values. */
void atk_guard_reset(uint64_t *front, uint64_t *back);

/* Internal: validate a guard pair and optionally log diagnostics. */
void atk_guard_check(uint64_t *front, uint64_t *back, const char *label);

/*
 * Internal: commit the current theme and update any cached validation CRCs.
 *
 * Called after theme initialization/mutation.
 */
void atk_state_theme_commit(atk_state_t *state);

/* Internal: validate that `state->theme` hasn't been corrupted. */
bool atk_state_theme_validate(const atk_state_t *state, const char *label);

/*
 * Internal: ensure the ATK state lock is initialized.
 *
 * `atk.c` calls this before acquiring/releasing to keep call sites simple.
 */
void atk_state_lock_init(void);

/*
 * Internal: acquire the ATK state lock and return the prior IRQ state.
 *
 * This is a spinlock used by the kernel's UI thread and input paths.
 */
uint64_t atk_state_lock_acquire(void);

/* Internal: release the ATK state lock using the saved IRQ state. */
void atk_state_lock_release(uint64_t flags);
#if ATK_DEBUG
void atk_state_theme_log(const atk_state_t *state, const char *label);
#else
/* Internal: theme logging stub (compiled out unless `ATK_DEBUG` is enabled). */
static inline void atk_state_theme_log(const atk_state_t *state, const char *label)
{
    (void)state;
    (void)label;
}
#endif

#endif
