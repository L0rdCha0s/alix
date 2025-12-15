#ifndef USER_ATK_APP_H
#define USER_ATK_APP_H

#include "atk_user.h"
#include "atk/atk_file_dialog.h"

typedef bool (*atk_app_mouse_handler_t)(const user_atk_event_t *event, void *context);
typedef bool (*atk_app_key_handler_t)(const user_atk_event_t *event, void *context);
typedef bool (*atk_app_resize_handler_t)(uint32_t width, uint32_t height, void *context);
typedef void (*atk_app_close_handler_t)(void *context);
typedef bool (*atk_app_tick_handler_t)(void *context);

typedef struct
{
    atk_app_resize_handler_t on_resize;
    atk_app_close_handler_t on_close;
    /* Legacy raw input hooks; only used when legacy_input is true. Prefer registering callbacks via atk_main_register_* handlers. */
    atk_app_mouse_handler_t on_mouse;
    atk_app_key_handler_t on_key;
} atk_app_event_handlers_t;

typedef struct
{
    atk_user_window_t *window;
    atk_app_tick_handler_t tick;
    void *tick_context;
    bool present_on_idle;
    bool legacy_input;
} atk_main_config_t;

/*
 * Run the standard userland ATK event loop for a remote window.
 *
 * Callers are expected to:
 * - create/open `config->window` via `atk_user_window_open*()`,
 * - call `atk_init()` and build their widget tree,
 * - call `atk_render()` + `atk_user_present_force()` once to paint the first frame,
 * - then call `atk_main()` to handle input and redraws.
 *
 * The loop drains events, dispatches them into ATK, calls the optional `tick`
 * callback, renders when ATK marks state dirty, and presents via
 * `atk_user_present()` (or `atk_user_present_force()` when `present_on_idle` is
 * true).
 *
 * Returns 0 on clean exit and -1 on invalid arguments or when the remote window
 * cannot be made active.
 */
int atk_main(const atk_main_config_t *config);

/*
 * Request `atk_main()` to exit as soon as possible.
 *
 * This is safe to call from callbacks invoked by `atk_main()`.
 */
void atk_main_request_exit(void);

/*
 * Install legacy event handlers used when `atk_main_config_t.legacy_input` is true.
 *
 * Prefer `atk_main_register_*_handler()` for new code.
 */
void atk_main_set_event_handlers(const atk_app_event_handlers_t *handlers, void *context);

/*
 * Install an optional "tick" callback invoked once per `atk_main()` iteration.
 *
 * If the tick returns true, ATK is rendered/presented as though a redraw was
 * requested by input.
 */
void atk_main_set_tick_handler(atk_app_tick_handler_t tick, void *context);

/* Return the currently active remote window (top of the window stack), or NULL. */
atk_user_window_t *atk_main_active_window(void);

/*
 * Push a remote window onto the active window stack.
 *
 * The pushed window becomes the active render target by attaching its buffer as
 * the userland video surface. Returns false if the stack is full.
 */
bool atk_main_push_window(atk_user_window_t *window);

/*
 * Pop the active remote window from the stack.
 *
 * Returns false if the stack is empty. If a window remains after the pop, it is
 * automatically re-attached as the active render target.
 */
bool atk_main_pop_window(void);

typedef struct
{
    atk_user_window_t remote;
    atk_widget_t *suspended_window;
    bool suspended_used;
    bool active;
} atk_modal_session_t;

/*
 * Begin a modal session by opening a new remote window and pushing it on the stack.
 *
 * If `suspend_window` is non-NULL, it is temporarily hidden by toggling its
 * `used` field off for the duration of the modal. This avoids the suspended
 * window drawing/receiving events while a modal is active.
 */
bool atk_modal_begin(atk_modal_session_t *session,
                     const char *title,
                     uint32_t width,
                     uint32_t height,
                     uint32_t flags,
                     atk_widget_t *suspend_window);

/*
 * End a modal session started with `atk_modal_begin()`.
 *
 * This closes the modal remote window, pops it from the stack, restores any
 * suspended window, and forces a full redraw/present of the newly active window.
 */
void atk_modal_end(atk_modal_session_t *session);

/*
 * Open a file-open dialog in a modal remote window.
 *
 * This is a convenience wrapper around `atk_modal_begin()` +
 * `atk_file_dialog_open()` that ensures an initial redraw/present.
 */
atk_widget_t *atk_app_open_file_dialog_modal(atk_modal_session_t *session,
                                             atk_widget_t *requester,
                                             const char *title,
                                             const char *initial_path,
                                             atk_file_dialog_result_t on_result,
                                             void *context,
                                             uint32_t width,
                                             uint32_t height,
                                             uint32_t flags);

/*
 * Open a file-save dialog in a modal remote window.
 *
 * This is a convenience wrapper around `atk_modal_begin()` +
 * `atk_file_dialog_save()` that ensures an initial redraw/present.
 */
atk_widget_t *atk_app_save_file_dialog_modal(atk_modal_session_t *session,
                                             atk_widget_t *requester,
                                             const char *title,
                                             const char *initial_path,
                                             atk_file_dialog_result_t on_result,
                                             void *context,
                                             uint32_t width,
                                             uint32_t height,
                                             uint32_t flags);

/*
 * Register additional mouse callbacks that run after ATK's default dispatch.
 *
 * Returns a positive handle on success and -1 on failure. Callbacks return true
 * to request a redraw.
 */
int atk_main_register_mouse_handler(atk_app_mouse_handler_t handler, void *context);

/*
 * Register additional key callbacks that run after ATK's default dispatch.
 *
 * Returns a positive handle on success and -1 on failure. Callbacks return true
 * to request a redraw.
 */
int atk_main_register_key_handler(atk_app_key_handler_t handler, void *context);

/* Unregister a mouse handler previously returned by `atk_main_register_mouse_handler()`. */
bool atk_main_unregister_mouse_handler(int handle);

/* Unregister a key handler previously returned by `atk_main_register_key_handler()`. */
bool atk_main_unregister_key_handler(int handle);

/*
 * Register a resize handler invoked for `USER_ATK_EVENT_RESIZE`.
 *
 * Returns a positive handle on success and -1 on failure. Handlers return true
 * to request a redraw (and can update layout/state based on the new size).
 */
int atk_main_register_resize_handler(atk_app_resize_handler_t handler, void *context);

/*
 * Register a close handler invoked for `USER_ATK_EVENT_CLOSE`.
 *
 * Returns a positive handle on success and -1 on failure. If no close handler is
 * registered, `atk_main()` performs a default close action (pop modal windows or
 * exit the loop when closing the last window).
 */
int atk_main_register_close_handler(atk_app_close_handler_t handler, void *context);

/* Unregister a resize handler previously returned by `atk_main_register_resize_handler()`. */
bool atk_main_unregister_resize_handler(int handle);

/* Unregister a close handler previously returned by `atk_main_register_close_handler()`. */
bool atk_main_unregister_close_handler(int handle);

/* Remove all registered mouse/key/resize/close handlers. */
void atk_main_clear_input_handlers(void);

#endif /* USER_ATK_APP_H */
