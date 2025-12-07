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

int atk_main(const atk_main_config_t *config);
void atk_main_request_exit(void);

void atk_main_set_event_handlers(const atk_app_event_handlers_t *handlers, void *context);
void atk_main_set_tick_handler(atk_app_tick_handler_t tick, void *context);

atk_user_window_t *atk_main_active_window(void);
bool atk_main_push_window(atk_user_window_t *window);
bool atk_main_pop_window(void);

typedef struct
{
    atk_user_window_t remote;
    atk_widget_t *suspended_window;
    bool suspended_used;
    bool active;
} atk_modal_session_t;

bool atk_modal_begin(atk_modal_session_t *session,
                     const char *title,
                     uint32_t width,
                     uint32_t height,
                     uint32_t flags,
                     atk_widget_t *suspend_window);
void atk_modal_end(atk_modal_session_t *session);

atk_widget_t *atk_app_open_file_dialog_modal(atk_modal_session_t *session,
                                             atk_widget_t *requester,
                                             const char *title,
                                             const char *initial_path,
                                             atk_file_dialog_result_t on_result,
                                             void *context,
                                             uint32_t width,
                                             uint32_t height,
                                             uint32_t flags);

/* Register additional input callbacks that run after ATK's default dispatch. Returns -1 on failure. */
int atk_main_register_mouse_handler(atk_app_mouse_handler_t handler, void *context);
int atk_main_register_key_handler(atk_app_key_handler_t handler, void *context);
bool atk_main_unregister_mouse_handler(int handle);
bool atk_main_unregister_key_handler(int handle);
int atk_main_register_resize_handler(atk_app_resize_handler_t handler, void *context);
int atk_main_register_close_handler(atk_app_close_handler_t handler, void *context);
bool atk_main_unregister_resize_handler(int handle);
bool atk_main_unregister_close_handler(int handle);
void atk_main_clear_input_handlers(void);

#endif /* USER_ATK_APP_H */
