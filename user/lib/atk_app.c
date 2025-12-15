#include "atk_app.h"

#include "atk.h"
#include "atk_internal.h"
#include "atk_window.h"
#include "libc.h"
#include "serial.h"
#include "usyscall.h"
#include "video_surface.h"

#ifndef ATK_MAIN_WINDOW_STACK
#define ATK_MAIN_WINDOW_STACK 4
#endif
#ifndef ATK_MAIN_MAX_MOUSE_HANDLERS
#define ATK_MAIN_MAX_MOUSE_HANDLERS 8
#endif
#ifndef ATK_MAIN_MAX_KEY_HANDLERS
#define ATK_MAIN_MAX_KEY_HANDLERS 8
#endif
#ifndef ATK_MAIN_MAX_RESIZE_HANDLERS
#define ATK_MAIN_MAX_RESIZE_HANDLERS 4
#endif
#ifndef ATK_MAIN_MAX_CLOSE_HANDLERS
#define ATK_MAIN_MAX_CLOSE_HANDLERS 4
#endif

typedef struct
{
    atk_user_window_t *remote;
} atk_main_window_entry_t;

typedef struct
{
    atk_app_mouse_handler_t handler;
    void *ctx;
    bool used;
} atk_main_mouse_slot_t;

typedef struct
{
    atk_app_key_handler_t handler;
    void *ctx;
    bool used;
} atk_main_key_slot_t;

typedef struct
{
    atk_app_resize_handler_t handler;
    void *ctx;
    bool used;
} atk_main_resize_slot_t;

typedef struct
{
    atk_app_close_handler_t handler;
    void *ctx;
    bool used;
} atk_main_close_slot_t;

static struct
{
    atk_main_window_entry_t stack[ATK_MAIN_WINDOW_STACK];
    int depth;
    const atk_app_event_handlers_t *handlers;
    void *handler_ctx;
    atk_app_tick_handler_t tick;
    void *tick_ctx;
    bool legacy_input;
    bool exit_requested;
    bool stack_changed;
    atk_main_mouse_slot_t mouse_handlers[ATK_MAIN_MAX_MOUSE_HANDLERS];
    atk_main_key_slot_t key_handlers[ATK_MAIN_MAX_KEY_HANDLERS];
    atk_main_resize_slot_t resize_handlers[ATK_MAIN_MAX_RESIZE_HANDLERS];
    atk_main_close_slot_t close_handlers[ATK_MAIN_MAX_CLOSE_HANDLERS];
} g_atk_main = { 0 };

static inline atk_user_window_t *atk_main_top_window(void)
{
    if (g_atk_main.depth <= 0)
    {
        return NULL;
    }
    return g_atk_main.stack[g_atk_main.depth - 1].remote;
}

static inline void atk_main_mark_stack_changed(void)
{
    g_atk_main.stack_changed = true;
}

static void atk_main_clear_mouse_handlers(void)
{
    for (int i = 0; i < ATK_MAIN_MAX_MOUSE_HANDLERS; ++i)
    {
        g_atk_main.mouse_handlers[i].handler = NULL;
        g_atk_main.mouse_handlers[i].ctx = NULL;
        g_atk_main.mouse_handlers[i].used = false;
    }
}

static void atk_main_clear_key_handlers(void)
{
    for (int i = 0; i < ATK_MAIN_MAX_KEY_HANDLERS; ++i)
    {
        g_atk_main.key_handlers[i].handler = NULL;
        g_atk_main.key_handlers[i].ctx = NULL;
        g_atk_main.key_handlers[i].used = false;
    }
}

static void atk_main_clear_resize_handlers(void)
{
    for (int i = 0; i < ATK_MAIN_MAX_RESIZE_HANDLERS; ++i)
    {
        g_atk_main.resize_handlers[i].handler = NULL;
        g_atk_main.resize_handlers[i].ctx = NULL;
        g_atk_main.resize_handlers[i].used = false;
    }
}

static void atk_main_clear_close_handlers(void)
{
    for (int i = 0; i < ATK_MAIN_MAX_CLOSE_HANDLERS; ++i)
    {
        g_atk_main.close_handlers[i].handler = NULL;
        g_atk_main.close_handlers[i].ctx = NULL;
        g_atk_main.close_handlers[i].used = false;
    }
}

void atk_main_clear_input_handlers(void)
{
    atk_main_clear_mouse_handlers();
    atk_main_clear_key_handlers();
    atk_main_clear_resize_handlers();
    atk_main_clear_close_handlers();
}

int atk_main_register_mouse_handler(atk_app_mouse_handler_t handler, void *context)
{
    if (!handler)
    {
        return -1;
    }
    for (int i = 0; i < ATK_MAIN_MAX_MOUSE_HANDLERS; ++i)
    {
        if (!g_atk_main.mouse_handlers[i].used)
        {
            g_atk_main.mouse_handlers[i].handler = handler;
            g_atk_main.mouse_handlers[i].ctx = context;
            g_atk_main.mouse_handlers[i].used = true;
            return i + 1;
        }
    }
    return -1;
}

bool atk_main_unregister_mouse_handler(int handle)
{
    if (handle <= 0 || handle > ATK_MAIN_MAX_MOUSE_HANDLERS)
    {
        return false;
    }
    atk_main_mouse_slot_t *slot = &g_atk_main.mouse_handlers[handle - 1];
    slot->handler = NULL;
    slot->ctx = NULL;
    slot->used = false;
    return true;
}

int atk_main_register_key_handler(atk_app_key_handler_t handler, void *context)
{
    if (!handler)
    {
        return -1;
    }
    for (int i = 0; i < ATK_MAIN_MAX_KEY_HANDLERS; ++i)
    {
        if (!g_atk_main.key_handlers[i].used)
        {
            g_atk_main.key_handlers[i].handler = handler;
            g_atk_main.key_handlers[i].ctx = context;
            g_atk_main.key_handlers[i].used = true;
            return i + 1;
        }
    }
    return -1;
}

bool atk_main_unregister_key_handler(int handle)
{
    if (handle <= 0 || handle > ATK_MAIN_MAX_KEY_HANDLERS)
    {
        return false;
    }
    atk_main_key_slot_t *slot = &g_atk_main.key_handlers[handle - 1];
    slot->handler = NULL;
    slot->ctx = NULL;
    slot->used = false;
    return true;
}

int atk_main_register_resize_handler(atk_app_resize_handler_t handler, void *context)
{
    if (!handler)
    {
        return -1;
    }
    for (int i = 0; i < ATK_MAIN_MAX_RESIZE_HANDLERS; ++i)
    {
        if (!g_atk_main.resize_handlers[i].used)
        {
            g_atk_main.resize_handlers[i].handler = handler;
            g_atk_main.resize_handlers[i].ctx = context;
            g_atk_main.resize_handlers[i].used = true;
            return i + 1;
        }
    }
    return -1;
}

bool atk_main_unregister_resize_handler(int handle)
{
    if (handle <= 0 || handle > ATK_MAIN_MAX_RESIZE_HANDLERS)
    {
        return false;
    }
    atk_main_resize_slot_t *slot = &g_atk_main.resize_handlers[handle - 1];
    slot->handler = NULL;
    slot->ctx = NULL;
    slot->used = false;
    return true;
}

int atk_main_register_close_handler(atk_app_close_handler_t handler, void *context)
{
    if (!handler)
    {
        return -1;
    }
    for (int i = 0; i < ATK_MAIN_MAX_CLOSE_HANDLERS; ++i)
    {
        if (!g_atk_main.close_handlers[i].used)
        {
            g_atk_main.close_handlers[i].handler = handler;
            g_atk_main.close_handlers[i].ctx = context;
            g_atk_main.close_handlers[i].used = true;
            return i + 1;
        }
    }
    return -1;
}

bool atk_main_unregister_close_handler(int handle)
{
    if (handle <= 0 || handle > ATK_MAIN_MAX_CLOSE_HANDLERS)
    {
        return false;
    }
    atk_main_close_slot_t *slot = &g_atk_main.close_handlers[handle - 1];
    slot->handler = NULL;
    slot->ctx = NULL;
    slot->used = false;
    return true;
}

static void atk_main_attach_remote(atk_user_window_t *win)
{
    if (!win || !win->buffer || win->width == 0 || win->height == 0)
    {
        return;
    }
    video_surface_attach(win->buffer, win->width, win->height, win->buffer_bytes);
    video_surface_set_tracking(win->track_dirty);
    video_surface_force_dirty();
    atk_main_mark_stack_changed();
}

void atk_main_set_event_handlers(const atk_app_event_handlers_t *handlers, void *context)
{
    g_atk_main.handlers = handlers;
    g_atk_main.handler_ctx = context;
}

void atk_main_set_tick_handler(atk_app_tick_handler_t tick, void *context)
{
    g_atk_main.tick = tick;
    g_atk_main.tick_ctx = context;
}

atk_user_window_t *atk_main_active_window(void)
{
    return atk_main_top_window();
}

bool atk_main_push_window(atk_user_window_t *window)
{
    if (!window || g_atk_main.depth >= ATK_MAIN_WINDOW_STACK)
    {
        return false;
    }
    g_atk_main.stack[g_atk_main.depth++].remote = window;
    atk_main_attach_remote(window);
    return true;
}

bool atk_main_pop_window(void)
{
    if (g_atk_main.depth <= 0)
    {
        return false;
    }
    g_atk_main.depth--;
    atk_user_window_t *next = atk_main_top_window();
    if (next)
    {
        atk_main_attach_remote(next);
    }
    else
    {
        video_surface_detach();
    }
    atk_main_mark_stack_changed();
    return true;
}

void atk_main_request_exit(void)
{
    g_atk_main.exit_requested = true;
}

static bool atk_main_state_dirty(void)
{
    atk_state_t *state = atk_state_get();
    if (!state)
    {
        return false;
    }
    return state->dirty_full || state->dirty_active;
}

static bool atk_main_fire_mouse_handlers(const user_atk_event_t *event)
{
    bool redraw = false;
    if (!event)
    {
        return false;
    }
    for (int i = 0; i < ATK_MAIN_MAX_MOUSE_HANDLERS; ++i)
    {
        atk_main_mouse_slot_t *slot = &g_atk_main.mouse_handlers[i];
        if (!slot->used || !slot->handler)
        {
            continue;
        }
        redraw |= slot->handler(event, slot->ctx);
        if (g_atk_main.exit_requested)
        {
            break;
        }
    }
    return redraw;
}

static bool atk_main_fire_key_handlers(const user_atk_event_t *event)
{
    bool redraw = false;
    if (!event)
    {
        return false;
    }
    for (int i = 0; i < ATK_MAIN_MAX_KEY_HANDLERS; ++i)
    {
        atk_main_key_slot_t *slot = &g_atk_main.key_handlers[i];
        if (!slot->used || !slot->handler)
        {
            continue;
        }
        redraw |= slot->handler(event, slot->ctx);
        if (g_atk_main.exit_requested)
        {
            break;
        }
    }
    return redraw;
}

static bool atk_main_fire_resize_handlers(uint32_t width, uint32_t height)
{
    bool redraw = false;
    for (int i = 0; i < ATK_MAIN_MAX_RESIZE_HANDLERS; ++i)
    {
        atk_main_resize_slot_t *slot = &g_atk_main.resize_handlers[i];
        if (!slot->used || !slot->handler)
        {
            continue;
        }
        redraw |= slot->handler(width, height, slot->ctx);
        if (g_atk_main.exit_requested)
        {
            break;
        }
    }
    return redraw;
}

static void atk_main_fire_close_handlers(void)
{
    for (int i = 0; i < ATK_MAIN_MAX_CLOSE_HANDLERS; ++i)
    {
        atk_main_close_slot_t *slot = &g_atk_main.close_handlers[i];
        if (!slot->used || !slot->handler)
        {
            continue;
        }
        slot->handler(slot->ctx);
        if (g_atk_main.exit_requested)
        {
            break;
        }
    }
}

static bool atk_main_handle_default_mouse(const user_atk_event_t *event)
{
    if (!event)
    {
        return false;
    }
    bool left = (event->flags & USER_ATK_MOUSE_FLAG_LEFT) != 0;
    bool press = (event->flags & USER_ATK_MOUSE_FLAG_PRESS) != 0;
    bool release = (event->flags & USER_ATK_MOUSE_FLAG_RELEASE) != 0;
    atk_mouse_event_result_t res = atk_handle_mouse_event(event->x, event->y, press, release, left);
    if (res.exit_video)
    {
        atk_main_request_exit();
    }
    return res.redraw;
}

static bool atk_main_handle_default_key(const user_atk_event_t *event)
{
    if (!event)
    {
        return false;
    }
    atk_key_event_result_t res = atk_handle_key_char((char)event->data0);
    if (res.exit_video)
    {
        atk_main_request_exit();
    }
    return res.redraw;
}

static void atk_main_handle_default_close(void)
{
    if (g_atk_main.depth > 1)
    {
        atk_user_window_t *active = atk_main_top_window();
        if (active)
        {
            atk_user_close(active);
        }
        atk_main_pop_window();
        atk_state_t *state = atk_state_get();
        if (state)
        {
            atk_dirty_mark_all();
        }
        return;
    }
    atk_main_request_exit();
}

static bool atk_main_dispatch_event(const user_atk_event_t *event)
{
    if (!event)
    {
        return false;
    }

    const atk_app_event_handlers_t *handlers = g_atk_main.handlers;
    void *ctx = g_atk_main.handler_ctx;

    switch (event->type)
    {
        case USER_ATK_EVENT_MOUSE:
            if (g_atk_main.legacy_input && handlers && handlers->on_mouse)
            {
                return handlers->on_mouse(event, ctx);
            }
            return atk_main_handle_default_mouse(event) | atk_main_fire_mouse_handlers(event);
        case USER_ATK_EVENT_KEY:
            if (g_atk_main.legacy_input && handlers && handlers->on_key)
            {
                return handlers->on_key(event, ctx);
            }
            return atk_main_handle_default_key(event) | atk_main_fire_key_handlers(event);
        case USER_ATK_EVENT_RESIZE:
        {
            bool handled = false;
            bool redraw = false;
            bool registered = false;
            if (g_atk_main.legacy_input && handlers && handlers->on_resize)
            {
                handled = true;
                redraw |= handlers->on_resize((uint32_t)event->data0, (uint32_t)event->data1, ctx);
            }
            for (int i = 0; i < ATK_MAIN_MAX_RESIZE_HANDLERS; ++i)
            {
                if (g_atk_main.resize_handlers[i].used)
                {
                    registered = true;
                    break;
                }
            }
            redraw |= atk_main_fire_resize_handlers((uint32_t)event->data0, (uint32_t)event->data1);
            if (!handled && !registered)
            {
                return true;
            }
            return redraw;
        }
        case USER_ATK_EVENT_CLOSE:
            if (g_atk_main.legacy_input && handlers && handlers->on_close)
            {
                handlers->on_close(ctx);
            }
            else
            {
                bool registered = false;
                for (int i = 0; i < ATK_MAIN_MAX_CLOSE_HANDLERS; ++i)
                {
                    if (g_atk_main.close_handlers[i].used)
                    {
                        registered = true;
                        break;
                    }
                }
                if (registered)
                {
                    atk_main_fire_close_handlers();
                }
                else
                {
                    atk_main_handle_default_close();
                }
            }
            return false;
        default:
            break;
    }
    return false;
}

int atk_main(const atk_main_config_t *config)
{
    if (!config || !config->window)
    {
        return -1;
    }

    atk_main_mouse_slot_t saved_mouse[ATK_MAIN_MAX_MOUSE_HANDLERS];
    atk_main_key_slot_t saved_key[ATK_MAIN_MAX_KEY_HANDLERS];
    atk_main_resize_slot_t saved_resize[ATK_MAIN_MAX_RESIZE_HANDLERS];
    atk_main_close_slot_t saved_close[ATK_MAIN_MAX_CLOSE_HANDLERS];
    memcpy(saved_mouse, g_atk_main.mouse_handlers, sizeof(saved_mouse));
    memcpy(saved_key, g_atk_main.key_handlers, sizeof(saved_key));
    memcpy(saved_resize, g_atk_main.resize_handlers, sizeof(saved_resize));
    memcpy(saved_close, g_atk_main.close_handlers, sizeof(saved_close));

    memset(&g_atk_main, 0, sizeof(g_atk_main));

    memcpy(g_atk_main.mouse_handlers, saved_mouse, sizeof(saved_mouse));
    memcpy(g_atk_main.key_handlers, saved_key, sizeof(saved_key));
    memcpy(g_atk_main.resize_handlers, saved_resize, sizeof(saved_resize));
    memcpy(g_atk_main.close_handlers, saved_close, sizeof(saved_close));

    atk_main_set_tick_handler(config->tick, config->tick_context);
    g_atk_main.legacy_input = config->legacy_input;
    g_atk_main.exit_requested = false;
    g_atk_main.stack_changed = false;

    if (!atk_main_push_window(config->window))
    {
        return -1;
    }

    while (!g_atk_main.exit_requested)
    {
        atk_user_window_t *active = atk_main_top_window();
        if (!active)
        {
            break;
        }

        bool redraw = false;
        bool had_event = false;
        g_atk_main.stack_changed = false;

        user_atk_event_t ev;
        while (!g_atk_main.exit_requested && atk_user_poll_event(active, &ev))
        {
            had_event = true;
            redraw |= atk_main_dispatch_event(&ev);
            if (g_atk_main.stack_changed)
            {
                break;
            }
        }

        if (g_atk_main.exit_requested)
        {
            break;
        }

        if (g_atk_main.stack_changed)
        {
            atk_user_window_t *cur = atk_main_top_window();
            if (cur)
            {
                atk_dirty_mark_all();
                atk_render();
                atk_user_present_force(cur);
            }
            continue;
        }

        if (g_atk_main.tick)
        {
            redraw |= g_atk_main.tick(g_atk_main.tick_ctx);
        }

        if (redraw || atk_main_state_dirty())
        {
            atk_render();
            if (config->present_on_idle)
            {
                atk_user_present_force(active);
            }
            else
            {
                atk_user_present(active);
            }
        }
        else if (!had_event)
        {
            sys_yield();
        }
    }

    return 0;
}

bool atk_modal_begin(atk_modal_session_t *session,
                     const char *title,
                     uint32_t width,
                     uint32_t height,
                     uint32_t flags,
                     atk_widget_t *suspend_window)
{
    if (!session || width == 0 || height == 0)
    {
        return false;
    }

    memset(session, 0, sizeof(*session));
    session->suspended_window = suspend_window;
    if (session->suspended_window)
    {
        session->suspended_used = session->suspended_window->used;
        session->suspended_window->used = false;
    }

    if (!atk_user_window_open_with_flags(&session->remote, title, width, height, flags))
    {
        if (session->suspended_window)
        {
            session->suspended_window->used = session->suspended_used;
        }
        return false;
    }

    atk_user_enable_dirty_tracking(&session->remote, true);
    if (!atk_main_push_window(&session->remote))
    {
        atk_user_close(&session->remote);
        if (session->suspended_window)
        {
            session->suspended_window->used = session->suspended_used;
        }
        return false;
    }

    session->active = true;
    return true;
}

void atk_modal_end(atk_modal_session_t *session)
{
    if (!session || !session->active)
    {
        return;
    }

    session->active = false;
    atk_user_close(&session->remote);
    atk_main_pop_window();

    if (session->suspended_window)
    {
        session->suspended_window->used = session->suspended_used;
        if (session->suspended_window->used)
        {
            atk_window_mark_dirty(session->suspended_window);
        }
    }

    atk_dirty_mark_all();
    atk_render();
    atk_user_window_t *active = atk_main_active_window();
    if (active)
    {
        atk_user_present_force(active);
    }
}

atk_widget_t *atk_app_open_file_dialog_modal(atk_modal_session_t *session,
                                             atk_widget_t *requester,
                                             const char *title,
                                             const char *initial_path,
                                             atk_file_dialog_result_t on_result,
                                             void *context,
                                             uint32_t width,
                                             uint32_t height,
                                             uint32_t flags)
{
    if (!session)
    {
        return NULL;
    }

    if (!atk_modal_begin(session, title, width, height, flags, requester))
    {
        return NULL;
    }

    atk_widget_t *dlg = atk_file_dialog_open(requester, title, initial_path, on_result, context);
    if (!dlg)
    {
        atk_modal_end(session);
        return NULL;
    }

    atk_window_mark_dirty(dlg);
    atk_render();
    atk_user_window_t *active = atk_main_active_window();
    if (active)
    {
        atk_user_present_force(active);
    }
    return dlg;
}

atk_widget_t *atk_app_save_file_dialog_modal(atk_modal_session_t *session,
                                             atk_widget_t *requester,
                                             const char *title,
                                             const char *initial_path,
                                             atk_file_dialog_result_t on_result,
                                             void *context,
                                             uint32_t width,
                                             uint32_t height,
                                             uint32_t flags)
{
    if (!session)
    {
        return NULL;
    }

    if (!atk_modal_begin(session, title, width, height, flags, requester))
    {
        return NULL;
    }

    atk_widget_t *dlg = atk_file_dialog_save(requester, title, initial_path, on_result, context);
    if (!dlg)
    {
        atk_modal_end(session);
        return NULL;
    }

    atk_window_mark_dirty(dlg);
    atk_render();
    atk_user_window_t *active = atk_main_active_window();
    if (active)
    {
        atk_user_present_force(active);
    }
    return dlg;
}
