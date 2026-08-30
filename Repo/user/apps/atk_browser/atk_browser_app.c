#include "browser_internal.h"

#include "stdio.h"
#include "string.h"

static bool browser_on_resize_event(uint32_t width, uint32_t height, void *context)
{
    browser_app_t *app = (browser_app_t *)context;
    if (!app || !app->window)
    {
        return false;
    }
    app->window->width = (int)width;
    app->window->height = (int)height;
    atk_window_request_layout(app->window);
    return true;
}

int main(void)
{
    browser_app_t *app = (browser_app_t *)calloc(1, sizeof(*app));
    if (!app)
    {
        printf("atk_browser: failed to allocate app state\n");
        return 1;
    }
    alix_mutex_init(&app->lock);
    alix_mutex_init(&app->debug_lock);
    alix_mutex_init(&app->decode_lock);
    alix_mutex_init(&app->resource_lock);
    alix_mutex_init(&app->load_lock);

    if (!atk_user_window_open_with_flags(&app->remote,
                                         "atk_browser",
                                         BROWSER_WIDTH,
                                         BROWSER_HEIGHT,
                                         USER_ATK_WINDOW_FLAG_RESIZABLE))
    {
        printf("atk_browser: failed to open window\n");
        free(app);
        return 1;
    }
    atk_user_enable_dirty_tracking(&app->remote, true);

    if (!browser_build_ui(app))
    {
        printf("atk_browser: failed to init UI\n");
        atk_user_close(&app->remote);
        free(app);
        return 1;
    }
    app->ui_event_head = 0;
    app->ui_event_count = 0;
    memset(app->ui_events, 0, sizeof(app->ui_events));
    memset(&app->deferred_ui_event, 0, sizeof(app->deferred_ui_event));
    app->deferred_ui_event_valid = false;
    app->debug_open_requested = false;
    app->debug_clear_requested = false;

    if (!browser_html_worker_start(app))
    {
        printf("atk_browser: failed to start html worker\n");
    }
    if (!browser_resource_worker_start(app))
    {
        printf("atk_browser: failed to start resource worker\n");
    }

    atk_render();
    atk_user_present_force(&app->remote);

    atk_main_config_t main_cfg = {
        .window = &app->remote,
        .tick = browser_tick,
        .tick_context = app,
        .present_on_idle = false,
        .legacy_input = false,
    };
    atk_main_register_mouse_handler(browser_on_mouse_event, app);
    atk_main_register_resize_handler(browser_on_resize_event, app);
    atk_main_register_close_handler(browser_on_close_event, app);
    atk_main(&main_cfg);

    browser_lock_enter(app, &app->lock, "app_lock");
    app->active_load_id = 0;
    browser_lock_exit(app, &app->lock, "app_lock");

    browser_html_worker_stop(app);
    browser_resource_worker_stop(app);

    if (app->deferred_ui_event_valid)
    {
        browser_ui_event_free_payload(&app->deferred_ui_event);
        memset(&app->deferred_ui_event, 0, sizeof(app->deferred_ui_event));
        app->deferred_ui_event_valid = false;
    }
    browser_ui_event_t ev = {0};
    while (browser_ui_event_dequeue(app, &ev))
    {
        browser_ui_event_free_payload(&ev);
        memset(&ev, 0, sizeof(ev));
    }
    browser_first_render_scripts_clear(app);
    browser_app_css_reset(app);

    if (app->debug_remote.handle != 0 || app->debug_window)
    {
        browser_debug_close_window(app);
    }
    atk_user_close(&app->remote);
    for (size_t i = 0; i < BROWSER_HISTORY_MAX; ++i)
    {
        free(app->history_urls[i]);
        app->history_urls[i] = NULL;
    }
    free(app->debug_log);
    free(app->cache_dir);
    free(app->pending_fragment);
    free(app);
    return 0;
}
