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
    app->debug_open_requested = false;
    app->debug_clear_requested = false;

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

    alix_thread_t join_threads[BROWSER_MAX_LOAD_THREADS];
    size_t join_count = 0;
    browser_lock_enter(app, &app->lock, "app_lock");
    join_count = app->load_thread_count;
    if (join_count > BROWSER_MAX_LOAD_THREADS)
    {
        join_count = BROWSER_MAX_LOAD_THREADS;
    }
    for (size_t i = 0; i < join_count; ++i)
    {
        join_threads[i] = app->load_threads[i];
    }
    app->load_thread_count = 0;
    browser_lock_exit(app, &app->lock, "app_lock");

    for (size_t i = 0; i < join_count; ++i)
    {
        if (join_threads[i] != 0)
        {
            (void)alix_thread_join(join_threads[i], NULL);
        }
    }

    browser_ui_event_t ev = {0};
    while (browser_ui_event_dequeue(app, &ev))
    {
        browser_ui_event_free_payload(&ev);
        memset(&ev, 0, sizeof(ev));
    }
    browser_app_css_reset(app);

    if (app->debug_remote.handle != 0 || app->debug_window)
    {
        browser_debug_close_window(app);
    }
    atk_user_close(&app->remote);
    free(app->debug_log);
    free(app->cache_dir);
    free(app->pending_fragment);
    free(app);
    return 0;
}
