#include "browser_internal.h"

#include "atk_menu_bar.h"
#include "ctype.h"
#include "stdio.h"
#include "string.h"
#include "usyscall.h"

#define BROWSER_TICK_SLOW_MS 16u
#define BROWSER_TICK_LOG_RATE_MS 250u

static void browser_menus_close(browser_app_t *app);
static void browser_menu_toggle(browser_app_t *app, atk_widget_t *menu, atk_widget_t *button);
static void browser_open_url(browser_app_t *app, const char *url);
static void on_url_submit(atk_widget_t *input, void *context);
static void browser_html_link_clicked(atk_widget_t *view, const char *href, void *context);
static bool browser_requeue_event(browser_app_t *app, browser_ui_event_t *ev);
static void browser_cancel_active_load(browser_app_t *app);
static void browser_clear_pending_fragment(browser_app_t *app);
static void browser_set_pending_fragment(browser_app_t *app, const char *fragment);
static void browser_try_apply_pending_fragment(browser_app_t *app);
static bool browser_button_hit_test(const atk_widget_t *button, int px, int py);
static void browser_history_init(browser_app_t *app);
static void browser_history_push(browser_app_t *app, const char *url);
static void browser_history_update_current(browser_app_t *app, const char *url);
static bool browser_history_can_go_back(const browser_app_t *app);
static void browser_history_jump_to(browser_app_t *app, size_t index);
static void browser_back_menu_show(browser_app_t *app);
static void browser_menu_back_item(void *context);
static void browser_back_button_action(atk_widget_t *button, void *context);

static bool browser_button_hit_test(const atk_widget_t *button, int px, int py)
{
    if (!button || !button->used)
    {
        return false;
    }

    int origin_x = 0;
    int origin_y = 0;
    if (button->parent)
    {
        atk_widget_absolute_position(button->parent, &origin_x, &origin_y);
    }
    return atk_button_hit_test(button, origin_x, origin_y, px, py);
}

static void browser_history_init(browser_app_t *app)
{
    if (!app)
    {
        return;
    }

    for (size_t i = 0; i < BROWSER_HISTORY_MAX; ++i)
    {
        app->history_urls[i] = NULL;
        app->history_menu_ctx[i].app = app;
        app->history_menu_ctx[i].index = i;
    }
    app->history_count = 0;
    app->history_index = 0;
    app->history_inhibit_push = false;
    app->back_press_start_ms = 0;
    app->back_press_active = false;
}

static void browser_history_clear_forward(browser_app_t *app)
{
    if (!app || app->history_count == 0 || app->history_index + 1 >= app->history_count)
    {
        return;
    }

    for (size_t i = app->history_index + 1; i < app->history_count; ++i)
    {
        free(app->history_urls[i]);
        app->history_urls[i] = NULL;
    }
    app->history_count = app->history_index + 1;
}

static void browser_history_push(browser_app_t *app, const char *url)
{
    if (!app || !url || url[0] == '\0')
    {
        return;
    }

    browser_history_clear_forward(app);

    if (app->history_count >= BROWSER_HISTORY_MAX)
    {
        free(app->history_urls[0]);
        for (size_t i = 1; i < app->history_count; ++i)
        {
            app->history_urls[i - 1] = app->history_urls[i];
        }
        app->history_urls[app->history_count - 1] = NULL;
        if (app->history_index > 0)
        {
            app->history_index--;
        }
        app->history_count--;
    }

    char *copy = browser_strdup(url);
    if (!copy)
    {
        return;
    }
    app->history_urls[app->history_count++] = copy;
    app->history_index = app->history_count - 1;
}

static void browser_history_update_current(browser_app_t *app, const char *url)
{
    if (!app || !url || url[0] == '\0' || app->history_count == 0 || app->history_index >= app->history_count)
    {
        return;
    }

    char *copy = browser_strdup(url);
    if (!copy)
    {
        return;
    }
    free(app->history_urls[app->history_index]);
    app->history_urls[app->history_index] = copy;
}

static bool browser_history_can_go_back(const browser_app_t *app)
{
    return app && app->history_count > 0 && app->history_index > 0;
}

static void browser_history_jump_to(browser_app_t *app, size_t index)
{
    if (!app || !app->url_input || index >= app->history_count)
    {
        return;
    }

    const char *url = app->history_urls[index];
    if (!url || url[0] == '\0')
    {
        return;
    }

    browser_menus_close(app);
    app->history_index = index;
    app->history_inhibit_push = true;
    browser_open_url(app, url);
}

static bool browser_back_menu_build(browser_app_t *app)
{
    if (!app || !app->menu_back)
    {
        return false;
    }

    atk_menu_clear(app->menu_back);
    if (!browser_history_can_go_back(app))
    {
        return false;
    }

    size_t idx = app->history_index;
    size_t added = 0;
    while (idx > 0 && added < BROWSER_BACK_MENU_MAX_ITEMS)
    {
        idx--;
        const char *url = app->history_urls[idx];
        if (!url || url[0] == '\0')
        {
            continue;
        }
        browser_history_menu_ctx_t *ctx = &app->history_menu_ctx[idx];
        ctx->app = app;
        ctx->index = idx;
        if (!atk_menu_add_item(app->menu_back, url, browser_menu_back_item, ctx))
        {
            return false;
        }
        added++;
    }

    return added > 0;
}

static void browser_back_menu_show(browser_app_t *app)
{
    if (!app || !app->menu_back || !app->menu_back_button)
    {
        return;
    }
    if (!browser_back_menu_build(app))
    {
        return;
    }
    browser_menu_toggle(app, app->menu_back, app->menu_back_button);
}

static void browser_menu_back_item(void *context)
{
    browser_history_menu_ctx_t *ctx = (browser_history_menu_ctx_t *)context;
    if (!ctx || !ctx->app)
    {
        return;
    }
    browser_history_jump_to(ctx->app, ctx->index);
}

static void browser_back_button_action(atk_widget_t *button, void *context)
{
    (void)button;
    browser_app_t *app = (browser_app_t *)context;
    if (!app)
    {
        return;
    }

    bool long_press = false;
    if (app->back_press_active && app->back_press_start_ms > 0)
    {
        uint64_t now_ms = sys_time_millis();
        long_press = (now_ms - app->back_press_start_ms) >= BROWSER_BACK_LONG_PRESS_MS;
    }
    app->back_press_active = false;
    app->back_press_start_ms = 0;

    if (long_press)
    {
        browser_back_menu_show(app);
        return;
    }

    if (browser_history_can_go_back(app))
    {
        browser_history_jump_to(app, app->history_index - 1);
    }
}

static void apply_theme(atk_state_t *state)
{
    if (!state)
    {
        return;
    }
    state->theme.background = video_make_color(0x12, 0x16, 0x1F);
    state->theme.window_border = video_make_color(0x2F, 0x38, 0x46);
    state->theme.window_title = video_make_color(0x28, 0x6A, 0xA8);
    state->theme.window_title_text = video_make_color(0xF3, 0xF5, 0xF7);
    state->theme.window_body = video_make_color(0x1B, 0x22, 0x2F);
    state->theme.button_face = video_make_color(0x28, 0x36, 0x48);
    state->theme.button_border = video_make_color(0x14, 0x1B, 0x26);
    state->theme.button_text = video_make_color(0xE4, 0xE9, 0xEF);
    state->theme.desktop_icon_face = video_make_color(0x3A, 0x78, 0xB0);
    state->theme.desktop_icon_text = state->theme.window_title_text;
    atk_state_theme_commit(state);
}

static void browser_menu_open_debug(void *context)
{
    browser_app_t *app = (browser_app_t *)context;
    if (!app)
    {
        return;
    }
    browser_menus_close(app);
    app->debug_open_requested = true;
}

static void browser_menu_clear_debug(void *context)
{
    browser_app_t *app = (browser_app_t *)context;
    if (!app)
    {
        return;
    }
    browser_menus_close(app);
    app->debug_clear_requested = true;
}

static void browser_menu_dump_dom(void *context)
{
    browser_app_t *app = (browser_app_t *)context;
    if (!app)
    {
        return;
    }
    browser_menus_close(app);
    if (app->viewer)
    {
        atk_html_view_dump_dom(app->viewer);
    }
}

static void browser_menu_bookmark_example(void *context)
{
    browser_app_t *app = (browser_app_t *)context;
    if (!app)
    {
        return;
    }
    browser_menus_close(app);
    browser_open_url(app, "https://www.example.com");
}

static void browser_menu_bookmark_acid2(void *context)
{
    browser_app_t *app = (browser_app_t *)context;
    if (!app)
    {
        return;
    }
    browser_menus_close(app);
    browser_open_url(app, "http://acid2.acidtests.org/");
}

static void browser_menu_bookmark_httpbin_form(void *context)
{
    browser_app_t *app = (browser_app_t *)context;
    if (!app)
    {
        return;
    }
    browser_menus_close(app);
    browser_open_url(app, "https://httpbin.org/forms/post");
}

static void browser_menu_bookmark_mdn_beginner(void *context)
{
    browser_app_t *app = (browser_app_t *)context;
    if (!app)
    {
        return;
    }
    browser_menus_close(app);
    browser_open_url(app, "https://mdn.github.io/beginner-html-site-styled/");
}

static void browser_menu_bookmark_css1_acid1(void *context)
{
    browser_app_t *app = (browser_app_t *)context;
    if (!app)
    {
        return;
    }
    browser_menus_close(app);
    browser_open_url(app, "https://www.w3.org/Style/CSS/Test/CSS1/current/test5526c.htm");
}

void browser_on_close_event(void *context)
{
    browser_app_t *app = (browser_app_t *)context;
    if (!app)
    {
        atk_main_request_exit();
        return;
    }

    browser_lock_enter(app, &app->lock, "app_lock");
    app->active_load_id = 0;
    browser_lock_exit(app, &app->lock, "app_lock");

    if (app->debug_remote.handle != 0)
    {
        browser_debug_close_window(app);
    }
    atk_main_request_exit();
}

static void browser_menus_close(browser_app_t *app)
{
    if (!app)
    {
        return;
    }

    if (app->menu_bookmarks)
    {
        atk_menu_hide(app->menu_bookmarks);
    }
    if (app->menu_debug)
    {
        atk_menu_hide(app->menu_debug);
    }
    if (app->menu_back)
    {
        atk_menu_hide(app->menu_back);
    }
    app->menu_open = NULL;
    if (app->window)
    {
        atk_window_mark_dirty(app->window);
    }
}

static void browser_menu_toggle(browser_app_t *app, atk_widget_t *menu, atk_widget_t *button)
{
    if (!app || !app->window || !menu || !button)
    {
        return;
    }

    bool already_open = (app->menu_open == menu) && atk_menu_is_visible(menu);
    browser_menus_close(app);
    if (already_open)
    {
        return;
    }

    atk_window_priv_t *wpriv = (atk_window_priv_t *)atk_widget_priv(app->window, &ATK_WINDOW_CLASS);
    if (wpriv)
    {
        atk_list_node_t *node = atk_list_find(&wpriv->children, menu);
        if (node)
        {
            atk_list_move_to_back(&wpriv->children, node);
        }
    }

    int menu_x = button->x;
    int menu_y = button->y + button->height;
    atk_menu_show(menu, menu_x, menu_y);
    if (menu->width < button->width)
    {
        menu->width = button->width;
    }
    if (menu->width > app->window->width)
    {
        menu->width = app->window->width;
    }
    if (menu->x + menu->width > app->window->width - 2)
    {
        menu->x = app->window->width - menu->width - 2;
    }
    if (menu->x < 0)
    {
        menu->x = 0;
    }

    app->menu_open = menu;
    atk_window_mark_dirty(app->window);
}

static void on_menu_button(atk_widget_t *button, void *context)
{
    browser_app_t *app = (browser_app_t *)context;
    if (!app || !button)
    {
        return;
    }

    if (button == app->menu_bookmarks_button)
    {
        browser_menu_toggle(app, app->menu_bookmarks, app->menu_bookmarks_button);
        return;
    }

    if (button == app->menu_debug_button)
    {
        browser_menu_toggle(app, app->menu_debug, app->menu_debug_button);
    }
}

bool browser_on_mouse_event(const user_atk_event_t *event, void *context)
{
    browser_app_t *app = (browser_app_t *)context;
    if (!app || !event)
    {
        return false;
    }

    bool left = (event->flags & USER_ATK_MOUSE_FLAG_LEFT) != 0;
    bool press = (event->flags & USER_ATK_MOUSE_FLAG_PRESS) != 0;
    bool release = (event->flags & USER_ATK_MOUSE_FLAG_RELEASE) != 0;
    int px = event->x;
    int py = event->y;
    if (left && press && browser_button_hit_test(app->menu_back_button, px, py))
    {
        app->back_press_active = true;
        app->back_press_start_ms = sys_time_millis();
    }
    if (release && app->back_press_active)
    {
        app->back_press_active = false;
        app->back_press_start_ms = 0;
    }

    if (left && press && app->menu_open && atk_menu_is_visible(app->menu_open))
    {
        bool inside_menu = atk_menu_contains(app->menu_open, px, py);
        bool inside_menu_button = browser_button_hit_test(app->menu_back_button, px, py) ||
                                  browser_button_hit_test(app->menu_bookmarks_button, px, py) ||
                                  browser_button_hit_test(app->menu_debug_button, px, py);
        if (!inside_menu && !inside_menu_button)
        {
            browser_menus_close(app);
        }
    }

    return false;
}

static void browser_open_url(browser_app_t *app, const char *url)
{
    if (!app || !url || url[0] == '\0' || !app->url_input)
    {
        return;
    }
    atk_text_input_set_text(app->url_input, url);
    on_url_submit(app->url_input, app);
}

static int browser_hex_value(int ch)
{
    if (ch >= '0' && ch <= '9')
    {
        return ch - '0';
    }
    ch = tolower((unsigned char)ch);
    if (ch >= 'a' && ch <= 'f')
    {
        return ch - 'a' + 10;
    }
    return -1;
}

static void browser_decode_fragment(char *fragment)
{
    if (!fragment)
    {
        return;
    }

    char *dst = fragment;
    const char *src = fragment;
    while (*src)
    {
        if (src[0] == '%' && src[1] && src[2])
        {
            int hi = browser_hex_value(src[1]);
            int lo = browser_hex_value(src[2]);
            if (hi >= 0 && lo >= 0)
            {
                *dst++ = (char)((hi << 4) | lo);
                src += 3;
                continue;
            }
        }
        *dst++ = *src++;
    }
    *dst = '\0';
}

static void browser_clear_pending_fragment(browser_app_t *app)
{
    if (!app)
    {
        return;
    }
    free(app->pending_fragment);
    app->pending_fragment = NULL;
}

static void browser_set_pending_fragment(browser_app_t *app, const char *fragment)
{
    if (!app)
    {
        return;
    }
    browser_clear_pending_fragment(app);
    if (!fragment)
    {
        return;
    }
    app->pending_fragment = browser_strdup(fragment);
    if (app->pending_fragment)
    {
        browser_decode_fragment(app->pending_fragment);
    }
}

static void browser_try_apply_pending_fragment(browser_app_t *app)
{
    if (!app || !app->pending_fragment || !app->viewer)
    {
        return;
    }
    if (atk_html_view_scroll_to_id(app->viewer, app->pending_fragment))
    {
        browser_clear_pending_fragment(app);
        if (app->window)
        {
            atk_window_mark_dirty(app->window);
        }
    }
}

static char *browser_split_fragment(const char *url, char **fragment_out)
{
    if (fragment_out)
    {
        *fragment_out = NULL;
    }
    if (!url)
    {
        return NULL;
    }

    const char *hash = strchr(url, '#');
    if (!hash)
    {
        return browser_strdup(url);
    }

    size_t base_len = (size_t)(hash - url);
    char *base = browser_strdup_len(url, base_len);
    if (fragment_out)
    {
        *fragment_out = browser_strdup(hash + 1);
    }
    return base;
}

static bool browser_href_supported(const char *href)
{
    if (!href || href[0] == '\0')
    {
        return false;
    }

    if (strncasecmp(href, "http://", 7) == 0 || strncasecmp(href, "https://", 8) == 0)
    {
        return true;
    }

    if (href[0] == '#' || href[0] == '/' || href[0] == '?' || href[0] == '.')
    {
        return true;
    }

    for (const char *p = href; *p; ++p)
    {
        if (*p == ':')
        {
            return false;
        }
        if (*p == '/' || *p == '?' || *p == '#')
        {
            break;
        }
    }
    return true;
}

static void browser_html_link_clicked(atk_widget_t *view, const char *href, void *context)
{
    (void)view;
    browser_app_t *app = (browser_app_t *)context;
    if (!app || !href || href[0] == '\0')
    {
        return;
    }

    if (!browser_href_supported(href))
    {
        browser_debug_logf(app, "[ui] link unsupported href=%s", href);
        return;
    }

    if (href[0] == '#')
    {
        browser_set_pending_fragment(app, href + 1);
        browser_try_apply_pending_fragment(app);
        return;
    }

    const char *base_text = app->url_input ? atk_text_input_text(app->url_input) : NULL;
    if (!base_text || base_text[0] == '\0')
    {
        return;
    }

    browser_url_t base_url = {0};
    if (!browser_parse_url(base_text, &base_url))
    {
        browser_debug_logf(app, "[ui] link base parse failed base=%s", base_text);
        return;
    }

    char *abs = browser_build_absolute_url(&base_url, href, strlen(href));
    browser_url_destroy(&base_url);
    if (!abs)
    {
        return;
    }

    char *fragment = NULL;
    char *base = browser_split_fragment(abs, &fragment);
    if (!base)
    {
        free(fragment);
        free(abs);
        return;
    }

    char *current_base = browser_split_fragment(base_text, NULL);
    if (fragment && current_base && strcmp(current_base, base) == 0)
    {
        browser_set_pending_fragment(app, fragment);
        browser_try_apply_pending_fragment(app);
        free(current_base);
        free(fragment);
        free(base);
        free(abs);
        return;
    }

    browser_set_pending_fragment(app, fragment);
    browser_debug_logf(app, "[ui] link click url=%s", base);
    browser_open_url(app, base);
    free(current_base);
    free(fragment);
    free(base);
    free(abs);
}

static void browser_cancel_active_load(browser_app_t *app)
{
    if (!app)
    {
        return;
    }

    browser_lock_enter(app, &app->lock, "app_lock");
    app->active_load_id = 0;
    browser_lock_exit(app, &app->lock, "app_lock");

    if (app->viewer)
    {
        atk_html_view_stop_js(app->viewer);
    }

    browser_ui_event_t ev = {0};
    while (browser_ui_event_dequeue(app, &ev))
    {
        browser_ui_event_free_payload(&ev);
        memset(&ev, 0, sizeof(ev));
    }
    browser_app_css_reset(app);
    browser_clear_pending_fragment(app);
}

static bool browser_requeue_event(browser_app_t *app, browser_ui_event_t *ev)
{
    if (!app || !ev)
    {
        return false;
    }
    if (browser_ui_event_enqueue(app, ev))
    {
        return true;
    }
    browser_debug_logf(app, "[ui] drop deferred event type=%u", (unsigned)ev->type);
    browser_ui_event_free_payload(ev);
    return false;
}

static void on_url_submit(atk_widget_t *input, void *context)
{
    browser_app_t *app = (browser_app_t *)context;
    if (!app || !input)
    {
        return;
    }
    const char *text = atk_text_input_text(input);
    if (!text || text[0] == '\0')
    {
        return;
    }
    browser_cancel_active_load(app);
    browser_debug_log_reset_file(app);
    browser_debug_logf(app, "[ui] submit url=%s", text);

    browser_menus_close(app);
    browser_clear_pending_fragment(app);
    bool suppress_history = app->history_inhibit_push;
    app->history_inhibit_push = false;
    if (!suppress_history)
    {
        browser_history_push(app, text);
    }

    char *fragment = NULL;
    char *base = browser_split_fragment(text, &fragment);
    if (!base)
    {
        free(fragment);
        return;
    }
    if (fragment)
    {
        browser_set_pending_fragment(app, fragment);
    }
    (void)browser_loader_start(app, base);
    free(fragment);
    free(base);
}

bool browser_tick(void *context)
{
    browser_app_t *app = (browser_app_t *)context;
    if (!app)
    {
        return false;
    }

    uint64_t tick_start_ms = sys_time_millis();
    size_t event_counts[BROWSER_UI_EVENT_THREAD_DONE + 1] = {0};
    bool redraw = false;
    if (app->debug_open_requested)
    {
        app->debug_open_requested = false;
        browser_debug_open_window(app);
    }
    if (app->debug_clear_requested)
    {
        app->debug_clear_requested = false;
        browser_debug_clear(app);
    }
    browser_debug_service(app);

    uint64_t start_ms = sys_time_millis();
    size_t events_processed = 0;
    browser_ui_event_t ev = {0};
    while (events_processed < BROWSER_UI_EVENTS_PER_TICK)
    {
        if (BROWSER_UI_EVENT_BUDGET_MS > 0 &&
            (sys_time_millis() - start_ms) >= BROWSER_UI_EVENT_BUDGET_MS)
        {
            break;
        }
        if (!browser_ui_event_dequeue(app, &ev))
        {
            break;
        }

        events_processed++;
        if ((unsigned)ev.type <= (unsigned)BROWSER_UI_EVENT_THREAD_DONE)
        {
            event_counts[ev.type]++;
        }
        bool skip_free = false;
        bool defer_event = false;
        switch (ev.type)
        {
            case BROWSER_UI_EVENT_DOC_READY:
            {
                if (browser_load_is_active(app, ev.load_id))
                {
                    if (ev.u.doc_ready.final_url && ev.u.doc_ready.final_url[0] != '\0' && app->url_input)
                    {
                        atk_text_input_set_text(app->url_input, ev.u.doc_ready.final_url);
                        browser_history_update_current(app, ev.u.doc_ready.final_url);
                    }

                    html_document_t *doc = ev.u.doc_ready.doc;
                    if (doc && doc->root)
                    {
                        size_t node_count = browser_dom_count_nodes(doc->root, 50000);
                        const html_node_t *body = browser_dom_find_first_element(doc->root, "body");
                        const html_node_t *title = browser_dom_find_first_element(doc->root, "title");
                        const char *title_text = browser_dom_first_text_child(title);
                        if (title_text && title_text[0] != '\0')
                        {
                            char title_preview[96];
                            size_t tlen = strlen(title_text);
                            size_t copy = tlen;
                            if (copy >= sizeof(title_preview))
                            {
                                copy = sizeof(title_preview) - 1;
                            }
                            memcpy(title_preview, title_text, copy);
                            title_preview[copy] = '\0';
                            browser_debug_logf(app, "[parse] title %s", title_preview);
                        }
                        browser_debug_logf(app, "[parse] nodes=%u body=%s",
                                           (unsigned)node_count,
                                           body ? "yes" : "no");
                    }
                    browser_app_css_reset(app);
                    ev.u.doc_ready.doc = NULL;
                    atk_html_view_set_document(app->viewer, doc);
                    browser_debug_logf(app, "[render] set document ok");
                    browser_try_apply_pending_fragment(app);
                    atk_window_mark_dirty(app->window);
                    redraw = true;
                }
                break;
            }
            case BROWSER_UI_EVENT_ERROR:
            {
                if (browser_load_is_active(app, ev.load_id))
                {
                    const char *msg = ev.u.error.message ? ev.u.error.message : "unknown error";
                    browser_debug_logf(app, "[render] showing fetch error page");

                    char page_buf[512];
                    snprintf(page_buf,
                             sizeof(page_buf),
                             "<!doctype html><html><body><p>Fetch error:</p><p>%s</p></body></html>",
                             msg);
                    (void)atk_html_view_set_html(app->viewer, page_buf, NULL);
                    atk_window_mark_dirty(app->window);
                    redraw = true;
                }
                break;
            }
            case BROWSER_UI_EVENT_CSS_APPEND:
            {
                if (browser_load_is_active(app, ev.load_id))
                {
                    if (browser_app_css_append(app, ev.u.css_append.css, ev.u.css_append.len))
                    {
                        (void)browser_app_css_append(app, "\n", 1);
                        if (!app->css_dirty)
                        {
                            app->css_dirty = true;
                            app->css_dirty_since_ms = sys_time_millis();
                        }
                    }
                    else
                    {
                        browser_debug_logf(app, "[css] stylesheet too large");
                    }
                }
                break;
            }
            case BROWSER_UI_EVENT_SCRIPT_APPEND:
            {
                if (browser_load_is_active(app, ev.load_id))
                {
                    bool ok = atk_html_view_try_add_script(app->viewer,
                                                           ev.u.script_append.script,
                                                           ev.u.script_append.len);
                    if (!ok)
                    {
                        browser_debug_logf(app,
                                           "[js] defer src=%s bytes=%u",
                                           ev.u.script_append.src ? ev.u.script_append.src : "(null)",
                                           (unsigned)ev.u.script_append.len);
                        if (browser_requeue_event(app, &ev))
                        {
                            skip_free = true;
                            defer_event = true;
                        }
                        else
                        {
                            skip_free = true;
                        }
                        break;
                    }
                    browser_debug_logf(app,
                                       "[js] queued src=%s bytes=%u",
                                       ev.u.script_append.src ? ev.u.script_append.src : "(null)",
                                       (unsigned)ev.u.script_append.len);
                    atk_window_mark_dirty(app->window);
                    redraw = true;
                }
                break;
            }
            case BROWSER_UI_EVENT_IMAGE_PNG:
            {
                if (browser_load_is_active(app, ev.load_id))
                {
                    bool ok = atk_html_view_add_image_png(app->viewer,
                                                         ev.u.image_png.src ? ev.u.image_png.src : "",
                                                         ev.u.image_png.data,
                                                         ev.u.image_png.len);
                    browser_debug_logf(app,
                                       "[img] %s src=%s bytes=%u",
                                       ok ? "loaded" : "failed",
                                       ev.u.image_png.src ? ev.u.image_png.src : "(null)",
                                       (unsigned)ev.u.image_png.len);
                    atk_window_mark_dirty(app->window);
                    redraw = true;
                }
                break;
            }
            case BROWSER_UI_EVENT_IMAGE_GIF:
            {
                if (browser_load_is_active(app, ev.load_id))
                {
                    bool ok = atk_html_view_add_image_gif(app->viewer,
                                                         ev.u.image_gif.src ? ev.u.image_gif.src : "",
                                                         ev.u.image_gif.data,
                                                         ev.u.image_gif.len);
                    browser_debug_logf(app,
                                       "[img] %s src=%s bytes=%u",
                                       ok ? "loaded" : "failed",
                                       ev.u.image_gif.src ? ev.u.image_gif.src : "(null)",
                                       (unsigned)ev.u.image_gif.len);
                    atk_window_mark_dirty(app->window);
                    redraw = true;
                }
                break;
            }
            case BROWSER_UI_EVENT_IMAGE_RGBA:
            {
                if (browser_load_is_active(app, ev.load_id))
                {
                    bool ok = atk_html_view_try_add_image_rgba(app->viewer,
                                                              ev.u.image_rgba.src ? ev.u.image_rgba.src : "",
                                                              ev.u.image_rgba.pixels,
                                                              ev.u.image_rgba.width,
                                                              ev.u.image_rgba.height,
                                                              ev.u.image_rgba.stride_bytes);
                    if (!ok)
                    {
                        browser_debug_logf(app,
                                           "[img] defer src=%s bytes=%u",
                                           ev.u.image_rgba.src ? ev.u.image_rgba.src : "(null)",
                                           (unsigned)(ev.u.image_rgba.stride_bytes * ev.u.image_rgba.height));
                        if (browser_requeue_event(app, &ev))
                        {
                            skip_free = true;
                            defer_event = true;
                        }
                        else
                        {
                            skip_free = true;
                        }
                        break;
                    }
                    browser_debug_logf(app,
                                       "[img] loaded src=%s bytes=%u",
                                       ev.u.image_rgba.src ? ev.u.image_rgba.src : "(null)",
                                       (unsigned)(ev.u.image_rgba.stride_bytes * ev.u.image_rgba.height));
                    ev.u.image_rgba.pixels = NULL;
                    atk_window_mark_dirty(app->window);
                    redraw = true;
                }
                break;
            }
            case BROWSER_UI_EVENT_THREAD_DONE:
            {
                (void)alix_thread_join(ev.u.thread_done.thread, NULL);
                browser_untrack_load_thread(app, ev.u.thread_done.thread);
                break;
            }
            default:
                break;
        }

        if (!skip_free)
        {
            browser_ui_event_free_payload(&ev);
        }
        memset(&ev, 0, sizeof(ev));
        if (defer_event)
        {
            break;
        }
    }

    if (app->css_dirty && app->viewer && app->window)
    {
        uint64_t now_ms = sys_time_millis();
        bool budget_ok = true;
        if (BROWSER_UI_EVENT_BUDGET_MS > 0 &&
            (now_ms - start_ms) >= BROWSER_UI_EVENT_BUDGET_MS)
        {
            budget_ok = false;
        }
        if (budget_ok && (now_ms - app->css_dirty_since_ms) >= BROWSER_CSS_APPLY_DEBOUNCE_MS)
        {
            if (atk_html_view_try_set_external_stylesheet(app->viewer, app->external_css))
            {
                app->css_dirty = false;
                app->css_dirty_since_ms = 0;
                atk_window_mark_dirty(app->window);
                redraw = true;
            }
            else
            {
                app->css_dirty_since_ms = now_ms;
            }
        }
    }

    browser_debug_service(app);
    if (app->viewer && atk_html_view_poll_js(app->viewer))
    {
        redraw = true;
    }
    browser_try_apply_pending_fragment(app);

    uint64_t tick_elapsed_ms = sys_time_millis() - tick_start_ms;
    if (tick_elapsed_ms >= BROWSER_TICK_SLOW_MS)
    {
        static uint64_t last_log_ms = 0;
        uint64_t now_ms = sys_time_millis();
        if (now_ms - last_log_ms >= BROWSER_TICK_LOG_RATE_MS)
        {
            last_log_ms = now_ms;
            size_t img_events = event_counts[BROWSER_UI_EVENT_IMAGE_PNG] +
                                event_counts[BROWSER_UI_EVENT_IMAGE_GIF] +
                                event_counts[BROWSER_UI_EVENT_IMAGE_RGBA];
            serial_printf("[ui] tick slow ms=%llu tid=%llu events=%u css=%u js=%u img=%u dirty=%u",
                          (unsigned long long)tick_elapsed_ms,
                          (unsigned long long)alix_thread_self(),
                          (unsigned)events_processed,
                          (unsigned)event_counts[BROWSER_UI_EVENT_CSS_APPEND],
                          (unsigned)event_counts[BROWSER_UI_EVENT_SCRIPT_APPEND],
                          (unsigned)img_events,
                          app->css_dirty ? 1u : 0u);
        }
    }
    return redraw;
}

bool browser_build_ui(browser_app_t *app)
{
    if (!app)
    {
        return false;
    }

    atk_init();
    atk_state_t *state = atk_state_get();
    atk_menu_bar_set_enabled(state, false);
    apply_theme(state);

    app->window = atk_window_create_at(state, BROWSER_WIDTH / 2, BROWSER_HEIGHT / 2);
    if (!app->window)
    {
        return false;
    }

    atk_window_set_chrome_visible(app->window, false);
    atk_window_set_title_text(app->window, "atk_browser");
    app->window->x = 0;
    app->window->y = 0;
    app->window->width = BROWSER_WIDTH;
    app->window->height = BROWSER_HEIGHT;
    atk_window_ensure_inside(app->window);

    int chrome_top = atk_window_is_chrome_visible(app->window) ? ATK_WINDOW_TITLE_HEIGHT : 0;
    int content_x = BROWSER_MARGIN;
    int content_y = chrome_top + BROWSER_MARGIN;
    int content_w = app->window->width - BROWSER_MARGIN * 2;
    int content_h = app->window->height - content_y - BROWSER_MARGIN;

    int menu_x = content_x;
    int menu_y = content_y;
    int menu_h = BROWSER_MENU_HEIGHT;

    int menu_w_back = atk_font_text_width("Back") + 32;
    if (menu_w_back < 72)
    {
        menu_w_back = 72;
    }
    app->menu_back_button = atk_window_add_button(app->window,
                                                  "Back",
                                                  menu_x,
                                                  menu_y,
                                                  menu_w_back,
                                                  menu_h,
                                                  ATK_BUTTON_STYLE_TITLE_INSIDE,
                                                  false,
                                                  browser_back_button_action,
                                                  app);
    if (!app->menu_back_button)
    {
        return false;
    }
    atk_widget_set_layout(app->menu_back_button, ATK_WIDGET_ANCHOR_TOP | ATK_WIDGET_ANCHOR_LEFT);

    menu_x += menu_w_back + 8;
    int menu_w_bookmarks = atk_font_text_width("Bookmarks") + 32;
    if (menu_w_bookmarks < 104)
    {
        menu_w_bookmarks = 104;
    }
    app->menu_bookmarks_button = atk_window_add_button(app->window,
                                                       "Bookmarks",
                                                       menu_x,
                                                       menu_y,
                                                       menu_w_bookmarks,
                                                       menu_h,
                                                       ATK_BUTTON_STYLE_TITLE_INSIDE,
                                                       false,
                                                       on_menu_button,
                                                       app);
    if (!app->menu_bookmarks_button)
    {
        return false;
    }
    atk_widget_set_layout(app->menu_bookmarks_button, ATK_WIDGET_ANCHOR_TOP | ATK_WIDGET_ANCHOR_LEFT);

    menu_x += menu_w_bookmarks + 8;
    int menu_w_debug = atk_font_text_width("Debug") + 32;
    if (menu_w_debug < 84)
    {
        menu_w_debug = 84;
    }
    app->menu_debug_button = atk_window_add_button(app->window,
                                                   "Debug",
                                                   menu_x,
                                                   menu_y,
                                                   menu_w_debug,
                                                   menu_h,
                                                   ATK_BUTTON_STYLE_TITLE_INSIDE,
                                                   false,
                                                   on_menu_button,
                                                   app);
    if (!app->menu_debug_button)
    {
        return false;
    }
    atk_widget_set_layout(app->menu_debug_button, ATK_WIDGET_ANCHOR_TOP | ATK_WIDGET_ANCHOR_LEFT);

    int url_y = menu_y + menu_h + BROWSER_GAP;
    app->url_input = atk_window_add_text_input(app->window, content_x, url_y, content_w);
    if (!app->url_input)
    {
        return false;
    }
    atk_text_input_set_text(app->url_input, "https://example.com/");
    atk_text_input_set_submit_handler(app->url_input, on_url_submit, app);
    atk_text_input_focus(state, app->url_input);

    atk_widget_set_layout(app->url_input,
                          ATK_WIDGET_ANCHOR_TOP | ATK_WIDGET_ANCHOR_LEFT | ATK_WIDGET_ANCHOR_RIGHT);

    atk_window_priv_t *wpriv = (atk_window_priv_t *)atk_widget_priv(app->window, &ATK_WINDOW_CLASS);
    if (!wpriv)
    {
        return false;
    }

    app->menu_back = atk_menu_create();
    app->menu_bookmarks = atk_menu_create();
    app->menu_debug = atk_menu_create();
    if (!app->menu_back || !app->menu_bookmarks || !app->menu_debug)
    {
        if (app->menu_back)
        {
            atk_menu_destroy(app->menu_back);
        }
        if (app->menu_bookmarks)
        {
            atk_menu_destroy(app->menu_bookmarks);
        }
        if (app->menu_debug)
        {
            atk_menu_destroy(app->menu_debug);
        }
        app->menu_back = NULL;
        app->menu_bookmarks = NULL;
        app->menu_debug = NULL;
        return false;
    }

    app->menu_back->parent = app->window;
    app->menu_bookmarks->parent = app->window;
    app->menu_debug->parent = app->window;
    if (!atk_list_push_back(&wpriv->children, app->menu_back) ||
        !atk_list_push_back(&wpriv->children, app->menu_bookmarks) ||
        !atk_list_push_back(&wpriv->children, app->menu_debug))
    {
        atk_menu_destroy(app->menu_back);
        atk_menu_destroy(app->menu_bookmarks);
        atk_menu_destroy(app->menu_debug);
        app->menu_back = NULL;
        app->menu_bookmarks = NULL;
        app->menu_debug = NULL;
        return false;
    }

    if (!atk_menu_add_item(app->menu_bookmarks, "https://www.example.com", browser_menu_bookmark_example, app) ||
        !atk_menu_add_item(app->menu_bookmarks, "http://acid2.acidtests.org/", browser_menu_bookmark_acid2, app) ||
        !atk_menu_add_item(app->menu_bookmarks, "https://httpbin.org/forms/post", browser_menu_bookmark_httpbin_form, app) ||
        !atk_menu_add_item(app->menu_bookmarks, "https://mdn.github.io/beginner-html-site-styled/", browser_menu_bookmark_mdn_beginner, app) ||
        !atk_menu_add_item(app->menu_bookmarks, "https://www.w3.org/Style/CSS/Test/CSS1/current/test5526c.htm", browser_menu_bookmark_css1_acid1, app))
    {
        return false;
    }

    if (!atk_menu_add_item(app->menu_debug, "Open Debug Window", browser_menu_open_debug, app) ||
        !atk_menu_add_item(app->menu_debug, "Clear Debug Log", browser_menu_clear_debug, app) ||
        !atk_menu_add_item(app->menu_debug, "Dump DOM + Styles", browser_menu_dump_dom, app))
    {
        return false;
    }
    app->menu_open = NULL;

    int viewer_y = url_y + app->url_input->height + BROWSER_GAP;
    int viewer_h = (content_y + content_h) - viewer_y;
    if (viewer_h < 16)
    {
        viewer_h = 16;
    }

    app->viewer = atk_window_add_html_view(app->window,
                                           content_x,
                                           viewer_y,
                                           content_w,
                                           viewer_h);
    if (!app->viewer)
    {
        return false;
    }
    atk_html_view_enable_async_render(app->viewer, true);
    atk_html_view_set_link_handler(app->viewer, browser_html_link_clicked, app);
    atk_widget_set_layout(app->viewer,
                          ATK_WIDGET_ANCHOR_LEFT | ATK_WIDGET_ANCHOR_RIGHT |
                              ATK_WIDGET_ANCHOR_TOP | ATK_WIDGET_ANCHOR_BOTTOM);
    (void)atk_html_view_set_html(app->viewer,
                                 "<!doctype html><html><body><p>Enter a URL above and press Enter.</p></body></html>",
                                 NULL);
    browser_history_init(app);
    return true;
}
