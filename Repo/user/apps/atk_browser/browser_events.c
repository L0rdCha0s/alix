#include "browser_internal.h"

#include "string.h"

bool browser_ui_event_move(browser_ui_event_t *dst, browser_ui_event_t *src)
{
    if (!dst || !src || dst == src)
    {
        return false;
    }
    *dst = *src;
    memset(src, 0, sizeof(*src));
    return true;
}

bool browser_ui_event_defer(browser_app_t *app, browser_ui_event_t *ev, uint64_t now_ms)
{
    if (!app || !ev || app->deferred_ui_event_valid)
    {
        return false;
    }

    if (!app->ui_defer_chain_active || app->ui_defer_chain_load_id != ev->load_id)
    {
        app->ui_defer_chain_active = true;
        app->ui_defer_chain_load_id = ev->load_id;
        app->ui_defer_chain_started_ms = now_ms;
        app->ui_defer_chain_attempts = 0u;
        ev->defer_attempts = 0u;
        ev->defer_started_ms = 0u;
        ev->defer_retry_after_ms = 0u;
    }
    if (ev->defer_attempts == 0u)
    {
        ev->defer_started_ms = now_ms;
    }
    if (ev->defer_attempts != UINT32_MAX)
    {
        ev->defer_attempts++;
    }
    if (app->ui_defer_chain_attempts != UINT32_MAX)
    {
        app->ui_defer_chain_attempts++;
    }
    if (now_ms > UINT64_MAX - BROWSER_UI_DEFER_RETRY_MS)
    {
        ev->defer_retry_after_ms = UINT64_MAX;
    }
    else
    {
        ev->defer_retry_after_ms = now_ms + BROWSER_UI_DEFER_RETRY_MS;
    }

    if (!browser_ui_event_move(&app->deferred_ui_event, ev))
    {
        return false;
    }
    app->deferred_ui_event_valid = true;
    return true;
}

bool browser_ui_event_take_deferred(browser_app_t *app, uint64_t now_ms, browser_ui_event_t *out)
{
    if (!app || !out || !app->deferred_ui_event_valid)
    {
        return false;
    }
    if (now_ms < app->deferred_ui_event.defer_retry_after_ms &&
        now_ms >= app->deferred_ui_event.defer_started_ms)
    {
        return false;
    }
    if (!browser_ui_event_move(out, &app->deferred_ui_event))
    {
        return false;
    }
    app->deferred_ui_event_valid = false;
    return true;
}

bool browser_ui_event_defer_expired(const browser_app_t *app,
                                    const browser_ui_event_t *ev,
                                    uint64_t now_ms)
{
    if (!app || !ev || !app->ui_defer_chain_active ||
        app->ui_defer_chain_load_id != ev->load_id)
    {
        return false;
    }
    if (app->ui_defer_chain_attempts >= BROWSER_UI_DEFER_MAX_ATTEMPTS)
    {
        return true;
    }
    return ev->defer_attempts > 0u && now_ms >= ev->defer_started_ms &&
           (now_ms - ev->defer_started_ms) >= BROWSER_UI_DEFER_TIMEOUT_MS;
}

void browser_ui_event_defer_chain_reset(browser_app_t *app)
{
    if (!app)
    {
        return;
    }
    app->ui_defer_chain_active = false;
    app->ui_defer_chain_load_id = 0u;
    app->ui_defer_chain_started_ms = 0u;
    app->ui_defer_chain_attempts = 0u;
}

bool browser_first_render_script_buffer(browser_app_t *app, browser_ui_event_t *ev)
{
    if (!app || !ev || ev->type != BROWSER_UI_EVENT_SCRIPT_APPEND ||
        app->first_render_script_count >= BROWSER_MAX_SCRIPTS)
    {
        return false;
    }
    browser_ui_event_t *slot =
        &app->first_render_scripts[app->first_render_script_count];
    if (!browser_ui_event_move(slot, ev))
    {
        return false;
    }
    app->first_render_script_count++;
    return true;
}

bool browser_first_render_script_take(browser_app_t *app, browser_ui_event_t *out)
{
    if (!app || !out || app->first_render_script_count == 0u)
    {
        return false;
    }
    if (!browser_ui_event_move(out, &app->first_render_scripts[0]))
    {
        return false;
    }
    app->first_render_script_count--;
    if (app->first_render_script_count > 0u)
    {
        memmove(&app->first_render_scripts[0],
                &app->first_render_scripts[1],
                app->first_render_script_count * sizeof(app->first_render_scripts[0]));
    }
    memset(&app->first_render_scripts[app->first_render_script_count],
           0,
           sizeof(app->first_render_scripts[0]));
    return true;
}

void browser_first_render_scripts_clear(browser_app_t *app)
{
    if (!app)
    {
        return;
    }
    for (size_t i = 0; i < app->first_render_script_count; ++i)
    {
        browser_ui_event_free_payload(&app->first_render_scripts[i]);
        memset(&app->first_render_scripts[i], 0, sizeof(app->first_render_scripts[i]));
    }
    app->first_render_script_count = 0u;
}

bool browser_script_event_init(browser_ui_event_t *ev,
                               uint64_t load_id,
                               const char *src,
                               char *script,
                               size_t len)
{
    if (!ev || !script || len == 0)
    {
        return false;
    }

    memset(ev, 0, sizeof(*ev));
    ev->type = BROWSER_UI_EVENT_SCRIPT_APPEND;
    ev->load_id = load_id;
    ev->u.script_append.script = script;
    ev->u.script_append.len = len;

    if (src && src[0] != '\0')
    {
        ev->u.script_append.src = browser_strdup(src);
    }

    return true;
}

bool browser_document_event_init_owned(browser_ui_event_t *ev,
                                       uint64_t load_id,
                                       html_document_t *doc,
                                       char *final_url,
                                       char *external_css,
                                       size_t external_css_len)
{
    if (!ev || !doc)
    {
        return false;
    }
    if (external_css_len > 0 && !external_css)
    {
        return false;
    }

    memset(ev, 0, sizeof(*ev));
    ev->type = BROWSER_UI_EVENT_DOC_READY;
    ev->load_id = load_id;
    ev->u.doc_ready.doc = doc;
    ev->u.doc_ready.final_url = final_url;
    ev->u.doc_ready.external_css = external_css;
    ev->u.doc_ready.external_css_len = external_css_len;
    return true;
}

bool browser_error_event_init(browser_ui_event_t *ev,
                              uint64_t load_id,
                              const char *message)
{
    if (!ev)
    {
        return false;
    }

    char *copy = browser_strdup(message ? message : "unknown error");
    if (!copy)
    {
        return false;
    }

    memset(ev, 0, sizeof(*ev));
    ev->type = BROWSER_UI_EVENT_ERROR;
    ev->load_id = load_id;
    ev->u.error.message = copy;
    return true;
}
