#include "browser_internal.h"

#include "string.h"

static void browser_ui_event_sanitize_locked(browser_app_t *app)
{
    if (!app)
    {
        return;
    }
    if (app->ui_event_head >= BROWSER_UI_EVENT_QUEUE_CAP ||
        app->ui_event_count > BROWSER_UI_EVENT_QUEUE_CAP)
    {
        app->ui_event_head = 0;
        app->ui_event_count = 0;
        memset(app->ui_events, 0, sizeof(app->ui_events));
    }
}

void browser_ui_event_free_payload(browser_ui_event_t *ev)
{
    if (!ev)
    {
        return;
    }

    switch (ev->type)
    {
        case BROWSER_UI_EVENT_DOC_READY:
            if (ev->u.doc_ready.doc)
            {
                html_document_destroy(ev->u.doc_ready.doc);
                ev->u.doc_ready.doc = NULL;
            }
            free(ev->u.doc_ready.final_url);
            ev->u.doc_ready.final_url = NULL;
            free(ev->u.doc_ready.external_css);
            ev->u.doc_ready.external_css = NULL;
            ev->u.doc_ready.external_css_len = 0;
            break;
        case BROWSER_UI_EVENT_LOAD_BEGIN:
            break;
        case BROWSER_UI_EVENT_NAV_UPDATE:
            free(ev->u.nav_update.final_url);
            ev->u.nav_update.final_url = NULL;
            break;
        case BROWSER_UI_EVENT_ERROR:
            free(ev->u.error.message);
            ev->u.error.message = NULL;
            break;
        case BROWSER_UI_EVENT_CSS_APPEND:
            free(ev->u.css_append.css);
            ev->u.css_append.css = NULL;
            ev->u.css_append.len = 0;
            break;
        case BROWSER_UI_EVENT_SCRIPT_APPEND:
            free(ev->u.script_append.src);
            ev->u.script_append.src = NULL;
            free(ev->u.script_append.script);
            ev->u.script_append.script = NULL;
            ev->u.script_append.len = 0;
            break;
        case BROWSER_UI_EVENT_IMAGE_PNG:
            free(ev->u.image_png.src);
            ev->u.image_png.src = NULL;
            free(ev->u.image_png.data);
            ev->u.image_png.data = NULL;
            ev->u.image_png.len = 0;
            break;
        case BROWSER_UI_EVENT_IMAGE_GIF:
            free(ev->u.image_gif.src);
            ev->u.image_gif.src = NULL;
            free(ev->u.image_gif.data);
            ev->u.image_gif.data = NULL;
            ev->u.image_gif.len = 0;
            break;
        case BROWSER_UI_EVENT_IMAGE_RGBA:
            free(ev->u.image_rgba.src);
            ev->u.image_rgba.src = NULL;
            free(ev->u.image_rgba.pixels);
            ev->u.image_rgba.pixels = NULL;
            ev->u.image_rgba.width = 0;
            ev->u.image_rgba.height = 0;
            ev->u.image_rgba.stride_bytes = 0;
            break;
        case BROWSER_UI_EVENT_THREAD_DONE:
            break;
        default:
            break;
    }
}

bool browser_ui_event_enqueue_owned(browser_app_t *app, browser_ui_event_t *ev)
{
    return browser_ui_event_enqueue_batch_owned(app, ev, 1u);
}

static bool browser_ui_event_enqueue_batch_impl(browser_app_t *app,
                                                uint64_t required_load_id,
                                                bool require_active_load,
                                                browser_ui_event_t *events,
                                                size_t count)
{
    if (!events || count == 0u)
    {
        return false;
    }
    if (!app)
    {
        for (size_t i = 0; i < count; ++i)
        {
            browser_ui_event_free_payload(&events[i]);
            memset(&events[i], 0, sizeof(events[i]));
        }
        return false;
    }

    bool ok = false;
    browser_lock_enter(app, &app->lock, "app_lock");
    browser_ui_event_sanitize_locked(app);
    bool active_ok = !require_active_load ||
                     (required_load_id != 0u && app->active_load_id == required_load_id);
    if (active_ok && count <= BROWSER_UI_EVENT_QUEUE_CAP - app->ui_event_count)
    {
        for (size_t i = 0; i < count; ++i)
        {
            size_t idx = (app->ui_event_head + app->ui_event_count + i) %
                         BROWSER_UI_EVENT_QUEUE_CAP;
            (void)browser_ui_event_move(&app->ui_events[idx], &events[i]);
        }
        app->ui_event_count += count;
        ok = true;
    }
    browser_lock_exit(app, &app->lock, "app_lock");
    if (!ok)
    {
        for (size_t i = 0; i < count; ++i)
        {
            browser_ui_event_free_payload(&events[i]);
            memset(&events[i], 0, sizeof(events[i]));
        }
    }
    return ok;
}

bool browser_ui_event_enqueue_batch_owned(browser_app_t *app,
                                          browser_ui_event_t *events,
                                          size_t count)
{
    return browser_ui_event_enqueue_batch_impl(app, 0u, false, events, count);
}

bool browser_ui_event_enqueue_batch_for_load_owned(browser_app_t *app,
                                                   uint64_t load_id,
                                                   browser_ui_event_t *events,
                                                   size_t count)
{
    return browser_ui_event_enqueue_batch_impl(app, load_id, true, events, count);
}

bool browser_load_queue_push(browser_app_t *app, browser_load_job_kind_t kind, uint64_t load_id, char *url_text)
{
    if (!app)
    {
        free(url_text);
        return false;
    }

    browser_load_request_t *job = (browser_load_request_t *)calloc(1, sizeof(*job));
    if (!job)
    {
        free(url_text);
        return false;
    }
    job->kind = kind;
    job->load_id = load_id;
    job->url_text = url_text;

    browser_lock_enter(app, &app->load_lock, "load_lock");
    if (app->load_queue.tail)
    {
        app->load_queue.tail->next = job;
    }
    else
    {
        app->load_queue.head = job;
    }
    app->load_queue.tail = job;
    app->load_queue.count++;
    browser_lock_exit(app, &app->load_lock, "load_lock");
    return true;
}

browser_load_request_t *browser_load_queue_pop(browser_app_t *app)
{
    if (!app)
    {
        return NULL;
    }

    browser_load_request_t *job = NULL;
    browser_lock_enter(app, &app->load_lock, "load_lock");
    job = app->load_queue.head;
    if (job)
    {
        app->load_queue.head = job->next;
        if (!app->load_queue.head)
        {
            app->load_queue.tail = NULL;
        }
        if (app->load_queue.count > 0)
        {
            app->load_queue.count--;
        }
    }
    browser_lock_exit(app, &app->load_lock, "load_lock");

    if (job)
    {
        job->next = NULL;
    }
    return job;
}

void browser_load_queue_clear(browser_app_t *app)
{
    if (!app)
    {
        return;
    }

    browser_load_request_t *job = NULL;
    browser_lock_enter(app, &app->load_lock, "load_lock");
    job = app->load_queue.head;
    app->load_queue.head = NULL;
    app->load_queue.tail = NULL;
    app->load_queue.count = 0;
    browser_lock_exit(app, &app->load_lock, "load_lock");

    while (job)
    {
        browser_load_request_t *next = job->next;
        free(job->url_text);
        free(job);
        job = next;
    }
}

bool browser_ui_event_dequeue(browser_app_t *app, browser_ui_event_t *out)
{
    if (!app || !out)
    {
        return false;
    }

    bool ok = false;
    browser_lock_enter(app, &app->lock, "app_lock");
    browser_ui_event_sanitize_locked(app);
    if (app->ui_event_count > 0)
    {
        *out = app->ui_events[app->ui_event_head];
        app->ui_event_head = (app->ui_event_head + 1) % BROWSER_UI_EVENT_QUEUE_CAP;
        app->ui_event_count--;
        ok = true;
    }
    browser_lock_exit(app, &app->lock, "app_lock");
    return ok;
}

bool browser_resource_queue_push(browser_app_t *app,
                                 browser_resource_kind_t kind,
                                 uint64_t load_id,
                                 char *url)
{
    if (!app || !url)
    {
        return false;
    }

    browser_resource_job_t *job = (browser_resource_job_t *)calloc(1, sizeof(*job));
    if (!job)
    {
        return false;
    }
    job->kind = kind;
    job->load_id = load_id;
    job->url = url;

    browser_lock_enter(app, &app->resource_lock, "resource_lock");
    if (__atomic_load_n(&app->resource_thread_stop, __ATOMIC_ACQUIRE) != 0u ||
        app->resource_thread == 0)
    {
        browser_lock_exit(app, &app->resource_lock, "resource_lock");
        free(job);
        return false;
    }
    if (app->resource_queue.tail)
    {
        app->resource_queue.tail->next = job;
    }
    else
    {
        app->resource_queue.head = job;
    }
    app->resource_queue.tail = job;
    app->resource_queue.count++;
    browser_lock_exit(app, &app->resource_lock, "resource_lock");
    return true;
}

browser_resource_job_t *browser_resource_queue_pop(browser_app_t *app)
{
    if (!app)
    {
        return NULL;
    }
    browser_resource_job_t *job = NULL;
    browser_lock_enter(app, &app->resource_lock, "resource_lock");
    job = app->resource_queue.head;
    uint64_t deferred_load_id =
        __atomic_load_n(&app->resource_defer_load_id, __ATOMIC_ACQUIRE);
    bool defer_job = job && job->kind != BROWSER_RESOURCE_CSS &&
                     deferred_load_id != 0u && job->load_id == deferred_load_id;
    if (job && !defer_job)
    {
        app->resource_queue.head = job->next;
        if (!app->resource_queue.head)
        {
            app->resource_queue.tail = NULL;
        }
        if (app->resource_queue.count > 0)
        {
            app->resource_queue.count--;
        }
    }
    else if (defer_job)
    {
        job = NULL;
    }
    browser_lock_exit(app, &app->resource_lock, "resource_lock");

    if (job)
    {
        job->next = NULL;
    }
    return job;
}

void browser_resource_queue_clear(browser_app_t *app)
{
    if (!app)
    {
        return;
    }

    browser_resource_job_t *job = NULL;
    browser_lock_enter(app, &app->resource_lock, "resource_lock");
    job = app->resource_queue.head;
    app->resource_queue.head = NULL;
    app->resource_queue.tail = NULL;
    app->resource_queue.count = 0;
    browser_lock_exit(app, &app->resource_lock, "resource_lock");

    while (job)
    {
        browser_resource_job_t *next = job->next;
        free(job->url);
        free(job);
        job = next;
    }
}

bool browser_resource_queue_append(browser_app_t *app, browser_resource_queue_t *queue)
{
    if (!app || !queue || !queue->head)
    {
        return true;
    }

    bool appended = false;
    browser_lock_enter(app, &app->resource_lock, "resource_lock");
    if (__atomic_load_n(&app->resource_thread_stop, __ATOMIC_ACQUIRE) == 0u &&
        app->resource_thread != 0)
    {
        if (app->resource_queue.tail)
        {
            app->resource_queue.tail->next = queue->head;
        }
        else
        {
            app->resource_queue.head = queue->head;
        }
        app->resource_queue.tail = queue->tail ? queue->tail : queue->head;
        app->resource_queue.count += queue->count;
        queue->head = NULL;
        queue->tail = NULL;
        queue->count = 0;
        appended = true;
    }
    browser_lock_exit(app, &app->resource_lock, "resource_lock");
    return appended;
}
