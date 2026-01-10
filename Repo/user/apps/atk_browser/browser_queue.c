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

bool browser_ui_event_enqueue(browser_app_t *app, const browser_ui_event_t *ev)
{
    if (!app || !ev)
    {
        return false;
    }

    bool ok = false;
    browser_lock_enter(app, &app->lock, "app_lock");
    browser_ui_event_sanitize_locked(app);
    if (app->ui_event_count < BROWSER_UI_EVENT_QUEUE_CAP)
    {
        size_t idx = (app->ui_event_head + app->ui_event_count) % BROWSER_UI_EVENT_QUEUE_CAP;
        app->ui_events[idx] = *ev;
        app->ui_event_count++;
        ok = true;
    }
    browser_lock_exit(app, &app->lock, "app_lock");
    return ok;
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
    if (job)
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
