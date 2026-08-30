#include "browser_internal.h"
#include "atk/html_view/html_view_internal.h"

#include "stdio.h"
#include "stdlib.h"
#include "string.h"

void alix_mutex_lock(alix_mutex_t *mutex)
{
    (void)mutex;
}

void alix_mutex_unlock(alix_mutex_t *mutex)
{
    (void)mutex;
}

alix_thread_t alix_thread_self(void)
{
    return 1u;
}

uint64_t sys_time_millis(void)
{
    return 1u;
}

static void free_script_event(browser_ui_event_t *ev)
{
    if (!ev)
    {
        return;
    }
    free(ev->u.script_append.src);
    free(ev->u.script_append.script);
    memset(ev, 0, sizeof(*ev));
}

static bool test_script_event_copies_src(void)
{
    const char *src = "https://example.com/app.js";
    const char *script_text = "console.log('ok');";
    size_t script_len = strlen(script_text);
    char *script = (char *)malloc(script_len + 1);
    if (!script)
    {
        return false;
    }
    memcpy(script, script_text, script_len + 1);

    browser_ui_event_t ev = {0};
    if (!browser_script_event_init(&ev, 1, src, script, script_len))
    {
        free(script);
        return false;
    }

    if (!ev.u.script_append.src)
    {
        free(ev.u.script_append.script);
        return false;
    }
    if (ev.u.script_append.src == src)
    {
        free(ev.u.script_append.src);
        free(ev.u.script_append.script);
        return false;
    }
    if (strcmp(ev.u.script_append.src, src) != 0)
    {
        free(ev.u.script_append.src);
        free(ev.u.script_append.script);
        return false;
    }
    if (ev.u.script_append.script != script)
    {
        free(ev.u.script_append.src);
        free(ev.u.script_append.script);
        return false;
    }

    free(ev.u.script_append.src);
    free(ev.u.script_append.script);
    return true;
}

static bool test_document_event_takes_heap_payloads(void)
{
    html_document_t *doc = (html_document_t *)calloc(1, sizeof(*doc));
    char *final_url = browser_strdup("https://example.com/final");
    char *css = browser_strdup("body { color: green; }");
    if (!doc || !final_url || !css)
    {
        free(doc);
        free(final_url);
        free(css);
        return false;
    }

    browser_ui_event_t ev = {0};
    if (!browser_document_event_init_owned(&ev,
                                           42,
                                           doc,
                                           final_url,
                                           css,
                                           strlen(css)))
    {
        free(doc);
        free(final_url);
        free(css);
        return false;
    }

    bool ok = ev.type == BROWSER_UI_EVENT_DOC_READY &&
              ev.load_id == 42 &&
              ev.u.doc_ready.doc == doc &&
              ev.u.doc_ready.final_url == final_url &&
              ev.u.doc_ready.external_css == css &&
              ev.u.doc_ready.external_css_len == strlen(css);

    browser_ui_event_t queued = {0};
    browser_ui_event_t zero = {0};
    ok = ok && browser_ui_event_move(&queued, &ev) &&
         memcmp(&ev, &zero, sizeof(ev)) == 0 &&
         queued.type == BROWSER_UI_EVENT_DOC_READY &&
         queued.u.doc_ready.doc == doc &&
         queued.u.doc_ready.final_url == final_url &&
         queued.u.doc_ready.external_css == css;
    free(doc);
    free(final_url);
    free(css);
    return ok;
}

static bool test_error_event_copies_worker_message(void)
{
    char worker_message[] = "connection reset";
    browser_ui_event_t ev = {0};
    if (!browser_error_event_init(&ev, 9, worker_message))
    {
        return false;
    }

    bool ok = ev.type == BROWSER_UI_EVENT_ERROR &&
              ev.load_id == 9 &&
              ev.u.error.message != worker_message &&
              strcmp(ev.u.error.message, worker_message) == 0;
    worker_message[0] = 'X';
    ok = ok && strcmp(ev.u.error.message, "connection reset") == 0;
    free(ev.u.error.message);
    return ok;
}

static bool test_deferred_event_preserves_order_and_is_bounded(void)
{
    browser_app_t app = {0};
    char *script_a = browser_strdup("window.a = 1;");
    char *script_b = browser_strdup("window.b = 1;");
    if (!script_a || !script_b)
    {
        free(script_a);
        free(script_b);
        return false;
    }

    browser_ui_event_t first = {0};
    browser_ui_event_t second = {0};
    if (!browser_script_event_init(&first, 7, "https://example.com/a.js", script_a, strlen(script_a)) ||
        !browser_script_event_init(&second, 7, "https://example.com/b.js", script_b, strlen(script_b)))
    {
        free_script_event(&first);
        free_script_event(&second);
        return false;
    }
    first.defer_last_log_ms = 999u;

    bool ok = browser_ui_event_defer(&app, &first, 1000u) &&
              app.deferred_ui_event_valid &&
              app.ui_defer_chain_active &&
              app.ui_defer_chain_attempts == 1u &&
              first.u.script_append.script == NULL &&
              app.deferred_ui_event.defer_attempts == 1u &&
              app.deferred_ui_event.defer_started_ms == 1000u &&
              app.deferred_ui_event.defer_last_log_ms == 999u &&
              app.deferred_ui_event.defer_retry_after_ms == 1000u + BROWSER_UI_DEFER_RETRY_MS;

    ok = ok && !browser_ui_event_defer(&app, &second, 1001u) &&
         second.u.script_append.script == script_b &&
         !browser_ui_event_take_deferred(&app, 1000u + BROWSER_UI_DEFER_RETRY_MS - 1u, &first);

    ok = ok && browser_ui_event_take_deferred(&app,
                                               1000u + BROWSER_UI_DEFER_RETRY_MS,
                                               &first) &&
         !app.deferred_ui_event_valid &&
         strcmp(first.u.script_append.src, "https://example.com/a.js") == 0 &&
         strcmp(second.u.script_append.src, "https://example.com/b.js") == 0 &&
         !browser_ui_event_defer_expired(&app,
                                         &first,
                                         1000u + BROWSER_UI_DEFER_TIMEOUT_MS - 1u) &&
         browser_ui_event_defer_expired(&app,
                                        &first,
                                        1000u + BROWSER_UI_DEFER_TIMEOUT_MS);

    ok = ok && browser_ui_event_defer(&app,
                                      &first,
                                      1000u + BROWSER_UI_DEFER_RETRY_MS) &&
         app.deferred_ui_event.defer_attempts == 2u &&
         app.deferred_ui_event.defer_started_ms == 1000u &&
         browser_ui_event_take_deferred(&app,
                                        1000u + BROWSER_UI_DEFER_RETRY_MS * 2u,
                                        &first) &&
         browser_ui_event_defer(&app, &second, 2000u) &&
         app.deferred_ui_event.defer_started_ms == 2000u &&
         app.ui_defer_chain_attempts == 3u;

    app.ui_defer_chain_attempts = BROWSER_UI_DEFER_MAX_ATTEMPTS;
    ok = ok && browser_ui_event_defer_expired(&app,
                                              &app.deferred_ui_event,
                                              500u);

    free_script_event(&app.deferred_ui_event);
    app.deferred_ui_event_valid = false;
    first.load_id = 8u;
    ok = ok && browser_ui_event_defer(&app, &first, 3000u) &&
         app.ui_defer_chain_load_id == 8u &&
         app.ui_defer_chain_attempts == 1u &&
         app.deferred_ui_event.defer_started_ms == 3000u;
    free_script_event(&app.deferred_ui_event);
    app.deferred_ui_event_valid = false;
    browser_ui_event_defer_chain_reset(&app);
    return ok;
}

static bool test_atomic_batch_queue_and_stale_load_rejection(void)
{
    browser_app_t app = {0};
    app.active_load_id = 7u;

    browser_ui_event_t batch[2] = {0};
    char *script_a = browser_strdup("window.a = 1;");
    char *script_b = browser_strdup("window.b = 1;");
    if (!script_a || !script_b)
    {
        free(script_a);
        free(script_b);
        return false;
    }
    if (!browser_script_event_init(&batch[0], 7u, "https://example.com/a.js", script_a, strlen(script_a)))
    {
        free(script_a);
        free(script_b);
        return false;
    }
    if (!browser_script_event_init(&batch[1], 7u, "https://example.com/b.js", script_b, strlen(script_b)))
    {
        free(script_b);
        free_script_event(&batch[0]);
        return false;
    }

    browser_ui_event_t zero = {0};
    bool ok = browser_ui_event_enqueue_batch_for_load_owned(&app, 7u, batch, 2u) &&
              app.ui_event_count == 2u &&
              memcmp(&batch[0], &zero, sizeof(zero)) == 0 &&
              memcmp(&batch[1], &zero, sizeof(zero)) == 0;

    browser_ui_event_t out = {0};
    ok = ok && browser_ui_event_dequeue(&app, &out) &&
         out.u.script_append.src && strcmp(out.u.script_append.src, "https://example.com/a.js") == 0;
    browser_ui_event_free_payload(&out);
    memset(&out, 0, sizeof(out));
    ok = ok && browser_ui_event_dequeue(&app, &out) &&
         out.u.script_append.src && strcmp(out.u.script_append.src, "https://example.com/b.js") == 0 &&
         app.ui_event_count == 0u;
    browser_ui_event_free_payload(&out);

    char *stale_script = browser_strdup("window.stale = 1;");
    browser_ui_event_t stale = {0};
    if (!stale_script)
    {
        return false;
    }
    if (!browser_script_event_init(&stale,
                                   7u,
                                   "https://example.com/stale.js",
                                   stale_script,
                                   strlen(stale_script)))
    {
        free(stale_script);
        return false;
    }
    app.active_load_id = 8u;
    ok = ok && !browser_ui_event_enqueue_batch_for_load_owned(&app, 7u, &stale, 1u) &&
         memcmp(&stale, &zero, sizeof(zero)) == 0 && app.ui_event_count == 0u;

    memset(app.ui_events, 0, sizeof(app.ui_events));
    browser_ui_event_t full_batch[2] = {0};
    char *full_a = browser_strdup("a");
    char *full_b = browser_strdup("b");
    if (!full_a || !full_b)
    {
        free(full_a);
        free(full_b);
        return false;
    }
    if (!browser_script_event_init(&full_batch[0], 8u, "a.js", full_a, 1u))
    {
        free(full_a);
        free(full_b);
        return false;
    }
    if (!browser_script_event_init(&full_batch[1], 8u, "b.js", full_b, 1u))
    {
        free(full_b);
        free_script_event(&full_batch[0]);
        return false;
    }
    app.ui_event_head = 0u;
    app.ui_event_count = BROWSER_UI_EVENT_QUEUE_CAP - 1u;
    ok = ok && !browser_ui_event_enqueue_batch_for_load_owned(&app, 8u, full_batch, 2u) &&
         memcmp(&full_batch[0], &zero, sizeof(zero)) == 0 &&
         memcmp(&full_batch[1], &zero, sizeof(zero)) == 0 &&
         app.ui_event_count == BROWSER_UI_EVENT_QUEUE_CAP - 1u;
    app.ui_event_count = 0u;
    return ok;
}

static bool test_async_render_consumes_latest_pre_layout_generation(void)
{
    volatile uint32_t sequence = 53u;
    volatile uint32_t stylesheet_dirty = 1u;
    volatile uint32_t js_dirty = 0u;
    char *pending_css = NULL;
    uint32_t target = 29u;

    bool ok = !html_view_render_prepare_generation(&sequence,
                                                   &stylesheet_dirty,
                                                   &js_dirty,
                                                   &pending_css,
                                                   &target) &&
              target == 29u;
    stylesheet_dirty = 0u;
    pending_css = (char *)(uintptr_t)1u;
    ok = ok && !html_view_render_prepare_generation(&sequence,
                                                    &stylesheet_dirty,
                                                    &js_dirty,
                                                    &pending_css,
                                                    &target) &&
         target == 29u;
    pending_css = NULL;
    js_dirty = HTML_VIEW_JS_DIRTY_RENDER;
    ok = ok && !html_view_render_prepare_generation(&sequence,
                                                    &stylesheet_dirty,
                                                    &js_dirty,
                                                    &pending_css,
                                                    &target) &&
         target == 29u;
    js_dirty = 0u;
    ok = ok && html_view_render_prepare_generation(&sequence,
                                                   &stylesheet_dirty,
                                                   &js_dirty,
                                                   &pending_css,
                                                   &target) &&
         target == 53u;
    return ok;
}

static bool test_first_render_script_buffer_preserves_order(void)
{
    browser_app_t app = {0};
    browser_ui_event_t first = {0};
    browser_ui_event_t second = {0};
    char *script_a = browser_strdup("window.a = 1;");
    char *script_b = browser_strdup("window.b = 1;");
    if (!script_a || !script_b)
    {
        free(script_a);
        free(script_b);
        return false;
    }
    if (!browser_script_event_init(&first, 12u, "a.js", script_a, strlen(script_a)))
    {
        free(script_a);
        free(script_b);
        return false;
    }
    if (!browser_script_event_init(&second, 12u, "b.js", script_b, strlen(script_b)))
    {
        free(script_b);
        free_script_event(&first);
        return false;
    }

    browser_ui_event_t zero = {0};
    bool ok = browser_first_render_script_buffer(&app, &first) &&
              browser_first_render_script_buffer(&app, &second) &&
              memcmp(&first, &zero, sizeof(first)) == 0 &&
              memcmp(&second, &zero, sizeof(second)) == 0 &&
              app.first_render_script_count == 2u;

    browser_ui_event_t out = {0};
    ok = ok && browser_first_render_script_take(&app, &out) &&
         out.u.script_append.src && strcmp(out.u.script_append.src, "a.js") == 0 &&
         app.first_render_script_count == 1u &&
         app.first_render_scripts[0].u.script_append.src &&
         strcmp(app.first_render_scripts[0].u.script_append.src, "b.js") == 0;
    browser_ui_event_free_payload(&out);
    browser_first_render_scripts_clear(&app);
    ok = ok && app.first_render_script_count == 0u &&
         !browser_first_render_script_take(&app, &out);

    for (size_t i = 0; i < BROWSER_MAX_SCRIPTS; ++i)
    {
        browser_ui_event_t buffered = {0};
        char *script = browser_strdup("x");
        if (!script)
        {
            browser_first_render_scripts_clear(&app);
            return false;
        }
        if (!browser_script_event_init(&buffered, 12u, NULL, script, 1u))
        {
            free(script);
            browser_first_render_scripts_clear(&app);
            return false;
        }
        if (!browser_first_render_script_buffer(&app, &buffered))
        {
            free_script_event(&buffered);
            browser_first_render_scripts_clear(&app);
            return false;
        }
    }
    browser_ui_event_t overflow = {0};
    char *overflow_script = browser_strdup("y");
    if (!overflow_script ||
        !browser_script_event_init(&overflow, 12u, NULL, overflow_script, 1u))
    {
        free(overflow_script);
        browser_first_render_scripts_clear(&app);
        return false;
    }
    ok = ok && !browser_first_render_script_buffer(&app, &overflow) &&
         overflow.u.script_append.script == overflow_script &&
         app.first_render_script_count == BROWSER_MAX_SCRIPTS;
    free_script_event(&overflow);
    browser_first_render_scripts_clear(&app);
    ok = ok && app.first_render_script_count == 0u;
    return ok;
}

static bool test_noncritical_resource_queue_waits_for_first_render(void)
{
    browser_app_t app = {0};
    app.resource_thread = 1u;
    app.resource_thread_stop = 0u;
    app.resource_defer_load_id = 21u;

    char *stale_url = browser_strdup("https://example.com/stale.js");
    if (!stale_url || !browser_resource_queue_push(&app,
                                                   BROWSER_RESOURCE_SCRIPT,
                                                   20u,
                                                   stale_url))
    {
        free(stale_url);
        return false;
    }
    browser_resource_job_t *stale_job = browser_resource_queue_pop(&app);
    bool ok = stale_job && stale_job->load_id == 20u;
    if (stale_job)
    {
        free(stale_job->url);
        free(stale_job);
    }
    else
    {
        browser_resource_queue_clear(&app);
    }

    char *url = browser_strdup("https://example.com/app.js");
    if (!url || !browser_resource_queue_push(&app,
                                             BROWSER_RESOURCE_SCRIPT,
                                             21u,
                                             url))
    {
        free(url);
        return false;
    }

    ok = ok && app.resource_queue.count == 1u &&
         browser_resource_queue_pop(&app) == NULL &&
         app.resource_queue.count == 1u;
    __atomic_store_n(&app.resource_defer_load_id, 0u, __ATOMIC_RELEASE);
    browser_resource_job_t *job = browser_resource_queue_pop(&app);
    ok = ok && job && job->kind == BROWSER_RESOURCE_SCRIPT &&
         job->load_id == 21u && job->url && strcmp(job->url, url) == 0 &&
         app.resource_queue.count == 0u;
    if (job)
    {
        free(job->url);
        free(job);
    }
    else
    {
        browser_resource_queue_clear(&app);
    }

    app.resource_defer_load_id = 21u;
    char *css_url = browser_strdup("https://example.com/app.css");
    if (!css_url || !browser_resource_queue_push(&app,
                                                 BROWSER_RESOURCE_CSS,
                                                 21u,
                                                 css_url))
    {
        free(css_url);
        return false;
    }
    browser_resource_job_t *css_job = browser_resource_queue_pop(&app);
    ok = ok && css_job && css_job->kind == BROWSER_RESOURCE_CSS;
    if (css_job)
    {
        free(css_job->url);
        free(css_job);
    }
    else
    {
        browser_resource_queue_clear(&app);
    }
    return ok;
}

static bool test_main_document_http_errors_are_rejected(void)
{
    struct
    {
        int status;
        const char *body;
        bool error;
        const char *message;
    } cases[] = {
        { 0, "<html><body>ok</body></html>", false, "" },
        { 200, "<html><title>Just a moment...</title></html>", false, "" },
        { 399, "redirect result", false, "" },
        { 400, "bad request body", true, "HTTP 400 Bad Request" },
        { 403, "<html><title>Just a moment...</title></html>", true, "HTTP 403 Forbidden" },
        { 404, "missing", true, "HTTP 404 Not Found" },
        { 500, "server error body", true, "HTTP 500 Internal Server Error" },
        { 0, "Error:\nconnection reset\n", true, "connection reset" },
        { 200, "Error:\nlegacy transport failure\n", true, "legacy transport failure" },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    {
        char message[96];
        bool error = browser_main_document_error(cases[i].status,
                                                 cases[i].body,
                                                 message,
                                                 sizeof(message));
        if (error != cases[i].error || strcmp(message, cases[i].message) != 0)
        {
            return false;
        }
    }
    return true;
}

int main(void)
{
    struct
    {
        const char *name;
        bool (*fn)(void);
    } tests[] = {
        { "script-event-copies-src", test_script_event_copies_src },
        { "document-event-takes-heap-payloads", test_document_event_takes_heap_payloads },
        { "error-event-copies-worker-message", test_error_event_copies_worker_message },
        { "deferred-event-preserves-order-and-is-bounded", test_deferred_event_preserves_order_and_is_bounded },
        { "atomic-batch-queue-and-stale-load-rejection", test_atomic_batch_queue_and_stale_load_rejection },
        { "async-render-consumes-latest-pre-layout-generation", test_async_render_consumes_latest_pre_layout_generation },
        { "first-render-script-buffer-preserves-order", test_first_render_script_buffer_preserves_order },
        { "noncritical-resource-queue-waits-for-first-render", test_noncritical_resource_queue_waits_for_first_render },
        { "main-document-http-errors-are-rejected", test_main_document_http_errors_are_rejected },
    };

    int failed = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i)
    {
        if (!tests[i].fn())
        {
            fprintf(stderr, "FAIL: %s\n", tests[i].name);
            failed++;
        }
        else
        {
            fprintf(stdout, "ok: %s\n", tests[i].name);
        }
    }

    return failed == 0 ? 0 : 1;
}
