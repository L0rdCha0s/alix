#include "browser_internal.h"

#include "stdarg.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

void browser_debug_logf(browser_app_t *app, const char *fmt, ...)
{
    (void)app;
    (void)fmt;
}

static void resource_queue_destroy(browser_resource_queue_t *queue)
{
    if (!queue)
    {
        return;
    }
    browser_resource_job_t *job = queue->head;
    while (job)
    {
        browser_resource_job_t *next = job->next;
        free(job->url);
        free(job);
        job = next;
    }
    memset(queue, 0, sizeof(*queue));
}

static bool test_resource_set_dedup_survives_growth(void)
{
    browser_resource_set_t set = {0};
    if (!browser_resource_set_init(&set))
    {
        return false;
    }

    bool ok = true;
    char url[96];
    for (unsigned i = 0; i < 300u; ++i)
    {
        snprintf(url, sizeof(url), "https://example.com/assets/%u.png", i);
        if (browser_resource_set_track(&set, BROWSER_RESOURCE_IMAGE, url) != BROWSER_RESOURCE_TRACK_NEW)
        {
            ok = false;
            break;
        }
    }

    if (ok)
    {
        ok = browser_resource_set_track(&set,
                                        BROWSER_RESOURCE_IMAGE,
                                        "https://example.com/assets/12.png") == BROWSER_RESOURCE_TRACK_DUP &&
             browser_resource_set_track(&set,
                                        BROWSER_RESOURCE_SCRIPT,
                                        "https://example.com/assets/12.png") == BROWSER_RESOURCE_TRACK_NEW;
    }

    browser_resource_set_destroy(&set);
    return ok;
}

static bool test_arena_dom_rewrite_and_scan_dedup(void)
{
    const char *html =
        "<!doctype html><html><body>"
        "<img src=\"/assets/avatar.png\">"
        "<img src=\"/assets/avatar.png\">"
        "<svg width=\"4\" height=\"4\"></svg>"
        "</body></html>";
    html_parse_error_t error = {0};
    html_document_t *doc = html_parse(html, &error);
    if (!doc || !doc->root)
    {
        html_document_destroy(doc);
        return false;
    }

    browser_url_t base = {0};
    browser_resource_set_t requested = {0};
    browser_resource_queue_t first_queue = {0};
    browser_resource_queue_t second_queue = {0};
    browser_resource_queue_t failed_tracking_queue = {0};
    browser_app_t app = {0};
    bool ok = browser_parse_url("https://example.com/questions", &base) &&
              browser_resource_set_init(&requested);

    size_t first_count = 0;
    size_t second_count = 0;
    size_t failed_tracking_count = 0;
    if (ok)
    {
        first_count = browser_collect_resource_urls(&app,
                                                    doc->root,
                                                    &base,
                                                    &requested,
                                                    BROWSER_RESOURCE_IMAGE,
                                                    9,
                                                    &first_queue);
        second_count = browser_collect_resource_urls(&app,
                                                     doc->root,
                                                     &base,
                                                     &requested,
                                                     BROWSER_RESOURCE_IMAGE,
                                                     9,
                                                     &second_queue);
        browser_resource_set_t unavailable = {0};
        failed_tracking_count = browser_collect_resource_urls(&app,
                                                              doc->root,
                                                              &base,
                                                              &unavailable,
                                                              BROWSER_RESOURCE_IMAGE,
                                                              9,
                                                              &failed_tracking_queue);
    }

    html_node_t *img = (html_node_t *)browser_dom_find_first_element(doc->root, "img");
    html_node_t *svg = (html_node_t *)browser_dom_find_first_element(doc->root, "svg");
    const char *img_src = img ? html_attr_get(img, "src") : NULL;
    ok = ok && first_count == 1u && first_queue.count == 1u &&
         second_count == 0u && second_queue.count == 0u &&
         failed_tracking_count == 0u && failed_tracking_queue.count == 0u &&
         img_src && strcmp(img_src, "https://example.com/assets/avatar.png") == 0 &&
         browser_dom_set_attr(img, "data-test", "arena-owned") &&
         strcmp(html_attr_get(img, "data-test"), "arena-owned") == 0 &&
         browser_dom_set_attr(img, "data-test", "updated") &&
         strcmp(html_attr_get(img, "data-test"), "updated") == 0 &&
         svg && browser_dom_set_tag_name(svg, "img") && strcmp(svg->name, "img") == 0;

    resource_queue_destroy(&first_queue);
    resource_queue_destroy(&second_queue);
    resource_queue_destroy(&failed_tracking_queue);
    browser_resource_set_destroy(&requested);
    browser_url_destroy(&base);
    html_document_destroy(doc);
    return ok;
}

static bool test_resource_collection_enforces_kind_limit(void)
{
    const char *html =
        "<html><body>"
        "<img src='/0.png'><img src='/1.png'><img src='/2.png'><img src='/3.png'>"
        "<img src='/4.png'><img src='/5.png'><img src='/6.png'><img src='/7.png'>"
        "<img src='/8.png'><img src='/9.png'><img src='/10.png'><img src='/11.png'>"
        "<img src='/12.png'><img src='/13.png'><img src='/14.png'><img src='/15.png'>"
        "<img src='/16.png'><img src='/17.png'>"
        "</body></html>";
    html_parse_error_t error = {0};
    html_document_t *doc = html_parse(html, &error);
    browser_url_t base = {0};
    browser_resource_set_t requested = {0};
    browser_resource_queue_t queue = {0};
    browser_app_t app = {0};
    bool ok = doc && doc->root &&
              browser_parse_url("https://example.com/", &base) &&
              browser_resource_set_init(&requested);
    size_t count = 0u;
    if (ok)
    {
        count = browser_collect_resource_urls(&app,
                                              doc->root,
                                              &base,
                                              &requested,
                                              BROWSER_RESOURCE_IMAGE,
                                              10u,
                                              &queue);
    }
    ok = ok && count == BROWSER_MAX_IMAGES &&
         queue.count == BROWSER_MAX_IMAGES &&
         browser_resource_set_count_kind(&requested, BROWSER_RESOURCE_IMAGE) ==
             BROWSER_MAX_IMAGES;

    resource_queue_destroy(&queue);
    browser_resource_set_destroy(&requested);
    browser_url_destroy(&base);
    html_document_destroy(doc);
    return ok;
}

int main(void)
{
    struct
    {
        const char *name;
        bool (*fn)(void);
    } tests[] = {
        { "resource-set-dedup-survives-growth", test_resource_set_dedup_survives_growth },
        { "arena-dom-rewrite-and-scan-dedup", test_arena_dom_rewrite_and_scan_dedup },
        { "resource-collection-enforces-kind-limit", test_resource_collection_enforces_kind_limit },
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
