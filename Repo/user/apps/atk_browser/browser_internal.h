#ifndef ATK_BROWSER_INTERNAL_H
#define ATK_BROWSER_INTERNAL_H

#include "atk_user.h"

#include "atk.h"
#include "atk_app.h"
#include "atk_internal.h"
#include "atk_window.h"
#include "atk/layout.h"
#include "atk/atk_font.h"
#include "atk/atk_html_view.h"
#include "atk/atk_menu.h"
#include "atk/atk_text_input.h"
#include "libc.h"
#include "serial.h"
#include "usyscall.h"
#include "video.h"
#include "video_surface.h"
#include "web/html.h"

#define BROWSER_WIDTH  1000
#define BROWSER_HEIGHT 720
#define BROWSER_MARGIN 14
#define BROWSER_GAP    10
#define BROWSER_MENU_HEIGHT 28
#define BROWSER_MAX_BYTES (2u * 1024u * 1024u)
#define BROWSER_MAX_REDIRECTS 8
#define BROWSER_DEBUG_LOG_MAX_BYTES (256u * 1024u)
#define BROWSER_DEBUG_WINDOW_WIDTH  860
#define BROWSER_DEBUG_WINDOW_HEIGHT 420
#define BROWSER_MAX_STYLESHEETS 8
#define BROWSER_MAX_IMAGES 16
#define BROWSER_MAX_SCRIPTS 16
#define BROWSER_MAX_INLINE_IMAGES 64
#define BROWSER_UI_EVENT_QUEUE_CAP 256
#define BROWSER_MAX_LOAD_THREADS 8
#define BROWSER_UI_EVENTS_PER_TICK 8
#define BROWSER_UI_EVENT_BUDGET_MS 4
#define BROWSER_UI_DEFER_RETRY_MS 16u
#define BROWSER_UI_DEFER_TIMEOUT_MS 60000u
#define BROWSER_UI_DEFER_MAX_ATTEMPTS (BROWSER_UI_DEFER_TIMEOUT_MS / BROWSER_UI_DEFER_RETRY_MS)
#define BROWSER_UI_DEFER_LOG_INTERVAL_MS 5000u
#define BROWSER_CSS_APPLY_DEBOUNCE_MS 64
#define BROWSER_HISTORY_MAX 64
#define BROWSER_BACK_MENU_MAX_ITEMS 12
#define BROWSER_BACK_LONG_PRESS_MS 500u

typedef struct browser_app browser_app_t;

typedef struct
{
    browser_app_t *app;
    size_t index;
} browser_history_menu_ctx_t;

typedef struct
{
    bool use_tls;
    uint16_t port;
    char *host;
    char *path;
} browser_url_t;

typedef enum
{
    BROWSER_UI_EVENT_LOAD_BEGIN = 0,
    BROWSER_UI_EVENT_DOC_READY,
    BROWSER_UI_EVENT_NAV_UPDATE,
    BROWSER_UI_EVENT_ERROR,
    BROWSER_UI_EVENT_CSS_APPEND,
    BROWSER_UI_EVENT_SCRIPT_APPEND,
    BROWSER_UI_EVENT_IMAGE_PNG,
    BROWSER_UI_EVENT_IMAGE_GIF,
    BROWSER_UI_EVENT_IMAGE_RGBA,
    BROWSER_UI_EVENT_THREAD_DONE
} browser_ui_event_type_t;

typedef struct
{
    browser_ui_event_type_t type;
    uint64_t load_id;
    uint64_t defer_started_ms;
    uint64_t defer_retry_after_ms;
    uint64_t defer_last_log_ms;
    uint32_t defer_attempts;
    union
    {
        struct
        {
            html_document_t *doc;
            char *final_url;
            char *external_css;
            size_t external_css_len;
        } doc_ready;
        struct
        {
            char *final_url;
        } nav_update;
        struct
        {
            char *message;
        } error;
        struct
        {
            char *css;
            size_t len;
        } css_append;
        struct
        {
            char *src;
            char *script;
            size_t len;
        } script_append;
        struct
        {
            char *src;
            uint8_t *data;
            size_t len;
        } image_png;
        struct
        {
            char *src;
            uint8_t *data;
            size_t len;
        } image_gif;
        struct
        {
            char *src;
            video_color_t *pixels;
            int width;
            int height;
            int stride_bytes;
        } image_rgba;
        struct
        {
            alix_thread_t thread;
        } thread_done;
    } u;
} browser_ui_event_t;

typedef enum
{
    BROWSER_RESOURCE_CSS = 0,
    BROWSER_RESOURCE_SCRIPT,
    BROWSER_RESOURCE_IMAGE
} browser_resource_kind_t;

typedef struct
{
    char *url;
    uint32_t hash;
    browser_resource_kind_t kind;
} browser_resource_entry_t;

typedef struct
{
    browser_resource_entry_t *entries;
    size_t cap;
    size_t count;
} browser_resource_set_t;

typedef struct browser_resource_job
{
    uint64_t load_id;
    browser_resource_kind_t kind;
    char *url;
    struct browser_resource_job *next;
} browser_resource_job_t;

typedef struct
{
    browser_resource_job_t *head;
    browser_resource_job_t *tail;
    size_t count;
} browser_resource_queue_t;

typedef enum
{
    BROWSER_LOAD_JOB_URL = 0
} browser_load_job_kind_t;

typedef struct browser_load_request
{
    browser_load_job_kind_t kind;
    uint64_t load_id;
    char *url_text;
    struct browser_load_request *next;
} browser_load_request_t;

typedef struct
{
    browser_load_request_t *head;
    browser_load_request_t *tail;
    size_t count;
} browser_load_queue_t;

typedef enum
{
    BROWSER_RESOURCE_TRACK_NEW = 0,
    BROWSER_RESOURCE_TRACK_DUP,
    BROWSER_RESOURCE_TRACK_ERROR
} browser_resource_track_t;

typedef struct browser_app
{
    atk_user_window_t remote;
    atk_user_window_t debug_remote;
    atk_widget_t *window;
    atk_widget_t *menu_back_button;
    atk_widget_t *menu_bookmarks_button;
    atk_widget_t *menu_debug_button;
    atk_widget_t *menu_js_button;
    atk_widget_t *menu_cache_button;
    atk_widget_t *menu_back;
    atk_widget_t *menu_bookmarks;
    atk_widget_t *menu_debug;
    atk_widget_t *menu_open;
    atk_widget_t *url_input;
    atk_widget_t *viewer;
    bool js_enabled;
    bool js_thread_enabled;

    alix_mutex_t lock;
    alix_mutex_t debug_lock;
    alix_mutex_t decode_lock;
    alix_mutex_t resource_lock;
    uint64_t next_load_id;
    uint64_t active_load_id;
    bool first_render_pending;
    bool first_render_release_armed;
    uint64_t first_render_started_ms;
    browser_ui_event_t first_render_scripts[BROWSER_MAX_SCRIPTS];
    size_t first_render_script_count;

    alix_mutex_t load_lock;
    alix_thread_t html_thread;
    uint32_t html_thread_stop;
    browser_load_queue_t load_queue;

    alix_thread_t resource_thread;
    uint32_t resource_thread_stop;
    volatile uint64_t resource_defer_load_id;
    browser_resource_queue_t resource_queue;

    char *cache_dir;
    bool cache_ready;
    bool cache_attempted;

    char *external_css;
    size_t external_css_len;
    size_t external_css_cap;
    bool css_dirty;
    uint64_t css_dirty_since_ms;
    char *pending_fragment;
    char *history_urls[BROWSER_HISTORY_MAX];
    size_t history_count;
    size_t history_index;
    bool history_inhibit_push;
    browser_history_menu_ctx_t history_menu_ctx[BROWSER_HISTORY_MAX];
    uint64_t back_press_start_ms;
    bool back_press_active;

    browser_ui_event_t ui_events[BROWSER_UI_EVENT_QUEUE_CAP];
    size_t ui_event_head;
    size_t ui_event_count;
    browser_ui_event_t deferred_ui_event;
    bool deferred_ui_event_valid;
    bool ui_defer_chain_active;
    uint64_t ui_defer_chain_load_id;
    uint64_t ui_defer_chain_started_ms;
    uint32_t ui_defer_chain_attempts;

    atk_widget_t *debug_window;
    atk_widget_t *debug_text;
    char *debug_log;
    size_t debug_log_len;
    size_t debug_log_cap;
    size_t debug_log_flush_offset;
    bool debug_log_resync;
    bool debug_open_requested;
    bool debug_clear_requested;
} browser_app_t;

/* common */
char *browser_strdup(const char *src);
char *browser_strdup_len(const char *src, size_t len);
bool browser_write_all(int fd, const uint8_t *data, size_t len);
bool browser_buf_append(char **buf, size_t *len, size_t *cap, const uint8_t *data, size_t data_len);
bool browser_has_token_ci(const char *value, size_t value_len, const char *token);
bool browser_main_document_error(int status,
                                 const char *body,
                                 char *message,
                                 size_t message_cap);

/* url */
bool browser_parse_url(const char *input, browser_url_t *out);
void browser_url_destroy(browser_url_t *url);
bool browser_url_clone(const browser_url_t *src, browser_url_t *dst);
char *browser_build_absolute_url(const browser_url_t *base, const char *location, size_t location_len);
char *browser_url_to_string(const browser_url_t *url);

/* dom */
const html_node_t *browser_dom_find_first_element(const html_node_t *root, const char *tag);
const char *browser_dom_first_text_child(const html_node_t *node);
size_t browser_dom_count_nodes(const html_node_t *root, size_t limit);
bool browser_is_png_bytes(const uint8_t *data, size_t len);
bool browser_is_gif_bytes(const uint8_t *data, size_t len);
bool browser_is_svg_bytes(const uint8_t *data, size_t len);
bool browser_dom_set_attr(html_node_t *node, const char *name, const char *value);
bool browser_dom_set_tag_name(html_node_t *node, const char *name);
size_t browser_collect_resource_urls(browser_app_t *app,
                                     html_node_t *root,
                                     const browser_url_t *base_url,
                                     browser_resource_set_t *requested,
                                     browser_resource_kind_t kind,
                                     uint64_t load_id,
                                     browser_resource_queue_t *queue);

/* http */
char *browser_fetch_http(browser_app_t *app,
                         const browser_url_t *url,
                         size_t *body_len_out,
                         browser_url_t *final_url_out);
char *browser_fetch_http_with_status(browser_app_t *app,
                                     const browser_url_t *url,
                                     size_t *body_len_out,
                                     browser_url_t *final_url_out,
                                     int *status_out);
bool browser_cache_clear(browser_app_t *app);

/* loader/events */
void browser_ui_event_free_payload(browser_ui_event_t *ev);
bool browser_ui_event_move(browser_ui_event_t *dst, browser_ui_event_t *src);
bool browser_ui_event_defer(browser_app_t *app, browser_ui_event_t *ev, uint64_t now_ms);
bool browser_ui_event_take_deferred(browser_app_t *app, uint64_t now_ms, browser_ui_event_t *out);
bool browser_ui_event_defer_expired(const browser_app_t *app,
                                    const browser_ui_event_t *ev,
                                    uint64_t now_ms);
void browser_ui_event_defer_chain_reset(browser_app_t *app);
bool browser_first_render_script_buffer(browser_app_t *app, browser_ui_event_t *ev);
bool browser_first_render_script_take(browser_app_t *app, browser_ui_event_t *out);
void browser_first_render_scripts_clear(browser_app_t *app);
/* Always consumes *ev, freeing its payload if the queue cannot accept it. */
bool browser_ui_event_enqueue_owned(browser_app_t *app, browser_ui_event_t *ev);
/* Atomically enqueues every event or consumes and frees the complete batch. */
bool browser_ui_event_enqueue_batch_owned(browser_app_t *app,
                                          browser_ui_event_t *events,
                                          size_t count);
bool browser_ui_event_enqueue_batch_for_load_owned(browser_app_t *app,
                                                   uint64_t load_id,
                                                   browser_ui_event_t *events,
                                                   size_t count);
bool browser_ui_event_dequeue(browser_app_t *app, browser_ui_event_t *out);
bool browser_load_is_active(browser_app_t *app, uint64_t load_id);
bool browser_load_queue_push(browser_app_t *app, browser_load_job_kind_t kind, uint64_t load_id, char *url_text);
browser_load_request_t *browser_load_queue_pop(browser_app_t *app);
void browser_load_queue_clear(browser_app_t *app);
void browser_app_css_reset(browser_app_t *app);
bool browser_app_css_append(browser_app_t *app, const char *data, size_t len);
bool browser_loader_start(browser_app_t *app, const char *url_text);
bool browser_html_worker_start(browser_app_t *app);
void browser_html_worker_stop(browser_app_t *app);
bool browser_script_event_init(browser_ui_event_t *ev,
                               uint64_t load_id,
                               const char *src,
                               char *script,
                               size_t len);
/* On success, the event owns doc, final_url, and external_css. */
bool browser_document_event_init_owned(browser_ui_event_t *ev,
                                       uint64_t load_id,
                                       html_document_t *doc,
                                       char *final_url,
                                       char *external_css,
                                       size_t external_css_len);
bool browser_error_event_init(browser_ui_event_t *ev,
                              uint64_t load_id,
                              const char *message);
bool browser_resource_set_init(browser_resource_set_t *set);
void browser_resource_set_destroy(browser_resource_set_t *set);
browser_resource_track_t browser_resource_set_track(browser_resource_set_t *set,
                                                    browser_resource_kind_t kind,
                                                    const char *url);
size_t browser_resource_set_count_kind(const browser_resource_set_t *set,
                                       browser_resource_kind_t kind);
size_t browser_resource_kind_limit(browser_resource_kind_t kind);
bool browser_resource_queue_push(browser_app_t *app,
                                 browser_resource_kind_t kind,
                                 uint64_t load_id,
                                 char *url);
browser_resource_job_t *browser_resource_queue_pop(browser_app_t *app);
void browser_resource_queue_clear(browser_app_t *app);
bool browser_resource_queue_append(browser_app_t *app, browser_resource_queue_t *queue);
bool browser_resource_worker_start(browser_app_t *app);
void browser_resource_worker_stop(browser_app_t *app);

/* debug */
void browser_debug_logf(browser_app_t *app, const char *fmt, ...);
void browser_debug_logf_locked(browser_app_t *app, const char *fmt, ...);
void browser_debug_log_reset_file(browser_app_t *app);
void browser_debug_open_window(browser_app_t *app);
void browser_debug_close_window(browser_app_t *app);
void browser_debug_clear(browser_app_t *app);
void browser_debug_service(browser_app_t *app);

static inline void browser_lock_enter(browser_app_t *app, alix_mutex_t *mutex, const char *name)
{
    if (!mutex)
    {
        return;
    }
    bool log_enabled = (app && name && name[0] != '\0');
    if (log_enabled && mutex == &app->debug_lock)
    {
        log_enabled = false;
    }
    uint64_t start_ms = 0;
    uint64_t tid = 0;
    if (log_enabled)
    {
        start_ms = sys_time_millis();
        tid = alix_thread_self();
    }
    alix_mutex_lock(mutex);
    if (log_enabled)
    {
        uint64_t waited_ms = sys_time_millis() - start_ms;
        (void)tid;
        (void)waited_ms;
        // serial_printf("[lock] enter name=%s tid=%llu wait=%llu",
        //               name,
        //               (unsigned long long)tid,
        //               (unsigned long long)waited_ms);
        // browser_debug_logf(app,
        //                    "[lock] enter %s tid=%llu wait=%llu",
        //                    name,
        //                    (unsigned long long)tid,
        //                    (unsigned long long)waited_ms);
    }
}

static inline void browser_lock_exit(browser_app_t *app, alix_mutex_t *mutex, const char *name)
{
    if (!mutex)
    {
        return;
    }
    bool log_enabled = (app && name && name[0] != '\0');
    if (log_enabled && mutex == &app->debug_lock)
    {
        log_enabled = false;
    }
    if (log_enabled)
    {
        uint64_t tid = alix_thread_self();
        (void)tid;
        // serial_printf("[lock] exit name=%s tid=%llu",
        //               name,
        //               (unsigned long long)tid);
        // browser_debug_logf(app,
        //                    "[lock] exit %s tid=%llu",
        //                    name,
        //                    (unsigned long long)tid);
    }
    alix_mutex_unlock(mutex);
}

static inline bool browser_js_enabled(browser_app_t *app)
{
    if (!app)
    {
        return true;
    }
    bool enabled = true;
    browser_lock_enter(app, &app->lock, "app_lock");
    enabled = app->js_enabled;
    browser_lock_exit(app, &app->lock, "app_lock");
    return enabled;
}

/* ui */
bool browser_build_ui(browser_app_t *app);
bool browser_tick(void *context);
bool browser_on_mouse_event(const user_atk_event_t *event, void *context);
void browser_on_close_event(void *context);

#endif /* ATK_BROWSER_INTERNAL_H */
