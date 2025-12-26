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
#define BROWSER_UI_EVENT_QUEUE_CAP 64
#define BROWSER_MAX_LOAD_THREADS 32
#define BROWSER_UI_EVENTS_PER_TICK 8

typedef struct
{
    bool use_tls;
    uint16_t port;
    char *host;
    char *path;
} browser_url_t;

typedef enum
{
    BROWSER_UI_EVENT_DOC_READY = 0,
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
    union
    {
        struct
        {
            html_document_t *doc;
            char *final_url;
        } doc_ready;
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

typedef struct
{
    atk_user_window_t remote;
    atk_user_window_t debug_remote;
    atk_widget_t *window;
    atk_widget_t *menu_bookmarks_button;
    atk_widget_t *menu_debug_button;
    atk_widget_t *menu_bookmarks;
    atk_widget_t *menu_debug;
    atk_widget_t *menu_open;
    atk_widget_t *url_input;
    atk_widget_t *viewer;

    alix_mutex_t lock;
    alix_mutex_t decode_lock;
    uint64_t next_load_id;
    uint64_t active_load_id;

    alix_thread_t load_threads[BROWSER_MAX_LOAD_THREADS];
    size_t load_thread_count;

    char *cache_dir;
    bool cache_ready;
    bool cache_attempted;

    char *external_css;
    size_t external_css_len;
    size_t external_css_cap;

    browser_ui_event_t ui_events[BROWSER_UI_EVENT_QUEUE_CAP];
    size_t ui_event_head;
    size_t ui_event_count;

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
void browser_dom_set_attr(html_node_t *node, const char *name, const char *value);
void browser_collect_resource_urls(browser_app_t *app,
                                  html_node_t *root,
                                  const browser_url_t *base_url,
                                  char **css_urls,
                                  size_t *css_count_io,
                                  char **img_urls,
                                  size_t *img_count_io,
                                  char **script_urls,
                                  size_t *script_count_io);

/* http */
char *browser_fetch_http(browser_app_t *app,
                         const browser_url_t *url,
                         size_t *body_len_out,
                         browser_url_t *final_url_out);

/* loader/events */
void browser_ui_event_free_payload(browser_ui_event_t *ev);
bool browser_ui_event_enqueue(browser_app_t *app, const browser_ui_event_t *ev);
bool browser_ui_event_dequeue(browser_app_t *app, browser_ui_event_t *out);
bool browser_load_is_active(browser_app_t *app, uint64_t load_id);
void browser_track_load_thread(browser_app_t *app, alix_thread_t thread);
void browser_untrack_load_thread(browser_app_t *app, alix_thread_t thread);
void browser_app_css_reset(browser_app_t *app);
bool browser_app_css_append(browser_app_t *app, const char *data, size_t len);
bool browser_loader_start(browser_app_t *app, const char *url_text);
bool browser_script_event_init(browser_ui_event_t *ev,
                               uint64_t load_id,
                               const char *src,
                               char *script,
                               size_t len);

/* debug */
void browser_debug_logf(browser_app_t *app, const char *fmt, ...);
void browser_debug_log_reset_file(browser_app_t *app);
void browser_debug_open_window(browser_app_t *app);
void browser_debug_close_window(browser_app_t *app);
void browser_debug_clear(browser_app_t *app);
void browser_debug_service(browser_app_t *app);

/* ui */
bool browser_build_ui(browser_app_t *app);
bool browser_tick(void *context);
bool browser_on_mouse_event(const user_atk_event_t *event, void *context);
void browser_on_close_event(void *context);

#endif /* ATK_BROWSER_INTERNAL_H */
