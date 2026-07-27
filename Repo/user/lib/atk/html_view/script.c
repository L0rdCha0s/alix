#include "atk/html_view/html_view_internal.h"

#include "web/js/internal.h"
#include "web/js/runtime/runtime_internal.h"

#include "ctype.h"
#include "serial.h"
#include "stdio.h"
#include "usyscall.h"

#define HTML_VIEW_DOM_LOCK_LOG_MIN_MS 1u
#define HTML_VIEW_DOM_LOCK_LOG_RATE_MS 250u
#define HTML_VIEW_DOM_LOCK_HOLD_LOG_MIN_MS 10u
#define HTML_VIEW_DOM_LOCK_HOLD_LOG_RATE_MS 250u
#define HTML_VIEW_JS_LOG_THROTTLE_MS 250u

static bool html_view_js_log_throttle(uint64_t *last_ms, uint64_t interval_ms)
{
    uint64_t now_ms = sys_time_millis();
    if (now_ms - *last_ms < interval_ms)
    {
        return false;
    }
    *last_ms = now_ms;
    return true;
}

typedef struct
{
    atk_widget_t *view;
    size_t handle;
} html_view_js_dom_element_t;

enum
{
    HTML_VIEW_JS_TARGET_ELEMENT = 0,
    HTML_VIEW_JS_TARGET_DOCUMENT = 1,
    HTML_VIEW_JS_TARGET_WINDOW = 2
};

struct html_view_js_event
{
    uint32_t target;
    size_t handle;
    char *type;
    struct html_view_js_event *next;
};

struct html_view_js_timer
{
    uint64_t id;
    uint64_t due_ms;
    uint64_t interval_ms;
    bool repeating;
    bool is_eval;
    bool is_animation_frame;
    js_value_t callback;
    js_value_t *args;
    size_t argc;
    char *source;
    struct html_view_js_timer *next;
};

struct html_view_js_storage_entry
{
    char *key;
    char *value;
    struct html_view_js_storage_entry *next;
};

typedef struct
{
    atk_widget_t *view;
    size_t handle;
} html_view_js_dom_classlist_t;

typedef struct
{
    atk_widget_t *view;
    size_t handle;
} html_view_js_dom_dataset_t;

typedef struct
{
    atk_widget_t *view;
    size_t handle;
} html_view_js_dom_style_t;

typedef struct
{
    atk_widget_t *view;
    bool session;
} html_view_js_storage_t;

typedef struct
{
    atk_widget_t *view;
} html_view_js_location_t;

typedef struct
{
    atk_widget_t *view;
} html_view_js_history_t;

typedef struct
{
    atk_widget_t *view;
} html_view_js_console_t;

typedef struct
{
    atk_widget_t *view;
} html_view_js_response_t;

void html_view_js_start_thread(atk_widget_t *view, atk_html_view_priv_t *priv);
void html_view_js_dispatch_click(atk_widget_t *view, const html_node_t *node);
static bool html_view_js_should_stop(const atk_html_view_priv_t *priv);
static bool html_view_js_queue_source_locked(atk_html_view_priv_t *priv, const char *source, size_t len);
static bool html_view_js_queue_program_locked(atk_html_view_priv_t *priv, js_program_t *program);
static bool html_view_js_event_queue_locked(atk_html_view_priv_t *priv,
                                            uint32_t target,
                                            size_t handle,
                                            const char *type,
                                            size_t type_len);
static html_view_js_event_t *html_view_js_event_pop_locked(atk_html_view_priv_t *priv);
static void html_view_js_events_clear_locked(atk_html_view_priv_t *priv);
static bool html_view_js_timer_add_locked(atk_html_view_priv_t *priv,
                                          bool repeating,
                                          bool is_eval,
                                          bool is_animation_frame,
                                          uint64_t delay_ms,
                                          const js_value_t *callback,
                                          const js_value_t *args,
                                          size_t argc,
                                          const char *source,
                                          size_t source_len,
                                          uint64_t *id_out,
                                          char **error_message);
static bool html_view_js_timer_remove_locked(atk_html_view_priv_t *priv, uint64_t id);
static html_view_js_timer_t *html_view_js_timer_take_due_locked(atk_html_view_priv_t *priv,
                                                                uint64_t now_ms,
                                                                uint64_t *next_due_out);
static void html_view_js_timers_clear_locked(atk_html_view_priv_t *priv);
static bool html_view_js_element_get(js_runtime_t *rt,
                                     void *user_data,
                                     const char *name,
                                     js_value_t *out,
                                     char **error_message);
static bool html_view_js_node_set_attr(html_node_t *node, const char *name, const char *value);
static bool html_view_js_node_remove_attr(html_node_t *node, const char *name);
static bool html_view_js_element_remove_event_listener(js_runtime_t *rt,
                                                       size_t argc,
                                                       const js_value_t *argv,
                                                       void *user_data,
                                                       js_value_t *out,
                                                       char **error_message);
static bool html_view_js_element_dispatch_event(js_runtime_t *rt,
                                                size_t argc,
                                                const js_value_t *argv,
                                                void *user_data,
                                                js_value_t *out,
                                                char **error_message);
static bool html_view_js_element_get_attribute(js_runtime_t *rt,
                                               size_t argc,
                                               const js_value_t *argv,
                                               void *user_data,
                                               js_value_t *out,
                                               char **error_message);
static bool html_view_js_element_set_attribute(js_runtime_t *rt,
                                               size_t argc,
                                               const js_value_t *argv,
                                               void *user_data,
                                               js_value_t *out,
                                               char **error_message);
static bool html_view_js_element_remove_attribute(js_runtime_t *rt,
                                                  size_t argc,
                                                  const js_value_t *argv,
                                                  void *user_data,
                                                  js_value_t *out,
                                                  char **error_message);
static bool html_view_js_element_has_attribute(js_runtime_t *rt,
                                               size_t argc,
                                               const js_value_t *argv,
                                               void *user_data,
                                               js_value_t *out,
                                               char **error_message);
static bool html_view_js_element_append_child(js_runtime_t *rt,
                                              size_t argc,
                                              const js_value_t *argv,
                                              void *user_data,
                                              js_value_t *out,
                                              char **error_message);
static bool html_view_js_element_remove_child(js_runtime_t *rt,
                                              size_t argc,
                                              const js_value_t *argv,
                                              void *user_data,
                                              js_value_t *out,
                                              char **error_message);
static bool html_view_js_element_insert_before(js_runtime_t *rt,
                                               size_t argc,
                                               const js_value_t *argv,
                                               void *user_data,
                                               js_value_t *out,
                                               char **error_message);
static bool html_view_js_element_replace_child(js_runtime_t *rt,
                                               size_t argc,
                                               const js_value_t *argv,
                                               void *user_data,
                                               js_value_t *out,
                                               char **error_message);
static bool html_view_js_element_query_selector(js_runtime_t *rt,
                                                size_t argc,
                                                const js_value_t *argv,
                                                void *user_data,
                                                js_value_t *out,
                                                char **error_message);
static bool html_view_js_element_query_selector_all(js_runtime_t *rt,
                                                    size_t argc,
                                                    const js_value_t *argv,
                                                    void *user_data,
                                                    js_value_t *out,
                                                    char **error_message);
static bool html_view_js_element_get_elements_by_tag(js_runtime_t *rt,
                                                     size_t argc,
                                                     const js_value_t *argv,
                                                     void *user_data,
                                                     js_value_t *out,
                                                     char **error_message);
static bool html_view_js_element_get_elements_by_class(js_runtime_t *rt,
                                                       size_t argc,
                                                       const js_value_t *argv,
                                                       void *user_data,
                                                       js_value_t *out,
                                                       char **error_message);
static bool html_view_js_element_matches(js_runtime_t *rt,
                                         size_t argc,
                                         const js_value_t *argv,
                                         void *user_data,
                                         js_value_t *out,
                                         char **error_message);
static bool html_view_js_element_closest(js_runtime_t *rt,
                                         size_t argc,
                                         const js_value_t *argv,
                                         void *user_data,
                                         js_value_t *out,
                                         char **error_message);
static bool html_view_js_element_contains(js_runtime_t *rt,
                                          size_t argc,
                                          const js_value_t *argv,
                                          void *user_data,
                                          js_value_t *out,
                                          char **error_message);
static bool html_view_js_element_focus(js_runtime_t *rt,
                                       size_t argc,
                                       const js_value_t *argv,
                                       void *user_data,
                                       js_value_t *out,
                                       char **error_message);
static bool html_view_js_element_blur(js_runtime_t *rt,
                                      size_t argc,
                                      const js_value_t *argv,
                                      void *user_data,
                                      js_value_t *out,
                                      char **error_message);
static bool html_view_js_element_click(js_runtime_t *rt,
                                       size_t argc,
                                       const js_value_t *argv,
                                       void *user_data,
                                       js_value_t *out,
                                       char **error_message);
static bool html_view_js_element_scroll_into_view(js_runtime_t *rt,
                                                  size_t argc,
                                                  const js_value_t *argv,
                                                  void *user_data,
                                                  js_value_t *out,
                                                  char **error_message);
static bool html_view_js_classlist_get(js_runtime_t *rt,
                                       void *user_data,
                                       const char *name,
                                       js_value_t *out,
                                       char **error_message);
static void html_view_js_classlist_destroy(void *user_data);
static bool html_view_js_classlist_add(js_runtime_t *rt,
                                       size_t argc,
                                       const js_value_t *argv,
                                       void *user_data,
                                       js_value_t *out,
                                       char **error_message);
static bool html_view_js_classlist_remove(js_runtime_t *rt,
                                          size_t argc,
                                          const js_value_t *argv,
                                          void *user_data,
                                          js_value_t *out,
                                          char **error_message);
static bool html_view_js_classlist_toggle(js_runtime_t *rt,
                                          size_t argc,
                                          const js_value_t *argv,
                                          void *user_data,
                                          js_value_t *out,
                                          char **error_message);
static bool html_view_js_classlist_contains(js_runtime_t *rt,
                                            size_t argc,
                                            const js_value_t *argv,
                                            void *user_data,
                                            js_value_t *out,
                                            char **error_message);
static bool html_view_js_dataset_get(js_runtime_t *rt,
                                     void *user_data,
                                     const char *name,
                                     js_value_t *out,
                                     char **error_message);
static bool html_view_js_dataset_set(js_runtime_t *rt,
                                     void *user_data,
                                     const char *name,
                                     const js_value_t *value,
                                     char **error_message);
static void html_view_js_dataset_destroy(void *user_data);
static bool html_view_js_style_get(js_runtime_t *rt,
                                   void *user_data,
                                   const char *name,
                                   js_value_t *out,
                                   char **error_message);
static bool html_view_js_style_set(js_runtime_t *rt,
                                   void *user_data,
                                   const char *name,
                                   const js_value_t *value,
                                   char **error_message);
static void html_view_js_style_destroy(void *user_data);
static bool html_view_js_style_set_property(js_runtime_t *rt,
                                            size_t argc,
                                            const js_value_t *argv,
                                            void *user_data,
                                            js_value_t *out,
                                            char **error_message);
static bool html_view_js_style_get_property(js_runtime_t *rt,
                                            size_t argc,
                                            const js_value_t *argv,
                                            void *user_data,
                                            js_value_t *out,
                                            char **error_message);
static bool html_view_js_style_remove_property(js_runtime_t *rt,
                                               size_t argc,
                                               const js_value_t *argv,
                                               void *user_data,
                                               js_value_t *out,
                                               char **error_message);
static bool html_view_js_make_element_object(js_value_t *out,
                                             atk_widget_t *view,
                                             size_t handle,
                                             char **error_message);

static void html_view_dom_lock_record(atk_html_view_priv_t *priv, void *caller)
{
    if (!priv)
    {
        return;
    }
    __atomic_store_n(&priv->dom_lock_owner, alix_thread_self(), __ATOMIC_RELAXED);
    __atomic_store_n(&priv->dom_lock_hold_start_ms, sys_time_millis(), __ATOMIC_RELAXED);
    __atomic_store_n(&priv->dom_lock_hold_caller, (uintptr_t)caller, __ATOMIC_RELAXED);
}

static bool html_view_dom_try_lock_with_caller(atk_html_view_priv_t *priv, void *caller)
{
    if (!priv)
    {
        return false;
    }
    if (__sync_lock_test_and_set(&priv->dom_lock.state, 1u) == 0u)
    {
        html_view_dom_lock_record(priv, caller);
        return true;
    }
    return false;
}

static char *html_view_js_strdup_len(const char *src, size_t len)
{
    if (!src)
    {
        src = "";
        len = 0;
    }
    char *dst = (char *)malloc(len + 1);
    if (!dst)
    {
        return NULL;
    }
    if (len)
    {
        memcpy(dst, src, len);
    }
    dst[len] = '\0';
    return dst;
}

static char *html_view_js_strdup_lower(const char *src, size_t len)
{
    char *dst = html_view_js_strdup_len(src, len);
    if (!dst)
    {
        return NULL;
    }
    for (size_t i = 0; i < len; ++i)
    {
        dst[i] = (char)tolower((unsigned char)dst[i]);
    }
    return dst;
}

static html_view_js_storage_entry_t **html_view_js_storage_list(atk_html_view_priv_t *priv, bool session)
{
    if (!priv)
    {
        return NULL;
    }
    return session ? &priv->js_session_storage : &priv->js_local_storage;
}

static html_view_js_storage_entry_t *html_view_js_storage_find(html_view_js_storage_entry_t *head,
                                                               const char *key)
{
    if (!key)
    {
        return NULL;
    }
    for (html_view_js_storage_entry_t *cur = head; cur; cur = cur->next)
    {
        if (cur->key && strcmp(cur->key, key) == 0)
        {
            return cur;
        }
    }
    return NULL;
}

static size_t html_view_js_storage_length(html_view_js_storage_entry_t *head)
{
    size_t count = 0;
    for (html_view_js_storage_entry_t *cur = head; cur; cur = cur->next)
    {
        count++;
    }
    return count;
}

static bool html_view_js_storage_set(html_view_js_storage_entry_t **head,
                                     const char *key,
                                     const char *value)
{
    if (!head || !key)
    {
        return false;
    }
    html_view_js_storage_entry_t *entry = html_view_js_storage_find(*head, key);
    if (!entry)
    {
        entry = (html_view_js_storage_entry_t *)calloc(1, sizeof(*entry));
        if (!entry)
        {
            return false;
        }
        entry->key = html_view_js_strdup_len(key, strlen(key));
        if (!entry->key)
        {
            free(entry);
            return false;
        }
        entry->next = *head;
        *head = entry;
    }
    char *copy = html_view_js_strdup_len(value ? value : "", value ? strlen(value) : 0);
    if (!copy)
    {
        return false;
    }
    free(entry->value);
    entry->value = copy;
    return true;
}

static bool html_view_js_storage_remove(html_view_js_storage_entry_t **head, const char *key)
{
    if (!head || !key)
    {
        return false;
    }
    html_view_js_storage_entry_t *prev = NULL;
    for (html_view_js_storage_entry_t *cur = *head; cur; cur = cur->next)
    {
        if (cur->key && strcmp(cur->key, key) == 0)
        {
            if (prev)
            {
                prev->next = cur->next;
            }
            else
            {
                *head = cur->next;
            }
            free(cur->key);
            free(cur->value);
            free(cur);
            return true;
        }
        prev = cur;
    }
    return false;
}

static void html_view_js_storage_clear(html_view_js_storage_entry_t **head)
{
    if (!head)
    {
        return;
    }
    html_view_js_storage_entry_t *cur = *head;
    *head = NULL;
    while (cur)
    {
        html_view_js_storage_entry_t *next = cur->next;
        free(cur->key);
        free(cur->value);
        free(cur);
        cur = next;
    }
}

static bool html_view_js_event_queue_locked(atk_html_view_priv_t *priv,
                                            uint32_t target,
                                            size_t handle,
                                            const char *type,
                                            size_t type_len)
{
    if (!priv || !type || type_len == 0)
    {
        return false;
    }
    html_view_js_event_t *evt = (html_view_js_event_t *)calloc(1, sizeof(*evt));
    if (!evt)
    {
        return false;
    }
    evt->type = html_view_js_strdup_lower(type, type_len);
    if (!evt->type)
    {
        free(evt);
        return false;
    }
    evt->target = target;
    evt->handle = handle;
    evt->next = NULL;
    if (priv->js_event_tail)
    {
        priv->js_event_tail->next = evt;
    }
    else
    {
        priv->js_event_head = evt;
    }
    priv->js_event_tail = evt;
    ++priv->js_event_count;
    return true;
}

static html_view_js_event_t *html_view_js_event_pop_locked(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return NULL;
    }
    html_view_js_event_t *evt = priv->js_event_head;
    if (!evt)
    {
        return NULL;
    }
    priv->js_event_head = evt->next;
    if (!priv->js_event_head)
    {
        priv->js_event_tail = NULL;
    }
    evt->next = NULL;
    if (priv->js_event_count > 0u)
    {
        --priv->js_event_count;
    }
    return evt;
}

static void html_view_js_events_clear_locked(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    html_view_js_event_t *cur = priv->js_event_head;
    priv->js_event_head = NULL;
    priv->js_event_tail = NULL;
    priv->js_event_count = 0;
    while (cur)
    {
        html_view_js_event_t *next = cur->next;
        free(cur->type);
        free(cur);
        cur = next;
    }
}

static void html_view_js_timer_destroy(html_view_js_timer_t *timer)
{
    if (!timer)
    {
        return;
    }
    if (!timer->is_eval)
    {
        js_value_destroy(&timer->callback);
    }
    if (timer->args)
    {
        for (size_t i = 0; i < timer->argc; ++i)
        {
            js_value_destroy(&timer->args[i]);
        }
        free(timer->args);
    }
    free(timer->source);
    free(timer);
}

static void html_view_js_timers_clear_locked(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    html_view_js_timer_t *cur = priv->js_timers;
    priv->js_timers = NULL;
    priv->js_timer_active_id = 0;
    priv->js_timer_active_cancel = false;
    while (cur)
    {
        html_view_js_timer_t *next = cur->next;
        html_view_js_timer_destroy(cur);
        cur = next;
    }
}

static bool html_view_js_timer_add_locked(atk_html_view_priv_t *priv,
                                          bool repeating,
                                          bool is_eval,
                                          bool is_animation_frame,
                                          uint64_t delay_ms,
                                          const js_value_t *callback,
                                          const js_value_t *args,
                                          size_t argc,
                                          const char *source,
                                          size_t source_len,
                                          uint64_t *id_out,
                                          char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!priv)
    {
        return false;
    }
    if (!is_eval && (!callback || (callback->type != JS_VALUE_FUNCTION && callback->type != JS_VALUE_NATIVE_FN)))
    {
        if (error_message)
        {
            *error_message = js_strdup("invalid callback");
        }
        return false;
    }

    html_view_js_timer_t *timer = (html_view_js_timer_t *)calloc(1, sizeof(*timer));
    if (!timer)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }

    timer->id = ++priv->js_timer_seq;
    timer->due_ms = sys_time_millis() + delay_ms;
    timer->interval_ms = delay_ms;
    timer->repeating = repeating;
    timer->is_eval = is_eval;
    timer->is_animation_frame = is_animation_frame;
    timer->args = NULL;
    timer->argc = 0;
    timer->source = NULL;

    if (is_eval)
    {
        timer->source = html_view_js_strdup_len(source, source_len);
        if (!timer->source)
        {
            html_view_js_timer_destroy(timer);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
    }
    else
    {
        if (!js_value_copy(&timer->callback, callback))
        {
            html_view_js_timer_destroy(timer);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
    }

    if (argc && args)
    {
        timer->args = (js_value_t *)calloc(argc, sizeof(*timer->args));
        if (!timer->args)
        {
            html_view_js_timer_destroy(timer);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        timer->argc = argc;
        for (size_t i = 0; i < argc; ++i)
        {
            if (!js_value_copy(&timer->args[i], &args[i]))
            {
                html_view_js_timer_destroy(timer);
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
        }
    }

    timer->next = priv->js_timers;
    priv->js_timers = timer;
    if (id_out)
    {
        *id_out = timer->id;
    }
    return true;
}

static bool html_view_js_timer_remove_locked(atk_html_view_priv_t *priv, uint64_t id)
{
    if (!priv || id == 0)
    {
        return false;
    }
    html_view_js_timer_t *prev = NULL;
    for (html_view_js_timer_t *cur = priv->js_timers; cur; cur = cur->next)
    {
        if (cur->id == id)
        {
            if (prev)
            {
                prev->next = cur->next;
            }
            else
            {
                priv->js_timers = cur->next;
            }
            html_view_js_timer_destroy(cur);
            return true;
        }
        prev = cur;
    }
    if (priv->js_timer_active_id == id)
    {
        priv->js_timer_active_cancel = true;
        return true;
    }
    return false;
}

static html_view_js_timer_t *html_view_js_timer_take_due_locked(atk_html_view_priv_t *priv,
                                                                uint64_t now_ms,
                                                                uint64_t *next_due_out)
{
    if (next_due_out)
    {
        *next_due_out = 0;
    }
    if (!priv)
    {
        return NULL;
    }

    html_view_js_timer_t *prev = NULL;
    html_view_js_timer_t *cur = priv->js_timers;
    html_view_js_timer_t *chosen = NULL;
    html_view_js_timer_t *chosen_prev = NULL;
    uint64_t next_due = 0;

    while (cur)
    {
        if (cur->due_ms <= now_ms)
        {
            chosen = cur;
            chosen_prev = prev;
            break;
        }
        if (next_due == 0 || cur->due_ms < next_due)
        {
            next_due = cur->due_ms;
        }
        prev = cur;
        cur = cur->next;
    }

    if (next_due_out)
    {
        *next_due_out = next_due;
    }
    if (!chosen)
    {
        return NULL;
    }

    if (chosen_prev)
    {
        chosen_prev->next = chosen->next;
    }
    else
    {
        priv->js_timers = chosen->next;
    }
    chosen->next = NULL;
    return chosen;
}

void html_view_dom_lock(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    void *caller = __builtin_return_address(0);
    if (html_view_dom_try_lock_with_caller(priv, caller))
    {
        return;
    }

    alix_thread_t owner = __atomic_load_n(&priv->dom_lock_owner, __ATOMIC_RELAXED);
    uint64_t hold_start_ms = __atomic_load_n(&priv->dom_lock_hold_start_ms, __ATOMIC_RELAXED);
    uintptr_t hold_caller = __atomic_load_n(&priv->dom_lock_hold_caller, __ATOMIC_RELAXED);
    alix_thread_t self = alix_thread_self();
    if (owner != 0 && owner == self)
    {
        static uint64_t last_reentry_log_ms = 0;
        uint64_t now_ms = sys_time_millis();
        if (now_ms - last_reentry_log_ms >= HTML_VIEW_DOM_LOCK_LOG_RATE_MS)
        {
            last_reentry_log_ms = now_ms;
            uint64_t hold_ms = hold_start_ms ? (now_ms - hold_start_ms) : 0u;
            serial_printf("[html_view] dom_lock reentry tid=%llu caller=0x%016llX hold_ms=%llu hold_caller=0x%016llX",
                          (unsigned long long)self,
                          (unsigned long long)(uintptr_t)caller,
                          (unsigned long long)hold_ms,
                          (unsigned long long)hold_caller);
        }
    }
    uint64_t start_ms = sys_time_millis();
    alix_mutex_lock(&priv->dom_lock);
    html_view_dom_lock_record(priv, caller);
    uint64_t waited_ms = sys_time_millis() - start_ms;
    if (waited_ms >= HTML_VIEW_DOM_LOCK_LOG_MIN_MS)
    {
        static uint64_t last_log_ms = 0;
        uint64_t now_ms = sys_time_millis();
        uint64_t last = __atomic_load_n(&last_log_ms, __ATOMIC_RELAXED);
        if (now_ms - last >= HTML_VIEW_DOM_LOCK_LOG_RATE_MS)
        {
            __atomic_store_n(&last_log_ms, now_ms, __ATOMIC_RELAXED);
            uint64_t hold_ms = hold_start_ms ? (now_ms - hold_start_ms) : 0u;
            serial_printf("[html_view] dom_lock wait=%u ms tid=%llu caller=0x%016llX owner=%llu hold_ms=%llu hold_caller=0x%016llX",
                          (unsigned)waited_ms,
                          (unsigned long long)self,
                          (unsigned long long)(uintptr_t)caller,
                          (unsigned long long)owner,
                          (unsigned long long)hold_ms,
                          (unsigned long long)hold_caller);
        }
    }
}

bool html_view_dom_try_lock(atk_html_view_priv_t *priv)
{
    void *caller = __builtin_return_address(0);
    if (html_view_dom_try_lock_with_caller(priv, caller))
    {
        return true;
    }

    alix_thread_t owner = __atomic_load_n(&priv->dom_lock_owner, __ATOMIC_RELAXED);
    uint64_t hold_start_ms = __atomic_load_n(&priv->dom_lock_hold_start_ms, __ATOMIC_RELAXED);
    uintptr_t hold_caller = __atomic_load_n(&priv->dom_lock_hold_caller, __ATOMIC_RELAXED);
    alix_thread_t self = alix_thread_self();
    if (owner != 0 && owner == self)
    {
        static uint64_t last_reentry_log_ms = 0;
        uint64_t now_ms = sys_time_millis();
        if (now_ms - last_reentry_log_ms >= HTML_VIEW_DOM_LOCK_LOG_RATE_MS)
        {
            last_reentry_log_ms = now_ms;
            uint64_t hold_ms = hold_start_ms ? (now_ms - hold_start_ms) : 0u;
            serial_printf("[html_view] dom_lock try reentry tid=%llu caller=0x%016llX hold_ms=%llu hold_caller=0x%016llX",
                          (unsigned long long)self,
                          (unsigned long long)(uintptr_t)caller,
                          (unsigned long long)hold_ms,
                          (unsigned long long)hold_caller);
        }
        return false;
    }

    if (hold_start_ms)
    {
        static uint64_t last_try_log_ms = 0;
        uint64_t now_ms = sys_time_millis();
        uint64_t hold_ms = now_ms - hold_start_ms;
        if (hold_ms >= HTML_VIEW_DOM_LOCK_HOLD_LOG_MIN_MS &&
            now_ms - last_try_log_ms >= HTML_VIEW_DOM_LOCK_LOG_RATE_MS)
        {
            last_try_log_ms = now_ms;
            serial_printf("[html_view] dom_lock try busy tid=%llu caller=0x%016llX owner=%llu hold_ms=%llu hold_caller=0x%016llX",
                          (unsigned long long)self,
                          (unsigned long long)(uintptr_t)caller,
                          (unsigned long long)owner,
                          (unsigned long long)hold_ms,
                          (unsigned long long)hold_caller);
        }
    }
    return false;
}

void html_view_dom_unlock(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    uint64_t hold_start_ms = __atomic_load_n(&priv->dom_lock_hold_start_ms, __ATOMIC_RELAXED);
    alix_thread_t owner = __atomic_load_n(&priv->dom_lock_owner, __ATOMIC_RELAXED);
    uintptr_t hold_caller = __atomic_load_n(&priv->dom_lock_hold_caller, __ATOMIC_RELAXED);
    void *release_caller = __builtin_return_address(0);
    __atomic_store_n(&priv->dom_lock_owner, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&priv->dom_lock_hold_start_ms, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&priv->dom_lock_hold_caller, 0, __ATOMIC_RELAXED);
    alix_mutex_unlock(&priv->dom_lock);
    if (hold_start_ms)
    {
        uint64_t now_ms = sys_time_millis();
        uint64_t hold_ms = now_ms - hold_start_ms;
        if (hold_ms >= HTML_VIEW_DOM_LOCK_HOLD_LOG_MIN_MS)
        {
            static uint64_t last_hold_log_ms = 0;
            uint64_t last = __atomic_load_n(&last_hold_log_ms, __ATOMIC_RELAXED);
            if (now_ms - last >= HTML_VIEW_DOM_LOCK_HOLD_LOG_RATE_MS)
            {
                __atomic_store_n(&last_hold_log_ms, now_ms, __ATOMIC_RELAXED);
                serial_printf("[html_view] dom_lock held=%llu ms owner=%llu caller=0x%016llX release=0x%016llX",
                              (unsigned long long)hold_ms,
                              (unsigned long long)owner,
                              (unsigned long long)hold_caller,
                              (unsigned long long)(uintptr_t)release_caller);
            }
        }
    }
}

static void html_view_js_handles_reset(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    free(priv->js_handles);
    priv->js_handles = NULL;
    priv->js_handle_count = 0;
    priv->js_handle_cap = 0;
}

static void html_view_js_listeners_clear(atk_html_view_priv_t *priv, js_runtime_t *rt)
{
    (void)rt;
    if (!priv)
    {
        return;
    }
    html_view_js_listener_t *cur = priv->js_listeners;
    priv->js_listeners = NULL;
    while (cur)
    {
        html_view_js_listener_t *next = cur->next;
        js_value_destroy(&cur->handler);
        free(cur->event_name);
        free(cur);
        cur = next;
    }
}

static size_t html_view_js_handle_for_node(atk_html_view_priv_t *priv, html_node_t *node)
{
    if (!priv || !node)
    {
        return 0;
    }
    for (size_t i = 0; i < priv->js_handle_count; ++i)
    {
        if (priv->js_handles[i] == node)
        {
            return i + 1;
        }
    }
    if (priv->js_handle_count == priv->js_handle_cap)
    {
        size_t new_cap = priv->js_handle_cap ? (priv->js_handle_cap * 2) : 64;
        html_node_t **new_handles = (html_node_t **)realloc(priv->js_handles, new_cap * sizeof(*new_handles));
        if (!new_handles)
        {
            return 0;
        }
        priv->js_handles = new_handles;
        priv->js_handle_cap = new_cap;
    }
    priv->js_handles[priv->js_handle_count++] = node;
    return priv->js_handle_count;
}

static html_node_t *html_view_js_node_for_handle(atk_html_view_priv_t *priv, size_t handle)
{
    if (!priv || handle == 0 || handle > priv->js_handle_count)
    {
        return NULL;
    }
    return priv->js_handles[handle - 1];
}

static bool html_view_js_handle_from_value(const js_value_t *value, size_t *handle_out)
{
    if (!handle_out || !value)
    {
        return false;
    }
    if (value->type == JS_VALUE_NUMBER)
    {
        double number = value->as.number;
        if (number < 1.0)
        {
            return false;
        }
        size_t handle = (size_t)number;
        if ((double)handle != number)
        {
            return false;
        }
        *handle_out = handle;
        return true;
    }
    if (value->type == JS_VALUE_OBJECT && value->as.object && value->as.object->get_fn == html_view_js_element_get)
    {
        html_view_js_dom_element_t *elem = (html_view_js_dom_element_t *)value->as.object->user_data;
        if (!elem || elem->handle == 0)
        {
            return false;
        }
        *handle_out = elem->handle;
        return true;
    }
    return false;
}

static bool html_view_js_dispatch_click_locked(atk_html_view_priv_t *priv, size_t handle)
{
    if (!priv || handle == 0)
    {
        return false;
    }
    return html_view_js_event_queue_locked(priv, HTML_VIEW_JS_TARGET_ELEMENT, handle, "click", 5);
}

void html_view_js_dispatch_click(atk_widget_t *view, const html_node_t *node)
{
    if (!view || !node)
    {
        return;
    }
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        return;
    }
    if (!priv->js_thread_enabled || !priv->js_enabled)
    {
        return;
    }

    bool queued = false;
    html_view_dom_lock(priv);
    if (priv->js_runtime_ready && priv->js_runtime && !html_view_js_should_stop(priv))
    {
        size_t handle = html_view_js_handle_for_node(priv, (html_node_t *)node);
        if (handle != 0)
        {
            queued = html_view_js_dispatch_click_locked(priv, handle);
        }
    }
    html_view_dom_unlock(priv);

    if (queued)
    {
        html_view_js_start_thread(view, priv);
    }
}

static bool html_view_js_should_stop(const atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return true;
    }
    return __atomic_load_n(&priv->js_stop, __ATOMIC_ACQUIRE) != 0;
}

static void html_view_js_mark_dirty(atk_html_view_priv_t *priv, uint32_t flags)
{
    if (!priv)
    {
        return;
    }
    __atomic_fetch_or(&priv->js_dirty, flags, __ATOMIC_RELEASE);
    __atomic_store_n(&priv->js_redraw_pending, 1u, __ATOMIC_RELEASE);
    if (flags != 0u)
    {
        html_view_render_request(priv);
    }
}

static uint32_t html_view_js_take_dirty(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return 0;
    }
    return __atomic_exchange_n(&priv->js_dirty, 0u, __ATOMIC_ACQ_REL);
}

static void html_view_js_scripts_clear_locked(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    html_view_js_script_t *cur = priv->js_script_head;
    priv->js_script_head = NULL;
    priv->js_script_tail = NULL;
    while (cur)
    {
        html_view_js_script_t *next = cur->next;
        free(cur->source);
        free(cur);
        cur = next;
    }
    priv->js_script_count = 0;
}

static void html_view_js_scripts_append_locked(atk_html_view_priv_t *priv, html_view_js_script_t *scripts)
{
    if (!priv || !scripts)
    {
        return;
    }
    if (priv->js_script_tail)
    {
        priv->js_script_tail->next = scripts;
    }
    else
    {
        priv->js_script_head = scripts;
    }
    html_view_js_script_t *tail = scripts;
    uint32_t count = 1u;
    while (tail->next)
    {
        tail = tail->next;
        ++count;
    }
    priv->js_script_tail = tail;
    priv->js_script_count += count;
}

static html_view_js_script_t *html_view_js_pop_script_locked(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return NULL;
    }
    html_view_js_script_t *script = priv->js_script_head;
    if (!script)
    {
        return NULL;
    }
    priv->js_script_head = script->next;
    if (!priv->js_script_head)
    {
        priv->js_script_tail = NULL;
    }
    script->next = NULL;
    if (priv->js_script_count > 0u)
    {
        --priv->js_script_count;
    }
    return script;
}

static bool html_view_js_queue_source_locked(atk_html_view_priv_t *priv, const char *source, size_t len)
{
    if (!priv || !source || len == 0)
    {
        return false;
    }
    html_view_js_script_t *script = (html_view_js_script_t *)calloc(1, sizeof(*script));
    if (!script)
    {
        return false;
    }
    script->source = html_view_js_strdup_len(source, len);
    if (!script->source)
    {
        free(script);
        return false;
    }
    script->len = len;
    script->program = NULL;
    script->next = NULL;
    if (priv->js_script_tail)
    {
        priv->js_script_tail->next = script;
    }
    else
    {
        priv->js_script_head = script;
    }
    priv->js_script_tail = script;
    ++priv->js_script_count;
    return true;
}

static bool html_view_js_queue_program_locked(atk_html_view_priv_t *priv, js_program_t *program)
{
    if (!priv || !program)
    {
        return false;
    }
    html_view_js_script_t *script = (html_view_js_script_t *)calloc(1, sizeof(*script));
    if (!script)
    {
        return false;
    }
    script->source = NULL;
    script->len = 0;
    script->program = program;
    script->next = NULL;
    if (priv->js_script_tail)
    {
        priv->js_script_tail->next = script;
    }
    else
    {
        priv->js_script_head = script;
    }
    priv->js_script_tail = script;
    ++priv->js_script_count;
    return true;
}

static html_view_js_script_t *html_view_js_collect_scripts(const html_node_t *node)
{
    if (!node)
    {
        return NULL;
    }

    const html_node_t **stack = NULL;
    size_t stack_cap = 0;
    size_t sp = 0;
    const html_node_t *cur = node->first_child;

    html_view_js_script_t *head = NULL;
    html_view_js_script_t *tail = NULL;

    while (cur)
    {
        bool descend = cur->first_child != NULL;
        if (cur->type == HTML_NODE_ELEMENT && cur->name && strcmp(cur->name, "script") == 0)
        {
            char *text = NULL;
            size_t text_len = 0;
            size_t text_cap = 0;
            bool ok = true;

            for (const html_node_t *txt = cur->first_child; txt; txt = txt->next_sibling)
            {
                if (txt->type == HTML_NODE_TEXT && txt->text)
                {
                    if (!html_view_buf_append(&text, &text_len, &text_cap, txt->text, strlen(txt->text)) ||
                        !html_view_buf_append(&text, &text_len, &text_cap, "\n", 1))
                    {
                        ok = false;
                        break;
                    }
                }
            }

            if (ok && text && text_len > 0)
            {
                html_view_js_script_t *entry = (html_view_js_script_t *)calloc(1, sizeof(*entry));
                if (entry)
                {
                    entry->source = text;
                    entry->len = text_len;
                    if (tail)
                    {
                        tail->next = entry;
                    }
                    else
                    {
                        head = entry;
                    }
                    tail = entry;
                }
                else
                {
                    free(text);
                }
            }
            else
            {
                free(text);
            }

            descend = false;
        }

        if (descend)
        {
            if (cur->next_sibling)
            {
                if (sp == stack_cap)
                {
                    size_t new_cap = stack_cap ? (stack_cap * 2) : 64;
                    const html_node_t **new_stack = (const html_node_t **)realloc(stack, new_cap * sizeof(*new_stack));
                    if (!new_stack)
                    {
                        break;
                    }
                    stack = new_stack;
                    stack_cap = new_cap;
                }
                stack[sp++] = cur->next_sibling;
            }
            cur = cur->first_child;
            continue;
        }

        if (cur->next_sibling)
        {
            cur = cur->next_sibling;
            continue;
        }
        if (sp > 0)
        {
            cur = stack[--sp];
            continue;
        }
        break;
    }

    free(stack);
    return head;
}

static bool html_view_js_node_name_is(const html_node_t *node, const char *tag)
{
    return node && node->type == HTML_NODE_ELEMENT && node->name && tag && strcmp(node->name, tag) == 0;
}

static bool html_view_js_node_is_style(const html_node_t *node)
{
    return html_view_js_node_name_is(node, "style");
}

static bool html_view_js_node_affects_controls(const html_node_t *node)
{
    for (const html_node_t *cur = node; cur; cur = cur->parent)
    {
        if (cur->type != HTML_NODE_ELEMENT || !cur->name)
        {
            continue;
        }
        if (strcmp(cur->name, "input") == 0 ||
            strcmp(cur->name, "textarea") == 0 ||
            strcmp(cur->name, "button") == 0)
        {
            return true;
        }
    }
    return false;
}

static bool html_view_js_attr_has_token(const char *value, const char *token)
{
    if (!value || !token || token[0] == '\0')
    {
        return false;
    }
    size_t token_len = strlen(token);
    if (token_len == 0)
    {
        return false;
    }
    const char *p = value;
    while (*p)
    {
        while (*p && isspace((unsigned char)*p))
        {
            ++p;
        }
        if (!*p)
        {
            break;
        }
        const char *start = p;
        while (*p && !isspace((unsigned char)*p))
        {
            ++p;
        }
        size_t len = (size_t)(p - start);
        if (len == token_len && strncmp(start, token, token_len) == 0)
        {
            return true;
        }
    }
    return false;
}

static html_node_t *html_view_js_find_element_by_id(const html_node_t *root, const char *id)
{
    if (!root || !id || id[0] == '\0')
    {
        return NULL;
    }

    const html_node_t **stack = NULL;
    size_t stack_cap = 0;
    size_t sp = 0;
    const html_node_t *cur = root;

    while (cur)
    {
        if (cur->type == HTML_NODE_ELEMENT && cur->name)
        {
            const char *attr = html_attr_get(cur, "id");
            if (attr && strcmp(attr, id) == 0)
            {
                free(stack);
                return (html_node_t *)cur;
            }
        }

        if (cur->first_child)
        {
            if (cur->next_sibling)
            {
                if (sp == stack_cap)
                {
                    size_t new_cap = stack_cap ? (stack_cap * 2) : 64;
                    const html_node_t **new_stack = (const html_node_t **)realloc(stack, new_cap * sizeof(*new_stack));
                    if (!new_stack)
                    {
                        break;
                    }
                    stack = new_stack;
                    stack_cap = new_cap;
                }
                stack[sp++] = cur->next_sibling;
            }
            cur = cur->first_child;
            continue;
        }

        if (cur->next_sibling)
        {
            cur = cur->next_sibling;
            continue;
        }
        if (sp > 0)
        {
            cur = stack[--sp];
            continue;
        }
        break;
    }

    free(stack);
    return NULL;
}

static html_node_t *html_view_js_create_node(html_node_type_t type)
{
    html_node_t *node = (html_node_t *)calloc(1, sizeof(*node));
    if (!node)
    {
        return NULL;
    }
    node->type = type;
    return node;
}

static void html_view_js_append_child(html_node_t *parent, html_node_t *child)
{
    if (!parent || !child)
    {
        return;
    }
    child->parent = parent;
    child->prev_sibling = parent->last_child;
    child->next_sibling = NULL;
    if (parent->last_child)
    {
        parent->last_child->next_sibling = child;
    }
    else
    {
        parent->first_child = child;
    }
    parent->last_child = child;
}

static bool html_view_js_node_set_text(html_node_t *node, const char *text, size_t len)
{
    if (!node)
    {
        return false;
    }

    char *copy = html_view_js_strdup_len(text, len);
    if (!copy)
    {
        return false;
    }

    if (node->type == HTML_NODE_TEXT)
    {
        free(node->text);
        node->text = copy;
        return true;
    }

    html_node_t *target = NULL;
    for (html_node_t *child = node->first_child; child; child = child->next_sibling)
    {
        if (child->type == HTML_NODE_TEXT)
        {
            target = child;
            break;
        }
    }
    if (!target)
    {
        target = html_view_js_create_node(HTML_NODE_TEXT);
        if (!target)
        {
            free(copy);
            return false;
        }
        html_view_js_append_child(node, target);
    }

    free(target->text);
    target->text = copy;
    return true;
}

static bool html_view_js_node_set_attr(html_node_t *node, const char *name, const char *value)
{
    if (!node || node->type != HTML_NODE_ELEMENT || !name || name[0] == '\0' || !value)
    {
        return false;
    }

    for (html_attr_t *attr = node->attrs; attr; attr = attr->next)
    {
        if (!attr->name)
        {
            continue;
        }
        if (strcasecmp(attr->name, name) != 0)
        {
            continue;
        }
        char *copy = html_view_strdup(value);
        if (!copy)
        {
            return false;
        }
        free(attr->value);
        attr->value = copy;
        return true;
    }

    html_attr_t *attr = (html_attr_t *)calloc(1, sizeof(*attr));
    if (!attr)
    {
        return false;
    }
    attr->name = html_view_strdup(name);
    attr->value = html_view_strdup(value);
    if (!attr->name || !attr->value)
    {
        free(attr->name);
        free(attr->value);
        free(attr);
        return false;
    }
    attr->next = node->attrs;
    node->attrs = attr;
    return true;
}

static bool html_view_js_node_remove_attr(html_node_t *node, const char *name)
{
    if (!node || node->type != HTML_NODE_ELEMENT || !name || name[0] == '\0')
    {
        return false;
    }

    html_attr_t *prev = NULL;
    for (html_attr_t *attr = node->attrs; attr; attr = attr->next)
    {
        if (!attr->name)
        {
            prev = attr;
            continue;
        }
        if (strcasecmp(attr->name, name) == 0)
        {
            if (node->attr_cache == attr)
            {
                node->attr_cache = NULL;
            }
            if (prev)
            {
                prev->next = attr->next;
            }
            else
            {
                node->attrs = attr->next;
            }
            free(attr->name);
            free(attr->value);
            free(attr);
            return true;
        }
        prev = attr;
    }
    return false;
}

static void html_view_js_note_dom_change(atk_html_view_priv_t *priv, bool styles_dirty, bool controls_dirty)
{
    uint32_t flags = HTML_VIEW_JS_DIRTY_RENDER;
    if (styles_dirty)
    {
        flags |= HTML_VIEW_JS_DIRTY_STYLES;
    }
    if (controls_dirty)
    {
        flags |= HTML_VIEW_JS_DIRTY_CONTROLS;
    }
    html_view_dom_bloom_mark_dirty(priv);
    html_view_js_mark_dirty(priv, flags);
}

static bool html_view_js_out_string(js_value_t *out,
                                    const char *text,
                                    size_t len,
                                    char **error_message)
{
    if (!out)
    {
        return false;
    }
    if (!js_value_make_string(out, text, len))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    return true;
}

static char *html_view_js_number_to_string(double value, size_t *out_len);

static bool html_view_js_value_to_string(const js_value_t *value, char **out, size_t *len)
{
    if (!out || !len)
    {
        return false;
    }
    *out = NULL;
    *len = 0;

    if (!value)
    {
        *out = html_view_js_strdup_len("undefined", 9);
        *len = *out ? 9 : 0;
        return *out != NULL;
    }

    if (value->type == JS_VALUE_STRING)
    {
        const char *text = value->as.string.data ? value->as.string.data : "";
        size_t text_len = value->as.string.len;
        *out = html_view_js_strdup_len(text, text_len);
        *len = *out ? text_len : 0;
        return *out != NULL;
    }

    if (value->type == JS_VALUE_NUMBER)
    {
        *out = html_view_js_number_to_string(value->as.number, len);
        return *out != NULL;
    }

    if (value->type == JS_VALUE_BOOL)
    {
        const char *text = value->as.boolean ? "true" : "false";
        *out = html_view_js_strdup_len(text, strlen(text));
        *len = *out ? strlen(text) : 0;
        return *out != NULL;
    }

    if (value->type == JS_VALUE_NULL)
    {
        *out = html_view_js_strdup_len("null", 4);
        *len = *out ? 4 : 0;
        return *out != NULL;
    }

    if (value->type == JS_VALUE_UNDEFINED)
    {
        *out = html_view_js_strdup_len("undefined", 9);
        *len = *out ? 9 : 0;
        return *out != NULL;
    }

    *out = html_view_js_strdup_len("[object]", 8);
    *len = *out ? 8 : 0;
    return *out != NULL;
}

static char *html_view_js_number_to_string(double value, size_t *out_len)
{
    if (out_len)
    {
        *out_len = 0;
    }

    if (value != value)
    {
        if (out_len)
        {
            *out_len = 3;
        }
        return html_view_js_strdup_len("NaN", 3);
    }

    if (value > 1e308)
    {
        if (out_len)
        {
            *out_len = 8;
        }
        return html_view_js_strdup_len("Infinity", 8);
    }
    if (value < -1e308)
    {
        if (out_len)
        {
            *out_len = 9;
        }
        return html_view_js_strdup_len("-Infinity", 9);
    }

    bool neg = value < 0.0;
    if (neg)
    {
        value = -value;
    }

    uint64_t int_part = (uint64_t)value;
    double frac = value - (double)int_part;

    const int max_frac = 6;
    double rounder = 0.5;
    for (int i = 0; i < max_frac; ++i)
    {
        rounder *= 0.1;
    }
    frac += rounder;
    if (frac >= 1.0)
    {
        uint64_t max_uint64 = ~(uint64_t)0;
        if (int_part < max_uint64)
        {
            int_part += 1;
        }
        frac -= 1.0;
    }

    char *int_digits = (char *)malloc(32);
    if (!int_digits)
    {
        return NULL;
    }
    size_t int_len = 0;
    do
    {
        int digit = (int)(int_part % 10u);
        int_digits[int_len++] = (char)('0' + digit);
        int_part /= 10u;
    } while (int_part > 0u && int_len < 32);

    char *frac_digits = NULL;
    size_t frac_len = 0;
    if (frac > 0.0)
    {
        frac_digits = (char *)malloc((size_t)max_frac);
        if (!frac_digits)
        {
            free(int_digits);
            return NULL;
        }
        double scaled = frac;
        for (int i = 0; i < max_frac; ++i)
        {
            scaled *= 10.0;
            int digit = (int)scaled;
            if (digit < 0) digit = 0;
            if (digit > 9) digit = 9;
            frac_digits[frac_len++] = (char)('0' + digit);
            scaled -= (double)digit;
        }
        while (frac_len > 0 && frac_digits[frac_len - 1] == '0')
        {
            frac_len--;
        }
    }

    size_t total_len = (neg ? 1u : 0u) + int_len + (frac_len ? (1u + frac_len) : 0u);
    char *out = (char *)malloc(total_len + 1);
    if (!out)
    {
        free(int_digits);
        free(frac_digits);
        return NULL;
    }
    size_t pos = 0;
    if (neg)
    {
        out[pos++] = '-';
    }
    for (size_t i = 0; i < int_len; ++i)
    {
        out[pos++] = int_digits[int_len - 1 - i];
    }
    if (frac_len)
    {
        out[pos++] = '.';
        memcpy(out + pos, frac_digits, frac_len);
        pos += frac_len;
    }
    out[pos] = '\0';

    if (out_len)
    {
        *out_len = pos;
    }
    free(int_digits);
    free(frac_digits);
    return out;
}

static void html_view_js_trim_range(const char **start, const char **end)
{
    if (!start || !end || !*start || !*end)
    {
        return;
    }
    while (*start < *end && isspace((unsigned char)**start))
    {
        (*start)++;
    }
    while (*end > *start && isspace((unsigned char)(*end)[-1]))
    {
        (*end)--;
    }
}

static void html_view_js_node_detach(html_node_t *node)
{
    if (!node || !node->parent)
    {
        return;
    }
    html_node_t *parent = node->parent;
    if (node->prev_sibling)
    {
        node->prev_sibling->next_sibling = node->next_sibling;
    }
    else
    {
        parent->first_child = node->next_sibling;
    }
    if (node->next_sibling)
    {
        node->next_sibling->prev_sibling = node->prev_sibling;
    }
    else
    {
        parent->last_child = node->prev_sibling;
    }
    node->parent = NULL;
    node->prev_sibling = NULL;
    node->next_sibling = NULL;
}

static void html_view_js_node_insert_before(html_node_t *parent, html_node_t *child, html_node_t *before)
{
    if (!parent || !child || parent->type != HTML_NODE_ELEMENT)
    {
        return;
    }
    if (!before)
    {
        html_view_js_append_child(parent, child);
        return;
    }
    html_view_js_node_detach(child);
    child->parent = parent;
    child->next_sibling = before;
    child->prev_sibling = before->prev_sibling;
    if (before->prev_sibling)
    {
        before->prev_sibling->next_sibling = child;
    }
    else
    {
        parent->first_child = child;
    }
    before->prev_sibling = child;
}

static bool html_view_js_node_contains(const html_node_t *node, const html_node_t *other)
{
    if (!node || !other)
    {
        return false;
    }
    for (const html_node_t *cur = other; cur; cur = cur->parent)
    {
        if (cur == node)
        {
            return true;
        }
    }
    return false;
}

static html_node_t *html_view_js_find_first_element_by_tag(const html_node_t *root, const char *tag)
{
    if (!root || !tag || tag[0] == '\0')
    {
        return NULL;
    }
    const html_node_t **stack = NULL;
    size_t stack_cap = 0;
    size_t sp = 0;
    const html_node_t *cur = (root->type == HTML_NODE_DOCUMENT) ? root->first_child : root;
    while (cur)
    {
        if (cur->type == HTML_NODE_ELEMENT && cur->name && strcasecmp(cur->name, tag) == 0)
        {
            free(stack);
            return (html_node_t *)cur;
        }
        if (cur->first_child)
        {
            if (cur->next_sibling)
            {
                if (sp == stack_cap)
                {
                    size_t new_cap = stack_cap ? (stack_cap * 2) : 64;
                    const html_node_t **new_stack = (const html_node_t **)realloc(stack, new_cap * sizeof(*new_stack));
                    if (!new_stack)
                    {
                        break;
                    }
                    stack = new_stack;
                    stack_cap = new_cap;
                }
                stack[sp++] = cur->next_sibling;
            }
            cur = cur->first_child;
            continue;
        }
        if (cur->next_sibling)
        {
            cur = cur->next_sibling;
            continue;
        }
        if (sp > 0)
        {
            cur = stack[--sp];
            continue;
        }
        break;
    }
    free(stack);
    return NULL;
}

static char *html_view_js_dataset_attr_name(const char *name, size_t len)
{
    if (!name || len == 0)
    {
        return NULL;
    }
    size_t cap = len * 2 + 6;
    char *out = (char *)malloc(cap);
    if (!out)
    {
        return NULL;
    }
    size_t pos = 0;
    memcpy(out, "data-", 5);
    pos = 5;
    for (size_t i = 0; i < len; ++i)
    {
        char c = name[i];
        if (c == '_')
        {
            out[pos++] = '-';
            continue;
        }
        if (c >= 'A' && c <= 'Z')
        {
            out[pos++] = '-';
            out[pos++] = (char)(c - 'A' + 'a');
            continue;
        }
        out[pos++] = (char)tolower((unsigned char)c);
    }
    out[pos] = '\0';
    return out;
}

static char *html_view_js_css_prop_from_js(const char *name, size_t len)
{
    if (!name || len == 0)
    {
        return NULL;
    }
    if (len == 8 && strncasecmp(name, "cssFloat", 8) == 0)
    {
        return html_view_js_strdup_len("float", 5);
    }
    size_t cap = len * 2 + 1;
    char *out = (char *)malloc(cap);
    if (!out)
    {
        return NULL;
    }
    size_t pos = 0;
    for (size_t i = 0; i < len; ++i)
    {
        char c = name[i];
        if (c == '_')
        {
            out[pos++] = '-';
            continue;
        }
        if (c >= 'A' && c <= 'Z')
        {
            out[pos++] = '-';
            out[pos++] = (char)(c - 'A' + 'a');
            continue;
        }
        out[pos++] = (char)tolower((unsigned char)c);
    }
    out[pos] = '\0';
    return out;
}

static char *html_view_js_style_get_property_value(const char *style, const char *prop, size_t *out_len)
{
    if (out_len)
    {
        *out_len = 0;
    }
    if (!style || !prop || prop[0] == '\0')
    {
        return html_view_js_strdup_len("", 0);
    }
    const char *p = style;
    while (*p)
    {
        const char *entry_start = p;
        const char *entry_end = strchr(entry_start, ';');
        if (!entry_end)
        {
            entry_end = entry_start + strlen(entry_start);
            p = entry_end;
        }
        else
        {
            p = entry_end + 1;
        }
        const char *sep = memchr(entry_start, ':', (size_t)(entry_end - entry_start));
        if (!sep)
        {
            continue;
        }
        const char *name_start = entry_start;
        const char *name_end = sep;
        html_view_js_trim_range(&name_start, &name_end);
        if (name_end <= name_start)
        {
            continue;
        }
        if (strncasecmp(name_start, prop, (size_t)(name_end - name_start)) != 0 ||
            strlen(prop) != (size_t)(name_end - name_start))
        {
            continue;
        }
        const char *value_start = sep + 1;
        const char *value_end = entry_end;
        html_view_js_trim_range(&value_start, &value_end);
        size_t len = (size_t)(value_end - value_start);
        if (out_len)
        {
            *out_len = len;
        }
        return html_view_js_strdup_len(value_start, len);
    }
    return html_view_js_strdup_len("", 0);
}

static bool html_view_js_style_set_property_value(html_node_t *node, const char *prop, const char *value)
{
    if (!node || node->type != HTML_NODE_ELEMENT || !prop || prop[0] == '\0')
    {
        return false;
    }
    const char *style = html_attr_get(node, "style");
    bool remove_prop = (!value || value[0] == '\0');
    bool found = false;
    char *out = NULL;
    size_t out_len = 0;
    size_t out_cap = 0;

    const char *p = style ? style : "";
    while (*p)
    {
        const char *entry_start = p;
        const char *entry_end = strchr(entry_start, ';');
        if (!entry_end)
        {
            entry_end = entry_start + strlen(entry_start);
            p = entry_end;
        }
        else
        {
            p = entry_end + 1;
        }
        const char *sep = memchr(entry_start, ':', (size_t)(entry_end - entry_start));
        if (!sep)
        {
            continue;
        }
        const char *name_start = entry_start;
        const char *name_end = sep;
        html_view_js_trim_range(&name_start, &name_end);
        if (name_end <= name_start)
        {
            continue;
        }
        size_t name_len = (size_t)(name_end - name_start);
        bool match = (name_len == strlen(prop)) && strncasecmp(name_start, prop, name_len) == 0;
        if (match)
        {
            found = true;
            if (remove_prop)
            {
                continue;
            }
        }
        if (!html_view_buf_append(&out, &out_len, &out_cap, name_start, name_len) ||
            !html_view_buf_append(&out, &out_len, &out_cap, ":", 1))
        {
            free(out);
            return false;
        }
        const char *value_start = sep + 1;
        const char *value_end = entry_end;
        html_view_js_trim_range(&value_start, &value_end);
        if (match)
        {
            value_start = value;
            value_end = value + strlen(value);
        }
        if (!html_view_buf_append(&out, &out_len, &out_cap, value_start, (size_t)(value_end - value_start)) ||
            !html_view_buf_append(&out, &out_len, &out_cap, ";", 1))
        {
            free(out);
            return false;
        }
    }

    if (!found && !remove_prop)
    {
        if (!html_view_buf_append(&out, &out_len, &out_cap, prop, strlen(prop)) ||
            !html_view_buf_append(&out, &out_len, &out_cap, ":", 1) ||
            !html_view_buf_append(&out, &out_len, &out_cap, value, strlen(value)) ||
            !html_view_buf_append(&out, &out_len, &out_cap, ";", 1))
        {
            free(out);
            return false;
        }
    }

    if (!out || out_len == 0)
    {
        free(out);
        return html_view_js_node_remove_attr(node, "style");
    }
    out[out_len] = '\0';
    bool ok = html_view_js_node_set_attr(node, "style", out);
    free(out);
    return ok;
}

static char *html_view_js_class_list_remove_token(const char *class_attr, const char *token, bool *removed)
{
    if (removed)
    {
        *removed = false;
    }
    if (!class_attr || !token || token[0] == '\0')
    {
        return html_view_js_strdup_len(class_attr ? class_attr : "", class_attr ? strlen(class_attr) : 0);
    }
    char *out = NULL;
    size_t out_len = 0;
    size_t out_cap = 0;
    const char *p = class_attr;
    while (*p)
    {
        while (*p && isspace((unsigned char)*p))
        {
            ++p;
        }
        if (!*p)
        {
            break;
        }
        const char *start = p;
        while (*p && !isspace((unsigned char)*p))
        {
            ++p;
        }
        size_t len = (size_t)(p - start);
        if (len == strlen(token) && strncmp(start, token, len) == 0)
        {
            if (removed)
            {
                *removed = true;
            }
            continue;
        }
        if (out_len > 0)
        {
            if (!html_view_buf_append(&out, &out_len, &out_cap, " ", 1))
            {
                free(out);
                return NULL;
            }
        }
        if (!html_view_buf_append(&out, &out_len, &out_cap, start, len))
        {
            free(out);
            return NULL;
        }
    }
    if (!out)
    {
        out = html_view_js_strdup_len("", 0);
    }
    return out;
}

static bool html_view_js_class_list_add_token(html_node_t *node, const char *token)
{
    if (!node || node->type != HTML_NODE_ELEMENT || !token || token[0] == '\0')
    {
        return false;
    }
    const char *class_attr = html_attr_get(node, "class");
    if (class_attr && html_view_js_attr_has_token(class_attr, token))
    {
        return true;
    }
    size_t token_len = strlen(token);
    size_t class_len = class_attr ? strlen(class_attr) : 0;
    size_t new_len = class_len + (class_len ? 1u : 0u) + token_len;
    char *buf = (char *)malloc(new_len + 1);
    if (!buf)
    {
        return false;
    }
    size_t pos = 0;
    if (class_attr && class_len)
    {
        memcpy(buf, class_attr, class_len);
        pos = class_len;
        buf[pos++] = ' ';
    }
    memcpy(buf + pos, token, token_len);
    pos += token_len;
    buf[pos] = '\0';
    bool ok = html_view_js_node_set_attr(node, "class", buf);
    free(buf);
    return ok;
}

static bool html_view_js_out_array(js_value_t *out, char **error_message)
{
    if (!out)
    {
        return false;
    }
    if (!js_value_make_array(out))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    return true;
}

static bool html_view_js_array_push_handle(js_value_t *array, size_t handle, char **error_message)
{
    if (!array)
    {
        return false;
    }
    js_value_t value = js_value_make_number((double)handle);
    if (!js_value_array_push(array, &value))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    return true;
}

static void html_view_js_dom_element_destroy(void *user_data)
{
    free(user_data);
}

static bool html_view_js_listener_add(atk_html_view_priv_t *priv,
                                      uint32_t target,
                                      size_t handle,
                                      const char *event_name,
                                      size_t event_len,
                                      const js_value_t *handler,
                                      char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!priv || !event_name || event_len == 0 || !handler)
    {
        return true;
    }
    html_view_js_listener_t *listener = (html_view_js_listener_t *)calloc(1, sizeof(*listener));
    if (!listener)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    listener->event_name = html_view_js_strdup_lower(event_name, event_len);
    if (!listener->event_name)
    {
        free(listener);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    if (!js_value_copy(&listener->handler, handler))
    {
        free(listener->event_name);
        free(listener);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    listener->handle = handle;
    listener->target = target;
    html_view_dom_lock(priv);
    listener->next = priv->js_listeners;
    priv->js_listeners = listener;
    html_view_dom_unlock(priv);
    return true;
}

static bool html_view_js_listener_remove(atk_html_view_priv_t *priv,
                                         uint32_t target,
                                         size_t handle,
                                         const char *event_name,
                                         size_t event_len,
                                         const js_value_t *handler)
{
    if (!priv || !event_name || event_len == 0 || !handler)
    {
        return false;
    }
    bool removed = false;
    html_view_dom_lock(priv);
    html_view_js_listener_t *prev = NULL;
    html_view_js_listener_t *cur = priv->js_listeners;
    while (cur)
    {
        html_view_js_listener_t *next = cur->next;
        if (cur->target == target &&
            cur->handle == handle &&
            cur->event_name &&
            strlen(cur->event_name) == event_len &&
            strncmp(cur->event_name, event_name, event_len) == 0 &&
            js_value_strict_equal(&cur->handler, handler))
        {
            if (prev)
            {
                prev->next = next;
            }
            else
            {
                priv->js_listeners = next;
            }
            js_value_destroy(&cur->handler);
            free(cur->event_name);
            free(cur);
            removed = true;
            cur = next;
            continue;
        }
        prev = cur;
        cur = next;
    }
    html_view_dom_unlock(priv);
    return removed;
}

static bool html_view_js_element_add_event_listener(js_runtime_t *rt,
                                                    size_t argc,
                                                    const js_value_t *argv,
                                                    void *user_data,
                                                    js_value_t *out,
                                                    char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined();
    if (!user_data || !argv || argc < 2)
    {
        return true;
    }
    html_view_js_dom_element_t *elem = (html_view_js_dom_element_t *)user_data;
    if (!elem->view)
    {
        return true;
    }
    if (argv[0].type != JS_VALUE_STRING)
    {
        return true;
    }
    if (argv[1].type != JS_VALUE_FUNCTION && argv[1].type != JS_VALUE_NATIVE_FN)
    {
        return true;
    }
    const char *event = argv[0].as.string.data ? argv[0].as.string.data : "";
    size_t event_len = argv[0].as.string.len;

    atk_html_view_priv_t *priv = html_view_priv_mut(elem->view);
    if (!priv)
    {
        return true;
    }

    return html_view_js_listener_add(priv,
                                     HTML_VIEW_JS_TARGET_ELEMENT,
                                     elem->handle,
                                     event,
                                     event_len,
                                     &argv[1],
                                     error_message);
}

static void html_view_js_classlist_destroy(void *user_data)
{
    free(user_data);
}

static size_t html_view_js_class_list_count(const char *class_attr)
{
    if (!class_attr || class_attr[0] == '\0')
    {
        return 0;
    }
    size_t count = 0;
    const char *p = class_attr;
    while (*p)
    {
        while (*p && isspace((unsigned char)*p))
        {
            ++p;
        }
        if (!*p)
        {
            break;
        }
        count++;
        while (*p && !isspace((unsigned char)*p))
        {
            ++p;
        }
    }
    return count;
}

static bool html_view_js_classlist_get(js_runtime_t *rt,
                                       void *user_data,
                                       const char *name,
                                       js_value_t *out,
                                       char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out || !user_data || !name)
    {
        return false;
    }
    html_view_js_dom_classlist_t *list = (html_view_js_dom_classlist_t *)user_data;
    if (!list->view)
    {
        *out = js_value_make_null();
        return true;
    }
    if (strcmp(name, "add") == 0)
    {
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_classlist_add;
        out->as.native.user_data = list;
        return true;
    }
    if (strcmp(name, "remove") == 0)
    {
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_classlist_remove;
        out->as.native.user_data = list;
        return true;
    }
    if (strcmp(name, "toggle") == 0)
    {
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_classlist_toggle;
        out->as.native.user_data = list;
        return true;
    }
    if (strcmp(name, "contains") == 0)
    {
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_classlist_contains;
        out->as.native.user_data = list;
        return true;
    }
    if (strcmp(name, "value") == 0 || strcmp(name, "toString") == 0)
    {
        atk_html_view_priv_t *priv = html_view_priv_mut(list->view);
        if (!priv)
        {
            *out = js_value_make_null();
            return true;
        }
        html_view_dom_lock(priv);
        html_node_t *node = html_view_js_node_for_handle(priv, list->handle);
        const char *class_attr = node ? html_attr_get(node, "class") : NULL;
        size_t len = class_attr ? strlen(class_attr) : 0;
        bool ok = html_view_js_out_string(out, class_attr ? class_attr : "", len, error_message);
        html_view_dom_unlock(priv);
        return ok;
    }
    if (strcmp(name, "length") == 0)
    {
        atk_html_view_priv_t *priv = html_view_priv_mut(list->view);
        if (!priv)
        {
            *out = js_value_make_number(0.0);
            return true;
        }
        html_view_dom_lock(priv);
        html_node_t *node = html_view_js_node_for_handle(priv, list->handle);
        const char *class_attr = node ? html_attr_get(node, "class") : NULL;
        size_t count = html_view_js_class_list_count(class_attr);
        html_view_dom_unlock(priv);
        *out = js_value_make_number((double)count);
        return true;
    }
    *out = js_value_make_undefined();
    return true;
}

static bool html_view_js_classlist_add(js_runtime_t *rt,
                                       size_t argc,
                                       const js_value_t *argv,
                                       void *user_data,
                                       js_value_t *out,
                                       char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined();
    if (!user_data || !argv || argc == 0)
    {
        return true;
    }
    html_view_js_dom_classlist_t *list = (html_view_js_dom_classlist_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(list->view);
    if (!priv)
    {
        return true;
    }
    bool ok = true;
    bool changed = false;
    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, list->handle);
    if (node && node->type == HTML_NODE_ELEMENT)
    {
        for (size_t i = 0; i < argc; ++i)
        {
            if (argv[i].type != JS_VALUE_STRING)
            {
                continue;
            }
            const char *token = argv[i].as.string.data ? argv[i].as.string.data : "";
            if (token[0] == '\0')
            {
                continue;
            }
            const char *class_attr = html_attr_get(node, "class");
            if (class_attr && html_view_js_attr_has_token(class_attr, token))
            {
                continue;
            }
            if (!html_view_js_class_list_add_token(node, token))
            {
                ok = false;
                break;
            }
            changed = true;
        }
        if (changed)
        {
            bool controls_dirty = html_view_js_node_affects_controls(node);
            html_view_js_note_dom_change(priv, true, controls_dirty);
        }
    }
    html_view_dom_unlock(priv);
    return ok;
}

static bool html_view_js_classlist_remove(js_runtime_t *rt,
                                          size_t argc,
                                          const js_value_t *argv,
                                          void *user_data,
                                          js_value_t *out,
                                          char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined();
    if (!user_data || !argv || argc == 0)
    {
        return true;
    }
    html_view_js_dom_classlist_t *list = (html_view_js_dom_classlist_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(list->view);
    if (!priv)
    {
        return true;
    }
    bool ok = true;
    bool changed = false;
    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, list->handle);
    if (node && node->type == HTML_NODE_ELEMENT)
    {
        const char *class_attr = html_attr_get(node, "class");
        char *current = class_attr ? html_view_js_strdup_len(class_attr, strlen(class_attr)) : html_view_js_strdup_len("", 0);
        if (!current)
        {
            html_view_dom_unlock(priv);
            return false;
        }
        for (size_t i = 0; i < argc; ++i)
        {
            if (argv[i].type != JS_VALUE_STRING)
            {
                continue;
            }
            const char *token = argv[i].as.string.data ? argv[i].as.string.data : "";
            if (token[0] == '\0')
            {
                continue;
            }
            bool removed = false;
            char *next = html_view_js_class_list_remove_token(current, token, &removed);
            free(current);
            current = next;
            if (!current)
            {
                ok = false;
                break;
            }
            if (removed)
            {
                changed = true;
            }
        }
        if (ok && changed)
        {
            if (current[0] == '\0')
            {
                ok = html_view_js_node_remove_attr(node, "class");
            }
            else
            {
                ok = html_view_js_node_set_attr(node, "class", current);
            }
            if (ok)
            {
                bool controls_dirty = html_view_js_node_affects_controls(node);
                html_view_js_note_dom_change(priv, true, controls_dirty);
            }
        }
        free(current);
    }
    html_view_dom_unlock(priv);
    return ok;
}

static bool html_view_js_classlist_toggle(js_runtime_t *rt,
                                          size_t argc,
                                          const js_value_t *argv,
                                          void *user_data,
                                          js_value_t *out,
                                          char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!user_data || !argv || argc == 0 || argv[0].type != JS_VALUE_STRING)
    {
        *out = js_value_make_bool(false);
        return true;
    }
    html_view_js_dom_classlist_t *list = (html_view_js_dom_classlist_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(list->view);
    if (!priv)
    {
        *out = js_value_make_bool(false);
        return true;
    }
    const char *token = argv[0].as.string.data ? argv[0].as.string.data : "";
    if (token[0] == '\0')
    {
        *out = js_value_make_bool(false);
        return true;
    }
    bool force = false;
    bool has_force = false;
    if (argc > 1 && argv[1].type == JS_VALUE_BOOL)
    {
        force = argv[1].as.boolean;
        has_force = true;
    }

    bool enabled = false;
    bool ok = true;
    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, list->handle);
    if (node && node->type == HTML_NODE_ELEMENT)
    {
        const char *class_attr = html_attr_get(node, "class");
        bool has_token = class_attr && html_view_js_attr_has_token(class_attr, token);
        if (has_force)
        {
            if (force && !has_token)
            {
                ok = html_view_js_class_list_add_token(node, token);
            }
            else if (!force && has_token)
            {
                char *next = html_view_js_class_list_remove_token(class_attr, token, NULL);
                if (next)
                {
                    if (next[0] == '\0')
                    {
                        ok = html_view_js_node_remove_attr(node, "class");
                    }
                    else
                    {
                        ok = html_view_js_node_set_attr(node, "class", next);
                    }
                    free(next);
                }
                else
                {
                    ok = false;
                }
            }
            enabled = force;
        }
        else
        {
            if (has_token)
            {
                char *next = html_view_js_class_list_remove_token(class_attr, token, NULL);
                if (next)
                {
                    if (next[0] == '\0')
                    {
                        ok = html_view_js_node_remove_attr(node, "class");
                    }
                    else
                    {
                        ok = html_view_js_node_set_attr(node, "class", next);
                    }
                    free(next);
                }
                else
                {
                    ok = false;
                }
                enabled = false;
            }
            else
            {
                ok = html_view_js_class_list_add_token(node, token);
                enabled = true;
            }
        }
        if (ok)
        {
            bool controls_dirty = html_view_js_node_affects_controls(node);
            html_view_js_note_dom_change(priv, true, controls_dirty);
        }
    }
    html_view_dom_unlock(priv);
    *out = js_value_make_bool(enabled);
    return ok;
}

static bool html_view_js_classlist_contains(js_runtime_t *rt,
                                            size_t argc,
                                            const js_value_t *argv,
                                            void *user_data,
                                            js_value_t *out,
                                            char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!user_data || !argv || argc == 0 || argv[0].type != JS_VALUE_STRING)
    {
        *out = js_value_make_bool(false);
        return true;
    }
    html_view_js_dom_classlist_t *list = (html_view_js_dom_classlist_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(list->view);
    if (!priv)
    {
        *out = js_value_make_bool(false);
        return true;
    }
    const char *token = argv[0].as.string.data ? argv[0].as.string.data : "";
    bool result = false;
    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, list->handle);
    if (node && node->type == HTML_NODE_ELEMENT)
    {
        const char *class_attr = html_attr_get(node, "class");
        result = class_attr && html_view_js_attr_has_token(class_attr, token);
    }
    html_view_dom_unlock(priv);
    *out = js_value_make_bool(result);
    return true;
}

static void html_view_js_dataset_destroy(void *user_data)
{
    free(user_data);
}

static bool html_view_js_dataset_get(js_runtime_t *rt,
                                     void *user_data,
                                     const char *name,
                                     js_value_t *out,
                                     char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out || !user_data || !name)
    {
        return false;
    }
    html_view_js_dom_dataset_t *dataset = (html_view_js_dom_dataset_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(dataset->view);
    if (!priv)
    {
        *out = js_value_make_null();
        return true;
    }
    char *attr = html_view_js_dataset_attr_name(name, strlen(name));
    if (!attr)
    {
        *out = js_value_make_undefined();
        return true;
    }
    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, dataset->handle);
    const char *value = node ? html_attr_get(node, attr) : NULL;
    size_t len = value ? strlen(value) : 0;
    bool ok = value ? html_view_js_out_string(out, value, len, error_message) : (*out = js_value_make_undefined(), true);
    html_view_dom_unlock(priv);
    free(attr);
    return ok;
}

static bool html_view_js_dataset_set(js_runtime_t *rt,
                                     void *user_data,
                                     const char *name,
                                     const js_value_t *value,
                                     char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!user_data || !name || !value)
    {
        return false;
    }
    html_view_js_dom_dataset_t *dataset = (html_view_js_dom_dataset_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(dataset->view);
    if (!priv)
    {
        return false;
    }
    char *attr = html_view_js_dataset_attr_name(name, strlen(name));
    if (!attr)
    {
        return false;
    }
    bool ok = false;
    bool styles_dirty = false;
    bool controls_dirty = false;
    if (value->type == JS_VALUE_NULL || value->type == JS_VALUE_UNDEFINED)
    {
        html_view_dom_lock(priv);
        html_node_t *node = html_view_js_node_for_handle(priv, dataset->handle);
        if (node)
        {
            ok = html_view_js_node_remove_attr(node, attr);
            if (ok)
            {
                controls_dirty = html_view_js_node_affects_controls(node);
                html_view_js_note_dom_change(priv, styles_dirty, controls_dirty);
            }
        }
        html_view_dom_unlock(priv);
        free(attr);
        return ok;
    }

    char *text = NULL;
    size_t text_len = 0;
    if (!html_view_js_value_to_string(value, &text, &text_len))
    {
        free(attr);
        return false;
    }
    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, dataset->handle);
    if (node)
    {
        ok = html_view_js_node_set_attr(node, attr, text ? text : "");
        if (ok)
        {
            controls_dirty = html_view_js_node_affects_controls(node);
            html_view_js_note_dom_change(priv, styles_dirty, controls_dirty);
        }
    }
    html_view_dom_unlock(priv);
    free(text);
    free(attr);
    return ok;
}

static void html_view_js_style_destroy(void *user_data)
{
    free(user_data);
}

static bool html_view_js_style_get(js_runtime_t *rt,
                                   void *user_data,
                                   const char *name,
                                   js_value_t *out,
                                   char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out || !user_data || !name)
    {
        return false;
    }
    html_view_js_dom_style_t *style = (html_view_js_dom_style_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(style->view);
    if (!priv)
    {
        *out = js_value_make_null();
        return true;
    }
    if (strcmp(name, "setProperty") == 0)
    {
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_style_set_property;
        out->as.native.user_data = style;
        return true;
    }
    if (strcmp(name, "getPropertyValue") == 0)
    {
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_style_get_property;
        out->as.native.user_data = style;
        return true;
    }
    if (strcmp(name, "removeProperty") == 0)
    {
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_style_remove_property;
        out->as.native.user_data = style;
        return true;
    }
    if (strcmp(name, "cssText") == 0)
    {
        html_view_dom_lock(priv);
        html_node_t *node = html_view_js_node_for_handle(priv, style->handle);
        const char *attr = node ? html_attr_get(node, "style") : NULL;
        size_t len = attr ? strlen(attr) : 0;
        bool ok = html_view_js_out_string(out, attr ? attr : "", len, error_message);
        html_view_dom_unlock(priv);
        return ok;
    }

    char *prop = html_view_js_css_prop_from_js(name, strlen(name));
    if (!prop)
    {
        *out = js_value_make_undefined();
        return true;
    }
    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, style->handle);
    const char *attr = node ? html_attr_get(node, "style") : NULL;
    size_t len = 0;
    char *value = html_view_js_style_get_property_value(attr, prop, &len);
    bool ok = html_view_js_out_string(out, value ? value : "", len, error_message);
    html_view_dom_unlock(priv);
    free(value);
    free(prop);
    return ok;
}

static bool html_view_js_style_set(js_runtime_t *rt,
                                   void *user_data,
                                   const char *name,
                                   const js_value_t *value,
                                   char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!user_data || !name || !value)
    {
        return false;
    }
    html_view_js_dom_style_t *style = (html_view_js_dom_style_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(style->view);
    if (!priv)
    {
        return false;
    }
    if (strcmp(name, "cssText") == 0)
    {
        char *text = NULL;
        size_t text_len = 0;
        if (!html_view_js_value_to_string(value, &text, &text_len))
        {
            return false;
        }
        html_view_dom_lock(priv);
        html_node_t *node = html_view_js_node_for_handle(priv, style->handle);
        if (node)
        {
            bool ok = html_view_js_node_set_attr(node, "style", text ? text : "");
            if (ok)
            {
                bool controls_dirty = html_view_js_node_affects_controls(node);
                html_view_js_note_dom_change(priv, true, controls_dirty);
            }
        }
        html_view_dom_unlock(priv);
        free(text);
        return true;
    }

    char *prop = html_view_js_css_prop_from_js(name, strlen(name));
    if (!prop)
    {
        return false;
    }
    char *text = NULL;
    size_t text_len = 0;
    if (!html_view_js_value_to_string(value, &text, &text_len))
    {
        free(prop);
        return false;
    }
    bool ok = false;
    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, style->handle);
    if (node)
    {
        ok = html_view_js_style_set_property_value(node, prop, text ? text : "");
        if (ok)
        {
            bool controls_dirty = html_view_js_node_affects_controls(node);
            html_view_js_note_dom_change(priv, true, controls_dirty);
        }
    }
    html_view_dom_unlock(priv);
    free(text);
    free(prop);
    return ok;
}

static bool html_view_js_style_set_property(js_runtime_t *rt,
                                            size_t argc,
                                            const js_value_t *argv,
                                            void *user_data,
                                            js_value_t *out,
                                            char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined();
    if (!user_data || argc < 2 || argv[0].type != JS_VALUE_STRING)
    {
        return true;
    }
    html_view_js_dom_style_t *style = (html_view_js_dom_style_t *)user_data;
    const char *prop_name = argv[0].as.string.data ? argv[0].as.string.data : "";
    char *prop = html_view_js_css_prop_from_js(prop_name, argv[0].as.string.len);
    if (!prop)
    {
        return true;
    }
    char *text = NULL;
    size_t text_len = 0;
    if (!html_view_js_value_to_string(&argv[1], &text, &text_len))
    {
        free(prop);
        return false;
    }
    atk_html_view_priv_t *priv = html_view_priv_mut(style->view);
    if (priv)
    {
        html_view_dom_lock(priv);
        html_node_t *node = html_view_js_node_for_handle(priv, style->handle);
        if (node)
        {
            bool ok = html_view_js_style_set_property_value(node, prop, text ? text : "");
            if (ok)
            {
                bool controls_dirty = html_view_js_node_affects_controls(node);
                html_view_js_note_dom_change(priv, true, controls_dirty);
            }
        }
        html_view_dom_unlock(priv);
    }
    free(text);
    free(prop);
    return true;
}

static bool html_view_js_style_get_property(js_runtime_t *rt,
                                            size_t argc,
                                            const js_value_t *argv,
                                            void *user_data,
                                            js_value_t *out,
                                            char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!user_data || argc < 1 || argv[0].type != JS_VALUE_STRING)
    {
        return html_view_js_out_string(out, "", 0, error_message);
    }
    html_view_js_dom_style_t *style = (html_view_js_dom_style_t *)user_data;
    const char *prop_name = argv[0].as.string.data ? argv[0].as.string.data : "";
    char *prop = html_view_js_css_prop_from_js(prop_name, argv[0].as.string.len);
    if (!prop)
    {
        return html_view_js_out_string(out, "", 0, error_message);
    }
    atk_html_view_priv_t *priv = html_view_priv_mut(style->view);
    if (!priv)
    {
        free(prop);
        return html_view_js_out_string(out, "", 0, error_message);
    }
    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, style->handle);
    const char *attr = node ? html_attr_get(node, "style") : NULL;
    size_t len = 0;
    char *value = html_view_js_style_get_property_value(attr, prop, &len);
    bool ok = html_view_js_out_string(out, value ? value : "", len, error_message);
    html_view_dom_unlock(priv);
    free(value);
    free(prop);
    return ok;
}

static bool html_view_js_style_remove_property(js_runtime_t *rt,
                                               size_t argc,
                                               const js_value_t *argv,
                                               void *user_data,
                                               js_value_t *out,
                                               char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined();
    if (!user_data || argc < 1 || argv[0].type != JS_VALUE_STRING)
    {
        return true;
    }
    html_view_js_dom_style_t *style = (html_view_js_dom_style_t *)user_data;
    const char *prop_name = argv[0].as.string.data ? argv[0].as.string.data : "";
    char *prop = html_view_js_css_prop_from_js(prop_name, argv[0].as.string.len);
    if (!prop)
    {
        return true;
    }
    atk_html_view_priv_t *priv = html_view_priv_mut(style->view);
    if (priv)
    {
        html_view_dom_lock(priv);
        html_node_t *node = html_view_js_node_for_handle(priv, style->handle);
        if (node)
        {
            bool ok = html_view_js_style_set_property_value(node, prop, "");
            if (ok)
            {
                bool controls_dirty = html_view_js_node_affects_controls(node);
                html_view_js_note_dom_change(priv, true, controls_dirty);
            }
        }
        html_view_dom_unlock(priv);
    }
    free(prop);
    return true;
}

static bool html_view_js_make_classlist_object(js_value_t *out,
                                               atk_widget_t *view,
                                               size_t handle,
                                               char **error_message)
{
    if (!out || !view || handle == 0)
    {
        return false;
    }
    html_view_js_dom_classlist_t *list = (html_view_js_dom_classlist_t *)calloc(1, sizeof(*list));
    if (!list)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    list->view = view;
    list->handle = handle;
    if (!js_value_make_host_object(out, html_view_js_classlist_get, NULL, html_view_js_classlist_destroy, list))
    {
        free(list);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    return true;
}

static bool html_view_js_make_dataset_object(js_value_t *out,
                                             atk_widget_t *view,
                                             size_t handle,
                                             char **error_message)
{
    if (!out || !view || handle == 0)
    {
        return false;
    }
    html_view_js_dom_dataset_t *dataset = (html_view_js_dom_dataset_t *)calloc(1, sizeof(*dataset));
    if (!dataset)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    dataset->view = view;
    dataset->handle = handle;
    if (!js_value_make_host_object(out, html_view_js_dataset_get, html_view_js_dataset_set, html_view_js_dataset_destroy, dataset))
    {
        free(dataset);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    return true;
}

static bool html_view_js_make_style_object(js_value_t *out,
                                           atk_widget_t *view,
                                           size_t handle,
                                           char **error_message)
{
    if (!out || !view || handle == 0)
    {
        return false;
    }
    html_view_js_dom_style_t *style = (html_view_js_dom_style_t *)calloc(1, sizeof(*style));
    if (!style)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    style->view = view;
    style->handle = handle;
    if (!js_value_make_host_object(out, html_view_js_style_get, html_view_js_style_set, html_view_js_style_destroy, style))
    {
        free(style);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    return true;
}

static bool html_view_js_element_get(js_runtime_t *rt,
                                     void *user_data,
                                     const char *name,
                                     js_value_t *out,
                                     char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out || !user_data || !name)
    {
        return false;
    }
    html_view_js_dom_element_t *elem = (html_view_js_dom_element_t *)user_data;
    if (!elem->view)
    {
        *out = js_value_make_null();
        return true;
    }

    atk_html_view_priv_t *priv = html_view_priv_mut(elem->view);
    if (!priv)
    {
        *out = js_value_make_null();
        return true;
    }

    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, elem->handle);
    if (!node)
    {
        html_view_dom_unlock(priv);
        *out = js_value_make_null();
        return true;
    }

    if (strcmp(name, "nodeType") == 0)
    {
        *out = js_value_make_number((double)node->type);
        html_view_dom_unlock(priv);
        return true;
    }
    if (strcmp(name, "nodeName") == 0 || strcmp(name, "tagName") == 0)
    {
        const char *tag = (node->type == HTML_NODE_ELEMENT && node->name) ? node->name : NULL;
        size_t len = tag ? strlen(tag) : 0;
        bool ok = tag ? html_view_js_out_string(out, tag, len, error_message) : (*out = js_value_make_null(), true);
        html_view_dom_unlock(priv);
        return ok;
    }
    if (strcmp(name, "id") == 0)
    {
        const char *value = html_attr_get(node, "id");
        size_t len = value ? strlen(value) : 0;
        bool ok = html_view_js_out_string(out, value ? value : "", len, error_message);
        html_view_dom_unlock(priv);
        return ok;
    }
    if (strcmp(name, "className") == 0)
    {
        const char *value = html_attr_get(node, "class");
        size_t len = value ? strlen(value) : 0;
        bool ok = html_view_js_out_string(out, value ? value : "", len, error_message);
        html_view_dom_unlock(priv);
        return ok;
    }
    if (strcmp(name, "classList") == 0)
    {
        html_view_dom_unlock(priv);
        return html_view_js_make_classlist_object(out, elem->view, elem->handle, error_message);
    }
    if (strcmp(name, "dataset") == 0)
    {
        html_view_dom_unlock(priv);
        return html_view_js_make_dataset_object(out, elem->view, elem->handle, error_message);
    }
    if (strcmp(name, "style") == 0)
    {
        html_view_dom_unlock(priv);
        return html_view_js_make_style_object(out, elem->view, elem->handle, error_message);
    }
    if (strcmp(name, "parentNode") == 0 || strcmp(name, "parentElement") == 0)
    {
        html_node_t *parent = node->parent;
        size_t handle = html_view_js_handle_for_node(priv, parent);
        html_view_dom_unlock(priv);
        if (!handle)
        {
            *out = js_value_make_null();
            return true;
        }
        return html_view_js_make_element_object(out, elem->view, handle, error_message);
    }
    if (strcmp(name, "firstChild") == 0 || strcmp(name, "lastChild") == 0 ||
        strcmp(name, "nextSibling") == 0 || strcmp(name, "previousSibling") == 0)
    {
        html_node_t *child = NULL;
        if (strcmp(name, "firstChild") == 0)
        {
            child = node->first_child;
        }
        else if (strcmp(name, "lastChild") == 0)
        {
            child = node->last_child;
        }
        else if (strcmp(name, "nextSibling") == 0)
        {
            child = node->next_sibling;
        }
        else
        {
            child = node->prev_sibling;
        }
        size_t handle = html_view_js_handle_for_node(priv, child);
        html_view_dom_unlock(priv);
        if (!handle)
        {
            *out = js_value_make_null();
            return true;
        }
        return html_view_js_make_element_object(out, elem->view, handle, error_message);
    }
    if (strcmp(name, "children") == 0 || strcmp(name, "childNodes") == 0)
    {
        bool elements_only = (strcmp(name, "children") == 0);
        bool ok = html_view_js_out_array(out, error_message);
        if (!ok)
        {
            html_view_dom_unlock(priv);
            return false;
        }
        for (html_node_t *child = node->first_child; child; child = child->next_sibling)
        {
            if (elements_only && child->type != HTML_NODE_ELEMENT)
            {
                continue;
            }
            size_t handle = html_view_js_handle_for_node(priv, child);
            if (!handle)
            {
                continue;
            }
            js_value_t elem_val;
            if (!html_view_js_make_element_object(&elem_val, elem->view, handle, error_message))
            {
                js_value_destroy(out);
                html_view_dom_unlock(priv);
                return false;
            }
            if (!js_value_array_push(out, &elem_val))
            {
                js_value_destroy(&elem_val);
                js_value_destroy(out);
                html_view_dom_unlock(priv);
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
            js_value_destroy(&elem_val);
        }
        html_view_dom_unlock(priv);
        return true;
    }
    if (strcmp(name, "value") == 0)
    {
        html_view_control_t *ctrl = html_view_control_find(priv, node);
        if (ctrl &&
            (ctrl->kind == HTML_VIEW_CONTROL_INPUT_TEXT ||
             ctrl->kind == HTML_VIEW_CONTROL_TEXTAREA) &&
            ctrl->widget)
        {
            const char *text = atk_text_input_text(ctrl->widget);
            size_t len = text ? strlen(text) : 0;
            bool ok = html_view_js_out_string(out, text ? text : "", len, error_message);
            html_view_dom_unlock(priv);
            return ok;
        }
        const char *value = html_attr_get(node, "value");
        size_t len = value ? strlen(value) : 0;
        bool ok = html_view_js_out_string(out, value ? value : "", len, error_message);
        html_view_dom_unlock(priv);
        return ok;
    }
    if (strcmp(name, "checked") == 0)
    {
        const char *value = html_attr_get(node, "checked");
        bool checked = value && value[0] != '\0';
        *out = js_value_make_bool(checked);
        html_view_dom_unlock(priv);
        return true;
    }
    if (strcmp(name, "textContent") == 0 || strcmp(name, "innerText") == 0 || strcmp(name, "innerHTML") == 0)
    {
        if (node->type == HTML_NODE_TEXT)
        {
            const char *text = node->text ? node->text : "";
            size_t len = strlen(text);
            bool ok = html_view_js_out_string(out, text, len, error_message);
            html_view_dom_unlock(priv);
            return ok;
        }

        char *text = NULL;
        size_t text_len = 0;
        size_t text_cap = 0;
        html_view_collect_text(node, &text, &text_len, &text_cap);
        bool ok = html_view_js_out_string(out, text ? text : "", text_len, error_message);
        free(text);
        html_view_dom_unlock(priv);
        return ok;
    }
    if (strcmp(name, "getAttribute") == 0)
    {
        html_view_dom_unlock(priv);
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_element_get_attribute;
        out->as.native.user_data = elem;
        return true;
    }
    if (strcmp(name, "setAttribute") == 0)
    {
        html_view_dom_unlock(priv);
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_element_set_attribute;
        out->as.native.user_data = elem;
        return true;
    }
    if (strcmp(name, "removeAttribute") == 0)
    {
        html_view_dom_unlock(priv);
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_element_remove_attribute;
        out->as.native.user_data = elem;
        return true;
    }
    if (strcmp(name, "hasAttribute") == 0)
    {
        html_view_dom_unlock(priv);
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_element_has_attribute;
        out->as.native.user_data = elem;
        return true;
    }
    if (strcmp(name, "appendChild") == 0)
    {
        html_view_dom_unlock(priv);
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_element_append_child;
        out->as.native.user_data = elem;
        return true;
    }
    if (strcmp(name, "removeChild") == 0)
    {
        html_view_dom_unlock(priv);
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_element_remove_child;
        out->as.native.user_data = elem;
        return true;
    }
    if (strcmp(name, "insertBefore") == 0)
    {
        html_view_dom_unlock(priv);
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_element_insert_before;
        out->as.native.user_data = elem;
        return true;
    }
    if (strcmp(name, "replaceChild") == 0)
    {
        html_view_dom_unlock(priv);
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_element_replace_child;
        out->as.native.user_data = elem;
        return true;
    }
    if (strcmp(name, "querySelector") == 0)
    {
        html_view_dom_unlock(priv);
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_element_query_selector;
        out->as.native.user_data = elem;
        return true;
    }
    if (strcmp(name, "querySelectorAll") == 0)
    {
        html_view_dom_unlock(priv);
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_element_query_selector_all;
        out->as.native.user_data = elem;
        return true;
    }
    if (strcmp(name, "getElementsByTagName") == 0)
    {
        html_view_dom_unlock(priv);
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_element_get_elements_by_tag;
        out->as.native.user_data = elem;
        return true;
    }
    if (strcmp(name, "getElementsByClassName") == 0)
    {
        html_view_dom_unlock(priv);
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_element_get_elements_by_class;
        out->as.native.user_data = elem;
        return true;
    }
    if (strcmp(name, "matches") == 0)
    {
        html_view_dom_unlock(priv);
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_element_matches;
        out->as.native.user_data = elem;
        return true;
    }
    if (strcmp(name, "closest") == 0)
    {
        html_view_dom_unlock(priv);
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_element_closest;
        out->as.native.user_data = elem;
        return true;
    }
    if (strcmp(name, "contains") == 0)
    {
        html_view_dom_unlock(priv);
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_element_contains;
        out->as.native.user_data = elem;
        return true;
    }
    if (strcmp(name, "focus") == 0)
    {
        html_view_dom_unlock(priv);
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_element_focus;
        out->as.native.user_data = elem;
        return true;
    }
    if (strcmp(name, "blur") == 0)
    {
        html_view_dom_unlock(priv);
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_element_blur;
        out->as.native.user_data = elem;
        return true;
    }
    if (strcmp(name, "click") == 0)
    {
        html_view_dom_unlock(priv);
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_element_click;
        out->as.native.user_data = elem;
        return true;
    }
    if (strcmp(name, "scrollIntoView") == 0)
    {
        html_view_dom_unlock(priv);
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_element_scroll_into_view;
        out->as.native.user_data = elem;
        return true;
    }
    if (strcmp(name, "addEventListener") == 0)
    {
        html_view_dom_unlock(priv);
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_element_add_event_listener;
        out->as.native.user_data = elem;
        return true;
    }
    if (strcmp(name, "removeEventListener") == 0)
    {
        html_view_dom_unlock(priv);
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_element_remove_event_listener;
        out->as.native.user_data = elem;
        return true;
    }
    if (strcmp(name, "dispatchEvent") == 0)
    {
        html_view_dom_unlock(priv);
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_element_dispatch_event;
        out->as.native.user_data = elem;
        return true;
    }

    if (node->type == HTML_NODE_ELEMENT)
    {
        const char *attr = html_attr_get(node, name);
        if (attr)
        {
            size_t len = strlen(attr);
            bool ok = html_view_js_out_string(out, attr, len, error_message);
            html_view_dom_unlock(priv);
            return ok;
        }
    }

    html_view_dom_unlock(priv);
    *out = js_value_make_undefined();
    return true;
}

static bool html_view_js_make_target_value(js_runtime_t *rt,
                                           atk_widget_t *view,
                                           atk_html_view_priv_t *priv,
                                           uint32_t target,
                                           size_t handle,
                                           js_value_t *out,
                                           char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out || !rt || !view || !priv)
    {
        return false;
    }
    if (target == HTML_VIEW_JS_TARGET_ELEMENT)
    {
        return html_view_js_make_element_object(out, view, handle, error_message);
    }
    if (target == HTML_VIEW_JS_TARGET_DOCUMENT)
    {
        return js_runtime_get_global(rt, "document", out);
    }
    if (target == HTML_VIEW_JS_TARGET_WINDOW)
    {
        js_value_t window_val;
        window_val.type = JS_VALUE_OBJECT;
        window_val.as.object = rt->global_object;
        js_object_retain(rt->global_object);
        *out = window_val;
        return true;
    }
    *out = js_value_make_null();
    return true;
}

static bool html_view_js_set_event_target(js_value_t *event_value, const js_value_t *target_value)
{
    if (!event_value || event_value->type != JS_VALUE_OBJECT || !event_value->as.object || !target_value)
    {
        return false;
    }
    (void)js_object_set_slot(event_value->as.object, "target", target_value);
    (void)js_object_set_slot(event_value->as.object, "currentTarget", target_value);
    return true;
}

static bool html_view_js_make_event_object(const char *type, js_value_t *out, char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out || !type)
    {
        return false;
    }
    if (!js_value_make_host_object(out, NULL, NULL, NULL, NULL))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    if (!out->as.object)
    {
        return true;
    }
    js_value_t type_val;
    if (!js_value_make_cstring(&type_val, type))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    (void)js_object_set_slot(out->as.object, "type", &type_val);
    js_value_destroy(&type_val);
    js_value_t bool_val = js_value_make_bool(false);
    (void)js_object_set_slot(out->as.object, "defaultPrevented", &bool_val);
    (void)js_object_set_slot(out->as.object, "bubbles", &bool_val);
    (void)js_object_set_slot(out->as.object, "cancelable", &bool_val);
    return true;
}

static bool html_view_js_event_type_from_value(js_runtime_t *rt,
                                               const js_value_t *value,
                                               char **type_out,
                                               size_t *len_out,
                                               char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (type_out)
    {
        *type_out = NULL;
    }
    if (len_out)
    {
        *len_out = 0;
    }
    if (!rt || !value || value->type != JS_VALUE_OBJECT || !value->as.object)
    {
        return false;
    }
    js_value_t type_val = js_value_make_undefined();
    char *err = NULL;
    bool ok = js_object_get_property(rt, value->as.object, "type", &type_val, &err);
    js_free(err);
    if (!ok || type_val.type != JS_VALUE_STRING)
    {
        js_value_destroy(&type_val);
        return false;
    }
    const char *raw = type_val.as.string.data ? type_val.as.string.data : "";
    size_t len = type_val.as.string.len;
    char *copy = html_view_js_strdup_lower(raw, len);
    js_value_destroy(&type_val);
    if (!copy)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    if (type_out)
    {
        *type_out = copy;
    }
    else
    {
        free(copy);
    }
    if (len_out)
    {
        *len_out = len;
    }
    return true;
}

static bool html_view_js_collect_handlers(atk_html_view_priv_t *priv,
                                          uint32_t target,
                                          size_t handle,
                                          const char *event_name,
                                          size_t event_len,
                                          js_value_t **handlers_out,
                                          size_t *count_out,
                                          char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (handlers_out)
    {
        *handlers_out = NULL;
    }
    if (count_out)
    {
        *count_out = 0;
    }
    if (!priv || !event_name || event_len == 0 || !handlers_out || !count_out)
    {
        return false;
    }
    js_value_t *handlers = NULL;
    size_t count = 0;
    size_t cap = 0;
    html_view_dom_lock(priv);
    for (html_view_js_listener_t *cur = priv->js_listeners; cur; cur = cur->next)
    {
        if (cur->target != target || cur->handle != handle || !cur->event_name)
        {
            continue;
        }
        if (strlen(cur->event_name) != event_len || strncmp(cur->event_name, event_name, event_len) != 0)
        {
            continue;
        }
        if (count == cap)
        {
            size_t new_cap = cap ? (cap * 2) : 4;
            js_value_t *next = (js_value_t *)realloc(handlers, new_cap * sizeof(*next));
            if (!next)
            {
                html_view_dom_unlock(priv);
                for (size_t i = 0; i < count; ++i)
                {
                    js_value_destroy(&handlers[i]);
                }
                free(handlers);
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
            handlers = next;
            cap = new_cap;
        }
        if (!js_value_copy(&handlers[count], &cur->handler))
        {
            html_view_dom_unlock(priv);
            for (size_t i = 0; i < count; ++i)
            {
                js_value_destroy(&handlers[i]);
            }
            free(handlers);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        count++;
    }
    html_view_dom_unlock(priv);
    *handlers_out = handlers;
    *count_out = count;
    return true;
}

static bool html_view_js_fire_event(js_runtime_t *rt,
                                    atk_widget_t *view,
                                    atk_html_view_priv_t *priv,
                                    uint32_t target,
                                    size_t handle,
                                    const char *event_name,
                                    size_t event_len,
                                    js_value_t *event_value,
                                    bool owns_event,
                                    char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!rt || !view || !priv || !event_name || event_len == 0)
    {
        return false;
    }
    js_value_t *handlers = NULL;
    size_t handler_count = 0;
    if (!html_view_js_collect_handlers(priv, target, handle, event_name, event_len, &handlers, &handler_count, error_message))
    {
        return false;
    }
    if (handler_count == 0)
    {
        free(handlers);
        if (owns_event && event_value)
        {
            js_value_destroy(event_value);
        }
        return true;
    }

    js_value_t target_val;
    if (!html_view_js_make_target_value(rt, view, priv, target, handle, &target_val, error_message))
    {
        for (size_t i = 0; i < handler_count; ++i)
        {
            js_value_destroy(&handlers[i]);
        }
        free(handlers);
        if (owns_event && event_value)
        {
            js_value_destroy(event_value);
        }
        return false;
    }
    if (event_value)
    {
        (void)html_view_js_set_event_target(event_value, &target_val);
    }
    for (size_t i = 0; i < handler_count; ++i)
    {
        js_value_t result = js_value_make_undefined();
        char *err = NULL;
        if (event_value)
        {
            (void)js_call_value(rt, &handlers[i], 1, event_value, &result, &err);
        }
        else
        {
            (void)js_call_value(rt, &handlers[i], 0, NULL, &result, &err);
        }
        js_free(err);
        js_value_destroy(&result);
        js_value_destroy(&handlers[i]);
    }
    free(handlers);
    js_value_destroy(&target_val);
    if (owns_event && event_value)
    {
        js_value_destroy(event_value);
    }
    return true;
}

static bool html_view_js_query_selector_first(const html_node_t *root,
                                              const char *selector,
                                              html_node_t **out_node)
{
    if (out_node)
    {
        *out_node = NULL;
    }
    if (!root || !selector || selector[0] == '\0')
    {
        return false;
    }
    const html_node_t **stack = NULL;
    size_t stack_cap = 0;
    size_t sp = 0;
    const html_node_t *cur = (root->type == HTML_NODE_DOCUMENT) ? root->first_child : root;
    while (cur)
    {
        if (cur->type == HTML_NODE_ELEMENT && html_view_selector_matches(selector, cur))
        {
            if (out_node)
            {
                *out_node = (html_node_t *)cur;
            }
            free(stack);
            return true;
        }
        if (cur->first_child)
        {
            if (cur->next_sibling)
            {
                if (sp == stack_cap)
                {
                    size_t new_cap = stack_cap ? (stack_cap * 2) : 64;
                    const html_node_t **new_stack = (const html_node_t **)realloc(stack, new_cap * sizeof(*new_stack));
                    if (!new_stack)
                    {
                        break;
                    }
                    stack = new_stack;
                    stack_cap = new_cap;
                }
                stack[sp++] = cur->next_sibling;
            }
            cur = cur->first_child;
            continue;
        }
        if (cur->next_sibling)
        {
            cur = cur->next_sibling;
            continue;
        }
        if (sp > 0)
        {
            cur = stack[--sp];
            continue;
        }
        break;
    }
    free(stack);
    return false;
}

static bool html_view_js_query_selector_all(atk_widget_t *view,
                                            atk_html_view_priv_t *priv,
                                            const html_node_t *root,
                                            const char *selector,
                                            js_value_t *out,
                                            char **error_message)
{
    if (!view || !priv || !root || !selector || selector[0] == '\0' || !out)
    {
        return false;
    }
    const html_node_t **stack = NULL;
    size_t stack_cap = 0;
    size_t sp = 0;
    const html_node_t *cur = (root->type == HTML_NODE_DOCUMENT) ? root->first_child : root;
    while (cur)
    {
        if (cur->type == HTML_NODE_ELEMENT && html_view_selector_matches(selector, cur))
        {
            size_t handle = html_view_js_handle_for_node(priv, (html_node_t *)cur);
            if (handle)
            {
                js_value_t elem_val;
                if (!html_view_js_make_element_object(&elem_val, view, handle, error_message))
                {
                    free(stack);
                    return false;
                }
                if (!js_value_array_push(out, &elem_val))
                {
                    js_value_destroy(&elem_val);
                    if (error_message)
                    {
                        *error_message = js_strdup("allocation failed");
                    }
                    free(stack);
                    return false;
                }
                js_value_destroy(&elem_val);
            }
        }
        if (cur->first_child)
        {
            if (cur->next_sibling)
            {
                if (sp == stack_cap)
                {
                    size_t new_cap = stack_cap ? (stack_cap * 2) : 64;
                    const html_node_t **new_stack = (const html_node_t **)realloc(stack, new_cap * sizeof(*new_stack));
                    if (!new_stack)
                    {
                        break;
                    }
                    stack = new_stack;
                    stack_cap = new_cap;
                }
                stack[sp++] = cur->next_sibling;
            }
            cur = cur->first_child;
            continue;
        }
        if (cur->next_sibling)
        {
            cur = cur->next_sibling;
            continue;
        }
        if (sp > 0)
        {
            cur = stack[--sp];
            continue;
        }
        break;
    }
    free(stack);
    return true;
}

static bool html_view_js_collect_elements_by_tag(atk_widget_t *view,
                                                 atk_html_view_priv_t *priv,
                                                 const html_node_t *root,
                                                 const char *tag,
                                                 js_value_t *out,
                                                 char **error_message)
{
    if (!view || !priv || !root || !tag || tag[0] == '\0' || !out)
    {
        return false;
    }
    const html_node_t **stack = NULL;
    size_t stack_cap = 0;
    size_t sp = 0;
    const html_node_t *cur = (root->type == HTML_NODE_DOCUMENT) ? root->first_child : root;
    while (cur)
    {
        if (cur->type == HTML_NODE_ELEMENT && cur->name)
        {
            if ((tag[0] == '*' && tag[1] == '\0') || strcasecmp(cur->name, tag) == 0)
            {
                size_t handle = html_view_js_handle_for_node(priv, (html_node_t *)cur);
                if (handle)
                {
                    js_value_t elem_val;
                    if (!html_view_js_make_element_object(&elem_val, view, handle, error_message))
                    {
                        free(stack);
                        return false;
                    }
                    if (!js_value_array_push(out, &elem_val))
                    {
                        js_value_destroy(&elem_val);
                        if (error_message)
                        {
                            *error_message = js_strdup("allocation failed");
                        }
                        free(stack);
                        return false;
                    }
                    js_value_destroy(&elem_val);
                }
            }
        }
        if (cur->first_child)
        {
            if (cur->next_sibling)
            {
                if (sp == stack_cap)
                {
                    size_t new_cap = stack_cap ? (stack_cap * 2) : 64;
                    const html_node_t **new_stack = (const html_node_t **)realloc(stack, new_cap * sizeof(*new_stack));
                    if (!new_stack)
                    {
                        break;
                    }
                    stack = new_stack;
                    stack_cap = new_cap;
                }
                stack[sp++] = cur->next_sibling;
            }
            cur = cur->first_child;
            continue;
        }
        if (cur->next_sibling)
        {
            cur = cur->next_sibling;
            continue;
        }
        if (sp > 0)
        {
            cur = stack[--sp];
            continue;
        }
        break;
    }
    free(stack);
    return true;
}

static bool html_view_js_collect_elements_by_class(atk_widget_t *view,
                                                   atk_html_view_priv_t *priv,
                                                   const html_node_t *root,
                                                   const char *class_name,
                                                   js_value_t *out,
                                                   char **error_message)
{
    if (!view || !priv || !root || !class_name || class_name[0] == '\0' || !out)
    {
        return false;
    }
    const html_node_t **stack = NULL;
    size_t stack_cap = 0;
    size_t sp = 0;
    const html_node_t *cur = (root->type == HTML_NODE_DOCUMENT) ? root->first_child : root;
    while (cur)
    {
        if (cur->type == HTML_NODE_ELEMENT && cur->name)
        {
            const char *class_attr = html_attr_get(cur, "class");
            if (class_attr && html_view_js_attr_has_token(class_attr, class_name))
            {
                size_t handle = html_view_js_handle_for_node(priv, (html_node_t *)cur);
                if (handle)
                {
                    js_value_t elem_val;
                    if (!html_view_js_make_element_object(&elem_val, view, handle, error_message))
                    {
                        free(stack);
                        return false;
                    }
                    if (!js_value_array_push(out, &elem_val))
                    {
                        js_value_destroy(&elem_val);
                        if (error_message)
                        {
                            *error_message = js_strdup("allocation failed");
                        }
                        free(stack);
                        return false;
                    }
                    js_value_destroy(&elem_val);
                }
            }
        }
        if (cur->first_child)
        {
            if (cur->next_sibling)
            {
                if (sp == stack_cap)
                {
                    size_t new_cap = stack_cap ? (stack_cap * 2) : 64;
                    const html_node_t **new_stack = (const html_node_t **)realloc(stack, new_cap * sizeof(*new_stack));
                    if (!new_stack)
                    {
                        break;
                    }
                    stack = new_stack;
                    stack_cap = new_cap;
                }
                stack[sp++] = cur->next_sibling;
            }
            cur = cur->first_child;
            continue;
        }
        if (cur->next_sibling)
        {
            cur = cur->next_sibling;
            continue;
        }
        if (sp > 0)
        {
            cur = stack[--sp];
            continue;
        }
        break;
    }
    free(stack);
    return true;
}

static bool html_view_js_element_remove_event_listener(js_runtime_t *rt,
                                                       size_t argc,
                                                       const js_value_t *argv,
                                                       void *user_data,
                                                       js_value_t *out,
                                                       char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined();
    if (!user_data || !argv || argc < 2 || argv[0].type != JS_VALUE_STRING)
    {
        return true;
    }
    html_view_js_dom_element_t *elem = (html_view_js_dom_element_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(elem->view);
    if (!priv)
    {
        return true;
    }
    const char *event = argv[0].as.string.data ? argv[0].as.string.data : "";
    size_t event_len = argv[0].as.string.len;
    (void)html_view_js_listener_remove(priv, HTML_VIEW_JS_TARGET_ELEMENT, elem->handle, event, event_len, &argv[1]);
    return true;
}

static bool html_view_js_element_dispatch_event(js_runtime_t *rt,
                                                size_t argc,
                                                const js_value_t *argv,
                                                void *user_data,
                                                js_value_t *out,
                                                char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!user_data || !argv || argc < 1)
    {
        *out = js_value_make_bool(false);
        return true;
    }
    html_view_js_dom_element_t *elem = (html_view_js_dom_element_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(elem->view);
    if (!priv)
    {
        *out = js_value_make_bool(false);
        return true;
    }
    char *event_type = NULL;
    size_t event_len = 0;
    if (!html_view_js_event_type_from_value(rt, &argv[0], &event_type, &event_len, error_message))
    {
        *out = js_value_make_bool(false);
        return true;
    }
    js_value_t event_value = argv[0];
    bool ok = html_view_js_fire_event(rt,
                                      elem->view,
                                      priv,
                                      HTML_VIEW_JS_TARGET_ELEMENT,
                                      elem->handle,
                                      event_type,
                                      event_len,
                                      &event_value,
                                      false,
                                      error_message);
    free(event_type);
    *out = js_value_make_bool(ok);
    return true;
}

static bool html_view_js_element_get_attribute(js_runtime_t *rt,
                                               size_t argc,
                                               const js_value_t *argv,
                                               void *user_data,
                                               js_value_t *out,
                                               char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out || !user_data)
    {
        return false;
    }
    if (argc < 1 || argv[0].type != JS_VALUE_STRING)
    {
        *out = js_value_make_null();
        return true;
    }
    html_view_js_dom_element_t *elem = (html_view_js_dom_element_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(elem->view);
    if (!priv)
    {
        *out = js_value_make_null();
        return true;
    }
    const char *attr_name = argv[0].as.string.data ? argv[0].as.string.data : "";
    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, elem->handle);
    const char *value = node ? html_attr_get(node, attr_name) : NULL;
    size_t len = value ? strlen(value) : 0;
    bool ok = value ? html_view_js_out_string(out, value, len, error_message) : (*out = js_value_make_null(), true);
    html_view_dom_unlock(priv);
    return ok;
}

static bool html_view_js_element_set_attribute(js_runtime_t *rt,
                                               size_t argc,
                                               const js_value_t *argv,
                                               void *user_data,
                                               js_value_t *out,
                                               char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined();
    if (!user_data || argc < 2 || argv[0].type != JS_VALUE_STRING)
    {
        return true;
    }
    html_view_js_dom_element_t *elem = (html_view_js_dom_element_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(elem->view);
    if (!priv)
    {
        return true;
    }
    const char *attr_name = argv[0].as.string.data ? argv[0].as.string.data : "";
    char *text = NULL;
    size_t text_len = 0;
    if (!html_view_js_value_to_string(&argv[1], &text, &text_len))
    {
        return false;
    }
    bool ok = false;
    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, elem->handle);
    if (node)
    {
        ok = html_view_js_node_set_attr(node, attr_name, text ? text : "");
        if (ok)
        {
            bool controls_dirty = html_view_js_node_affects_controls(node);
            html_view_js_note_dom_change(priv, true, controls_dirty);
        }
    }
    html_view_dom_unlock(priv);
    free(text);
    return ok;
}

static bool html_view_js_element_remove_attribute(js_runtime_t *rt,
                                                  size_t argc,
                                                  const js_value_t *argv,
                                                  void *user_data,
                                                  js_value_t *out,
                                                  char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined();
    if (!user_data || argc < 1 || argv[0].type != JS_VALUE_STRING)
    {
        return true;
    }
    html_view_js_dom_element_t *elem = (html_view_js_dom_element_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(elem->view);
    if (!priv)
    {
        return true;
    }
    const char *attr_name = argv[0].as.string.data ? argv[0].as.string.data : "";
    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, elem->handle);
    bool ok = false;
    if (node)
    {
        ok = html_view_js_node_remove_attr(node, attr_name);
        if (ok)
        {
            bool controls_dirty = html_view_js_node_affects_controls(node);
            html_view_js_note_dom_change(priv, true, controls_dirty);
        }
    }
    html_view_dom_unlock(priv);
    return ok;
}

static bool html_view_js_element_has_attribute(js_runtime_t *rt,
                                               size_t argc,
                                               const js_value_t *argv,
                                               void *user_data,
                                               js_value_t *out,
                                               char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!user_data || argc < 1 || argv[0].type != JS_VALUE_STRING)
    {
        *out = js_value_make_bool(false);
        return true;
    }
    html_view_js_dom_element_t *elem = (html_view_js_dom_element_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(elem->view);
    if (!priv)
    {
        *out = js_value_make_bool(false);
        return true;
    }
    const char *attr_name = argv[0].as.string.data ? argv[0].as.string.data : "";
    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, elem->handle);
    bool ok = node && html_attr_get(node, attr_name) != NULL;
    html_view_dom_unlock(priv);
    *out = js_value_make_bool(ok);
    return true;
}

static bool html_view_js_element_append_child(js_runtime_t *rt,
                                              size_t argc,
                                              const js_value_t *argv,
                                              void *user_data,
                                              js_value_t *out,
                                              char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!user_data || argc < 1 || !argv)
    {
        *out = js_value_make_null();
        return true;
    }
    html_view_js_dom_element_t *elem = (html_view_js_dom_element_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(elem->view);
    if (!priv)
    {
        *out = js_value_make_null();
        return true;
    }
    size_t child_handle = 0;
    if (!html_view_js_handle_from_value(&argv[0], &child_handle))
    {
        *out = js_value_make_null();
        return true;
    }
    bool ok = false;
    html_view_dom_lock(priv);
    html_node_t *parent = html_view_js_node_for_handle(priv, elem->handle);
    html_node_t *child = html_view_js_node_for_handle(priv, child_handle);
    if (parent && child)
    {
        html_view_js_node_detach(child);
        html_view_js_append_child(parent, child);
        bool controls_dirty = html_view_js_node_affects_controls(child);
        html_view_js_note_dom_change(priv, true, controls_dirty);
        ok = true;
    }
    html_view_dom_unlock(priv);
    if (!ok)
    {
        *out = js_value_make_null();
        return true;
    }
    return html_view_js_make_element_object(out, elem->view, child_handle, error_message);
}

static bool html_view_js_element_remove_child(js_runtime_t *rt,
                                              size_t argc,
                                              const js_value_t *argv,
                                              void *user_data,
                                              js_value_t *out,
                                              char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!user_data || argc < 1 || !argv)
    {
        *out = js_value_make_null();
        return true;
    }
    html_view_js_dom_element_t *elem = (html_view_js_dom_element_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(elem->view);
    if (!priv)
    {
        *out = js_value_make_null();
        return true;
    }
    size_t child_handle = 0;
    if (!html_view_js_handle_from_value(&argv[0], &child_handle))
    {
        *out = js_value_make_null();
        return true;
    }
    bool ok = false;
    html_view_dom_lock(priv);
    html_node_t *parent = html_view_js_node_for_handle(priv, elem->handle);
    html_node_t *child = html_view_js_node_for_handle(priv, child_handle);
    if (parent && child && child->parent == parent)
    {
        html_view_js_node_detach(child);
        bool controls_dirty = html_view_js_node_affects_controls(child);
        html_view_js_note_dom_change(priv, true, controls_dirty);
        ok = true;
    }
    html_view_dom_unlock(priv);
    if (!ok)
    {
        *out = js_value_make_null();
        return true;
    }
    return html_view_js_make_element_object(out, elem->view, child_handle, error_message);
}

static bool html_view_js_element_insert_before(js_runtime_t *rt,
                                               size_t argc,
                                               const js_value_t *argv,
                                               void *user_data,
                                               js_value_t *out,
                                               char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!user_data || argc < 1 || !argv)
    {
        *out = js_value_make_null();
        return true;
    }
    html_view_js_dom_element_t *elem = (html_view_js_dom_element_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(elem->view);
    if (!priv)
    {
        *out = js_value_make_null();
        return true;
    }
    size_t child_handle = 0;
    if (!html_view_js_handle_from_value(&argv[0], &child_handle))
    {
        *out = js_value_make_null();
        return true;
    }
    size_t ref_handle = 0;
    html_node_t *ref_node = NULL;
    if (argc > 1 && argv[1].type != JS_VALUE_NULL && argv[1].type != JS_VALUE_UNDEFINED)
    {
        if (!html_view_js_handle_from_value(&argv[1], &ref_handle))
        {
            *out = js_value_make_null();
            return true;
        }
    }
    bool ok = false;
    html_view_dom_lock(priv);
    html_node_t *parent = html_view_js_node_for_handle(priv, elem->handle);
    html_node_t *child = html_view_js_node_for_handle(priv, child_handle);
    if (ref_handle)
    {
        ref_node = html_view_js_node_for_handle(priv, ref_handle);
    }
    if (parent && child)
    {
        if (ref_node && ref_node->parent != parent)
        {
            html_view_dom_unlock(priv);
            *out = js_value_make_null();
            return true;
        }
        html_view_js_node_detach(child);
        if (ref_node)
        {
            html_view_js_node_insert_before(parent, child, ref_node);
        }
        else
        {
            html_view_js_append_child(parent, child);
        }
        bool controls_dirty = html_view_js_node_affects_controls(child);
        html_view_js_note_dom_change(priv, true, controls_dirty);
        ok = true;
    }
    html_view_dom_unlock(priv);
    if (!ok)
    {
        *out = js_value_make_null();
        return true;
    }
    return html_view_js_make_element_object(out, elem->view, child_handle, error_message);
}

static bool html_view_js_element_replace_child(js_runtime_t *rt,
                                               size_t argc,
                                               const js_value_t *argv,
                                               void *user_data,
                                               js_value_t *out,
                                               char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!user_data || argc < 2 || !argv)
    {
        *out = js_value_make_null();
        return true;
    }
    html_view_js_dom_element_t *elem = (html_view_js_dom_element_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(elem->view);
    if (!priv)
    {
        *out = js_value_make_null();
        return true;
    }
    size_t new_handle = 0;
    size_t old_handle = 0;
    if (!html_view_js_handle_from_value(&argv[0], &new_handle) ||
        !html_view_js_handle_from_value(&argv[1], &old_handle))
    {
        *out = js_value_make_null();
        return true;
    }
    bool ok = false;
    html_view_dom_lock(priv);
    html_node_t *parent = html_view_js_node_for_handle(priv, elem->handle);
    html_node_t *new_node = html_view_js_node_for_handle(priv, new_handle);
    html_node_t *old_node = html_view_js_node_for_handle(priv, old_handle);
    if (parent && new_node && old_node && old_node->parent == parent)
    {
        html_view_js_node_detach(new_node);
        html_view_js_node_insert_before(parent, new_node, old_node);
        html_view_js_node_detach(old_node);
        bool controls_dirty = html_view_js_node_affects_controls(new_node) || html_view_js_node_affects_controls(old_node);
        html_view_js_note_dom_change(priv, true, controls_dirty);
        ok = true;
    }
    html_view_dom_unlock(priv);
    if (!ok)
    {
        *out = js_value_make_null();
        return true;
    }
    return html_view_js_make_element_object(out, elem->view, old_handle, error_message);
}

static bool html_view_js_element_query_selector(js_runtime_t *rt,
                                                size_t argc,
                                                const js_value_t *argv,
                                                void *user_data,
                                                js_value_t *out,
                                                char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out || !user_data)
    {
        return false;
    }
    if (argc < 1 || argv[0].type != JS_VALUE_STRING)
    {
        *out = js_value_make_null();
        return true;
    }
    html_view_js_dom_element_t *elem = (html_view_js_dom_element_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(elem->view);
    if (!priv)
    {
        *out = js_value_make_null();
        return true;
    }
    const char *selector = argv[0].as.string.data ? argv[0].as.string.data : "";
    html_node_t *match = NULL;
    html_view_dom_lock(priv);
    html_node_t *root = html_view_js_node_for_handle(priv, elem->handle);
    if (root)
    {
        (void)html_view_js_query_selector_first(root, selector, &match);
    }
    size_t handle = html_view_js_handle_for_node(priv, match);
    html_view_dom_unlock(priv);
    if (!handle)
    {
        *out = js_value_make_null();
        return true;
    }
    return html_view_js_make_element_object(out, elem->view, handle, error_message);
}

static bool html_view_js_element_query_selector_all(js_runtime_t *rt,
                                                    size_t argc,
                                                    const js_value_t *argv,
                                                    void *user_data,
                                                    js_value_t *out,
                                                    char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out || !user_data)
    {
        return false;
    }
    if (argc < 1 || argv[0].type != JS_VALUE_STRING)
    {
        return html_view_js_out_array(out, error_message);
    }
    html_view_js_dom_element_t *elem = (html_view_js_dom_element_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(elem->view);
    if (!priv)
    {
        return html_view_js_out_array(out, error_message);
    }
    const char *selector = argv[0].as.string.data ? argv[0].as.string.data : "";
    if (!html_view_js_out_array(out, error_message))
    {
        return false;
    }
    html_view_dom_lock(priv);
    html_node_t *root = html_view_js_node_for_handle(priv, elem->handle);
    if (root)
    {
        bool ok = html_view_js_query_selector_all(elem->view, priv, root, selector, out, error_message);
        html_view_dom_unlock(priv);
        return ok;
    }
    html_view_dom_unlock(priv);
    return true;
}

static bool html_view_js_element_get_elements_by_tag(js_runtime_t *rt,
                                                     size_t argc,
                                                     const js_value_t *argv,
                                                     void *user_data,
                                                     js_value_t *out,
                                                     char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out || !user_data)
    {
        return false;
    }
    if (argc < 1 || argv[0].type != JS_VALUE_STRING)
    {
        return html_view_js_out_array(out, error_message);
    }
    html_view_js_dom_element_t *elem = (html_view_js_dom_element_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(elem->view);
    if (!priv)
    {
        return html_view_js_out_array(out, error_message);
    }
    const char *tag = argv[0].as.string.data ? argv[0].as.string.data : "";
    if (!html_view_js_out_array(out, error_message))
    {
        return false;
    }
    html_view_dom_lock(priv);
    html_node_t *root = html_view_js_node_for_handle(priv, elem->handle);
    if (root)
    {
        bool ok = html_view_js_collect_elements_by_tag(elem->view, priv, root, tag, out, error_message);
        html_view_dom_unlock(priv);
        return ok;
    }
    html_view_dom_unlock(priv);
    return true;
}

static bool html_view_js_element_get_elements_by_class(js_runtime_t *rt,
                                                       size_t argc,
                                                       const js_value_t *argv,
                                                       void *user_data,
                                                       js_value_t *out,
                                                       char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out || !user_data)
    {
        return false;
    }
    if (argc < 1 || argv[0].type != JS_VALUE_STRING)
    {
        return html_view_js_out_array(out, error_message);
    }
    html_view_js_dom_element_t *elem = (html_view_js_dom_element_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(elem->view);
    if (!priv)
    {
        return html_view_js_out_array(out, error_message);
    }
    const char *class_name = argv[0].as.string.data ? argv[0].as.string.data : "";
    if (!html_view_js_out_array(out, error_message))
    {
        return false;
    }
    html_view_dom_lock(priv);
    html_node_t *root = html_view_js_node_for_handle(priv, elem->handle);
    if (root)
    {
        bool ok = html_view_js_collect_elements_by_class(elem->view, priv, root, class_name, out, error_message);
        html_view_dom_unlock(priv);
        return ok;
    }
    html_view_dom_unlock(priv);
    return true;
}

static bool html_view_js_element_matches(js_runtime_t *rt,
                                         size_t argc,
                                         const js_value_t *argv,
                                         void *user_data,
                                         js_value_t *out,
                                         char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!user_data || argc < 1 || argv[0].type != JS_VALUE_STRING)
    {
        *out = js_value_make_bool(false);
        return true;
    }
    html_view_js_dom_element_t *elem = (html_view_js_dom_element_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(elem->view);
    if (!priv)
    {
        *out = js_value_make_bool(false);
        return true;
    }
    const char *selector = argv[0].as.string.data ? argv[0].as.string.data : "";
    bool match = false;
    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, elem->handle);
    if (node && node->type == HTML_NODE_ELEMENT)
    {
        match = html_view_selector_matches(selector, node);
    }
    html_view_dom_unlock(priv);
    *out = js_value_make_bool(match);
    return true;
}

static bool html_view_js_element_closest(js_runtime_t *rt,
                                         size_t argc,
                                         const js_value_t *argv,
                                         void *user_data,
                                         js_value_t *out,
                                         char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!user_data || argc < 1 || argv[0].type != JS_VALUE_STRING)
    {
        *out = js_value_make_null();
        return true;
    }
    html_view_js_dom_element_t *elem = (html_view_js_dom_element_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(elem->view);
    if (!priv)
    {
        *out = js_value_make_null();
        return true;
    }
    const char *selector = argv[0].as.string.data ? argv[0].as.string.data : "";
    html_node_t *match = NULL;
    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, elem->handle);
    for (html_node_t *cur = node; cur; cur = cur->parent)
    {
        if (cur->type == HTML_NODE_ELEMENT && html_view_selector_matches(selector, cur))
        {
            match = cur;
            break;
        }
    }
    size_t handle = html_view_js_handle_for_node(priv, match);
    html_view_dom_unlock(priv);
    if (!handle)
    {
        *out = js_value_make_null();
        return true;
    }
    return html_view_js_make_element_object(out, elem->view, handle, error_message);
}

static bool html_view_js_element_contains(js_runtime_t *rt,
                                          size_t argc,
                                          const js_value_t *argv,
                                          void *user_data,
                                          js_value_t *out,
                                          char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!user_data || argc < 1 || !argv)
    {
        *out = js_value_make_bool(false);
        return true;
    }
    html_view_js_dom_element_t *elem = (html_view_js_dom_element_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(elem->view);
    if (!priv)
    {
        *out = js_value_make_bool(false);
        return true;
    }
    size_t other_handle = 0;
    if (!html_view_js_handle_from_value(&argv[0], &other_handle))
    {
        *out = js_value_make_bool(false);
        return true;
    }
    bool result = false;
    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, elem->handle);
    html_node_t *other = html_view_js_node_for_handle(priv, other_handle);
    if (node && other)
    {
        result = html_view_js_node_contains(node, other);
    }
    html_view_dom_unlock(priv);
    *out = js_value_make_bool(result);
    return true;
}

static bool html_view_js_element_focus(js_runtime_t *rt,
                                       size_t argc,
                                       const js_value_t *argv,
                                       void *user_data,
                                       js_value_t *out,
                                       char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined();
    if (!user_data)
    {
        return true;
    }
    html_view_js_dom_element_t *elem = (html_view_js_dom_element_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(elem->view);
    if (!priv)
    {
        return true;
    }
    html_view_dom_lock(priv);
    priv->js_active_handle = elem->handle;
    html_view_dom_unlock(priv);
    return true;
}

static bool html_view_js_element_blur(js_runtime_t *rt,
                                      size_t argc,
                                      const js_value_t *argv,
                                      void *user_data,
                                      js_value_t *out,
                                      char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined();
    if (!user_data)
    {
        return true;
    }
    html_view_js_dom_element_t *elem = (html_view_js_dom_element_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(elem->view);
    if (!priv)
    {
        return true;
    }
    html_view_dom_lock(priv);
    if (priv->js_active_handle == elem->handle)
    {
        priv->js_active_handle = 0;
    }
    html_view_dom_unlock(priv);
    return true;
}

static bool html_view_js_element_click(js_runtime_t *rt,
                                       size_t argc,
                                       const js_value_t *argv,
                                       void *user_data,
                                       js_value_t *out,
                                       char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined();
    if (!user_data)
    {
        return true;
    }
    html_view_js_dom_element_t *elem = (html_view_js_dom_element_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(elem->view);
    if (!priv)
    {
        return true;
    }
    html_view_js_event_t evt = {0};
    evt.target = HTML_VIEW_JS_TARGET_ELEMENT;
    evt.handle = elem->handle;
    evt.type = "click";
    js_value_t event_obj;
    if (html_view_js_make_event_object("click", &event_obj, error_message))
    {
        (void)html_view_js_fire_event(rt,
                                      elem->view,
                                      priv,
                                      HTML_VIEW_JS_TARGET_ELEMENT,
                                      elem->handle,
                                      "click",
                                      5,
                                      &event_obj,
                                      true,
                                      error_message);
    }
    return true;
}

static bool html_view_js_element_scroll_into_view(js_runtime_t *rt,
                                                  size_t argc,
                                                  const js_value_t *argv,
                                                  void *user_data,
                                                  js_value_t *out,
                                                  char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined();
    return true;
}

static bool html_view_js_element_set(js_runtime_t *rt,
                                     void *user_data,
                                     const char *name,
                                     const js_value_t *value,
                                     char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!user_data || !name || !value)
    {
        return false;
    }
    html_view_js_dom_element_t *elem = (html_view_js_dom_element_t *)user_data;
    if (!elem->view)
    {
        return false;
    }

    char *text = NULL;
    size_t text_len = 0;
    bool is_text = (strcmp(name, "textContent") == 0 || strcmp(name, "innerText") == 0 || strcmp(name, "innerHTML") == 0);
    bool is_value = (strcmp(name, "value") == 0);
    bool is_id = (strcmp(name, "id") == 0);
    bool is_class = (strcmp(name, "className") == 0);
    bool is_checked = (strcmp(name, "checked") == 0);
    bool is_style = (strcmp(name, "style") == 0);
    if (!is_text && !is_value && !is_id && !is_class && !is_checked && !is_style)
    {
        return true;
    }

    bool ok = false;
    bool styles_dirty = is_id || is_class || is_style;
    bool controls_dirty = false;

    atk_html_view_priv_t *priv = html_view_priv_mut(elem->view);
    if (!priv)
    {
        return false;
    }

    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, elem->handle);
    if (node)
    {
        if (is_text)
        {
            if (!html_view_js_value_to_string(value, &text, &text_len))
            {
                html_view_dom_unlock(priv);
                return false;
            }
            ok = html_view_js_node_set_text(node, text ? text : "", text_len);
        }
        else if (is_value)
        {
            if (!html_view_js_value_to_string(value, &text, &text_len))
            {
                html_view_dom_unlock(priv);
                return false;
            }
            ok = html_view_js_node_set_attr(node, "value", text ? text : "");
        }
        else if (is_id)
        {
            if (!html_view_js_value_to_string(value, &text, &text_len))
            {
                html_view_dom_unlock(priv);
                return false;
            }
            ok = html_view_js_node_set_attr(node, "id", text ? text : "");
        }
        else if (is_class)
        {
            if (!html_view_js_value_to_string(value, &text, &text_len))
            {
                html_view_dom_unlock(priv);
                return false;
            }
            ok = html_view_js_node_set_attr(node, "class", text ? text : "");
        }
        else if (is_style)
        {
            if (!html_view_js_value_to_string(value, &text, &text_len))
            {
                html_view_dom_unlock(priv);
                return false;
            }
            ok = html_view_js_node_set_attr(node, "style", text ? text : "");
        }
        else if (is_checked)
        {
            bool checked = js_value_is_truthy(value);
            if (checked)
            {
                ok = html_view_js_node_set_attr(node, "checked", "checked");
            }
            else
            {
                ok = html_view_js_node_remove_attr(node, "checked");
            }
        }
        if (ok)
        {
            if (is_text && (html_view_js_node_is_style(node) || html_view_js_node_is_style(node->parent)))
            {
                styles_dirty = true;
            }
            controls_dirty = html_view_js_node_affects_controls(node);
            html_view_js_note_dom_change(priv, styles_dirty, controls_dirty);
        }
    }
    html_view_dom_unlock(priv);

    free(text);
    return ok;
}

static bool html_view_js_make_element_object(js_value_t *out,
                                             atk_widget_t *view,
                                             size_t handle,
                                             char **error_message)
{
    if (!out || !view || handle == 0)
    {
        return false;
    }
    html_view_js_dom_element_t *elem = (html_view_js_dom_element_t *)calloc(1, sizeof(*elem));
    if (!elem)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    elem->view = view;
    elem->handle = handle;
    if (!js_value_make_host_object(out, html_view_js_element_get, html_view_js_element_set, html_view_js_dom_element_destroy, elem))
    {
        free(elem);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    return true;
}

static bool html_view_js_document_get_element_by_id(js_runtime_t *rt,
                                                    size_t argc,
                                                    const js_value_t *argv,
                                                    void *user_data,
                                                    js_value_t *out,
                                                    char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out || !user_data)
    {
        return false;
    }
    if (argc < 1 || !argv || argv[0].type != JS_VALUE_STRING)
    {
        *out = js_value_make_null();
        return true;
    }

    const char *id = argv[0].as.string.data ? argv[0].as.string.data : "";
    if (id[0] == '\0')
    {
        *out = js_value_make_null();
        return true;
    }

    atk_widget_t *view = (atk_widget_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv || !priv->doc || !priv->doc->root)
    {
        *out = js_value_make_null();
        return true;
    }

    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_find_element_by_id(priv->doc->root, id);
    size_t handle = html_view_js_handle_for_node(priv, node);
    html_view_dom_unlock(priv);

    if (!handle)
    {
        *out = js_value_make_null();
        return true;
    }

    return html_view_js_make_element_object(out, view, handle, error_message);
}

static bool html_view_js_document_get(js_runtime_t *rt,
                                      void *user_data,
                                      const char *name,
                                      js_value_t *out,
                                      char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out || !name)
    {
        return false;
    }
    if (strcmp(name, "getElementById") == 0)
    {
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_document_get_element_by_id;
        out->as.native.user_data = user_data;
        return true;
    }
    *out = js_value_make_undefined();
    return true;
}

static bool html_view_js_dom_get_root(js_runtime_t *rt,
                                      size_t argc,
                                      const js_value_t *argv,
                                      void *user_data,
                                      js_value_t *out,
                                      char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }

    atk_widget_t *view = (atk_widget_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv || !priv->doc || !priv->doc->root)
    {
        *out = js_value_make_null();
        return true;
    }

    html_view_dom_lock(priv);
    size_t handle = html_view_js_handle_for_node(priv, priv->doc->root);
    html_view_dom_unlock(priv);

    if (!handle)
    {
        *out = js_value_make_null();
    }
    else
    {
        *out = js_value_make_number((double)handle);
    }
    return true;
}

static bool html_view_js_dom_get_element_by_id(js_runtime_t *rt,
                                               size_t argc,
                                               const js_value_t *argv,
                                               void *user_data,
                                               js_value_t *out,
                                               char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (argc < 1 || !argv || argv[0].type != JS_VALUE_STRING)
    {
        *out = js_value_make_null();
        return true;
    }

    const char *id = argv[0].as.string.data ? argv[0].as.string.data : "";
    if (id[0] == '\0')
    {
        *out = js_value_make_null();
        return true;
    }

    atk_widget_t *view = (atk_widget_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv || !priv->doc || !priv->doc->root)
    {
        *out = js_value_make_null();
        return true;
    }

    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_find_element_by_id(priv->doc->root, id);
    size_t handle = html_view_js_handle_for_node(priv, node);
    html_view_dom_unlock(priv);

    if (!handle)
    {
        *out = js_value_make_null();
    }
    else
    {
        *out = js_value_make_number((double)handle);
    }
    return true;
}

static bool html_view_js_dom_get_type(js_runtime_t *rt,
                                      size_t argc,
                                      const js_value_t *argv,
                                      void *user_data,
                                      js_value_t *out,
                                      char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (argc < 1 || !argv)
    {
        *out = js_value_make_null();
        return true;
    }

    atk_widget_t *view = (atk_widget_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        *out = js_value_make_null();
        return true;
    }

    size_t handle = 0;
    if (!html_view_js_handle_from_value(&argv[0], &handle))
    {
        *out = js_value_make_null();
        return true;
    }

    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, handle);
    html_view_dom_unlock(priv);

    if (!node)
    {
        *out = js_value_make_null();
    }
    else
    {
        *out = js_value_make_number((double)node->type);
    }
    return true;
}

static bool html_view_js_dom_get_tag(js_runtime_t *rt,
                                     size_t argc,
                                     const js_value_t *argv,
                                     void *user_data,
                                     js_value_t *out,
                                     char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (argc < 1 || !argv)
    {
        *out = js_value_make_null();
        return true;
    }

    atk_widget_t *view = (atk_widget_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        *out = js_value_make_null();
        return true;
    }

    size_t handle = 0;
    if (!html_view_js_handle_from_value(&argv[0], &handle))
    {
        *out = js_value_make_null();
        return true;
    }

    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, handle);
    const char *name = (node && node->type == HTML_NODE_ELEMENT && node->name) ? node->name : NULL;
    size_t len = name ? strlen(name) : 0;
    bool ok = true;
    if (name)
    {
        ok = html_view_js_out_string(out, name, len, error_message);
    }
    else
    {
        *out = js_value_make_null();
    }
    html_view_dom_unlock(priv);
    return ok;
}

static bool html_view_js_dom_get_attr(js_runtime_t *rt,
                                      size_t argc,
                                      const js_value_t *argv,
                                      void *user_data,
                                      js_value_t *out,
                                      char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (argc < 2 || !argv || argv[1].type != JS_VALUE_STRING)
    {
        *out = js_value_make_null();
        return true;
    }

    atk_widget_t *view = (atk_widget_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        *out = js_value_make_null();
        return true;
    }

    size_t handle = 0;
    if (!html_view_js_handle_from_value(&argv[0], &handle))
    {
        *out = js_value_make_null();
        return true;
    }

    const char *attr_name = argv[1].as.string.data ? argv[1].as.string.data : "";

    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, handle);
    const char *value = (node && node->type == HTML_NODE_ELEMENT) ? html_attr_get(node, attr_name) : NULL;
    size_t len = value ? strlen(value) : 0;
    bool ok = true;
    if (value)
    {
        ok = html_view_js_out_string(out, value, len, error_message);
    }
    else
    {
        *out = js_value_make_null();
    }
    html_view_dom_unlock(priv);
    return ok;
}

static bool html_view_js_dom_set_attr(js_runtime_t *rt,
                                      size_t argc,
                                      const js_value_t *argv,
                                      void *user_data,
                                      js_value_t *out,
                                      char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (argc < 2 || !argv || argv[1].type != JS_VALUE_STRING)
    {
        *out = js_value_make_bool(false);
        return true;
    }

    atk_widget_t *view = (atk_widget_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        *out = js_value_make_bool(false);
        return true;
    }

    size_t handle = 0;
    if (!html_view_js_handle_from_value(&argv[0], &handle))
    {
        *out = js_value_make_bool(false);
        return true;
    }

    const char *attr_name = argv[1].as.string.data ? argv[1].as.string.data : "";
    const char *attr_value = NULL;
    bool remove_attr = false;

    if (argc >= 3 && argv[2].type == JS_VALUE_STRING)
    {
        attr_value = argv[2].as.string.data ? argv[2].as.string.data : "";
    }
    else if (argc >= 3 && (argv[2].type == JS_VALUE_NULL || argv[2].type == JS_VALUE_UNDEFINED))
    {
        remove_attr = true;
    }
    else
    {
        *out = js_value_make_bool(false);
        return true;
    }

    bool ok = false;
    bool styles_dirty = false;
    bool controls_dirty = false;

    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, handle);
    if (node && node->type == HTML_NODE_ELEMENT)
    {
        if (remove_attr)
        {
            ok = html_view_js_node_remove_attr(node, attr_name);
        }
        else
        {
            ok = html_view_js_node_set_attr(node, attr_name, attr_value);
        }
        if (ok)
        {
            controls_dirty = html_view_js_node_affects_controls(node);
            html_view_js_note_dom_change(priv, styles_dirty, controls_dirty);
        }
    }
    html_view_dom_unlock(priv);

    *out = js_value_make_bool(ok);
    return true;
}

static bool html_view_js_dom_get_text(js_runtime_t *rt,
                                      size_t argc,
                                      const js_value_t *argv,
                                      void *user_data,
                                      js_value_t *out,
                                      char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (argc < 1 || !argv)
    {
        *out = js_value_make_null();
        return true;
    }

    atk_widget_t *view = (atk_widget_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        *out = js_value_make_null();
        return true;
    }

    size_t handle = 0;
    if (!html_view_js_handle_from_value(&argv[0], &handle))
    {
        *out = js_value_make_null();
        return true;
    }

    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, handle);
    if (!node)
    {
        html_view_dom_unlock(priv);
        *out = js_value_make_null();
        return true;
    }

    if (node->type == HTML_NODE_TEXT)
    {
        const char *text = node->text ? node->text : "";
        size_t len = strlen(text);
        bool ok = html_view_js_out_string(out, text, len, error_message);
        html_view_dom_unlock(priv);
        return ok;
    }

    char *text = NULL;
    size_t text_len = 0;
    size_t text_cap = 0;
    html_view_collect_text(node, &text, &text_len, &text_cap);

    bool ok = true;
    if (text)
    {
        ok = html_view_js_out_string(out, text, text_len, error_message);
    }
    else
    {
        ok = html_view_js_out_string(out, "", 0, error_message);
    }
    free(text);
    html_view_dom_unlock(priv);
    return ok;
}

static bool html_view_js_dom_set_text(js_runtime_t *rt,
                                      size_t argc,
                                      const js_value_t *argv,
                                      void *user_data,
                                      js_value_t *out,
                                      char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (argc < 2 || !argv || argv[1].type != JS_VALUE_STRING)
    {
        *out = js_value_make_bool(false);
        return true;
    }

    atk_widget_t *view = (atk_widget_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        *out = js_value_make_bool(false);
        return true;
    }

    size_t handle = 0;
    if (!html_view_js_handle_from_value(&argv[0], &handle))
    {
        *out = js_value_make_bool(false);
        return true;
    }

    const char *text = argv[1].as.string.data ? argv[1].as.string.data : "";
    size_t text_len = argv[1].as.string.len;

    bool ok = false;
    bool styles_dirty = false;
    bool controls_dirty = false;

    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, handle);
    if (node)
    {
        ok = html_view_js_node_set_text(node, text, text_len);
        if (ok)
        {
            if (html_view_js_node_is_style(node) || html_view_js_node_is_style(node->parent))
            {
                styles_dirty = true;
            }
            controls_dirty = html_view_js_node_affects_controls(node);
            html_view_js_note_dom_change(priv, styles_dirty, controls_dirty);
        }
    }
    html_view_dom_unlock(priv);

    *out = js_value_make_bool(ok);
    return true;
}

static bool html_view_js_dom_first_child(js_runtime_t *rt,
                                         size_t argc,
                                         const js_value_t *argv,
                                         void *user_data,
                                         js_value_t *out,
                                         char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (argc < 1 || !argv)
    {
        *out = js_value_make_null();
        return true;
    }

    atk_widget_t *view = (atk_widget_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        *out = js_value_make_null();
        return true;
    }

    size_t handle = 0;
    if (!html_view_js_handle_from_value(&argv[0], &handle))
    {
        *out = js_value_make_null();
        return true;
    }

    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, handle);
    html_node_t *child = node ? node->first_child : NULL;
    size_t child_handle = html_view_js_handle_for_node(priv, child);
    html_view_dom_unlock(priv);

    if (!child_handle)
    {
        *out = js_value_make_null();
    }
    else
    {
        *out = js_value_make_number((double)child_handle);
    }
    return true;
}

static bool html_view_js_dom_next_sibling(js_runtime_t *rt,
                                          size_t argc,
                                          const js_value_t *argv,
                                          void *user_data,
                                          js_value_t *out,
                                          char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (argc < 1 || !argv)
    {
        *out = js_value_make_null();
        return true;
    }

    atk_widget_t *view = (atk_widget_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        *out = js_value_make_null();
        return true;
    }

    size_t handle = 0;
    if (!html_view_js_handle_from_value(&argv[0], &handle))
    {
        *out = js_value_make_null();
        return true;
    }

    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, handle);
    html_node_t *next = node ? node->next_sibling : NULL;
    size_t next_handle = html_view_js_handle_for_node(priv, next);
    html_view_dom_unlock(priv);

    if (!next_handle)
    {
        *out = js_value_make_null();
    }
    else
    {
        *out = js_value_make_number((double)next_handle);
    }
    return true;
}

static bool html_view_js_dom_parent(js_runtime_t *rt,
                                    size_t argc,
                                    const js_value_t *argv,
                                    void *user_data,
                                    js_value_t *out,
                                    char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (argc < 1 || !argv)
    {
        *out = js_value_make_null();
        return true;
    }

    atk_widget_t *view = (atk_widget_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        *out = js_value_make_null();
        return true;
    }

    size_t handle = 0;
    if (!html_view_js_handle_from_value(&argv[0], &handle))
    {
        *out = js_value_make_null();
        return true;
    }

    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, handle);
    html_node_t *parent = node ? node->parent : NULL;
    size_t parent_handle = html_view_js_handle_for_node(priv, parent);
    html_view_dom_unlock(priv);

    if (!parent_handle)
    {
        *out = js_value_make_null();
    }
    else
    {
        *out = js_value_make_number((double)parent_handle);
    }
    return true;
}

static bool html_view_js_tag_matches(const char *name, const char *tag)
{
    if (!name || !tag)
    {
        return false;
    }
    if (strcmp(tag, "*") == 0)
    {
        return true;
    }
    return strcasecmp(name, tag) == 0;
}

static bool html_view_js_dom_get_children(js_runtime_t *rt,
                                          size_t argc,
                                          const js_value_t *argv,
                                          void *user_data,
                                          js_value_t *out,
                                          char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!html_view_js_out_array(out, error_message))
    {
        return false;
    }
    if (argc < 1 || !argv)
    {
        return true;
    }

    atk_widget_t *view = (atk_widget_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        return true;
    }

    size_t handle = 0;
    if (!html_view_js_handle_from_value(&argv[0], &handle))
    {
        return true;
    }

    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, handle);
    for (html_node_t *child = node ? node->first_child : NULL; child; child = child->next_sibling)
    {
        size_t child_handle = html_view_js_handle_for_node(priv, child);
        if (child_handle && !html_view_js_array_push_handle(out, child_handle, error_message))
        {
            html_view_dom_unlock(priv);
            js_value_destroy(out);
            return false;
        }
    }
    html_view_dom_unlock(priv);
    return true;
}

static bool html_view_js_dom_get_elements_by_tag(js_runtime_t *rt,
                                                 size_t argc,
                                                 const js_value_t *argv,
                                                 void *user_data,
                                                 js_value_t *out,
                                                 char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!html_view_js_out_array(out, error_message))
    {
        return false;
    }
    if (!argv || argc == 0)
    {
        return true;
    }

    const js_value_t *tag_value = NULL;
    const js_value_t *root_value = NULL;
    if (argc >= 2 && argv[0].type == JS_VALUE_NUMBER && argv[1].type == JS_VALUE_STRING)
    {
        root_value = &argv[0];
        tag_value = &argv[1];
    }
    else if (argv[0].type == JS_VALUE_STRING)
    {
        tag_value = &argv[0];
    }
    else
    {
        return true;
    }

    const char *tag = tag_value && tag_value->as.string.data ? tag_value->as.string.data : "";
    if (!tag || tag[0] == '\0')
    {
        return true;
    }

    atk_widget_t *view = (atk_widget_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        return true;
    }

    html_view_dom_lock(priv);
    html_node_t *root = (priv->doc && priv->doc->root) ? priv->doc->root : NULL;
    if (root_value)
    {
        size_t handle = 0;
        if (html_view_js_handle_from_value(root_value, &handle))
        {
            root = html_view_js_node_for_handle(priv, handle);
        }
        else
        {
            root = NULL;
        }
    }
    if (!root)
    {
        html_view_dom_unlock(priv);
        return true;
    }

    const html_node_t **stack = NULL;
    size_t stack_cap = 0;
    size_t sp = 0;

    stack_cap = 64;
    stack = (const html_node_t **)malloc(stack_cap * sizeof(*stack));
    if (!stack)
    {
        html_view_dom_unlock(priv);
        js_value_destroy(out);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    stack[sp++] = root;

    while (sp > 0)
    {
        const html_node_t *node = stack[--sp];
        if (node->type == HTML_NODE_ELEMENT && node->name && html_view_js_tag_matches(node->name, tag))
        {
            size_t handle = html_view_js_handle_for_node(priv, (html_node_t *)node);
            if (handle && !html_view_js_array_push_handle(out, handle, error_message))
            {
                html_view_dom_unlock(priv);
                free(stack);
                js_value_destroy(out);
                return false;
            }
        }
        for (const html_node_t *child = node->last_child; child; child = child->prev_sibling)
        {
            if (sp == stack_cap)
            {
                size_t new_cap = stack_cap ? (stack_cap * 2) : 64;
                const html_node_t **new_stack = (const html_node_t **)realloc(stack, new_cap * sizeof(*new_stack));
                if (!new_stack)
                {
                    break;
                }
                stack = new_stack;
                stack_cap = new_cap;
            }
            if (sp < stack_cap)
            {
                stack[sp++] = child;
            }
        }
    }

    html_view_dom_unlock(priv);
    free(stack);
    return true;
}

static bool html_view_js_dom_get_elements_by_class(js_runtime_t *rt,
                                                   size_t argc,
                                                   const js_value_t *argv,
                                                   void *user_data,
                                                   js_value_t *out,
                                                   char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!html_view_js_out_array(out, error_message))
    {
        return false;
    }
    if (!argv || argc == 0)
    {
        return true;
    }

    const js_value_t *class_value = NULL;
    const js_value_t *root_value = NULL;
    if (argc >= 2 && argv[0].type == JS_VALUE_NUMBER && argv[1].type == JS_VALUE_STRING)
    {
        root_value = &argv[0];
        class_value = &argv[1];
    }
    else if (argv[0].type == JS_VALUE_STRING)
    {
        class_value = &argv[0];
    }
    else
    {
        return true;
    }

    const char *class_name = class_value && class_value->as.string.data ? class_value->as.string.data : "";
    if (!class_name || class_name[0] == '\0')
    {
        return true;
    }

    atk_widget_t *view = (atk_widget_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        return true;
    }

    html_view_dom_lock(priv);
    html_node_t *root = (priv->doc && priv->doc->root) ? priv->doc->root : NULL;
    if (root_value)
    {
        size_t handle = 0;
        if (html_view_js_handle_from_value(root_value, &handle))
        {
            root = html_view_js_node_for_handle(priv, handle);
        }
        else
        {
            root = NULL;
        }
    }
    if (!root)
    {
        html_view_dom_unlock(priv);
        return true;
    }

    const html_node_t **stack = NULL;
    size_t stack_cap = 0;
    size_t sp = 0;

    stack_cap = 64;
    stack = (const html_node_t **)malloc(stack_cap * sizeof(*stack));
    if (!stack)
    {
        html_view_dom_unlock(priv);
        js_value_destroy(out);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    stack[sp++] = root;

    while (sp > 0)
    {
        const html_node_t *node = stack[--sp];
        if (node->type == HTML_NODE_ELEMENT && node->name)
        {
            const char *class_attr = html_attr_get(node, "class");
            if (class_attr && html_view_js_attr_has_token(class_attr, class_name))
            {
                size_t handle = html_view_js_handle_for_node(priv, (html_node_t *)node);
                if (handle && !html_view_js_array_push_handle(out, handle, error_message))
                {
                    html_view_dom_unlock(priv);
                    free(stack);
                    js_value_destroy(out);
                    return false;
                }
            }
        }
        for (const html_node_t *child = node->last_child; child; child = child->prev_sibling)
        {
            if (sp == stack_cap)
            {
                size_t new_cap = stack_cap ? (stack_cap * 2) : 64;
                const html_node_t **new_stack = (const html_node_t **)realloc(stack, new_cap * sizeof(*new_stack));
                if (!new_stack)
                {
                    break;
                }
                stack = new_stack;
                stack_cap = new_cap;
            }
            if (sp < stack_cap)
            {
                stack[sp++] = child;
            }
        }
    }

    html_view_dom_unlock(priv);
    free(stack);
    return true;
}

static bool html_view_js_view_invalidate(js_runtime_t *rt,
                                         size_t argc,
                                         const js_value_t *argv,
                                         void *user_data,
                                         js_value_t *out,
                                         char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    atk_widget_t *view = (atk_widget_t *)user_data;
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (priv)
    {
        __atomic_store_n(&priv->js_redraw_pending, 1u, __ATOMIC_RELEASE);
    }
    *out = js_value_make_undefined();
    return true;
}

static bool html_view_js_view_get_width(js_runtime_t *rt,
                                        size_t argc,
                                        const js_value_t *argv,
                                        void *user_data,
                                        js_value_t *out,
                                        char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    atk_widget_t *view = (atk_widget_t *)user_data;
    int width = view ? view->width : 0;
    *out = js_value_make_number((double)width);
    return true;
}

static bool html_view_js_view_get_height(js_runtime_t *rt,
                                         size_t argc,
                                         const js_value_t *argv,
                                         void *user_data,
                                         js_value_t *out,
                                         char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    atk_widget_t *view = (atk_widget_t *)user_data;
    int height = view ? view->height : 0;
    *out = js_value_make_number((double)height);
    return true;
}

static bool html_view_js_register_global_number(js_runtime_t *rt, const char *name, double value)
{
    if (!rt || !name)
    {
        return false;
    }
    js_value_t num = js_value_make_number(value);
    return js_runtime_set_global(rt, name, &num);
}

static bool html_view_js_register_natives(js_runtime_t *rt, atk_widget_t *view)
{
    if (!rt || !view)
    {
        return false;
    }

    if (!js_runtime_set_native(rt, "dom_get_root", html_view_js_dom_get_root, view) ||
        !js_runtime_set_native(rt, "dom_get_element_by_id", html_view_js_dom_get_element_by_id, view) ||
        !js_runtime_set_native(rt, "dom_get_type", html_view_js_dom_get_type, view) ||
        !js_runtime_set_native(rt, "dom_get_tag", html_view_js_dom_get_tag, view) ||
        !js_runtime_set_native(rt, "dom_get_attr", html_view_js_dom_get_attr, view) ||
        !js_runtime_set_native(rt, "dom_set_attr", html_view_js_dom_set_attr, view) ||
        !js_runtime_set_native(rt, "dom_get_text", html_view_js_dom_get_text, view) ||
        !js_runtime_set_native(rt, "dom_set_text", html_view_js_dom_set_text, view) ||
        !js_runtime_set_native(rt, "dom_first_child", html_view_js_dom_first_child, view) ||
        !js_runtime_set_native(rt, "dom_next_sibling", html_view_js_dom_next_sibling, view) ||
        !js_runtime_set_native(rt, "dom_parent", html_view_js_dom_parent, view) ||
        !js_runtime_set_native(rt, "dom_get_children", html_view_js_dom_get_children, view) ||
        !js_runtime_set_native(rt, "dom_get_elements_by_tag", html_view_js_dom_get_elements_by_tag, view) ||
        !js_runtime_set_native(rt, "dom_get_elements_by_class", html_view_js_dom_get_elements_by_class, view) ||
        !js_runtime_set_native(rt, "view_invalidate", html_view_js_view_invalidate, view) ||
        !js_runtime_set_native(rt, "view_get_width", html_view_js_view_get_width, view) ||
        !js_runtime_set_native(rt, "view_get_height", html_view_js_view_get_height, view))
    {
        return false;
    }

    if (!html_view_js_register_global_number(rt, "DOM_NODE_DOCUMENT", (double)HTML_NODE_DOCUMENT) ||
        !html_view_js_register_global_number(rt, "DOM_NODE_ELEMENT", (double)HTML_NODE_ELEMENT) ||
        !html_view_js_register_global_number(rt, "DOM_NODE_TEXT", (double)HTML_NODE_TEXT) ||
        !html_view_js_register_global_number(rt, "DOM_NODE_DOCTYPE", (double)HTML_NODE_DOCTYPE) ||
        !html_view_js_register_global_number(rt, "DOM_NODE_COMMENT", (double)HTML_NODE_COMMENT))
    {
        return false;
    }

    js_value_t document;
    if (!js_value_make_host_object(&document, html_view_js_document_get, NULL, NULL, view))
    {
        return false;
    }
    bool ok = js_runtime_set_global(rt, "document", &document);
    js_value_destroy(&document);
    if (!ok)
    {
        return false;
    }

    return true;
}

static bool html_view_js_runtime_ensure(atk_widget_t *view, atk_html_view_priv_t *priv)
{
    if (!view || !priv)
    {
        return false;
    }
    if (priv->js_runtime)
    {
        return true;
    }
    priv->js_runtime = js_runtime_create();
    if (!priv->js_runtime)
    {
        printf("html_view_js: runtime create failed\n");
        return false;
    }
    if (!html_view_js_register_natives(priv->js_runtime, view))
    {
        printf("html_view_js: failed to register host functions\n");
        js_runtime_destroy(priv->js_runtime);
        priv->js_runtime = NULL;
        return false;
    }
    priv->js_runtime_ready = true;
    return true;
}

static void html_view_js_runtime_destroy(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    if (priv->js_runtime)
    {
        js_runtime_destroy(priv->js_runtime);
        priv->js_runtime = NULL;
    }
    priv->js_runtime_ready = false;
}

static void html_view_js_thread(void *arg)
{
    atk_widget_t *view = (atk_widget_t *)arg;
    if (!view)
    {
        return;
    }

    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        return;
    }

    js_runtime_t *rt = priv->js_runtime;
    if (!rt)
    {
        printf("html_view_js: missing runtime\n");
        return;
    }

    size_t index = 0;
    serial_printf("[html_js] thread start tid=%llu view=%p",
                  (unsigned long long)alix_thread_self(),
                  (void *)view);
    while (!html_view_js_should_stop(priv))
    {
        if (__atomic_load_n(&priv->js_script_count, __ATOMIC_ACQUIRE) == 0u)
        {
            (void)sys_sleep_ms(2);
            continue;
        }
        html_view_dom_lock(priv);
        html_view_js_script_t *script = html_view_js_pop_script_locked(priv);
        html_view_dom_unlock(priv);

        if (!script)
        {
            (void)sys_yield();
            continue;
        }

        if (html_view_js_should_stop(priv))
        {
            free(script->source);
            free(script);
            break;
        }

        if (script->program || (script->source && script->source[0] != '\0'))
        {
            js_exec_result_t res = script->program ? js_execute(rt, script->program)
                                                   : js_eval(rt, script->source);
            if (!res.ok)
            {
                printf("html_view_js: script %u error: %s\n",
                       (unsigned)index,
                       res.error_message ? res.error_message : "<no message>");
            }
            js_exec_result_destroy(&res);
        }
        free(script->source);
        free(script);
        ++index;
    }
    serial_printf("[html_js] thread exit tid=%llu view=%p scripts=%u",
                  (unsigned long long)alix_thread_self(),
                  (void *)view,
                  (unsigned)index);
}

void html_view_js_apply_dirty(atk_widget_t *view, atk_html_view_priv_t *priv)
{
    if (!view || !priv)
    {
        return;
    }
    uint32_t dirty = html_view_js_take_dirty(priv);
    if (dirty == 0)
    {
        return;
    }
    static uint64_t last_js_log_ms = 0;
    if (html_view_js_log_throttle(&last_js_log_ms, HTML_VIEW_JS_LOG_THROTTLE_MS))
    {
        serial_printf("[html_view] js_dirty view=%p dirty=0x%08X styles=%u controls=%u render=%u",
                      (void *)view,
                      dirty,
                      (dirty & HTML_VIEW_JS_DIRTY_STYLES) ? 1u : 0u,
                      (dirty & HTML_VIEW_JS_DIRTY_CONTROLS) ? 1u : 0u,
                      (dirty & HTML_VIEW_JS_DIRTY_RENDER) ? 1u : 0u);
    }

    if (dirty & HTML_VIEW_JS_DIRTY_STYLES)
    {
        html_view_stylesheet_mark_dirty(priv);
        if (!priv->render_async && !priv->render_external)
        {
            html_view_stylesheet_rebuild_if_needed(priv);
        }
    }
    if (dirty & HTML_VIEW_JS_DIRTY_CONTROLS)
    {
        html_view_controls_clear(view, priv);
        html_view_controls_build(view, priv);
    }
    if (dirty & HTML_VIEW_JS_DIRTY_RENDER)
    {
        html_view_render_cache_mark_dirty(priv);
        priv->pressed_href = NULL;
    }
    if (dirty != 0u)
    {
        html_view_render_request(priv);
    }
}

void html_view_js_init(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    alix_mutex_init(&priv->dom_lock);
    priv->dom_lock_hold_start_ms = 0;
    priv->dom_lock_owner = 0;
    priv->dom_lock_hold_caller = 0;
    priv->js_thread = 0;
    priv->js_stop = 0;
    priv->js_dirty = 0;
    priv->js_redraw_pending = 0;
    priv->js_runtime = NULL;
    priv->js_runtime_ready = false;
    priv->js_enabled = true;
    priv->js_thread_enabled = true;
    priv->js_script_head = NULL;
    priv->js_script_tail = NULL;
    priv->js_script_count = 0;
    priv->js_listeners = NULL;
    priv->js_listener_seq = 0;
    priv->js_defer_start = 0;
    priv->js_handles = NULL;
    priv->js_handle_count = 0;
    priv->js_handle_cap = 0;
}

void html_view_js_start_thread(atk_widget_t *view, atk_html_view_priv_t *priv)
{
    if (!view || !priv)
    {
        return;
    }
    if (!priv->js_enabled || !priv->js_thread_enabled)
    {
        return;
    }
    html_view_dom_lock(priv);
    bool running = (priv->js_thread != 0);
    bool defer_start = (priv->js_defer_start != 0u);
    html_view_dom_unlock(priv);
    if (defer_start)
    {
        return;
    }
    if (running)
    {
        serial_printf("[html_js] start skip view=%p (already running)", (void *)view);
        return;
    }
    if (!html_view_js_runtime_ensure(view, priv))
    {
        html_view_dom_lock(priv);
        html_view_js_scripts_clear_locked(priv);
        html_view_dom_unlock(priv);
        return;
    }

    __atomic_store_n(&priv->js_stop, 0u, __ATOMIC_RELEASE);
    alix_thread_t thread = 0;
    if (alix_thread_create(&thread, "atk_html_js", html_view_js_thread, view) != 0)
    {
        return;
    }

    html_view_dom_lock(priv);
    priv->js_thread = thread;
    html_view_dom_unlock(priv);
    serial_printf("[html_js] start view=%p thread=%llu",
                  (void *)view,
                  (unsigned long long)thread);
}

void html_view_js_stop_thread(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return;
    }

    alix_thread_t thread = 0;
    html_view_dom_lock(priv);
    thread = priv->js_thread;
    if (thread)
    {
        __atomic_store_n(&priv->js_stop, 1u, __ATOMIC_RELEASE);
    }
    html_view_dom_unlock(priv);
    if (thread)
    {
        uint64_t start_ms = sys_time_millis();
        serial_printf("[html_js] stop begin tid=%llu", (unsigned long long)thread);
        (void)alix_thread_join(thread, NULL);
        uint64_t waited_ms = sys_time_millis() - start_ms;
        serial_printf("[html_js] stop done tid=%llu wait=%llu",
                      (unsigned long long)thread,
                      (unsigned long long)waited_ms);
        html_view_dom_lock(priv);
        if (priv->js_thread == thread)
        {
            priv->js_thread = 0;
        }
        html_view_dom_unlock(priv);
    }

    __atomic_store_n(&priv->js_stop, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&priv->js_dirty, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&priv->js_redraw_pending, 0u, __ATOMIC_RELEASE);
}

void html_view_js_stop(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return;
    }

    html_view_js_stop_thread(priv);

    html_view_dom_lock(priv);
    html_view_js_scripts_clear_locked(priv);
    html_view_js_handles_reset(priv);
    html_view_js_listeners_clear(priv, priv->js_runtime);
    priv->js_listener_seq = 0;
    html_view_dom_unlock(priv);

    html_view_js_runtime_destroy(priv);
}

void html_view_js_start(atk_widget_t *view, atk_html_view_priv_t *priv)
{
    if (!view || !priv || !priv->doc || !priv->doc->root)
    {
        return;
    }
    if (!priv->js_enabled)
    {
        return;
    }

    html_view_dom_lock(priv);
    html_view_js_script_t *scripts = html_view_js_collect_scripts(priv->doc->root);
    if (scripts)
    {
        html_view_js_scripts_append_locked(priv, scripts);
    }
    bool has_scripts = (priv->js_script_head != NULL);
    bool defer_start = (priv->js_defer_start != 0u);
    html_view_dom_unlock(priv);

    if (!has_scripts || defer_start)
    {
        return;
    }

    html_view_js_start_thread(view, priv);
}

static bool html_view_js_queue_external_impl(atk_widget_t *view,
                                             atk_html_view_priv_t *priv,
                                             const char *script_text,
                                             size_t len,
                                             bool try_only)
{
    if (!view || !priv || !script_text || len == 0)
    {
        return false;
    }
    if (!priv->js_enabled)
    {
        return false;
    }

    bool queued = false;
    bool defer_start = false;
    if (try_only)
    {
        if (!html_view_dom_try_lock(priv))
        {
            return false;
        }
    }
    else
    {
        html_view_dom_lock(priv);
    }
    queued = html_view_js_queue_source_locked(priv, script_text, len);
    defer_start = (priv->js_defer_start != 0u);
    html_view_dom_unlock(priv);
    if (!queued)
    {
        return false;
    }

    if (defer_start)
    {
        return true;
    }
    html_view_js_start_thread(view, priv);
    return true;
}

bool html_view_js_queue_external(atk_widget_t *view,
                                 atk_html_view_priv_t *priv,
                                 const char *script_text,
                                 size_t len)
{
    return html_view_js_queue_external_impl(view, priv, script_text, len, false);
}

bool html_view_js_queue_external_try(atk_widget_t *view,
                                     atk_html_view_priv_t *priv,
                                     const char *script_text,
                                     size_t len)
{
    return html_view_js_queue_external_impl(view, priv, script_text, len, true);
}

void html_view_js_shutdown(atk_widget_t *view, atk_html_view_priv_t *priv)
{
    (void)view;
    html_view_js_stop(priv);
}
