#include "atk/html_view/html_view_internal.h"

#include "ctype.h"
#include "serial.h"
#include "stdio.h"
#include "usyscall.h"

#define HTML_VIEW_DOM_LOCK_LOG_MIN_MS 2u
#define HTML_VIEW_DOM_LOCK_LOG_RATE_MS 250u

typedef struct
{
    atk_widget_t *view;
    size_t handle;
} html_view_js_dom_element_t;

static void html_view_js_start_thread(atk_widget_t *view, atk_html_view_priv_t *priv);
void html_view_js_dispatch_click(atk_widget_t *view, const html_node_t *node);
static bool html_view_js_should_stop(const atk_html_view_priv_t *priv);
static bool html_view_js_queue_source_locked(atk_html_view_priv_t *priv, const char *source, size_t len);
static bool html_view_js_queue_program_locked(atk_html_view_priv_t *priv, js_program_t *program);

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

void html_view_dom_lock(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    if (html_view_dom_try_lock(priv))
    {
        return;
    }

    uint64_t start_ms = sys_time_millis();
    alix_mutex_lock(&priv->dom_lock);
    uint64_t waited_ms = sys_time_millis() - start_ms;
    if (waited_ms >= HTML_VIEW_DOM_LOCK_LOG_MIN_MS)
    {
        static uint64_t last_log_ms = 0;
        uint64_t now_ms = sys_time_millis();
        uint64_t last = __atomic_load_n(&last_log_ms, __ATOMIC_RELAXED);
        if (now_ms - last >= HTML_VIEW_DOM_LOCK_LOG_RATE_MS)
        {
            __atomic_store_n(&last_log_ms, now_ms, __ATOMIC_RELAXED);
            serial_printf("[html_view] dom_lock wait=%u ms", (unsigned)waited_ms);
        }
    }
}

bool html_view_dom_try_lock(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return false;
    }
    return __sync_lock_test_and_set(&priv->dom_lock.state, 1u) == 0u;
}

void html_view_dom_unlock(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    alix_mutex_unlock(&priv->dom_lock);
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
    if (!priv)
    {
        return;
    }
    html_view_js_listener_t *cur = priv->js_listeners;
    priv->js_listeners = NULL;
    if (rt)
    {
        js_value_t undef = js_value_make_undefined();
        while (cur)
        {
            html_view_js_listener_t *next = cur->next;
            if (cur->handler_name)
            {
                (void)js_runtime_set_global(rt, cur->handler_name, &undef);
            }
            if (cur->call_program)
            {
                js_program_destroy(cur->call_program);
            }
            free(cur->handler_name);
            free(cur);
            cur = next;
        }
        return;
    }

    while (cur)
    {
        html_view_js_listener_t *next = cur->next;
        if (cur->call_program)
        {
            js_program_destroy(cur->call_program);
        }
        free(cur->handler_name);
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
    if (!handle_out || !value || value->type != JS_VALUE_NUMBER)
    {
        return false;
    }
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

static bool html_view_js_dispatch_click_locked(atk_html_view_priv_t *priv, size_t handle)
{
    if (!priv || handle == 0)
    {
        return false;
    }
    bool queued = false;
    for (html_view_js_listener_t *listener = priv->js_listeners; listener; listener = listener->next)
    {
        if (listener->handle == handle)
        {
            if (listener->call_program)
            {
                queued |= html_view_js_queue_program_locked(priv, listener->call_program);
            }
        }
    }
    return queued;
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
    while (tail->next)
    {
        tail = tail->next;
    }
    priv->js_script_tail = tail;
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
            *error_message = html_view_strdup("allocation failed");
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
            *error_message = html_view_strdup("allocation failed");
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
            *error_message = html_view_strdup("allocation failed");
        }
        return false;
    }
    return true;
}

static void html_view_js_dom_element_destroy(void *user_data)
{
    free(user_data);
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
    const char *event = argv[0].as.string.data ? argv[0].as.string.data : "";
    size_t event_len = argv[0].as.string.len;
    if (!(event_len == 5 && strncmp(event, "click", 5) == 0))
    {
        return true;
    }
    if (argv[1].type != JS_VALUE_FUNCTION && argv[1].type != JS_VALUE_NATIVE_FN)
    {
        return true;
    }

    atk_html_view_priv_t *priv = html_view_priv_mut(elem->view);
    if (!priv)
    {
        return true;
    }

    char name_buf[32];
    html_view_dom_lock(priv);
    uint32_t seq = ++priv->js_listener_seq;
    int name_len = snprintf(name_buf, sizeof(name_buf), "_atk_html_evt_%u", (unsigned)seq);
    if (name_len <= 0 || (size_t)name_len >= sizeof(name_buf))
    {
        html_view_dom_unlock(priv);
        if (error_message)
        {
            *error_message = html_view_strdup("listener name overflow");
        }
        return false;
    }

    char *handler_name = html_view_js_strdup_len(name_buf, (size_t)name_len);
    if (!handler_name)
    {
        html_view_dom_unlock(priv);
        if (error_message)
        {
            *error_message = html_view_strdup("allocation failed");
        }
        return false;
    }

    if (!js_runtime_set_global(rt, handler_name, &argv[1]))
    {
        html_view_dom_unlock(priv);
        free(handler_name);
        if (error_message)
        {
            *error_message = html_view_strdup("listener registration failed");
        }
        return false;
    }

    size_t call_len = (size_t)name_len + 3;
    char *call_src = (char *)malloc(call_len + 1);
    if (!call_src)
    {
        js_value_t undef = js_value_make_undefined();
        (void)js_runtime_set_global(rt, handler_name, &undef);
        html_view_dom_unlock(priv);
        free(handler_name);
        if (error_message)
        {
            *error_message = html_view_strdup("allocation failed");
        }
        return false;
    }
    memcpy(call_src, handler_name, (size_t)name_len);
    call_src[name_len] = '(';
    call_src[name_len + 1] = ')';
    call_src[name_len + 2] = ';';
    call_src[call_len] = '\0';

    js_parse_error_t parse_err = {0};
    js_program_t *call_program = js_parse(call_src, &parse_err);
    free(call_src);
    if (!call_program)
    {
        js_value_t undef = js_value_make_undefined();
        (void)js_runtime_set_global(rt, handler_name, &undef);
        html_view_dom_unlock(priv);
        free(handler_name);
        if (error_message)
        {
            *error_message = parse_err.message ? html_view_strdup(parse_err.message) : html_view_strdup("parse error");
        }
        return false;
    }

    html_view_js_listener_t *listener = (html_view_js_listener_t *)calloc(1, sizeof(*listener));
    if (!listener)
    {
        js_program_destroy(call_program);
        js_value_t undef = js_value_make_undefined();
        (void)js_runtime_set_global(rt, handler_name, &undef);
        html_view_dom_unlock(priv);
        free(handler_name);
        if (error_message)
        {
            *error_message = html_view_strdup("allocation failed");
        }
        return false;
    }
    listener->handle = elem->handle;
    listener->handler_name = handler_name;
    listener->call_program = call_program;
    listener->next = priv->js_listeners;
    priv->js_listeners = listener;
    html_view_dom_unlock(priv);
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
    if (strcmp(name, "textContent") == 0)
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
    if (strcmp(name, "addEventListener") == 0)
    {
        html_view_dom_unlock(priv);
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = html_view_js_element_add_event_listener;
        out->as.native.user_data = elem;
        return true;
    }

    html_view_dom_unlock(priv);
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
    bool is_text = (strcmp(name, "textContent") == 0);
    bool is_value = (strcmp(name, "value") == 0);
    if (!is_text && !is_value)
    {
        return true;
    }
    if (!html_view_js_value_to_string(value, &text, &text_len))
    {
        return false;
    }

    bool ok = false;
    bool styles_dirty = false;
    bool controls_dirty = false;

    atk_html_view_priv_t *priv = html_view_priv_mut(elem->view);
    if (!priv)
    {
        free(text);
        return false;
    }

    html_view_dom_lock(priv);
    html_node_t *node = html_view_js_node_for_handle(priv, elem->handle);
    if (node)
    {
        if (is_text)
        {
            ok = html_view_js_node_set_text(node, text ? text : "", text_len);
        }
        else if (is_value)
        {
            ok = html_view_js_node_set_attr(node, "value", text ? text : "");
        }
        if (ok)
        {
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
            *error_message = html_view_strdup("allocation failed");
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
            *error_message = html_view_strdup("allocation failed");
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
            *error_message = html_view_strdup("allocation failed");
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
            *error_message = html_view_strdup("allocation failed");
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

    if (dirty & HTML_VIEW_JS_DIRTY_STYLES)
    {
        html_view_stylesheet_mark_dirty(priv);
        if (!priv->render_async)
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
        html_view_render_cache_invalidate_locked(priv);
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
    priv->js_thread = 0;
    priv->js_stop = 0;
    priv->js_dirty = 0;
    priv->js_redraw_pending = 0;
    priv->js_runtime = NULL;
    priv->js_runtime_ready = false;
    priv->js_enabled = true;
    priv->js_script_head = NULL;
    priv->js_script_tail = NULL;
    priv->js_listeners = NULL;
    priv->js_listener_seq = 0;
    priv->js_handles = NULL;
    priv->js_handle_count = 0;
    priv->js_handle_cap = 0;
}

static void html_view_js_start_thread(atk_widget_t *view, atk_html_view_priv_t *priv)
{
    if (!view || !priv)
    {
        return;
    }
    html_view_dom_lock(priv);
    bool running = (priv->js_thread != 0);
    html_view_dom_unlock(priv);
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

void html_view_js_stop(atk_html_view_priv_t *priv)
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

    html_view_dom_lock(priv);
    html_view_js_script_t *scripts = html_view_js_collect_scripts(priv->doc->root);
    if (scripts)
    {
        html_view_js_scripts_append_locked(priv, scripts);
    }
    bool has_scripts = (priv->js_script_head != NULL);
    html_view_dom_unlock(priv);

    if (!has_scripts)
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

    bool queued = false;
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
    html_view_dom_unlock(priv);
    if (!queued)
    {
        return false;
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
