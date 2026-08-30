#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "web/html.h"
#include "web/html/html_internal.h"
#include "web/js.h"

typedef struct
{
    html_document_t *doc;
} test_document_t;

typedef struct
{
    html_document_t *doc;
    html_node_t *node;
} test_element_t;

static bool buf_append(char **buf, size_t *len, size_t *cap, const char *text)
{
    if (!buf || !len || !cap || !text)
    {
        return false;
    }
    size_t text_len = strlen(text);
    if (text_len == 0)
    {
        return true;
    }
    size_t needed = *len + text_len + 1;
    if (needed > *cap)
    {
        size_t new_cap = *cap ? (*cap * 2) : 64;
        while (new_cap < needed)
        {
            new_cap *= 2;
        }
        char *next = (char *)realloc(*buf, new_cap);
        if (!next)
        {
            return false;
        }
        *buf = next;
        *cap = new_cap;
    }
    memcpy((*buf) + *len, text, text_len);
    *len += text_len;
    (*buf)[*len] = '\0';
    return true;
}

static void collect_text(const html_node_t *node, char **buf, size_t *len, size_t *cap)
{
    if (!node || !buf || !len || !cap)
    {
        return;
    }
    if (node->type == HTML_NODE_TEXT && node->text)
    {
        (void)buf_append(buf, len, cap, node->text);
        return;
    }
    for (const html_node_t *child = node->first_child; child; child = child->next_sibling)
    {
        collect_text(child, buf, len, cap);
    }
}

static html_node_t *find_element_by_id(html_node_t *root, const char *id)
{
    if (!root || !id || id[0] == '\0')
    {
        return NULL;
    }
    html_node_t *stack[128];
    size_t sp = 0;
    stack[sp++] = root;
    while (sp > 0)
    {
        html_node_t *node = stack[--sp];
        if (node->type == HTML_NODE_ELEMENT && node->attrs)
        {
            const char *value = html_attr_get(node, "id");
            if (value && strcmp(value, id) == 0)
            {
                return node;
            }
        }
        for (html_node_t *child = node->last_child; child; child = child->prev_sibling)
        {
            if (sp < sizeof(stack) / sizeof(stack[0]))
            {
                stack[sp++] = child;
            }
        }
    }
    return NULL;
}

static html_node_t *create_node(html_node_type_t type)
{
    html_node_t *node = (html_node_t *)calloc(1, sizeof(*node));
    if (!node)
    {
        return NULL;
    }
    node->type = type;
    return node;
}

static void append_child(html_node_t *parent, html_node_t *child)
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

static bool node_set_text(html_node_t *node, const char *text)
{
    if (!node)
    {
        return false;
    }
    if (!text)
    {
        text = "";
    }

    size_t text_len = strlen(text);
    char *copy = node->doc
                     ? html_doc_strdup_range(node->doc, text, text + text_len, false)
                     : strdup(text);
    if (!copy)
    {
        return false;
    }

    if (node->type == HTML_NODE_TEXT)
    {
        if (!node->doc)
        {
            free(node->text);
        }
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
        target = create_node(HTML_NODE_TEXT);
        if (!target)
        {
            free(copy);
            return false;
        }
        append_child(node, target);
    }
    if (!target->doc)
    {
        free(target->text);
    }
    target->text = copy;
    return true;
}

static bool node_set_attr(html_node_t *node, const char *name, const char *value)
{
    if (!node || node->type != HTML_NODE_ELEMENT || !name || name[0] == '\0' || !value)
    {
        return false;
    }
    for (html_attr_t *attr = node->attrs; attr; attr = attr->next)
    {
        if (attr->name && strcasecmp(attr->name, name) == 0)
        {
            size_t value_len = strlen(value);
            char *copy = node->doc
                             ? html_doc_strdup_range(node->doc, value, value + value_len, false)
                             : strdup(value);
            if (!copy)
            {
                return false;
            }
            if (!node->doc)
            {
                free(attr->value);
            }
            attr->value = copy;
            return true;
        }
    }
    html_attr_t *attr = node->doc
                            ? (html_attr_t *)html_doc_alloc(node->doc, sizeof(*attr))
                            : (html_attr_t *)calloc(1, sizeof(*attr));
    if (!attr)
    {
        return false;
    }
    attr->name = node->doc
                     ? html_doc_strdup_range(node->doc, name, name + strlen(name), false)
                     : strdup(name);
    attr->value = node->doc
                      ? html_doc_strdup_range(node->doc, value, value + strlen(value), false)
                      : strdup(value);
    if (!attr->name || !attr->value)
    {
        if (!node->doc)
        {
            free(attr->name);
            free(attr->value);
            free(attr);
        }
        return false;
    }
    attr->next = node->attrs;
    node->attrs = attr;
    return true;
}

static bool value_to_string(const js_value_t *value, char **out)
{
    if (!out)
    {
        return false;
    }
    *out = NULL;
    if (!value)
    {
        *out = strdup("undefined");
        return *out != NULL;
    }
    if (value->type == JS_VALUE_STRING)
    {
        const char *text = value->as.string.data ? value->as.string.data : "";
        *out = strdup(text);
        return *out != NULL;
    }
    if (value->type == JS_VALUE_NUMBER)
    {
        char buf[64];
        int written = snprintf(buf, sizeof(buf), "%.15g", value->as.number);
        if (written < 0)
        {
            return false;
        }
        buf[sizeof(buf) - 1] = '\0';
        *out = strdup(buf);
        return *out != NULL;
    }
    if (value->type == JS_VALUE_BOOL)
    {
        *out = strdup(value->as.boolean ? "true" : "false");
        return *out != NULL;
    }
    if (value->type == JS_VALUE_NULL)
    {
        *out = strdup("null");
        return *out != NULL;
    }
    if (value->type == JS_VALUE_UNDEFINED)
    {
        *out = strdup("undefined");
        return *out != NULL;
    }
    *out = strdup("[object]");
    return *out != NULL;
}

static bool element_add_event_listener(js_runtime_t *rt,
                                       size_t argc,
                                       const js_value_t *argv,
                                       void *user_data,
                                       js_value_t *out,
                                       char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
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

static bool element_get(js_runtime_t *rt,
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
    if (!out || !name || !user_data)
    {
        return false;
    }
    test_element_t *elem = (test_element_t *)user_data;
    if (!elem->node)
    {
        *out = js_value_make_null();
        return true;
    }
    if (strcmp(name, "value") == 0)
    {
        const char *value = html_attr_get(elem->node, "value");
        if (!value)
        {
            value = "";
        }
        return js_value_make_cstring(out, value);
    }
    if (strcmp(name, "textContent") == 0)
    {
        char *text = NULL;
        size_t text_len = 0;
        size_t text_cap = 0;
        collect_text(elem->node, &text, &text_len, &text_cap);
        bool ok = js_value_make_string(out, text ? text : "", text_len);
        free(text);
        return ok;
    }
    if (strcmp(name, "addEventListener") == 0)
    {
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = element_add_event_listener;
        out->as.native.user_data = elem;
        return true;
    }
    *out = js_value_make_undefined();
    return true;
}

static bool element_set(js_runtime_t *rt,
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
    if (!name || !user_data || !value)
    {
        return false;
    }
    test_element_t *elem = (test_element_t *)user_data;
    if (!elem->node)
    {
        return false;
    }
    char *text = NULL;
    if (strcmp(name, "textContent") == 0)
    {
        if (!value_to_string(value, &text))
        {
            return false;
        }
        bool ok = node_set_text(elem->node, text);
        free(text);
        return ok;
    }
    if (strcmp(name, "value") == 0)
    {
        if (!value_to_string(value, &text))
        {
            return false;
        }
        bool ok = node_set_attr(elem->node, "value", text);
        free(text);
        return ok;
    }
    return true;
}

static void element_finalize(void *user_data)
{
    free(user_data);
}

static bool document_get_element_by_id(js_runtime_t *rt,
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
    test_document_t *doc = (test_document_t *)user_data;
    if (!doc->doc || !doc->doc->root || argc < 1 || !argv || argv[0].type != JS_VALUE_STRING)
    {
        *out = js_value_make_null();
        return true;
    }
    const char *id = argv[0].as.string.data ? argv[0].as.string.data : "";
    html_node_t *node = find_element_by_id(doc->doc->root, id);
    if (!node)
    {
        *out = js_value_make_null();
        return true;
    }
    test_element_t *elem = (test_element_t *)calloc(1, sizeof(*elem));
    if (!elem)
    {
        return false;
    }
    elem->doc = doc->doc;
    elem->node = node;
    if (!js_value_make_host_object(out, element_get, element_set, element_finalize, elem))
    {
        free(elem);
        return false;
    }
    return true;
}

static bool document_get(js_runtime_t *rt,
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
        out->as.native.fn = document_get_element_by_id;
        out->as.native.user_data = user_data;
        return true;
    }
    *out = js_value_make_undefined();
    return true;
}

static bool register_document(js_runtime_t *rt, html_document_t *doc)
{
    if (!rt || !doc)
    {
        return false;
    }
    static test_document_t wrapper;
    wrapper.doc = doc;
    js_value_t document;
    if (!js_value_make_host_object(&document, document_get, NULL, NULL, &wrapper))
    {
        return false;
    }
    bool ok = js_runtime_set_global(rt, "document", &document);
    js_value_destroy(&document);
    return ok;
}

int main(void)
{
    const char *html =
        "<!doctype html>"
        "<html>"
        "<body>"
        "<label>A:<input id=\"a\" type=\"number\" value=\"1\" /></label>"
        "<label>B:<input id=\"b\" type=\"number\" value=\"2\" /></label>"
        "<button id=\"addBtn\" type=\"button\">Add</button>"
        "<div id=\"result\">Result: (click Add)</div>"
        "</body>"
        "</html>";

    html_parse_error_t err = {0};
    html_document_t *doc = html_parse(html, &err);
    if (!doc)
    {
        printf("html_js_host_test: parse failed at %zu: %s\n", err.offset, err.message ? err.message : "unknown");
        return 1;
    }

    js_runtime_t *rt = js_runtime_create();
    if (!rt)
    {
        html_document_destroy(doc);
        printf("html_js_host_test: runtime create failed\n");
        return 1;
    }
    if (!register_document(rt, doc))
    {
        js_runtime_destroy(rt);
        html_document_destroy(doc);
        printf("html_js_host_test: register document failed\n");
        return 1;
    }

    const char *script =
        "(function () {"
        "  const aEl = document.getElementById(\"a\");"
        "  const bEl = document.getElementById(\"b\");"
        "  const btn = document.getElementById(\"addBtn\");"
        "  const resultEl = document.getElementById(\"result\");"
        "  function update() {"
        "    const a = Number(aEl.value);"
        "    const b = Number(bEl.value);"
        "    const sum = a + b;"
        "    resultEl.textContent = \"Result: \" + sum;"
        "  }"
        "  btn.addEventListener(\"click\", update);"
        "  update();"
        "})();";

    js_exec_result_t res = js_eval(rt, script);
    if (!res.ok)
    {
        printf("html_js_host_test: js error: %s\n", res.error_message ? res.error_message : "<no message>");
        js_exec_result_destroy(&res);
        js_runtime_destroy(rt);
        html_document_destroy(doc);
        return 1;
    }
    js_exec_result_destroy(&res);

    html_node_t *result = find_element_by_id(doc->root, "result");
    char *text = NULL;
    size_t text_len = 0;
    size_t text_cap = 0;
    collect_text(result, &text, &text_len, &text_cap);
    bool ok = text && strcmp(text, "Result: 3") == 0;
    if (!ok)
    {
        printf("html_js_host_test: unexpected result text: %s\n", text ? text : "<null>");
    }
    free(text);
    js_runtime_destroy(rt);
    html_document_destroy(doc);
    return ok ? 0 : 1;
}
