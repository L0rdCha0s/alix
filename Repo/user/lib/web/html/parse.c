#include "web/html/html_internal.h"

#include "ctype.h"
#include "libc.h"

typedef struct
{
    html_node_t **items;
    size_t count;
    size_t capacity;
} html_node_stack_t;

static bool html_stack_push(html_node_stack_t *stack, html_node_t *node)
{
    if (!stack)
    {
        return false;
    }
    if (stack->count == stack->capacity)
    {
        size_t new_cap = stack->capacity ? stack->capacity * 2u : 16u;
        html_node_t **new_items = (html_node_t **)realloc(stack->items, new_cap * sizeof(*new_items));
        if (!new_items)
        {
            return false;
        }
        stack->items = new_items;
        stack->capacity = new_cap;
    }
    stack->items[stack->count++] = node;
    return true;
}

static html_node_t *html_stack_top(const html_node_stack_t *stack)
{
    if (!stack || stack->count == 0)
    {
        return NULL;
    }
    return stack->items[stack->count - 1];
}

static html_node_t *html_stack_pop(html_node_stack_t *stack)
{
    if (!stack || stack->count == 0)
    {
        return NULL;
    }
    return stack->items[--stack->count];
}

static void html_stack_destroy(html_node_stack_t *stack)
{
    if (!stack)
    {
        return;
    }
    free(stack->items);
    stack->items = NULL;
    stack->count = 0;
    stack->capacity = 0;
}

static void html_error(html_parse_error_t *err, size_t offset, const char *message)
{
    if (!err)
    {
        return;
    }
    err->offset = offset;
    err->message = message;
}

static bool html_text_has_non_ws(const char *text)
{
    if (!text)
    {
        return false;
    }
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p)
    {
        if (*p >= 0x80u || !isspace(*p))
        {
            return true;
        }
    }
    return false;
}

static bool html_parent_preserves_ws(const html_node_stack_t *stack)
{
    html_node_t *parent = html_stack_top(stack);
    if (!parent || parent->type != HTML_NODE_ELEMENT || !parent->name)
    {
        return false;
    }
    return strcmp(parent->name, "pre") == 0 ||
           strcmp(parent->name, "code") == 0 ||
           strcmp(parent->name, "textarea") == 0 ||
           strcmp(parent->name, "script") == 0 ||
           strcmp(parent->name, "style") == 0;
}

static inline bool html_is_name_char(char c)
{
    unsigned char uc = (unsigned char)c;
    return isalnum(uc) || c == '-' || c == '_' || c == ':' || c == '.';
}

static void html_skip_ws(const char **p)
{
    if (!p || !*p)
    {
        return;
    }
    while (**p && isspace((unsigned char)**p))
    {
        (*p)++;
    }
}

static bool html_is_void_element(const char *tag)
{
    if (!tag || tag[0] == '\0')
    {
        return false;
    }
    /* minimal set; expand over time */
    return strcmp(tag, "meta") == 0 ||
           strcmp(tag, "link") == 0 ||
           strcmp(tag, "br") == 0 ||
           strcmp(tag, "hr") == 0 ||
           strcmp(tag, "img") == 0 ||
           strcmp(tag, "input") == 0 ||
           strcmp(tag, "area") == 0 ||
           strcmp(tag, "base") == 0 ||
           strcmp(tag, "col") == 0 ||
           strcmp(tag, "embed") == 0 ||
           strcmp(tag, "param") == 0 ||
           strcmp(tag, "source") == 0 ||
           strcmp(tag, "track") == 0 ||
           strcmp(tag, "wbr") == 0;
}

static bool html_closes_p_on_tag(const char *tag)
{
    if (!tag)
    {
        return false;
    }
    return strcmp(tag, "address") == 0 ||
           strcmp(tag, "article") == 0 ||
           strcmp(tag, "aside") == 0 ||
           strcmp(tag, "blockquote") == 0 ||
           strcmp(tag, "div") == 0 ||
           strcmp(tag, "dl") == 0 ||
           strcmp(tag, "dt") == 0 ||
           strcmp(tag, "dd") == 0 ||
           strcmp(tag, "fieldset") == 0 ||
           strcmp(tag, "footer") == 0 ||
           strcmp(tag, "form") == 0 ||
           strcmp(tag, "h1") == 0 ||
           strcmp(tag, "h2") == 0 ||
           strcmp(tag, "h3") == 0 ||
           strcmp(tag, "h4") == 0 ||
           strcmp(tag, "h5") == 0 ||
           strcmp(tag, "h6") == 0 ||
           strcmp(tag, "header") == 0 ||
           strcmp(tag, "menu") == 0 ||
           strcmp(tag, "nav") == 0 ||
           strcmp(tag, "ol") == 0 ||
           strcmp(tag, "p") == 0 ||
           strcmp(tag, "pre") == 0 ||
           strcmp(tag, "section") == 0 ||
           strcmp(tag, "table") == 0 ||
           strcmp(tag, "ul") == 0;
}

static void html_apply_implicit_closures(html_node_stack_t *stack, const char *new_tag)
{
    if (!stack || !new_tag)
    {
        return;
    }

    html_node_t *top = html_stack_top(stack);
    if (!top || top->type != HTML_NODE_ELEMENT || !top->name)
    {
        return;
    }

    if (strcmp(new_tag, "body") == 0 && strcmp(top->name, "head") == 0)
    {
        (void)html_stack_pop(stack);
        return;
    }

    if (strcmp(new_tag, "p") == 0 && strcmp(top->name, "p") == 0)
    {
        (void)html_stack_pop(stack);
        return;
    }

    if (strcmp(top->name, "p") == 0 && html_closes_p_on_tag(new_tag))
    {
        (void)html_stack_pop(stack);
        return;
    }
}

static bool html_tag_name_matches_range(const char *open_tag, const char *close_start, const char *close_end)
{
    if (!open_tag || !close_start || !close_end || close_end <= close_start)
    {
        return false;
    }
    size_t close_len = (size_t)(close_end - close_start);
    if (strlen(open_tag) != close_len)
    {
        return false;
    }
    return strncasecmp(open_tag, close_start, close_len) == 0;
}

static const char *html_strcasestr_simple(const char *haystack, const char *needle)
{
    if (!haystack || !needle || needle[0] == '\0')
    {
        return haystack;
    }

    size_t nlen = strlen(needle);
    for (const char *p = haystack; *p; ++p)
    {
        size_t i = 0;
        for (; i < nlen; ++i)
        {
            char hc = p[i];
            if (!hc)
            {
                return NULL;
            }
            if (tolower((unsigned char)hc) != tolower((unsigned char)needle[i]))
            {
                break;
            }
        }
        if (i == nlen)
        {
            return p;
        }
    }
    return NULL;
}

static bool html_parse_end_tag(const char **p, html_node_stack_t *stack)
{
    if (!p || !*p || !stack)
    {
        return false;
    }
    const char *s = *p;
    if (s[0] != '<' || s[1] != '/')
    {
        return false;
    }
    s += 2;
    html_skip_ws(&s);
    const char *name_start = s;
    while (*s && html_is_name_char(*s))
    {
        ++s;
    }
    const char *name_end = s;
    html_skip_ws(&s);

    while (*s && *s != '>')
    {
        ++s;
    }
    if (*s == '>')
    {
        ++s;
    }

    if (name_end <= name_start)
    {
        *p = s;
        return true;
    }

    while (stack->count > 1)
    {
        html_node_t *top = html_stack_top(stack);
        if (top && top->type == HTML_NODE_ELEMENT && top->name &&
            html_tag_name_matches_range(top->name, name_start, name_end))
        {
            (void)html_stack_pop(stack);
            break;
        }
        (void)html_stack_pop(stack);
    }
    *p = s;
    return true;
}

static bool html_parse_comment(const char **p)
{
    if (!p || !*p)
    {
        return false;
    }
    const char *s = *p;
    if (strncmp(s, "<!--", 4) != 0)
    {
        return false;
    }
    const char *end = strstr(s + 4, "-->");
    if (!end)
    {
        *p = s + strlen(s);
        return true;
    }
    *p = end + 3;
    return true;
}

static bool html_parse_doctype(const char **p)
{
    if (!p || !*p)
    {
        return false;
    }
    const char *s = *p;
    if (s[0] != '<' || s[1] != '!')
    {
        return false;
    }
    if (strncasecmp(s, "<!doctype", 9) != 0)
    {
        return false;
    }
    const char *gt = strchr(s, '>');
    if (!gt)
    {
        *p = s + strlen(s);
        return true;
    }
    *p = gt + 1;
    return true;
}

static bool html_parse_attrs(const char **p,
                             html_attr_t **attrs_out,
                             bool *self_closed_out,
                             html_parse_error_t *error_out,
                             size_t input_offset)
{
    if (!p || !*p || !attrs_out || !self_closed_out)
    {
        return false;
    }
    *attrs_out = NULL;
    *self_closed_out = false;

    html_attr_t *attrs_head = NULL;
    html_attr_t *attrs_tail = NULL;

    const char *s = *p;

    while (*s)
    {
        html_skip_ws(&s);
        if (*s == '\0')
        {
            break;
        }
        if (*s == '>')
        {
            ++s;
            break;
        }
        if (*s == '/' && s[1] == '>')
        {
            *self_closed_out = true;
            s += 2;
            break;
        }

        const char *name_start = s;
        while (*s && html_is_name_char(*s))
        {
            ++s;
        }
        const char *name_end = s;
        if (name_end <= name_start)
        {
            /* skip invalid byte */
            ++s;
            continue;
        }

        char *name = html_strdup_range(name_start, name_end, true);
        if (!name)
        {
            html_error(error_out, input_offset, "allocation failed");
            html_attr_free_list(attrs_head);
            return false;
        }

        html_skip_ws(&s);
        char *value = NULL;
        if (*s == '=')
        {
            ++s;
            html_skip_ws(&s);
            if (*s == '"' || *s == '\'')
            {
                char quote = *s++;
                const char *vstart = s;
                while (*s && *s != quote)
                {
                    ++s;
                }
                const char *vend = s;
                if (*s == quote)
                {
                    ++s;
                }
                value = html_strdup_decoded_range(vstart, vend);
            }
            else
            {
                const char *vstart = s;
                while (*s && !isspace((unsigned char)*s) && *s != '>' && !(*s == '/' && s[1] == '>'))
                {
                    ++s;
                }
                const char *vend = s;
                value = html_strdup_decoded_range(vstart, vend);
            }
        }
        else
        {
            value = html_strdup_range("", "", false);
        }

        if (!value)
        {
            free(name);
            html_error(error_out, input_offset, "allocation failed");
            html_attr_free_list(attrs_head);
            return false;
        }

        html_attr_t *attr = (html_attr_t *)calloc(1, sizeof(*attr));
        if (!attr)
        {
            free(name);
            free(value);
            html_error(error_out, input_offset, "allocation failed");
            html_attr_free_list(attrs_head);
            return false;
        }
        attr->name = name;
        attr->value = value;
        attr->next = NULL;

        if (!attrs_head)
        {
            attrs_head = attrs_tail = attr;
        }
        else
        {
            attrs_tail->next = attr;
            attrs_tail = attr;
        }
    }

    *attrs_out = attrs_head;
    *p = s;
    return true;
}

static bool html_parse_start_tag(const char **p,
                                 html_node_stack_t *stack,
                                 html_parse_error_t *error_out,
                                 const char *input_base)
{
    if (!p || !*p || !stack)
    {
        return false;
    }
    const char *s = *p;
    if (*s != '<' || s[1] == '/' || s[1] == '!' || s[1] == '?')
    {
        return false;
    }
    ++s;
    html_skip_ws(&s);

    const char *name_start = s;
    while (*s && html_is_name_char(*s))
    {
        ++s;
    }
    const char *name_end = s;
    if (name_end <= name_start)
    {
        return false;
    }

    char *tag = html_strdup_range(name_start, name_end, true);
    if (!tag)
    {
        html_error(error_out, (size_t)(*p - input_base), "allocation failed");
        return false;
    }

    html_apply_implicit_closures(stack, tag);

    html_attr_t *attrs = NULL;
    bool self_closed = false;
    if (!html_parse_attrs(&s, &attrs, &self_closed, error_out, (size_t)(*p - input_base)))
    {
        free(tag);
        return false;
    }

    bool is_void = html_is_void_element(tag);
    bool needs_push = (!self_closed && !is_void);

    html_node_t *node = html_node_create(HTML_NODE_ELEMENT);
    if (!node)
    {
        free(tag);
        html_attr_free_list(attrs);
        html_error(error_out, (size_t)(*p - input_base), "allocation failed");
        return false;
    }
    node->name = tag;
    node->attrs = attrs;

    html_node_t *parent = html_stack_top(stack);
    if (needs_push)
    {
        if (!html_stack_push(stack, node))
        {
            html_error(error_out, (size_t)(*p - input_base), "allocation failed");
            html_attr_free_list(attrs);
            free(tag);
            free(node);
            return false;
        }
    }

    if (parent)
    {
        html_node_append_child(parent, node);
    }

    if (strcmp(tag, "style") == 0 || strcmp(tag, "script") == 0)
    {
        const char *close_pat = (strcmp(tag, "style") == 0) ? "</style" : "</script";
        const char *end = html_strcasestr_simple(s, close_pat);
        const char *content_end = end ? end : (s + strlen(s));
        if (content_end > s)
        {
            html_node_t *text_node = html_node_create(HTML_NODE_TEXT);
            if (text_node)
            {
                text_node->text = html_strdup_range(s, content_end, false);
                html_node_append_child(node, text_node);
            }
        }
        if (end)
        {
            const char *gt = strchr(end, '>');
            s = gt ? (gt + 1) : (end + strlen(end));
        }
        else
        {
            s = content_end;
        }

        /* style/script should not remain open if we consumed until close tag. */
        if (needs_push && html_stack_top(stack) == node)
        {
            (void)html_stack_pop(stack);
        }
    }

    *p = s;
    return true;
}

static void html_append_text_node(html_node_stack_t *stack, const char *start, const char *end)
{
    if (!stack || !start || !end || end <= start)
    {
        return;
    }
    html_node_t *parent = html_stack_top(stack);
    if (!parent)
    {
        return;
    }
    bool preserve_ws = html_parent_preserves_ws(stack);
    html_node_t *text = html_node_create(HTML_NODE_TEXT);
    if (!text)
    {
        return;
    }
    text->text = html_strdup_decoded_range(start, end);
    if (!text->text)
    {
        free(text);
        return;
    }
    if (!preserve_ws && !html_text_has_non_ws(text->text))
    {
        free(text->text);
        free(text);
        return;
    }
    if (parent->last_child && parent->last_child->type == HTML_NODE_TEXT &&
        parent->last_child->text)
    {
        size_t left_len = strlen(parent->last_child->text);
        size_t right_len = strlen(text->text);
        size_t merged_len = left_len + right_len;
        char *merged = (char *)malloc(merged_len + 1);
        if (merged)
        {
            memcpy(merged, parent->last_child->text, left_len);
            memcpy(merged + left_len, text->text, right_len);
            merged[merged_len] = '\0';
            free(parent->last_child->text);
            parent->last_child->text = merged;
            free(text->text);
            free(text);
            return;
        }
    }
    html_node_append_child(parent, text);
}

html_document_t *html_parse(const char *input, html_parse_error_t *error_out)
{
    html_parse_error_t tmp_err = {0};
    if (!error_out)
    {
        error_out = &tmp_err;
    }
    html_error(error_out, 0, NULL);

    if (!input)
    {
        html_error(error_out, 0, "null input");
        return NULL;
    }

    html_document_t *doc = (html_document_t *)calloc(1, sizeof(*doc));
    if (!doc)
    {
        html_error(error_out, 0, "allocation failed");
        return NULL;
    }

    html_node_t *root = html_node_create(HTML_NODE_DOCUMENT);
    if (!root)
    {
        free(doc);
        html_error(error_out, 0, "allocation failed");
        return NULL;
    }
    doc->root = root;

    html_node_stack_t stack = {0};
    if (!html_stack_push(&stack, root))
    {
        html_document_destroy(doc);
        html_stack_destroy(&stack);
        html_error(error_out, 0, "allocation failed");
        return NULL;
    }

    const char *p = input;
    while (*p)
    {
        const char *lt = strchr(p, '<');
        if (!lt)
        {
            html_append_text_node(&stack, p, p + strlen(p));
            break;
        }
        if (lt > p)
        {
            html_append_text_node(&stack, p, lt);
        }
        p = lt;

        if (html_parse_comment(&p))
        {
            continue;
        }
        if (html_parse_doctype(&p))
        {
            continue;
        }
        if (p[0] == '<' && p[1] == '/')
        {
            if (html_parse_end_tag(&p, &stack))
            {
                continue;
            }
        }
        if (p[0] == '<' && p[1] == '?')
        {
            const char *gt = strchr(p, '>');
            p = gt ? gt + 1 : (p + strlen(p));
            continue;
        }
        if (p[0] == '<')
        {
            if (html_parse_start_tag(&p, &stack, error_out, input))
            {
                continue;
            }
            if (error_out && error_out->message)
            {
                html_document_destroy(doc);
                html_stack_destroy(&stack);
                return NULL;
            }
        }

        /* fallback: treat '<' as text */
        html_append_text_node(&stack, p, p + 1);
        ++p;
    }

    html_stack_destroy(&stack);
    return doc;
}
