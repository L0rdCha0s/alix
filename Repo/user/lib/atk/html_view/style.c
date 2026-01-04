#include "atk/html_view/html_view_internal.h"

#include "ctype.h"
#include "web/css/css_internal.h"

#ifdef HTML_VIEW_HOST_TRACE
typedef struct
{
    bool enabled;
    uint32_t rule_stride;
    uint32_t node_stride;
    uint64_t rule_checks;
    uint64_t node_visits;
} html_view_trace_state_t;

static html_view_trace_state_t g_html_view_trace_state = {0};

void html_view_trace_configure(bool enabled, uint32_t rule_stride, uint32_t node_stride)
{
    g_html_view_trace_state.enabled = enabled;
    g_html_view_trace_state.rule_stride = rule_stride ? rule_stride : 200000u;
    g_html_view_trace_state.node_stride = node_stride ? node_stride : 5000u;
    g_html_view_trace_state.rule_checks = 0;
    g_html_view_trace_state.node_visits = 0;
}

void html_view_trace_note_rule(const html_node_t *node, const char *selector, const char *phase)
{
    if (!g_html_view_trace_state.enabled || g_html_view_trace_state.rule_stride == 0)
    {
        return;
    }
    uint64_t count = ++g_html_view_trace_state.rule_checks;
    if (count % g_html_view_trace_state.rule_stride != 0)
    {
        return;
    }
    const char *tag = (node && node->name) ? node->name : "(null)";
    const char *id = node ? html_attr_get(node, "id") : NULL;
    const char *cls = node ? html_attr_get(node, "class") : NULL;
    printf("html_view_trace: phase=%s rule_checks=%llu tag=%s id=%s class=%s selector=%.96s\n",
           phase ? phase : "style",
           (unsigned long long)count,
           tag,
           id ? id : "(null)",
           cls ? cls : "(null)",
           selector ? selector : "(null)");
}

void html_view_trace_note_node(const html_node_t *node, const char *phase)
{
    if (!g_html_view_trace_state.enabled || g_html_view_trace_state.node_stride == 0)
    {
        return;
    }
    uint64_t count = ++g_html_view_trace_state.node_visits;
    if (count % g_html_view_trace_state.node_stride != 0)
    {
        return;
    }
    const char *tag = (node && node->name) ? node->name : "(null)";
    const char *id = node ? html_attr_get(node, "id") : NULL;
    const char *cls = node ? html_attr_get(node, "class") : NULL;
    printf("html_view_trace: phase=%s node_visits=%llu tag=%s id=%s class=%s\n",
           phase ? phase : "render",
           (unsigned long long)count,
           tag,
           id ? id : "(null)",
           cls ? cls : "(null)");
}
#endif

enum
{
    HTML_VIEW_PSEUDO_MASK_NONE = 1u << 0,
    HTML_VIEW_PSEUDO_MASK_BEFORE = 1u << 1,
    HTML_VIEW_PSEUDO_MASK_AFTER = 1u << 2,
};

static uint8_t html_view_pseudo_mask(html_view_pseudo_t pseudo)
{
    switch (pseudo)
    {
    case HTML_VIEW_PSEUDO_BEFORE:
        return HTML_VIEW_PSEUDO_MASK_BEFORE;
    case HTML_VIEW_PSEUDO_AFTER:
        return HTML_VIEW_PSEUDO_MASK_AFTER;
    default:
        return HTML_VIEW_PSEUDO_MASK_NONE;
    }
}

static void html_view_trim_range(const char **start, const char **end)
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

static void html_view_style_inherit_from_parent(css_style_t *out, const css_style_t *parent, bool inherit_text_align)
{
    if (!out || !parent)
    {
        return;
    }
    if (parent->has_color)
    {
        out->has_color = true;
        out->color = parent->color;
    }
    if (parent->has_font_size)
    {
        out->has_font_size = true;
        out->font_size = parent->font_size;
    }
    if (parent->has_line_height)
    {
        out->has_line_height = true;
        out->line_height_milli = parent->line_height_milli;
        out->line_height_is_length = parent->line_height_is_length;
        out->line_height = parent->line_height;
    }
    if (inherit_text_align && parent->has_text_align)
    {
        out->has_text_align = true;
        out->text_align = parent->text_align;
    }
    if (parent->has_letter_spacing)
    {
        out->has_letter_spacing = true;
        out->letter_spacing = parent->letter_spacing;
    }
}

static void html_view_resolve_float_inherit(css_style_t *style, const css_style_t *parent)
{
    if (!style || !style->has_float || !style->float_inherit)
    {
        return;
    }
    if (parent && parent->has_float)
    {
        style->float_mode = parent->float_mode;
    }
    else
    {
        style->float_mode = CSS_FLOAT_NONE;
    }
    style->float_inherit = false;
}

static const html_node_t *html_view_prev_element_sibling(const html_node_t *node)
{
    if (!node)
    {
        return NULL;
    }
    for (const html_node_t *p = node->prev_sibling; p; p = p->prev_sibling)
    {
        if (p->type == HTML_NODE_ELEMENT)
        {
            return p;
        }
    }
    return NULL;
}

static char *html_view_unescape_selector_value(const char *start, const char *end);

static uint64_t html_view_bloom_hash_range_ci(const char *start, const char *end, bool unescape)
{
    if (!start || !end || end <= start)
    {
        return 0;
    }
    uint64_t h = 1469598103934665603ull;
    for (const char *p = start; p < end; ++p)
    {
        char c = *p;
        if (unescape && c == '\\' && (p + 1) < end)
        {
            ++p;
            c = *p;
        }
        c = (char)tolower((unsigned char)c);
        h ^= (uint64_t)(unsigned char)c;
        h *= 1099511628211ull;
    }
    return h;
}

static bool html_view_bloom_is_zero(const web_bloom_t *mask)
{
    if (!mask)
    {
        return true;
    }
    for (size_t i = 0; i < WEB_BLOOM_WORDS; ++i)
    {
        if (mask->bits[i] != 0)
        {
            return false;
        }
    }
    return true;
}

static void html_view_bloom_clear(web_bloom_t *mask)
{
    if (!mask)
    {
        return;
    }
    memset(mask->bits, 0, sizeof(mask->bits));
}

static void html_view_bloom_set_bit(web_bloom_t *mask, uint8_t bit)
{
    if (!mask)
    {
        return;
    }
    size_t word = (size_t)(bit >> 6);
    size_t offset = (size_t)(bit & 63u);
    mask->bits[word] |= (1ull << offset);
}

static void html_view_bloom_add_hash(web_bloom_t *mask, uint64_t h)
{
    html_view_bloom_set_bit(mask, (uint8_t)(h & 0xffu));
    html_view_bloom_set_bit(mask, (uint8_t)((h >> 8) & 0xffu));
    html_view_bloom_set_bit(mask, (uint8_t)((h >> 16) & 0xffu));
    html_view_bloom_set_bit(mask, (uint8_t)((h >> 24) & 0xffu));
}

static bool html_view_bloom_contains(const web_bloom_t *mask, const web_bloom_t *need)
{
    if (!mask || !need)
    {
        return false;
    }
    for (size_t i = 0; i < WEB_BLOOM_WORDS; ++i)
    {
        if ((mask->bits[i] & need->bits[i]) != need->bits[i])
        {
            return false;
        }
    }
    return true;
}

static void html_view_bloom_add_range(web_bloom_t *mask,
                                      const char *start,
                                      const char *end,
                                      bool unescape)
{
    if (!mask || !start || !end || end <= start)
    {
        return;
    }
    uint64_t h = html_view_bloom_hash_range_ci(start, end, unescape);
    if (h == 0)
    {
        return;
    }
    html_view_bloom_add_hash(mask, h);
}

static void html_view_bloom_add_cstr(web_bloom_t *mask, const char *s)
{
    if (!mask || !s || s[0] == '\0')
    {
        return;
    }
    html_view_bloom_add_range(mask, s, s + strlen(s), false);
}

static const html_class_token_t *html_view_node_class_tokens(const html_node_t *node,
                                                             size_t *out_count,
                                                             const char **out_class_value)
{
    if (out_count)
    {
        *out_count = 0;
    }
    if (out_class_value)
    {
        *out_class_value = NULL;
    }
    if (!node || node->type != HTML_NODE_ELEMENT)
    {
        return NULL;
    }

    const char *classes = html_attr_get(node, "class");
    if (!classes || classes[0] == '\0')
    {
        return NULL;
    }
    if (out_class_value)
    {
        *out_class_value = classes;
    }

    html_node_t *mut = (html_node_t *)node;
    if (mut->class_cache_value != classes)
    {
        free(mut->class_tokens);
        mut->class_tokens = NULL;
        mut->class_token_count = 0;
        mut->class_token_cap = 0;
        mut->class_cache_value = classes;

        const char *p = classes;
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
            if (len == 0)
            {
                continue;
            }
            if (mut->class_token_count == mut->class_token_cap)
            {
                size_t new_cap = mut->class_token_cap ? (mut->class_token_cap * 2) : 8;
                html_class_token_t *next = (html_class_token_t *)realloc(mut->class_tokens,
                                                                         new_cap * sizeof(*next));
                if (!next)
                {
                    free(mut->class_tokens);
                    mut->class_tokens = NULL;
                    mut->class_token_count = 0;
                    mut->class_token_cap = 0;
                    break;
                }
                mut->class_tokens = next;
                mut->class_token_cap = new_cap;
            }
            mut->class_tokens[mut->class_token_count++] = (html_class_token_t){
                .start = start,
                .len = len,
            };
        }
    }

    if (out_count)
    {
        *out_count = mut->class_token_count;
    }
    return mut->class_tokens;
}

static web_bloom_t html_view_node_self_bloom(const html_node_t *node)
{
    web_bloom_t mask = {0};
    if (!node || node->type != HTML_NODE_ELEMENT)
    {
        return mask;
    }

    if (node->name && node->name[0] != '\0')
    {
        html_view_bloom_add_cstr(&mask, node->name);
    }

    const char *id = html_attr_get(node, "id");
    if (id && id[0] != '\0')
    {
        html_view_bloom_add_cstr(&mask, id);
    }

    size_t token_count = 0;
    const char *classes = NULL;
    const html_class_token_t *tokens = html_view_node_class_tokens(node, &token_count, &classes);
    if (tokens && token_count > 0)
    {
        for (size_t i = 0; i < token_count; ++i)
        {
            const html_class_token_t *tok = &tokens[i];
            if (tok->len == 0)
            {
                continue;
            }
            html_view_bloom_add_range(&mask, tok->start, tok->start + tok->len, false);
        }
    }
    else if (classes && classes[0] != '\0')
    {
        const char *p = classes;
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
            if (p > start)
            {
                html_view_bloom_add_range(&mask, start, p, false);
            }
        }
    }

    for (const html_attr_t *attr = node->attrs; attr; attr = attr->next)
    {
        if (attr->name && attr->name[0] != '\0')
        {
            html_view_bloom_add_cstr(&mask, attr->name);
        }
    }

    return mask;
}

void html_view_dom_bloom_mark_dirty(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    __atomic_store_n(&priv->dom_bloom_dirty, 1u, __ATOMIC_RELEASE);
}

void html_view_dom_bloom_rebuild_if_needed(atk_html_view_priv_t *priv)
{
    if (!priv || !priv->doc || !priv->doc->root)
    {
        return;
    }
    if (__atomic_exchange_n(&priv->dom_bloom_dirty, 0u, __ATOMIC_ACQ_REL) == 0u)
    {
        return;
    }

    typedef struct
    {
        html_node_t *node;
        web_bloom_t parent_bloom;
    } html_view_bloom_entry_t;

    size_t cap = 128;
    size_t count = 0;
    html_view_bloom_entry_t *stack = (html_view_bloom_entry_t *)malloc(cap * sizeof(*stack));
    if (!stack)
    {
        __atomic_store_n(&priv->dom_bloom_dirty, 1u, __ATOMIC_RELEASE);
        return;
    }

    stack[count++] = (html_view_bloom_entry_t){
        .node = priv->doc->root,
        .parent_bloom = {{0}},
    };

    while (count > 0)
    {
        html_view_bloom_entry_t entry = stack[--count];
        html_node_t *node = entry.node;
        if (!node)
        {
            continue;
        }

        web_bloom_t self_bloom = html_view_node_self_bloom(node);
        node->self_bloom = self_bloom;
        for (size_t i = 0; i < WEB_BLOOM_WORDS; ++i)
        {
            node->ancestor_bloom.bits[i] = entry.parent_bloom.bits[i] | self_bloom.bits[i];
        }

        web_bloom_t next_parent = node->ancestor_bloom;
        for (html_node_t *child = node->first_child; child; child = child->next_sibling)
        {
            if (count == cap)
            {
                size_t new_cap = cap ? (cap * 2u) : 128u;
                html_view_bloom_entry_t *next = (html_view_bloom_entry_t *)realloc(stack,
                                                                                   new_cap * sizeof(*next));
                if (!next)
                {
                    break;
                }
                stack = next;
                cap = new_cap;
            }
            stack[count++] = (html_view_bloom_entry_t){
                .node = child,
                .parent_bloom = next_parent,
            };
        }
    }

    free(stack);
}

static bool html_view_node_has_class_raw(const html_node_t *node, const char *cls_start, size_t cls_len)
{
    if (!node || node->type != HTML_NODE_ELEMENT || !cls_start || cls_len == 0)
    {
        return false;
    }

    const char *classes = NULL;
    size_t token_count = 0;
    const html_class_token_t *tokens = html_view_node_class_tokens(node, &token_count, &classes);
    if (tokens && token_count > 0)
    {
        for (size_t i = 0; i < token_count; ++i)
        {
            const html_class_token_t *tok = &tokens[i];
            if (tok->len == cls_len && strncasecmp(tok->start, cls_start, cls_len) == 0)
            {
                return true;
            }
        }
        return false;
    }

    if (!classes || classes[0] == '\0')
    {
        return false;
    }

    const char *p = classes;
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
        if (len == cls_len && strncasecmp(start, cls_start, cls_len) == 0)
        {
            return true;
        }
    }

    return false;
}

static bool html_view_node_has_class(const html_node_t *node, const char *cls_start, size_t cls_len)
{
    if (!node || node->type != HTML_NODE_ELEMENT || !cls_start || cls_len == 0)
    {
        return false;
    }

    for (size_t i = 0; i < cls_len; ++i)
    {
        if (cls_start[i] == '\\')
        {
            char *unescaped = html_view_unescape_selector_value(cls_start, cls_start + cls_len);
            if (!unescaped)
            {
                return false;
            }
            bool match = html_view_node_has_class_raw(node, unescaped, strlen(unescaped));
            free(unescaped);
            return match;
        }
    }

    return html_view_node_has_class_raw(node, cls_start, cls_len);
}

static bool html_view_attr_value_has_token(const char *value, const char *token)
{
    if (!value || !token || token[0] == '\0')
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
        if (len > 0 && strlen(token) == len && strncasecmp(start, token, len) == 0)
        {
            return true;
        }
    }
    return false;
}

static bool html_view_selector_range_eq_ci_token(const char *token,
                                                 size_t token_len,
                                                 const char *sel_start,
                                                 size_t sel_len)
{
    if (!token || token_len == 0 || !sel_start || sel_len == 0)
    {
        return false;
    }
    const char *sel_end = sel_start + sel_len;
    size_t ti = 0;
    for (const char *p = sel_start; p < sel_end; ++p)
    {
        char c = *p;
        if (c == '\\' && (p + 1) < sel_end)
        {
            ++p;
            c = *p;
        }
        if (ti >= token_len)
        {
            return false;
        }
        if (tolower((unsigned char)c) != tolower((unsigned char)token[ti]))
        {
            return false;
        }
        ++ti;
    }
    return ti == token_len;
}

static bool html_view_selector_range_eq_ci(const char *value,
                                           const char *sel_start,
                                           size_t sel_len)
{
    if (!value || !sel_start || sel_len == 0)
    {
        return false;
    }
    size_t value_len = strlen(value);
    return html_view_selector_range_eq_ci_token(value, value_len, sel_start, sel_len);
}

static bool html_view_selector_range_has_space(const char *sel_start, const char *sel_end)
{
    if (!sel_start || !sel_end || sel_end <= sel_start)
    {
        return false;
    }
    for (const char *p = sel_start; p < sel_end; ++p)
    {
        if (*p == '\\' && (p + 1) < sel_end)
        {
            if (isspace((unsigned char)p[1]))
            {
                return true;
            }
            ++p;
            continue;
        }
        if (isspace((unsigned char)*p))
        {
            return true;
        }
    }
    return false;
}

static bool html_view_attr_value_has_token_range(const char *value,
                                                 const char *sel_start,
                                                 size_t sel_len)
{
    if (!value || !sel_start || sel_len == 0)
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
        if (len > 0 && html_view_selector_range_eq_ci_token(start, len, sel_start, sel_len))
        {
            return true;
        }
    }
    return false;
}

static char *html_view_unescape_selector_value(const char *start, const char *end)
{
    if (!start || !end || end < start)
    {
        return NULL;
    }
    size_t cap = (size_t)(end - start) + 1;
    char *out = (char *)malloc(cap);
    if (!out)
    {
        return NULL;
    }
    size_t len = 0;
    for (const char *p = start; p < end; ++p)
    {
        if (*p == '\\' && (p + 1) < end)
        {
            ++p;
        }
        out[len++] = *p;
    }
    out[len] = '\0';
    return out;
}

static bool html_view_parse_attr_selector_meta(const char **p,
                                               const char *sel_end,
                                               const char **name_start,
                                               const char **name_end,
                                               char *op_out,
                                               const char **value_start,
                                               const char **value_end,
                                               bool *unsupported_op)
{
    if (!p || !*p || !sel_end)
    {
        return false;
    }
    if (name_start)
    {
        *name_start = NULL;
    }
    if (name_end)
    {
        *name_end = NULL;
    }
    if (op_out)
    {
        *op_out = 0;
    }
    if (value_start)
    {
        *value_start = NULL;
    }
    if (value_end)
    {
        *value_end = NULL;
    }
    if (unsupported_op)
    {
        *unsupported_op = false;
    }

    const char *s = *p;
    if (*s != '[')
    {
        return false;
    }
    ++s;
    while (s < sel_end && isspace((unsigned char)*s))
    {
        ++s;
    }

    const char *nstart = s;
    while (s < sel_end && (isalnum((unsigned char)*s) || *s == '-' || *s == '_'))
    {
        ++s;
    }
    const char *nend = s;
    if (nend <= nstart)
    {
        return false;
    }

    while (s < sel_end && isspace((unsigned char)*s))
    {
        ++s;
    }

    char op = 0;
    bool unsupported = false;
    if (s < sel_end && *s == ']')
    {
        op = 0;
    }
    else if (s + 1 < sel_end && s[0] == '~' && s[1] == '=')
    {
        op = '~';
        s += 2;
    }
    else if (s + 1 < sel_end && s[0] == '^' && s[1] == '=')
    {
        op = '^';
        unsupported = true;
        s += 2;
    }
    else if (s + 1 < sel_end && s[0] == '$' && s[1] == '=')
    {
        op = '$';
        unsupported = true;
        s += 2;
    }
    else if (s + 1 < sel_end && s[0] == '*' && s[1] == '=')
    {
        op = '*';
        unsupported = true;
        s += 2;
    }
    else if (s + 1 < sel_end && s[0] == '|' && s[1] == '=')
    {
        op = '|';
        unsupported = true;
        s += 2;
    }
    else if (s < sel_end && *s == '=')
    {
        op = '=';
        ++s;
    }
    else
    {
        return false;
    }

    while (s < sel_end && isspace((unsigned char)*s))
    {
        ++s;
    }

    const char *vstart = NULL;
    const char *vend = NULL;
    if (op != 0)
    {
        if (s >= sel_end)
        {
            return false;
        }
        if (*s == '"' || *s == '\'')
        {
            char quote = *s++;
            vstart = s;
            while (s < sel_end && *s != quote)
            {
                if (*s == '\\' && (s + 1) < sel_end)
                {
                    s += 2;
                    continue;
                }
                ++s;
            }
            vend = s;
            if (s < sel_end && *s == quote)
            {
                ++s;
            }
        }
        else
        {
            vstart = s;
            while (s < sel_end)
            {
                if (*s == '\\' && (s + 1) < sel_end)
                {
                    s += 2;
                    continue;
                }
                if (isspace((unsigned char)*s) || *s == ']')
                {
                    break;
                }
                ++s;
            }
            vend = s;
        }
    }

    while (s < sel_end && isspace((unsigned char)*s))
    {
        ++s;
    }
    if (s >= sel_end || *s != ']')
    {
        return false;
    }
    ++s;

    if (name_start)
    {
        *name_start = nstart;
    }
    if (name_end)
    {
        *name_end = nend;
    }
    if (op_out)
    {
        *op_out = op;
    }
    if (value_start)
    {
        *value_start = vstart;
    }
    if (value_end)
    {
        *value_end = vend;
    }
    if (unsupported_op)
    {
        *unsupported_op = unsupported;
    }

    *p = s;
    return true;
}

static const char *html_view_attr_get_range(const html_node_t *node,
                                            const char *name_start,
                                            size_t name_len)
{
    if (!node || node->type != HTML_NODE_ELEMENT || !name_start || name_len == 0)
    {
        return NULL;
    }
    for (const html_attr_t *attr = node->attrs; attr; attr = attr->next)
    {
        if (!attr->name || attr->name[0] == '\0')
        {
            continue;
        }
        if (html_view_selector_range_eq_ci(attr->name, name_start, name_len))
        {
            return attr->value;
        }
    }
    return NULL;
}

static bool html_view_parse_attr_selector(const char **p,
                                          const char *sel_end,
                                          const html_node_t *node)
{
    if (!p || !*p || !sel_end || !node || node->type != HTML_NODE_ELEMENT)
    {
        return false;
    }

    const char *s = *p;
    if (*s != '[')
    {
        return false;
    }
    ++s;
    while (s < sel_end && isspace((unsigned char)*s))
    {
        ++s;
    }

    const char *name_start = s;
    while (s < sel_end && (isalnum((unsigned char)*s) || *s == '-' || *s == '_'))
    {
        ++s;
    }
    const char *name_end = s;
    if (name_end <= name_start)
    {
        return false;
    }

    while (s < sel_end && isspace((unsigned char)*s))
    {
        ++s;
    }

    char op = 0;
    if (s < sel_end && *s == ']')
    {
        op = 0;
    }
    else if (s + 1 < sel_end && s[0] == '~' && s[1] == '=')
    {
        op = '~';
        s += 2;
    }
    else if (s < sel_end && *s == '=')
    {
        op = '=';
        ++s;
    }
    else
    {
        return false;
    }

    while (s < sel_end && isspace((unsigned char)*s))
    {
        ++s;
    }

    char *value = NULL;
    if (op != 0)
    {
        if (s >= sel_end)
        {
            return false;
        }
        if (*s == '"' || *s == '\'')
        {
            char quote = *s++;
            const char *vstart = s;
            while (s < sel_end && *s != quote)
            {
                if (*s == '\\' && (s + 1) < sel_end)
                {
                    s += 2;
                    continue;
                }
                ++s;
            }
            const char *vend = s;
            if (s < sel_end && *s == quote)
            {
                ++s;
            }
            value = html_view_unescape_selector_value(vstart, vend);
        }
        else
        {
            const char *vstart = s;
            while (s < sel_end)
            {
                if (*s == '\\' && (s + 1) < sel_end)
                {
                    s += 2;
                    continue;
                }
                if (isspace((unsigned char)*s) || *s == ']')
                {
                    break;
                }
                ++s;
            }
            value = html_view_unescape_selector_value(vstart, s);
        }
        if (!value)
        {
            return false;
        }
    }

    while (s < sel_end && isspace((unsigned char)*s))
    {
        ++s;
    }
    if (s >= sel_end || *s != ']')
    {
        free(value);
        return false;
    }
    ++s;

    char *name = html_view_unescape_selector_value(name_start, name_end);
    if (!name)
    {
        free(value);
        return false;
    }

    bool match = false;
    const char *attr_value = html_attr_get(node, name);
    if (!attr_value)
    {
        match = false;
    }
    else if (op == 0)
    {
        match = true;
    }
    else if (op == '=')
    {
        match = (strcasecmp(attr_value, value) == 0);
    }
    else if (op == '~')
    {
        bool has_ws = false;
        for (const char *c = value; c && *c; ++c)
        {
            if (isspace((unsigned char)*c))
            {
                has_ws = true;
                break;
            }
        }
        if (!has_ws)
        {
            if (strcasecmp(name, "class") == 0)
            {
                match = html_view_node_has_class(node, value, strlen(value));
            }
            else
            {
                match = html_view_attr_value_has_token(attr_value, value);
            }
        }
    }

    free(name);
    free(value);
    *p = s;
    return match;
}

static bool html_view_simple_selector_matches_range_internal(const char *sel_start,
                                                             const char *sel_end,
                                                             const html_node_t *node,
                                                             html_view_pseudo_t pseudo)
{
    if (!sel_start || !sel_end || sel_end <= sel_start || !node || node->type != HTML_NODE_ELEMENT || !node->name)
    {
        return false;
    }

    html_view_trim_range(&sel_start, &sel_end);
    if (sel_end <= sel_start)
    {
        return false;
    }

    const char *p = sel_start;
    bool have_tag = false;
    bool match = true;
    bool require_link = false;
    bool pseudo_seen = false;

    if (*p == '*')
    {
        ++p;
    }
    else if (*p != '#' && *p != '.' && *p != '[' && *p != ':')
    {
        const char *tag_end = p;
        while (tag_end < sel_end && *tag_end != ':' && *tag_end != '.' && *tag_end != '#' && *tag_end != '[' && !isspace((unsigned char)*tag_end))
        {
            tag_end++;
        }
        size_t tag_len = (size_t)(tag_end - p);
        if (tag_len == 0 || strlen(node->name) != tag_len || strncasecmp(node->name, p, tag_len) != 0)
        {
            match = false;
        }
        have_tag = true;
        p = tag_end;
    }

    (void)have_tag;

    while (match && p < sel_end)
    {
        if (*p == '.')
        {
            ++p;
            const char *cls_end = p;
            while (cls_end < sel_end && *cls_end != ':' && *cls_end != '.' && *cls_end != '#' && *cls_end != '[' && !isspace((unsigned char)*cls_end))
            {
                cls_end++;
            }
            size_t cls_len = (size_t)(cls_end - p);
            if (cls_len == 0 || !html_view_node_has_class(node, p, cls_len))
            {
                match = false;
                break;
            }
            p = cls_end;
            continue;
        }

        if (*p == '#')
        {
            ++p;
            const char *id_end = p;
            while (id_end < sel_end && *id_end != ':' && *id_end != '.' && *id_end != '#' && *id_end != '[' && !isspace((unsigned char)*id_end))
            {
                id_end++;
            }
            size_t id_len = (size_t)(id_end - p);
            const char *id = (id_len > 0) ? html_attr_get(node, "id") : NULL;
            if (!id || strlen(id) != id_len || strncasecmp(id, p, id_len) != 0)
            {
                match = false;
                break;
            }
            p = id_end;
            continue;
        }

        if (*p == '[')
        {
            bool attr_match = html_view_parse_attr_selector(&p, sel_end, node);
            if (!attr_match)
            {
                match = false;
            }
            continue;
        }

        if (*p == ':')
        {
            const char *name = p + 1;
            if (name < sel_end && *name == ':')
            {
                ++name;
            }
            const char *name_end = name;
            while (name_end < sel_end &&
                   (isalnum((unsigned char)*name_end) || *name_end == '-' || *name_end == '_'))
            {
                ++name_end;
            }
            if (name_end == name)
            {
                match = false;
                break;
            }
            if (name_end < sel_end && *name_end == '(')
            {
                match = false;
                break;
            }
            size_t name_len = (size_t)(name_end - name);
            if (name_len == 4 && strncasecmp(name, "link", 4) == 0)
            {
                require_link = true;
            }
            else if (name_len == 7 && strncasecmp(name, "visited", 7) == 0)
            {
                match = false;
                break;
            }
            else if (name_len == 5 && strncasecmp(name, "hover", 5) == 0)
            {
                match = false;
                break;
            }
            else if (name_len == 6 && strncasecmp(name, "before", 6) == 0)
            {
                if (pseudo == HTML_VIEW_PSEUDO_BEFORE)
                {
                    pseudo_seen = true;
                }
                else
                {
                    match = false;
                    break;
                }
            }
            else if (name_len == 5 && strncasecmp(name, "after", 5) == 0)
            {
                if (pseudo == HTML_VIEW_PSEUDO_AFTER)
                {
                    pseudo_seen = true;
                }
                else
                {
                    match = false;
                    break;
                }
            }
            else
            {
                match = false;
                break;
            }
            p = name_end;
            continue;
        }

        if (*p == '>' || *p == '+' || *p == '~' || isspace((unsigned char)*p))
        {
            break;
        }

        ++p;
    }

    if (match && require_link)
    {
        if (strcasecmp(node->name, "a") != 0)
        {
            match = false;
        }
        else
        {
            const char *href = html_attr_get(node, "href");
            if (!href || href[0] == '\0')
            {
                match = false;
            }
        }
    }

    if (match && pseudo != HTML_VIEW_PSEUDO_NONE && !pseudo_seen)
    {
        match = false;
    }

    return match;
}

static bool html_view_selector_cache_push(css_selector_cache_t *cache,
                                          uint32_t start,
                                          uint32_t end,
                                          char combinator)
{
    if (!cache || start >= end)
    {
        return false;
    }
    if (cache->count == cache->cap)
    {
        size_t new_cap = cache->cap ? (cache->cap * 2u) : 8u;
        css_selector_part_t *next = (css_selector_part_t *)realloc(cache->parts,
                                                                   new_cap * sizeof(*next));
        if (!next)
        {
            return false;
        }
        cache->parts = next;
        cache->cap = new_cap;
    }
    cache->parts[cache->count++] = (css_selector_part_t){
        .start = start,
        .end = end,
        .combinator = combinator,
    };
    return true;
}

static void html_view_selector_cache_set_hints(css_selector_cache_t *cache, const char *selector)
{
    if (!cache)
    {
        return;
    }
    cache->tag_hint_valid = false;
    cache->tag_hint_any = false;
    cache->tag_hint_start = 0;
    cache->tag_hint_len = 0;
    cache->class_hint_valid = false;
    cache->class_hint_start = 0;
    cache->class_hint_len = 0;
    cache->scope_class_hint_valid = false;
    cache->scope_class_hint_start = 0;
    cache->scope_class_hint_len = 0;
    cache->parent_class_hint_valid = false;
    cache->parent_class_hint_start = 0;
    cache->parent_class_hint_len = 0;
    cache->id_hint_valid = false;
    cache->id_hint_start = 0;
    cache->id_hint_len = 0;
    if (!selector || cache->count == 0)
    {
        return;
    }

    const css_selector_part_t *part = &cache->parts[cache->count - 1];
    const char *part_start = selector + part->start;
    const char *part_end = selector + part->end;
    html_view_trim_range(&part_start, &part_end);
    if (part_end <= part_start)
    {
        return;
    }
    bool can_tag_hint = true;
    if (*part_start == '*')
    {
        cache->tag_hint_any = true;
        can_tag_hint = false;
    }
    if (*part_start == '#' || *part_start == '.' || *part_start == '[' || *part_start == ':')
    {
        can_tag_hint = false;
    }
    if (can_tag_hint)
    {
        const char *tag_end = part_start;
        while (tag_end < part_end &&
               *tag_end != ':' && *tag_end != '.' && *tag_end != '#' && *tag_end != '[' &&
               !isspace((unsigned char)*tag_end))
        {
            ++tag_end;
        }
        size_t tag_len = (size_t)(tag_end - part_start);
        if (tag_len > 0)
        {
            cache->tag_hint_valid = true;
            cache->tag_hint_start = (uint32_t)(part_start - selector);
            cache->tag_hint_len = (uint32_t)tag_len;
        }
    }

    const char *class_start = NULL;
    const char *class_end = NULL;
    const char *id_start = NULL;
    const char *id_end = NULL;
    bool escape = false;
    char quote = 0;
    int bracket_depth = 0;
    int paren_depth = 0;
    const char *p = part_start;
    while (p < part_end)
    {
        char c = *p;
        if (escape)
        {
            escape = false;
            ++p;
            continue;
        }
        if (c == '\\')
        {
            escape = true;
            ++p;
            continue;
        }
        if (quote)
        {
            if (c == quote)
            {
                quote = 0;
            }
            ++p;
            continue;
        }
        if (c == '"' || c == '\'')
        {
            quote = c;
            ++p;
            continue;
        }
        if (bracket_depth == 0 && paren_depth == 0 && c == '[')
        {
            const char *name_start = NULL;
            const char *name_end = NULL;
            const char *value_start = NULL;
            const char *value_end = NULL;
            char op = 0;
            bool unsupported = false;
            const char *scan = p;
            if (html_view_parse_attr_selector_meta(&scan,
                                                   part_end,
                                                   &name_start,
                                                   &name_end,
                                                   &op,
                                                   &value_start,
                                                   &value_end,
                                                   &unsupported))
            {
                if (name_start && name_end && name_end > name_start)
                {
                    html_view_bloom_add_range(&cache->ancestor_bloom_mask, name_start, name_end, true);
                }
                p = scan;
                continue;
            }
        }
        if (c == '[')
        {
            ++bracket_depth;
            ++p;
            continue;
        }
        if (c == ']' && bracket_depth > 0)
        {
            --bracket_depth;
            ++p;
            continue;
        }
        if (bracket_depth == 0)
        {
            if (c == '(')
            {
                ++paren_depth;
                ++p;
                continue;
            }
            if (c == ')' && paren_depth > 0)
            {
                --paren_depth;
                ++p;
                continue;
            }
        }
        if (bracket_depth == 0 && paren_depth == 0 && (c == '#' || c == '.'))
        {
            const char *name_start = p + 1;
            const char *q = name_start;
            bool token_escape = false;
            while (q < part_end)
            {
                char qc = *q;
                if (token_escape)
                {
                    token_escape = false;
                    ++q;
                    continue;
                }
                if (qc == '\\')
                {
                    token_escape = true;
                    ++q;
                    continue;
                }
                if (qc == ':' || qc == '.' || qc == '#' || qc == '[' || qc == ']' ||
                    qc == '(' || qc == ')' || isspace((unsigned char)qc))
                {
                    break;
                }
                ++q;
            }
            if (q > name_start)
            {
                if (c == '#' && !id_start)
                {
                    id_start = name_start;
                    id_end = q;
                    break;
                }
                if (c == '.' && !class_start)
                {
                    class_start = name_start;
                    class_end = q;
                }
            }
            p = q;
            continue;
        }
        ++p;
    }

    if (id_start && id_end && id_end > id_start)
    {
        cache->id_hint_valid = true;
        cache->id_hint_start = (uint32_t)(id_start - selector);
        cache->id_hint_len = (uint32_t)(id_end - id_start);
    }
    if (class_start && class_end && class_end > class_start)
    {
        cache->class_hint_valid = true;
        cache->class_hint_start = (uint32_t)(class_start - selector);
        cache->class_hint_len = (uint32_t)(class_end - class_start);
    }

    if (cache->count >= 2)
    {
        const css_selector_part_t *parent_part = &cache->parts[cache->count - 2];
        char comb = parent_part->combinator ? parent_part->combinator : ' ';
        if (comb == '>')
        {
            const char *parent_start = selector + parent_part->start;
            const char *parent_end = selector + parent_part->end;
            html_view_trim_range(&parent_start, &parent_end);
            if (parent_end > parent_start)
            {
                bool parent_escape = false;
                char parent_quote = 0;
                int parent_bracket_depth = 0;
                int parent_paren_depth = 0;
                const char *q = parent_start;
                while (q < parent_end)
                {
                    char c = *q;
                    if (parent_escape)
                    {
                        parent_escape = false;
                        ++q;
                        continue;
                    }
                    if (c == '\\')
                    {
                        parent_escape = true;
                        ++q;
                        continue;
                    }
                    if (parent_quote)
                    {
                        if (c == parent_quote)
                        {
                            parent_quote = 0;
                        }
                        ++q;
                        continue;
                    }
                    if (c == '"' || c == '\'')
                    {
                        parent_quote = c;
                        ++q;
                        continue;
                    }
                    if (c == '[')
                    {
                        ++parent_bracket_depth;
                        ++q;
                        continue;
                    }
                    if (c == ']' && parent_bracket_depth > 0)
                    {
                        --parent_bracket_depth;
                        ++q;
                        continue;
                    }
                    if (parent_bracket_depth == 0)
                    {
                        if (c == '(')
                        {
                            ++parent_paren_depth;
                            ++q;
                            continue;
                        }
                        if (c == ')' && parent_paren_depth > 0)
                        {
                            --parent_paren_depth;
                            ++q;
                            continue;
                        }
                    }
                    if (parent_bracket_depth == 0 && parent_paren_depth == 0 && c == '.')
                    {
                        const char *name_start = q + 1;
                        const char *r = name_start;
                        bool token_escape = false;
                        while (r < parent_end)
                        {
                            char rc = *r;
                            if (token_escape)
                            {
                                token_escape = false;
                                ++r;
                                continue;
                            }
                            if (rc == '\\')
                            {
                                token_escape = true;
                                ++r;
                                continue;
                            }
                            if (rc == ':' || rc == '.' || rc == '#' || rc == '[' || rc == ']' ||
                                rc == '(' || rc == ')' || isspace((unsigned char)rc))
                            {
                                break;
                            }
                            ++r;
                        }
                        if (r > name_start)
                        {
                            cache->parent_class_hint_valid = true;
                            cache->parent_class_hint_start = (uint32_t)(name_start - selector);
                            cache->parent_class_hint_len = (uint32_t)(r - name_start);
                        }
                        break;
                    }
                    ++q;
                }
            }
        }
    }
}

static void html_view_selector_bloom_add_part_mask(web_bloom_t *mask,
                                                   const char *selector,
                                                   const css_selector_part_t *part)
{
    if (!mask || !selector || !part)
    {
        return;
    }
    const char *part_start = selector + part->start;
    const char *part_end = selector + part->end;
    html_view_trim_range(&part_start, &part_end);
    if (part_end <= part_start)
    {
        return;
    }

    const char *p = part_start;
    if (*p == '*')
    {
        ++p;
    }
    else if (*p != '#' && *p != '.' && *p != '[' && *p != ':')
    {
        const char *tag_end = p;
        while (tag_end < part_end &&
               *tag_end != ':' && *tag_end != '.' && *tag_end != '#' && *tag_end != '[' &&
               !isspace((unsigned char)*tag_end))
        {
            ++tag_end;
        }
        if (tag_end > p)
        {
            html_view_bloom_add_range(mask, p, tag_end, true);
        }
        p = tag_end;
    }

    bool escape = false;
    char quote = 0;
    int paren_depth = 0;
    while (p < part_end)
    {
        char c = *p;
        if (escape)
        {
            escape = false;
            ++p;
            continue;
        }
        if (c == '\\')
        {
            escape = true;
            ++p;
            continue;
        }
        if (quote)
        {
            if (c == quote)
            {
                quote = 0;
            }
            ++p;
            continue;
        }
        if (c == '"' || c == '\'')
        {
            quote = c;
            ++p;
            continue;
        }
        if (c == '(')
        {
            ++paren_depth;
            ++p;
            continue;
        }
        if (c == ')' && paren_depth > 0)
        {
            --paren_depth;
            ++p;
            continue;
        }
        if (paren_depth > 0)
        {
            ++p;
            continue;
        }
        if (c == '[')
        {
            const char *q = p + 1;
            while (q < part_end && isspace((unsigned char)*q))
            {
                ++q;
            }
            const char *name_start = q;
            while (q < part_end && (isalnum((unsigned char)*q) || *q == '-' || *q == '_' || *q == ':'))
            {
                ++q;
            }
            const char *name_end = q;
            if (name_end > name_start)
            {
                html_view_bloom_add_range(mask, name_start, name_end, true);
            }

            bool attr_escape = false;
            char attr_quote = 0;
            q = p + 1;
            while (q < part_end)
            {
                char qc = *q;
                if (attr_escape)
                {
                    attr_escape = false;
                    ++q;
                    continue;
                }
                if (qc == '\\')
                {
                    attr_escape = true;
                    ++q;
                    continue;
                }
                if (attr_quote)
                {
                    if (qc == attr_quote)
                    {
                        attr_quote = 0;
                    }
                    ++q;
                    continue;
                }
                if (qc == '"' || qc == '\'')
                {
                    attr_quote = qc;
                    ++q;
                    continue;
                }
                if (qc == ']')
                {
                    ++q;
                    break;
                }
                ++q;
            }
            p = q;
            continue;
        }
        if (c == '#' || c == '.')
        {
            const char *name_start = p + 1;
            const char *q = name_start;
            bool token_escape = false;
            while (q < part_end)
            {
                char qc = *q;
                if (token_escape)
                {
                    token_escape = false;
                    ++q;
                    continue;
                }
                if (qc == '\\')
                {
                    token_escape = true;
                    ++q;
                    continue;
                }
                if (qc == ':' || qc == '.' || qc == '#' || qc == '[' || qc == ']' ||
                    qc == '(' || qc == ')' || isspace((unsigned char)qc))
                {
                    break;
                }
                ++q;
            }
            if (q > name_start)
            {
                html_view_bloom_add_range(mask, name_start, q, true);
            }
            p = q;
            continue;
        }
        ++p;
    }
}

static void html_view_selector_cache_set_ancestor_bloom_mask(css_selector_cache_t *cache,
                                                             const char *selector)
{
    if (!cache)
    {
        return;
    }
    html_view_bloom_clear(&cache->ancestor_bloom_mask);
    html_view_bloom_clear(&cache->self_bloom_mask);
    if (!selector || cache->count == 0)
    {
        return;
    }

    html_view_selector_bloom_add_part_mask(&cache->self_bloom_mask,
                                           selector,
                                           &cache->parts[cache->count - 1]);
    if (cache->count < 2)
    {
        return;
    }

    bool ancestor_path = true;
    for (size_t idx = cache->count - 1; idx > 0; --idx)
    {
        const css_selector_part_t *left = &cache->parts[idx - 1];
        char comb = left->combinator ? left->combinator : ' ';
        if (comb == '+' || comb == '~')
        {
            ancestor_path = false;
            break;
        }
        if (!ancestor_path)
        {
            break;
        }
        html_view_selector_bloom_add_part_mask(&cache->ancestor_bloom_mask, selector, left);
    }
}

static void html_view_selector_cache_set_pseudo_flags(css_selector_cache_t *cache, const char *selector)
{
    if (!cache)
    {
        return;
    }
    cache->never_match = false;
    cache->pseudo_mask = HTML_VIEW_PSEUDO_MASK_NONE;
    if (!selector || cache->count == 0)
    {
        return;
    }

    bool has_before = false;
    bool has_after = false;
    for (size_t i = 0; i < cache->count; ++i)
    {
        const css_selector_part_t *part = &cache->parts[i];
        const char *part_start = selector + part->start;
        const char *part_end = selector + part->end;
        html_view_trim_range(&part_start, &part_end);
        if (part_end <= part_start)
        {
            continue;
        }

        bool escape = false;
        char quote = 0;
        int bracket_depth = 0;
        const char *p = part_start;
        while (p < part_end)
        {
            char c = *p;
            if (escape)
            {
                escape = false;
                ++p;
                continue;
            }
            if (c == '\\')
            {
                escape = true;
                ++p;
                continue;
            }
            if (quote)
            {
                if (c == quote)
                {
                    quote = 0;
                }
                ++p;
                continue;
            }
            if (c == '"' || c == '\'')
            {
                quote = c;
                ++p;
                continue;
            }
            if (c == '[')
            {
                ++bracket_depth;
                ++p;
                continue;
            }
            if (c == ']' && bracket_depth > 0)
            {
                --bracket_depth;
                ++p;
                continue;
            }
            if (bracket_depth > 0)
            {
                ++p;
                continue;
            }
            if (c == ':')
            {
                const char *name = p + 1;
                if (name < part_end && *name == ':')
                {
                    ++name;
                }
                const char *name_end = name;
                while (name_end < part_end &&
                       (isalnum((unsigned char)*name_end) || *name_end == '-' || *name_end == '_'))
                {
                    ++name_end;
                }
                if (name_end == name)
                {
                    cache->never_match = true;
                    return;
                }
                if (name_end < part_end && *name_end == '(')
                {
                    cache->never_match = true;
                    return;
                }
                size_t name_len = (size_t)(name_end - name);
                if (name_len == 6 && strncasecmp(name, "before", 6) == 0)
                {
                    has_before = true;
                }
                else if (name_len == 5 && strncasecmp(name, "after", 5) == 0)
                {
                    has_after = true;
                }
                else if (name_len == 4 && strncasecmp(name, "link", 4) == 0)
                {
                    /* supported pseudo-class */
                }
                else
                {
                    cache->never_match = true;
                    return;
                }
                p = name_end;
                continue;
            }
            ++p;
        }
    }

    if (has_before && has_after)
    {
        cache->never_match = true;
        return;
    }
    if (has_before || has_after)
    {
        cache->pseudo_mask = 0;
        if (has_before)
        {
            cache->pseudo_mask |= HTML_VIEW_PSEUDO_MASK_BEFORE;
        }
        if (has_after)
        {
            cache->pseudo_mask |= HTML_VIEW_PSEUDO_MASK_AFTER;
        }
    }
}

static void html_view_selector_cache_set_attr_flags(css_selector_cache_t *cache, const char *selector)
{
    if (!cache)
    {
        return;
    }
    cache->attr_hint_valid = false;
    cache->attr_hint_name_start = 0;
    cache->attr_hint_name_len = 0;
    cache->attr_hint_value_valid = false;
    cache->attr_hint_value_start = 0;
    cache->attr_hint_value_len = 0;
    cache->attr_hint_op = 0;
    if (!selector || cache->count == 0)
    {
        return;
    }

    for (size_t i = 0; i < cache->count; ++i)
    {
        const css_selector_part_t *part = &cache->parts[i];
        const char *part_start = selector + part->start;
        const char *part_end = selector + part->end;
        html_view_trim_range(&part_start, &part_end);
        if (part_end <= part_start)
        {
            continue;
        }

        bool escape = false;
        char quote = 0;
        const char *p = part_start;
        while (p < part_end)
        {
            char c = *p;
            if (escape)
            {
                escape = false;
                ++p;
                continue;
            }
            if (c == '\\')
            {
                escape = true;
                ++p;
                continue;
            }
            if (quote)
            {
                if (c == quote)
                {
                    quote = 0;
                }
                ++p;
                continue;
            }
            if (c == '"' || c == '\'')
            {
                quote = c;
                ++p;
                continue;
            }
            if (c != '[')
            {
                ++p;
                continue;
            }

            const char *name_start = NULL;
            const char *name_end = NULL;
            const char *value_start = NULL;
            const char *value_end = NULL;
            char op = 0;
            bool unsupported = false;
            const char *scan = p;
            if (!html_view_parse_attr_selector_meta(&scan,
                                                    part_end,
                                                    &name_start,
                                                    &name_end,
                                                    &op,
                                                    &value_start,
                                                    &value_end,
                                                    &unsupported))
            {
                cache->never_match = true;
                return;
            }
            if (unsupported)
            {
                cache->never_match = true;
                return;
            }

            if (i == cache->count - 1 && name_start && name_end && name_end > name_start)
            {
                size_t name_len = (size_t)(name_end - name_start);
                bool has_value = (op != 0 && value_start && value_end && value_end > value_start);
                bool is_class = html_view_selector_range_eq_ci("class", name_start, name_len);
                bool is_id = html_view_selector_range_eq_ci("id", name_start, name_len);
                bool value_has_space = has_value && html_view_selector_range_has_space(value_start, value_end);

                if (is_id && op == '=' && has_value)
                {
                    if (value_has_space)
                    {
                        cache->never_match = true;
                        return;
                    }
                    if (!cache->id_hint_valid)
                    {
                        cache->id_hint_valid = true;
                        cache->id_hint_start = (uint32_t)(value_start - selector);
                        cache->id_hint_len = (uint32_t)(value_end - value_start);
                    }
                }
                else if (is_class && (op == '=' || op == '~') && has_value)
                {
                    if (value_has_space)
                    {
                        if (op == '~')
                        {
                            cache->never_match = true;
                            return;
                        }
                    }
                    else if (!cache->class_hint_valid)
                    {
                        cache->class_hint_valid = true;
                        cache->class_hint_start = (uint32_t)(value_start - selector);
                        cache->class_hint_len = (uint32_t)(value_end - value_start);
                    }
                }

                if ((!is_class && !is_id) ||
                    (is_class && op == '=' && has_value && value_has_space))
                {
                    size_t value_len = has_value ? (size_t)(value_end - value_start) : 0;
                    bool prefer = false;
                    if (!cache->attr_hint_valid)
                    {
                        prefer = true;
                    }
                    else if (has_value && !cache->attr_hint_value_valid)
                    {
                        prefer = true;
                    }
                    else if (has_value && cache->attr_hint_value_valid &&
                             value_len > cache->attr_hint_value_len)
                    {
                        prefer = true;
                    }
                    else if (!has_value && !cache->attr_hint_value_valid &&
                             name_len > cache->attr_hint_name_len)
                    {
                        prefer = true;
                    }

                    if (prefer)
                    {
                        cache->attr_hint_valid = true;
                        cache->attr_hint_name_start = (uint32_t)(name_start - selector);
                        cache->attr_hint_name_len = (uint32_t)name_len;
                        cache->attr_hint_op = op;
                        cache->attr_hint_value_valid = has_value;
                        if (has_value)
                        {
                            cache->attr_hint_value_start = (uint32_t)(value_start - selector);
                            cache->attr_hint_value_len = (uint32_t)value_len;
                        }
                        else
                        {
                            cache->attr_hint_value_start = 0;
                            cache->attr_hint_value_len = 0;
                        }
                    }
                }
            }

            p = scan;
        }
    }
}

static bool html_view_selector_cache_parse(css_selector_cache_t *cache, const char *selector)
{
    if (!cache || !selector)
    {
        return false;
    }
    if (cache->parsed || cache->parse_failed)
    {
        return cache->parsed;
    }

    const char *start = selector;
    const char *end = selector + strlen(selector);
    html_view_trim_range(&start, &end);
    if (end <= start)
    {
        cache->parse_failed = true;
        return false;
    }

    const char *p = start;
    while (p < end)
    {
        while (p < end && isspace((unsigned char)*p))
        {
            ++p;
        }
        if (p >= end)
        {
            break;
        }

        const char *part_start = p;
        char quote = 0;
        bool escape = false;
        int bracket_depth = 0;
        while (p < end)
        {
            char c = *p;
            if (escape)
            {
                escape = false;
                ++p;
                continue;
            }
            if (c == '\\')
            {
                escape = true;
                ++p;
                continue;
            }
            if (quote)
            {
                if (c == quote)
                {
                    quote = 0;
                }
                ++p;
                continue;
            }
            if (c == '"' || c == '\'')
            {
                quote = c;
                ++p;
                continue;
            }
            if (c == '[')
            {
                ++bracket_depth;
                ++p;
                continue;
            }
            if (c == ']' && bracket_depth > 0)
            {
                --bracket_depth;
                ++p;
                continue;
            }
            if (bracket_depth == 0 && (c == '>' || c == '+' || c == '~' || isspace((unsigned char)c)))
            {
                break;
            }
            ++p;
        }

        const char *part_end = p;
        html_view_trim_range(&part_start, &part_end);
        if (part_end <= part_start)
        {
            cache->parse_failed = true;
            free(cache->parts);
            cache->parts = NULL;
            cache->count = 0;
            cache->cap = 0;
            return false;
        }

        bool had_space = false;
        while (p < end && isspace((unsigned char)*p))
        {
            had_space = true;
            ++p;
        }

        char combinator = 0;
        if (p < end)
        {
            if (*p == '>' || *p == '+' || *p == '~')
            {
                combinator = *p;
                ++p;
            }
            else if (had_space)
            {
                combinator = ' ';
            }
            else
            {
                combinator = ' ';
            }
            while (p < end && isspace((unsigned char)*p))
            {
                ++p;
            }
        }

        if (!html_view_selector_cache_push(cache,
                                           (uint32_t)(part_start - selector),
                                           (uint32_t)(part_end - selector),
                                           combinator))
        {
            cache->parse_failed = true;
            free(cache->parts);
            cache->parts = NULL;
            cache->count = 0;
            cache->cap = 0;
            return false;
        }
    }

    cache->parsed = true;
    html_view_selector_cache_set_hints(cache, selector);
    html_view_selector_cache_set_pseudo_flags(cache, selector);
    html_view_selector_cache_set_attr_flags(cache, selector);
    html_view_selector_cache_set_ancestor_bloom_mask(cache, selector);
    return true;
}

static bool html_view_selector_matches_parts(const css_selector_part_t *parts,
                                             size_t part_count,
                                             const char *selector,
                                             const html_node_t *node,
                                             html_view_pseudo_t pseudo)
{
    if (!parts || part_count == 0 || !selector || !node || node->type != HTML_NODE_ELEMENT)
    {
        return false;
    }

    const html_node_t *cur = node;
    const css_selector_part_t *right = &parts[part_count - 1];
    if (!html_view_simple_selector_matches_range_internal(selector + right->start,
                                                          selector + right->end,
                                                          cur,
                                                          pseudo))
    {
        return false;
    }

    for (size_t idx = part_count - 1; idx > 0; --idx)
    {
        const css_selector_part_t *left = &parts[idx - 1];
        char comb = left->combinator ? left->combinator : ' ';
        if (comb == ' ')
        {
            bool found = false;
            for (const html_node_t *p = cur->parent; p; p = p->parent)
            {
                if (html_view_simple_selector_matches_range_internal(selector + left->start,
                                                                     selector + left->end,
                                                                     p,
                                                                     HTML_VIEW_PSEUDO_NONE))
                {
                    cur = p;
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                return false;
            }
        }
        else if (comb == '>')
        {
            cur = cur->parent;
            if (!cur || !html_view_simple_selector_matches_range_internal(selector + left->start,
                                                                          selector + left->end,
                                                                          cur,
                                                                          HTML_VIEW_PSEUDO_NONE))
            {
                return false;
            }
        }
        else if (comb == '+')
        {
            cur = html_view_prev_element_sibling(cur);
            if (!cur || !html_view_simple_selector_matches_range_internal(selector + left->start,
                                                                          selector + left->end,
                                                                          cur,
                                                                          HTML_VIEW_PSEUDO_NONE))
            {
                return false;
            }
        }
        else if (comb == '~')
        {
            bool found = false;
            for (const html_node_t *p = html_view_prev_element_sibling(cur); p; p = html_view_prev_element_sibling(p))
            {
                if (html_view_simple_selector_matches_range_internal(selector + left->start,
                                                                     selector + left->end,
                                                                     p,
                                                                     HTML_VIEW_PSEUDO_NONE))
                {
                    cur = p;
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                return false;
            }
        }
        else
        {
            return false;
        }
    }

    return true;
}

static bool html_view_selector_matches_internal(const char *selector,
                                                const html_node_t *node,
                                                html_view_pseudo_t pseudo)
{
    if (!selector || !node || node->type != HTML_NODE_ELEMENT)
    {
        return false;
    }

    const char *start = selector;
    const char *end = selector + strlen(selector);
    html_view_trim_range(&start, &end);
    if (end <= start)
    {
        return false;
    }

    css_selector_cache_t *cache = (css_selector_cache_t *)calloc(1, sizeof(*cache));
    if (!cache)
    {
        return false;
    }
    if (!html_view_selector_cache_parse(cache, selector) || cache->count == 0)
    {
        free(cache->parts);
        free(cache);
        return false;
    }
    bool match = html_view_selector_matches_parts(cache->parts, cache->count, selector, node, pseudo);
    free(cache->parts);
    free(cache);
    return match;
}

static bool html_view_selector_cache_precheck(css_rule_t *rule,
                                              const html_node_t *node,
                                              html_view_pseudo_t pseudo,
                                              css_selector_cache_t **out_cache,
                                              bool *out_fallback)
{
    if (out_cache)
    {
        *out_cache = NULL;
    }
    if (out_fallback)
    {
        *out_fallback = false;
    }
    if (!rule || !rule->selector || !node || node->type != HTML_NODE_ELEMENT)
    {
        return false;
    }

    css_selector_cache_t *cache = rule->selector_cache;
    if (!cache)
    {
        cache = (css_selector_cache_t *)calloc(1, sizeof(*cache));
        if (!cache)
        {
            if (out_fallback)
            {
                *out_fallback = true;
            }
            return true;
        }
        rule->selector_cache = cache;
    }

    if (!cache->parsed && !cache->parse_failed)
    {
        (void)html_view_selector_cache_parse(cache, rule->selector);
    }
    if (cache->parse_failed)
    {
        return false;
    }
    if (!cache->parsed || cache->count == 0)
    {
        if (out_fallback)
        {
            *out_fallback = true;
        }
        return true;
    }
    if (cache->never_match)
    {
        return false;
    }
    if ((cache->pseudo_mask & html_view_pseudo_mask(pseudo)) == 0)
    {
        return false;
    }
    if (!html_view_bloom_is_zero(&cache->ancestor_bloom_mask))
    {
        bool ancestor_bloom_valid = (node->parent == NULL) ||
                                    !html_view_bloom_is_zero(&node->ancestor_bloom);
        if (ancestor_bloom_valid &&
            !html_view_bloom_contains(&node->ancestor_bloom, &cache->ancestor_bloom_mask))
        {
            return false;
        }
    }
    if (!html_view_bloom_is_zero(&cache->self_bloom_mask))
    {
        web_bloom_t self_bloom = node->self_bloom;
        if (html_view_bloom_is_zero(&self_bloom))
        {
            self_bloom = html_view_node_self_bloom(node);
        }
        if (!html_view_bloom_contains(&self_bloom, &cache->self_bloom_mask))
        {
            return false;
        }
    }

    if (cache->tag_hint_valid)
    {
        if (!node->name || strlen(node->name) != cache->tag_hint_len ||
            strncasecmp(node->name, rule->selector + cache->tag_hint_start, cache->tag_hint_len) != 0)
        {
            return false;
        }
    }
    if (cache->id_hint_valid)
    {
        const char *id = html_attr_get(node, "id");
        if (!id || strlen(id) != cache->id_hint_len ||
            strncasecmp(id, rule->selector + cache->id_hint_start, cache->id_hint_len) != 0)
        {
            return false;
        }
    }
    if (cache->class_hint_valid)
    {
        if (!html_view_node_has_class(node,
                                      rule->selector + cache->class_hint_start,
                                      cache->class_hint_len))
        {
            return false;
        }
    }
    if (cache->attr_hint_valid)
    {
        const char *name_start = rule->selector + cache->attr_hint_name_start;
        size_t name_len = cache->attr_hint_name_len;
        const char *attr_value = html_view_attr_get_range(node, name_start, name_len);
        if (!attr_value)
        {
            return false;
        }
        if (cache->attr_hint_op == '=')
        {
            const char *val_start = rule->selector + cache->attr_hint_value_start;
            if (!cache->attr_hint_value_valid ||
                !html_view_selector_range_eq_ci(attr_value, val_start, cache->attr_hint_value_len))
            {
                return false;
            }
        }
        else if (cache->attr_hint_op == '~')
        {
            const char *val_start = rule->selector + cache->attr_hint_value_start;
            if (!cache->attr_hint_value_valid ||
                !html_view_attr_value_has_token_range(attr_value, val_start, cache->attr_hint_value_len))
            {
                return false;
            }
        }
    }
    if (cache->parent_class_hint_valid)
    {
        const html_node_t *parent = node->parent;
        if (!parent || !html_view_node_has_class(parent,
                                                 rule->selector + cache->parent_class_hint_start,
                                                 cache->parent_class_hint_len))
        {
            return false;
        }
    }

    if (out_cache)
    {
        *out_cache = cache;
    }
    return true;
}

static bool html_view_selector_matches_cached(css_rule_t *rule,
                                              const html_node_t *node,
                                              html_view_pseudo_t pseudo)
{
    if (!rule || !rule->selector || !node || node->type != HTML_NODE_ELEMENT)
    {
        return false;
    }

    css_selector_cache_t *cache = NULL;
    bool fallback = false;
    if (!html_view_selector_cache_precheck(rule, node, pseudo, &cache, &fallback))
    {
        return false;
    }
    if (fallback || !cache)
    {
        return html_view_selector_matches_internal(rule->selector, node, pseudo);
    }
    return html_view_selector_matches_parts(cache->parts, cache->count, rule->selector, node, pseudo);
}

static void html_view_rule_index_free(html_view_rule_index_t *index)
{
    if (!index)
    {
        return;
    }
    for (size_t i = 0; i < index->tag_bucket_count; ++i)
    {
        html_view_rule_bucket_t *bucket = &index->tag_buckets[i];
        for (size_t j = 0; j < bucket->parent_count; ++j)
        {
            html_view_rule_bucket_t *parent = &bucket->parent_buckets[j];
            free(parent->tag);
            free(parent->rules);
        }
        free(bucket->parent_buckets);
        free(bucket->tag);
        free(bucket->rules);
    }
    for (size_t i = 0; i < index->class_bucket_count; ++i)
    {
        html_view_rule_bucket_t *bucket = &index->class_buckets[i];
        for (size_t j = 0; j < bucket->parent_count; ++j)
        {
            html_view_rule_bucket_t *parent = &bucket->parent_buckets[j];
            free(parent->tag);
            free(parent->rules);
        }
        free(bucket->parent_buckets);
        free(bucket->tag);
        free(bucket->rules);
    }
    for (size_t i = 0; i < index->scope_class_bucket_count; ++i)
    {
        html_view_rule_bucket_t *bucket = &index->scope_class_buckets[i];
        for (size_t j = 0; j < bucket->parent_count; ++j)
        {
            html_view_rule_bucket_t *parent = &bucket->parent_buckets[j];
            free(parent->tag);
            free(parent->rules);
        }
        free(bucket->parent_buckets);
        free(bucket->tag);
        free(bucket->rules);
    }
    for (size_t i = 0; i < index->id_bucket_count; ++i)
    {
        html_view_rule_bucket_t *bucket = &index->id_buckets[i];
        for (size_t j = 0; j < bucket->parent_count; ++j)
        {
            html_view_rule_bucket_t *parent = &bucket->parent_buckets[j];
            free(parent->tag);
            free(parent->rules);
        }
        free(bucket->parent_buckets);
        free(bucket->tag);
        free(bucket->rules);
    }
    for (size_t i = 0; i < index->attr_bucket_count; ++i)
    {
        html_view_rule_bucket_t *bucket = &index->attr_buckets[i];
        for (size_t j = 0; j < bucket->parent_count; ++j)
        {
            html_view_rule_bucket_t *parent = &bucket->parent_buckets[j];
            free(parent->tag);
            free(parent->rules);
        }
        free(bucket->parent_buckets);
        free(bucket->tag);
        free(bucket->rules);
    }
    free(index->tag_buckets);
    free(index->class_buckets);
    free(index->scope_class_buckets);
    free(index->id_buckets);
    free(index->attr_buckets);
    free(index->global_rules);
    free(index);
}

void html_view_rule_index_clear(atk_html_view_priv_t *priv)
{
    if (!priv || !priv->rule_index)
    {
        return;
    }
    html_view_rule_index_free(priv->rule_index);
    priv->rule_index = NULL;
}

static bool html_view_rule_index_list_push(css_rule_t ***list,
                                           size_t *count,
                                           size_t *cap,
                                           css_rule_t *rule)
{
    if (!list || !count || !cap || !rule)
    {
        return false;
    }
    if (*count == *cap)
    {
        size_t new_cap = *cap ? (*cap * 2u) : 16u;
        css_rule_t **next = (css_rule_t **)realloc(*list, new_cap * sizeof(*next));
        if (!next)
        {
            return false;
        }
        *list = next;
        *cap = new_cap;
    }
    (*list)[(*count)++] = rule;
    return true;
}

static char *html_view_strdup_lower_range(const char *start, size_t len)
{
    if (!start || len == 0)
    {
        return NULL;
    }
    char *out = (char *)malloc(len + 1);
    if (!out)
    {
        return NULL;
    }
    for (size_t i = 0; i < len; ++i)
    {
        out[i] = (char)tolower((unsigned char)start[i]);
    }
    out[len] = '\0';
    return out;
}

static char *html_view_strdup_lower_unescaped_range(const char *start, size_t len)
{
    if (!start || len == 0)
    {
        return NULL;
    }
    const char *end = start + len;
    char *out = html_view_unescape_selector_value(start, end);
    if (!out)
    {
        return NULL;
    }
    for (char *p = out; *p; ++p)
    {
        *p = (char)tolower((unsigned char)*p);
    }
    return out;
}

typedef struct
{
    char *key;
    size_t len;
    uint32_t count;
} html_view_key_count_t;

typedef struct
{
    html_view_key_count_t *items;
    size_t count;
    size_t cap;
} html_view_key_count_map_t;

static html_view_key_count_t *html_view_key_count_find(html_view_key_count_map_t *map,
                                                       const char *key,
                                                       size_t len)
{
    if (!map || !key || len == 0)
    {
        return NULL;
    }
    for (size_t i = 0; i < map->count; ++i)
    {
        html_view_key_count_t *entry = &map->items[i];
        if (entry->len == len && strncasecmp(entry->key, key, len) == 0)
        {
            return entry;
        }
    }
    return NULL;
}

static bool html_view_key_count_inc(html_view_key_count_map_t *map,
                                    const char *start,
                                    const char *end)
{
    if (!map || !start || !end || end <= start)
    {
        return false;
    }
    size_t len = (size_t)(end - start);
    char *key = html_view_strdup_lower_unescaped_range(start, len);
    if (!key)
    {
        return false;
    }

    html_view_key_count_t *entry = html_view_key_count_find(map, key, strlen(key));
    if (entry)
    {
        entry->count++;
        free(key);
        return true;
    }

    if (map->count == map->cap)
    {
        size_t new_cap = map->cap ? (map->cap * 2u) : 16u;
        html_view_key_count_t *next = (html_view_key_count_t *)realloc(map->items,
                                                                       new_cap * sizeof(*next));
        if (!next)
        {
            free(key);
            return false;
        }
        map->items = next;
        map->cap = new_cap;
    }

    map->items[map->count++] = (html_view_key_count_t){
        .key = key,
        .len = strlen(key),
        .count = 1u,
    };
    return true;
}

static uint32_t html_view_key_count_get(const html_view_key_count_map_t *map,
                                        const char *start,
                                        const char *end)
{
    if (!map || !start || !end || end <= start)
    {
        return 0xffffffffu;
    }
    size_t len = (size_t)(end - start);
    char *key = html_view_strdup_lower_unescaped_range(start, len);
    if (!key)
    {
        return 0xffffffffu;
    }
    size_t key_len = strlen(key);
    uint32_t out = 0xffffffffu;
    for (size_t i = 0; i < map->count; ++i)
    {
        const html_view_key_count_t *entry = &map->items[i];
        if (entry->len == key_len && strncasecmp(entry->key, key, entry->len) == 0)
        {
            out = entry->count;
            break;
        }
    }
    free(key);
    return out;
}

static void html_view_key_count_map_free(html_view_key_count_map_t *map)
{
    if (!map)
    {
        return;
    }
    for (size_t i = 0; i < map->count; ++i)
    {
        free(map->items[i].key);
    }
    free(map->items);
    map->items = NULL;
    map->count = 0;
    map->cap = 0;
}

static void html_view_selector_collect_class_counts(const char *part_start,
                                                    const char *part_end,
                                                    html_view_key_count_map_t *map)
{
    if (!part_start || !part_end || part_end <= part_start || !map)
    {
        return;
    }

    bool escape = false;
    char quote = 0;
    int bracket_depth = 0;
    int paren_depth = 0;
    const char *p = part_start;
    while (p < part_end)
    {
        char c = *p;
        if (escape)
        {
            escape = false;
            ++p;
            continue;
        }
        if (c == '\\')
        {
            escape = true;
            ++p;
            continue;
        }
        if (quote)
        {
            if (c == quote)
            {
                quote = 0;
            }
            ++p;
            continue;
        }
        if (c == '"' || c == '\'')
        {
            quote = c;
            ++p;
            continue;
        }
        if (c == '[')
        {
            ++bracket_depth;
            ++p;
            continue;
        }
        if (c == ']' && bracket_depth > 0)
        {
            --bracket_depth;
            ++p;
            continue;
        }
        if (bracket_depth == 0)
        {
            if (c == '(')
            {
                ++paren_depth;
                ++p;
                continue;
            }
            if (c == ')' && paren_depth > 0)
            {
                --paren_depth;
                ++p;
                continue;
            }
        }
        if (bracket_depth == 0 && paren_depth == 0 && c == '.')
        {
            const char *name_start = p + 1;
            const char *q = name_start;
            bool token_escape = false;
            while (q < part_end)
            {
                char qc = *q;
                if (token_escape)
                {
                    token_escape = false;
                    ++q;
                    continue;
                }
                if (qc == '\\')
                {
                    token_escape = true;
                    ++q;
                    continue;
                }
                if (qc == ':' || qc == '.' || qc == '#' || qc == '[' || qc == ']' ||
                    qc == '(' || qc == ')' || isspace((unsigned char)qc))
                {
                    break;
                }
                ++q;
            }
            if (q > name_start)
            {
                (void)html_view_key_count_inc(map, name_start, q);
            }
            p = q;
            continue;
        }
        ++p;
    }
}

static void html_view_selector_choose_best_class_hint(css_selector_cache_t *cache,
                                                      const char *selector,
                                                      const html_view_key_count_map_t *map)
{
    if (!cache || !selector || cache->count == 0 || !map)
    {
        return;
    }

    const css_selector_part_t *part = &cache->parts[cache->count - 1];
    const char *part_start = selector + part->start;
    const char *part_end = selector + part->end;
    html_view_trim_range(&part_start, &part_end);
    if (part_end <= part_start)
    {
        return;
    }

    const char *best_start = NULL;
    const char *best_end = NULL;
    uint32_t best_count = 0xffffffffu;
    size_t best_len = 0;

    bool escape = false;
    char quote = 0;
    int bracket_depth = 0;
    int paren_depth = 0;
    const char *p = part_start;
    while (p < part_end)
    {
        char c = *p;
        if (escape)
        {
            escape = false;
            ++p;
            continue;
        }
        if (c == '\\')
        {
            escape = true;
            ++p;
            continue;
        }
        if (quote)
        {
            if (c == quote)
            {
                quote = 0;
            }
            ++p;
            continue;
        }
        if (c == '"' || c == '\'')
        {
            quote = c;
            ++p;
            continue;
        }
        if (c == '[')
        {
            ++bracket_depth;
            ++p;
            continue;
        }
        if (c == ']' && bracket_depth > 0)
        {
            --bracket_depth;
            ++p;
            continue;
        }
        if (bracket_depth == 0)
        {
            if (c == '(')
            {
                ++paren_depth;
                ++p;
                continue;
            }
            if (c == ')' && paren_depth > 0)
            {
                --paren_depth;
                ++p;
                continue;
            }
        }
        if (bracket_depth == 0 && paren_depth == 0 && c == '.')
        {
            const char *name_start = p + 1;
            const char *q = name_start;
            bool token_escape = false;
            while (q < part_end)
            {
                char qc = *q;
                if (token_escape)
                {
                    token_escape = false;
                    ++q;
                    continue;
                }
                if (qc == '\\')
                {
                    token_escape = true;
                    ++q;
                    continue;
                }
                if (qc == ':' || qc == '.' || qc == '#' || qc == '[' || qc == ']' ||
                    qc == '(' || qc == ')' || isspace((unsigned char)qc))
                {
                    break;
                }
                ++q;
            }
            if (q > name_start)
            {
                uint32_t count = html_view_key_count_get(map, name_start, q);
                size_t len = (size_t)(q - name_start);
                if (count < best_count || (count == best_count && len > best_len))
                {
                    best_count = count;
                    best_start = name_start;
                    best_end = q;
                    best_len = len;
                }
            }
            p = q;
            continue;
        }
        ++p;
    }

    if (best_start && best_end && best_end > best_start)
    {
        cache->class_hint_valid = true;
        cache->class_hint_start = (uint32_t)(best_start - selector);
        cache->class_hint_len = (uint32_t)(best_end - best_start);
    }
}

static void html_view_selector_choose_best_scope_class_hint(css_selector_cache_t *cache,
                                                            const char *selector,
                                                            const html_view_key_count_map_t *map)
{
    if (!cache || !selector || !map)
    {
        return;
    }
    cache->scope_class_hint_valid = false;
    cache->scope_class_hint_start = 0;
    cache->scope_class_hint_len = 0;
    if (cache->count < 2)
    {
        return;
    }

    const char *best_start = NULL;
    const char *best_end = NULL;
    uint32_t best_count = 0xffffffffu;
    size_t best_len = 0;

    for (size_t part_idx = 0; part_idx + 1 < cache->count; ++part_idx)
    {
        const css_selector_part_t *part = &cache->parts[part_idx];
        const char *part_start = selector + part->start;
        const char *part_end = selector + part->end;
        html_view_trim_range(&part_start, &part_end);
        if (part_end <= part_start)
        {
            continue;
        }

        bool escape = false;
        char quote = 0;
        int bracket_depth = 0;
        int paren_depth = 0;
        const char *p = part_start;
        while (p < part_end)
        {
            char c = *p;
            if (escape)
            {
                escape = false;
                ++p;
                continue;
            }
            if (c == '\\')
            {
                escape = true;
                ++p;
                continue;
            }
            if (quote)
            {
                if (c == quote)
                {
                    quote = 0;
                }
                ++p;
                continue;
            }
            if (c == '"' || c == '\'')
            {
                quote = c;
                ++p;
                continue;
            }
            if (c == '[')
            {
                ++bracket_depth;
                ++p;
                continue;
            }
            if (c == ']' && bracket_depth > 0)
            {
                --bracket_depth;
                ++p;
                continue;
            }
            if (bracket_depth == 0)
            {
                if (c == '(')
                {
                    ++paren_depth;
                    ++p;
                    continue;
                }
                if (c == ')' && paren_depth > 0)
                {
                    --paren_depth;
                    ++p;
                    continue;
                }
            }
            if (bracket_depth == 0 && paren_depth == 0 && c == '.')
            {
                const char *name_start = p + 1;
                const char *q = name_start;
                bool token_escape = false;
                while (q < part_end)
                {
                    char qc = *q;
                    if (token_escape)
                    {
                        token_escape = false;
                        ++q;
                        continue;
                    }
                    if (qc == '\\')
                    {
                        token_escape = true;
                        ++q;
                        continue;
                    }
                    if (qc == ':' || qc == '.' || qc == '#' || qc == '[' || qc == ']' ||
                        qc == '(' || qc == ')' || isspace((unsigned char)qc))
                    {
                        break;
                    }
                    ++q;
                }
                if (q > name_start)
                {
                    uint32_t count = html_view_key_count_get(map, name_start, q);
                    size_t len = (size_t)(q - name_start);
                    if (count < best_count || (count == best_count && len > best_len))
                    {
                        best_count = count;
                        best_start = name_start;
                        best_end = q;
                        best_len = len;
                    }
                }
                p = q;
                continue;
            }
            ++p;
        }
    }

    if (best_start && best_end && best_end > best_start)
    {
        cache->scope_class_hint_valid = true;
        cache->scope_class_hint_start = (uint32_t)(best_start - selector);
        cache->scope_class_hint_len = (uint32_t)(best_end - best_start);
    }
}

static html_view_rule_bucket_t *html_view_rule_index_find_bucket_list(html_view_rule_bucket_t *buckets,
                                                                      size_t bucket_count,
                                                                      const char *key,
                                                                      size_t len)
{
    if (!buckets || !key || len == 0)
    {
        return NULL;
    }
    for (size_t i = 0; i < bucket_count; ++i)
    {
        html_view_rule_bucket_t *bucket = &buckets[i];
        if (bucket->tag_len == len && strncasecmp(bucket->tag, key, len) == 0)
        {
            return bucket;
        }
    }
    return NULL;
}

static html_view_rule_bucket_t *html_view_rule_index_get_bucket_list(html_view_rule_bucket_t **buckets,
                                                                     size_t *bucket_count,
                                                                     size_t *bucket_cap,
                                                                     const char *key,
                                                                     size_t len,
                                                                     bool unescape)
{
    if (!buckets || !bucket_count || !bucket_cap || !key || len == 0)
    {
        return NULL;
    }

    html_view_rule_bucket_t *bucket = html_view_rule_index_find_bucket_list(*buckets, *bucket_count, key, len);
    if (bucket)
    {
        return bucket;
    }

    if (*bucket_count == *bucket_cap)
    {
        size_t new_cap = *bucket_cap ? (*bucket_cap * 2u) : 8u;
        html_view_rule_bucket_t *next = (html_view_rule_bucket_t *)realloc(*buckets,
                                                                           new_cap * sizeof(*next));
        if (!next)
        {
            return NULL;
        }
        *buckets = next;
        *bucket_cap = new_cap;
    }

    char *key_copy = unescape
        ? html_view_strdup_lower_unescaped_range(key, len)
        : html_view_strdup_lower_range(key, len);
    if (!key_copy)
    {
        return NULL;
    }

    bucket = &(*buckets)[(*bucket_count)++];
    memset(bucket, 0, sizeof(*bucket));
    bucket->tag = key_copy;
    bucket->tag_len = strlen(key_copy);
    return bucket;
}

static html_view_rule_bucket_t *html_view_rule_bucket_find_parent_bucket(html_view_rule_bucket_t *bucket,
                                                                         const char *key,
                                                                         size_t len)
{
    if (!bucket || !key || len == 0 || !bucket->parent_buckets)
    {
        return NULL;
    }
    return html_view_rule_index_find_bucket_list(bucket->parent_buckets, bucket->parent_count, key, len);
}

static html_view_rule_bucket_t *html_view_rule_bucket_get_parent_bucket(html_view_rule_bucket_t *bucket,
                                                                        const char *key,
                                                                        size_t len)
{
    if (!bucket || !key || len == 0)
    {
        return NULL;
    }
    return html_view_rule_index_get_bucket_list(&bucket->parent_buckets,
                                                &bucket->parent_count,
                                                &bucket->parent_cap,
                                                key,
                                                len,
                                                true);
}

static bool html_view_rule_index_add_rule(html_view_rule_index_t *index, css_rule_t *rule, uint32_t order)
{
    if (!index || !rule || !rule->selector)
    {
        return false;
    }

    css_selector_cache_t *cache = rule->selector_cache;
    if (!cache)
    {
        cache = (css_selector_cache_t *)calloc(1, sizeof(*cache));
        if (!cache)
        {
            return false;
        }
        rule->selector_cache = cache;
    }
    cache->order = order;
    if (cache && !cache->parsed && !cache->parse_failed)
    {
        (void)html_view_selector_cache_parse(cache, rule->selector);
    }
    if (cache && (cache->parse_failed || cache->never_match))
    {
        return true;
    }

    uint8_t rule_pseudo_mask = cache ? cache->pseudo_mask : HTML_VIEW_PSEUDO_MASK_NONE;
    if (cache && cache->parsed && !cache->parse_failed)
    {
        if (cache->id_hint_valid)
        {
            const char *id_start = rule->selector + cache->id_hint_start;
            size_t id_len = cache->id_hint_len;
            html_view_rule_bucket_t *bucket = html_view_rule_index_get_bucket_list(&index->id_buckets,
                                                                                   &index->id_bucket_count,
                                                                                   &index->id_bucket_cap,
                                                                                   id_start,
                                                                                   id_len,
                                                                                   true);
            if (!bucket)
            {
                return false;
            }
            if (!html_view_rule_index_list_push(&bucket->rules, &bucket->count, &bucket->cap, rule))
            {
                return false;
            }
            bucket->pseudo_mask |= rule_pseudo_mask;
            return true;
        }

        if (cache->class_hint_valid)
        {
            const char *class_start = rule->selector + cache->class_hint_start;
            size_t class_len = cache->class_hint_len;
            html_view_rule_bucket_t *bucket = html_view_rule_index_get_bucket_list(&index->class_buckets,
                                                                                   &index->class_bucket_count,
                                                                                   &index->class_bucket_cap,
                                                                                   class_start,
                                                                                   class_len,
                                                                                   true);
            if (!bucket)
            {
                return false;
            }
            if (cache->parent_class_hint_valid)
            {
                const char *parent_start = rule->selector + cache->parent_class_hint_start;
                size_t parent_len = cache->parent_class_hint_len;
                html_view_rule_bucket_t *parent_bucket = html_view_rule_bucket_get_parent_bucket(bucket,
                                                                                                 parent_start,
                                                                                                 parent_len);
                if (!parent_bucket)
                {
                    return false;
                }
                if (!html_view_rule_index_list_push(&parent_bucket->rules,
                                                    &parent_bucket->count,
                                                    &parent_bucket->cap,
                                                    rule))
                {
                    return false;
                }
                parent_bucket->pseudo_mask |= rule_pseudo_mask;
                return true;
            }
            if (!html_view_rule_index_list_push(&bucket->rules, &bucket->count, &bucket->cap, rule))
            {
                return false;
            }
            bucket->pseudo_mask |= rule_pseudo_mask;
            return true;
        }

        if (cache->attr_hint_valid)
        {
            const char *attr_start = rule->selector + cache->attr_hint_name_start;
            size_t attr_len = cache->attr_hint_name_len;
            html_view_rule_bucket_t *bucket = html_view_rule_index_get_bucket_list(&index->attr_buckets,
                                                                                   &index->attr_bucket_count,
                                                                                   &index->attr_bucket_cap,
                                                                                   attr_start,
                                                                                   attr_len,
                                                                                   true);
            if (!bucket)
            {
                return false;
            }
            if (!html_view_rule_index_list_push(&bucket->rules, &bucket->count, &bucket->cap, rule))
            {
                return false;
            }
            bucket->pseudo_mask |= rule_pseudo_mask;
            return true;
        }

        if (!cache->id_hint_valid && !cache->class_hint_valid && !cache->attr_hint_valid &&
            cache->scope_class_hint_valid)
        {
            const char *scope_start = rule->selector + cache->scope_class_hint_start;
            size_t scope_len = cache->scope_class_hint_len;
            html_view_rule_bucket_t *bucket = html_view_rule_index_get_bucket_list(&index->scope_class_buckets,
                                                                                   &index->scope_class_bucket_count,
                                                                                   &index->scope_class_bucket_cap,
                                                                                   scope_start,
                                                                                   scope_len,
                                                                                   true);
            if (!bucket)
            {
                return false;
            }
            if (!html_view_rule_index_list_push(&bucket->rules, &bucket->count, &bucket->cap, rule))
            {
                return false;
            }
            bucket->pseudo_mask |= rule_pseudo_mask;
            return true;
        }

        if (cache->tag_hint_valid && !cache->tag_hint_any)
        {
            const char *tag_start = rule->selector + cache->tag_hint_start;
            size_t tag_len = cache->tag_hint_len;
            html_view_rule_bucket_t *bucket = html_view_rule_index_get_bucket_list(&index->tag_buckets,
                                                                                   &index->tag_bucket_count,
                                                                                   &index->tag_bucket_cap,
                                                                                   tag_start,
                                                                                   tag_len,
                                                                                   false);
            if (!bucket)
            {
                return false;
            }
            if (!html_view_rule_index_list_push(&bucket->rules, &bucket->count, &bucket->cap, rule))
            {
                return false;
            }
            bucket->pseudo_mask |= rule_pseudo_mask;
            return true;
        }
    }

    if (!html_view_rule_index_list_push(&index->global_rules,
                                        &index->global_count,
                                        &index->global_cap,
                                        rule))
    {
        return false;
    }
    index->global_pseudo_mask |= rule_pseudo_mask;
    return true;
}

static html_view_rule_index_t *html_view_rule_index_build(const css_stylesheet_t *sheet)
{
    if (!sheet)
    {
        return NULL;
    }
    html_view_rule_index_t *index = (html_view_rule_index_t *)calloc(1, sizeof(*index));
    if (!index)
    {
        return NULL;
    }
    index->sheet = sheet;

    html_view_key_count_map_t class_freq = {0};
    for (css_rule_t *rule = sheet->rules; rule; rule = rule->next)
    {
        if (!rule->selector)
        {
            continue;
        }
        css_selector_cache_t *cache = rule->selector_cache;
        if (!cache)
        {
            cache = (css_selector_cache_t *)calloc(1, sizeof(*cache));
            if (!cache)
            {
                continue;
            }
            rule->selector_cache = cache;
        }
        if (!cache->parsed && !cache->parse_failed)
        {
            (void)html_view_selector_cache_parse(cache, rule->selector);
        }
        if (!cache->parsed || cache->parse_failed || cache->never_match || cache->count == 0)
        {
            continue;
        }

        for (size_t part_idx = 0; part_idx < cache->count; ++part_idx)
        {
            const css_selector_part_t *part = &cache->parts[part_idx];
            const char *part_start = rule->selector + part->start;
            const char *part_end = rule->selector + part->end;
            html_view_trim_range(&part_start, &part_end);
            if (part_end > part_start)
            {
                html_view_selector_collect_class_counts(part_start, part_end, &class_freq);
            }
        }
    }

    uint32_t order = 0;
    for (css_rule_t *rule = sheet->rules; rule; rule = rule->next)
    {
        if (rule->selector && rule->selector_cache && rule->selector_cache->parsed)
        {
            html_view_selector_choose_best_class_hint(rule->selector_cache,
                                                      rule->selector,
                                                      &class_freq);
            html_view_selector_choose_best_scope_class_hint(rule->selector_cache,
                                                            rule->selector,
                                                            &class_freq);
        }
        if (!html_view_rule_index_add_rule(index, rule, order++))
        {
            html_view_key_count_map_free(&class_freq);
            html_view_rule_index_free(index);
            return NULL;
        }
    }

    html_view_key_count_map_free(&class_freq);
    return index;
}

static const html_view_rule_index_t *html_view_rule_index_get(atk_html_view_priv_t *priv,
                                                              const css_stylesheet_t *sheet)
{
    if (!priv || !sheet)
    {
        return NULL;
    }
    if (priv->rule_index && priv->rule_index->sheet == sheet)
    {
        return priv->rule_index;
    }

    html_view_rule_index_clear(priv);
    priv->rule_index = html_view_rule_index_build(sheet);
    return priv->rule_index;
}

typedef struct
{
    css_rule_t *const *rules;
    size_t count;
} html_view_rule_list_t;

static uint32_t html_view_rule_order(const css_rule_t *rule)
{
    if (!rule || !rule->selector_cache)
    {
        return 0xffffffffu;
    }
    return rule->selector_cache->order;
}

static void html_view_apply_rule(css_style_t *out,
                                 const html_node_t *node,
                                 html_view_pseudo_t pseudo,
                                 css_rule_t *rule)
{
    if (!out || !node || !rule || !rule->selector)
    {
        return;
    }
    css_selector_cache_t *cache = NULL;
    bool fallback = false;
    if (!html_view_selector_cache_precheck(rule, node, pseudo, &cache, &fallback))
    {
        return;
    }
#ifdef HTML_VIEW_HOST_TRACE
    html_view_trace_note_rule(node,
                              rule->selector,
                              pseudo == HTML_VIEW_PSEUDO_NONE ? "style" : "pseudo");
#endif
    bool match = false;
    if (fallback || !cache)
    {
        match = html_view_selector_matches_internal(rule->selector, node, pseudo);
    }
    else
    {
        match = html_view_selector_matches_parts(cache->parts, cache->count, rule->selector, node, pseudo);
    }
    if (match)
    {
        css_style_merge(out, &rule->style);
    }
}

static void html_view_apply_rule_list(css_style_t *out,
                                      const html_node_t *node,
                                      html_view_pseudo_t pseudo,
                                      css_rule_t *const *rules,
                                      size_t rule_count)
{
    if (!out || !node || !rules)
    {
        return;
    }
    for (size_t i = 0; i < rule_count; ++i)
    {
        html_view_apply_rule(out, node, pseudo, rules[i]);
    }
}

static void html_view_rule_list_add_unique(html_view_rule_list_t *lists,
                                           size_t *list_count,
                                           size_t list_cap,
                                           css_rule_t *const *rules,
                                           size_t rule_count)
{
    if (!lists || !list_count || !rules || rule_count == 0)
    {
        return;
    }
    for (size_t i = 0; i < *list_count; ++i)
    {
        if (lists[i].rules == rules)
        {
            return;
        }
    }
    if (*list_count < list_cap)
    {
        lists[(*list_count)++] = (html_view_rule_list_t){
            .rules = rules,
            .count = rule_count,
        };
    }
}

static void html_view_apply_rule_lists(css_style_t *out,
                                       const html_node_t *node,
                                       html_view_pseudo_t pseudo,
                                       const html_view_rule_list_t *lists,
                                       size_t list_count)
{
    if (!out || !node || !lists || list_count == 0)
    {
        return;
    }
    if (list_count == 1)
    {
        html_view_apply_rule_list(out, node, pseudo, lists[0].rules, lists[0].count);
        return;
    }

    size_t *positions = (size_t *)calloc(list_count, sizeof(*positions));
    if (!positions)
    {
        for (size_t i = 0; i < list_count; ++i)
        {
            html_view_apply_rule_list(out, node, pseudo, lists[i].rules, lists[i].count);
        }
        return;
    }

    for (;;)
    {
        size_t best = (size_t)-1;
        uint32_t best_order = 0xffffffffu;
        for (size_t i = 0; i < list_count; ++i)
        {
            size_t pos = positions[i];
            if (pos >= lists[i].count)
            {
                continue;
            }
            css_rule_t *rule = lists[i].rules[pos];
            uint32_t order = html_view_rule_order(rule);
            if (best == (size_t)-1 || order < best_order)
            {
                best = i;
                best_order = order;
            }
        }
        if (best == (size_t)-1)
        {
            break;
        }
        css_rule_t *rule = lists[best].rules[positions[best]++];
        html_view_apply_rule(out, node, pseudo, rule);
    }

    free(positions);
}

static size_t html_view_count_class_tokens(const char *classes)
{
    if (!classes || classes[0] == '\0')
    {
        return 0;
    }
    size_t count = 0;
    const char *p = classes;
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
        ++count;
        while (*p && !isspace((unsigned char)*p))
        {
            ++p;
        }
    }
    return count;
}

static void html_view_apply_indexed_rules(css_style_t *out,
                                          const html_node_t *node,
                                          html_view_pseudo_t pseudo,
                                          const html_view_rule_index_t *index)
{
    if (!out || !node || !index)
    {
        return;
    }

    const char *id = html_attr_get(node, "id");
    size_t id_len = (id && id[0] != '\0') ? strlen(id) : 0;

    const char *classes_value = NULL;
    size_t class_token_count = 0;
    const html_class_token_t *class_tokens = html_view_node_class_tokens(node,
                                                                         &class_token_count,
                                                                         &classes_value);
    size_t class_scan_count = 0;
    if (class_token_count == 0 && classes_value && classes_value[0] != '\0')
    {
        class_scan_count = html_view_count_class_tokens(classes_value);
    }

    const html_node_t *parent = (node && node->type == HTML_NODE_ELEMENT) ? node->parent : NULL;
    const char *parent_classes_value = NULL;
    size_t parent_class_token_count = 0;
    const html_class_token_t *parent_tokens = NULL;
    size_t parent_class_scan_count = 0;
    if (parent && parent->type == HTML_NODE_ELEMENT)
    {
        parent_tokens = html_view_node_class_tokens(parent,
                                                    &parent_class_token_count,
                                                    &parent_classes_value);
        if (parent_class_token_count == 0 && parent_classes_value && parent_classes_value[0] != '\0')
        {
            parent_class_scan_count = html_view_count_class_tokens(parent_classes_value);
        }
    }

    uint8_t pseudo_mask = html_view_pseudo_mask(pseudo);
    bool wants_pseudo = (pseudo != HTML_VIEW_PSEUDO_NONE);

    size_t max_lists = 0;
    if (index->global_count > 0 &&
        (!wants_pseudo || (index->global_pseudo_mask & pseudo_mask) != 0))
    {
        ++max_lists;
    }
    if (node->name)
    {
        ++max_lists;
    }
    if (id_len > 0)
    {
        ++max_lists;
    }
    size_t class_count = class_token_count ? class_token_count : class_scan_count;
    size_t parent_count = parent_class_token_count ? parent_class_token_count : parent_class_scan_count;
    size_t ancestor_class_count = 0;
    if (index->scope_class_bucket_count > 0 && parent)
    {
        for (const html_node_t *anc = parent; anc; anc = anc->parent)
        {
            size_t token_count = 0;
            const char *classes_value = NULL;
            const html_class_token_t *tokens = html_view_node_class_tokens(anc,
                                                                           &token_count,
                                                                           &classes_value);
            if (tokens && token_count > 0)
            {
                ancestor_class_count += token_count;
            }
            else if (classes_value && classes_value[0] != '\0')
            {
                ancestor_class_count += html_view_count_class_tokens(classes_value);
            }
        }
    }
    size_t attr_count = 0;
    if (node && node->type == HTML_NODE_ELEMENT)
    {
        for (const html_attr_t *attr = node->attrs; attr; attr = attr->next)
        {
            if (attr->name && attr->name[0] != '\0')
            {
                ++attr_count;
            }
        }
    }
    max_lists += class_count;
    max_lists += ancestor_class_count;
    max_lists += attr_count;
    if (class_count > 0 && parent_count > 0)
    {
        size_t extra = class_count * parent_count;
        if (parent_count != 0 && extra / parent_count == class_count)
        {
            max_lists += extra;
        }
    }
    if (max_lists == 0)
    {
        return;
    }

    html_view_rule_list_t *lists = (html_view_rule_list_t *)calloc(max_lists, sizeof(*lists));
    if (!lists)
    {
        for (css_rule_t *rule = index->sheet->rules; rule; rule = rule->next)
        {
            html_view_apply_rule(out, node, pseudo, rule);
        }
        return;
    }

    size_t list_count = 0;
    if (index->global_count > 0 &&
        (!wants_pseudo || (index->global_pseudo_mask & pseudo_mask) != 0))
    {
        html_view_rule_list_add_unique(lists, &list_count, max_lists,
                                       index->global_rules,
                                       index->global_count);
    }

    if (node->name)
    {
        html_view_rule_bucket_t *bucket = html_view_rule_index_find_bucket_list(index->tag_buckets,
                                                                                index->tag_bucket_count,
                                                                                node->name,
                                                                                strlen(node->name));
        if (bucket && bucket->count > 0 &&
            (!wants_pseudo || (bucket->pseudo_mask & pseudo_mask) != 0))
        {
            html_view_rule_list_add_unique(lists, &list_count, max_lists,
                                           bucket->rules,
                                           bucket->count);
        }
    }

    if (id_len > 0)
    {
        html_view_rule_bucket_t *bucket = html_view_rule_index_find_bucket_list(index->id_buckets,
                                                                                index->id_bucket_count,
                                                                                id,
                                                                                id_len);
        if (bucket && bucket->count > 0 &&
            (!wants_pseudo || (bucket->pseudo_mask & pseudo_mask) != 0))
        {
            html_view_rule_list_add_unique(lists, &list_count, max_lists,
                                           bucket->rules,
                                           bucket->count);
        }
    }

    if (attr_count > 0)
    {
        for (const html_attr_t *attr = node->attrs; attr; attr = attr->next)
        {
            if (!attr->name || attr->name[0] == '\0')
            {
                continue;
            }
            html_view_rule_bucket_t *bucket = html_view_rule_index_find_bucket_list(index->attr_buckets,
                                                                                    index->attr_bucket_count,
                                                                                    attr->name,
                                                                                    strlen(attr->name));
            if (!bucket)
            {
                continue;
            }
            if (bucket->count > 0 &&
                (!wants_pseudo || (bucket->pseudo_mask & pseudo_mask) != 0))
            {
                html_view_rule_list_add_unique(lists, &list_count, max_lists,
                                               bucket->rules,
                                               bucket->count);
            }
        }
    }

    if (class_token_count > 0 && class_tokens)
    {
        for (size_t i = 0; i < class_token_count; ++i)
        {
            const html_class_token_t *tok = &class_tokens[i];
            if (tok->len == 0)
            {
                continue;
            }
            html_view_rule_bucket_t *bucket = html_view_rule_index_find_bucket_list(index->class_buckets,
                                                                                    index->class_bucket_count,
                                                                                    tok->start,
                                                                                    tok->len);
            if (!bucket)
            {
                continue;
            }
            if (bucket->count > 0 &&
                (!wants_pseudo || (bucket->pseudo_mask & pseudo_mask) != 0))
            {
                html_view_rule_list_add_unique(lists, &list_count, max_lists,
                                               bucket->rules,
                                               bucket->count);
            }
            if (parent && bucket->parent_count > 0)
            {
                if (parent_class_token_count > 0 && parent_tokens)
                {
                    for (size_t j = 0; j < parent_class_token_count; ++j)
                    {
                        const html_class_token_t *ptok = &parent_tokens[j];
                        if (ptok->len == 0)
                        {
                            continue;
                        }
                        html_view_rule_bucket_t *parent_bucket = html_view_rule_bucket_find_parent_bucket(bucket,
                                                                                                         ptok->start,
                                                                                                         ptok->len);
                        if (parent_bucket && parent_bucket->count > 0 &&
                            (!wants_pseudo || (parent_bucket->pseudo_mask & pseudo_mask) != 0))
                        {
                            html_view_rule_list_add_unique(lists, &list_count, max_lists,
                                                           parent_bucket->rules,
                                                           parent_bucket->count);
                        }
                    }
                }
                else if (parent_classes_value && parent_classes_value[0] != '\0')
                {
                    const char *pp = parent_classes_value;
                    while (*pp)
                    {
                        while (*pp && isspace((unsigned char)*pp))
                        {
                            ++pp;
                        }
                        if (!*pp)
                        {
                            break;
                        }
                        const char *pstart = pp;
                        while (*pp && !isspace((unsigned char)*pp))
                        {
                            ++pp;
                        }
                        size_t plen = (size_t)(pp - pstart);
                        if (plen == 0)
                        {
                            continue;
                        }
                        html_view_rule_bucket_t *parent_bucket = html_view_rule_bucket_find_parent_bucket(bucket,
                                                                                                         pstart,
                                                                                                         plen);
                        if (parent_bucket && parent_bucket->count > 0 &&
                            (!wants_pseudo || (parent_bucket->pseudo_mask & pseudo_mask) != 0))
                        {
                            html_view_rule_list_add_unique(lists, &list_count, max_lists,
                                                           parent_bucket->rules,
                                                           parent_bucket->count);
                        }
                    }
                }
            }
        }
    }

    if (ancestor_class_count > 0 && index->scope_class_bucket_count > 0)
    {
        for (const html_node_t *anc = parent; anc; anc = anc->parent)
        {
            size_t token_count = 0;
            const char *classes_value = NULL;
            const html_class_token_t *tokens = html_view_node_class_tokens(anc,
                                                                           &token_count,
                                                                           &classes_value);
            if (token_count == 0 && classes_value && classes_value[0] != '\0')
            {
                const char *p = classes_value;
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
                    if (len == 0)
                    {
                        continue;
                    }
                    html_view_rule_bucket_t *bucket = html_view_rule_index_find_bucket_list(index->scope_class_buckets,
                                                                                            index->scope_class_bucket_count,
                                                                                            start,
                                                                                            len);
                    if (!bucket)
                    {
                        continue;
                    }
                    if (bucket->count > 0 &&
                        (!wants_pseudo || (bucket->pseudo_mask & pseudo_mask) != 0))
                    {
                        html_view_rule_list_add_unique(lists, &list_count, max_lists,
                                                       bucket->rules,
                                                       bucket->count);
                    }
                }
                continue;
            }
            if (tokens && token_count > 0)
            {
                for (size_t i = 0; i < token_count; ++i)
                {
                    const html_class_token_t *tok = &tokens[i];
                    if (tok->len == 0)
                    {
                        continue;
                    }
                    html_view_rule_bucket_t *bucket = html_view_rule_index_find_bucket_list(index->scope_class_buckets,
                                                                                            index->scope_class_bucket_count,
                                                                                            tok->start,
                                                                                            tok->len);
                    if (!bucket)
                    {
                        continue;
                    }
                    if (bucket->count > 0 &&
                        (!wants_pseudo || (bucket->pseudo_mask & pseudo_mask) != 0))
                    {
                        html_view_rule_list_add_unique(lists, &list_count, max_lists,
                                                       bucket->rules,
                                                       bucket->count);
                    }
                }
            }
        }
    }
    else if (classes_value && classes_value[0] != '\0')
    {
        const char *p = classes_value;
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
            if (len == 0)
            {
                continue;
            }
            html_view_rule_bucket_t *bucket = html_view_rule_index_find_bucket_list(index->class_buckets,
                                                                                    index->class_bucket_count,
                                                                                    start,
                                                                                    len);
            if (!bucket)
            {
                continue;
            }
            if (bucket->count > 0 &&
                (!wants_pseudo || (bucket->pseudo_mask & pseudo_mask) != 0))
            {
                html_view_rule_list_add_unique(lists, &list_count, max_lists,
                                               bucket->rules,
                                               bucket->count);
            }
            if (parent && bucket->parent_count > 0)
            {
                if (parent_class_token_count > 0 && parent_tokens)
                {
                    for (size_t j = 0; j < parent_class_token_count; ++j)
                    {
                        const html_class_token_t *ptok = &parent_tokens[j];
                        if (ptok->len == 0)
                        {
                            continue;
                        }
                        html_view_rule_bucket_t *parent_bucket = html_view_rule_bucket_find_parent_bucket(bucket,
                                                                                                         ptok->start,
                                                                                                         ptok->len);
                        if (parent_bucket && parent_bucket->count > 0 &&
                            (!wants_pseudo || (parent_bucket->pseudo_mask & pseudo_mask) != 0))
                        {
                            html_view_rule_list_add_unique(lists, &list_count, max_lists,
                                                           parent_bucket->rules,
                                                           parent_bucket->count);
                        }
                    }
                }
                else if (parent_classes_value && parent_classes_value[0] != '\0')
                {
                    const char *pp = parent_classes_value;
                    while (*pp)
                    {
                        while (*pp && isspace((unsigned char)*pp))
                        {
                            ++pp;
                        }
                        if (!*pp)
                        {
                            break;
                        }
                        const char *pstart = pp;
                        while (*pp && !isspace((unsigned char)*pp))
                        {
                            ++pp;
                        }
                        size_t plen = (size_t)(pp - pstart);
                        if (plen == 0)
                        {
                            continue;
                        }
                        html_view_rule_bucket_t *parent_bucket = html_view_rule_bucket_find_parent_bucket(bucket,
                                                                                                         pstart,
                                                                                                         plen);
                        if (parent_bucket && parent_bucket->count > 0 &&
                            (!wants_pseudo || (parent_bucket->pseudo_mask & pseudo_mask) != 0))
                        {
                            html_view_rule_list_add_unique(lists, &list_count, max_lists,
                                                           parent_bucket->rules,
                                                           parent_bucket->count);
                        }
                    }
                }
            }
        }
    }

    if (list_count > 0)
    {
        html_view_apply_rule_lists(out, node, pseudo, lists, list_count);
    }

    free(lists);
}

static bool html_view_parse_color(const char *s, video_color_t *out)
{
    if (!s || !out || s[0] == '\0')
    {
        return false;
    }

    const char *start = s;
    while (*start && isspace((unsigned char)*start))
    {
        ++start;
    }
    const char *end = start + strlen(start);
    while (end > start && isspace((unsigned char)end[-1]))
    {
        --end;
    }
    if (end <= start)
    {
        return false;
    }

    if (*start == '#')
    {
        ++start;
        size_t len = (size_t)(end - start);
        if (len != 3 && len != 6)
        {
            return false;
        }

        uint32_t value = 0;
        for (size_t i = 0; i < len; ++i)
        {
            unsigned char c = (unsigned char)start[i];
            uint32_t d = 0;
            if (c >= '0' && c <= '9')
            {
                d = (uint32_t)(c - '0');
            }
            else if (c >= 'a' && c <= 'f')
            {
                d = 10u + (uint32_t)(c - 'a');
            }
            else if (c >= 'A' && c <= 'F')
            {
                d = 10u + (uint32_t)(c - 'A');
            }
            else
            {
                return false;
            }
            value = (value << 4) | d;
        }

        if (len == 3)
        {
            uint8_t r = (uint8_t)(((value >> 8) & 0xFu) * 17u);
            uint8_t g = (uint8_t)(((value >> 4) & 0xFu) * 17u);
            uint8_t b = (uint8_t)(((value >> 0) & 0xFu) * 17u);
            *out = video_make_color(r, g, b);
            return true;
        }

        uint8_t r = (uint8_t)((value >> 16) & 0xFFu);
        uint8_t g = (uint8_t)((value >> 8) & 0xFFu);
        uint8_t b = (uint8_t)((value >> 0) & 0xFFu);
        *out = video_make_color(r, g, b);
        return true;
    }

    size_t len = (size_t)(end - start);
    if (len == 5 && strncasecmp(start, "black", 5) == 0)
    {
        *out = video_make_color(0x00, 0x00, 0x00);
        return true;
    }
    if (len == 5 && strncasecmp(start, "white", 5) == 0)
    {
        *out = video_make_color(0xFF, 0xFF, 0xFF);
        return true;
    }
    if (len == 6 && strncasecmp(start, "silver", 6) == 0)
    {
        *out = video_make_color(0xC0, 0xC0, 0xC0);
        return true;
    }
    if ((len == 4 && strncasecmp(start, "gray", 4) == 0) ||
        (len == 4 && strncasecmp(start, "grey", 4) == 0))
    {
        *out = video_make_color(0x80, 0x80, 0x80);
        return true;
    }
    if (len == 6 && strncasecmp(start, "maroon", 6) == 0)
    {
        *out = video_make_color(0x80, 0x00, 0x00);
        return true;
    }
    if (len == 3 && strncasecmp(start, "red", 3) == 0)
    {
        *out = video_make_color(0xFF, 0x00, 0x00);
        return true;
    }
    if (len == 6 && strncasecmp(start, "purple", 6) == 0)
    {
        *out = video_make_color(0x80, 0x00, 0x80);
        return true;
    }
    if (len == 7 && strncasecmp(start, "fuchsia", 7) == 0)
    {
        *out = video_make_color(0xFF, 0x00, 0xFF);
        return true;
    }
    if (len == 5 && strncasecmp(start, "green", 5) == 0)
    {
        *out = video_make_color(0x00, 0x80, 0x00);
        return true;
    }
    if (len == 4 && strncasecmp(start, "lime", 4) == 0)
    {
        *out = video_make_color(0x00, 0xFF, 0x00);
        return true;
    }
    if (len == 5 && strncasecmp(start, "olive", 5) == 0)
    {
        *out = video_make_color(0x80, 0x80, 0x00);
        return true;
    }
    if (len == 6 && strncasecmp(start, "yellow", 6) == 0)
    {
        *out = video_make_color(0xFF, 0xFF, 0x00);
        return true;
    }
    if (len == 4 && strncasecmp(start, "navy", 4) == 0)
    {
        *out = video_make_color(0x00, 0x00, 0x80);
        return true;
    }
    if (len == 4 && strncasecmp(start, "blue", 4) == 0)
    {
        *out = video_make_color(0x00, 0x00, 0xFF);
        return true;
    }
    if (len == 4 && strncasecmp(start, "teal", 4) == 0)
    {
        *out = video_make_color(0x00, 0x80, 0x80);
        return true;
    }
    if (len == 4 && strncasecmp(start, "aqua", 4) == 0)
    {
        *out = video_make_color(0x00, 0xFF, 0xFF);
        return true;
    }
    if (len == 6 && strncasecmp(start, "orange", 6) == 0)
    {
        *out = video_make_color(0xFF, 0xA5, 0x00);
        return true;
    }

    return false;
}

static int html_view_font_size_percent(int size)
{
    static const int sizes[] = {67, 83, 100, 117, 150, 200, 300};
    if (size < 1)
    {
        size = 1;
    }
    if (size > (int)(sizeof(sizes) / sizeof(sizes[0])))
    {
        size = (int)(sizeof(sizes) / sizeof(sizes[0]));
    }
    return sizes[size - 1];
}

static bool html_view_parse_font_size_attr(const char *value, css_length_t *out)
{
    if (!value || !out)
    {
        return false;
    }
    while (*value && isspace((unsigned char)*value))
    {
        ++value;
    }
    if (*value == '\0')
    {
        return false;
    }

    bool relative = false;
    int sign = 1;
    if (*value == '+' || *value == '-')
    {
        relative = true;
        sign = (*value == '-') ? -1 : 1;
        ++value;
    }

    int number = 0;
    bool have_digit = false;
    while (*value && isdigit((unsigned char)*value))
    {
        have_digit = true;
        number = number * 10 + (*value - '0');
        ++value;
    }
    if (!have_digit)
    {
        return false;
    }

    int size = relative ? (3 + sign * number) : number;
    int percent = html_view_font_size_percent(size);
    out->valid = true;
    out->is_auto = false;
    out->value_milli = percent * 1000;
    out->unit = CSS_UNIT_PERCENT;
    return true;
}

static bool html_view_parse_html_length_attr(const char *value, css_length_t *out)
{
    if (!value || !out)
    {
        return false;
    }
    while (*value && isspace((unsigned char)*value))
    {
        ++value;
    }
    if (*value == '\0')
    {
        return false;
    }

    bool percent = false;
    int32_t number = 0;
    bool have_digit = false;
    const char *p = value;
    while (*p && isdigit((unsigned char)*p))
    {
        have_digit = true;
        number = number * 10 + (*p - '0');
        ++p;
        if (number > 1000000)
        {
            break;
        }
    }
    while (*p && isspace((unsigned char)*p))
    {
        ++p;
    }
    if (*p == '%')
    {
        percent = true;
    }

    if (!have_digit)
    {
        return false;
    }

    out->valid = true;
    out->is_auto = false;
    out->value_milli = number * 1000;
    out->unit = percent ? CSS_UNIT_PERCENT : CSS_UNIT_PX;
    return true;
}

static void html_view_apply_presentational_attrs(css_style_t *style, const css_style_t *parent, const html_node_t *node)
{
    (void)parent;
    if (!style || !node || node->type != HTML_NODE_ELEMENT || !node->name)
    {
        return;
    }

    const char *bgcolor = html_attr_get(node, "bgcolor");
    if (bgcolor && bgcolor[0] != '\0' && !style->has_background)
    {
        video_color_t c;
        if (html_view_parse_color(bgcolor, &c))
        {
            style->has_background = true;
            style->background = c;
        }
    }

    const char *color = html_attr_get(node, "color");
    if (color && color[0] != '\0' && !style->has_color)
    {
        video_color_t c;
        if (html_view_parse_color(color, &c))
        {
            style->has_color = true;
            style->color = c;
        }
    }

    const char *w = html_attr_get(node, "width");
    if (w && w[0] != '\0' && !style->has_width)
    {
        css_length_t len = {0};
        if (html_view_parse_html_length_attr(w, &len))
        {
            style->has_width = true;
            style->width = len;
        }
    }

    const char *h = html_attr_get(node, "height");
    if (h && h[0] != '\0' && !style->has_height)
    {
        css_length_t len = {0};
        if (html_view_parse_html_length_attr(h, &len))
        {
            style->has_height = true;
            style->height = len;
        }
    }

    const char *align = html_attr_get(node, "align");
    if (align && align[0] != '\0' && !style->has_text_align)
    {
        if (strcasecmp(align, "center") == 0)
        {
            style->has_text_align = true;
            style->text_align = CSS_TEXT_ALIGN_CENTER;
        }
        else if (strcasecmp(align, "right") == 0)
        {
            style->has_text_align = true;
            style->text_align = CSS_TEXT_ALIGN_RIGHT;
        }
        else if (strcasecmp(align, "left") == 0)
        {
            style->has_text_align = true;
            style->text_align = CSS_TEXT_ALIGN_LEFT;
        }
    }

    if (strcmp(node->name, "table") == 0)
    {
        const char *border = html_attr_get(node, "border");
        if (border && border[0] != '\0' && !style->has_border)
        {
            int b = atoi(border);
            if (b > 0)
            {
                css_length_t px = {
                    .valid = true,
                    .is_auto = false,
                    .value_milli = b * 1000,
                    .unit = CSS_UNIT_PX,
                };
                style->has_border = true;
                style->border_width.top = px;
                style->border_width.right = px;
                style->border_width.bottom = px;
                style->border_width.left = px;
            }
        }

        const char *table_align = html_attr_get(node, "align");
        if (table_align && table_align[0] != '\0' && strcasecmp(table_align, "center") == 0)
        {
            style->has_margin = true;
            style->margin.left.valid = true;
            style->margin.left.is_auto = true;
            style->margin.right.valid = true;
            style->margin.right.is_auto = true;
        }
    }

    if (strcmp(node->name, "center") == 0 && !style->has_text_align)
    {
        style->has_text_align = true;
        style->text_align = CSS_TEXT_ALIGN_CENTER;
    }

    if (strcmp(node->name, "font") == 0)
    {
        const char *size = html_attr_get(node, "size");
        if (size && size[0] != '\0' && !style->has_font_size)
        {
            css_length_t len = {0};
            if (html_view_parse_font_size_attr(size, &len))
            {
                style->has_font_size = true;
                style->font_size = len;
            }
        }
    }
}

static void html_view_apply_inline_style(css_style_t *style, const char *inline_style)
{
    if (!style || !inline_style || inline_style[0] == '\0')
    {
        return;
    }
    size_t len = strlen(inline_style);
    char *buf = (char *)malloc(len + 4);
    if (!buf)
    {
        return;
    }
    memcpy(buf, "x{", 2);
    memcpy(buf + 2, inline_style, len);
    buf[2 + len] = '}';
    buf[3 + len] = '\0';

    css_stylesheet_t *sheet = css_parse(buf);
    free(buf);
    if (!sheet)
    {
        return;
    }
    if (sheet->rules)
    {
        css_style_merge(style, &sheet->rules->style);
        if (sheet->rules->style.has_background_image)
        {
            if (style->background_image_owned && style->background_image)
            {
                free((void *)style->background_image);
                style->background_image = NULL;
            }
            style->background_image_owned = false;
            style->has_background_image = true;
            style->background_image = NULL;
            if (sheet->rules->style.background_image)
            {
                char *dup = html_view_strdup(sheet->rules->style.background_image);
                if (dup)
                {
                    style->background_image = dup;
                    style->background_image_owned = true;
                }
            }
        }
        if (sheet->rules->style.has_content)
        {
            if (style->content_owned && style->content)
            {
                free((void *)style->content);
                style->content = NULL;
            }
            style->content_owned = false;
            style->has_content = true;
            style->content = NULL;
            if (sheet->rules->style.content)
            {
                char *dup = html_view_strdup(sheet->rules->style.content);
                if (dup)
                {
                    style->content = dup;
                    style->content_owned = true;
                }
            }
        }
    }
    css_stylesheet_destroy(sheet);
}

static css_stylesheet_t *html_view_inline_style_sheet(const char *inline_style)
{
    if (!inline_style || inline_style[0] == '\0')
    {
        return NULL;
    }
    size_t len = strlen(inline_style);
    char *buf = (char *)malloc(len + 4);
    if (!buf)
    {
        return NULL;
    }
    memcpy(buf, "x{", 2);
    memcpy(buf + 2, inline_style, len);
    buf[2 + len] = '}';
    buf[3 + len] = '\0';

    css_stylesheet_t *sheet = css_parse(buf);
    free(buf);
    return sheet;
}

void html_view_inline_style_cache_clear(atk_html_view_priv_t *priv)
{
    if (!priv || !priv->inline_cache)
    {
        return;
    }
    for (size_t i = 0; i < priv->inline_cache_count; ++i)
    {
        if (priv->inline_cache[i].sheet)
        {
            css_stylesheet_destroy(priv->inline_cache[i].sheet);
        }
    }
    free(priv->inline_cache);
    priv->inline_cache = NULL;
    priv->inline_cache_count = 0;
    priv->inline_cache_cap = 0;
}

const css_style_t *html_view_inline_style_cached(atk_html_view_priv_t *priv,
                                                 const html_node_t *node,
                                                 const char *inline_style)
{
    if (!priv || !node || !inline_style || inline_style[0] == '\0')
    {
        return NULL;
    }

    for (size_t i = 0; i < priv->inline_cache_count; ++i)
    {
        html_view_inline_style_cache_t *entry = &priv->inline_cache[i];
        if (entry->node == node && entry->style_attr == inline_style)
        {
            return entry->style;
        }
    }

    css_stylesheet_t *sheet = html_view_inline_style_sheet(inline_style);
    if (!sheet || !sheet->rules)
    {
        if (sheet)
        {
            css_stylesheet_destroy(sheet);
        }
        return NULL;
    }

    if (priv->inline_cache_count == priv->inline_cache_cap)
    {
        size_t new_cap = priv->inline_cache_cap ? (priv->inline_cache_cap * 2u) : 16u;
        html_view_inline_style_cache_t *next = (html_view_inline_style_cache_t *)realloc(priv->inline_cache,
                                                                                         new_cap * sizeof(*next));
        if (!next)
        {
            css_stylesheet_destroy(sheet);
            return NULL;
        }
        priv->inline_cache = next;
        priv->inline_cache_cap = new_cap;
    }

    html_view_inline_style_cache_t *entry = &priv->inline_cache[priv->inline_cache_count++];
    entry->node = node;
    entry->style_attr = inline_style;
    entry->sheet = sheet;
    entry->style = &sheet->rules->style;
    return entry->style;
}

void html_view_style_for_node(css_style_t *out,
                              const css_stylesheet_t *sheet,
                              const css_style_t *parent,
                              const html_node_t *node,
                              atk_html_view_priv_t *priv)
{
    if (!out)
    {
        return;
    }
    memset(out, 0, sizeof(*out));

    if (priv)
    {
        html_view_dom_bloom_rebuild_if_needed(priv);
    }

    bool is_table_cell = false;
    bool is_table_header = false;
    if (node && node->type == HTML_NODE_ELEMENT && node->name)
    {
        is_table_cell = (strcmp(node->name, "td") == 0 || strcmp(node->name, "th") == 0);
        is_table_header = (strcmp(node->name, "th") == 0);
    }

    html_view_style_inherit_from_parent(out, parent, !is_table_cell);

    if (sheet && node && node->type == HTML_NODE_ELEMENT)
    {
        const html_view_rule_index_t *index = html_view_rule_index_get(priv, sheet);
        if (index)
        {
            html_view_apply_indexed_rules(out, node, HTML_VIEW_PSEUDO_NONE, index);
        }
        else
        {
            for (css_rule_t *rule = sheet->rules; rule; rule = rule->next)
            {
                if (rule->selector && html_view_selector_matches_cached(rule, node, HTML_VIEW_PSEUDO_NONE))
                {
                    css_style_merge(out, &rule->style);
                }
            }
        }
    }

    html_view_apply_presentational_attrs(out, parent, node);

    const char *inline_style = html_attr_get(node, "style");
    if (inline_style && inline_style[0] != '\0')
    {
        const css_style_t *cached = html_view_inline_style_cached(priv, node, inline_style);
        if (cached)
        {
            css_style_merge(out, cached);
        }
        else
        {
            html_view_apply_inline_style(out, inline_style);
        }
    }

    html_view_resolve_float_inherit(out, parent);

    if (is_table_cell && !out->has_text_align)
    {
        out->has_text_align = true;
        out->text_align = is_table_header ? CSS_TEXT_ALIGN_CENTER : CSS_TEXT_ALIGN_LEFT;
    }
}

bool html_view_style_for_pseudo(css_style_t *out,
                                const css_stylesheet_t *sheet,
                                const css_style_t *parent,
                                const html_node_t *node,
                                atk_html_view_priv_t *priv,
                                html_view_pseudo_t pseudo)
{
    if (!out)
    {
        return false;
    }
    memset(out, 0, sizeof(*out));
    if (priv)
    {
        html_view_dom_bloom_rebuild_if_needed(priv);
    }

    html_view_style_inherit_from_parent(out, parent, true);

    if (sheet && node && node->type == HTML_NODE_ELEMENT)
    {
        const html_view_rule_index_t *index = html_view_rule_index_get(priv, sheet);
        if (index)
        {
            html_view_apply_indexed_rules(out, node, pseudo, index);
        }
        else
        {
            for (css_rule_t *rule = sheet->rules; rule; rule = rule->next)
            {
                if (rule->selector && html_view_selector_matches_cached(rule, node, pseudo))
                {
                    css_style_merge(out, &rule->style);
                }
            }
        }
    }

    html_view_resolve_float_inherit(out, parent);

    return out->has_content;
}

void html_view_style_stack_destroy(html_view_ctx_t *ctx)
{
    if (!ctx)
    {
        return;
    }

    html_view_style_block_t *blk = ctx->style_block;
    while (blk)
    {
        for (size_t i = 0; i < blk->used; ++i)
        {
            css_style_release(&blk->styles[i]);
        }
        html_view_style_block_t *prev = blk->prev;
        free(blk);
        blk = prev;
    }
    ctx->style_block = NULL;
    ctx->style_depth = 0;
}

const css_style_t *html_view_style_push(html_view_ctx_t *ctx, const css_style_t *parent, const html_node_t *node)
{
    if (!ctx)
    {
        return NULL;
    }

    if (!ctx->style_block || ctx->style_block->used >= (sizeof(ctx->style_block->styles) / sizeof(ctx->style_block->styles[0])))
    {
        html_view_style_block_t *blk = (html_view_style_block_t *)calloc(1, sizeof(*blk));
        if (!blk)
        {
            return NULL;
        }
        blk->prev = ctx->style_block;
        ctx->style_block = blk;
    }

    css_style_t *slot = &ctx->style_block->styles[ctx->style_block->used++];
    ctx->style_depth++;
    html_view_style_for_node(slot, ctx->sheet, parent, node, ctx->priv);
    return slot;
}

void html_view_style_pop(html_view_ctx_t *ctx)
{
    if (!ctx || ctx->style_depth == 0)
    {
        return;
    }

    ctx->style_depth--;

    html_view_style_block_t *blk = ctx->style_block;
    if (!blk)
    {
        return;
    }
    if (blk->used > 0)
    {
        css_style_release(&blk->styles[blk->used - 1]);
        blk->used--;
    }
    if (blk->used == 0 && blk->prev)
    {
        ctx->style_block = blk->prev;
        free(blk);
    }
}

int html_view_length_to_px(const css_length_t *len,
                           int viewport_w,
                           int viewport_h,
                           int ref_w,
                           int ref_h,
                           int font_px,
                           bool horizontal)
{
    if (!len || !len->valid || len->is_auto)
    {
        return 0;
    }
    int32_t v = len->value_milli;
    if (v <= 0)
    {
        return 0;
    }

    switch (len->unit)
    {
        case CSS_UNIT_VW:
            return (int)(((int64_t)viewport_w * (int64_t)v + 50000LL) / 100000LL);
        case CSS_UNIT_VH:
            return (int)(((int64_t)viewport_h * (int64_t)v + 50000LL) / 100000LL);
        case CSS_UNIT_PERCENT:
        {
            int ref = horizontal ? ref_w : ref_h;
            return (int)(((int64_t)ref * (int64_t)v + 50000LL) / 100000LL);
        }
        case CSS_UNIT_EM:
            return (int)(((int64_t)font_px * (int64_t)v + 500LL) / 1000LL);
        case CSS_UNIT_PX:
        case CSS_UNIT_NONE:
        default:
            return (int)((v + 500) / 1000);
    }
}

int html_view_length_to_px_signed(const css_length_t *len,
                                  int viewport_w,
                                  int viewport_h,
                                  int ref_w,
                                  int ref_h,
                                  int font_px,
                                  bool horizontal)
{
    if (!len || !len->valid || len->is_auto)
    {
        return 0;
    }

    int32_t v = len->value_milli;
    if (v == 0)
    {
        return 0;
    }

    int sign = 1;
    if (v < 0)
    {
        sign = -1;
        v = -v;
    }

    int px = 0;
    switch (len->unit)
    {
        case CSS_UNIT_VW:
            px = (int)(((int64_t)viewport_w * (int64_t)v + 50000LL) / 100000LL);
            break;
        case CSS_UNIT_VH:
            px = (int)(((int64_t)viewport_h * (int64_t)v + 50000LL) / 100000LL);
            break;
        case CSS_UNIT_PERCENT:
        {
            int ref = horizontal ? ref_w : ref_h;
            px = (int)(((int64_t)ref * (int64_t)v + 50000LL) / 100000LL);
            break;
        }
        case CSS_UNIT_EM:
            px = (int)(((int64_t)font_px * (int64_t)v + 500LL) / 1000LL);
            break;
        case CSS_UNIT_PX:
        case CSS_UNIT_NONE:
        default:
            px = (int)((v + 500) / 1000);
            break;
    }

    return sign * px;
}

bool html_view_length_to_px_height(const html_view_ctx_t *ctx,
                                   const css_length_t *len,
                                   int *out_px)
{
    if (out_px)
    {
        *out_px = 0;
    }
    if (!ctx || !len || !len->valid || len->is_auto)
    {
        return false;
    }
    if (len->unit == CSS_UNIT_PERCENT &&
        (!ctx->height_basis_valid || !ctx->height_basis_explicit))
    {
        return false;
    }

    int ref_h = ctx->height_basis_valid ? ctx->height_basis : ctx->viewport_h;
    int px = html_view_length_to_px(len,
                                    ctx->viewport_w,
                                    ctx->viewport_h,
                                    ctx->body_w,
                                    ref_h,
                                    ctx->base_font_px,
                                    false);
    if (out_px)
    {
        *out_px = px;
    }
    return true;
}

int html_view_line_height_for_style(const html_view_ctx_t *ctx, const css_style_t *style)
{
    if (!ctx)
    {
        return atk_font_line_height() + 4;
    }

    int metrics_total = 0;
    if (ctx->priv && ctx->actual_font_px > 0)
    {
        html_view_font_size_cache_t *cache = html_view_font_state_get_cache(&ctx->priv->font, ctx->actual_font_px);
        if (cache)
        {
            int descent = cache->metrics.descent;
            if (descent < 0)
            {
                descent = -descent;
            }
            metrics_total = cache->metrics.ascent + descent;
            if (cache->metrics.line_gap > 0)
            {
                metrics_total += cache->metrics.line_gap;
            }
        }
    }

    int actual_font_px = ctx->actual_font_px > 0 ? ctx->actual_font_px : atk_font_line_height();
    int base_font_px = ctx->base_font_px > 0 ? ctx->base_font_px : actual_font_px;
    int line_height = ctx->base_line_height > 0 ? ctx->base_line_height : (base_font_px + 4);
    bool explicit_line_height = false;

    if (style && style->has_line_height)
    {
        if (style->line_height_is_length)
        {
            int px = html_view_length_to_px(&style->line_height,
                                            ctx->viewport_w,
                                            ctx->viewport_h,
                                            ctx->viewport_w,
                                            ctx->viewport_h,
                                            base_font_px,
                                            false);
            if (px > 0)
            {
                line_height = px;
                explicit_line_height = true;
            }
        }
        else if (style->line_height_milli > 0)
        {
            line_height = (int)(((int64_t)base_font_px * (int64_t)style->line_height_milli + 500LL) / 1000LL);
            explicit_line_height = true;
        }
    }

    if (!explicit_line_height)
    {
        if (line_height < actual_font_px)
        {
            line_height = actual_font_px;
        }
        if (metrics_total > line_height)
        {
            line_height = metrics_total;
        }
        if (line_height < 8)
        {
            line_height = 8;
        }
    }
    else if (line_height < 1)
    {
        line_height = 1;
    }
    return line_height;
}

int html_view_font_px_for_style(const html_view_ctx_t *ctx, const css_style_t *style, int parent_font_px)
{
    int clamped_parent = parent_font_px;
    if (clamped_parent > HTML_VIEW_FONT_MAX_PX)
    {
        clamped_parent = HTML_VIEW_FONT_MAX_PX;
    }
    if (!ctx || !style || !style->has_font_size || !style->font_size.valid || style->font_size.is_auto)
    {
        return clamped_parent;
    }

    if (style->font_size.unit == CSS_UNIT_PERCENT)
    {
        int64_t scaled = (int64_t)clamped_parent * (int64_t)style->font_size.value_milli;
        int px = (int)((scaled + 50000LL) / 100000LL);
        if (px > HTML_VIEW_FONT_MAX_PX)
        {
            px = HTML_VIEW_FONT_MAX_PX;
        }
        return px > 0 ? px : clamped_parent;
    }

    int px = html_view_length_to_px(&style->font_size,
                                    ctx->viewport_w,
                                    ctx->viewport_h,
                                    ctx->viewport_w,
                                    ctx->viewport_h,
                                    clamped_parent,
                                    true);
    if (px > HTML_VIEW_FONT_MAX_PX)
    {
        px = HTML_VIEW_FONT_MAX_PX;
    }
    return px > 0 ? px : clamped_parent;
}

void html_view_font_scope_push(html_view_ctx_t *ctx, const css_style_t *style, bool block, html_view_font_scope_t *saved)
{
    if (!ctx || !saved)
    {
        return;
    }

    saved->actual_font_px = ctx->actual_font_px;
    saved->base_font_px = ctx->base_font_px;
    saved->line_height = ctx->line_height;
    saved->space_w = ctx->space_w;

    int parent_font_px = ctx->base_font_px > 0 ? ctx->base_font_px : ctx->actual_font_px;
    if (parent_font_px <= 0)
    {
        parent_font_px = atk_font_line_height();
    }

    int font_px = html_view_font_px_for_style(ctx, style, parent_font_px);
    if (font_px <= 0)
    {
        font_px = parent_font_px;
    }

    if (style && style->has_font_size && font_px > 0)
    {
        css_style_t *mutable_style = (css_style_t *)style;
        mutable_style->font_size.valid = true;
        mutable_style->font_size.is_auto = false;
        mutable_style->font_size.unit = CSS_UNIT_PX;
        mutable_style->font_size.value_milli = font_px * 1000;
    }

    ctx->base_font_px = font_px;
    ctx->actual_font_px = font_px;
    ctx->space_w = html_view_text_width(ctx, " ");

    int candidate_line_height = html_view_line_height_for_style(ctx, style);
    if (!block)
    {
        ctx->line_height = candidate_line_height;
        return;
    }
    if (block)
    {
        ctx->line_height = candidate_line_height;
    }
    else if (candidate_line_height > ctx->line_height)
    {
        ctx->line_height = candidate_line_height;
    }
    else if (candidate_line_height < ctx->line_height)
    {
        bool line_empty = (ctx->x == ctx->line_start_x) && !ctx->pending_space;
        if (line_empty)
        {
            ctx->line_height = candidate_line_height;
        }
    }
}

void html_view_font_scope_pop(html_view_ctx_t *ctx, const html_view_font_scope_t *saved)
{
    if (!ctx || !saved)
    {
        return;
    }

    ctx->actual_font_px = saved->actual_font_px;
    ctx->base_font_px = saved->base_font_px;
    ctx->line_height = saved->line_height;
    ctx->space_w = saved->space_w;
}
