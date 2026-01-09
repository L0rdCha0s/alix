#include "atk/html_view/html_view_internal.h"

#include "ctype.h"
#include "string.h"
#include "web/css/css_internal.h"

#ifdef HTML_VIEW_HOST_TRACE
typedef struct
{
    bool enabled;
    uint32_t rule_stride;
    uint32_t node_stride;
    uint64_t rule_checks;
    uint64_t node_visits;
    uint64_t measure_counts[HTML_VIEW_TRACE_MEASURE_KIND_COUNT];
} html_view_trace_state_t;

static html_view_trace_state_t g_html_view_trace_state = {0};

void html_view_trace_configure(bool enabled, uint32_t rule_stride, uint32_t node_stride)
{
    g_html_view_trace_state.enabled = enabled;
    g_html_view_trace_state.rule_stride = rule_stride ? rule_stride : 200000u;
    g_html_view_trace_state.node_stride = node_stride ? node_stride : 5000u;
    g_html_view_trace_state.rule_checks = 0;
    g_html_view_trace_state.node_visits = 0;
    memset(g_html_view_trace_state.measure_counts, 0, sizeof(g_html_view_trace_state.measure_counts));
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

void html_view_trace_note_measure(html_view_trace_measure_kind_t kind)
{
    if (!g_html_view_trace_state.enabled)
    {
        return;
    }
    if ((unsigned int)kind >= (unsigned int)HTML_VIEW_TRACE_MEASURE_KIND_COUNT)
    {
        return;
    }
    g_html_view_trace_state.measure_counts[kind]++;
}

void html_view_trace_reset_measure(void)
{
    if (!g_html_view_trace_state.enabled)
    {
        return;
    }
    memset(g_html_view_trace_state.measure_counts, 0, sizeof(g_html_view_trace_state.measure_counts));
}

void html_view_trace_dump_measure(const char *label)
{
    if (!g_html_view_trace_state.enabled)
    {
        return;
    }
    printf("html_view_trace: measure label=%s inline=%llu inline_block=%llu block=%llu table=%llu flex=%llu grid=%llu\n",
           label ? label : "(null)",
           (unsigned long long)g_html_view_trace_state.measure_counts[HTML_VIEW_TRACE_MEASURE_INLINE],
           (unsigned long long)g_html_view_trace_state.measure_counts[HTML_VIEW_TRACE_MEASURE_INLINE_BLOCK],
           (unsigned long long)g_html_view_trace_state.measure_counts[HTML_VIEW_TRACE_MEASURE_BLOCK],
           (unsigned long long)g_html_view_trace_state.measure_counts[HTML_VIEW_TRACE_MEASURE_TABLE],
           (unsigned long long)g_html_view_trace_state.measure_counts[HTML_VIEW_TRACE_MEASURE_FLEX],
           (unsigned long long)g_html_view_trace_state.measure_counts[HTML_VIEW_TRACE_MEASURE_GRID]);
}
#endif

enum
{
    HTML_VIEW_PSEUDO_MASK_NONE = 1u << 0,
    HTML_VIEW_PSEUDO_MASK_BEFORE = 1u << 1,
    HTML_VIEW_PSEUDO_MASK_AFTER = 1u << 2,
};

enum
{
    HTML_VIEW_RULE_TRIE_MIN_RULES = 8,
    HTML_VIEW_RULE_TRIE_CACHE_MIN_RULES = 32,
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
    if (parent->has_list_style_type)
    {
        out->has_list_style_type = true;
        out->list_style_type = parent->list_style_type;
    }
    if (parent->custom_env)
    {
        out->custom_env = css_var_env_ref(parent->custom_env);
        out->custom_env_local = false;
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

static void html_view_resolve_box_sizing_inherit(css_style_t *style, const css_style_t *parent)
{
    if (!style || !style->has_box_sizing || !style->box_sizing_inherit)
    {
        return;
    }

    if (parent && parent->has_box_sizing)
    {
        style->box_sizing = parent->box_sizing;
    }
    else
    {
        style->has_box_sizing = false;
    }
    style->box_sizing_inherit = false;
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
static const char *html_view_selector_token_end(const char *p, const char *end);

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

static void html_view_bloom_copy(web_bloom_t *dst, const web_bloom_t *src)
{
    if (!dst || !src)
    {
        return;
    }
    memcpy(dst->bits, src->bits, sizeof(dst->bits));
}

static void html_view_bloom_or(web_bloom_t *dst, const web_bloom_t *src)
{
    if (!dst || !src)
    {
        return;
    }
    for (size_t i = 0; i < WEB_BLOOM_WORDS; ++i)
    {
        dst->bits[i] |= src->bits[i];
    }
}

static void html_view_bloom_and(web_bloom_t *dst, const web_bloom_t *src)
{
    if (!dst || !src)
    {
        return;
    }
    for (size_t i = 0; i < WEB_BLOOM_WORDS; ++i)
    {
        dst->bits[i] &= src->bits[i];
    }
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
    html_view_style_cache_mark_dirty(priv);
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

static bool html_view_selector_range_eq_ci_ranges(const char *a_start,
                                                  size_t a_len,
                                                  const char *b_start,
                                                  size_t b_len)
{
    if (!a_start || !b_start)
    {
        return false;
    }
    const char *a_end = a_start + a_len;
    const char *b_end = b_start + b_len;
    const char *a = a_start;
    const char *b = b_start;
    while (a < a_end && b < b_end)
    {
        char ca = *a;
        char cb = *b;
        if (ca == '\\' && (a + 1) < a_end)
        {
            ++a;
            ca = *a;
        }
        if (cb == '\\' && (b + 1) < b_end)
        {
            ++b;
            cb = *b;
        }
        if (tolower((unsigned char)ca) != tolower((unsigned char)cb))
        {
            return false;
        }
        ++a;
        ++b;
    }
    return a == a_end && b == b_end;
}

static size_t html_view_selector_range_unescaped_len(const char *sel_start, size_t sel_len)
{
    if (!sel_start || sel_len == 0)
    {
        return 0;
    }
    const char *p = sel_start;
    const char *end = sel_start + sel_len;
    size_t len = 0;
    while (p < end)
    {
        if (*p == '\\' && (p + 1) < end)
        {
            ++p;
        }
        ++len;
        ++p;
    }
    return len;
}

static bool html_view_selector_range_startswith_ci_value(const char *value,
                                                         const char *sel_start,
                                                         size_t sel_len)
{
    if (!value || !sel_start || sel_len == 0)
    {
        return false;
    }
    size_t value_len = strlen(value);
    const char *p = sel_start;
    const char *end = sel_start + sel_len;
    size_t vi = 0;
    while (p < end)
    {
        char sc = *p;
        if (sc == '\\' && (p + 1) < end)
        {
            ++p;
            sc = *p;
        }
        if (vi >= value_len)
        {
            return false;
        }
        if (tolower((unsigned char)sc) != tolower((unsigned char)value[vi]))
        {
            return false;
        }
        ++vi;
        ++p;
    }
    return true;
}

static bool html_view_selector_range_endswith_ci_value(const char *value,
                                                       const char *sel_start,
                                                       size_t sel_len)
{
    if (!value || !sel_start || sel_len == 0)
    {
        return false;
    }
    size_t value_len = strlen(value);
    size_t pat_len = html_view_selector_range_unescaped_len(sel_start, sel_len);
    if (pat_len == 0 || value_len < pat_len)
    {
        return false;
    }
    return html_view_selector_range_eq_ci_token(value + (value_len - pat_len),
                                                pat_len,
                                                sel_start,
                                                sel_len);
}

static bool html_view_selector_range_contains_ci_value(const char *value,
                                                       const char *sel_start,
                                                       size_t sel_len)
{
    if (!value || !sel_start || sel_len == 0)
    {
        return false;
    }
    size_t value_len = strlen(value);
    size_t pat_len = html_view_selector_range_unescaped_len(sel_start, sel_len);
    if (pat_len == 0 || value_len < pat_len)
    {
        return false;
    }
    for (size_t i = 0; i + pat_len <= value_len; ++i)
    {
        if (html_view_selector_range_eq_ci_token(value + i, pat_len, sel_start, sel_len))
        {
            return true;
        }
    }
    return false;
}

static bool html_view_selector_range_dashmatch_ci_value(const char *value,
                                                        const char *sel_start,
                                                        size_t sel_len)
{
    if (!value || !sel_start || sel_len == 0)
    {
        return false;
    }
    size_t value_len = strlen(value);
    size_t pat_len = html_view_selector_range_unescaped_len(sel_start, sel_len);
    if (pat_len == 0 || value_len < pat_len)
    {
        return false;
    }
    if (!html_view_selector_range_eq_ci_token(value, pat_len, sel_start, sel_len))
    {
        return false;
    }
    if (value_len == pat_len)
    {
        return true;
    }
    return value[pat_len] == '-';
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

static const char *html_view_selector_skip_parens(const char *p, const char *end)
{
    if (!p || !end || p >= end || *p != '(')
    {
        return p;
    }
    int depth = 0;
    char quote = 0;
    bool escape = false;
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
        if (c == '(')
        {
            ++depth;
            ++p;
            continue;
        }
        if (c == ')')
        {
            --depth;
            ++p;
            if (depth <= 0)
            {
                return p;
            }
            continue;
        }
        ++p;
    }
    return end;
}

static bool html_view_pseudo_class_is_dynamic(const char *name, size_t len)
{
    if (!name || len == 0)
    {
        return false;
    }
    return (len == 7 && strncasecmp(name, "visited", 7) == 0) ||
           (len == 5 && strncasecmp(name, "hover", 5) == 0) ||
           (len == 6 && strncasecmp(name, "active", 6) == 0) ||
           (len == 5 && strncasecmp(name, "focus", 5) == 0) ||
           (len == 12 && strncasecmp(name, "focus-within", 12) == 0) ||
           (len == 13 && strncasecmp(name, "focus-visible", 13) == 0) ||
           (len == 6 && strncasecmp(name, "target", 6) == 0) ||
           (len == 8 && strncasecmp(name, "disabled", 8) == 0) ||
           (len == 7 && strncasecmp(name, "enabled", 7) == 0) ||
           (len == 7 && strncasecmp(name, "checked", 7) == 0) ||
           (len == 8 && strncasecmp(name, "selected", 8) == 0);
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
        s += 2;
    }
    else if (s + 1 < sel_end && s[0] == '$' && s[1] == '=')
    {
        op = '$';
        s += 2;
    }
    else if (s + 1 < sel_end && s[0] == '*' && s[1] == '=')
    {
        op = '*';
        s += 2;
    }
    else if (s + 1 < sel_end && s[0] == '|' && s[1] == '=')
    {
        op = '|';
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
    else if (s + 1 < sel_end && s[0] == '^' && s[1] == '=')
    {
        op = '^';
        s += 2;
    }
    else if (s + 1 < sel_end && s[0] == '$' && s[1] == '=')
    {
        op = '$';
        s += 2;
    }
    else if (s + 1 < sel_end && s[0] == '*' && s[1] == '=')
    {
        op = '*';
        s += 2;
    }
    else if (s + 1 < sel_end && s[0] == '|' && s[1] == '=')
    {
        op = '|';
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
    else if (op == '^')
    {
        match = html_view_selector_range_startswith_ci_value(attr_value, value, strlen(value));
    }
    else if (op == '$')
    {
        match = html_view_selector_range_endswith_ci_value(attr_value, value, strlen(value));
    }
    else if (op == '*')
    {
        match = html_view_selector_range_contains_ci_value(attr_value, value, strlen(value));
    }
    else if (op == '|')
    {
        match = html_view_selector_range_dashmatch_ci_value(attr_value, value, strlen(value));
    }

    free(name);
    free(value);
    *p = s;
    return match;
}

typedef enum
{
    HTML_VIEW_SELECTOR_MATCH_NO = 0,
    HTML_VIEW_SELECTOR_MATCH_YES,
    HTML_VIEW_SELECTOR_MATCH_UNSUPPORTED
} html_view_selector_match_t;

static size_t html_view_node_element_index(const html_node_t *node, size_t *out_total)
{
    if (out_total)
    {
        *out_total = 0;
    }
    if (!node || !node->parent)
    {
        return 0;
    }
    size_t total = 0;
    size_t index = 0;
    for (const html_node_t *child = node->parent->first_child; child; child = child->next_sibling)
    {
        if (child->type != HTML_NODE_ELEMENT)
        {
            continue;
        }
        ++total;
        if (child == node)
        {
            index = total;
        }
    }
    if (out_total)
    {
        *out_total = total;
    }
    return index;
}

static size_t html_view_node_element_type_index(const html_node_t *node, size_t *out_total)
{
    if (out_total)
    {
        *out_total = 0;
    }
    if (!node || !node->parent || !node->name)
    {
        return 0;
    }
    size_t total = 0;
    size_t index = 0;
    for (const html_node_t *child = node->parent->first_child; child; child = child->next_sibling)
    {
        if (child->type != HTML_NODE_ELEMENT || !child->name)
        {
            continue;
        }
        if (strcasecmp(child->name, node->name) != 0)
        {
            continue;
        }
        ++total;
        if (child == node)
        {
            index = total;
        }
    }
    if (out_total)
    {
        *out_total = total;
    }
    return index;
}

static bool html_view_nth_matches(int32_t a, int32_t b, size_t index)
{
    if (index == 0)
    {
        return false;
    }
    int32_t idx = (int32_t)index;
    if (a == 0)
    {
        return idx == b;
    }
    int32_t diff = idx - b;
    if ((a > 0 && diff < 0) || (a < 0 && diff > 0))
    {
        return false;
    }
    return (diff % a) == 0;
}

static bool html_view_parse_nth_expression(const char *start,
                                           const char *end,
                                           int32_t *out_a,
                                           int32_t *out_b)
{
    if (!out_a || !out_b)
    {
        return false;
    }
    *out_a = 0;
    *out_b = 0;
    if (!start || !end || end <= start)
    {
        return false;
    }
    html_view_trim_range(&start, &end);
    if (end <= start)
    {
        return false;
    }

    size_t len = (size_t)(end - start);
    if (len == 3 && strncasecmp(start, "odd", 3) == 0)
    {
        *out_a = 2;
        *out_b = 1;
        return true;
    }
    if (len == 4 && strncasecmp(start, "even", 4) == 0)
    {
        *out_a = 2;
        *out_b = 0;
        return true;
    }

    const char *p = start;
    int sign = 1;
    if (*p == '+' || *p == '-')
    {
        sign = (*p == '-') ? -1 : 1;
        ++p;
    }
    while (p < end && isspace((unsigned char)*p))
    {
        ++p;
    }

    int32_t value = 0;
    bool have_digits = false;
    while (p < end && isdigit((unsigned char)*p))
    {
        have_digits = true;
        value = (int32_t)(value * 10 + (*p - '0'));
        ++p;
    }

    if (p < end && (*p == 'n' || *p == 'N'))
    {
        int32_t a = have_digits ? value : 1;
        a *= sign;
        ++p;
        while (p < end && isspace((unsigned char)*p))
        {
            ++p;
        }
        if (p >= end)
        {
            *out_a = a;
            *out_b = 0;
            return true;
        }
        int bsign = 1;
        if (*p == '+' || *p == '-')
        {
            bsign = (*p == '-') ? -1 : 1;
            ++p;
        }
        while (p < end && isspace((unsigned char)*p))
        {
            ++p;
        }
        int32_t bval = 0;
        bool have_b = false;
        while (p < end && isdigit((unsigned char)*p))
        {
            have_b = true;
            bval = (int32_t)(bval * 10 + (*p - '0'));
            ++p;
        }
        while (p < end && isspace((unsigned char)*p))
        {
            ++p;
        }
        if (!have_b || p != end)
        {
            return false;
        }
        *out_a = a;
        *out_b = bsign * bval;
        return true;
    }

    if (!have_digits)
    {
        return false;
    }
    while (p < end && isspace((unsigned char)*p))
    {
        ++p;
    }
    if (p != end)
    {
        return false;
    }
    *out_a = 0;
    *out_b = sign * value;
    return true;
}

static bool html_view_selector_range_has_combinator(const char *start, const char *end)
{
    if (!start || !end || end <= start)
    {
        return false;
    }
    bool escape = false;
    char quote = 0;
    int bracket_depth = 0;
    int paren_depth = 0;
    bool seen_token = false;
    for (const char *p = start; p < end; ++p)
    {
        char c = *p;
        if (escape)
        {
            escape = false;
            continue;
        }
        if (c == '\\')
        {
            escape = true;
            continue;
        }
        if (quote)
        {
            if (c == quote)
            {
                quote = 0;
            }
            continue;
        }
        if (c == '"' || c == '\'')
        {
            quote = c;
            continue;
        }
        if (c == '[')
        {
            ++bracket_depth;
            continue;
        }
        if (c == ']' && bracket_depth > 0)
        {
            --bracket_depth;
            continue;
        }
        if (bracket_depth > 0)
        {
            continue;
        }
        if (c == '(')
        {
            ++paren_depth;
            continue;
        }
        if (c == ')' && paren_depth > 0)
        {
            --paren_depth;
            continue;
        }
        if (paren_depth > 0)
        {
            continue;
        }
        if (c == '>' || c == '+' || c == '~')
        {
            return true;
        }
        if (isspace((unsigned char)c))
        {
            if (!seen_token)
            {
                continue;
            }
            const char *q = p + 1;
            while (q < end && isspace((unsigned char)*q))
            {
                ++q;
            }
            if (q < end && *q != ',' && *q != ')')
            {
                return true;
            }
            p = q - 1;
            continue;
        }
        seen_token = true;
    }
    return false;
}

typedef struct
{
    uint16_t a;
    uint16_t b;
    uint16_t c;
} html_view_specificity_t;

static html_view_specificity_t html_view_specificity_add(html_view_specificity_t left,
                                                         html_view_specificity_t right)
{
    html_view_specificity_t out = left;
    out.a = (uint16_t)((uint32_t)out.a + (uint32_t)right.a);
    out.b = (uint16_t)((uint32_t)out.b + (uint32_t)right.b);
    out.c = (uint16_t)((uint32_t)out.c + (uint32_t)right.c);
    return out;
}

static int html_view_specificity_cmp(html_view_specificity_t left,
                                     html_view_specificity_t right)
{
    if (left.a != right.a)
    {
        return left.a < right.a ? -1 : 1;
    }
    if (left.b != right.b)
    {
        return left.b < right.b ? -1 : 1;
    }
    if (left.c != right.c)
    {
        return left.c < right.c ? -1 : 1;
    }
    return 0;
}

static html_view_specificity_t html_view_specificity_max(html_view_specificity_t left,
                                                         html_view_specificity_t right)
{
    return html_view_specificity_cmp(left, right) >= 0 ? left : right;
}

static uint32_t html_view_specificity_to_value(html_view_specificity_t spec)
{
    uint32_t a = spec.a > 999 ? 999u : spec.a;
    uint32_t b = spec.b > 999 ? 999u : spec.b;
    uint32_t c = spec.c > 999 ? 999u : spec.c;
    return a * 1000000u + b * 1000u + c;
}

static bool html_view_selector_is_pseudo_element(const char *name, size_t len, bool double_colon)
{
    if (double_colon)
    {
        return true;
    }
    if (len == 6 && strncasecmp(name, "before", 6) == 0)
    {
        return true;
    }
    if (len == 5 && strncasecmp(name, "after", 5) == 0)
    {
        return true;
    }
    if (len == 10 && strncasecmp(name, "first-line", 10) == 0)
    {
        return true;
    }
    if (len == 12 && strncasecmp(name, "first-letter", 12) == 0)
    {
        return true;
    }
    return false;
}

static html_view_specificity_t html_view_selector_specificity_range(const char *start,
                                                                     const char *end);

static html_view_specificity_t html_view_selector_specificity_list(const char *start,
                                                                    const char *end)
{
    html_view_specificity_t best = {0};
    if (!start || !end || end <= start)
    {
        return best;
    }
    const char *item_start = start;
    bool escape = false;
    char quote = 0;
    int bracket_depth = 0;
    int paren_depth = 0;

    for (const char *p = start; p <= end; ++p)
    {
        bool at_end = (p == end);
        char c = at_end ? ',' : *p;
        if (!at_end)
        {
            if (escape)
            {
                escape = false;
                continue;
            }
            if (c == '\\')
            {
                escape = true;
                continue;
            }
            if (quote)
            {
                if (c == quote)
                {
                    quote = 0;
                }
                continue;
            }
            if (c == '"' || c == '\'')
            {
                quote = c;
                continue;
            }
            if (c == '[')
            {
                ++bracket_depth;
                continue;
            }
            if (c == ']' && bracket_depth > 0)
            {
                --bracket_depth;
                continue;
            }
            if (bracket_depth > 0)
            {
                continue;
            }
            if (c == '(')
            {
                ++paren_depth;
                continue;
            }
            if (c == ')' && paren_depth > 0)
            {
                --paren_depth;
                continue;
            }
            if (paren_depth > 0)
            {
                continue;
            }
            if (c != ',')
            {
                continue;
            }
        }

        const char *item_end = p;
        html_view_trim_range(&item_start, &item_end);
        if (item_end > item_start)
        {
            html_view_specificity_t spec = html_view_selector_specificity_range(item_start, item_end);
            best = html_view_specificity_max(best, spec);
        }
        item_start = p + 1;
    }

    return best;
}

static const char *html_view_selector_skip_bracket(const char *p, const char *end)
{
    if (!p || !end || p >= end || *p != '[')
    {
        return p;
    }
    bool escape = false;
    char quote = 0;
    ++p;
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
        if (c == ']')
        {
            return p + 1;
        }
        ++p;
    }
    return end;
}

static html_view_specificity_t html_view_selector_specificity_simple(const char *start,
                                                                      const char *end)
{
    html_view_specificity_t spec = {0};
    if (!start || !end || end <= start)
    {
        return spec;
    }
    html_view_trim_range(&start, &end);
    if (end <= start)
    {
        return spec;
    }

    const char *p = start;
    if (*p == '*')
    {
        ++p;
    }
    else if (*p != '#' && *p != '.' && *p != '[' && *p != ':')
    {
        const char *tag_end = p;
        while (tag_end < end &&
               *tag_end != ':' && *tag_end != '.' && *tag_end != '#' &&
               *tag_end != '[' && !isspace((unsigned char)*tag_end))
        {
            ++tag_end;
        }
        if (tag_end > p)
        {
            spec.c += 1;
        }
        p = tag_end;
    }

    while (p < end)
    {
        char c = *p;
        if (c == '.')
        {
            ++p;
            const char *cls_end = p;
            bool escape = false;
            while (cls_end < end)
            {
                char cc = *cls_end;
                if (escape)
                {
                    escape = false;
                    ++cls_end;
                    continue;
                }
                if (cc == '\\')
                {
                    escape = true;
                    ++cls_end;
                    continue;
                }
                if (cc == ':' || cc == '.' || cc == '#' || cc == '[' || cc == ']' ||
                    cc == '(' || cc == ')' || isspace((unsigned char)cc))
                {
                    break;
                }
                ++cls_end;
            }
            if (cls_end > p)
            {
                spec.b += 1;
            }
            p = cls_end;
            continue;
        }
        if (c == '#')
        {
            ++p;
            const char *id_end = p;
            bool escape = false;
            while (id_end < end)
            {
                char cc = *id_end;
                if (escape)
                {
                    escape = false;
                    ++id_end;
                    continue;
                }
                if (cc == '\\')
                {
                    escape = true;
                    ++id_end;
                    continue;
                }
                if (cc == ':' || cc == '.' || cc == '#' || cc == '[' || cc == ']' ||
                    cc == '(' || cc == ')' || isspace((unsigned char)cc))
                {
                    break;
                }
                ++id_end;
            }
            if (id_end > p)
            {
                spec.a += 1;
            }
            p = id_end;
            continue;
        }
        if (c == '[')
        {
            spec.b += 1;
            p = html_view_selector_skip_bracket(p, end);
            continue;
        }
        if (c == ':')
        {
            bool double_colon = false;
            const char *name = p + 1;
            if (name < end && *name == ':')
            {
                double_colon = true;
                ++name;
            }
            const char *name_end = name;
            while (name_end < end &&
                   (isalnum((unsigned char)*name_end) || *name_end == '-' || *name_end == '_'))
            {
                ++name_end;
            }
            if (name_end == name)
            {
                break;
            }
            size_t name_len = (size_t)(name_end - name);
            if (name_end < end && *name_end == '(')
            {
                const char *next = html_view_selector_skip_parens(name_end, end);
                if (!next || next <= name_end)
                {
                    break;
                }
                const char *args_start = name_end + 1;
                const char *args_end = next - 1;
                html_view_trim_range(&args_start, &args_end);
                if ((name_len == 3 && strncasecmp(name, "not", 3) == 0) ||
                    (name_len == 2 && strncasecmp(name, "is", 2) == 0) ||
                    (name_len == 3 && strncasecmp(name, "has", 3) == 0))
                {
                    html_view_specificity_t inner = html_view_selector_specificity_list(args_start, args_end);
                    spec = html_view_specificity_add(spec, inner);
                }
                else if (name_len == 5 && strncasecmp(name, "where", 5) == 0)
                {
                    /* zero specificity */
                }
                else
                {
                    spec.b += 1;
                }
                p = next;
                continue;
            }

            if (html_view_selector_is_pseudo_element(name, name_len, double_colon))
            {
                spec.c += 1;
            }
            else
            {
                spec.b += 1;
            }
            p = name_end;
            continue;
        }
        if (c == '>' || c == '+' || c == '~' || isspace((unsigned char)c))
        {
            break;
        }
        ++p;
    }

    return spec;
}

static html_view_specificity_t html_view_selector_specificity_range(const char *start,
                                                                     const char *end)
{
    html_view_specificity_t total = {0};
    if (!start || !end || end <= start)
    {
        return total;
    }
    html_view_trim_range(&start, &end);
    if (end <= start)
    {
        return total;
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
        if (part_end > part_start)
        {
            html_view_specificity_t part_spec = html_view_selector_specificity_simple(part_start, part_end);
            total = html_view_specificity_add(total, part_spec);
        }

        while (p < end && isspace((unsigned char)*p))
        {
            ++p;
        }
        if (p < end && (*p == '>' || *p == '+' || *p == '~'))
        {
            ++p;
        }
    }

    return total;
}

static html_view_selector_match_t html_view_simple_selector_matches_range_ex(const char *sel_start,
                                                                             const char *sel_end,
                                                                             const html_node_t *node,
                                                                             html_view_pseudo_t pseudo);

static html_view_selector_match_t html_view_selector_list_matches(const char *sel_start,
                                                                  const char *sel_end,
                                                                  const html_node_t *node,
                                                                  html_view_pseudo_t pseudo,
                                                                  bool negate)
{
    if (!sel_start || !sel_end || sel_end <= sel_start)
    {
        return HTML_VIEW_SELECTOR_MATCH_UNSUPPORTED;
    }
    const char *item_start = sel_start;
    bool escape = false;
    char quote = 0;
    int bracket_depth = 0;
    int paren_depth = 0;
    bool any_match = false;
    bool any_supported = false;
    bool any_unsupported = false;

    for (const char *p = sel_start; p <= sel_end; ++p)
    {
        bool at_end = (p == sel_end);
        char c = at_end ? ',' : *p;
        if (!at_end)
        {
            if (escape)
            {
                escape = false;
                continue;
            }
            if (c == '\\')
            {
                escape = true;
                continue;
            }
            if (quote)
            {
                if (c == quote)
                {
                    quote = 0;
                }
                continue;
            }
            if (c == '"' || c == '\'')
            {
                quote = c;
                continue;
            }
            if (c == '[')
            {
                ++bracket_depth;
                continue;
            }
            if (c == ']' && bracket_depth > 0)
            {
                --bracket_depth;
                continue;
            }
            if (bracket_depth > 0)
            {
                continue;
            }
            if (c == '(')
            {
                ++paren_depth;
                continue;
            }
            if (c == ')' && paren_depth > 0)
            {
                --paren_depth;
                continue;
            }
            if (paren_depth > 0)
            {
                continue;
            }
            if (c != ',')
            {
                continue;
            }
        }

        const char *item_end = p;
        html_view_trim_range(&item_start, &item_end);
        if (item_end <= item_start)
        {
            any_unsupported = true;
        }
        else if (html_view_selector_range_has_combinator(item_start, item_end))
        {
            any_unsupported = true;
        }
        else
        {
            html_view_selector_match_t item_match = html_view_simple_selector_matches_range_ex(item_start,
                                                                                               item_end,
                                                                                               node,
                                                                                               pseudo);
            if (item_match == HTML_VIEW_SELECTOR_MATCH_UNSUPPORTED)
            {
                any_unsupported = true;
            }
            else
            {
                any_supported = true;
                if (item_match == HTML_VIEW_SELECTOR_MATCH_YES)
                {
                    any_match = true;
                }
            }
        }

        if (negate)
        {
            if (any_match)
            {
                return HTML_VIEW_SELECTOR_MATCH_NO;
            }
        }
        else
        {
            if (any_match)
            {
                return HTML_VIEW_SELECTOR_MATCH_YES;
            }
        }

        item_start = p + 1;
    }

    if (negate)
    {
        if (any_unsupported)
        {
            return HTML_VIEW_SELECTOR_MATCH_UNSUPPORTED;
        }
        return HTML_VIEW_SELECTOR_MATCH_YES;
    }
    if (any_supported)
    {
        return HTML_VIEW_SELECTOR_MATCH_NO;
    }
    return any_unsupported ? HTML_VIEW_SELECTOR_MATCH_UNSUPPORTED : HTML_VIEW_SELECTOR_MATCH_NO;
}

static html_view_selector_match_t html_view_simple_selector_matches_range_ex(const char *sel_start,
                                                                             const char *sel_end,
                                                                             const html_node_t *node,
                                                                             html_view_pseudo_t pseudo)
{
    if (!sel_start || !sel_end || sel_end <= sel_start || !node || node->type != HTML_NODE_ELEMENT || !node->name)
    {
        return HTML_VIEW_SELECTOR_MATCH_NO;
    }

    html_view_trim_range(&sel_start, &sel_end);
    if (sel_end <= sel_start)
    {
        return HTML_VIEW_SELECTOR_MATCH_NO;
    }

    const char *p = sel_start;
    bool match = true;
    bool require_link = false;
    bool require_root = false;
    bool pseudo_seen = false;
    bool unsupported = false;

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
        p = tag_end;
    }

    while (match && p < sel_end)
    {
        if (*p == '.')
        {
            ++p;
            const char *cls_end = html_view_selector_token_end(p, sel_end);
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
            const char *id_end = html_view_selector_token_end(p, sel_end);
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
            size_t name_len = (size_t)(name_end - name);
            if (name_end < sel_end && *name_end == '(')
            {
                const char *next = html_view_selector_skip_parens(name_end, sel_end);
                if (!next || next <= name_end)
                {
                    match = false;
                    break;
                }
                const char *args_start = name_end + 1;
                const char *args_end = next - 1;
                html_view_trim_range(&args_start, &args_end);
                if (name_len == 3 && strncasecmp(name, "not", 3) == 0)
                {
                    html_view_selector_match_t res = html_view_selector_list_matches(args_start,
                                                                                      args_end,
                                                                                      node,
                                                                                      pseudo,
                                                                                      true);
                    if (res == HTML_VIEW_SELECTOR_MATCH_UNSUPPORTED)
                    {
                        unsupported = true;
                        match = false;
                        break;
                    }
                    match = (res == HTML_VIEW_SELECTOR_MATCH_YES);
                }
                else if ((name_len == 2 && strncasecmp(name, "is", 2) == 0) ||
                         (name_len == 5 && strncasecmp(name, "where", 5) == 0))
                {
                    html_view_selector_match_t res = html_view_selector_list_matches(args_start,
                                                                                      args_end,
                                                                                      node,
                                                                                      pseudo,
                                                                                      false);
                    if (res == HTML_VIEW_SELECTOR_MATCH_UNSUPPORTED)
                    {
                        unsupported = true;
                        match = false;
                        break;
                    }
                    match = (res == HTML_VIEW_SELECTOR_MATCH_YES);
                }
                else if (name_len == 9 && strncasecmp(name, "nth-child", 9) == 0)
                {
                    int32_t a = 0;
                    int32_t b = 0;
                    if (!html_view_parse_nth_expression(args_start, args_end, &a, &b))
                    {
                        unsupported = true;
                        match = false;
                        break;
                    }
                    size_t total = 0;
                    size_t index = html_view_node_element_index(node, &total);
                    match = html_view_nth_matches(a, b, index);
                }
                else if (name_len == 14 && strncasecmp(name, "nth-last-child", 14) == 0)
                {
                    int32_t a = 0;
                    int32_t b = 0;
                    if (!html_view_parse_nth_expression(args_start, args_end, &a, &b))
                    {
                        unsupported = true;
                        match = false;
                        break;
                    }
                    size_t total = 0;
                    size_t index = html_view_node_element_index(node, &total);
                    size_t from_end = (total >= index && index > 0) ? (total - index + 1) : 0;
                    match = html_view_nth_matches(a, b, from_end);
                }
                else if (name_len == 11 && strncasecmp(name, "nth-of-type", 11) == 0)
                {
                    int32_t a = 0;
                    int32_t b = 0;
                    if (!html_view_parse_nth_expression(args_start, args_end, &a, &b))
                    {
                        unsupported = true;
                        match = false;
                        break;
                    }
                    size_t total = 0;
                    size_t index = html_view_node_element_type_index(node, &total);
                    match = html_view_nth_matches(a, b, index);
                }
                else if (name_len == 16 && strncasecmp(name, "nth-last-of-type", 16) == 0)
                {
                    int32_t a = 0;
                    int32_t b = 0;
                    if (!html_view_parse_nth_expression(args_start, args_end, &a, &b))
                    {
                        unsupported = true;
                        match = false;
                        break;
                    }
                    size_t total = 0;
                    size_t index = html_view_node_element_type_index(node, &total);
                    size_t from_end = (total >= index && index > 0) ? (total - index + 1) : 0;
                    match = html_view_nth_matches(a, b, from_end);
                }
                else if (name_len == 3 && strncasecmp(name, "has", 3) == 0)
                {
                    unsupported = true;
                    match = false;
                    break;
                }
                else
                {
                    unsupported = true;
                    match = false;
                    break;
                }
                p = next;
                continue;
            }

            if (html_view_pseudo_class_is_dynamic(name, name_len))
            {
                match = false;
                break;
            }
            if (name_len == 4 && strncasecmp(name, "link", 4) == 0)
            {
                require_link = true;
            }
            else if (name_len == 4 && strncasecmp(name, "root", 4) == 0)
            {
                require_root = true;
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
            else if (name_len == 11 && strncasecmp(name, "first-child", 11) == 0)
            {
                size_t total = 0;
                size_t index = html_view_node_element_index(node, &total);
                match = (index == 1);
            }
            else if (name_len == 10 && strncasecmp(name, "last-child", 10) == 0)
            {
                size_t total = 0;
                size_t index = html_view_node_element_index(node, &total);
                match = (index != 0 && index == total);
            }
            else if (name_len == 10 && strncasecmp(name, "only-child", 10) == 0)
            {
                size_t total = 0;
                size_t index = html_view_node_element_index(node, &total);
                match = (index == 1 && total == 1);
            }
            else if (name_len == 13 && strncasecmp(name, "first-of-type", 13) == 0)
            {
                size_t total = 0;
                size_t index = html_view_node_element_type_index(node, &total);
                match = (index == 1);
            }
            else if (name_len == 12 && strncasecmp(name, "last-of-type", 12) == 0)
            {
                size_t total = 0;
                size_t index = html_view_node_element_type_index(node, &total);
                match = (index != 0 && index == total);
            }
            else if (name_len == 12 && strncasecmp(name, "only-of-type", 12) == 0)
            {
                size_t total = 0;
                size_t index = html_view_node_element_type_index(node, &total);
                match = (index == 1 && total == 1);
            }
            else if (name_len == 5 && strncasecmp(name, "empty", 5) == 0)
            {
                bool has_child = false;
                for (const html_node_t *child = node->first_child; child; child = child->next_sibling)
                {
                    if (child->type == HTML_NODE_ELEMENT)
                    {
                        has_child = true;
                        break;
                    }
                    if (child->type == HTML_NODE_TEXT && child->text && child->text[0] != '\0')
                    {
                        has_child = true;
                        break;
                    }
                }
                match = !has_child;
            }
            else
            {
                unsupported = true;
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

    if (match && require_root)
    {
        const html_node_t *parent = node->parent;
        if (!parent || parent->type != HTML_NODE_DOCUMENT)
        {
            match = false;
        }
    }

    if (match && pseudo != HTML_VIEW_PSEUDO_NONE && !pseudo_seen)
    {
        match = false;
    }

    if (unsupported)
    {
        return HTML_VIEW_SELECTOR_MATCH_UNSUPPORTED;
    }
    return match ? HTML_VIEW_SELECTOR_MATCH_YES : HTML_VIEW_SELECTOR_MATCH_NO;
}

static bool html_view_simple_selector_matches_range_internal(const char *sel_start,
                                                             const char *sel_end,
                                                             const html_node_t *node,
                                                             html_view_pseudo_t pseudo)
{
    return html_view_simple_selector_matches_range_ex(sel_start, sel_end, node, pseudo) ==
           HTML_VIEW_SELECTOR_MATCH_YES;
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
            const char *scan = p;
            if (html_view_parse_attr_selector_meta(&scan,
                                                   part_end,
                                                   &name_start,
                                                   &name_end,
                                                   &op,
                                                   &value_start,
                                                   &value_end,
                                                   NULL))
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
                    const char *next = html_view_selector_skip_parens(name_end, part_end);
                    if (!next || next <= name_end)
                    {
                        cache->never_match = true;
                        return;
                    }
                    p = next;
                    continue;
                }
                size_t name_len = (size_t)(name_end - name);
                if (html_view_pseudo_class_is_dynamic(name, name_len))
                {
                    cache->never_match = true;
                    return;
                }
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
                else if (name_len == 4 && strncasecmp(name, "root", 4) == 0)
                {
                    /* supported pseudo-class */
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
            const char *scan = p;
            if (!html_view_parse_attr_selector_meta(&scan,
                                                    part_end,
                                                    &name_start,
                                                    &name_end,
                                                    &op,
                                                    &value_start,
                                                    &value_end,
                                                    NULL))
            {
                ++p;
                continue;
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

static void html_view_selector_cache_add_self_class(css_selector_cache_t *cache,
                                                    const char *selector,
                                                    const char *start,
                                                    const char *end)
{
    if (!cache || !selector || !start || !end || end <= start)
    {
        return;
    }
    uint32_t len = (uint32_t)(end - start);
    uint32_t offset = (uint32_t)(start - selector);
    for (uint8_t i = 0; i < cache->self_class_count; ++i)
    {
        uint32_t existing_len = cache->self_class_len[i];
        if (existing_len == len &&
            strncasecmp(selector + cache->self_class_start[i], start, len) == 0)
        {
            return;
        }
    }
    if (cache->self_class_count < 4)
    {
        cache->self_class_start[cache->self_class_count] = offset;
        cache->self_class_len[cache->self_class_count] = len;
        ++cache->self_class_count;
    }
    else
    {
        cache->self_class_truncated = true;
    }
}

static void html_view_selector_cache_add_self_attr(css_selector_cache_t *cache,
                                                   const char *selector,
                                                   const char *start,
                                                   const char *end)
{
    if (!cache || !selector || !start || !end || end <= start)
    {
        return;
    }
    uint32_t len = (uint32_t)(end - start);
    uint32_t offset = (uint32_t)(start - selector);
    for (uint8_t i = 0; i < cache->self_attr_count; ++i)
    {
        uint32_t existing_len = cache->self_attr_len[i];
        if (existing_len == len &&
            strncasecmp(selector + cache->self_attr_start[i], start, len) == 0)
        {
            return;
        }
    }
    if (cache->self_attr_count < 2)
    {
        cache->self_attr_start[cache->self_attr_count] = offset;
        cache->self_attr_len[cache->self_attr_count] = len;
        ++cache->self_attr_count;
    }
    else
    {
        cache->self_attr_truncated = true;
    }
}

static void html_view_selector_cache_set_self_requirements(css_selector_cache_t *cache,
                                                           const char *selector)
{
    if (!cache)
    {
        return;
    }
    cache->self_class_count = 0;
    cache->self_attr_count = 0;
    cache->self_class_truncated = false;
    cache->self_attr_truncated = false;
    cache->self_simple = false;
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

    bool escape = false;
    char quote = 0;
    int bracket_depth = 0;
    int paren_depth = 0;
    bool has_pseudo = false;
    bool has_attr = false;
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
        if (c == '[' && bracket_depth == 0 && paren_depth == 0)
        {
            has_attr = true;
            const char *scan = p;
            const char *name_start = NULL;
            const char *name_end = NULL;
            if (html_view_parse_attr_selector_meta(&scan,
                                                   part_end,
                                                   &name_start,
                                                   &name_end,
                                                   NULL,
                                                   NULL,
                                                   NULL,
                                                   NULL))
            {
                if (name_start && name_end && name_end > name_start)
                {
                    html_view_selector_cache_add_self_attr(cache, selector, name_start, name_end);
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
        if (bracket_depth > 0 || paren_depth > 0)
        {
            ++p;
            continue;
        }
        if (c == ':')
        {
            has_pseudo = true;
            const char *name = p + 1;
            if (name < part_end && *name == ':')
            {
                ++name;
            }
            while (name < part_end &&
                   (isalnum((unsigned char)*name) || *name == '-' || *name == '_'))
            {
                ++name;
            }
            p = name;
            continue;
        }
        if (c == '.')
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
                html_view_selector_cache_add_self_class(cache, selector, name_start, q);
            }
            p = q;
            continue;
        }
        ++p;
    }

    if (cache->count == 1 && !has_attr && !has_pseudo && !cache->self_class_truncated)
    {
        cache->self_simple = true;
    }
}

enum
{
    HTML_VIEW_SELECTOR_PSEUDO_REQ_NONE = 0,
    HTML_VIEW_SELECTOR_PSEUDO_REQ_BEFORE = 1,
    HTML_VIEW_SELECTOR_PSEUDO_REQ_AFTER = 2,
};

static void html_view_selector_cache_free_compiled(css_selector_cache_t *cache)
{
    if (!cache || !cache->compiled_parts)
    {
        if (cache)
        {
            cache->compiled = false;
            cache->compiled_count = 0;
        }
        return;
    }
    for (size_t i = 0; i < cache->compiled_count; ++i)
    {
        css_selector_compiled_part_t *part = &cache->compiled_parts[i];
        free(part->classes);
        free(part->attrs);
    }
    free(cache->compiled_parts);
    cache->compiled_parts = NULL;
    cache->compiled_count = 0;
    cache->compiled = false;
}

static const char *html_view_selector_token_end(const char *p, const char *end)
{
    bool escape = false;
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
        if (c == ':' || c == '.' || c == '#' || c == '[' || c == ']' ||
            c == '(' || c == ')' || isspace((unsigned char)c))
        {
            break;
        }
        ++p;
    }
    return p;
}

static bool html_view_selector_compiled_part_add_class(css_selector_compiled_part_t *part,
                                                       uint32_t start,
                                                       uint32_t len)
{
    if (!part || len == 0)
    {
        return false;
    }
    if (part->class_count == part->class_cap)
    {
        size_t new_cap = part->class_cap ? (size_t)part->class_cap * 2u : 4u;
        if (new_cap > 0xffffu)
        {
            new_cap = 0xffffu;
        }
        if (new_cap <= part->class_cap)
        {
            return false;
        }
        css_selector_atom_t *next = (css_selector_atom_t *)realloc(part->classes,
                                                                   new_cap * sizeof(*next));
        if (!next)
        {
            return false;
        }
        part->classes = next;
        part->class_cap = (uint16_t)new_cap;
    }
    part->classes[part->class_count++] = (css_selector_atom_t){
        .start = start,
        .len = len,
    };
    return true;
}

static bool html_view_selector_compiled_part_add_attr(css_selector_compiled_part_t *part,
                                                      uint32_t name_start,
                                                      uint32_t name_len,
                                                      uint32_t value_start,
                                                      uint32_t value_len,
                                                      char op,
                                                      bool has_value)
{
    if (!part || name_len == 0)
    {
        return false;
    }
    if (part->attr_count == part->attr_cap)
    {
        size_t new_cap = part->attr_cap ? (size_t)part->attr_cap * 2u : 4u;
        if (new_cap > 0xffffu)
        {
            new_cap = 0xffffu;
        }
        if (new_cap <= part->attr_cap)
        {
            return false;
        }
        css_selector_attr_req_t *next = (css_selector_attr_req_t *)realloc(part->attrs,
                                                                           new_cap * sizeof(*next));
        if (!next)
        {
            return false;
        }
        part->attrs = next;
        part->attr_cap = (uint16_t)new_cap;
    }
    part->attrs[part->attr_count++] = (css_selector_attr_req_t){
        .name_start = name_start,
        .name_len = name_len,
        .value_start = value_start,
        .value_len = value_len,
        .op = op,
        .has_value = has_value,
    };
    return true;
}

static bool html_view_selector_cache_compile_parts(css_selector_cache_t *cache, const char *selector)
{
    if (!cache || !selector)
    {
        return false;
    }
    if (cache->compiled || cache->compiled_failed)
    {
        return cache->compiled;
    }
    if (cache->count == 0)
    {
        cache->compiled_failed = true;
        return false;
    }

    cache->compiled_parts = (css_selector_compiled_part_t *)calloc(cache->count,
                                                                   sizeof(*cache->compiled_parts));
    if (!cache->compiled_parts)
    {
        cache->compiled_failed = true;
        return false;
    }
    cache->compiled_count = cache->count;

    for (size_t i = 0; i < cache->count; ++i)
    {
        const css_selector_part_t *part = &cache->parts[i];
        const char *part_start = selector + part->start;
        const char *part_end = selector + part->end;
        html_view_trim_range(&part_start, &part_end);
        if (part_end <= part_start)
        {
            cache->compiled_failed = true;
            html_view_selector_cache_free_compiled(cache);
            return false;
        }

        css_selector_compiled_part_t *out = &cache->compiled_parts[i];
        const char *p = part_start;
        if (*p == '*')
        {
            out->tag_any = true;
            ++p;
        }
        else if (*p != '#' && *p != '.' && *p != '[' && *p != ':')
        {
            const char *tag_end = p;
            while (tag_end < part_end &&
                   *tag_end != ':' && *tag_end != '.' && *tag_end != '#' &&
                   *tag_end != '[' && !isspace((unsigned char)*tag_end))
            {
                ++tag_end;
            }
            if (tag_end > p)
            {
                out->tag_start = (uint32_t)(p - selector);
                out->tag_len = (uint32_t)(tag_end - p);
            }
            p = tag_end;
        }

        while (p < part_end)
        {
            char c = *p;
            if (c == '.')
            {
                const char *name_start = p + 1;
                const char *name_end = html_view_selector_token_end(name_start, part_end);
                if (name_end <= name_start)
                {
                    cache->never_match = true;
                    cache->compiled_failed = true;
                    html_view_selector_cache_free_compiled(cache);
                    return false;
                }
                if (!html_view_selector_compiled_part_add_class(out,
                                                                (uint32_t)(name_start - selector),
                                                                (uint32_t)(name_end - name_start)))
                {
                    cache->compiled_failed = true;
                    html_view_selector_cache_free_compiled(cache);
                    return false;
                }
                p = name_end;
                continue;
            }
            if (c == '#')
            {
                const char *name_start = p + 1;
                const char *name_end = html_view_selector_token_end(name_start, part_end);
                if (name_end <= name_start)
                {
                    cache->never_match = true;
                    cache->compiled_failed = true;
                    html_view_selector_cache_free_compiled(cache);
                    return false;
                }
                if (out->id_valid)
                {
                    if (out->id_len != (uint32_t)(name_end - name_start) ||
                        strncasecmp(selector + out->id_start, name_start,
                                    (size_t)(name_end - name_start)) != 0)
                    {
                        cache->never_match = true;
                        cache->compiled_failed = true;
                        html_view_selector_cache_free_compiled(cache);
                        return false;
                    }
                }
                else
                {
                    out->id_valid = true;
                    out->id_start = (uint32_t)(name_start - selector);
                    out->id_len = (uint32_t)(name_end - name_start);
                }
                p = name_end;
                continue;
            }
            if (c == '[')
            {
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
                    cache->compiled_failed = true;
                    html_view_selector_cache_free_compiled(cache);
                    return false;
                }
                if (unsupported)
                {
                    cache->compiled_failed = true;
                    html_view_selector_cache_free_compiled(cache);
                    return false;
                }

                uint32_t name_len = (uint32_t)(name_end - name_start);
                bool has_value = (op != 0 && value_start && value_end && value_end > value_start);
                uint32_t value_len = has_value ? (uint32_t)(value_end - value_start) : 0;
                if (!html_view_selector_compiled_part_add_attr(out,
                                                               (uint32_t)(name_start - selector),
                                                               name_len,
                                                               has_value ? (uint32_t)(value_start - selector) : 0,
                                                               value_len,
                                                               op,
                                                               has_value))
                {
                    cache->compiled_failed = true;
                    html_view_selector_cache_free_compiled(cache);
                    return false;
                }
                p = scan;
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
                    cache->compiled_failed = true;
                    html_view_selector_cache_free_compiled(cache);
                    return false;
                }
                if (name_end < part_end && *name_end == '(')
                {
                    const char *next = html_view_selector_skip_parens(name_end, part_end);
                    if (!next || next <= name_end)
                    {
                        cache->compiled_failed = true;
                        html_view_selector_cache_free_compiled(cache);
                        return false;
                    }
                    p = next;
                    continue;
                }
                size_t name_len = (size_t)(name_end - name);
                if (name_len == 4 && strncasecmp(name, "link", 4) == 0)
                {
                    out->require_link = true;
                }
                else if (name_len == 4 && strncasecmp(name, "root", 4) == 0)
                {
                    out->require_root = true;
                }
                else if (name_len == 6 && strncasecmp(name, "before", 6) == 0)
                {
                    if (out->pseudo_required != HTML_VIEW_SELECTOR_PSEUDO_REQ_NONE &&
                        out->pseudo_required != HTML_VIEW_SELECTOR_PSEUDO_REQ_BEFORE)
                    {
                        cache->compiled_failed = true;
                        html_view_selector_cache_free_compiled(cache);
                        return false;
                    }
                    out->pseudo_required = HTML_VIEW_SELECTOR_PSEUDO_REQ_BEFORE;
                }
                else if (name_len == 5 && strncasecmp(name, "after", 5) == 0)
                {
                    if (out->pseudo_required != HTML_VIEW_SELECTOR_PSEUDO_REQ_NONE &&
                        out->pseudo_required != HTML_VIEW_SELECTOR_PSEUDO_REQ_AFTER)
                    {
                        cache->compiled_failed = true;
                        html_view_selector_cache_free_compiled(cache);
                        return false;
                    }
                    out->pseudo_required = HTML_VIEW_SELECTOR_PSEUDO_REQ_AFTER;
                }
                p = name_end;
                continue;
            }
            if (c == '>' || c == '+' || c == '~' || isspace((unsigned char)c))
            {
                break;
            }
            ++p;
        }
    }

    cache->compiled = true;
    return true;
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
    cache->specificity = html_view_specificity_to_value(
        html_view_selector_specificity_range(start, end));
    html_view_selector_cache_set_hints(cache, selector);
    html_view_selector_cache_set_pseudo_flags(cache, selector);
    html_view_selector_cache_set_attr_flags(cache, selector);
    html_view_selector_cache_set_self_requirements(cache, selector);
    html_view_selector_cache_set_ancestor_bloom_mask(cache, selector);
    if (!cache->never_match)
    {
        (void)html_view_selector_cache_compile_parts(cache, selector);
    }
    return true;
}

static bool html_view_selector_part_has_pseudo(const char *start, const char *end)
{
    if (!start || !end || end <= start)
    {
        return false;
    }
    bool escape = false;
    char quote = 0;
    int bracket_depth = 0;
    int paren_depth = 0;
    for (const char *p = start; p < end; ++p)
    {
        char c = *p;
        if (escape)
        {
            escape = false;
            continue;
        }
        if (c == '\\')
        {
            escape = true;
            continue;
        }
        if (quote)
        {
            if (c == quote)
            {
                quote = 0;
            }
            continue;
        }
        if (c == '"' || c == '\'')
        {
            quote = c;
            continue;
        }
        if (c == '[')
        {
            ++bracket_depth;
            continue;
        }
        if (c == ']' && bracket_depth > 0)
        {
            --bracket_depth;
            continue;
        }
        if (bracket_depth > 0)
        {
            continue;
        }
        if (c == '(')
        {
            ++paren_depth;
            continue;
        }
        if (c == ')' && paren_depth > 0)
        {
            --paren_depth;
            continue;
        }
        if (paren_depth > 0)
        {
            continue;
        }
        if (c == ':')
        {
            return true;
        }
    }
    return false;
}

static bool html_view_selector_part_matches_compiled(const css_selector_compiled_part_t *part,
                                                     const css_selector_part_t *raw_part,
                                                     const char *selector,
                                                     const html_node_t *node,
                                                     html_view_pseudo_t pseudo)
{
    if (!part || !selector || !node || node->type != HTML_NODE_ELEMENT || !node->name)
    {
        return false;
    }

    if (part->tag_len > 0)
    {
        if (strlen(node->name) != part->tag_len ||
            strncasecmp(node->name, selector + part->tag_start, part->tag_len) != 0)
        {
            return false;
        }
    }

    if (part->id_valid)
    {
        const char *id = html_attr_get(node, "id");
        if (!id || strlen(id) != part->id_len ||
            strncasecmp(id, selector + part->id_start, part->id_len) != 0)
        {
            return false;
        }
    }

    for (uint16_t i = 0; i < part->class_count; ++i)
    {
        const css_selector_atom_t *atom = &part->classes[i];
        if (!html_view_node_has_class(node, selector + atom->start, atom->len))
        {
            return false;
        }
    }

    for (uint16_t i = 0; i < part->attr_count; ++i)
    {
        const css_selector_attr_req_t *attr = &part->attrs[i];
        const char *attr_value = html_view_attr_get_range(node,
                                                          selector + attr->name_start,
                                                          attr->name_len);
        if (!attr_value)
        {
            return false;
        }
        if (!attr->has_value || attr->op == 0)
        {
            continue;
        }
        if (attr->op == '=')
        {
            if (!html_view_selector_range_eq_ci(attr_value,
                                                selector + attr->value_start,
                                                attr->value_len))
            {
                return false;
            }
        }
        else if (attr->op == '~')
        {
            if (html_view_selector_range_eq_ci("class",
                                               selector + attr->name_start,
                                               attr->name_len))
            {
                if (!html_view_node_has_class(node,
                                              selector + attr->value_start,
                                              attr->value_len))
                {
                    return false;
                }
            }
            else if (!html_view_attr_value_has_token_range(attr_value,
                                                           selector + attr->value_start,
                                                           attr->value_len))
            {
                return false;
            }
        }
        else if (attr->op == '^')
        {
            if (!html_view_selector_range_startswith_ci_value(attr_value,
                                                              selector + attr->value_start,
                                                              attr->value_len))
            {
                return false;
            }
        }
        else if (attr->op == '$')
        {
            if (!html_view_selector_range_endswith_ci_value(attr_value,
                                                            selector + attr->value_start,
                                                            attr->value_len))
            {
                return false;
            }
        }
        else if (attr->op == '*')
        {
            if (!html_view_selector_range_contains_ci_value(attr_value,
                                                            selector + attr->value_start,
                                                            attr->value_len))
            {
                return false;
            }
        }
        else if (attr->op == '|')
        {
            if (!html_view_selector_range_dashmatch_ci_value(attr_value,
                                                             selector + attr->value_start,
                                                             attr->value_len))
            {
                return false;
            }
        }
        else
        {
            return false;
        }
    }

    if (part->require_link)
    {
        if (strcasecmp(node->name, "a") != 0)
        {
            return false;
        }
        const char *href = html_attr_get(node, "href");
        if (!href || href[0] == '\0')
        {
            return false;
        }
    }

    if (part->require_root)
    {
        const html_node_t *parent = node->parent;
        if (!parent || parent->type != HTML_NODE_DOCUMENT)
        {
            return false;
        }
    }

    if (part->pseudo_required != HTML_VIEW_SELECTOR_PSEUDO_REQ_NONE)
    {
        if (pseudo == HTML_VIEW_PSEUDO_NONE)
        {
            return false;
        }
        if (part->pseudo_required == HTML_VIEW_SELECTOR_PSEUDO_REQ_BEFORE &&
            pseudo != HTML_VIEW_PSEUDO_BEFORE)
        {
            return false;
        }
        if (part->pseudo_required == HTML_VIEW_SELECTOR_PSEUDO_REQ_AFTER &&
            pseudo != HTML_VIEW_PSEUDO_AFTER)
        {
            return false;
        }
    }
    else if (pseudo != HTML_VIEW_PSEUDO_NONE)
    {
        return false;
    }

    if (raw_part)
    {
        const char *raw_start = selector + raw_part->start;
        const char *raw_end = selector + raw_part->end;
        if (html_view_selector_part_has_pseudo(raw_start, raw_end))
        {
            if (!html_view_simple_selector_matches_range_internal(raw_start, raw_end, node, pseudo))
            {
                return false;
            }
        }
    }

    return true;
}

static bool html_view_selector_matches_compiled(const css_selector_cache_t *cache,
                                                const char *selector,
                                                const html_node_t *node,
                                                html_view_pseudo_t pseudo)
{
    if (!cache || !selector || !node || node->type != HTML_NODE_ELEMENT ||
        !cache->compiled_parts || cache->compiled_count == 0 ||
        cache->compiled_count != cache->count)
    {
        return false;
    }

    const html_node_t *cur = node;
    const css_selector_compiled_part_t *right = &cache->compiled_parts[cache->compiled_count - 1];
    const css_selector_part_t *right_part = &cache->parts[cache->compiled_count - 1];
    if (!html_view_selector_part_matches_compiled(right, right_part, selector, cur, pseudo))
    {
        return false;
    }

    for (size_t idx = cache->compiled_count - 1; idx > 0; --idx)
    {
        const css_selector_part_t *left_part = &cache->parts[idx - 1];
        const css_selector_compiled_part_t *left = &cache->compiled_parts[idx - 1];
        char comb = left_part->combinator ? left_part->combinator : ' ';
        if (comb == ' ')
        {
            bool found = false;
            for (const html_node_t *p = cur->parent; p; p = p->parent)
            {
                if (html_view_selector_part_matches_compiled(left, left_part, selector, p, HTML_VIEW_PSEUDO_NONE))
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
            if (!cur || !html_view_selector_part_matches_compiled(left, left_part, selector, cur, HTML_VIEW_PSEUDO_NONE))
            {
                return false;
            }
        }
        else if (comb == '+')
        {
            cur = html_view_prev_element_sibling(cur);
            if (!cur || !html_view_selector_part_matches_compiled(left, left_part, selector, cur, HTML_VIEW_PSEUDO_NONE))
            {
                return false;
            }
        }
        else if (comb == '~')
        {
            bool found = false;
            for (const html_node_t *p = html_view_prev_element_sibling(cur); p; p = html_view_prev_element_sibling(p))
            {
                if (html_view_selector_part_matches_compiled(left, left_part, selector, p, HTML_VIEW_PSEUDO_NONE))
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
    bool match = cache->compiled
        ? html_view_selector_matches_compiled(cache, selector, node, pseudo)
        : html_view_selector_matches_parts(cache->parts, cache->count, selector, node, pseudo);
    html_view_selector_cache_free_compiled(cache);
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
    if (cache->self_class_count > 0)
    {
        for (uint8_t i = 0; i < cache->self_class_count; ++i)
        {
            uint32_t cls_start = cache->self_class_start[i];
            uint32_t cls_len = cache->self_class_len[i];
            if (cache->class_hint_valid &&
                cls_start == cache->class_hint_start &&
                cls_len == cache->class_hint_len)
            {
                continue;
            }
            if (!html_view_node_has_class(node, rule->selector + cls_start, cls_len))
            {
                return false;
            }
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
        else if (cache->attr_hint_op == '^')
        {
            const char *val_start = rule->selector + cache->attr_hint_value_start;
            if (!cache->attr_hint_value_valid ||
                !html_view_selector_range_startswith_ci_value(attr_value, val_start, cache->attr_hint_value_len))
            {
                return false;
            }
        }
        else if (cache->attr_hint_op == '$')
        {
            const char *val_start = rule->selector + cache->attr_hint_value_start;
            if (!cache->attr_hint_value_valid ||
                !html_view_selector_range_endswith_ci_value(attr_value, val_start, cache->attr_hint_value_len))
            {
                return false;
            }
        }
        else if (cache->attr_hint_op == '*')
        {
            const char *val_start = rule->selector + cache->attr_hint_value_start;
            if (!cache->attr_hint_value_valid ||
                !html_view_selector_range_contains_ci_value(attr_value, val_start, cache->attr_hint_value_len))
            {
                return false;
            }
        }
        else if (cache->attr_hint_op == '|')
        {
            const char *val_start = rule->selector + cache->attr_hint_value_start;
            if (!cache->attr_hint_value_valid ||
                !html_view_selector_range_dashmatch_ci_value(attr_value, val_start, cache->attr_hint_value_len))
            {
                return false;
            }
        }
    }
    if (cache->self_attr_count > 0)
    {
        for (uint8_t i = 0; i < cache->self_attr_count; ++i)
        {
            uint32_t attr_start = cache->self_attr_start[i];
            uint32_t attr_len = cache->self_attr_len[i];
            if (cache->attr_hint_valid &&
                attr_start == cache->attr_hint_name_start &&
                attr_len == cache->attr_hint_name_len)
            {
                continue;
            }
            if (!html_view_attr_get_range(node, rule->selector + attr_start, attr_len))
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

typedef struct html_view_rule_trie_node
{
    const css_selector_compiled_part_t *part;
    const css_selector_part_t *raw_part;
    const char *selector;
    char combinator;
    web_bloom_t part_bloom;
    web_bloom_t left_chain_bloom;
    struct html_view_rule_trie_node **children;
    size_t child_count;
    size_t child_cap;
    css_rule_t **rules;
    size_t rule_count;
    size_t rule_cap;
    uint32_t match_stamp;
} html_view_rule_trie_node_t;

typedef struct html_view_rule_trie_cache_attr
{
    char *name;
    size_t name_len;
    char *value;
    size_t value_len;
} html_view_rule_trie_cache_attr_t;

typedef struct html_view_rule_trie_cache_entry
{
    uint64_t hash;
    html_view_pseudo_t pseudo;
    const html_node_t *parent;
    char *tag;
    size_t tag_len;
    char *id;
    size_t id_len;
    char *class_value;
    size_t class_len;
    html_class_token_t *class_tokens;
    size_t class_token_count;
    html_view_rule_trie_cache_attr_t *attrs;
    size_t attr_count;
    css_rule_t **rules;
    size_t rule_count;
    bool valid;
} html_view_rule_trie_cache_entry_t;

typedef struct html_view_rule_trie_cache
{
    html_view_rule_trie_cache_entry_t *entries;
    size_t entry_count;
} html_view_rule_trie_cache_t;

typedef struct html_view_rule_trie
{
    html_view_rule_trie_node_t **roots;
    size_t root_count;
    size_t root_cap;
    css_rule_t **fallback_rules;
    size_t fallback_count;
    size_t fallback_cap;
    size_t rule_count;
    bool cache_enabled;
    bool cache_require_parent;
    html_view_rule_trie_cache_t cache;
} html_view_rule_trie_t;

static uint32_t html_view_rule_order(const css_rule_t *rule);
static uint32_t html_view_rule_specificity(const css_rule_t *rule);
static int html_view_rule_compare(const css_rule_t *left, const css_rule_t *right);

static char html_view_selector_combinator_normalize(char combinator)
{
    return combinator ? combinator : ' ';
}

static bool html_view_rule_trie_part_equals(const css_selector_compiled_part_t *a,
                                            const char *a_selector,
                                            const css_selector_compiled_part_t *b,
                                            const char *b_selector)
{
    if (!a || !b || !a_selector || !b_selector)
    {
        return false;
    }
    if (a->tag_len != b->tag_len)
    {
        return false;
    }
    if (a->tag_len > 0 &&
        !html_view_selector_range_eq_ci_ranges(a_selector + a->tag_start, a->tag_len,
                                               b_selector + b->tag_start, b->tag_len))
    {
        return false;
    }
    if (a->id_valid != b->id_valid)
    {
        return false;
    }
    if (a->id_valid)
    {
        if (a->id_len != b->id_len ||
            !html_view_selector_range_eq_ci_ranges(a_selector + a->id_start, a->id_len,
                                                   b_selector + b->id_start, b->id_len))
        {
            return false;
        }
    }
    if (a->class_count != b->class_count)
    {
        return false;
    }
    for (uint16_t i = 0; i < a->class_count; ++i)
    {
        const css_selector_atom_t *ac = &a->classes[i];
        const css_selector_atom_t *bc = &b->classes[i];
        if (ac->len != bc->len ||
            !html_view_selector_range_eq_ci_ranges(a_selector + ac->start, ac->len,
                                                   b_selector + bc->start, bc->len))
        {
            return false;
        }
    }
    if (a->attr_count != b->attr_count)
    {
        return false;
    }
    for (uint16_t i = 0; i < a->attr_count; ++i)
    {
        const css_selector_attr_req_t *aa = &a->attrs[i];
        const css_selector_attr_req_t *ba = &b->attrs[i];
        if (aa->name_len != ba->name_len ||
            aa->value_len != ba->value_len ||
            aa->op != ba->op ||
            aa->has_value != ba->has_value)
        {
            return false;
        }
        if (!html_view_selector_range_eq_ci_ranges(a_selector + aa->name_start, aa->name_len,
                                                   b_selector + ba->name_start, ba->name_len))
        {
            return false;
        }
        if (aa->has_value && aa->value_len > 0)
        {
            if (!html_view_selector_range_eq_ci_ranges(a_selector + aa->value_start, aa->value_len,
                                                       b_selector + ba->value_start, ba->value_len))
            {
                return false;
            }
        }
    }
    if (a->require_link != b->require_link)
    {
        return false;
    }
    if (a->pseudo_required != b->pseudo_required)
    {
        return false;
    }
    return true;
}

static bool html_view_rule_trie_node_equals(const html_view_rule_trie_node_t *node,
                                            const css_selector_compiled_part_t *part,
                                            const css_selector_part_t *raw_part,
                                            const char *selector,
                                            char combinator)
{
    if (!node || !part || !raw_part || !selector)
    {
        return false;
    }
    if (node->combinator != html_view_selector_combinator_normalize(combinator))
    {
        return false;
    }
    return html_view_rule_trie_part_equals(node->part, node->selector, part, selector);
}

static html_view_rule_trie_node_t *html_view_rule_trie_node_create(const css_selector_compiled_part_t *part,
                                                                   const css_selector_part_t *raw_part,
                                                                   const char *selector,
                                                                   char combinator)
{
    if (!part || !raw_part || !selector)
    {
        return NULL;
    }
    html_view_rule_trie_node_t *node = (html_view_rule_trie_node_t *)calloc(1, sizeof(*node));
    if (!node)
    {
        return NULL;
    }
    node->part = part;
    node->raw_part = raw_part;
    node->selector = selector;
    node->combinator = html_view_selector_combinator_normalize(combinator);
    html_view_bloom_clear(&node->part_bloom);
    html_view_selector_bloom_add_part_mask(&node->part_bloom, selector, raw_part);
    html_view_bloom_copy(&node->left_chain_bloom, &node->part_bloom);
    return node;
}

static bool html_view_rule_trie_node_add_rule(html_view_rule_trie_node_t *node, css_rule_t *rule)
{
    if (!node || !rule)
    {
        return false;
    }
    if (node->rule_count == node->rule_cap)
    {
        size_t new_cap = node->rule_cap ? node->rule_cap * 2u : 4u;
        css_rule_t **next = (css_rule_t **)realloc(node->rules, new_cap * sizeof(*next));
        if (!next)
        {
            return false;
        }
        node->rules = next;
        node->rule_cap = new_cap;
    }
    node->rules[node->rule_count++] = rule;
    return true;
}

static html_view_rule_trie_node_t *html_view_rule_trie_find_child(const html_view_rule_trie_node_t *parent,
                                                                  const css_selector_compiled_part_t *part,
                                                                  const css_selector_part_t *raw_part,
                                                                  const char *selector,
                                                                  char combinator)
{
    if (!parent || !part || !raw_part || !selector)
    {
        return NULL;
    }
    for (size_t i = 0; i < parent->child_count; ++i)
    {
        html_view_rule_trie_node_t *child = parent->children[i];
        if (html_view_rule_trie_node_equals(child, part, raw_part, selector, combinator))
        {
            return child;
        }
    }
    return NULL;
}

static html_view_rule_trie_node_t *html_view_rule_trie_get_child(html_view_rule_trie_node_t *parent,
                                                                 const css_selector_compiled_part_t *part,
                                                                 const css_selector_part_t *raw_part,
                                                                 const char *selector,
                                                                 char combinator)
{
    if (!parent)
    {
        return NULL;
    }
    html_view_rule_trie_node_t *child = html_view_rule_trie_find_child(parent,
                                                                       part,
                                                                       raw_part,
                                                                       selector,
                                                                       combinator);
    if (child)
    {
        return child;
    }
    child = html_view_rule_trie_node_create(part, raw_part, selector, combinator);
    if (!child)
    {
        return NULL;
    }
    if (parent->child_count == parent->child_cap)
    {
        size_t new_cap = parent->child_cap ? parent->child_cap * 2u : 4u;
        html_view_rule_trie_node_t **next = (html_view_rule_trie_node_t **)realloc(parent->children,
                                                                                   new_cap * sizeof(*next));
        if (!next)
        {
            free(child);
            return NULL;
        }
        parent->children = next;
        parent->child_cap = new_cap;
    }
    parent->children[parent->child_count++] = child;
    return child;
}

static html_view_rule_trie_node_t *html_view_rule_trie_get_root(html_view_rule_trie_t *trie,
                                                                const css_selector_compiled_part_t *part,
                                                                const css_selector_part_t *raw_part,
                                                                const char *selector)
{
    if (!trie || !part || !raw_part || !selector)
    {
        return NULL;
    }
    for (size_t i = 0; i < trie->root_count; ++i)
    {
        html_view_rule_trie_node_t *root = trie->roots[i];
        if (html_view_rule_trie_node_equals(root, part, raw_part, selector, 0))
        {
            return root;
        }
    }
    html_view_rule_trie_node_t *root = html_view_rule_trie_node_create(part, raw_part, selector, 0);
    if (!root)
    {
        return NULL;
    }
    if (trie->root_count == trie->root_cap)
    {
        size_t new_cap = trie->root_cap ? trie->root_cap * 2u : 8u;
        html_view_rule_trie_node_t **next = (html_view_rule_trie_node_t **)realloc(trie->roots,
                                                                                   new_cap * sizeof(*next));
        if (!next)
        {
            free(root);
            return NULL;
        }
        trie->roots = next;
        trie->root_cap = new_cap;
    }
    trie->roots[trie->root_count++] = root;
    return root;
}

static bool html_view_rule_trie_fallback_push(html_view_rule_trie_t *trie, css_rule_t *rule)
{
    if (!trie || !rule)
    {
        return false;
    }
    if (trie->fallback_count == trie->fallback_cap)
    {
        size_t new_cap = trie->fallback_cap ? trie->fallback_cap * 2u : 8u;
        css_rule_t **next = (css_rule_t **)realloc(trie->fallback_rules, new_cap * sizeof(*next));
        if (!next)
        {
            return false;
        }
        trie->fallback_rules = next;
        trie->fallback_cap = new_cap;
    }
    trie->fallback_rules[trie->fallback_count++] = rule;
    return true;
}

static bool html_view_rule_trie_cache_is_id_or_class(const char *name)
{
    if (!name || name[0] == '\0')
    {
        return false;
    }
    return (strcasecmp(name, "id") == 0) || (strcasecmp(name, "class") == 0);
}

static uint64_t html_view_rule_trie_cache_hash_combine(uint64_t h, uint64_t v)
{
    h ^= v;
    h *= 1099511628211ull;
    return h;
}

static uint64_t html_view_rule_trie_cache_hash_node(const html_node_t *node,
                                                    html_view_pseudo_t pseudo,
                                                    bool include_parent)
{
    if (!node || node->type != HTML_NODE_ELEMENT)
    {
        return 0;
    }
    uint64_t h = 1469598103934665603ull;
    h = html_view_rule_trie_cache_hash_combine(h, (uint64_t)pseudo + 0x9e3779b97f4a7c15ull);
    if (include_parent)
    {
        h = html_view_rule_trie_cache_hash_combine(h, (uint64_t)(uintptr_t)node->parent);
    }

    if (node->name && node->name[0] != '\0')
    {
        uint64_t tag_hash = html_view_bloom_hash_range_ci(node->name,
                                                          node->name + strlen(node->name),
                                                          false);
        h = html_view_rule_trie_cache_hash_combine(h, tag_hash);
    }

    const char *id = html_attr_get(node, "id");
    if (id && id[0] != '\0')
    {
        uint64_t id_hash = html_view_bloom_hash_range_ci(id, id + strlen(id), false);
        h = html_view_rule_trie_cache_hash_combine(h, id_hash);
    }

    size_t class_count = 0;
    const char *class_value = NULL;
    const html_class_token_t *class_tokens = html_view_node_class_tokens(node,
                                                                        &class_count,
                                                                        &class_value);
    uint64_t class_hash = 0;
    if (class_tokens && class_count > 0)
    {
        for (size_t i = 0; i < class_count; ++i)
        {
            const html_class_token_t *tok = &class_tokens[i];
            if (tok->len == 0)
            {
                continue;
            }
            uint64_t tok_hash = html_view_bloom_hash_range_ci(tok->start,
                                                              tok->start + tok->len,
                                                              false);
            class_hash += tok_hash * 0x9e3779b97f4a7c15ull;
        }
    }
    else if (class_value && class_value[0] != '\0')
    {
        class_hash = html_view_bloom_hash_range_ci(class_value,
                                                   class_value + strlen(class_value),
                                                   false);
    }
    h = html_view_rule_trie_cache_hash_combine(h, class_hash);
    h = html_view_rule_trie_cache_hash_combine(h, (uint64_t)class_count);

    uint64_t attr_hash = 0;
    size_t attr_count = 0;
    for (const html_attr_t *attr = node->attrs; attr; attr = attr->next)
    {
        if (!attr->name || attr->name[0] == '\0')
        {
            continue;
        }
        if (html_view_rule_trie_cache_is_id_or_class(attr->name))
        {
            continue;
        }
        uint64_t name_hash = html_view_bloom_hash_range_ci(attr->name,
                                                           attr->name + strlen(attr->name),
                                                           false);
        uint64_t value_hash = 0;
        if (attr->value && attr->value[0] != '\0')
        {
            value_hash = html_view_bloom_hash_range_ci(attr->value,
                                                       attr->value + strlen(attr->value),
                                                       false);
        }
        uint64_t pair = name_hash ^ (value_hash + 0x9e3779b97f4a7c15ull + (name_hash << 6) + (name_hash >> 2));
        attr_hash += pair;
        attr_count++;
    }
    h = html_view_rule_trie_cache_hash_combine(h, attr_hash);
    h = html_view_rule_trie_cache_hash_combine(h, (uint64_t)attr_count);
    return h;
}

static bool html_view_rule_trie_cache_class_tokens_build(html_view_rule_trie_cache_entry_t *entry)
{
    if (!entry || !entry->class_value || entry->class_value[0] == '\0')
    {
        return true;
    }

    const char *classes = entry->class_value;
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
        const char *start = p;
        while (*p && !isspace((unsigned char)*p))
        {
            ++p;
        }
        if (p > start)
        {
            ++count;
        }
    }
    if (count == 0)
    {
        return true;
    }

    html_class_token_t *tokens = (html_class_token_t *)calloc(count, sizeof(*tokens));
    if (!tokens)
    {
        return false;
    }

    size_t idx = 0;
    p = classes;
    while (*p && idx < count)
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
        tokens[idx++] = (html_class_token_t){
            .start = start,
            .len = len,
        };
    }

    entry->class_tokens = tokens;
    entry->class_token_count = idx;
    return true;
}

static void html_view_rule_trie_cache_entry_clear(html_view_rule_trie_cache_entry_t *entry)
{
    if (!entry)
    {
        return;
    }
    free(entry->tag);
    free(entry->id);
    free(entry->class_value);
    free(entry->class_tokens);
    if (entry->attrs)
    {
        for (size_t i = 0; i < entry->attr_count; ++i)
        {
            free(entry->attrs[i].name);
            free(entry->attrs[i].value);
        }
        free(entry->attrs);
    }
    free(entry->rules);
    *entry = (html_view_rule_trie_cache_entry_t){0};
}

static bool html_view_rule_trie_cache_entry_copy_key(html_view_rule_trie_cache_entry_t *entry,
                                                     const html_node_t *node,
                                                     bool include_parent)
{
    if (!entry || !node || node->type != HTML_NODE_ELEMENT)
    {
        return false;
    }
    if (include_parent)
    {
        entry->parent = node->parent;
    }
    if (node->name && node->name[0] != '\0')
    {
        entry->tag = html_view_strdup(node->name);
        if (!entry->tag)
        {
            return false;
        }
        entry->tag_len = strlen(entry->tag);
    }

    const char *id = html_attr_get(node, "id");
    if (id && id[0] != '\0')
    {
        entry->id = html_view_strdup(id);
        if (!entry->id)
        {
            return false;
        }
        entry->id_len = strlen(entry->id);
    }

    const char *classes = html_attr_get(node, "class");
    if (classes && classes[0] != '\0')
    {
        entry->class_value = html_view_strdup(classes);
        if (!entry->class_value)
        {
            return false;
        }
        entry->class_len = strlen(entry->class_value);
        if (!html_view_rule_trie_cache_class_tokens_build(entry))
        {
            return false;
        }
    }

    size_t attr_count = 0;
    for (const html_attr_t *attr = node->attrs; attr; attr = attr->next)
    {
        if (!attr->name || attr->name[0] == '\0')
        {
            continue;
        }
        if (html_view_rule_trie_cache_is_id_or_class(attr->name))
        {
            continue;
        }
        attr_count++;
    }
    if (attr_count > 0)
    {
        entry->attrs = (html_view_rule_trie_cache_attr_t *)calloc(attr_count, sizeof(*entry->attrs));
        if (!entry->attrs)
        {
            return false;
        }
        entry->attr_count = attr_count;
        size_t idx = 0;
        for (const html_attr_t *attr = node->attrs; attr; attr = attr->next)
        {
            if (!attr->name || attr->name[0] == '\0')
            {
                continue;
            }
            if (html_view_rule_trie_cache_is_id_or_class(attr->name))
            {
                continue;
            }
            entry->attrs[idx].name = html_view_strdup(attr->name);
            if (!entry->attrs[idx].name)
            {
                return false;
            }
            entry->attrs[idx].name_len = strlen(entry->attrs[idx].name);
            if (attr->value && attr->value[0] != '\0')
            {
                entry->attrs[idx].value = html_view_strdup(attr->value);
                if (!entry->attrs[idx].value)
                {
                    return false;
                }
                entry->attrs[idx].value_len = strlen(entry->attrs[idx].value);
            }
            ++idx;
        }
    }

    return true;
}

static bool html_view_rule_trie_cache_class_contains(const html_class_token_t *tokens,
                                                     size_t token_count,
                                                     const char *start,
                                                     size_t len)
{
    if (!tokens || token_count == 0 || !start || len == 0)
    {
        return false;
    }
    for (size_t i = 0; i < token_count; ++i)
    {
        const html_class_token_t *tok = &tokens[i];
        if (tok->len != len)
        {
            continue;
        }
        if (html_view_selector_range_eq_ci_ranges(tok->start, tok->len, start, len))
        {
            return true;
        }
    }
    return false;
}

static bool html_view_rule_trie_cache_class_set_equals(const html_view_rule_trie_cache_entry_t *entry,
                                                       const html_node_t *node)
{
    if (!entry || !node || node->type != HTML_NODE_ELEMENT)
    {
        return false;
    }
    size_t node_count = 0;
    const char *node_class_value = NULL;
    const html_class_token_t *node_tokens = html_view_node_class_tokens(node,
                                                                       &node_count,
                                                                       &node_class_value);
    if (entry->class_len == 0)
    {
        return (!node_tokens || node_count == 0);
    }
    if (!node_class_value || node_class_value[0] == '\0')
    {
        return false;
    }
    if (entry->class_token_count == 0 || !entry->class_tokens)
    {
        size_t node_len = strlen(node_class_value);
        if (entry->class_len != node_len)
        {
            return false;
        }
        return html_view_selector_range_eq_ci_ranges(entry->class_value,
                                                     entry->class_len,
                                                     node_class_value,
                                                     node_len);
    }
    if (!node_tokens || node_count == 0)
    {
        return false;
    }
    if (entry->class_token_count != node_count)
    {
        return false;
    }
    for (size_t i = 0; i < entry->class_token_count; ++i)
    {
        const html_class_token_t *tok = &entry->class_tokens[i];
        if (!html_view_rule_trie_cache_class_contains(node_tokens, node_count, tok->start, tok->len))
        {
            return false;
        }
    }
    for (size_t i = 0; i < node_count; ++i)
    {
        const html_class_token_t *tok = &node_tokens[i];
        if (!html_view_rule_trie_cache_class_contains(entry->class_tokens,
                                                      entry->class_token_count,
                                                      tok->start,
                                                      tok->len))
        {
            return false;
        }
    }
    return true;
}

static bool html_view_rule_trie_cache_attr_eq(const html_view_rule_trie_cache_attr_t *entry,
                                              const html_attr_t *attr)
{
    if (!entry || !attr || !attr->name)
    {
        return false;
    }
    size_t name_len = strlen(attr->name);
    if (entry->name_len != name_len)
    {
        return false;
    }
    if (!html_view_selector_range_eq_ci_ranges(entry->name, entry->name_len,
                                               attr->name, name_len))
    {
        return false;
    }
    const char *value = attr->value ? attr->value : "";
    size_t value_len = value[0] != '\0' ? strlen(value) : 0;
    if (entry->value_len != value_len)
    {
        return false;
    }
    if (value_len == 0)
    {
        return true;
    }
    return html_view_selector_range_eq_ci_ranges(entry->value,
                                                 entry->value_len,
                                                 value,
                                                 value_len);
}

static bool html_view_rule_trie_cache_attr_list_matches(const html_view_rule_trie_cache_entry_t *entry,
                                                        const html_node_t *node)
{
    if (!entry || !node || node->type != HTML_NODE_ELEMENT)
    {
        return false;
    }
    size_t node_attr_count = 0;
    for (const html_attr_t *attr = node->attrs; attr; attr = attr->next)
    {
        if (!attr->name || attr->name[0] == '\0')
        {
            continue;
        }
        if (html_view_rule_trie_cache_is_id_or_class(attr->name))
        {
            continue;
        }
        node_attr_count++;
    }
    if (node_attr_count != entry->attr_count)
    {
        return false;
    }
    if (node_attr_count == 0)
    {
        return true;
    }

    for (size_t i = 0; i < entry->attr_count; ++i)
    {
        bool found = false;
        for (const html_attr_t *attr = node->attrs; attr; attr = attr->next)
        {
            if (!attr->name || attr->name[0] == '\0')
            {
                continue;
            }
            if (html_view_rule_trie_cache_is_id_or_class(attr->name))
            {
                continue;
            }
            if (html_view_rule_trie_cache_attr_eq(&entry->attrs[i], attr))
            {
                found = true;
                break;
            }
        }
        if (!found)
        {
            return false;
        }
    }

    for (const html_attr_t *attr = node->attrs; attr; attr = attr->next)
    {
        if (!attr->name || attr->name[0] == '\0')
        {
            continue;
        }
        if (html_view_rule_trie_cache_is_id_or_class(attr->name))
        {
            continue;
        }
        bool found = false;
        for (size_t i = 0; i < entry->attr_count; ++i)
        {
            if (html_view_rule_trie_cache_attr_eq(&entry->attrs[i], attr))
            {
                found = true;
                break;
            }
        }
        if (!found)
        {
            return false;
        }
    }
    return true;
}

static bool html_view_rule_trie_cache_entry_matches(const html_view_rule_trie_cache_entry_t *entry,
                                                    const html_node_t *node,
                                                    html_view_pseudo_t pseudo,
                                                    bool require_parent)
{
    if (!entry || !entry->valid || !node || node->type != HTML_NODE_ELEMENT)
    {
        return false;
    }
    if (require_parent && entry->parent != node->parent)
    {
        return false;
    }
    if (entry->pseudo != pseudo)
    {
        return false;
    }
    const char *tag = node->name ? node->name : "";
    size_t tag_len = tag[0] != '\0' ? strlen(tag) : 0;
    if (entry->tag_len != tag_len)
    {
        return false;
    }
    if (tag_len > 0 &&
        !html_view_selector_range_eq_ci_ranges(entry->tag, entry->tag_len, tag, tag_len))
    {
        return false;
    }

    const char *id = html_attr_get(node, "id");
    size_t id_len = (id && id[0] != '\0') ? strlen(id) : 0;
    if (entry->id_len != id_len)
    {
        return false;
    }
    if (id_len > 0 &&
        !html_view_selector_range_eq_ci_ranges(entry->id, entry->id_len, id, id_len))
    {
        return false;
    }

    if (!html_view_rule_trie_cache_class_set_equals(entry, node))
    {
        return false;
    }
    return html_view_rule_trie_cache_attr_list_matches(entry, node);
}

static size_t html_view_rule_trie_cache_capacity(size_t rule_count)
{
    if (rule_count < HTML_VIEW_RULE_TRIE_CACHE_MIN_RULES)
    {
        return 0;
    }
    size_t cap = 32u;
    size_t target = rule_count * 2u;
    while (cap < target && cap < 4096u)
    {
        cap <<= 1u;
    }
    return cap;
}

static void html_view_rule_trie_cache_init(html_view_rule_trie_t *trie, size_t rule_count)
{
    if (!trie || !trie->cache_enabled)
    {
        return;
    }
    size_t cap = html_view_rule_trie_cache_capacity(rule_count);
    if (cap == 0)
    {
        return;
    }
    trie->cache.entries = (html_view_rule_trie_cache_entry_t *)calloc(cap, sizeof(*trie->cache.entries));
    if (!trie->cache.entries)
    {
        return;
    }
    trie->cache.entry_count = cap;
}

static const html_view_rule_trie_cache_entry_t *html_view_rule_trie_cache_lookup(const html_view_rule_trie_t *trie,
                                                                                 const html_node_t *node,
                                                                                 html_view_pseudo_t pseudo,
                                                                                 uint64_t *out_hash)
{
    if (out_hash)
    {
        *out_hash = 0;
    }
    if (!trie || !trie->cache_enabled || !trie->cache.entries || trie->cache.entry_count == 0 ||
        !node || node->type != HTML_NODE_ELEMENT)
    {
        return NULL;
    }
    uint64_t hash = html_view_rule_trie_cache_hash_node(node, pseudo, trie->cache_require_parent);
    if (out_hash)
    {
        *out_hash = hash;
    }
    size_t idx = (size_t)hash & (trie->cache.entry_count - 1u);
    html_view_rule_trie_cache_entry_t *entry = &trie->cache.entries[idx];
    if (!entry->valid || entry->hash != hash)
    {
        return NULL;
    }
    if (!html_view_rule_trie_cache_entry_matches(entry, node, pseudo, trie->cache_require_parent))
    {
        return NULL;
    }
    return entry;
}

static bool html_view_rule_trie_cache_store(const html_view_rule_trie_t *trie,
                                            const html_node_t *node,
                                            html_view_pseudo_t pseudo,
                                            uint64_t hash,
                                            css_rule_t **rules,
                                            size_t rule_count)
{
    if (!trie || !trie->cache_enabled || !trie->cache.entries || trie->cache.entry_count == 0 ||
        !node || node->type != HTML_NODE_ELEMENT)
    {
        return false;
    }
    size_t idx = (size_t)hash & (trie->cache.entry_count - 1u);
    html_view_rule_trie_cache_entry_t *entry = &trie->cache.entries[idx];
    html_view_rule_trie_cache_entry_clear(entry);
    if (!html_view_rule_trie_cache_entry_copy_key(entry, node, trie->cache_require_parent))
    {
        html_view_rule_trie_cache_entry_clear(entry);
        return false;
    }
    entry->hash = hash;
    entry->pseudo = pseudo;
    entry->rules = rules;
    entry->rule_count = rule_count;
    entry->valid = true;
    return true;
}

typedef struct html_view_rule_trie_bloom_stack
{
    html_view_rule_trie_node_t *node;
    bool expanded;
} html_view_rule_trie_bloom_stack_t;

static bool html_view_rule_trie_compute_left_chain_bloom(html_view_rule_trie_t *trie)
{
    if (!trie || trie->root_count == 0)
    {
        return true;
    }
    html_view_rule_trie_bloom_stack_t *stack = NULL;
    size_t stack_count = 0;
    size_t stack_cap = 0;
    for (size_t i = 0; i < trie->root_count; ++i)
    {
        if (!trie->roots[i])
        {
            continue;
        }
        if (stack_count == stack_cap)
        {
            size_t new_cap = stack_cap ? stack_cap * 2u : 32u;
            html_view_rule_trie_bloom_stack_t *next = (html_view_rule_trie_bloom_stack_t *)realloc(stack,
                                                                                                   new_cap * sizeof(*next));
            if (!next)
            {
                free(stack);
                return false;
            }
            stack = next;
            stack_cap = new_cap;
        }
        stack[stack_count++] = (html_view_rule_trie_bloom_stack_t){
            .node = trie->roots[i],
            .expanded = false,
        };
    }

    while (stack_count > 0)
    {
        html_view_rule_trie_bloom_stack_t entry = stack[--stack_count];
        html_view_rule_trie_node_t *node = entry.node;
        if (!node)
        {
            continue;
        }
        if (!entry.expanded)
        {
            if (stack_count == stack_cap)
            {
                size_t new_cap = stack_cap ? stack_cap * 2u : 32u;
                html_view_rule_trie_bloom_stack_t *next = (html_view_rule_trie_bloom_stack_t *)realloc(stack,
                                                                                                       new_cap * sizeof(*next));
                if (!next)
                {
                    free(stack);
                    return false;
                }
                stack = next;
                stack_cap = new_cap;
            }
            stack[stack_count++] = (html_view_rule_trie_bloom_stack_t){
                .node = node,
                .expanded = true,
            };
            for (size_t i = 0; i < node->child_count; ++i)
            {
                html_view_rule_trie_node_t *child = node->children[i];
                if (!child)
                {
                    continue;
                }
                if (stack_count == stack_cap)
                {
                    size_t new_cap = stack_cap ? stack_cap * 2u : 32u;
                    html_view_rule_trie_bloom_stack_t *next = (html_view_rule_trie_bloom_stack_t *)realloc(stack,
                                                                                                           new_cap * sizeof(*next));
                    if (!next)
                    {
                        free(stack);
                        return false;
                    }
                    stack = next;
                    stack_cap = new_cap;
                }
                stack[stack_count++] = (html_view_rule_trie_bloom_stack_t){
                    .node = child,
                    .expanded = false,
                };
            }
            continue;
        }

        bool has_path = false;
        web_bloom_t result = node->part_bloom;
        if (node->rule_count > 0)
        {
            result = node->part_bloom;
            has_path = true;
        }
        for (size_t i = 0; i < node->child_count; ++i)
        {
            html_view_rule_trie_node_t *child = node->children[i];
            if (!child)
            {
                continue;
            }
            web_bloom_t path = node->part_bloom;
            if (child->combinator == ' ' || child->combinator == '>')
            {
                html_view_bloom_or(&path, &child->left_chain_bloom);
            }
            if (!has_path)
            {
                result = path;
                has_path = true;
            }
            else
            {
                html_view_bloom_and(&result, &path);
            }
        }
        if (!has_path)
        {
            result = node->part_bloom;
        }
        node->left_chain_bloom = result;
    }

    free(stack);
    return true;
}

static void html_view_rule_trie_free(html_view_rule_trie_t *trie)
{
    if (!trie)
    {
        return;
    }
    html_view_rule_trie_node_t **stack = NULL;
    size_t stack_count = 0;
    size_t stack_cap = 0;
    for (size_t i = 0; i < trie->root_count; ++i)
    {
        if (!trie->roots[i])
        {
            continue;
        }
        if (stack_count == stack_cap)
        {
            size_t new_cap = stack_cap ? stack_cap * 2u : 32u;
            html_view_rule_trie_node_t **next = (html_view_rule_trie_node_t **)realloc(stack,
                                                                                       new_cap * sizeof(*next));
            if (!next)
            {
                break;
            }
            stack = next;
            stack_cap = new_cap;
        }
        stack[stack_count++] = trie->roots[i];
    }
    while (stack_count > 0)
    {
        html_view_rule_trie_node_t *node = stack[--stack_count];
        if (node->children && node->child_count > 0)
        {
            for (size_t i = 0; i < node->child_count; ++i)
            {
                if (node->children[i])
                {
                    if (stack_count == stack_cap)
                    {
                        size_t new_cap = stack_cap ? stack_cap * 2u : 32u;
                        html_view_rule_trie_node_t **next = (html_view_rule_trie_node_t **)realloc(stack,
                                                                                                   new_cap * sizeof(*next));
                        if (!next)
                        {
                            break;
                        }
                        stack = next;
                        stack_cap = new_cap;
                    }
                    if (stack_count < stack_cap)
                    {
                        stack[stack_count++] = node->children[i];
                    }
                }
            }
        }
        free(node->children);
        free(node->rules);
        free(node);
    }
    free(stack);
    if (trie->cache.entries)
    {
        for (size_t i = 0; i < trie->cache.entry_count; ++i)
        {
            html_view_rule_trie_cache_entry_clear(&trie->cache.entries[i]);
        }
        free(trie->cache.entries);
    }
    free(trie->roots);
    free(trie->fallback_rules);
    free(trie);
}

static bool html_view_rule_trie_add_rule(html_view_rule_trie_t *trie,
                                         css_rule_t *rule,
                                         const css_selector_cache_t *cache)
{
    if (!trie || !rule || !cache || !cache->compiled || !cache->compiled_parts ||
        cache->compiled_count != cache->count || cache->count == 0)
    {
        return false;
    }
    size_t right_idx = cache->compiled_count - 1;
    html_view_rule_trie_node_t *node = html_view_rule_trie_get_root(trie,
                                                                    &cache->compiled_parts[right_idx],
                                                                    &cache->parts[right_idx],
                                                                    rule->selector);
    if (!node)
    {
        return false;
    }
    for (size_t idx = right_idx; idx > 0; --idx)
    {
        const css_selector_compiled_part_t *left = &cache->compiled_parts[idx - 1];
        const css_selector_part_t *left_raw = &cache->parts[idx - 1];
        char comb = left_raw->combinator;
        node = html_view_rule_trie_get_child(node, left, left_raw, rule->selector, comb);
        if (!node)
        {
            return false;
        }
    }
    return html_view_rule_trie_node_add_rule(node, rule);
}

static void html_view_rule_trie_update_cache_mode(html_view_rule_trie_t *trie,
                                                  const css_selector_cache_t *cache)
{
    if (!trie || !cache || !trie->cache_enabled || cache->count == 0)
    {
        return;
    }
    for (size_t i = 0; i < cache->count; ++i)
    {
        char comb = cache->parts[i].combinator;
        if (comb == '+' || comb == '~')
        {
            trie->cache_enabled = false;
            return;
        }
        if (comb == '>' || comb == ' ')
        {
            trie->cache_require_parent = true;
        }
    }
}

static html_view_rule_trie_t *html_view_rule_trie_build(css_rule_t **rules, size_t rule_count)
{
    if (!rules || rule_count < HTML_VIEW_RULE_TRIE_MIN_RULES)
    {
        return NULL;
    }
    html_view_rule_trie_t *trie = (html_view_rule_trie_t *)calloc(1, sizeof(*trie));
    if (!trie)
    {
        return NULL;
    }
    trie->cache_enabled = true;
    size_t compiled_rules = 0;
    for (size_t i = 0; i < rule_count; ++i)
    {
        css_rule_t *rule = rules[i];
        if (!rule || !rule->selector)
        {
            continue;
        }
        if (!rule->selector_cache)
        {
            if (!html_view_rule_trie_fallback_push(trie, rule))
            {
                html_view_rule_trie_free(trie);
                return NULL;
            }
            continue;
        }
        css_selector_cache_t *cache = rule->selector_cache;
        if (!cache->compiled || !cache->compiled_parts || cache->compiled_count != cache->count ||
            cache->count == 0)
        {
            if (!html_view_rule_trie_fallback_push(trie, rule))
            {
                html_view_rule_trie_free(trie);
                return NULL;
            }
            continue;
        }
        html_view_rule_trie_update_cache_mode(trie, cache);
        if (!html_view_rule_trie_add_rule(trie, rule, cache))
        {
            html_view_rule_trie_free(trie);
            return NULL;
        }
        compiled_rules++;
    }
    if (compiled_rules == 0)
    {
        html_view_rule_trie_free(trie);
        return NULL;
    }
    trie->rule_count = compiled_rules;
    html_view_rule_trie_compute_left_chain_bloom(trie);
    html_view_rule_trie_cache_init(trie, compiled_rules);
    return trie;
}

typedef struct
{
    const html_view_rule_trie_node_t *node;
    const html_node_t *dom;
} html_view_rule_trie_stack_t;

static bool html_view_rule_trie_stack_push(html_view_rule_trie_stack_t **stack,
                                           size_t *count,
                                           size_t *cap,
                                           const html_view_rule_trie_node_t *node,
                                           const html_node_t *dom)
{
    if (!stack || !count || !cap || !node || !dom)
    {
        return false;
    }
    if (*count == *cap)
    {
        size_t new_cap = *cap ? (*cap * 2u) : 32u;
        html_view_rule_trie_stack_t *next = (html_view_rule_trie_stack_t *)realloc(*stack,
                                                                                   new_cap * sizeof(*next));
        if (!next)
        {
            return false;
        }
        *stack = next;
        *cap = new_cap;
    }
    (*stack)[(*count)++] = (html_view_rule_trie_stack_t){
        .node = node,
        .dom = dom,
    };
    return true;
}

static bool html_view_rule_trie_append_rules(css_rule_t ***rules,
                                             size_t *rule_count,
                                             size_t *rule_cap,
                                             css_rule_t *const *append_rules,
                                             size_t append_count)
{
    if (!rules || !rule_count || !rule_cap || !append_rules || append_count == 0)
    {
        return true;
    }
    size_t new_count = *rule_count + append_count;
    if (new_count < *rule_count)
    {
        return false;
    }
    if (new_count > *rule_cap)
    {
        size_t new_cap = *rule_cap ? *rule_cap : 8u;
        while (new_cap < new_count)
        {
            new_cap *= 2u;
        }
        css_rule_t **next = (css_rule_t **)realloc(*rules, new_cap * sizeof(*next));
        if (!next)
        {
            return false;
        }
        *rules = next;
        *rule_cap = new_cap;
    }
    memcpy(*rules + *rule_count, append_rules, append_count * sizeof(*append_rules));
    *rule_count = new_count;
    return true;
}

static void html_view_rule_trie_sort_rules(css_rule_t **rules, size_t count)
{
    if (!rules || count < 2)
    {
        return;
    }
    for (size_t i = 1; i < count; ++i)
    {
        css_rule_t *key = rules[i];
        size_t j = i;
        while (j > 0)
        {
            if (html_view_rule_compare(rules[j - 1], key) <= 0)
            {
                break;
            }
            rules[j] = rules[j - 1];
            --j;
        }
        rules[j] = key;
    }
}

static uint32_t g_html_view_rule_trie_stamp = 1u;

static bool html_view_rule_trie_collect_matches(const html_view_rule_trie_t *trie,
                                                const html_node_t *node,
                                                html_view_pseudo_t pseudo,
                                                css_rule_t ***out_rules,
                                                size_t *out_count)
{
    if (out_rules)
    {
        *out_rules = NULL;
    }
    if (out_count)
    {
        *out_count = 0;
    }
    if (!trie || !node || node->type != HTML_NODE_ELEMENT || trie->root_count == 0)
    {
        return true;
    }

    uint32_t stamp = g_html_view_rule_trie_stamp++;
    if (stamp == 0)
    {
        stamp = g_html_view_rule_trie_stamp++;
    }

    html_view_rule_trie_stack_t *stack = NULL;
    size_t stack_count = 0;
    size_t stack_cap = 0;
    for (size_t i = 0; i < trie->root_count; ++i)
    {
        const html_view_rule_trie_node_t *root = trie->roots[i];
        if (!root)
        {
            continue;
        }
        if (html_view_selector_part_matches_compiled(root->part,
                                                     root->raw_part,
                                                     root->selector,
                                                     node,
                                                     pseudo))
        {
            if (!html_view_rule_trie_stack_push(&stack, &stack_count, &stack_cap, root, node))
            {
                free(stack);
                return false;
            }
        }
    }

    css_rule_t **matched = NULL;
    size_t matched_count = 0;
    size_t matched_cap = 0;

    while (stack_count > 0)
    {
        html_view_rule_trie_stack_t entry = stack[--stack_count];
        const html_view_rule_trie_node_t *cur = entry.node;
        const html_node_t *cur_node = entry.dom;
        if (cur->rule_count > 0 && cur->match_stamp != stamp)
        {
            ((html_view_rule_trie_node_t *)cur)->match_stamp = stamp;
            if (!html_view_rule_trie_append_rules(&matched,
                                                  &matched_count,
                                                  &matched_cap,
                                                  cur->rules,
                                                  cur->rule_count))
            {
                free(stack);
                free(matched);
                return false;
            }
        }

        if (cur->child_count == 0)
        {
            continue;
        }

        for (size_t i = 0; i < cur->child_count; ++i)
        {
            const html_view_rule_trie_node_t *child = cur->children[i];
            if (!child)
            {
                continue;
            }
            char comb = child->combinator;
            if (comb == '>')
            {
                const html_node_t *p = cur_node->parent;
                if (p && html_view_selector_part_matches_compiled(child->part,
                                                                  child->raw_part,
                                                                  child->selector,
                                                                  p,
                                                                  HTML_VIEW_PSEUDO_NONE))
                {
                    if (!html_view_rule_trie_stack_push(&stack, &stack_count, &stack_cap, child, p))
                    {
                        free(stack);
                        free(matched);
                        return false;
                    }
                }
                continue;
            }
            if (comb == '+')
            {
                const html_node_t *p = html_view_prev_element_sibling(cur_node);
                if (p && html_view_selector_part_matches_compiled(child->part,
                                                                  child->raw_part,
                                                                  child->selector,
                                                                  p,
                                                                  HTML_VIEW_PSEUDO_NONE))
                {
                    if (!html_view_rule_trie_stack_push(&stack, &stack_count, &stack_cap, child, p))
                    {
                        free(stack);
                        free(matched);
                        return false;
                    }
                }
                continue;
            }
            if (comb == '~')
            {
                for (const html_node_t *p = html_view_prev_element_sibling(cur_node);
                     p;
                     p = html_view_prev_element_sibling(p))
                {
                    if (html_view_selector_part_matches_compiled(child->part,
                                                                  child->raw_part,
                                                                  child->selector,
                                                                  p,
                                                                  HTML_VIEW_PSEUDO_NONE))
                    {
                        if (!html_view_rule_trie_stack_push(&stack, &stack_count, &stack_cap, child, p))
                        {
                            free(stack);
                            free(matched);
                            return false;
                        }
                    }
                }
                continue;
            }

            const html_node_t *ancestor_start = cur_node->parent;
            if (!ancestor_start)
            {
                continue;
            }
            bool has_chain_bloom = !html_view_bloom_is_zero(&child->left_chain_bloom);
            if (has_chain_bloom && !html_view_bloom_is_zero(&ancestor_start->ancestor_bloom))
            {
                if (!html_view_bloom_contains(&ancestor_start->ancestor_bloom, &child->left_chain_bloom))
                {
                    continue;
                }
            }
            for (const html_node_t *p = ancestor_start; p; p = p->parent)
            {
                if (html_view_selector_part_matches_compiled(child->part,
                                                              child->raw_part,
                                                              child->selector,
                                                              p,
                                                              HTML_VIEW_PSEUDO_NONE))
                {
                    if (!html_view_rule_trie_stack_push(&stack, &stack_count, &stack_cap, child, p))
                    {
                        free(stack);
                        free(matched);
                        return false;
                    }
                }
            }
        }
    }

    free(stack);

    if (matched_count > 1)
    {
        html_view_rule_trie_sort_rules(matched, matched_count);
        size_t out_idx = 1;
        uint32_t last_order = html_view_rule_order(matched[0]);
        for (size_t i = 1; i < matched_count; ++i)
        {
            uint32_t order = html_view_rule_order(matched[i]);
            if (order != last_order)
            {
                matched[out_idx++] = matched[i];
                last_order = order;
            }
        }
        matched_count = out_idx;
    }

    if (out_rules)
    {
        *out_rules = matched;
    }
    else
    {
        free(matched);
    }
    if (out_count)
    {
        *out_count = matched_count;
    }
    return true;
}

static void html_view_rule_index_free(html_view_rule_index_t *index)
{
    if (!index)
    {
        return;
    }
    html_view_rule_trie_free(index->global_trie);
    for (size_t i = 0; i < index->tag_bucket_count; ++i)
    {
        html_view_rule_bucket_t *bucket = &index->tag_buckets[i];
        html_view_rule_trie_free(bucket->trie);
        for (size_t j = 0; j < bucket->parent_count; ++j)
        {
            html_view_rule_bucket_t *parent = &bucket->parent_buckets[j];
            html_view_rule_trie_free(parent->trie);
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
        html_view_rule_trie_free(bucket->trie);
        for (size_t j = 0; j < bucket->parent_count; ++j)
        {
            html_view_rule_bucket_t *parent = &bucket->parent_buckets[j];
            html_view_rule_trie_free(parent->trie);
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
        html_view_rule_trie_free(bucket->trie);
        for (size_t j = 0; j < bucket->parent_count; ++j)
        {
            html_view_rule_bucket_t *parent = &bucket->parent_buckets[j];
            html_view_rule_trie_free(parent->trie);
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
        html_view_rule_trie_free(bucket->trie);
        for (size_t j = 0; j < bucket->parent_count; ++j)
        {
            html_view_rule_bucket_t *parent = &bucket->parent_buckets[j];
            html_view_rule_trie_free(parent->trie);
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
        html_view_rule_trie_free(bucket->trie);
        for (size_t j = 0; j < bucket->parent_count; ++j)
        {
            html_view_rule_bucket_t *parent = &bucket->parent_buckets[j];
            html_view_rule_trie_free(parent->trie);
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
    html_view_style_cache_mark_dirty(priv);
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

    char *norm_key = NULL;
    const char *lookup_key = key;
    size_t lookup_len = len;
    if (unescape)
    {
        norm_key = html_view_strdup_lower_unescaped_range(key, len);
        if (!norm_key)
        {
            return NULL;
        }
        lookup_key = norm_key;
        lookup_len = strlen(norm_key);
    }

    html_view_rule_bucket_t *bucket = html_view_rule_index_find_bucket_list(*buckets,
                                                                            *bucket_count,
                                                                            lookup_key,
                                                                            lookup_len);
    if (bucket)
    {
        free(norm_key);
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

    char *key_copy = NULL;
    if (unescape)
    {
        key_copy = norm_key;
        norm_key = NULL;
    }
    else
    {
        key_copy = html_view_strdup_lower_range(key, len);
    }
    if (!key_copy)
    {
        free(norm_key);
        return NULL;
    }

    bucket = &(*buckets)[(*bucket_count)++];
    memset(bucket, 0, sizeof(*bucket));
    bucket->tag = key_copy;
    bucket->tag_len = strlen(key_copy);
    free(norm_key);
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

static void html_view_rule_index_build_bucket_tries(html_view_rule_bucket_t *buckets,
                                                    size_t bucket_count)
{
    if (!buckets || bucket_count == 0)
    {
        return;
    }
    for (size_t i = 0; i < bucket_count; ++i)
    {
        html_view_rule_bucket_t *bucket = &buckets[i];
        bucket->trie = html_view_rule_trie_build(bucket->rules, bucket->count);
        for (size_t j = 0; j < bucket->parent_count; ++j)
        {
            html_view_rule_bucket_t *parent = &bucket->parent_buckets[j];
            parent->trie = html_view_rule_trie_build(parent->rules, parent->count);
        }
    }
}

static void html_view_rule_index_build_tries(html_view_rule_index_t *index)
{
    if (!index)
    {
        return;
    }
    index->global_trie = html_view_rule_trie_build(index->global_rules, index->global_count);
    html_view_rule_index_build_bucket_tries(index->tag_buckets, index->tag_bucket_count);
    html_view_rule_index_build_bucket_tries(index->class_buckets, index->class_bucket_count);
    html_view_rule_index_build_bucket_tries(index->scope_class_buckets, index->scope_class_bucket_count);
    html_view_rule_index_build_bucket_tries(index->id_buckets, index->id_bucket_count);
    html_view_rule_index_build_bucket_tries(index->attr_buckets, index->attr_bucket_count);
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
    html_view_rule_index_build_tries(index);
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
    css_rule_t **rules;
    size_t count;
    const void *key;
    bool matched;
    bool owned;
} html_view_rule_list_t;

typedef enum
{
    HTML_VIEW_RULE_PHASE_NORMAL = 0,
    HTML_VIEW_RULE_PHASE_IMPORTANT = 1,
} html_view_rule_phase_t;

static uint32_t html_view_rule_order(const css_rule_t *rule)
{
    if (!rule || !rule->selector_cache)
    {
        return 0xffffffffu;
    }
    return rule->selector_cache->order;
}

static uint32_t html_view_rule_specificity(const css_rule_t *rule)
{
    if (!rule || !rule->selector_cache)
    {
        return 0;
    }
    return rule->selector_cache->specificity;
}

static int html_view_rule_compare(const css_rule_t *left, const css_rule_t *right)
{
    uint32_t left_spec = html_view_rule_specificity(left);
    uint32_t right_spec = html_view_rule_specificity(right);
    if (left_spec != right_spec)
    {
        return left_spec < right_spec ? -1 : 1;
    }
    uint32_t left_order = html_view_rule_order(left);
    uint32_t right_order = html_view_rule_order(right);
    if (left_order != right_order)
    {
        return left_order < right_order ? -1 : 1;
    }
    return 0;
}

static bool html_view_rule_list_has_key(const html_view_rule_list_t *lists,
                                        size_t list_count,
                                        const void *key,
                                        bool matched)
{
    if (!lists || list_count == 0)
    {
        return false;
    }
    for (size_t i = 0; i < list_count; ++i)
    {
        if (lists[i].key == key && lists[i].matched == matched)
        {
            return true;
        }
    }
    return false;
}

static bool html_view_rule_matches(css_rule_t *rule,
                                   const html_node_t *node,
                                   html_view_pseudo_t pseudo)
{
    if (!node || !rule || !rule->selector)
    {
        return false;
    }
    css_selector_cache_t *cache = NULL;
    bool fallback = false;
    if (!html_view_selector_cache_precheck(rule, node, pseudo, &cache, &fallback))
    {
        return false;
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
    else if (cache->self_simple)
    {
        match = true;
    }
    else if (cache->compiled)
    {
        match = html_view_selector_matches_compiled(cache, rule->selector, node, pseudo);
    }
    else
    {
        match = html_view_selector_matches_parts(cache->parts, cache->count, rule->selector, node, pseudo);
    }
    return match;
}

static void html_view_style_merge_rule(css_style_t *out, const css_style_t *src)
{
    if (!out || !src)
    {
        return;
    }
    if (src->has_background_image)
    {
        if (out->background_image_owned && out->background_image)
        {
            free((void *)out->background_image);
        }
        out->background_image_owned = false;
    }
    if (src->has_content)
    {
        if (out->content_owned && out->content)
        {
            free((void *)out->content);
        }
        out->content_owned = false;
    }
    css_style_merge(out, src);
}



static void html_view_apply_rule_list(css_style_t *out,
                                      const html_node_t *node,
                                      html_view_pseudo_t pseudo,
                                      css_rule_t *const *rules,
                                      size_t rule_count,
                                      html_view_rule_phase_t phase)
{
    if (!out || !node || !rules)
    {
        return;
    }

    for (size_t i = 0; i < rule_count; ++i)
    {
        css_rule_t *rule = rules[i];
        if (!rule)
        {
            continue;
        }
        if (phase == HTML_VIEW_RULE_PHASE_IMPORTANT && !rule->has_important)
        {
            continue;
        }
        if (html_view_rule_matches(rule, node, pseudo))
        {
            if (phase == HTML_VIEW_RULE_PHASE_IMPORTANT)
            {
                html_view_style_merge_rule(out, &rule->important_style);
            }
            else
            {
                html_view_style_merge_rule(out, &rule->style);
            }
        }
    }
}

static void html_view_apply_rule_list_matched(css_style_t *out,
                                              css_rule_t *const *rules,
                                              size_t rule_count,
                                              html_view_rule_phase_t phase)
{
    if (!out || !rules)
    {
        return;
    }
    for (size_t i = 0; i < rule_count; ++i)
    {
        if (!rules[i])
        {
            continue;
        }
        if (phase == HTML_VIEW_RULE_PHASE_IMPORTANT)
        {
            if (rules[i]->has_important)
            {
                html_view_style_merge_rule(out, &rules[i]->important_style);
            }
        }
        else
        {
            html_view_style_merge_rule(out, &rules[i]->style);
        }
    }
}

static bool html_view_rule_list_add_unique(html_view_rule_list_t **lists,
                                           size_t *list_count,
                                           size_t *list_cap,
                                           css_rule_t **rules,
                                           size_t rule_count,
                                           const void *key,
                                           bool matched,
                                           bool owned)
{
    if (!lists || !list_count || !list_cap || !rules || rule_count == 0)
    {
        return true;
    }
    if (html_view_rule_list_has_key(*lists, *list_count, key, matched))
    {
        return true;
    }
    if (*list_count == *list_cap)
    {
        size_t new_cap = *list_cap ? (*list_cap * 2u) : 16u;
        html_view_rule_list_t *next = (html_view_rule_list_t *)realloc(*lists,
                                                                       new_cap * sizeof(*next));
        if (!next)
        {
            return false;
        }
        *lists = next;
        *list_cap = new_cap;
    }
    (*lists)[(*list_count)++] = (html_view_rule_list_t){
        .rules = rules,
        .count = rule_count,
        .key = key,
        .matched = matched,
        .owned = owned,
    };
    return true;
}

static bool html_view_rule_lists_have_important(const html_view_rule_list_t *lists,
                                                size_t list_count)
{
    if (!lists || list_count == 0)
    {
        return false;
    }
    for (size_t i = 0; i < list_count; ++i)
    {
        const html_view_rule_list_t *list = &lists[i];
        if (!list->rules || list->count == 0)
        {
            continue;
        }
        for (size_t j = 0; j < list->count; ++j)
        {
            css_rule_t *rule = list->rules[j];
            if (rule && rule->has_important)
            {
                return true;
            }
        }
    }
    return false;
}

static void html_view_apply_rule_lists(css_style_t *out,
                                       const html_node_t *node,
                                       html_view_pseudo_t pseudo,
                                       const html_view_rule_list_t *lists,
                                       size_t list_count,
                                       html_view_rule_phase_t phase)
{
    if (!out || !node || !lists || list_count == 0)
    {
        return;
    }
    if (phase == HTML_VIEW_RULE_PHASE_IMPORTANT &&
        !html_view_rule_lists_have_important(lists, list_count))
    {
        return;
    }
    if (list_count == 1)
    {
        if (lists[0].matched)
        {
            html_view_apply_rule_list_matched(out, lists[0].rules, lists[0].count, phase);
        }
        else
        {
            html_view_apply_rule_list(out, node, pseudo, lists[0].rules, lists[0].count, phase);
        }
        return;
    }

    size_t *positions = (size_t *)calloc(list_count, sizeof(*positions));
    if (!positions)
    {
        for (size_t i = 0; i < list_count; ++i)
        {
            if (lists[i].matched)
            {
                html_view_apply_rule_list_matched(out, lists[i].rules, lists[i].count, phase);
            }
            else
            {
                html_view_apply_rule_list(out, node, pseudo, lists[i].rules, lists[i].count, phase);
            }
        }
        return;
    }

    for (;;)
    {
        size_t best = (size_t)-1;
        css_rule_t *best_rule = NULL;
        for (size_t i = 0; i < list_count; ++i)
        {
            size_t pos = positions[i];
            if (pos >= lists[i].count)
            {
                continue;
            }
            css_rule_t *rule = lists[i].rules[pos];
            if (!rule)
            {
                continue;
            }
            if (!best_rule || html_view_rule_compare(rule, best_rule) < 0)
            {
                best = i;
                best_rule = rule;
            }
        }
        if (best == (size_t)-1)
        {
            break;
        }
        css_rule_t *rule = lists[best].rules[positions[best]++];
        if (phase == HTML_VIEW_RULE_PHASE_IMPORTANT && (!rule || !rule->has_important))
        {
            continue;
        }
        if (lists[best].matched)
        {
            if (phase == HTML_VIEW_RULE_PHASE_IMPORTANT)
            {
                html_view_style_merge_rule(out, &rule->important_style);
            }
            else
            {
                html_view_style_merge_rule(out, &rule->style);
            }
        }
        else
        {
            if (html_view_rule_matches(rule, node, pseudo))
            {
                if (phase == HTML_VIEW_RULE_PHASE_IMPORTANT)
                {
                    html_view_style_merge_rule(out, &rule->important_style);
                }
                else
                {
                    html_view_style_merge_rule(out, &rule->style);
                }
            }
        }
    }

    free(positions);
}

static bool html_view_rule_trie_add_matches(html_view_rule_list_t **lists,
                                            size_t *list_count,
                                            size_t *list_cap,
                                            const html_view_rule_trie_t *trie,
                                            const html_node_t *node,
                                            html_view_pseudo_t pseudo,
                                            const void *key)
{
    if (!trie)
    {
        return true;
    }
    if (trie->fallback_count > 0 &&
        !html_view_rule_list_has_key(*lists, *list_count, key, false))
    {
        if (!html_view_rule_list_add_unique(lists,
                                            list_count,
                                            list_cap,
                                            trie->fallback_rules,
                                            trie->fallback_count,
                                            key,
                                            false,
                                            false))
        {
            return false;
        }
    }
    if (html_view_rule_list_has_key(*lists, *list_count, key, true))
    {
        return true;
    }

    uint64_t cache_hash = 0;
    const html_view_rule_trie_cache_entry_t *cached = html_view_rule_trie_cache_lookup(trie,
                                                                                       node,
                                                                                       pseudo,
                                                                                       &cache_hash);
    if (cached)
    {
        if (cached->rule_count == 0)
        {
            return true;
        }
        return html_view_rule_list_add_unique(lists,
                                              list_count,
                                              list_cap,
                                              cached->rules,
                                              cached->rule_count,
                                              key,
                                              true,
                                              false);
    }

    css_rule_t **matched = NULL;
    size_t matched_count = 0;
    if (!html_view_rule_trie_collect_matches(trie, node, pseudo, &matched, &matched_count))
    {
        free(matched);
        return false;
    }
    bool cached_store = false;
    if (trie->cache.entries)
    {
        cached_store = html_view_rule_trie_cache_store(trie,
                                                       node,
                                                       pseudo,
                                                       cache_hash,
                                                       matched,
                                                       matched_count);
    }
    if (matched_count == 0)
    {
        if (!cached_store)
        {
            free(matched);
        }
        return true;
    }
    if (!html_view_rule_list_add_unique(lists,
                                        list_count,
                                        list_cap,
                                        matched,
                                        matched_count,
                                        key,
                                        true,
                                        !cached_store))
    {
        if (!cached_store)
        {
            free(matched);
        }
        return false;
    }
    return true;
}

static void html_view_rule_lists_release(html_view_rule_list_t *lists, size_t list_count)
{
    if (!lists)
    {
        return;
    }
    for (size_t i = 0; i < list_count; ++i)
    {
        if (lists[i].owned)
        {
            free(lists[i].rules);
        }
    }
    free(lists);
}

static bool html_view_collect_indexed_rule_lists(const html_node_t *node,
                                                 html_view_pseudo_t pseudo,
                                                 const html_view_rule_index_t *index,
                                                 html_view_rule_list_t **lists_out,
                                                 size_t *list_count_out)
{
    if (!node || !index || !lists_out || !list_count_out)
    {
        return false;
    }

    const char *id = html_attr_get(node, "id");
    size_t id_len = (id && id[0] != '\0') ? strlen(id) : 0;

    const char *classes_value = NULL;
    size_t class_token_count = 0;
    const html_class_token_t *class_tokens = html_view_node_class_tokens(node,
                                                                         &class_token_count,
                                                                         &classes_value);

    const html_node_t *parent = (node && node->type == HTML_NODE_ELEMENT) ? node->parent : NULL;
    const char *parent_classes_value = NULL;
    size_t parent_class_token_count = 0;
    const html_class_token_t *parent_tokens = NULL;
    if (parent && parent->type == HTML_NODE_ELEMENT)
    {
        parent_tokens = html_view_node_class_tokens(parent,
                                                    &parent_class_token_count,
                                                    &parent_classes_value);
    }

    uint8_t pseudo_mask = html_view_pseudo_mask(pseudo);
    bool wants_pseudo = (pseudo != HTML_VIEW_PSEUDO_NONE);

    html_view_rule_list_t *lists = NULL;
    size_t list_count = 0;
    size_t list_cap = 0;
    if (index->global_count > 0 &&
        (!wants_pseudo || (index->global_pseudo_mask & pseudo_mask) != 0))
    {
        if (index->global_trie)
        {
            if (!html_view_rule_trie_add_matches(&lists,
                                                 &list_count,
                                                 &list_cap,
                                                 index->global_trie,
                                                 node,
                                                 pseudo,
                                                 index))
            {
                goto fallback;
            }
        }
        else
        {
            if (!html_view_rule_list_add_unique(&lists,
                                                &list_count,
                                                &list_cap,
                                                index->global_rules,
                                                index->global_count,
                                                index,
                                                false,
                                                false))
            {
                goto fallback;
            }
        }
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
            if (bucket->trie)
            {
                if (!html_view_rule_trie_add_matches(&lists,
                                                     &list_count,
                                                     &list_cap,
                                                     bucket->trie,
                                                     node,
                                                     pseudo,
                                                     bucket))
                {
                    goto fallback;
                }
            }
            else
            {
                if (!html_view_rule_list_add_unique(&lists,
                                                    &list_count,
                                                    &list_cap,
                                                    bucket->rules,
                                                    bucket->count,
                                                    bucket,
                                                    false,
                                                    false))
                {
                    goto fallback;
                }
            }
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
            if (bucket->trie)
            {
                if (!html_view_rule_trie_add_matches(&lists,
                                                     &list_count,
                                                     &list_cap,
                                                     bucket->trie,
                                                     node,
                                                     pseudo,
                                                     bucket))
                {
                    goto fallback;
                }
            }
            else
            {
                if (!html_view_rule_list_add_unique(&lists,
                                                    &list_count,
                                                    &list_cap,
                                                    bucket->rules,
                                                    bucket->count,
                                                    bucket,
                                                    false,
                                                    false))
                {
                    goto fallback;
                }
            }
        }
    }

    if (node && node->type == HTML_NODE_ELEMENT)
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
                if (bucket->trie)
                {
                    if (!html_view_rule_trie_add_matches(&lists,
                                                         &list_count,
                                                         &list_cap,
                                                         bucket->trie,
                                                         node,
                                                         pseudo,
                                                         bucket))
                    {
                        goto fallback;
                    }
                }
                else
                {
                    if (!html_view_rule_list_add_unique(&lists,
                                                        &list_count,
                                                        &list_cap,
                                                        bucket->rules,
                                                        bucket->count,
                                                        bucket,
                                                        false,
                                                        false))
                    {
                        goto fallback;
                    }
                }
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
                if (bucket->trie)
                {
                    if (!html_view_rule_trie_add_matches(&lists,
                                                         &list_count,
                                                         &list_cap,
                                                         bucket->trie,
                                                         node,
                                                         pseudo,
                                                         bucket))
                    {
                        goto fallback;
                    }
                }
                else
                {
                    if (!html_view_rule_list_add_unique(&lists,
                                                        &list_count,
                                                        &list_cap,
                                                        bucket->rules,
                                                        bucket->count,
                                                        bucket,
                                                        false,
                                                        false))
                    {
                        goto fallback;
                    }
                }
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
                            if (parent_bucket->trie)
                            {
                                if (!html_view_rule_trie_add_matches(&lists,
                                                                     &list_count,
                                                                     &list_cap,
                                                                     parent_bucket->trie,
                                                                     node,
                                                                     pseudo,
                                                                     parent_bucket))
                                {
                                    goto fallback;
                                }
                            }
                            else
                            {
                                if (!html_view_rule_list_add_unique(&lists,
                                                                    &list_count,
                                                                    &list_cap,
                                                                    parent_bucket->rules,
                                                                    parent_bucket->count,
                                                                    parent_bucket,
                                                                    false,
                                                                    false))
                                {
                                    goto fallback;
                                }
                            }
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
                            if (parent_bucket->trie)
                            {
                                if (!html_view_rule_trie_add_matches(&lists,
                                                                     &list_count,
                                                                     &list_cap,
                                                                     parent_bucket->trie,
                                                                     node,
                                                                     pseudo,
                                                                     parent_bucket))
                                {
                                    goto fallback;
                                }
                            }
                            else
                            {
                                if (!html_view_rule_list_add_unique(&lists,
                                                                    &list_count,
                                                                    &list_cap,
                                                                    parent_bucket->rules,
                                                                    parent_bucket->count,
                                                                    parent_bucket,
                                                                    false,
                                                                    false))
                                {
                                    goto fallback;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (index->scope_class_bucket_count > 0 && parent)
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
                        if (bucket->trie)
                        {
                            if (!html_view_rule_trie_add_matches(&lists,
                                                                 &list_count,
                                                                 &list_cap,
                                                                 bucket->trie,
                                                                 node,
                                                                 pseudo,
                                                                 bucket))
                            {
                                goto fallback;
                            }
                        }
                        else
                        {
                            if (!html_view_rule_list_add_unique(&lists,
                                                                &list_count,
                                                                &list_cap,
                                                                bucket->rules,
                                                                bucket->count,
                                                                bucket,
                                                                false,
                                                                false))
                            {
                                goto fallback;
                            }
                        }
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
                        if (bucket->trie)
                        {
                            if (!html_view_rule_trie_add_matches(&lists,
                                                                 &list_count,
                                                                 &list_cap,
                                                                 bucket->trie,
                                                                 node,
                                                                 pseudo,
                                                                 bucket))
                            {
                                goto fallback;
                            }
                        }
                        else
                        {
                            if (!html_view_rule_list_add_unique(&lists,
                                                                &list_count,
                                                                &list_cap,
                                                                bucket->rules,
                                                                bucket->count,
                                                                bucket,
                                                                false,
                                                                false))
                            {
                                goto fallback;
                            }
                        }
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
                if (bucket->trie)
                {
                    if (!html_view_rule_trie_add_matches(&lists,
                                                         &list_count,
                                                         &list_cap,
                                                         bucket->trie,
                                                         node,
                                                         pseudo,
                                                         bucket))
                    {
                        goto fallback;
                    }
                }
                else
                {
                    if (!html_view_rule_list_add_unique(&lists,
                                                        &list_count,
                                                        &list_cap,
                                                        bucket->rules,
                                                        bucket->count,
                                                        bucket,
                                                        false,
                                                        false))
                    {
                        goto fallback;
                    }
                }
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
                            if (parent_bucket->trie)
                            {
                                if (!html_view_rule_trie_add_matches(&lists,
                                                                     &list_count,
                                                                     &list_cap,
                                                                     parent_bucket->trie,
                                                                     node,
                                                                     pseudo,
                                                                     parent_bucket))
                                {
                                    goto fallback;
                                }
                            }
                            else
                            {
                                if (!html_view_rule_list_add_unique(&lists,
                                                                    &list_count,
                                                                    &list_cap,
                                                                    parent_bucket->rules,
                                                                    parent_bucket->count,
                                                                    parent_bucket,
                                                                    false,
                                                                    false))
                                {
                                    goto fallback;
                                }
                            }
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
                            if (parent_bucket->trie)
                            {
                                if (!html_view_rule_trie_add_matches(&lists,
                                                                     &list_count,
                                                                     &list_cap,
                                                                     parent_bucket->trie,
                                                                     node,
                                                                     pseudo,
                                                                     parent_bucket))
                                {
                                    goto fallback;
                                }
                            }
                            else
                            {
                                if (!html_view_rule_list_add_unique(&lists,
                                                                    &list_count,
                                                                    &list_cap,
                                                                    parent_bucket->rules,
                                                                    parent_bucket->count,
                                                                    parent_bucket,
                                                                    false,
                                                                    false))
                                {
                                    goto fallback;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    *lists_out = lists;
    *list_count_out = list_count;
    return true;

fallback:
    html_view_rule_lists_release(lists, list_count);
    return false;
}

static void html_view_apply_rule_sheet_phase(css_style_t *out,
                                             const html_node_t *node,
                                             html_view_pseudo_t pseudo,
                                             css_rule_t *rules,
                                             html_view_rule_phase_t phase)
{
    if (!out || !node || !rules)
    {
        return;
    }
    for (css_rule_t *rule = rules; rule; rule = rule->next)
    {
        if (phase == HTML_VIEW_RULE_PHASE_IMPORTANT && !rule->has_important)
        {
            continue;
        }
        if (html_view_rule_matches(rule, node, pseudo))
        {
            if (phase == HTML_VIEW_RULE_PHASE_IMPORTANT)
            {
                html_view_style_merge_rule(out, &rule->important_style);
            }
            else
            {
                html_view_style_merge_rule(out, &rule->style);
            }
        }
    }
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

    html_view_rule_list_t *lists = NULL;
    size_t list_count = 0;
    if (html_view_collect_indexed_rule_lists(node, pseudo, index, &lists, &list_count))
    {
        if (list_count > 0)
        {
            html_view_apply_rule_lists(out,
                                       node,
                                       pseudo,
                                       lists,
                                       list_count,
                                       HTML_VIEW_RULE_PHASE_NORMAL);
            html_view_apply_rule_lists(out,
                                       node,
                                       pseudo,
                                       lists,
                                       list_count,
                                       HTML_VIEW_RULE_PHASE_IMPORTANT);
        }
        html_view_rule_lists_release(lists, list_count);
        return;
    }

    html_view_apply_rule_sheet_phase(out,
                                     node,
                                     pseudo,
                                     index->sheet->rules,
                                     HTML_VIEW_RULE_PHASE_NORMAL);
    html_view_apply_rule_sheet_phase(out,
                                     node,
                                     pseudo,
                                     index->sheet->rules,
                                     HTML_VIEW_RULE_PHASE_IMPORTANT);
    return;
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

static void html_view_apply_inline_rule_style(css_style_t *style, const css_style_t *src)
{
    if (!style || !src)
    {
        return;
    }
    html_view_style_merge_rule(style, src);
    if (src->has_background_image)
    {
        if (style->background_image_owned && style->background_image)
        {
            free((void *)style->background_image);
            style->background_image = NULL;
        }
        style->background_image_owned = false;
        style->has_background_image = true;
        style->background_image = NULL;
        if (src->background_image)
        {
            char *dup = html_view_strdup(src->background_image);
            if (dup)
            {
                style->background_image = dup;
                style->background_image_owned = true;
            }
        }
    }
    if (src->has_content)
    {
        if (style->content_owned && style->content)
        {
            free((void *)style->content);
            style->content = NULL;
        }
        style->content_owned = false;
        style->has_content = true;
        style->content = NULL;
        if (src->content)
        {
            char *dup = html_view_strdup(src->content);
            if (dup)
            {
                style->content = dup;
                style->content_owned = true;
            }
        }
    }
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

void html_view_style_cache_mark_dirty(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    __atomic_store_n(&priv->style_cache_dirty, 1u, __ATOMIC_RELEASE);
}

void html_view_style_cache_clear(atk_html_view_priv_t *priv)
{
    if (!priv || !priv->style_cache)
    {
        return;
    }
    for (size_t i = 0; i < priv->style_cache_cap; ++i)
    {
        html_view_style_cache_entry_t *entry = &priv->style_cache[i];
        if (!entry->valid)
        {
            continue;
        }
        css_style_release(&entry->style);
        entry->valid = false;
        entry->node = NULL;
    }
    __atomic_store_n(&priv->style_cache_dirty, 0u, __ATOMIC_RELEASE);
}

static void html_view_style_cache_clear_if_needed(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    if (__atomic_exchange_n(&priv->style_cache_dirty, 0u, __ATOMIC_ACQ_REL) == 0u)
    {
        return;
    }
    html_view_style_cache_clear(priv);
}

static bool html_view_style_cache_init(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return false;
    }
    if (priv->style_cache && priv->style_cache_cap > 0)
    {
        return true;
    }
    size_t cap = HTML_VIEW_STYLE_CACHE_MAX;
    html_view_style_cache_entry_t *entries = (html_view_style_cache_entry_t *)calloc(cap, sizeof(*entries));
    if (!entries)
    {
        return false;
    }
    priv->style_cache = entries;
    priv->style_cache_cap = cap;
    priv->style_cache_mask = cap - 1u;
    return true;
}

static size_t html_view_style_cache_index(const atk_html_view_priv_t *priv,
                                          const html_node_t *node,
                                          html_view_pseudo_t pseudo)
{
    uintptr_t key = (uintptr_t)node;
    key ^= (uintptr_t)pseudo * 0x9e3779b97f4a7c15ull;
    key >>= 4u;
    return (size_t)key & priv->style_cache_mask;
}

static const css_style_t *html_view_style_cache_lookup(atk_html_view_priv_t *priv,
                                                       const html_node_t *node,
                                                       html_view_pseudo_t pseudo)
{
    if (!priv || !node || !priv->style_cache || priv->style_cache_cap == 0)
    {
        return NULL;
    }
    size_t index = html_view_style_cache_index(priv, node, pseudo);
    const html_view_style_cache_entry_t *entry = &priv->style_cache[index];
    if (!entry->valid || entry->node != node || entry->pseudo != pseudo)
    {
        return NULL;
    }
    return &entry->style;
}

static bool html_view_style_cache_store(atk_html_view_priv_t *priv,
                                        const html_node_t *node,
                                        html_view_pseudo_t pseudo,
                                        const css_style_t *style)
{
    if (!priv || !node || !style)
    {
        return false;
    }
    if (!html_view_style_cache_init(priv))
    {
        return false;
    }
    size_t index = html_view_style_cache_index(priv, node, pseudo);
    html_view_style_cache_entry_t *entry = &priv->style_cache[index];
    if (entry->valid)
    {
        css_style_release(&entry->style);
    }
    if (!css_style_copy(&entry->style, style))
    {
        entry->valid = false;
        entry->node = NULL;
        return false;
    }
    entry->node = node;
    entry->pseudo = pseudo;
    entry->valid = true;
    return true;
}

static void html_view_style_cache_copy_out(css_style_t *out, const css_style_t *cached)
{
    if (!out || !cached)
    {
        return;
    }
    if (!css_style_copy(out, cached))
    {
        memset(out, 0, sizeof(*out));
    }
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

const html_view_inline_style_cache_t *html_view_inline_style_cached(atk_html_view_priv_t *priv,
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
            return entry;
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
    entry->important_style = &sheet->rules->important_style;
    entry->has_important = sheet->rules->has_important;
    return entry;
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
    if (priv)
    {
        html_view_style_cache_clear_if_needed(priv);
        html_view_dom_bloom_rebuild_if_needed(priv);
        if (node && node->type == HTML_NODE_ELEMENT)
        {
            const css_style_t *cached = html_view_style_cache_lookup(priv, node, HTML_VIEW_PSEUDO_NONE);
            if (cached)
            {
                html_view_style_cache_copy_out(out, cached);
                return;
            }
        }
    }

    memset(out, 0, sizeof(*out));

    bool is_table_cell = false;
    bool is_table_header = false;
    if (node && node->type == HTML_NODE_ELEMENT && node->name)
    {
        is_table_cell = (strcmp(node->name, "td") == 0 || strcmp(node->name, "th") == 0);
        is_table_header = (strcmp(node->name, "th") == 0);
    }

    html_view_style_inherit_from_parent(out, parent, !is_table_cell);
    if (sheet && sheet->global_env && !out->custom_env)
    {
        out->custom_env = css_var_env_ref(sheet->global_env);
        out->custom_env_local = false;
    }

    html_view_rule_list_t *rule_lists = NULL;
    size_t rule_list_count = 0;
    bool use_rule_lists = false;
    bool use_fallback = false;

    if (sheet && node && node->type == HTML_NODE_ELEMENT)
    {
        const html_view_rule_index_t *index = html_view_rule_index_get(priv, sheet);
        if (index)
        {
            if (html_view_collect_indexed_rule_lists(node,
                                                     HTML_VIEW_PSEUDO_NONE,
                                                     index,
                                                     &rule_lists,
                                                     &rule_list_count))
            {
                use_rule_lists = true;
                if (rule_list_count > 0)
                {
                    html_view_apply_rule_lists(out,
                                               node,
                                               HTML_VIEW_PSEUDO_NONE,
                                               rule_lists,
                                               rule_list_count,
                                               HTML_VIEW_RULE_PHASE_NORMAL);
                }
            }
            else
            {
                use_fallback = true;
                html_view_apply_rule_sheet_phase(out,
                                                 node,
                                                 HTML_VIEW_PSEUDO_NONE,
                                                 sheet->rules,
                                                 HTML_VIEW_RULE_PHASE_NORMAL);
            }
        }
        else
        {
            use_fallback = true;
            html_view_apply_rule_sheet_phase(out,
                                             node,
                                             HTML_VIEW_PSEUDO_NONE,
                                             sheet->rules,
                                             HTML_VIEW_RULE_PHASE_NORMAL);
        }
    }

    html_view_apply_presentational_attrs(out, parent, node);

    const char *inline_style = html_attr_get(node, "style");
    const html_view_inline_style_cache_t *inline_cache = NULL;
    css_stylesheet_t *inline_sheet = NULL;
    const css_rule_t *inline_rule = NULL;
    if (inline_style && inline_style[0] != '\0')
    {
        if (priv)
        {
            inline_cache = html_view_inline_style_cached(priv, node, inline_style);
        }
        if (inline_cache)
        {
            html_view_style_merge_rule(out, inline_cache->style);
        }
        else
        {
            inline_sheet = html_view_inline_style_sheet(inline_style);
            if (inline_sheet && inline_sheet->rules)
            {
                inline_rule = inline_sheet->rules;
                html_view_apply_inline_rule_style(out, &inline_rule->style);
            }
            else if (inline_sheet)
            {
                css_stylesheet_destroy(inline_sheet);
                inline_sheet = NULL;
            }
        }
    }

    if (use_rule_lists)
    {
        html_view_apply_rule_lists(out,
                                   node,
                                   HTML_VIEW_PSEUDO_NONE,
                                   rule_lists,
                                   rule_list_count,
                                   HTML_VIEW_RULE_PHASE_IMPORTANT);
    }
    else if (use_fallback)
    {
        html_view_apply_rule_sheet_phase(out,
                                         node,
                                         HTML_VIEW_PSEUDO_NONE,
                                         sheet->rules,
                                         HTML_VIEW_RULE_PHASE_IMPORTANT);
    }

    if (inline_cache && inline_cache->has_important)
    {
        html_view_style_merge_rule(out, inline_cache->important_style);
    }
    else if (inline_rule && inline_rule->has_important)
    {
        html_view_apply_inline_rule_style(out, &inline_rule->important_style);
    }
    if (inline_sheet)
    {
        css_stylesheet_destroy(inline_sheet);
    }
    if (use_rule_lists)
    {
        html_view_rule_lists_release(rule_lists, rule_list_count);
    }

    html_view_resolve_float_inherit(out, parent);
    html_view_resolve_box_sizing_inherit(out, parent);

    if (is_table_cell && !out->has_text_align)
    {
        out->has_text_align = true;
        out->text_align = is_table_header ? CSS_TEXT_ALIGN_CENTER : CSS_TEXT_ALIGN_LEFT;
    }

    (void)css_style_apply_custom_props(out, &out->custom_props);
    css_style_resolve_deferred(out);

    if (priv && node && node->type == HTML_NODE_ELEMENT)
    {
        (void)html_view_style_cache_store(priv, node, HTML_VIEW_PSEUDO_NONE, out);
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
    if (priv)
    {
        html_view_style_cache_clear_if_needed(priv);
        html_view_dom_bloom_rebuild_if_needed(priv);
        if (node && node->type == HTML_NODE_ELEMENT)
        {
            const css_style_t *cached = html_view_style_cache_lookup(priv, node, pseudo);
            if (cached)
            {
                html_view_style_cache_copy_out(out, cached);
                return out->has_content;
            }
        }
    }
    memset(out, 0, sizeof(*out));

    html_view_style_inherit_from_parent(out, parent, true);
    if (sheet && sheet->global_env && !out->custom_env)
    {
        out->custom_env = css_var_env_ref(sheet->global_env);
        out->custom_env_local = false;
    }

    if (sheet && node && node->type == HTML_NODE_ELEMENT)
    {
        const html_view_rule_index_t *index = html_view_rule_index_get(priv, sheet);
        if (index)
        {
            html_view_apply_indexed_rules(out, node, pseudo, index);
        }
        else
        {
            html_view_apply_rule_sheet_phase(out,
                                             node,
                                             pseudo,
                                             sheet->rules,
                                             HTML_VIEW_RULE_PHASE_NORMAL);
            html_view_apply_rule_sheet_phase(out,
                                             node,
                                             pseudo,
                                             sheet->rules,
                                             HTML_VIEW_RULE_PHASE_IMPORTANT);
        }
    }

    html_view_resolve_float_inherit(out, parent);
    html_view_resolve_box_sizing_inherit(out, parent);

    (void)css_style_apply_custom_props(out, &out->custom_props);
    css_style_resolve_deferred(out);

    if (priv && node && node->type == HTML_NODE_ELEMENT)
    {
        (void)html_view_style_cache_store(priv, node, pseudo, out);
    }

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
