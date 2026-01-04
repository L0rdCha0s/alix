#include "atk/html_view/html_view_internal.h"

#include "ctype.h"
#include "web/css/css_internal.h"

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

static bool html_view_node_has_class(const html_node_t *node, const char *cls_start, size_t cls_len)
{
    if (!node || node->type != HTML_NODE_ELEMENT || !cls_start || cls_len == 0)
    {
        return false;
    }
    const char *classes = html_attr_get(node, "class");
    if (!classes || classes[0] == '\0')
    {
        return false;
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

    if (mut->class_token_count > 0)
    {
        for (size_t i = 0; i < mut->class_token_count; ++i)
        {
            html_class_token_t *tok = &mut->class_tokens[i];
            if (tok->len == cls_len && strncasecmp(tok->start, cls_start, cls_len) == 0)
            {
                return true;
            }
        }
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

static void html_view_selector_cache_set_tag_hint(css_selector_cache_t *cache, const char *selector)
{
    if (!cache)
    {
        return;
    }
    cache->tag_hint_valid = false;
    cache->tag_hint_any = false;
    cache->tag_hint_start = 0;
    cache->tag_hint_len = 0;
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
    if (*part_start == '*')
    {
        cache->tag_hint_any = true;
        return;
    }
    if (*part_start == '#' || *part_start == '.' || *part_start == '[' || *part_start == ':')
    {
        return;
    }
    const char *tag_end = part_start;
    while (tag_end < part_end &&
           *tag_end != ':' && *tag_end != '.' && *tag_end != '#' && *tag_end != '[' &&
           !isspace((unsigned char)*tag_end))
    {
        ++tag_end;
    }
    size_t tag_len = (size_t)(tag_end - part_start);
    if (tag_len == 0)
    {
        return;
    }
    cache->tag_hint_valid = true;
    cache->tag_hint_start = (uint32_t)(part_start - selector);
    cache->tag_hint_len = (uint32_t)tag_len;
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
    html_view_selector_cache_set_tag_hint(cache, selector);
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

static bool html_view_selector_matches_cached(css_rule_t *rule,
                                              const html_node_t *node,
                                              html_view_pseudo_t pseudo)
{
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
            return html_view_selector_matches_internal(rule->selector, node, pseudo);
        }
        rule->selector_cache = cache;
    }

    if (!cache->parsed && !cache->parse_failed)
    {
        (void)html_view_selector_cache_parse(cache, rule->selector);
    }
    if (!cache->parsed || cache->count == 0)
    {
        return html_view_selector_matches_internal(rule->selector, node, pseudo);
    }

    if (cache->tag_hint_valid)
    {
        if (!node->name || strlen(node->name) != cache->tag_hint_len ||
            strncasecmp(node->name, rule->selector + cache->tag_hint_start, cache->tag_hint_len) != 0)
        {
            return false;
        }
    }

    return html_view_selector_matches_parts(cache->parts, cache->count, rule->selector, node, pseudo);
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
        for (css_rule_t *rule = sheet->rules; rule; rule = rule->next)
        {
            if (rule->selector && html_view_selector_matches_cached(rule, node, HTML_VIEW_PSEUDO_NONE))
            {
                css_style_merge(out, &rule->style);
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
    (void)priv;

    html_view_style_inherit_from_parent(out, parent, true);

    if (sheet && node && node->type == HTML_NODE_ELEMENT)
    {
        for (css_rule_t *rule = sheet->rules; rule; rule = rule->next)
        {
            if (rule->selector && html_view_selector_matches_cached(rule, node, pseudo))
            {
                css_style_merge(out, &rule->style);
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
