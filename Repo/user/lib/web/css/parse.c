#include "web/css/css_internal.h"

#include "ctype.h"
#include "libc.h"

typedef struct
{
    int width_px;
    int height_px;
    css_media_color_scheme_t color_scheme;
} css_media_env_t;

static css_media_env_t g_css_media_env = {0};

void css_media_env_set(int width_px, int height_px, css_media_color_scheme_t scheme)
{
    if (width_px < 0)
    {
        width_px = 0;
    }
    if (height_px < 0)
    {
        height_px = 0;
    }
    g_css_media_env.width_px = width_px;
    g_css_media_env.height_px = height_px;
    g_css_media_env.color_scheme = scheme;
}

static bool css_strip_priority(const char *start,
                               const char *end,
                               const char **out_end,
                               bool *out_important)
{
    if (out_end)
    {
        *out_end = end;
    }
    if (out_important)
    {
        *out_important = false;
    }
    if (!start || !end || end <= start)
    {
        return true;
    }

    const char *p = start;
    const char *bang = NULL;
    char quote = 0;
    int paren_depth = 0;
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
        if (c == '/' && p + 1 < end && p[1] == '*')
        {
            p += 2;
            while (p + 1 < end && !(p[0] == '*' && p[1] == '/'))
            {
                ++p;
            }
            if (p + 1 < end)
            {
                p += 2;
            }
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
        if (c == '!' && paren_depth == 0)
        {
            bang = p;
            break;
        }
        ++p;
    }

    if (!bang)
    {
        return true;
    }

    const char *q = bang + 1;
    css_skip_ws_and_comments_range(&q, end);
    const char *kw_start = q;
    while (q < end && isalpha((unsigned char)*q))
    {
        ++q;
    }
    if ((size_t)(q - kw_start) != 9 || strncasecmp(kw_start, "important", 9) != 0)
    {
        return false;
    }
    css_skip_ws_and_comments_range(&q, end);
    if (q < end)
    {
        return false;
    }
    if (out_end)
    {
        *out_end = bang;
    }
    if (out_important)
    {
        *out_important = true;
    }
    return true;
}

static const char *css_scan_value_end_range(const char *p, const char *end)
{
    if (!p)
    {
        return NULL;
    }
    if (!end || end < p)
    {
        end = p + strlen(p);
    }
    char quote = 0;
    int paren_depth = 0;
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
        if (c == '/' && (p + 1) < end && p[1] == '*')
        {
            p += 2;
            while (p + 1 < end && !(p[0] == '*' && p[1] == '/'))
            {
                ++p;
            }
            if (p + 1 < end)
            {
                p += 2;
            }
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
        if ((c == ';' || c == '}') && paren_depth == 0)
        {
            break;
        }
        ++p;
    }
    return p;
}

static char *css_strdup(const char *s)
{
    if (!s)
    {
        return NULL;
    }
    size_t len = strlen(s);
    char *out = (char *)malloc(len + 1);
    if (!out)
    {
        return NULL;
    }
    memcpy(out, s, len + 1);
    return out;
}



typedef struct css_dynstr
{
    char *data;
    size_t len;
    size_t cap;
} css_dynstr_t;

bool css_decl_list_push(css_decl_list_t *list,
                        const char *prop_start,
                        const char *prop_end,
                        const char *val_start,
                               const char *val_end,
                               bool important)
{
    if (!list || !prop_start || !prop_end || prop_end <= prop_start || !val_start || !val_end)
    {
        return false;
    }
    if (list->count == list->cap)
    {
        size_t new_cap = list->cap ? list->cap * 2u : 16u;
        css_decl_t *next = (css_decl_t *)realloc(list->items, new_cap * sizeof(*next));
        if (!next)
        {
            return false;
        }
        list->items = next;
        list->cap = new_cap;
    }
    list->items[list->count++] = (css_decl_t){
        .prop_start = prop_start,
        .prop_end = prop_end,
        .val_start = val_start,
        .val_end = val_end,
        .important = important,
    };
    return true;
}

void css_decl_list_free(css_decl_list_t *list)
{
    if (!list)
    {
        return;
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}

static char *css_strdup_range(const char *start, const char *end)
{
    if (!start || !end || end <= start)
    {
        return NULL;
    }
    size_t len = (size_t)(end - start);
    char *out = (char *)malloc(len + 1);
    if (!out)
    {
        return NULL;
    }
    memcpy(out, start, len);
    out[len] = '\0';
    return out;
}

static uint32_t css_var_hash_range(const char *start, const char *end)
{
    uint32_t hash = 2166136261u;
    if (!start || !end || end <= start)
    {
        return hash;
    }
    for (const char *p = start; p < end; ++p)
    {
        hash ^= (uint8_t)(*p);
        hash *= 16777619u;
    }
    return hash;
}

static void css_var_map_slots_free(css_var_map_t *map)
{
    if (!map || !map->slots)
    {
        return;
    }
    free(map->slots);
    map->slots = NULL;
    map->slot_cap = 0;
}

static bool css_var_map_rebuild_index(css_var_map_t *map)
{
    if (!map || map->shared)
    {
        return false;
    }
    if (map->count < 8)
    {
        css_var_map_slots_free(map);
        return true;
    }

    size_t cap = 16;
    while (cap < map->count * 2u)
    {
        cap <<= 1;
    }

    uint32_t *slots = (uint32_t *)calloc(cap, sizeof(*slots));
    if (!slots)
    {
        return false;
    }

    size_t mask = cap - 1u;
    for (size_t i = 0; i < map->count; ++i)
    {
        const css_var_entry_t *entry = &map->items[i];
        if (!entry->name || entry->name_len == 0)
        {
            continue;
        }
        size_t idx = (size_t)entry->name_hash & mask;
        while (slots[idx] != 0u)
        {
            idx = (idx + 1u) & mask;
        }
        slots[idx] = (uint32_t)(i + 1u);
    }

    css_var_map_slots_free(map);
    map->slots = slots;
    map->slot_cap = cap;
    return true;
}

static void css_var_map_slot_insert(css_var_map_t *map, size_t entry_index)
{
    if (!map || !map->slots || map->slot_cap == 0 || map->shared)
    {
        return;
    }
    size_t mask = map->slot_cap - 1u;
    size_t idx = (size_t)map->items[entry_index].name_hash & mask;
    while (map->slots[idx] != 0u)
    {
        idx = (idx + 1u) & mask;
    }
    map->slots[idx] = (uint32_t)(entry_index + 1u);
}

void css_var_map_free(css_var_map_t *map)
{
    if (!map)
    {
        return;
    }
    if (!map->shared)
    {
        for (size_t i = 0; i < map->count; ++i)
        {
            free(map->items[i].name);
            free(map->items[i].value);
        }
        free(map->items);
        css_var_map_slots_free(map);
    }
    map->items = NULL;
    map->count = 0;
    map->cap = 0;
    map->slots = NULL;
    map->slot_cap = 0;
    map->shared = false;
}

static const css_var_entry_t *css_var_map_find_hash(const css_var_map_t *map,
                                                    const char *name_start,
                                                    size_t name_len,
                                                    uint32_t name_hash)
{
    if (!map || !name_start || name_len == 0)
    {
        return NULL;
    }
    if (map->slots && map->slot_cap > 0)
    {
        size_t mask = map->slot_cap - 1u;
        size_t idx = (size_t)name_hash & mask;
        while (true)
        {
            uint32_t slot = map->slots[idx];
            if (slot == 0u)
            {
                return NULL;
            }
            const css_var_entry_t *entry = &map->items[slot - 1u];
            if (entry->name_hash == name_hash && entry->name_len == name_len &&
                entry->name && memcmp(entry->name, name_start, name_len) == 0)
            {
                return entry;
            }
            idx = (idx + 1u) & mask;
        }
    }
    for (size_t i = 0; i < map->count; ++i)
    {
        const css_var_entry_t *entry = &map->items[i];
        if (!entry->name)
        {
            continue;
        }
        if (entry->name_hash == name_hash && entry->name_len == name_len &&
            memcmp(entry->name, name_start, name_len) == 0)
        {
            return entry;
        }
    }
    return NULL;
}

static bool css_var_map_detach(css_var_map_t *map)
{
    if (!map || !map->shared)
    {
        return true;
    }
    if (map->count == 0)
    {
        map->items = NULL;
        map->cap = 0;
        map->slots = NULL;
        map->slot_cap = 0;
        map->shared = false;
        return true;
    }

    css_var_entry_t *items = (css_var_entry_t *)calloc(map->count, sizeof(*items));
    if (!items)
    {
        return false;
    }

    for (size_t i = 0; i < map->count; ++i)
    {
        const css_var_entry_t *src = &map->items[i];
        if (src->name)
        {
            items[i].name = css_strdup_range(src->name, src->name + src->name_len);
            if (!items[i].name)
            {
                css_var_map_t cleanup = {
                    .items = items,
                    .count = i,
                    .cap = map->count,
                    .slots = NULL,
                    .slot_cap = 0,
                    .shared = false,
                };
                css_var_map_free(&cleanup);
                return false;
            }
        }
        if (src->value)
        {
            items[i].value = css_strdup_range(src->value, src->value + src->value_len);
            if (!items[i].value)
            {
                css_var_map_t cleanup = {
                    .items = items,
                    .count = i + 1,
                    .cap = map->count,
                    .slots = NULL,
                    .slot_cap = 0,
                    .shared = false,
                };
                css_var_map_free(&cleanup);
                return false;
            }
        }
        items[i].name_hash = src->name_hash;
        items[i].name_len = src->name_len;
        items[i].value_len = src->value_len;
    }

    map->items = items;
    map->cap = map->count;
    map->slots = NULL;
    map->slot_cap = 0;
    map->shared = false;
    return true;
}

bool css_var_map_set(css_var_map_t *map,
                            const char *name_start,
                            const char *name_end,
                            const char *value_start,
                            const char *value_end,
                            bool allow_override)
{
    if (!map || !name_start || !name_end || name_end <= name_start)
    {
        return false;
    }
    css_trim_range(&name_start, &name_end);
    css_trim_range(&value_start, &value_end);
    if (name_end <= name_start)
    {
        return false;
    }

    size_t name_len = (size_t)(name_end - name_start);
    size_t value_len = 0;
    if (value_start && value_end && value_end > value_start)
    {
        value_len = (size_t)(value_end - value_start);
    }
    uint32_t name_hash = css_var_hash_range(name_start, name_end);
    const css_var_entry_t *existing = css_var_map_find_hash(map, name_start, name_len, name_hash);
    if (existing && !allow_override)
    {
        return true;
    }

    bool detached = false;
    if (map->shared)
    {
        if (!css_var_map_detach(map))
        {
            return false;
        }
        detached = true;
        existing = css_var_map_find_hash(map, name_start, name_len, name_hash);
    }

    if (existing)
    {
        for (size_t i = 0; i < map->count; ++i)
        {
            css_var_entry_t *entry = &map->items[i];
            if (!entry->name)
            {
                continue;
            }
            if (entry->name_len == name_len &&
                memcmp(entry->name, name_start, name_len) == 0)
            {
                char *value_dup = css_strdup_range(value_start, value_end);
                if (!value_dup && value_start && value_end && value_end > value_start)
                {
                    return false;
                }
                free(entry->value);
                entry->value = value_dup;
                entry->value_len = (uint32_t)value_len;
                if (detached && map->count >= 8)
                {
                    (void)css_var_map_rebuild_index(map);
                }
                return true;
            }
        }
    }

    if (map->count == map->cap)
    {
        size_t new_cap = map->cap ? map->cap * 2u : 16u;
        css_var_entry_t *next = (css_var_entry_t *)realloc(map->items, new_cap * sizeof(*next));
        if (!next)
        {
            return false;
        }
        map->items = next;
        map->cap = new_cap;
    }

    char *name_dup = css_strdup_range(name_start, name_end);
    if (!name_dup)
    {
        return false;
    }
    char *value_dup = css_strdup_range(value_start, value_end);
    if (!value_dup && value_start && value_end && value_end > value_start)
    {
        free(name_dup);
        return false;
    }

    map->items[map->count++] = (css_var_entry_t){
        .name = name_dup,
        .value = value_dup,
        .name_hash = name_hash,
        .name_len = (uint32_t)name_len,
        .value_len = (uint32_t)value_len,
    };
    if (map->count >= 8)
    {
        if (!map->slots || map->count * 2u >= map->slot_cap)
        {
            if (!css_var_map_rebuild_index(map))
            {
                return false;
            }
        }
        else
        {
            css_var_map_slot_insert(map, map->count - 1u);
        }
    }
    return true;
}

const char *css_var_map_lookup(const css_var_map_t *map,
                                      const css_var_map_t *fallback_map,
                                      const char *name_start,
                                      const char *name_end,
                                      size_t *out_len)
{
    size_t name_len = 0;
    if (name_start && name_end && name_end > name_start)
    {
        name_len = (size_t)(name_end - name_start);
    }
    uint32_t name_hash = css_var_hash_range(name_start, name_end);
    const css_var_entry_t *entry = css_var_map_find_hash(map, name_start, name_len, name_hash);
    if (!entry)
    {
        entry = css_var_map_find_hash(fallback_map, name_start, name_len, name_hash);
    }
    if (!entry || !entry->value)
    {
        return NULL;
    }
    if (out_len)
    {
        *out_len = entry->value_len;
    }
    return entry->value;
}

static bool css_dynstr_append(css_dynstr_t *out, const char *data, size_t len)
{
    if (!out || !data || len == 0)
    {
        return true;
    }
    if (out->len + len + 1 > out->cap)
    {
        size_t new_cap = out->cap ? out->cap * 2u : 64u;
        while (new_cap < out->len + len + 1)
        {
            new_cap *= 2u;
        }
        char *next = (char *)realloc(out->data, new_cap);
        if (!next)
        {
            return false;
        }
        out->data = next;
        out->cap = new_cap;
    }
    memcpy(out->data + out->len, data, len);
    out->len += len;
    out->data[out->len] = '\0';
    return true;
}

bool css_value_has_var(const char *start, const char *end)
{
    if (!start || !end || end <= start)
    {
        return false;
    }
    char quote = 0;
    bool escape = false;
    const char *p = start;
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
        if (c == '/' && (p + 1) < end && p[1] == '*')
        {
            p += 2;
            while (p + 1 < end && !(p[0] == '*' && p[1] == '/'))
            {
                ++p;
            }
            if (p + 1 < end)
            {
                p += 2;
            }
            continue;
        }
        if ((end - p) >= 4 && (p[0] == 'v' || p[0] == 'V') &&
            (p[1] == 'a' || p[1] == 'A') &&
            (p[2] == 'r' || p[2] == 'R') && p[3] == '(')
        {
            return true;
        }
        ++p;
    }
    return false;
}

char *css_expand_vars_range(const char *val_start,
                            const char *val_end,
                            const css_var_map_t *global_vars,
                            const css_var_map_t *local_vars,
                            int depth)
{
    if (!val_start || !val_end || val_end <= val_start)
    {
        return NULL;
    }
    if (depth > 8)
    {
        return css_strdup_range(val_start, val_end);
    }

    css_dynstr_t out = {0};
    const char *p = val_start;
    while (p < val_end)
    {
        char c = *p;
        if ((val_end - p) >= 4 && (c == 'v' || c == 'V') &&
            (p[1] == 'a' || p[1] == 'A') &&
            (p[2] == 'r' || p[2] == 'R') && p[3] == '(')
        {
            const char *func_start = p;
            const char *args_start = p + 4;
            const char *scan = args_start;
            char quote = 0;
            bool escape = false;
            int paren_depth = 1;
            const char *comma = NULL;
            while (scan < val_end)
            {
                char sc = *scan;
                if (escape)
                {
                    escape = false;
                    ++scan;
                    continue;
                }
                if (sc == '\\')
                {
                    escape = true;
                    ++scan;
                    continue;
                }
                if (quote)
                {
                    if (sc == quote)
                    {
                        quote = 0;
                    }
                    ++scan;
                    continue;
                }
                if (sc == '"' || sc == '\'')
                {
                    quote = sc;
                    ++scan;
                    continue;
                }
                if (sc == '(')
                {
                    ++paren_depth;
                    ++scan;
                    continue;
                }
                if (sc == ')')
                {
                    --paren_depth;
                    if (paren_depth == 0)
                    {
                        break;
                    }
                    ++scan;
                    continue;
                }
                if (sc == ',' && paren_depth == 1 && !comma)
                {
                    comma = scan;
                    ++scan;
                    continue;
                }
                ++scan;
            }

            if (scan >= val_end || *scan != ')')
            {
                if (!css_dynstr_append(&out, func_start, (size_t)(val_end - func_start)))
                {
                    free(out.data);
                    return NULL;
                }
                return out.data ? out.data : css_strdup_range(val_start, val_end);
            }

            const char *args_end = scan;
            const char *name_start = args_start;
            const char *name_end = comma ? comma : args_end;
            css_trim_range(&name_start, &name_end);
            const char *fallback_start = NULL;
            const char *fallback_end = NULL;
            if (comma)
            {
                fallback_start = comma + 1;
                fallback_end = args_end;
                css_trim_range(&fallback_start, &fallback_end);
            }

            size_t value_len = 0;
            const char *value = css_var_map_lookup(local_vars, global_vars, name_start, name_end, &value_len);
            if (value)
            {
                char *expanded = css_expand_vars_range(value, value + value_len, global_vars, local_vars, depth + 1);
                if (expanded)
                {
                    bool ok = css_dynstr_append(&out, expanded, strlen(expanded));
                    free(expanded);
                    if (!ok)
                    {
                        free(out.data);
                        return NULL;
                    }
                }
                else
                {
                    if (!css_dynstr_append(&out, value, value_len))
                    {
                        free(out.data);
                        return NULL;
                    }
                }
            }
            else if (fallback_start && fallback_end && fallback_end > fallback_start)
            {
                char *expanded = css_expand_vars_range(fallback_start, fallback_end, global_vars, local_vars, depth + 1);
                if (expanded)
                {
                    bool ok = css_dynstr_append(&out, expanded, strlen(expanded));
                    free(expanded);
                    if (!ok)
                    {
                        free(out.data);
                        return NULL;
                    }
                }
                else
                {
                    if (!css_dynstr_append(&out, fallback_start, (size_t)(fallback_end - fallback_start)))
                    {
                        free(out.data);
                        return NULL;
                    }
                }
            }
            else
            {
                if (!css_dynstr_append(&out, func_start, (size_t)(scan + 1 - func_start)))
                {
                    free(out.data);
                    return NULL;
                }
            }

            p = scan + 1;
            continue;
        }

        if (!css_dynstr_append(&out, p, 1))
        {
            free(out.data);
            return NULL;
        }
        ++p;
    }

    return out.data ? out.data : css_strdup_range(val_start, val_end);
}

static bool css_var_name_is_local(const char *name_start, const char *name_end)
{
    if (!name_start || !name_end || name_end <= name_start)
    {
        return false;
    }
    /* Treat all custom properties as potentially global/inherited.
       The previous heuristic of treating --_ as local is removed to support
       Stack Overflow's Stacks CSS which uses --_ for component-scoped but inherited variables. */
    return false;
}

static bool css_append_rule(css_stylesheet_t *sheet,
                            const char *selector_start,
                            const char *selector_end,
                            const css_style_t *style,
                            const css_style_t *important_style,
                            const css_var_map_t *custom_props,
                            const css_var_map_t *important_custom_props,
                            const css_decl_list_t *deferred_decls,
                            bool has_important)
{
    if (!sheet || !selector_start || !selector_end || selector_end <= selector_start)
    {
        return false;
    }
    css_trim_range(&selector_start, &selector_end);
    if (selector_end <= selector_start)
    {
        return true;
    }

    css_rule_t *rule = (css_rule_t *)calloc(1, sizeof(*rule));
    if (!rule)
    {
        return false;
    }
    rule->selector = css_strdup_lower(selector_start, selector_end);
    if (!rule->selector)
    {
        free(rule);
        return false;
    }
    if (style)
    {
        rule->style = *style;
    }
    if (custom_props)
    {
        for (size_t i = 0; i < custom_props->count; ++i)
        {
            css_var_map_set(&rule->custom_props,
                            custom_props->items[i].name,
                            custom_props->items[i].name + custom_props->items[i].name_len,
                            custom_props->items[i].value,
                            custom_props->items[i].value + custom_props->items[i].value_len,
                            true);
            css_var_map_set(&rule->style.custom_props,
                            custom_props->items[i].name,
                            custom_props->items[i].name + custom_props->items[i].name_len,
                            custom_props->items[i].value,
                            custom_props->items[i].value + custom_props->items[i].value_len,
                            true);
        }
    }
    if (deferred_decls)
    {
        for (size_t i = 0; i < deferred_decls->count; ++i)
        {
            css_decl_list_push(&rule->deferred_decls,
                               deferred_decls->items[i].prop_start,
                               deferred_decls->items[i].prop_end,
                               deferred_decls->items[i].val_start,
                               deferred_decls->items[i].val_end,
                               deferred_decls->items[i].important);
            if (deferred_decls->items[i].important)
            {
                css_decl_list_push(&rule->important_style.deferred_decls,
                                   deferred_decls->items[i].prop_start,
                                   deferred_decls->items[i].prop_end,
                                   deferred_decls->items[i].val_start,
                                   deferred_decls->items[i].val_end,
                                   true);
            }
            else
            {
                css_decl_list_push(&rule->style.deferred_decls,
                                   deferred_decls->items[i].prop_start,
                                   deferred_decls->items[i].prop_end,
                                   deferred_decls->items[i].val_start,
                                   deferred_decls->items[i].val_end,
                                   false);
            }
        }
    }
    if (rule->style.background_image_owned && rule->style.background_image)
    {
        char *dup = css_strdup(rule->style.background_image);
        if (!dup)
        {
            free(rule->selector);
            free(rule);
            return false;
        }
        rule->style.background_image = dup;
    }
    if (rule->style.content_owned && rule->style.content)
    {
        char *dup = css_strdup(rule->style.content);
        if (!dup)
        {
            css_style_release(&rule->style);
            free(rule->selector);
            free(rule);
            return false;
        }
        rule->style.content = dup;
    }
    if (important_style)
    {
        rule->important_style = *important_style;
    }
    if (important_custom_props)
    {
        for (size_t i = 0; i < important_custom_props->count; ++i)
        {
            css_var_map_set(&rule->important_custom_props,
                            important_custom_props->items[i].name,
                            important_custom_props->items[i].name + important_custom_props->items[i].name_len,
                            important_custom_props->items[i].value,
                            important_custom_props->items[i].value + important_custom_props->items[i].value_len,
                            true);
            css_var_map_set(&rule->important_style.custom_props,
                            important_custom_props->items[i].name,
                            important_custom_props->items[i].name + important_custom_props->items[i].name_len,
                            important_custom_props->items[i].value,
                            important_custom_props->items[i].value + important_custom_props->items[i].value_len,
                            true);
        }
    }
    if (important_style) // This block was originally part of the `if (important_style)` above.
    {
        rule->has_important = has_important;
        if (rule->important_style.background_image_owned && rule->important_style.background_image)
        {
            char *dup = css_strdup(rule->important_style.background_image);
            if (!dup)
            {
                css_style_release(&rule->important_style);
                css_style_release(&rule->style);
                free(rule->selector);
                free(rule);
                return false;
            }
            rule->important_style.background_image = dup;
        }
        if (rule->important_style.content_owned && rule->important_style.content)
        {
            char *dup = css_strdup(rule->important_style.content);
            if (!dup)
            {
                css_style_release(&rule->important_style);
                css_style_release(&rule->style);
                free(rule->selector);
                free(rule);
                return false;
            }
            rule->important_style.content = dup;
        }
    }
    rule->next = NULL;

    if (!sheet->rules)
    {
        sheet->rules = rule;
        return true;
    }
    css_rule_t *tail = sheet->rules;
    while (tail->next)
    {
        tail = tail->next;
    }
    tail->next = rule;
    return true;
}

static bool css_at_rule_name_is(const char *start, const char *end, const char *name)
{
    if (!start || !end || !name || end <= start)
    {
        return false;
    }
    size_t len = (size_t)(end - start);
    size_t name_len = strlen(name);
    if (len != name_len)
    {
        return false;
    }
    return strncasecmp(start, name, len) == 0;
}

static bool css_at_rule_has_nested_rules(const char *start, const char *end)
{
    return css_at_rule_name_is(start, end, "media") ||
           css_at_rule_name_is(start, end, "supports") ||
           css_at_rule_name_is(start, end, "layer") ||
           css_at_rule_name_is(start, end, "container") ||
           css_at_rule_name_is(start, end, "scope") ||
           css_at_rule_name_is(start, end, "document");
}

static bool css_media_env_is_default(const css_media_env_t *env)
{
    if (!env)
    {
        return true;
    }
    return env->width_px == 0 &&
           env->height_px == 0 &&
           env->color_scheme == CSS_MEDIA_COLOR_SCHEME_ANY;
}

static bool css_media_length_to_px(const css_length_t *len,
                                   int width_px,
                                   int height_px,
                                   int base_px,
                                   int *out_px)
{
    if (!len || !len->valid || len->is_auto || !out_px)
    {
        return false;
    }
    int64_t px = 0;
    switch (len->unit)
    {
        case CSS_UNIT_NONE:
        case CSS_UNIT_PX:
            px = len->value_milli / 1000;
            break;
        case CSS_UNIT_VW:
            px = (int64_t)width_px * len->value_milli / 100000;
            break;
        case CSS_UNIT_VH:
            px = (int64_t)height_px * len->value_milli / 100000;
            break;
        case CSS_UNIT_PERCENT:
            px = (int64_t)base_px * len->value_milli / 100000;
            break;
        case CSS_UNIT_EM:
            px = (int64_t)16 * len->value_milli / 1000;
            break;
        default:
            return false;
    }
    *out_px = (int)px;
    return true;
}

static bool css_media_feature_matches(const char *start,
                                      const char *end,
                                      const css_media_env_t *env)
{
    if (!start || !end || end <= start || !env)
    {
        return false;
    }
    css_trim_range(&start, &end);
    if (end <= start)
    {
        return false;
    }

    const char *colon = start;
    while (colon < end && *colon != ':')
    {
        ++colon;
    }
    if (colon >= end)
    {
        return false;
    }

    const char *name_start = start;
    const char *name_end = colon;
    css_trim_range(&name_start, &name_end);
    const char *val_start = colon + 1;
    const char *val_end = end;
    css_trim_range(&val_start, &val_end);
    if (name_end <= name_start || val_end <= val_start)
    {
        return false;
    }

    if (css_at_rule_name_is(name_start, name_end, "min-width") ||
        css_at_rule_name_is(name_start, name_end, "max-width") ||
        css_at_rule_name_is(name_start, name_end, "min-height") ||
        css_at_rule_name_is(name_start, name_end, "max-height"))
    {
        css_length_t len = {0};
        if (!css_parse_length_token(val_start, val_end, &len))
        {
            return false;
        }

        bool is_width = css_at_rule_name_is(name_start, name_end, "min-width") ||
                        css_at_rule_name_is(name_start, name_end, "max-width");
        int ref_px = is_width ? env->width_px : env->height_px;
        int cmp_px = 0;
        if (!css_media_length_to_px(&len,
                                    env->width_px,
                                    env->height_px,
                                    ref_px,
                                    &cmp_px))
        {
            return false;
        }

        if (css_at_rule_name_is(name_start, name_end, "min-width") ||
            css_at_rule_name_is(name_start, name_end, "min-height"))
        {
            return ref_px >= cmp_px;
        }
        return ref_px <= cmp_px;
    }

    if (css_at_rule_name_is(name_start, name_end, "prefers-color-scheme"))
    {
        if (env->color_scheme == CSS_MEDIA_COLOR_SCHEME_ANY)
        {
            return true;
        }
        if (css_at_rule_name_is(val_start, val_end, "dark"))
        {
            return env->color_scheme == CSS_MEDIA_COLOR_SCHEME_DARK;
        }
        if (css_at_rule_name_is(val_start, val_end, "light"))
        {
            return env->color_scheme == CSS_MEDIA_COLOR_SCHEME_LIGHT;
        }
        return false;
    }

    return false;
}

static bool css_media_query_group_matches(const char *start,
                                          const char *end,
                                          const css_media_env_t *env)
{
    if (!start || !end || end <= start)
    {
        return true;
    }

    const char *p = start;
    bool match = true;
    bool negate = false;
    bool saw_condition = false;

    while (p < end)
    {
        css_skip_ws_and_comments_range(&p, end);
        if (p >= end)
        {
            break;
        }

        if (*p == '(')
        {
            const char *feature_start = p + 1;
            const char *s = feature_start;
            int depth = 1;
            char quote = 0;
            bool escape = false;
            while (s < end && depth > 0)
            {
                char c = *s;
                if (escape)
                {
                    escape = false;
                    ++s;
                    continue;
                }
                if (c == '\\')
                {
                    escape = true;
                    ++s;
                    continue;
                }
                if (quote)
                {
                    if (c == quote)
                    {
                        quote = 0;
                    }
                    ++s;
                    continue;
                }
                if (c == '"' || c == '\'')
                {
                    quote = c;
                    ++s;
                    continue;
                }
                if (c == '(')
                {
                    ++depth;
                    ++s;
                    continue;
                }
                if (c == ')')
                {
                    --depth;
                    ++s;
                    continue;
                }
                ++s;
            }
            const char *feature_end = (depth == 0 && s > feature_start) ? (s - 1) : end;
            bool feature_match = css_media_feature_matches(feature_start, feature_end, env);
            match = match && feature_match;
            saw_condition = true;
            p = s;
            continue;
        }

        if (isalnum((unsigned char)*p) || *p == '-' || *p == '_')
        {
            const char *tok_start = p;
            while (p < end &&
                   (isalnum((unsigned char)*p) || *p == '-' || *p == '_'))
            {
                ++p;
            }
            const char *tok_end = p;

            if (css_at_rule_name_is(tok_start, tok_end, "not"))
            {
                negate = true;
                continue;
            }
            if (css_at_rule_name_is(tok_start, tok_end, "only") ||
                css_at_rule_name_is(tok_start, tok_end, "and"))
            {
                continue;
            }
            if (css_at_rule_name_is(tok_start, tok_end, "screen") ||
                css_at_rule_name_is(tok_start, tok_end, "all"))
            {
                saw_condition = true;
                continue;
            }
            if (css_at_rule_name_is(tok_start, tok_end, "print") ||
                css_at_rule_name_is(tok_start, tok_end, "speech"))
            {
                saw_condition = true;
                match = false;
                continue;
            }

            saw_condition = true;
            match = false;
            continue;
        }

        ++p;
    }

    if (!saw_condition)
    {
        return true;
    }
    if (negate)
    {
        match = !match;
    }
    return match;
}

static bool css_media_query_list_matches(const char *start,
                                         const char *end,
                                         const css_media_env_t *env)
{
    if (!start || !end || end < start || !env)
    {
        return true;
    }
    if (css_media_env_is_default(env))
    {
        return true;
    }

    css_trim_range(&start, &end);
    if (end <= start)
    {
        return true;
    }

    const char *group_start = start;
    int paren_depth = 0;
    char quote = 0;
    bool escape = false;
    for (const char *p = start; p <= end; ++p)
    {
        if (p == end || (paren_depth == 0 && *p == ','))
        {
            if (css_media_query_group_matches(group_start, p, env))
            {
                return true;
            }
            group_start = p + 1;
            continue;
        }

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
        if (c == '(')
        {
            ++paren_depth;
            continue;
        }
        if (c == ')' && paren_depth > 0)
        {
            --paren_depth;
        }
    }

    return false;
}

static const char *css_scan_to_block_internal(const char *p,
                                              const char *end,
                                              bool *out_block,
                                              bool stop_at_semicolon)
{
    if (out_block)
    {
        *out_block = false;
    }
    if (!p || !end || end < p)
    {
        return p;
    }
    char quote = 0;
    bool escape = false;
    int paren_depth = 0;
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
        if (c == '/' && (p + 1) < end && p[1] == '*')
        {
            p += 2;
            while (p + 1 < end && !(p[0] == '*' && p[1] == '/'))
            {
                ++p;
            }
            if (p + 1 < end)
            {
                p += 2;
            }
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
        if (paren_depth == 0 && bracket_depth == 0)
        {
            if (c == '{')
            {
                if (out_block)
                {
                    *out_block = true;
                }
                return p;
            }
            if (stop_at_semicolon && c == ';')
            {
                if (out_block)
                {
                    *out_block = false;
                }
                return p;
            }
        }
        ++p;
    }
    return p;
}

static const char *css_scan_to_block_or_semicolon(const char *p, const char *end, bool *out_block)
{
    return css_scan_to_block_internal(p, end, out_block, true);
}

static const char *css_scan_to_block(const char *p, const char *end, bool *out_block)
{
    return css_scan_to_block_internal(p, end, out_block, false);
}

static void css_skip_block_range(const char **p, const char *end)
{
    if (!p || !*p || !end)
    {
        return;
    }
    const char *s = *p;
    if (s >= end || *s != '{')
    {
        return;
    }
    ++s;
    int depth = 1;
    char quote = 0;
    bool escape = false;
    while (s < end && depth > 0)
    {
        char c = *s;
        if (escape)
        {
            escape = false;
            ++s;
            continue;
        }
        if (c == '\\')
        {
            escape = true;
            ++s;
            continue;
        }
        if (quote)
        {
            if (c == quote)
            {
                quote = 0;
            }
            ++s;
            continue;
        }
        if (c == '"' || c == '\'')
        {
            quote = c;
            ++s;
            continue;
        }
        if (c == '/' && (s + 1) < end && s[1] == '*')
        {
            s += 2;
            while (s + 1 < end && !(s[0] == '*' && s[1] == '/'))
            {
                ++s;
            }
            if (s + 1 < end)
            {
                s += 2;
            }
            continue;
        }
        if (c == '{')
        {
            ++depth;
            ++s;
            continue;
        }
        if (c == '}')
        {
            --depth;
            ++s;
            continue;
        }
        ++s;
    }
    *p = s;
}

static bool css_parse_declarations(const char **p,
                                   const char *end,
                                   css_decl_list_t *decls)
{
    if (!p || !*p || !end || !decls)
    {
        return false;
    }

    while (*p < end)
    {
        css_skip_ws_and_comments_range(p, end);
        if (*p >= end)
        {
            return true;
        }
        if (**p == '}')
        {
            ++(*p);
            return true;
        }

        const char *prop_start = *p;
        const char *scan = prop_start;
        while (scan < end && *scan != ':' && *scan != ';' && *scan != '}')
        {
            ++scan;
        }
        const char *prop_end = scan;
        if (scan >= end)
        {
            *p = scan;
            return true;
        }
        if (*scan != ':')
        {
            if (*scan == ';')
            {
                *p = scan + 1;
                continue;
            }
            if (*scan == '}')
            {
                *p = scan + 1;
                return true;
            }
            *p = scan;
            continue;
        }

        *p = scan + 1;
        const char *val_start = *p;
        const char *val_end_scan = css_scan_value_end_range(*p, end);
        if (!val_end_scan)
        {
            val_end_scan = *p;
        }
        const char *val_end = val_end_scan;
        bool important = false;
        if (!css_strip_priority(val_start, val_end, &val_end, &important))
        {
            *p = val_end_scan;
            if (*p < end && **p == ';')
            {
                ++(*p);
            }
            continue;
        }

        if (!css_decl_list_push(decls, prop_start, prop_end, val_start, val_end, important))
        {
            return false;
        }

        *p = val_end_scan;
        if (*p < end && **p == ';')
        {
            ++(*p);
        }
    }
    return true;
}

static bool css_ident_is(const char *start, const char *end, const char *name)
{
    if (!start || !end || !name)
    {
        return false;
    }
    size_t name_len = strlen(name);
    size_t len = (size_t)(end - start);
    return len == name_len && strncasecmp(start, name, name_len) == 0;
}

static bool css_range_contains_ci(const char *start, const char *end, const char *needle)
{
    if (!start || !end || !needle)
    {
        return false;
    }
    size_t needle_len = strlen(needle);
    if (needle_len == 0 || (size_t)(end - start) < needle_len)
    {
        return false;
    }
    for (const char *p = start; p + needle_len <= end; ++p)
    {
        if (strncasecmp(p, needle, needle_len) == 0)
        {
            return true;
        }
    }
    return false;
}

static bool css_selector_has_theme_override(const char *start, const char *end)
{
    if (!start || !end || end <= start)
    {
        return false;
    }
    static const char *tokens[] = {
        "theme-dark__forced",
        "theme-dark",
        "theme-highcontrast",
        "theme-system",
        "theme-light__forced",
        "theme-light",
    };
    bool in_not = false;
    int not_depth = 0;
    for (const char *p = start; p < end; ++p)
    {
        if (!in_not && *p == ':' && (end - p) >= 4 && strncasecmp(p, ":not", 4) == 0)
        {
            const char *q = p + 4;
            while (q < end && isspace((unsigned char)*q))
            {
                ++q;
            }
            if (q < end && *q == '(')
            {
                in_not = true;
                not_depth = 1;
                p = q;
                continue;
            }
        }
        if (in_not)
        {
            if (*p == '(')
            {
                ++not_depth;
            }
            else if (*p == ')')
            {
                --not_depth;
                if (not_depth <= 0)
                {
                    in_not = false;
                    not_depth = 0;
                }
            }
            continue;
        }
        for (size_t i = 0; i < sizeof(tokens) / sizeof(tokens[0]); ++i)
        {
            size_t len = strlen(tokens[i]);
            if ((size_t)(end - p) >= len && strncasecmp(p, tokens[i], len) == 0)
            {
                return true;
            }
        }
    }
    return false;
}

static bool css_selector_is_rootish(const char *start, const char *end)
{
    if (!start || !end || end <= start)
    {
        return false;
    }
    const char *p = start;
    css_trim_range(&p, &end);
    if (p >= end)
    {
        return false;
    }

    bool escape = false;
    char quote = 0;
    int bracket_depth = 0;
    int paren_depth = 0;
    const char *compound_end = end;
    for (const char *q = p; q < end; ++q)
    {
        char c = *q;
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
        if (bracket_depth == 0 && paren_depth == 0)
        {
            if (c == '>' || c == '+' || c == '~' || isspace((unsigned char)c))
            {
                compound_end = q;
                break;
            }
        }
    }

    const char *tail = compound_end;
    while (tail < end && isspace((unsigned char)*tail))
    {
        ++tail;
    }
    if (tail < end)
    {
        return false;
    }

    bool rootish = false;
    const char *q = p;
    if (q < compound_end && *q == '*')
    {
        ++q;
    }
    else if (q < compound_end && isalpha((unsigned char)*q))
    {
        const char *ident_start = q;
        while (q < compound_end &&
               (isalnum((unsigned char)*q) || *q == '-' || *q == '_'))
        {
            ++q;
        }
        if (css_ident_is(ident_start, q, "html") ||
            css_ident_is(ident_start, q, "body"))
        {
            rootish = true;
        }
    }

    escape = false;
    quote = 0;
    bracket_depth = 0;
    paren_depth = 0;
    for (const char *r = p; r < compound_end; ++r)
    {
        char c = *r;
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
        if (bracket_depth > 0 || paren_depth > 0)
        {
            continue;
        }
        if (c == ':')
        {
            const char *name = r + 1;
            if (name < compound_end && *name == ':')
            {
                ++name;
            }
            const char *name_end = name;
            while (name_end < compound_end &&
                   (isalnum((unsigned char)*name_end) || *name_end == '-' || *name_end == '_'))
            {
                ++name_end;
            }
            if (name_end > name && css_ident_is(name, name_end, "root"))
            {
                return true;
            }
        }
    }

    return rootish;
}

static bool css_selectors_allow_global_vars(const char *sel_start, const char *sel_end)
{
    if (!sel_start || !sel_end || sel_end <= sel_start)
    {
        return false;
    }
    const char *cur = sel_start;
    bool any = false;
    while (cur < sel_end)
    {
        const char *comma = cur;
        while (comma < sel_end && *comma != ',')
        {
            ++comma;
        }
        const char *seg_start = cur;
        const char *seg_end = comma;
        css_trim_range(&seg_start, &seg_end);
        if (seg_end > seg_start)
        {
            if (!css_selector_has_theme_override(seg_start, seg_end) &&
                css_selector_is_rootish(seg_start, seg_end))
            {
                any = true;
            }
        }
        cur = (comma < sel_end) ? (comma + 1) : sel_end;
    }
    return any;
}

static void css_collect_vars_from_decls(const css_decl_list_t *decls,
                                        css_var_map_t *global_vars,
                                        bool allow_override)
{
    if (!decls || !global_vars)
    {
        return;
    }

    for (size_t i = 0; i < decls->count; ++i)
    {
        const css_decl_t *decl = &decls->items[i];
        const char *prop_start = decl->prop_start;
        const char *prop_end = decl->prop_end;
        css_trim_range(&prop_start, &prop_end);
        if (prop_end <= prop_start)
        {
            continue;
        }
        if ((prop_end - prop_start) < 2 || prop_start[0] != '-' || prop_start[1] != '-')
        {
            continue;
        }
        if (css_var_name_is_local(prop_start, prop_end))
        {
            continue;
        }
        const char *val_start = decl->val_start;
        const char *val_end = decl->val_end;
        css_trim_range(&val_start, &val_end);
        if (val_end < val_start)
        {
            continue;
        }
        (void)css_var_map_set(global_vars, prop_start, prop_end, val_start, val_end, allow_override);
    }
}

static bool css_apply_rule_from_decls(css_stylesheet_t *sheet,
                                      const char *sel_start,
                                      const char *sel_end,
                                      const css_decl_list_t *decls,
                                      css_var_map_t *global_vars,
                                      bool allow_global_vars)
{
    if (!sheet || !decls || !sel_start || !sel_end || sel_end <= sel_start)
    {
        return false;
    }

    css_style_t style = {0};
    css_style_t important_style = {0};
    css_var_map_t local_vars = {0};
    css_var_map_t custom_props = {0};
    css_var_map_t important_custom_props = {0};
    css_decl_list_t deferred_decls = {0};
    bool has_style = false;
    bool has_important = false;

    for (size_t i = 0; i < decls->count; ++i)
    {
        const css_decl_t *decl = &decls->items[i];
        const char *prop_start = decl->prop_start;
        const char *prop_end = decl->prop_end;
        const char *val_start = decl->val_start;
        const char *val_end = decl->val_end;
        css_trim_range(&prop_start, &prop_end);
        if (prop_end <= prop_start)
        {
            continue;
        }
        if ((prop_end - prop_start) >= 2 && prop_start[0] == '-' && prop_start[1] == '-')
        {
            css_trim_range(&val_start, &val_end);
            if (val_end < val_start)
            {
                continue;
            }
            if (!css_var_map_set(&local_vars, prop_start, prop_end, val_start, val_end, true))
            {
                css_var_map_free(&local_vars);
                css_var_map_free(&custom_props);
                css_var_map_free(&important_custom_props);
                css_decl_list_free(&deferred_decls);
                css_style_release(&style);
                return false;
            }
            if (decl->important)
            {
                css_var_map_set(&important_custom_props, prop_start, prop_end, val_start, val_end, true);
            }
            else
            {
                css_var_map_set(&custom_props, prop_start, prop_end, val_start, val_end, true);
            }

            if (allow_global_vars && global_vars && !css_var_name_is_local(prop_start, prop_end))
            {
                if (!css_var_map_set(global_vars, prop_start, prop_end, val_start, val_end, false))
                {
                    css_var_map_free(&local_vars);
                    css_var_map_free(&custom_props);
                    css_var_map_free(&important_custom_props);
                    css_decl_list_free(&deferred_decls);
                    css_style_release(&style);
                    return false;
                }
            }
        }
    }

    for (size_t i = 0; i < decls->count; ++i)
    {
        const css_decl_t *decl = &decls->items[i];
        const char *prop_start = decl->prop_start;
        const char *prop_end = decl->prop_end;
        bool decl_important = decl->important;
        css_trim_range(&prop_start, &prop_end);
        if (prop_end <= prop_start)
        {
            continue;
        }
        if ((prop_end - prop_start) >= 2 && prop_start[0] == '-' && prop_start[1] == '-')
        {
            continue;
        }

        const char *val_start = decl->val_start;
        const char *val_end = decl->val_end;
        css_trim_range(&val_start, &val_end);
        if (val_end < val_start)
        {
            continue;
        }

        char *expanded = NULL;
        const char *apply_start = val_start;
        const char *apply_end = val_end;
        bool has_var = css_value_has_var(val_start, val_end);
        if (has_var)
        {
            expanded = css_expand_vars_range(val_start, val_end, global_vars, &local_vars, 0);
            if (expanded)
            {
                apply_start = expanded;
                apply_end = expanded + strlen(expanded);
            }
        }

        if (css_value_has_var(apply_start, apply_end))
        {
            css_decl_list_push(&deferred_decls, prop_start, prop_end, val_start, val_end, decl_important);
        }

        if (decl_important)
        {
            css_style_apply_property(&important_style, prop_start, prop_end, apply_start, apply_end);
            has_important = true;
        }
        else
        {
            css_style_apply_property(&style, prop_start, prop_end, apply_start, apply_end);
            has_style = true;
        }

        free(expanded);
    }

    bool ok = true;
    if (has_style || has_important || custom_props.count > 0 || important_custom_props.count > 0 || deferred_decls.count > 0)
    {
        const char *cur = sel_start;
        while (cur < sel_end)
        {
            const char *comma = cur;
            while (comma < sel_end && *comma != ',')
            {
                ++comma;
            }
            if (!css_append_rule(sheet, cur, comma, has_style ? &style : NULL,
                                 has_important ? &important_style : NULL,
                                 &custom_props, &important_custom_props, &deferred_decls,
                                 has_important))
            {
                ok = false;
                break;
            }
            cur = (comma < sel_end) ? comma + 1 : sel_end;
        }
    }

    css_var_map_free(&local_vars);
    css_var_map_free(&custom_props);
    css_var_map_free(&important_custom_props);
    css_decl_list_free(&deferred_decls);
    css_style_release(&style);
    css_style_release(&important_style);
    return ok;
}

static bool css_parse_rules(css_stylesheet_t *sheet,
                            const char **p,
                            const char *end,
                            css_var_map_t *global_vars,
                            bool collect_only)
{
    if (!p || !*p)
    {
        return false;
    }

    while (*p < end)
    {
        css_skip_ws_and_comments_range(p, end);
        if (*p >= end)
        {
            return true;
        }
        if (**p == '}')
        {
            ++(*p);
            return true;
        }

        if (**p == '@')
        {
            const char *name_start = *p + 1;
            const char *name_end = name_start;
            while (name_end < end &&
                   (isalnum((unsigned char)*name_end) || *name_end == '-' || *name_end == '_'))
            {
                ++name_end;
            }

            bool has_block = false;
            const char *mark = css_scan_to_block_or_semicolon(name_end, end, &has_block);
            if (mark >= end)
            {
                *p = end;
                return true;
            }
            if (!has_block)
            {
                *p = (mark < end) ? (mark + 1) : mark;
                continue;
            }

            if (css_at_rule_name_is(name_start, name_end, "media"))
            {
                const char *query_start = name_end;
                const char *query_end = mark;
                css_trim_range(&query_start, &query_end);
                if (css_media_query_list_matches(query_start, query_end, &g_css_media_env))
                {
                    *p = mark + 1;
                    if (!css_parse_rules(sheet, p, end, global_vars, collect_only))
                    {
                        return false;
                    }
                }
                else
                {
                    const char *skip = mark;
                    css_skip_block_range(&skip, end);
                    *p = skip;
                }
                continue;
            }

            if (css_at_rule_has_nested_rules(name_start, name_end))
            {
                *p = mark + 1;
                if (!css_parse_rules(sheet, p, end, global_vars, collect_only))
                {
                    return false;
                }
                continue;
            }

            const char *skip = mark;
            css_skip_block_range(&skip, end);
            *p = skip;
            continue;
        }

        const char *sel_start = *p;
        bool has_block = false;
        const char *mark = css_scan_to_block(sel_start, end, &has_block);
        if (!has_block)
        {
            if (mark < end && *mark == ';')
            {
                *p = mark + 1;
                continue;
            }
            *p = mark;
            return true;
        }
        const char *sel_end = mark;
        *p = mark + 1;

        css_decl_list_t decls = {0};
        if (!css_parse_declarations(p, end, &decls))
        {
            css_decl_list_free(&decls);
            return false;
        }

        bool allow_global_vars = global_vars && css_selectors_allow_global_vars(sel_start, sel_end);
        if (allow_global_vars)
        {
            css_collect_vars_from_decls(&decls, global_vars, collect_only);
        }
        if (!collect_only)
        {
            if (!css_apply_rule_from_decls(sheet,
                                           sel_start,
                                           sel_end,
                                           &decls,
                                           global_vars,
                                           allow_global_vars))
            {
                css_decl_list_free(&decls);
                return false;
            }
        }

        css_decl_list_free(&decls);
    }

    return true;
}

css_stylesheet_t *css_parse(const char *css_text)
{
    if (!css_text)
    {
        return NULL;
    }

    css_stylesheet_t *sheet = (css_stylesheet_t *)calloc(1, sizeof(*sheet));
    if (!sheet)
    {
        return NULL;
    }

    const char *p = css_text;
    const char *end = css_text + strlen(css_text);
    css_var_map_t global_vars = {0};
    if (!css_parse_rules(NULL, &p, end, &global_vars, true))
    {
        css_var_map_free(&global_vars);
        css_stylesheet_destroy(sheet);
        return NULL;
    }
    p = css_text;
    if (!css_parse_rules(sheet, &p, end, &global_vars, false))
    {
        css_var_map_free(&global_vars);
        css_stylesheet_destroy(sheet);
        return NULL;
    }
    css_var_map_free(&global_vars);
    return sheet;
}

void css_stylesheet_destroy(css_stylesheet_t *sheet)
{
    if (!sheet)
    {
        return;
    }
    css_rule_t *rule = sheet->rules;
    while (rule)
    {
        css_rule_t *next = rule->next;
        css_style_release(&rule->style);
        css_style_release(&rule->important_style);
        if (rule->selector_cache)
        {
            if (rule->selector_cache->compiled_parts)
            {
                for (size_t i = 0; i < rule->selector_cache->compiled_count; ++i)
                {
                    css_selector_compiled_part_t *part = &rule->selector_cache->compiled_parts[i];
                    free(part->classes);
                    free(part->attrs);
                }
                free(rule->selector_cache->compiled_parts);
            }
            free(rule->selector_cache->parts);
            free(rule->selector_cache);
        }
        free(rule->selector);
        free(rule);
        rule = next;
    }
    free(sheet);
}
