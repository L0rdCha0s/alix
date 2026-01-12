#include "web/css/css_internal.h"

#include "ctype.h"
#include "libc.h"
#include "stdio.h"

#ifdef TTF_HOST_BUILD
#include <time.h>
#endif

typedef struct
{
    int width_px;
    int height_px;
    css_media_color_scheme_t color_scheme;
} css_media_env_t;

static css_media_env_t g_css_media_env = {0};

typedef struct css_alloc_node
{
    struct css_alloc_node *next;
    size_t used;
    size_t capacity;
    unsigned char data[];
} css_alloc_node_t;

enum
{
    CSS_SHEET_ARENA_BLOCK_SIZE = 32768
};

#define CSS_DYNSTR_SCRATCH_MIN_CAP 512u

typedef enum
{
    CSS_VAR_TOKEN_TEXT = 0,
    CSS_VAR_TOKEN_VAR
} css_var_token_kind_t;

typedef struct css_var_token
{
    css_var_token_kind_t kind;
    const char *start;
    uint32_t len;
    const char *name_start;
    uint32_t name_len;
    uint32_t name_hash;
    const struct css_var_tokens *fallback;
    const char *raw_start;
    uint32_t raw_len;
} css_var_token_t;

struct css_var_tokens
{
    css_var_token_t *items;
    size_t count;
    size_t cap;
    bool has_var;
};

typedef struct
{
    uint32_t name_hash;
    const char *name;
    uint32_t name_len;
    const char *value;
    uint32_t value_len;
    bool owned;
    bool resolved;
} css_var_cache_entry_t;

#define CSS_VAR_CACHE_INLINE_CAP 16u
#define CSS_VAR_CACHE_INLINE_SLOTS 32u

typedef struct
{
    css_var_cache_entry_t *items;
    size_t count;
    size_t cap;
    uint32_t *slots;
    size_t slot_cap;
    css_var_cache_entry_t inline_items[CSS_VAR_CACHE_INLINE_CAP];
    uint32_t inline_slots[CSS_VAR_CACHE_INLINE_SLOTS];
} css_var_cache_t;

typedef struct
{
    uint32_t tokens_hash;
    const css_var_tokens_t *tokens;
    const char *value;
    uint32_t value_len;
    bool owned;
    bool resolved;
} css_var_eval_cache_entry_t;

#define CSS_VAR_EVAL_CACHE_INLINE_CAP 16u
#define CSS_VAR_EVAL_CACHE_INLINE_SLOTS 32u

typedef struct
{
    css_var_eval_cache_entry_t *items;
    size_t count;
    size_t cap;
    uint32_t *slots;
    size_t slot_cap;
    css_var_eval_cache_entry_t inline_items[CSS_VAR_EVAL_CACHE_INLINE_CAP];
    uint32_t inline_slots[CSS_VAR_EVAL_CACHE_INLINE_SLOTS];
} css_var_eval_cache_t;

struct css_var_env
{
    uint32_t refcount;
    struct css_var_env *parent;
    css_var_map_t map;
    css_var_cache_t cache;
    css_var_eval_cache_t eval_cache;
    char *dynstr_scratch;
    size_t dynstr_scratch_cap;
    uint32_t dynstr_scratch_in_use;
};

typedef struct
{
    bool enabled;
    uint64_t var_map_set_calls;
    uint64_t var_map_entry_adds;
    uint64_t var_map_entry_updates;
    uint64_t var_env_create_calls;
    uint64_t deferred_prop_sets;
    uint64_t deferred_prop_merges;
    uint64_t deferred_prop_resolves;
    uint64_t var_tokens_builds;
    uint64_t expand_calls;
    uint64_t expand_input_bytes;
    uint64_t expand_output_bytes;
    uint64_t var_map_set_ns;
    uint64_t deferred_resolve_ns;
} css_perf_stats_t;

static css_perf_stats_t g_css_perf = {0};

static uint64_t css_perf_now_ns(void)
{
#ifdef TTF_HOST_BUILD
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
#else
    return 0;
#endif
}

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

void css_perf_reset(bool enabled)
{
    memset(&g_css_perf, 0, sizeof(g_css_perf));
    g_css_perf.enabled = enabled;
}

void css_perf_dump(void)
{
    if (!g_css_perf.enabled)
    {
        return;
    }
    printf("css_perf: var_map_set=%llu adds=%llu updates=%llu var_env_create=%llu tokens=%llu\n",
           (unsigned long long)g_css_perf.var_map_set_calls,
           (unsigned long long)g_css_perf.var_map_entry_adds,
           (unsigned long long)g_css_perf.var_map_entry_updates,
           (unsigned long long)g_css_perf.var_env_create_calls,
           (unsigned long long)g_css_perf.var_tokens_builds);
    printf("css_perf: deferred_sets=%llu deferred_merges=%llu deferred_resolves=%llu\n",
           (unsigned long long)g_css_perf.deferred_prop_sets,
           (unsigned long long)g_css_perf.deferred_prop_merges,
           (unsigned long long)g_css_perf.deferred_prop_resolves);
    printf("css_perf: expand_calls=%llu in_bytes=%llu out_bytes=%llu\n",
           (unsigned long long)g_css_perf.expand_calls,
           (unsigned long long)g_css_perf.expand_input_bytes,
           (unsigned long long)g_css_perf.expand_output_bytes);
    printf("css_perf: var_map_set_ns=%llu deferred_resolve_ns=%llu\n",
           (unsigned long long)g_css_perf.var_map_set_ns,
           (unsigned long long)g_css_perf.deferred_resolve_ns);
}

static void *css_sheet_alloc(css_stylesheet_t *sheet, size_t size)
{
    if (!sheet || size == 0)
    {
        return NULL;
    }
    size_t align = sizeof(void *);
    size_t padded = (size + align - 1u) & ~(align - 1u);

    css_alloc_node_t *block = sheet->allocations;
    if (!block || block->capacity - block->used < padded)
    {
        size_t capacity = CSS_SHEET_ARENA_BLOCK_SIZE;
        if (padded > capacity)
        {
            capacity = padded;
        }
        css_alloc_node_t *next = (css_alloc_node_t *)malloc(sizeof(*next) + capacity);
        if (!next)
        {
            return NULL;
        }
        next->next = sheet->allocations;
        next->used = 0;
        next->capacity = capacity;
        sheet->allocations = next;
        block = next;
    }

    void *ptr = block->data + block->used;
    block->used += padded;
    memset(ptr, 0, size);
    return ptr;
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

static char *css_sheet_strdup_lower(css_stylesheet_t *sheet, const char *start, const char *end)
{
    if (!sheet || !start || !end || end < start)
    {
        return NULL;
    }
    size_t len = (size_t)(end - start);
    char *out = (char *)css_sheet_alloc(sheet, len + 1);
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


typedef struct css_dynstr
{
    char *data;
    size_t len;
    size_t cap;
    css_var_env_t *scratch_env;
} css_dynstr_t;

static bool css_dynstr_reserve(css_dynstr_t *out, size_t needed);

static void css_dynstr_scratch_release(css_dynstr_t *out)
{
    if (!out || !out->scratch_env)
    {
        return;
    }
    out->scratch_env->dynstr_scratch_in_use = 0u;
    out->scratch_env = NULL;
}

static bool css_dynstr_prepare(css_dynstr_t *out, css_var_env_t *env, size_t needed)
{
    if (!out || needed == 0)
    {
        return true;
    }
    if (out->cap >= needed)
    {
        return true;
    }
    if (env && !out->scratch_env && !env->dynstr_scratch_in_use)
    {
        size_t cap = env->dynstr_scratch_cap;
        if (cap < needed)
        {
            size_t new_cap = cap ? cap : CSS_DYNSTR_SCRATCH_MIN_CAP;
            while (new_cap < needed)
            {
                new_cap *= 2u;
            }
            char *next = (char *)realloc(env->dynstr_scratch, new_cap);
            if (!next)
            {
                return false;
            }
            env->dynstr_scratch = next;
            env->dynstr_scratch_cap = new_cap;
            cap = new_cap;
        }
        env->dynstr_scratch_in_use = 1u;
        out->data = env->dynstr_scratch;
        out->cap = cap;
        out->len = 0;
        out->scratch_env = env;
        out->data[0] = '\0';
        return true;
    }
    return css_dynstr_reserve(out, needed);
}

static void css_dynstr_release(css_dynstr_t *out)
{
    if (!out)
    {
        return;
    }
    if (out->scratch_env)
    {
        css_dynstr_scratch_release(out);
    }
    else
    {
        free(out->data);
    }
    out->data = NULL;
    out->len = 0;
    out->cap = 0;
}

static char *css_dynstr_detach(css_dynstr_t *out)
{
    if (!out)
    {
        return NULL;
    }
    if (out->scratch_env)
    {
        char *copy = NULL;
        if (out->len > 0)
        {
            copy = (char *)malloc(out->len + 1u);
            if (!copy)
            {
                css_dynstr_release(out);
                return NULL;
            }
            memcpy(copy, out->data, out->len);
            copy[out->len] = '\0';
        }
        css_dynstr_scratch_release(out);
        out->data = NULL;
        out->len = 0;
        out->cap = 0;
        return copy;
    }
    char *data = out->data;
    out->data = NULL;
    out->len = 0;
    out->cap = 0;
    return data;
}

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
    if (map->slots != map->inline_slots)
    {
        free(map->slots);
    }
    map->slots = NULL;
    map->slot_cap = 0;
}

static bool css_var_slots_prepare(uint32_t **slots,
                                  size_t *slot_cap,
                                  size_t min_cap,
                                  uint32_t *inline_slots,
                                  size_t inline_cap)
{
    if (!slots || !slot_cap || min_cap == 0)
    {
        return false;
    }
    size_t cap = *slot_cap;
    if (!*slots || cap < min_cap)
    {
        if (!*slots && inline_slots && inline_cap >= min_cap)
        {
            *slots = inline_slots;
            cap = inline_cap;
            *slot_cap = cap;
        }
        else
        {
            uint32_t *next = NULL;
            if (*slots && (!inline_slots || *slots != inline_slots))
            {
                next = (uint32_t *)realloc(*slots, min_cap * sizeof(**slots));
            }
            else
            {
                next = (uint32_t *)malloc(min_cap * sizeof(**slots));
            }
            if (!next)
            {
                return false;
            }
            *slots = next;
            cap = min_cap;
            *slot_cap = cap;
        }
    }
    memset(*slots, 0, cap * sizeof(**slots));
    return true;
}

static bool css_var_map_rebuild_index(css_var_map_t *map)
{
    if (!map)
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

    if (!css_var_slots_prepare(&map->slots,
                               &map->slot_cap,
                               cap,
                               map->inline_slots,
                               CSS_VAR_MAP_INLINE_SLOTS))
    {
        return false;
    }

    uint32_t *slots = map->slots;
    size_t mask = map->slot_cap - 1u;
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

    return true;
}

static void css_var_map_slot_insert(css_var_map_t *map, size_t entry_index)
{
    if (!map || !map->slots || map->slot_cap == 0)
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
    if (map->items && map->items != map->inline_items)
    {
        free(map->items);
    }
    css_var_map_slots_free(map);
    map->items = NULL;
    map->count = 0;
    map->cap = 0;
    map->slots = NULL;
    map->slot_cap = 0;
}

bool css_var_map_clone(css_var_map_t *dst, const css_var_map_t *src)
{
    if (!dst || !src)
    {
        return false;
    }
    *dst = (css_var_map_t){0};
    if (src->count == 0)
    {
        return true;
    }
    if (src->count <= CSS_VAR_MAP_INLINE_CAP)
    {
        dst->items = dst->inline_items;
        dst->cap = CSS_VAR_MAP_INLINE_CAP;
    }
    else
    {
        dst->items = (css_var_entry_t *)calloc(src->count, sizeof(*dst->items));
        if (!dst->items)
        {
            return false;
        }
        dst->cap = src->count;
    }
    memcpy(dst->items, src->items, src->count * sizeof(*dst->items));
    dst->count = src->count;
    if (src->slot_cap > 0 && src->slots)
    {
        if (src->slot_cap <= CSS_VAR_MAP_INLINE_SLOTS)
        {
            dst->slots = dst->inline_slots;
            dst->slot_cap = src->slot_cap;
        }
        else
        {
            dst->slots = (uint32_t *)calloc(src->slot_cap, sizeof(*dst->slots));
            if (!dst->slots)
            {
                css_var_map_free(dst);
                return false;
            }
            dst->slot_cap = src->slot_cap;
        }
        memcpy(dst->slots, src->slots, src->slot_cap * sizeof(*dst->slots));
    }
    return true;
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

bool css_var_map_set(css_var_map_t *map,
                     const char *name_start,
                     const char *name_end,
                     const char *value_start,
                     const char *value_end,
                     const css_var_tokens_t *tokens,
                     bool allow_override)
{
    if (!map || !name_start || !name_end || name_end <= name_start)
    {
        return false;
    }
    uint64_t t0 = g_css_perf.enabled ? css_perf_now_ns() : 0;
    if (g_css_perf.enabled)
    {
        g_css_perf.var_map_set_calls++;
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
                entry->value = value_start;
                entry->value_len = (uint32_t)value_len;
                entry->tokens = tokens;
                if (g_css_perf.enabled)
                {
                    g_css_perf.var_map_entry_updates++;
                }
                if (g_css_perf.enabled && t0)
                {
                    g_css_perf.var_map_set_ns += (css_perf_now_ns() - t0);
                }
                return true;
            }
        }
    }

    if (!map->items)
    {
        map->items = map->inline_items;
        map->cap = CSS_VAR_MAP_INLINE_CAP;
    }
    if (map->count == map->cap)
    {
        size_t new_cap = map->cap ? map->cap * 2u : CSS_VAR_MAP_INLINE_CAP;
        css_var_entry_t *next = NULL;
        if (map->items == map->inline_items)
        {
            next = (css_var_entry_t *)malloc(new_cap * sizeof(*next));
            if (!next)
            {
                return false;
            }
            memcpy(next, map->items, map->count * sizeof(*next));
        }
        else
        {
            next = (css_var_entry_t *)realloc(map->items, new_cap * sizeof(*next));
            if (!next)
            {
                return false;
            }
        }
        map->items = next;
        map->cap = new_cap;
    }

    map->items[map->count++] = (css_var_entry_t){
        .name = name_start,
        .value = value_start,
        .name_hash = name_hash,
        .name_len = (uint32_t)name_len,
        .value_len = (uint32_t)value_len,
        .tokens = tokens,
    };
    if (g_css_perf.enabled)
    {
        g_css_perf.var_map_entry_adds++;
    }
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
    if (g_css_perf.enabled && t0)
    {
        g_css_perf.var_map_set_ns += (css_perf_now_ns() - t0);
    }
    return true;
}

bool css_var_map_set_parsed(css_stylesheet_t *sheet,
                            css_var_map_t *map,
                            const char *name_start,
                            const char *name_end,
                            const char *value_start,
                            const char *value_end,
                            bool allow_override)
{
    const css_var_tokens_t *tokens = NULL;
    if (value_start && value_end && css_value_has_var(value_start, value_end))
    {
        tokens = css_var_tokens_parse_range(sheet, value_start, value_end);
        if (!tokens)
        {
            return false;
        }
    }
    return css_var_map_set(map, name_start, name_end, value_start, value_end, tokens, allow_override);
}

bool css_var_map_set_entry(css_var_map_t *map,
                           const css_var_entry_t *entry,
                           bool allow_override)
{
    if (!map || !entry || !entry->name || entry->name_len == 0)
    {
        return false;
    }
    const char *name_start = entry->name;
    const char *name_end = entry->name + entry->name_len;
    const char *value_start = entry->value;
    const char *value_end = entry->value + entry->value_len;
    return css_var_map_set(map, name_start, name_end, value_start, value_end, entry->tokens, allow_override);
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
        if (!css_dynstr_reserve(out, out->len + len + 1))
        {
            return false;
        }
    }
    memcpy(out->data + out->len, data, len);
    out->len += len;
    out->data[out->len] = '\0';
    return true;
}

static bool css_dynstr_reserve(css_dynstr_t *out, size_t needed)
{
    if (!out || needed <= out->cap)
    {
        return true;
    }
    size_t new_cap = out->cap ? out->cap : 64u;
    while (new_cap < needed)
    {
        new_cap *= 2u;
    }
    if (out->scratch_env)
    {
        char *next = (char *)malloc(new_cap);
        if (!next)
        {
            return false;
        }
        if (out->data && out->len > 0)
        {
            memcpy(next, out->data, out->len);
        }
        next[out->len] = '\0';
        css_dynstr_scratch_release(out);
        out->data = next;
        out->cap = new_cap;
        return true;
    }
    char *next = out->data ? (char *)realloc(out->data, new_cap) : (char *)malloc(new_cap);
    if (!next)
    {
        return false;
    }
    out->data = next;
    out->cap = new_cap;
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

typedef struct
{
    css_var_token_t *items;
    size_t count;
    size_t cap;
} css_var_token_builder_t;

static void css_var_token_builder_free(css_var_token_builder_t *builder)
{
    if (!builder)
    {
        return;
    }
    free(builder->items);
    builder->items = NULL;
    builder->count = 0;
    builder->cap = 0;
}

static bool css_var_token_builder_push(css_var_token_builder_t *builder, const css_var_token_t *token)
{
    if (!builder || !token)
    {
        return false;
    }
    if (builder->count == builder->cap)
    {
        size_t new_cap = builder->cap ? builder->cap * 2u : 8u;
        css_var_token_t *next = (css_var_token_t *)realloc(builder->items, new_cap * sizeof(*next));
        if (!next)
        {
            return false;
        }
        builder->items = next;
        builder->cap = new_cap;
    }
    builder->items[builder->count++] = *token;
    return true;
}

static const css_var_tokens_t *css_var_tokens_finalize(css_stylesheet_t *sheet,
                                                       const css_var_token_builder_t *builder,
                                                       bool has_var)
{
    if (!sheet || !builder || builder->count == 0)
    {
        return NULL;
    }
    css_var_tokens_t *tokens = (css_var_tokens_t *)css_sheet_alloc(sheet, sizeof(*tokens));
    if (!tokens)
    {
        return NULL;
    }
    css_var_token_t *items = (css_var_token_t *)css_sheet_alloc(sheet, builder->count * sizeof(*items));
    if (!items)
    {
        return NULL;
    }
    memcpy(items, builder->items, builder->count * sizeof(*items));
    tokens->items = items;
    tokens->count = builder->count;
    tokens->cap = builder->count;
    tokens->has_var = has_var;
    if (g_css_perf.enabled)
    {
        g_css_perf.var_tokens_builds++;
    }
    return tokens;
}

const css_var_tokens_t *css_var_tokens_parse_range(css_stylesheet_t *sheet,
                                                   const char *start,
                                                   const char *end)
{
    if (!sheet || !start || !end || end <= start)
    {
        return NULL;
    }
    css_trim_range(&start, &end);
    if (end <= start)
    {
        return NULL;
    }

    css_var_token_builder_t builder = {0};
    bool has_var = false;
    const char *segment = start;
    const char *p = start;
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
        if (c == '/' && (p + 1) < end && p[1] == '*')
        {
            if (segment < p)
            {
                css_var_token_t tok = {
                    .kind = CSS_VAR_TOKEN_TEXT,
                    .start = segment,
                    .len = (uint32_t)(p - segment),
                };
                if (!css_var_token_builder_push(&builder, &tok))
                {
                    css_var_token_builder_free(&builder);
                    return NULL;
                }
            }
            p += 2;
            while (p + 1 < end && !(p[0] == '*' && p[1] == '/'))
            {
                ++p;
            }
            if (p + 1 < end)
            {
                p += 2;
            }
            segment = p;
            continue;
        }
        if ((end - p) >= 4 && (p[0] == 'v' || p[0] == 'V') &&
            (p[1] == 'a' || p[1] == 'A') &&
            (p[2] == 'r' || p[2] == 'R') && p[3] == '(')
        {
            if (segment < p)
            {
                css_var_token_t tok = {
                    .kind = CSS_VAR_TOKEN_TEXT,
                    .start = segment,
                    .len = (uint32_t)(p - segment),
                };
                if (!css_var_token_builder_push(&builder, &tok))
                {
                    css_var_token_builder_free(&builder);
                    return NULL;
                }
            }

            const char *func_start = p;
            const char *scan = p + 4;
            const char *comma = NULL;
            char vquote = 0;
            bool vescape = false;
            int depth = 1;

            while (scan < end)
            {
                char vc = *scan;
                if (vescape)
                {
                    vescape = false;
                    ++scan;
                    continue;
                }
                if (vc == '\\')
                {
                    vescape = true;
                    ++scan;
                    continue;
                }
                if (vquote)
                {
                    if (vc == vquote)
                    {
                        vquote = 0;
                    }
                    ++scan;
                    continue;
                }
                if (vc == '"' || vc == '\'')
                {
                    vquote = vc;
                    ++scan;
                    continue;
                }
                if (vc == '/' && (scan + 1) < end && scan[1] == '*')
                {
                    scan += 2;
                    while (scan + 1 < end && !(scan[0] == '*' && scan[1] == '/'))
                    {
                        ++scan;
                    }
                    if (scan + 1 < end)
                    {
                        scan += 2;
                    }
                    continue;
                }
                if (vc == '(')
                {
                    ++depth;
                    ++scan;
                    continue;
                }
                if (vc == ')')
                {
                    --depth;
                    if (depth == 0)
                    {
                        break;
                    }
                    ++scan;
                    continue;
                }
                if (vc == ',' && depth == 1 && !comma)
                {
                    comma = scan;
                    ++scan;
                    continue;
                }
                ++scan;
            }

            if (depth != 0 || scan >= end)
            {
                p = func_start + 1;
                segment = func_start;
                continue;
            }

            const char *func_end = scan;
            const char *name_start = p + 4;
            const char *name_end = comma ? comma : func_end;
            css_trim_range(&name_start, &name_end);
            if (name_end <= name_start)
            {
                css_var_token_t tok = {
                    .kind = CSS_VAR_TOKEN_TEXT,
                    .start = func_start,
                    .len = (uint32_t)(func_end + 1 - func_start),
                };
                if (!css_var_token_builder_push(&builder, &tok))
                {
                    css_var_token_builder_free(&builder);
                    return NULL;
                }
                p = func_end + 1;
                segment = p;
                continue;
            }

            const char *fallback_start = NULL;
            const char *fallback_end = NULL;
            if (comma)
            {
                fallback_start = comma + 1;
                fallback_end = func_end;
                css_trim_range(&fallback_start, &fallback_end);
                if (!fallback_start || !fallback_end || fallback_end <= fallback_start)
                {
                    fallback_start = NULL;
                    fallback_end = NULL;
                }
            }

            const css_var_tokens_t *fallback_tokens = NULL;
            if (fallback_start && fallback_end)
            {
                fallback_tokens = css_var_tokens_parse_range(sheet, fallback_start, fallback_end);
            }

            css_var_token_t tok = {
                .kind = CSS_VAR_TOKEN_VAR,
                .name_start = name_start,
                .name_len = (uint32_t)(name_end - name_start),
                .name_hash = css_var_hash_range(name_start, name_end),
                .fallback = fallback_tokens,
                .raw_start = func_start,
                .raw_len = (uint32_t)(func_end + 1 - func_start),
            };
            if (!css_var_token_builder_push(&builder, &tok))
            {
                css_var_token_builder_free(&builder);
                return NULL;
            }
            has_var = true;
            p = func_end + 1;
            segment = p;
            continue;
        }
        ++p;
    }

    if (segment < end)
    {
        css_var_token_t tok = {
            .kind = CSS_VAR_TOKEN_TEXT,
            .start = segment,
            .len = (uint32_t)(end - segment),
        };
        if (!css_var_token_builder_push(&builder, &tok))
        {
            css_var_token_builder_free(&builder);
            return NULL;
        }
    }

    const css_var_tokens_t *tokens = css_var_tokens_finalize(sheet, &builder, has_var);
    css_var_token_builder_free(&builder);
    return tokens;
}

static void css_var_cache_slots_free(css_var_cache_t *cache)
{
    if (!cache || !cache->slots)
    {
        return;
    }
    if (cache->slots != cache->inline_slots)
    {
        free(cache->slots);
    }
    cache->slots = NULL;
    cache->slot_cap = 0;
}

static bool css_var_cache_rebuild_index(css_var_cache_t *cache)
{
    if (!cache)
    {
        return false;
    }
    if (cache->count < 8)
    {
        css_var_cache_slots_free(cache);
        return true;
    }

    size_t cap = 16;
    while (cap < cache->count * 2u)
    {
        cap <<= 1;
    }

    if (!css_var_slots_prepare(&cache->slots,
                               &cache->slot_cap,
                               cap,
                               cache->inline_slots,
                               CSS_VAR_CACHE_INLINE_SLOTS))
    {
        return false;
    }

    uint32_t *slots = cache->slots;
    size_t mask = cache->slot_cap - 1u;
    for (size_t i = 0; i < cache->count; ++i)
    {
        const css_var_cache_entry_t *entry = &cache->items[i];
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

    return true;
}

static void css_var_cache_slot_insert(css_var_cache_t *cache, size_t entry_index)
{
    if (!cache || !cache->slots || cache->slot_cap == 0)
    {
        return;
    }
    size_t mask = cache->slot_cap - 1u;
    size_t idx = (size_t)cache->items[entry_index].name_hash & mask;
    while (cache->slots[idx] != 0u)
    {
        idx = (idx + 1u) & mask;
    }
    cache->slots[idx] = (uint32_t)(entry_index + 1u);
}

static css_var_cache_entry_t *css_var_cache_find(css_var_cache_t *cache,
                                                 const char *name_start,
                                                 size_t name_len,
                                                 uint32_t name_hash)
{
    if (!cache || !name_start || name_len == 0)
    {
        return NULL;
    }
    if (cache->slots && cache->slot_cap > 0)
    {
        size_t mask = cache->slot_cap - 1u;
        size_t idx = (size_t)name_hash & mask;
        while (true)
        {
            uint32_t slot = cache->slots[idx];
            if (slot == 0u)
            {
                return NULL;
            }
            css_var_cache_entry_t *entry = &cache->items[slot - 1u];
            if (entry->name_hash == name_hash && entry->name_len == name_len &&
                entry->name && memcmp(entry->name, name_start, name_len) == 0)
            {
                return entry;
            }
            idx = (idx + 1u) & mask;
        }
    }
    for (size_t i = 0; i < cache->count; ++i)
    {
        css_var_cache_entry_t *entry = &cache->items[i];
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

static bool css_var_cache_set(css_var_cache_t *cache,
                              const char *name_start,
                              size_t name_len,
                              uint32_t name_hash,
                              const char *value,
                              uint32_t value_len,
                              bool owned,
                              bool resolved)
{
    if (!cache || !name_start || name_len == 0)
    {
        return false;
    }
    css_var_cache_entry_t *existing = css_var_cache_find(cache, name_start, name_len, name_hash);
    if (existing)
    {
        if (existing->owned && existing->value)
        {
            free((void *)existing->value);
        }
        existing->value = value;
        existing->value_len = value_len;
        existing->owned = owned;
        existing->resolved = resolved;
        return true;
    }

    if (!cache->items)
    {
        cache->items = cache->inline_items;
        cache->cap = CSS_VAR_CACHE_INLINE_CAP;
    }
    if (cache->count == cache->cap)
    {
        size_t new_cap = cache->cap ? cache->cap * 2u : CSS_VAR_CACHE_INLINE_CAP;
        css_var_cache_entry_t *next = NULL;
        if (cache->items == cache->inline_items)
        {
            next = (css_var_cache_entry_t *)malloc(new_cap * sizeof(*next));
            if (!next)
            {
                return false;
            }
            memcpy(next, cache->items, cache->count * sizeof(*next));
        }
        else
        {
            next = (css_var_cache_entry_t *)realloc(cache->items, new_cap * sizeof(*next));
            if (!next)
            {
                return false;
            }
        }
        cache->items = next;
        cache->cap = new_cap;
    }

    cache->items[cache->count++] = (css_var_cache_entry_t){
        .name_hash = name_hash,
        .name = name_start,
        .name_len = (uint32_t)name_len,
        .value = value,
        .value_len = value_len,
        .owned = owned,
        .resolved = resolved,
    };
    if (cache->count >= 8)
    {
        if (!cache->slots || cache->count * 2u >= cache->slot_cap)
        {
            if (!css_var_cache_rebuild_index(cache))
            {
                return false;
            }
        }
        else
        {
            css_var_cache_slot_insert(cache, cache->count - 1u);
        }
    }
    return true;
}

static void css_var_cache_free(css_var_cache_t *cache)
{
    if (!cache)
    {
        return;
    }
    if (cache->items)
    {
        for (size_t i = 0; i < cache->count; ++i)
        {
            if (cache->items[i].owned && cache->items[i].value)
            {
                free((void *)cache->items[i].value);
            }
        }
    }
    if (cache->items && cache->items != cache->inline_items)
    {
        free(cache->items);
    }
    cache->items = NULL;
    cache->count = 0;
    cache->cap = 0;
    css_var_cache_slots_free(cache);
}

static uint32_t css_var_eval_hash(const css_var_tokens_t *tokens)
{
    uintptr_t ptr = (uintptr_t)tokens;
    uint32_t hash = 2166136261u;
    hash ^= (uint32_t)(ptr >> 4);
    hash *= 16777619u;
    hash ^= (uint32_t)ptr;
    hash *= 16777619u;
    return hash;
}

static void css_var_eval_cache_slots_free(css_var_eval_cache_t *cache)
{
    if (!cache)
    {
        return;
    }
    if (cache->slots && cache->slots != cache->inline_slots)
    {
        free(cache->slots);
    }
    cache->slots = NULL;
    cache->slot_cap = 0;
}

static bool css_var_eval_cache_rebuild_index(css_var_eval_cache_t *cache)
{
    if (!cache || cache->count == 0)
    {
        return true;
    }
    size_t new_cap = 1u;
    while (new_cap < cache->count * 2u)
    {
        new_cap <<= 1u;
    }
    if (!css_var_slots_prepare(&cache->slots,
                               &cache->slot_cap,
                               new_cap,
                               cache->inline_slots,
                               CSS_VAR_EVAL_CACHE_INLINE_SLOTS))
    {
        return false;
    }

    uint32_t *slots = cache->slots;
    size_t mask = cache->slot_cap - 1u;
    for (size_t i = 0; i < cache->count; ++i)
    {
        const css_var_eval_cache_entry_t *entry = &cache->items[i];
        if (!entry->tokens)
        {
            continue;
        }
        size_t idx = (size_t)entry->tokens_hash & mask;
        while (slots[idx] != 0u)
        {
            idx = (idx + 1u) & mask;
        }
        slots[idx] = (uint32_t)(i + 1u);
    }
    return true;
}

static void css_var_eval_cache_slot_insert(css_var_eval_cache_t *cache, size_t entry_index)
{
    if (!cache || !cache->slots || cache->slot_cap == 0)
    {
        return;
    }
    size_t mask = cache->slot_cap - 1u;
    size_t idx = (size_t)cache->items[entry_index].tokens_hash & mask;
    while (cache->slots[idx] != 0u)
    {
        idx = (idx + 1u) & mask;
    }
    cache->slots[idx] = (uint32_t)(entry_index + 1u);
}

static css_var_eval_cache_entry_t *css_var_eval_cache_find(css_var_eval_cache_t *cache,
                                                           const css_var_tokens_t *tokens,
                                                           uint32_t tokens_hash)
{
    if (!cache || !tokens || cache->count == 0)
    {
        return NULL;
    }
    if (cache->slots && cache->slot_cap > 0)
    {
        size_t mask = cache->slot_cap - 1u;
        size_t idx = (size_t)tokens_hash & mask;
        for (size_t probe = 0; probe < cache->slot_cap; ++probe)
        {
            uint32_t slot = cache->slots[idx];
            if (slot == 0u)
            {
                return NULL;
            }
            css_var_eval_cache_entry_t *entry = &cache->items[slot - 1u];
            if (entry->tokens == tokens)
            {
                return entry;
            }
            idx = (idx + 1u) & mask;
        }
    }
    for (size_t i = 0; i < cache->count; ++i)
    {
        css_var_eval_cache_entry_t *entry = &cache->items[i];
        if (entry->tokens == tokens)
        {
            return entry;
        }
    }
    return NULL;
}

static bool css_var_eval_cache_set(css_var_eval_cache_t *cache,
                                   const css_var_tokens_t *tokens,
                                   const char *value,
                                   uint32_t value_len,
                                   bool owned,
                                   bool resolved)
{
    if (!cache || !tokens)
    {
        return false;
    }
    uint32_t tokens_hash = css_var_eval_hash(tokens);
    css_var_eval_cache_entry_t *existing = css_var_eval_cache_find(cache, tokens, tokens_hash);
    if (existing)
    {
        if (existing->owned && existing->value)
        {
            free((void *)existing->value);
        }
        existing->value = value;
        existing->value_len = value_len;
        existing->owned = owned;
        existing->resolved = resolved;
        return true;
    }

    if (!cache->items)
    {
        cache->items = cache->inline_items;
        cache->cap = CSS_VAR_EVAL_CACHE_INLINE_CAP;
    }
    if (cache->count == cache->cap)
    {
        size_t new_cap = cache->cap ? cache->cap * 2u : CSS_VAR_EVAL_CACHE_INLINE_CAP;
        css_var_eval_cache_entry_t *next = NULL;
        if (cache->items == cache->inline_items)
        {
            next = (css_var_eval_cache_entry_t *)malloc(new_cap * sizeof(*next));
            if (!next)
            {
                return false;
            }
            memcpy(next, cache->items, cache->count * sizeof(*next));
        }
        else
        {
            next = (css_var_eval_cache_entry_t *)realloc(cache->items,
                                                         new_cap * sizeof(*next));
            if (!next)
            {
                return false;
            }
        }
        cache->items = next;
        cache->cap = new_cap;
    }

    cache->items[cache->count++] = (css_var_eval_cache_entry_t){
        .tokens_hash = tokens_hash,
        .tokens = tokens,
        .value = value,
        .value_len = value_len,
        .owned = owned,
        .resolved = resolved,
    };
    if (cache->count >= 8)
    {
        if (!cache->slots || cache->count * 2u >= cache->slot_cap)
        {
            if (!css_var_eval_cache_rebuild_index(cache))
            {
                return false;
            }
        }
        else
        {
            css_var_eval_cache_slot_insert(cache, cache->count - 1u);
        }
    }
    return true;
}

static void css_var_eval_cache_free(css_var_eval_cache_t *cache)
{
    if (!cache)
    {
        return;
    }
    if (cache->items)
    {
        for (size_t i = 0; i < cache->count; ++i)
        {
            css_var_eval_cache_entry_t *entry = &cache->items[i];
            if (entry->owned && entry->value)
            {
                free((void *)entry->value);
            }
        }
    }
    if (cache->items && cache->items != cache->inline_items)
    {
        free(cache->items);
    }
    cache->items = NULL;
    cache->count = 0;
    cache->cap = 0;
    css_var_eval_cache_slots_free(cache);
}

css_var_env_t *css_var_env_create(css_var_env_t *parent)
{
    css_var_env_t *env = (css_var_env_t *)calloc(1, sizeof(*env));
    if (!env)
    {
        return NULL;
    }
    env->refcount = 1u;
    env->parent = css_var_env_ref(parent);
    if (g_css_perf.enabled)
    {
        g_css_perf.var_env_create_calls++;
    }
    return env;
}

css_var_env_t *css_var_env_ref(css_var_env_t *env)
{
    if (!env)
    {
        return NULL;
    }
    env->refcount++;
    return env;
}

void css_var_env_release(css_var_env_t *env)
{
    if (!env)
    {
        return;
    }
    if (--env->refcount > 0)
    {
        return;
    }
    css_var_env_release(env->parent);
    css_var_map_free(&env->map);
    css_var_cache_free(&env->cache);
    css_var_eval_cache_free(&env->eval_cache);
    if (env->dynstr_scratch)
    {
        free(env->dynstr_scratch);
        env->dynstr_scratch = NULL;
        env->dynstr_scratch_cap = 0;
        env->dynstr_scratch_in_use = 0u;
    }
    free(env);
}

bool css_var_env_ensure_local(css_style_t *style)
{
    if (!style)
    {
        return false;
    }
    if (style->custom_env && style->custom_env_local)
    {
        return true;
    }
    css_var_env_t *parent = style->custom_env;
    css_var_env_t *env = css_var_env_create(parent);
    if (!env)
    {
        return false;
    }
    if (style->custom_env)
    {
        css_var_env_release(style->custom_env);
    }
    style->custom_env = env;
    style->custom_env_local = true;
    return true;
}

static const css_var_entry_t *css_var_env_find_entry(const css_var_env_t *env,
                                                     const char *name_start,
                                                     size_t name_len,
                                                     uint32_t name_hash)
{
    if (!env)
    {
        return NULL;
    }
    return css_var_map_find_hash(&env->map, name_start, name_len, name_hash);
}

static bool css_var_tokens_eval_into(css_dynstr_t *out,
                                     const css_var_tokens_t *tokens,
                                     css_var_env_t *env,
                                     int depth);

static const char *css_var_env_resolve(css_var_env_t *env,
                                       const char *name_start,
                                       size_t name_len,
                                       uint32_t name_hash,
                                       size_t *out_len,
                                       int depth)
{
    if (!env || !name_start || name_len == 0 || depth > 32)
    {
        return NULL;
    }
    css_var_cache_entry_t *cached = css_var_cache_find(&env->cache, name_start, name_len, name_hash);
    if (cached && cached->resolved)
    {
        if (cached->value && out_len)
        {
            *out_len = cached->value_len;
        }
        return cached->value;
    }

    const css_var_entry_t *entry = css_var_env_find_entry(env, name_start, name_len, name_hash);
    if (!entry)
    {
        if (env->parent)
        {
            size_t parent_len = 0;
            const char *parent_val = css_var_env_resolve(env->parent,
                                                        name_start,
                                                        name_len,
                                                        name_hash,
                                                        &parent_len,
                                                        depth + 1);
            (void)css_var_cache_set(&env->cache,
                                    name_start,
                                    name_len,
                                    name_hash,
                                    parent_val,
                                    (uint32_t)parent_len,
                                    false,
                                    true);
            if (parent_val && out_len)
            {
                *out_len = parent_len;
            }
            return parent_val;
        }
        (void)css_var_cache_set(&env->cache, name_start, name_len, name_hash, NULL, 0u, false, true);
        return NULL;
    }

    if (entry->tokens && entry->tokens->has_var)
    {
        css_dynstr_t out = {0};
        if (css_var_tokens_eval_into(&out, entry->tokens, env, depth + 1))
        {
            if (g_css_perf.enabled)
            {
                g_css_perf.expand_calls++;
                g_css_perf.expand_output_bytes += out.len;
            }
            size_t resolved_len = out.len;
            char *resolved = css_dynstr_detach(&out);
            if (resolved_len > 0 && !resolved)
            {
                (void)css_var_cache_set(&env->cache, name_start, name_len, name_hash, NULL, 0u, false, true);
                return NULL;
            }
            (void)css_var_cache_set(&env->cache, name_start, name_len, name_hash,
                                    resolved, (uint32_t)resolved_len, true, true);
            if (out_len)
            {
                *out_len = resolved_len;
            }
            return resolved;
        }
        css_dynstr_release(&out);
        (void)css_var_cache_set(&env->cache, name_start, name_len, name_hash, NULL, 0u, false, true);
        return NULL;
    }

    (void)css_var_cache_set(&env->cache, name_start, name_len, name_hash,
                            entry->value, entry->value_len, false, true);
    if (out_len)
    {
        *out_len = entry->value_len;
    }
    return entry->value;
}

static bool css_var_tokens_eval_into(css_dynstr_t *out,
                                     const css_var_tokens_t *tokens,
                                     css_var_env_t *env,
                                     int depth)
{
    if (!tokens || !out)
    {
        return true;
    }
    if (depth > 32)
    {
        return false;
    }
    if (out->cap == 0 && tokens->count > 0)
    {
        size_t reserve = 0;
        for (size_t i = 0; i < tokens->count; ++i)
        {
            const css_var_token_t *token = &tokens->items[i];
            if (token->kind == CSS_VAR_TOKEN_TEXT)
            {
                reserve += token->len;
                continue;
            }
            if (token->kind == CSS_VAR_TOKEN_VAR && token->raw_len > 0)
            {
                reserve += token->raw_len;
            }
        }
        if (reserve > 0 && !css_dynstr_prepare(out, env, reserve + 1u))
        {
            return false;
        }
    }
    for (size_t i = 0; i < tokens->count; ++i)
    {
        const css_var_token_t *token = &tokens->items[i];
        if (token->kind == CSS_VAR_TOKEN_TEXT)
        {
            if (!css_dynstr_append(out, token->start, token->len))
            {
                return false;
            }
            continue;
        }
        if (token->kind != CSS_VAR_TOKEN_VAR)
        {
            continue;
        }

        size_t resolved_len = 0;
        const char *resolved = css_var_env_resolve(env,
                                                   token->name_start,
                                                   token->name_len,
                                                   token->name_hash,
                                                   &resolved_len,
                                                   depth + 1);
        if (resolved)
        {
            if (!css_dynstr_append(out, resolved, resolved_len))
            {
                return false;
            }
            continue;
        }

        if (token->fallback)
        {
            if (css_var_tokens_eval_into(out, token->fallback, env, depth + 1))
            {
                continue;
            }
        }

        if (token->raw_start && token->raw_len > 0)
        {
            if (!css_dynstr_append(out, token->raw_start, token->raw_len))
            {
                return false;
            }
        }
    }
    return true;
}

bool css_style_apply_custom_props(css_style_t *style, const css_var_map_t *props)
{
    if (!style || !props || props->count == 0)
    {
        return true;
    }
    if (!css_var_env_ensure_local(style))
    {
        return false;
    }
    for (size_t i = 0; i < props->count; ++i)
    {
        (void)css_var_map_set_entry(&style->custom_env->map, &props->items[i], true);
    }
    if (props == &style->custom_props)
    {
        css_var_map_free(&style->custom_props);
    }
    return true;
}

static uint32_t css_prop_hash_range(const char *start, const char *end)
{
    uint32_t hash = 2166136261u;
    if (!start || !end || end <= start)
    {
        return hash;
    }
    for (const char *p = start; p < end; ++p)
    {
        hash ^= (uint8_t)tolower((unsigned char)*p);
        hash *= 16777619u;
    }
    return hash;
}

static void css_deferred_map_slots_free(css_deferred_map_t *map)
{
    if (!map || !map->slots)
    {
        return;
    }
    if (map->slots != map->inline_slots)
    {
        free(map->slots);
    }
    map->slots = NULL;
    map->slot_cap = 0;
}

static bool css_deferred_map_rebuild_index(css_deferred_map_t *map)
{
    if (!map)
    {
        return false;
    }
    if (map->count < 8)
    {
        css_deferred_map_slots_free(map);
        return true;
    }

    size_t cap = 16;
    while (cap < map->count * 2u)
    {
        cap <<= 1;
    }

    if (!css_var_slots_prepare(&map->slots,
                               &map->slot_cap,
                               cap,
                               map->inline_slots,
                               CSS_DEFERRED_MAP_INLINE_SLOTS))
    {
        return false;
    }

    uint32_t *slots = map->slots;
    size_t mask = map->slot_cap - 1u;
    for (size_t i = 0; i < map->count; ++i)
    {
        const css_deferred_prop_t *entry = &map->items[i];
        if (!entry->prop_start || entry->prop_len == 0)
        {
            continue;
        }
        size_t idx = (size_t)entry->prop_hash & mask;
        while (slots[idx] != 0u)
        {
            idx = (idx + 1u) & mask;
        }
        slots[idx] = (uint32_t)(i + 1u);
    }

    return true;
}

static void css_deferred_map_slot_insert(css_deferred_map_t *map, size_t entry_index)
{
    if (!map || !map->slots || map->slot_cap == 0)
    {
        return;
    }
    size_t mask = map->slot_cap - 1u;
    size_t idx = (size_t)map->items[entry_index].prop_hash & mask;
    while (map->slots[idx] != 0u)
    {
        idx = (idx + 1u) & mask;
    }
    map->slots[idx] = (uint32_t)(entry_index + 1u);
}

static css_deferred_prop_t *css_deferred_map_find_hash(css_deferred_map_t *map,
                                                       const char *prop_start,
                                                       size_t prop_len,
                                                       uint32_t prop_hash)
{
    if (!map || !prop_start || prop_len == 0)
    {
        return NULL;
    }
    if (map->slots && map->slot_cap > 0)
    {
        size_t mask = map->slot_cap - 1u;
        size_t idx = (size_t)prop_hash & mask;
        while (true)
        {
            uint32_t slot = map->slots[idx];
            if (slot == 0u)
            {
                return NULL;
            }
            css_deferred_prop_t *entry = &map->items[slot - 1u];
            if (entry->prop_hash == prop_hash && entry->prop_len == prop_len &&
                entry->prop_start && strncasecmp(entry->prop_start, prop_start, prop_len) == 0)
            {
                return entry;
            }
            idx = (idx + 1u) & mask;
        }
    }
    for (size_t i = 0; i < map->count; ++i)
    {
        css_deferred_prop_t *entry = &map->items[i];
        if (!entry->prop_start)
        {
            continue;
        }
        if (entry->prop_hash == prop_hash && entry->prop_len == prop_len &&
            strncasecmp(entry->prop_start, prop_start, prop_len) == 0)
        {
            return entry;
        }
    }
    return NULL;
}

bool css_deferred_map_set(css_deferred_map_t *map,
                          const char *prop_start,
                          const char *prop_end,
                          const css_var_tokens_t *tokens,
                          bool allow_override)
{
    if (!map || !prop_start || !prop_end || prop_end <= prop_start)
    {
        return false;
    }
    if (g_css_perf.enabled)
    {
        g_css_perf.deferred_prop_sets++;
    }
    css_trim_range(&prop_start, &prop_end);
    if (prop_end <= prop_start)
    {
        return false;
    }
    size_t prop_len = (size_t)(prop_end - prop_start);
    uint32_t prop_hash = css_prop_hash_range(prop_start, prop_end);
    css_deferred_prop_t *existing = css_deferred_map_find_hash(map, prop_start, prop_len, prop_hash);
    if (existing && !allow_override)
    {
        return true;
    }
    if (existing)
    {
        existing->prop_start = prop_start;
        existing->prop_len = (uint32_t)prop_len;
        existing->prop_hash = prop_hash;
        existing->tokens = tokens;
        return true;
    }

    if (!map->items)
    {
        map->items = map->inline_items;
        map->cap = CSS_DEFERRED_MAP_INLINE_CAP;
    }
    if (map->count == map->cap)
    {
        size_t new_cap = map->cap ? map->cap * 2u : CSS_DEFERRED_MAP_INLINE_CAP;
        css_deferred_prop_t *next = NULL;
        if (map->items == map->inline_items)
        {
            next = (css_deferred_prop_t *)malloc(new_cap * sizeof(*next));
            if (!next)
            {
                return false;
            }
            memcpy(next, map->items, map->count * sizeof(*next));
        }
        else
        {
            next = (css_deferred_prop_t *)realloc(map->items, new_cap * sizeof(*next));
            if (!next)
            {
                return false;
            }
        }
        map->items = next;
        map->cap = new_cap;
    }

    map->items[map->count++] = (css_deferred_prop_t){
        .prop_start = prop_start,
        .prop_len = (uint32_t)prop_len,
        .prop_hash = prop_hash,
        .tokens = tokens,
    };
    if (map->count >= 8)
    {
        if (!map->slots || map->count * 2u >= map->slot_cap)
        {
            if (!css_deferred_map_rebuild_index(map))
            {
                return false;
            }
        }
        else
        {
            css_deferred_map_slot_insert(map, map->count - 1u);
        }
    }
    return true;
}

void css_deferred_map_free(css_deferred_map_t *map)
{
    if (!map)
    {
        return;
    }
    if (map->items && map->items != map->inline_items)
    {
        free(map->items);
    }
    map->items = NULL;
    map->count = 0;
    map->cap = 0;
    css_deferred_map_slots_free(map);
}

bool css_deferred_map_clone(css_deferred_map_t *dst, const css_deferred_map_t *src)
{
    if (!dst || !src)
    {
        return false;
    }
    *dst = (css_deferred_map_t){0};
    if (src->count == 0)
    {
        return true;
    }
    if (src->count <= CSS_DEFERRED_MAP_INLINE_CAP)
    {
        dst->items = dst->inline_items;
        dst->cap = CSS_DEFERRED_MAP_INLINE_CAP;
    }
    else
    {
        dst->items = (css_deferred_prop_t *)calloc(src->count, sizeof(*dst->items));
        if (!dst->items)
        {
            return false;
        }
        dst->cap = src->count;
    }
    memcpy(dst->items, src->items, src->count * sizeof(*dst->items));
    dst->count = src->count;
    if (src->slot_cap > 0 && src->slots)
    {
        if (src->slot_cap <= CSS_DEFERRED_MAP_INLINE_SLOTS)
        {
            dst->slots = dst->inline_slots;
            dst->slot_cap = src->slot_cap;
        }
        else
        {
            dst->slots = (uint32_t *)calloc(src->slot_cap, sizeof(*dst->slots));
            if (!dst->slots)
            {
                css_deferred_map_free(dst);
                return false;
            }
            dst->slot_cap = src->slot_cap;
        }
        memcpy(dst->slots, src->slots, src->slot_cap * sizeof(*dst->slots));
    }
    return true;
}

bool css_deferred_map_merge(css_deferred_map_t *dst, const css_deferred_map_t *src)
{
    if (!dst || !src || src->count == 0)
    {
        return true;
    }
    if (g_css_perf.enabled)
    {
        g_css_perf.deferred_prop_merges++;
    }
    for (size_t i = 0; i < src->count; ++i)
    {
        const css_deferred_prop_t *entry = &src->items[i];
        if (!css_deferred_map_set(dst,
                                  entry->prop_start,
                                  entry->prop_start + entry->prop_len,
                                  entry->tokens,
                                  true))
        {
            return false;
        }
    }
    return true;
}

void css_style_resolve_deferred(css_style_t *style)
{
    if (!style || style->deferred_props.count == 0)
    {
        return;
    }
    uint64_t t0 = g_css_perf.enabled ? css_perf_now_ns() : 0;
    if (g_css_perf.enabled)
    {
        g_css_perf.deferred_prop_resolves++;
    }

    for (size_t i = 0; i < style->deferred_props.count; ++i)
    {
        const css_deferred_prop_t *entry = &style->deferred_props.items[i];
        if (!entry->tokens)
        {
            continue;
        }
        if (style->custom_env)
        {
            uint32_t tokens_hash = css_var_eval_hash(entry->tokens);
            css_var_eval_cache_entry_t *cached =
                css_var_eval_cache_find(&style->custom_env->eval_cache, entry->tokens, tokens_hash);
            if (cached && cached->resolved)
            {
                if (!cached->value)
                {
                    continue;
                }
                css_style_apply_property(style,
                                         entry->prop_start,
                                         entry->prop_start + entry->prop_len,
                                         cached->value,
                                         cached->value + cached->value_len);
                continue;
            }
        }
        css_dynstr_t out = {0};
        if (!css_var_tokens_eval_into(&out, entry->tokens, style->custom_env, 0))
        {
            css_dynstr_release(&out);
            if (style->custom_env)
            {
                (void)css_var_eval_cache_set(&style->custom_env->eval_cache,
                                             entry->tokens,
                                             NULL,
                                             0u,
                                             false,
                                             true);
            }
            continue;
        }
        if (g_css_perf.enabled)
        {
            g_css_perf.expand_calls++;
            g_css_perf.expand_output_bytes += out.len;
        }
        size_t resolved_len = out.len;
        char *resolved = css_dynstr_detach(&out);
        if (resolved_len > 0 && !resolved)
        {
            if (style->custom_env)
            {
                (void)css_var_eval_cache_set(&style->custom_env->eval_cache,
                                             entry->tokens,
                                             NULL,
                                             0u,
                                             false,
                                             true);
            }
            continue;
        }
        bool cached = false;
        if (style->custom_env)
        {
            cached = css_var_eval_cache_set(&style->custom_env->eval_cache,
                                            entry->tokens,
                                            resolved,
                                            (uint32_t)resolved_len,
                                            true,
                                            true);
        }
        const char *resolved_end = resolved ? resolved + resolved_len : NULL;
        css_style_apply_property(style,
                                 entry->prop_start,
                                 entry->prop_start + entry->prop_len,
                                 resolved,
                                 resolved_end);
        if (!cached)
        {
            free(resolved);
        }
    }
    css_deferred_map_free(&style->deferred_props);
    if (g_css_perf.enabled && t0)
    {
        g_css_perf.deferred_resolve_ns += (css_perf_now_ns() - t0);
    }
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
                    css_dynstr_release(&out);
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
                        css_dynstr_release(&out);
                        return NULL;
                    }
                }
                else
                {
                    if (!css_dynstr_append(&out, value, value_len))
                    {
                        css_dynstr_release(&out);
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
                        css_dynstr_release(&out);
                        return NULL;
                    }
                }
                else
                {
                    if (!css_dynstr_append(&out, fallback_start, (size_t)(fallback_end - fallback_start)))
                    {
                        css_dynstr_release(&out);
                        return NULL;
                    }
                }
            }
            else
            {
                if (!css_dynstr_append(&out, func_start, (size_t)(scan + 1 - func_start)))
                {
                    css_dynstr_release(&out);
                    return NULL;
                }
            }

            p = scan + 1;
            continue;
        }

        if (!css_dynstr_append(&out, p, 1))
        {
            css_dynstr_release(&out);
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

    css_rule_t *rule = (css_rule_t *)css_sheet_alloc(sheet, sizeof(*rule));
    if (!rule)
    {
        return false;
    }
    rule->selector = css_sheet_strdup_lower(sheet, selector_start, selector_end);
    if (!rule->selector)
    {
        return false;
    }
    if (style)
    {
        if (!css_style_copy(&rule->style, style))
        {
            return false;
        }
    }
    if (important_style)
    {
        if (!css_style_copy(&rule->important_style, important_style))
        {
            css_style_release(&rule->style);
            return false;
        }
    }
    rule->has_important = has_important;
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

static void css_var_refs_scan_range(css_stylesheet_t *sheet,
                                    const char *start,
                                    const char *end)
{
    if (!sheet || !start || !end || end <= start)
    {
        return;
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
            while ((p + 1) < end && !(p[0] == '*' && p[1] == '/'))
            {
                ++p;
            }
            if ((p + 1) < end)
            {
                p += 2;
            }
            continue;
        }
        if ((c == 'v' || c == 'V') && (p + 3) < end)
        {
            char a = p[1];
            char r = p[2];
            if ((a == 'a' || a == 'A') && (r == 'r' || r == 'R') && p[3] == '(')
            {
                const char *name_start = p + 4;
                while (name_start < end && isspace((unsigned char)*name_start))
                {
                    ++name_start;
                }
                if ((name_start + 1) < end && name_start[0] == '-' && name_start[1] == '-')
                {
                    const char *name_end = name_start + 2;
                    while (name_end < end)
                    {
                        unsigned char ch = (unsigned char)*name_end;
                        if (isalnum(ch) || ch == '-' || ch == '_')
                        {
                            ++name_end;
                            continue;
                        }
                        break;
                    }
                    if (name_end > name_start + 2)
                    {
                        (void)css_var_map_set(&sheet->var_refs,
                                              name_start,
                                              name_end,
                                              NULL,
                                              NULL,
                                              NULL,
                                              false);
                    }
                    p = name_end;
                    continue;
                }
            }
        }
        ++p;
    }
}

static void css_collect_var_refs_from_decls(css_stylesheet_t *sheet,
                                            const css_decl_list_t *decls)
{
    if (!sheet || !decls)
    {
        return;
    }
    for (size_t i = 0; i < decls->count; ++i)
    {
        const css_decl_t *decl = &decls->items[i];
        const char *val_start = decl->val_start;
        const char *val_end = decl->val_end;
        css_trim_range(&val_start, &val_end);
        if (val_end <= val_start)
        {
            continue;
        }
        if (!css_value_has_var(val_start, val_end))
        {
            continue;
        }
        css_var_refs_scan_range(sheet, val_start, val_end);
    }
}

static bool css_var_refs_contains(const css_stylesheet_t *sheet,
                                  const char *name_start,
                                  const char *name_end)
{
    if (!sheet || !name_start || !name_end || name_end <= name_start)
    {
        return true;
    }
    if (sheet->var_refs.count == 0)
    {
        return true;
    }
    css_trim_range(&name_start, &name_end);
    if (name_end <= name_start)
    {
        return true;
    }
    size_t name_len = (size_t)(name_end - name_start);
    uint32_t name_hash = css_var_hash_range(name_start, name_end);
    const css_var_entry_t *entry = css_var_map_find_hash(&sheet->var_refs,
                                                         name_start,
                                                         name_len,
                                                         name_hash);
    return entry != NULL;
}

static void css_collect_vars_from_decls(css_stylesheet_t *sheet,
                                        const css_decl_list_t *decls,
                                        css_var_map_t *global_vars,
                                        bool allow_override)
{
    if (!sheet || !decls || !global_vars)
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
        if (!css_var_refs_contains(sheet, prop_start, prop_end))
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
        (void)css_var_map_set_parsed(sheet,
                                     global_vars,
                                     prop_start,
                                     prop_end,
                                     val_start,
                                     val_end,
                                     allow_override);
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
            if (!css_var_refs_contains(sheet, prop_start, prop_end))
            {
                continue;
            }
            if (decl->important)
            {
                if (!css_var_map_set_parsed(sheet,
                                            &important_style.custom_props,
                                            prop_start,
                                            prop_end,
                                            val_start,
                                            val_end,
                                            true))
                {
                    css_style_release(&style);
                    css_style_release(&important_style);
                    return false;
                }
            }
            else
            {
                if (!css_var_map_set_parsed(sheet,
                                            &style.custom_props,
                                            prop_start,
                                            prop_end,
                                            val_start,
                                            val_end,
                                            true))
                {
                    css_style_release(&style);
                    css_style_release(&important_style);
                    return false;
                }
            }

            if (allow_global_vars && global_vars && !css_var_name_is_local(prop_start, prop_end))
            {
                if (!css_var_map_set_parsed(sheet,
                                            global_vars,
                                            prop_start,
                                            prop_end,
                                            val_start,
                                            val_end,
                                            false))
                {
                    css_style_release(&style);
                    css_style_release(&important_style);
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
        if (css_value_has_var(val_start, val_end))
        {
            const css_var_tokens_t *tokens = css_var_tokens_parse_range(sheet, val_start, val_end);
            if (!tokens)
            {
                css_style_release(&style);
                css_style_release(&important_style);
                return false;
            }
            if (decl_important)
            {
                if (!css_deferred_map_set(&important_style.deferred_props, prop_start, prop_end, tokens, true))
                {
                    css_style_release(&style);
                    css_style_release(&important_style);
                    return false;
                }
                has_important = true;
            }
            else
            {
                if (!css_deferred_map_set(&style.deferred_props, prop_start, prop_end, tokens, true))
                {
                    css_style_release(&style);
                    css_style_release(&important_style);
                    return false;
                }
                has_style = true;
            }
            continue;
        }

        if (decl_important)
        {
            css_style_apply_property(&important_style, prop_start, prop_end, val_start, val_end);
            has_important = true;
        }
        else
        {
            css_style_apply_property(&style, prop_start, prop_end, val_start, val_end);
            has_style = true;
        }
    }

    bool ok = true;
    if (has_style || has_important ||
        style.custom_props.count > 0 || important_style.custom_props.count > 0 ||
        style.deferred_props.count > 0 || important_style.deferred_props.count > 0)
    {
        const char *cur = sel_start;
        while (cur < sel_end)
        {
            const char *comma = cur;
            while (comma < sel_end && *comma != ',')
            {
                ++comma;
            }
            if (!css_append_rule(sheet,
                                 cur,
                                 comma,
                                 has_style ? &style : NULL,
                                 has_important ? &important_style : NULL,
                                 has_important))
            {
                ok = false;
                break;
            }
            cur = (comma < sel_end) ? comma + 1 : sel_end;
        }
    }

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
        if (collect_only)
        {
            css_collect_var_refs_from_decls(sheet, &decls);
        }
        if (allow_global_vars)
        {
            css_collect_vars_from_decls(sheet, &decls, global_vars, collect_only);
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

    size_t text_len = strlen(css_text);
    sheet->source = (char *)malloc(text_len + 1);
    if (!sheet->source)
    {
        css_stylesheet_destroy(sheet);
        return NULL;
    }
    memcpy(sheet->source, css_text, text_len);
    sheet->source[text_len] = '\0';
    sheet->source_len = text_len;

    const char *p = sheet->source;
    const char *end = sheet->source + sheet->source_len;
    css_var_map_t global_vars = {0};
    if (!css_parse_rules(sheet, &p, end, &global_vars, true))
    {
        css_var_map_free(&global_vars);
        css_stylesheet_destroy(sheet);
        return NULL;
    }
    p = sheet->source;
    if (!css_parse_rules(sheet, &p, end, &global_vars, false))
    {
        css_var_map_free(&global_vars);
        css_stylesheet_destroy(sheet);
        return NULL;
    }
    if (global_vars.count > 0)
    {
        sheet->global_env = css_var_env_create(NULL);
        if (!sheet->global_env)
        {
            css_var_map_free(&global_vars);
            css_stylesheet_destroy(sheet);
            return NULL;
        }
        sheet->global_env->map = global_vars;
        if (sheet->global_env->map.items && sheet->global_env->map.cap <= CSS_VAR_MAP_INLINE_CAP)
        {
            sheet->global_env->map.items = sheet->global_env->map.inline_items;
        }
        if (sheet->global_env->map.slots && sheet->global_env->map.slot_cap <= CSS_VAR_MAP_INLINE_SLOTS)
        {
            sheet->global_env->map.slots = sheet->global_env->map.inline_slots;
        }
        global_vars = (css_var_map_t){0};
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
        rule = next;
    }
    css_var_env_release(sheet->global_env);
    sheet->global_env = NULL;
    css_var_map_free(&sheet->var_refs);
    free(sheet->source);
    sheet->source = NULL;
    sheet->source_len = 0;
    css_alloc_node_t *alloc = sheet->allocations;
    while (alloc)
    {
        css_alloc_node_t *next = alloc->next;
        free(alloc);
        alloc = next;
    }
    sheet->allocations = NULL;
    free(sheet);
}
