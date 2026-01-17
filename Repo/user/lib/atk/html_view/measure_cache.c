#include "atk/html_view/html_view_internal.h"

static uint32_t html_view_measure_cache_hash(const html_node_t *node,
                                             int content_w,
                                             int font_px,
                                             int line_height,
                                             bool shrink,
                                             int origin_x,
                                             uint8_t kind)
{
    uint32_t hash = 2166136261u;
    uintptr_t ptr = (uintptr_t)node;
    hash ^= (uint32_t)(ptr >> 4);
    hash *= 16777619u;
    hash ^= (uint32_t)content_w;
    hash *= 16777619u;
    hash ^= (uint32_t)font_px;
    hash *= 16777619u;
    hash ^= (uint32_t)line_height;
    hash *= 16777619u;
    hash ^= (uint32_t)origin_x;
    hash *= 16777619u;
    hash ^= (uint32_t)(shrink ? 1u : 0u);
    hash *= 16777619u;
    hash ^= (uint32_t)kind;
    hash *= 16777619u;
    return hash;
}

static bool html_view_measure_cache_init(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return false;
    }
    if (priv->measure_cache && priv->measure_cache_cap > 0)
    {
        return true;
    }

    size_t cap = HTML_VIEW_MEASURE_CACHE_MAX;
    if (cap < 64)
    {
        cap = 64;
    }
    if ((cap & (cap - 1u)) != 0u)
    {
        size_t pow2 = 1u;
        while (pow2 < cap)
        {
            pow2 <<= 1u;
        }
        cap = pow2;
    }

    html_view_measure_cache_entry_t *entries = (html_view_measure_cache_entry_t *)calloc(cap, sizeof(*entries));
    if (!entries)
    {
        return false;
    }

    priv->measure_cache = entries;
    priv->measure_cache_cap = cap;
    priv->measure_cache_mask = cap - 1u;
    priv->measure_cache_count = 0;
    return true;
}

bool html_view_measure_cache_lookup(atk_html_view_priv_t *priv,
                                    const html_node_t *node,
                                    int content_w,
                                    int font_px,
                                    int line_height,
                                    bool shrink,
                                    int origin_x,
                                    uint8_t kind,
                                    int *out_w,
                                    int *out_h)
{
    if (out_w)
    {
        *out_w = 0;
    }
    if (out_h)
    {
        *out_h = 0;
    }
    if (!priv || !node || !priv->measure_cache || priv->measure_cache_cap == 0)
    {
        return false;
    }

    uint32_t hash = html_view_measure_cache_hash(node,
                                                 content_w,
                                                 font_px,
                                                 line_height,
                                                 shrink,
                                                 origin_x,
                                                 kind);
    size_t mask = priv->measure_cache_mask;
    size_t index = (size_t)hash & mask;

    for (size_t probe = 0; probe < priv->measure_cache_cap; ++probe)
    {
        const html_view_measure_cache_entry_t *entry = &priv->measure_cache[index];
        if (!entry->valid)
        {
            html_view_perf_note_measure_cache(priv, false, kind);
            return false;
        }
        if (entry->hash == hash &&
            entry->node == node &&
            entry->content_w == content_w &&
            entry->font_px == font_px &&
            entry->line_height == line_height &&
            entry->origin_x == origin_x &&
            entry->shrink == shrink &&
            entry->kind == kind)
        {
            if (out_w)
            {
                *out_w = entry->out_w;
            }
            if (out_h)
            {
                *out_h = entry->out_h;
            }
            html_view_perf_note_measure_cache(priv, true, kind);
            return true;
        }
        index = (index + 1u) & mask;
    }

    html_view_perf_note_measure_cache(priv, false, kind);
    return false;
}

void html_view_measure_cache_store(atk_html_view_priv_t *priv,
                                   const html_node_t *node,
                                   int content_w,
                                   int font_px,
                                   int line_height,
                                   bool shrink,
                                   int origin_x,
                                   uint8_t kind,
                                   int out_w,
                                   int out_h)
{
    if (!priv || !node)
    {
        return;
    }
    if (!html_view_measure_cache_init(priv))
    {
        return;
    }

    uint32_t hash = html_view_measure_cache_hash(node,
                                                 content_w,
                                                 font_px,
                                                 line_height,
                                                 shrink,
                                                 origin_x,
                                                 kind);
    size_t mask = priv->measure_cache_mask;
    size_t index = (size_t)hash & mask;

    for (size_t probe = 0; probe < priv->measure_cache_cap; ++probe)
    {
        html_view_measure_cache_entry_t *entry = &priv->measure_cache[index];
        if (!entry->valid)
        {
            entry->valid = true;
            entry->hash = hash;
            entry->node = node;
            entry->content_w = content_w;
            entry->font_px = font_px;
            entry->line_height = line_height;
            entry->origin_x = origin_x;
            entry->shrink = shrink;
            entry->kind = kind;
            entry->out_w = out_w;
            entry->out_h = out_h;
            priv->measure_cache_count++;
            return;
        }
        if (entry->hash == hash &&
            entry->node == node &&
            entry->content_w == content_w &&
            entry->font_px == font_px &&
            entry->line_height == line_height &&
            entry->origin_x == origin_x &&
            entry->shrink == shrink &&
            entry->kind == kind)
        {
            entry->out_w = out_w;
            entry->out_h = out_h;
            return;
        }
        index = (index + 1u) & mask;
    }

    html_view_measure_cache_entry_t *entry = &priv->measure_cache[(size_t)hash & mask];
    entry->valid = true;
    entry->hash = hash;
    entry->node = node;
    entry->content_w = content_w;
    entry->font_px = font_px;
    entry->line_height = line_height;
    entry->origin_x = origin_x;
    entry->shrink = shrink;
    entry->kind = kind;
    entry->out_w = out_w;
    entry->out_h = out_h;
}

void html_view_measure_cache_clear(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    free(priv->measure_cache);
    priv->measure_cache = NULL;
    priv->measure_cache_count = 0;
    priv->measure_cache_cap = 0;
    priv->measure_cache_mask = 0;
}
