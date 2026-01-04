#include "atk/html_view/html_view_internal.h"

bool html_view_measure_cache_lookup(atk_html_view_priv_t *priv,
                                    const html_node_t *node,
                                    int content_w,
                                    int font_px,
                                    int line_height,
                                    bool shrink,
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
    if (!priv || !node || !priv->measure_cache || priv->measure_cache_count == 0)
    {
        return false;
    }

    for (size_t i = 0; i < priv->measure_cache_count; ++i)
    {
        const html_view_measure_cache_entry_t *entry = &priv->measure_cache[i];
        if (entry->node == node &&
            entry->content_w == content_w &&
            entry->font_px == font_px &&
            entry->line_height == line_height &&
            entry->shrink == shrink)
        {
            if (out_w)
            {
                *out_w = entry->out_w;
            }
            if (out_h)
            {
                *out_h = entry->out_h;
            }
            return true;
        }
    }

    return false;
}

void html_view_measure_cache_store(atk_html_view_priv_t *priv,
                                   const html_node_t *node,
                                   int content_w,
                                   int font_px,
                                   int line_height,
                                   bool shrink,
                                   int out_w,
                                   int out_h)
{
    if (!priv || !node)
    {
        return;
    }

    if (priv->measure_cache_count >= HTML_VIEW_MEASURE_CACHE_MAX)
    {
        html_view_measure_cache_clear(priv);
    }

    if (priv->measure_cache_count == priv->measure_cache_cap)
    {
        size_t new_cap = priv->measure_cache_cap ? (priv->measure_cache_cap * 2u) : 64u;
        if (new_cap > HTML_VIEW_MEASURE_CACHE_MAX)
        {
            new_cap = HTML_VIEW_MEASURE_CACHE_MAX;
        }
        html_view_measure_cache_entry_t *next = (html_view_measure_cache_entry_t *)realloc(priv->measure_cache,
                                                                                           new_cap * sizeof(*next));
        if (!next)
        {
            return;
        }
        priv->measure_cache = next;
        priv->measure_cache_cap = new_cap;
    }

    html_view_measure_cache_entry_t *entry = &priv->measure_cache[priv->measure_cache_count++];
    entry->node = node;
    entry->content_w = content_w;
    entry->font_px = font_px;
    entry->line_height = line_height;
    entry->shrink = shrink;
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
}
